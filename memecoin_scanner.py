"""
Memecoin Scanner — automatically scans new tokens on ETH, BSC, and Base.

Runs every 5 minutes. For every new token found it runs 26 checks across:
  - GoPlusLabs API  (security: honeypot, taxes, functions, ownership)
  - DexScreener API (market: MC, volume, liquidity, buys/sells, holders)

Hard gates: any critical security failure = instant reject, no score shown.
Scoring: 100 points across security, distribution, and market quality.

Alerts sent for:
  A grade (80+)  — strong candidate
  B grade (65–79) — moderate candidate (proceed with caution)

Commands:
  /scan ADDRESS [CHAIN]  — manually scan any token address
                           chain: eth, bsc, base (default: auto-detect)
  /recent                — last 10 tokens that passed screening
  /help
"""

import os
import json
import time
import logging
import requests
import asyncio
from datetime import datetime, timezone
from telegram import Bot

TELEGRAM_TOKEN  = os.environ.get("TELEGRAM_TOKEN", "YOUR_BOT_TOKEN_HERE")
CHAT_ID         = os.environ.get("CHAT_ID", "YOUR_CHAT_ID_HERE")
SCAN_INTERVAL   = 300        # 5 minutes
SEEN_FILE       = "memecoin_seen.json"
RESULTS_FILE    = "memecoin_results.json"
MAX_SEEN        = 2000
POLL_INTERVAL   = 2

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger(__name__)

# ── API endpoints ─────────────────────────────────────────────────────────────

GOPLUS_URL        = "https://api.gopluslabs.io/api/v1/token_security/%s"
DEXSCREEN_LATEST  = "https://api.dexscreener.com/token-profiles/latest/v1"
DEXSCREEN_TOKEN   = "https://api.dexscreener.com/latest/dex/tokens/%s"

CHAIN_MAP = {
    "ethereum": {"goplus_id": "1",    "label": "ETH"},
    "bsc":      {"goplus_id": "56",   "label": "BSC"},
    "base":     {"goplus_id": "8453", "label": "BASE"},
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def safe_get(url, timeout=15):
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        log.warning("HTTP error %s: %s" % (url[:60], e))
    return None

def load_seen():
    if not os.path.exists(SEEN_FILE):
        return set()
    try:
        with open(SEEN_FILE, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_seen(seen):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen)[-MAX_SEEN:], f)

def load_results():
    if not os.path.exists(RESULTS_FILE):
        return []
    try:
        with open(RESULTS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_result(result):
    results = load_results()
    results.append(result)
    with open(RESULTS_FILE, "w") as f:
        json.dump(results[-100:], f, indent=2)

def fv(n):
    if n is None: return "N/A"
    if n >= 1e9:  return "$%.2fB" % (n / 1e9)
    if n >= 1e6:  return "$%.2fM" % (n / 1e6)
    if n >= 1e3:  return "$%.1fK" % (n / 1e3)
    return "$%.2f" % n

# ── GoPlusLabs security fetch ─────────────────────────────────────────────────

def fetch_security(chain_id, address):
    data = safe_get(GOPLUS_URL % chain_id)
    if not data:
        return None
    # GoPlusLabs takes address as query param
    data = safe_get((GOPLUS_URL % chain_id) + "?contract_addresses=" + address)
    if not data or not data.get("result"):
        return None
    result = data["result"].get(address.lower()) or data["result"].get(address)
    return result

# ── DexScreener market fetch ──────────────────────────────────────────────────

def fetch_dexscreen(address):
    data = safe_get(DEXSCREEN_TOKEN % address)
    if not data or not data.get("pairs"):
        return None
    # Return the pair with highest liquidity
    pairs = data["pairs"]
    pairs.sort(key=lambda p: float(p.get("liquidity", {}).get("usd", 0) or 0), reverse=True)
    return pairs[0] if pairs else None

# ── Core analyser ─────────────────────────────────────────────────────────────

def analyse_token(address, chain_id, chain_label):
    """
    Returns (passed, grade, score, details, hard_fail_reason) or None on API error.
    """
    sec  = fetch_security(chain_id, address)
    pair = fetch_dexscreen(address)

    if not sec and not pair:
        return None

    checks  = {}   # check_name → (passed: bool, note: str)
    score   = 0
    hard_fails = []

    # ── HARD GATES — instant reject if any fail ───────────────────────────────

    if sec:
        # Honeypot
        if sec.get("is_honeypot") == "1":
            hard_fails.append("HONEYPOT — cannot sell")
        checks["Honeypot"] = (sec.get("is_honeypot") != "1", "")

        # Contract verified
        is_open = sec.get("is_open_source", "0") == "1"
        if not is_open:
            hard_fails.append("CONTRACT UNVERIFIED — source code hidden")
        checks["Verified contract"] = (is_open, "")

        # Taxes
        buy_tax  = float(sec.get("buy_tax",  "0") or 0) * 100
        sell_tax = float(sec.get("sell_tax", "0") or 0) * 100
        if sell_tax > 15:
            hard_fails.append("SELL TAX %.0f%% — exit trap" % sell_tax)
        if buy_tax > 15:
            hard_fails.append("BUY TAX %.0f%% — entry trap" % buy_tax)
        checks["Buy tax ≤10%%"]  = (buy_tax  <= 10, "%.1f%%" % buy_tax)
        checks["Sell tax ≤10%%"] = (sell_tax <= 10, "%.1f%%" % sell_tax)

        # Asymmetric tax (sell tax notably higher than buy = dump trap)
        if sell_tax > buy_tax + 5:
            hard_fails.append("ASYMMETRIC TAX — sell %.0f%% vs buy %.0f%%" % (sell_tax, buy_tax))

    if hard_fails:
        return (False, "FAIL", 0, checks, hard_fails[0])

    # ── SCORED SECURITY CHECKS (40 pts) ──────────────────────────────────────

    if sec:
        def flag(key, pts, label):
            nonlocal score
            val = sec.get(key, "0")
            passed = (val == "0" or val is None or val == "")
            if passed:
                score += pts
            checks[label] = (passed, "")
            return passed

        flag("is_mintable",               8,  "No mint function")
        flag("is_blacklisted",            8,  "No blacklist function")
        flag("transfer_pausable",         7,  "No transfer pause")
        flag("is_proxy",                  6,  "No proxy contract")
        flag("hidden_owner",              5,  "No hidden owner")
        flag("selfdestruct",              4,  "No self-destruct")
        flag("can_take_back_ownership",   2,  "Cannot reclaim ownership")

        # Contract renounced
        owner = (sec.get("owner_address") or "").lower()
        renounced = owner in ("", "0x0000000000000000000000000000000000000000")
        if renounced:
            score += 5
        checks["Contract renounced"] = (renounced, "owner: %s" % (owner[:10] + "..." if owner else "none"))

    # ── SCORED DISTRIBUTION CHECKS (25 pts) ──────────────────────────────────

    if sec:
        # Dev/creator wallet
        creator_pct = float(sec.get("creator_percent", "0") or 0) * 100
        dev_ok = creator_pct < 5
        if dev_ok:
            score += 10
        checks["Dev wallet <5%%"] = (dev_ok, "%.1f%%" % creator_pct)

        # Top 10 holders < 20%
        holders_list = sec.get("holders", []) or []
        top10_pct = sum(float(h.get("percent", 0) or 0) * 100 for h in holders_list[:10])
        top10_ok = top10_pct < 20
        if top10_ok:
            score += 10
        checks["Top 10 holders <20%%"] = (top10_ok, "%.1f%%" % top10_pct)

        # LP locked
        lp_locked = False
        lp_holders = sec.get("lp_holders", []) or []
        for lp in lp_holders:
            if lp.get("is_locked") == 1 or str(lp.get("is_locked")) == "1":
                lp_locked = True
                break
        if lp_locked:
            score += 5
        checks["LP locked"] = (lp_locked, "")

    # ── SCORED MARKET CHECKS (35 pts) ────────────────────────────────────────

    if pair:
        liq_usd  = float(pair.get("liquidity", {}).get("usd", 0) or 0)
        fdv      = float(pair.get("fdv", 0) or 0)
        vol_24h  = float(pair.get("volume", {}).get("h24", 0) or 0)
        txns_24h = pair.get("txns", {}).get("h24", {})
        buys_24h = int(txns_24h.get("buys",  0) or 0)
        sels_24h = int(txns_24h.get("sells", 0) or 0)
        price_chg_24h = float(pair.get("priceChange", {}).get("h24", 0) or 0)
        pair_age_ms   = pair.get("pairCreatedAt")
        pair_age_h    = ((time.time() * 1000 - pair_age_ms) / 3600000) if pair_age_ms else 0

        # MC range $500K–$5M
        mc_ok = 500_000 <= fdv <= 5_000_000
        if mc_ok:
            score += 10
        elif fdv < 500_000:
            score += 3   # too small but not zero
        checks["MC $500K–$5M"] = (mc_ok, fv(fdv))

        # Liquidity > $100K
        liq_ok = liq_usd >= 100_000
        if liq_ok:
            score += 8
        elif liq_usd >= 50_000:
            score += 3
        checks["Liquidity >$100K"] = (liq_ok, fv(liq_usd))

        # Liquidity ≥ 10% of MC (depth quality)
        liq_ratio = liq_usd / fdv * 100 if fdv > 0 else 0
        liq_ratio_ok = liq_ratio >= 10
        if liq_ratio_ok:
            score += 5
        checks["Liq ≥10%% of MC"] = (liq_ratio_ok, "%.1f%%" % liq_ratio)

        # Volume $50K+ in 24h
        vol_ok = vol_24h >= 50_000
        if vol_ok:
            score += 5
        checks["Volume >$50K 24h"] = (vol_ok, fv(vol_24h))

        # Volume/MC ratio 20–100% (organic)
        vol_mc_ratio = vol_24h / fdv * 100 if fdv > 0 else 0
        vol_organic  = 20 <= vol_mc_ratio <= 100
        if vol_organic:
            score += 5
        elif vol_mc_ratio > 100:
            checks["Volume organic"] = (False, "%.0f%% — possible bots" % vol_mc_ratio)
        else:
            checks["Volume organic"] = (False, "%.0f%% — low activity" % vol_mc_ratio)
        if vol_organic:
            checks["Volume organic"] = (True, "%.0f%% of MC" % vol_mc_ratio)

        # Buy/sell ratio > 1.2
        bs_ratio = buys_24h / sels_24h if sels_24h > 0 else (2.0 if buys_24h > 0 else 1.0)
        bs_ok    = bs_ratio >= 1.2
        if bs_ok:
            score += 7
        checks["Buy/sell >1.2x"] = (bs_ok, "%.2fx (%d/%d)" % (bs_ratio, buys_24h, sels_24h))

        # Token age 24h–7 days
        age_ok = 24 <= pair_age_h <= 168
        if age_ok:
            score += 3
        elif pair_age_h < 24:
            checks["Age 24h–7 days"] = (False, "%.1fh old — too new" % pair_age_h)
        else:
            checks["Age 24h–7 days"] = (False, "%.0fd old — pump may be done" % (pair_age_h / 24))
        if age_ok:
            checks["Age 24h–7 days"] = (True, "%.1fh" % pair_age_h)

    # ── Grade ─────────────────────────────────────────────────────────────────

    if score >= 80:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 50:
        grade = "C"
    else:
        grade = "D"

    passed = grade in ("A", "B")
    return (passed, grade, score, checks, None)

# ── Alert builder ─────────────────────────────────────────────────────────────

def build_alert(address, chain_label, name, symbol, grade, score, checks, pair):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    grade_line = {
        "A": "A  STRONG CANDIDATE",
        "B": "B  MODERATE — proceed carefully",
    }.get(grade, grade)

    passed_checks  = [k for k, (p, _) in checks.items() if p]
    failed_checks  = [k for k, (p, _) in checks.items() if not p]
    detail_lines   = []
    for k, (p, note) in checks.items():
        icon = "PASS" if p else "FAIL"
        line = "  %s  %s" % (icon, k)
        if note:
            line += "  [%s]" % note
        detail_lines.append(line)

    market_lines = ""
    if pair:
        fdv     = float(pair.get("fdv", 0) or 0)
        liq_usd = float(pair.get("liquidity", {}).get("usd", 0) or 0)
        vol_24h = float(pair.get("volume", {}).get("h24", 0) or 0)
        price   = pair.get("priceUsd", "N/A")
        dex_url = pair.get("url", "")
        market_lines = (
            "\n=== MARKET DATA ===\n"
            "Price:      $%s\n"
            "Market Cap: %s\n"
            "Liquidity:  %s\n"
            "Vol 24h:    %s\n"
            "%s"
        ) % (
            price, fv(fdv), fv(liq_usd), fv(vol_24h),
            ("\nChart: %s" % dex_url) if dex_url else "",
        )

    return (
        "MEMECOIN ALERT — GRADE %s\n"
        "\n"
        "Token:   %s (%s)\n"
        "Chain:   %s\n"
        "Score:   %d / 100\n"
        "Grade:   %s\n"
        "%s"
        "\n"
        "=== CHECKS (%d pass / %d fail) ===\n"
        "%s\n"
        "\n"
        "Address: %s\n"
        "\n"
        "NOT financial advice. Always verify\n"
        "manually before entering.\n"
        "Time: %s UTC"
    ) % (
        grade,
        name, symbol,
        chain_label,
        score,
        grade_line,
        market_lines,
        len(passed_checks), len(failed_checks),
        "\n".join(detail_lines),
        address,
        now,
    )

def build_hardfail_alert(address, chain_label, name, reason):
    return (
        "MEMECOIN REJECTED — %s\n"
        "\n"
        "Token:  %s\n"
        "Chain:  %s\n"
        "Reason: %s\n"
        "\n"
        "This token failed a hard security gate.\n"
        "Do NOT buy — this is a danger signal.\n"
        "\n"
        "Address: %s\n"
        "Time: %s UTC"
    ) % (
        reason.split(" ")[0],
        name, chain_label, reason, address,
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
    )

# ── Main scanner loop ─────────────────────────────────────────────────────────

async def scan_loop(bot):
    seen = load_seen()
    scan_count = 0

    while True:
        scan_count += 1
        log.info("Memecoin scan #%d..." % scan_count)
        alerts_sent = 0

        data = safe_get(DEXSCREEN_LATEST)
        if not data:
            await asyncio.sleep(SCAN_INTERVAL)
            continue

        tokens = data if isinstance(data, list) else data.get("data", [])

        for token in tokens:
            chain   = token.get("chainId", "")
            address = token.get("tokenAddress", "")

            if not address or chain not in CHAIN_MAP:
                continue

            uid = "%s_%s" % (chain, address.lower())
            if uid in seen:
                continue
            seen.add(uid)

            chain_info = CHAIN_MAP[chain]
            chain_id   = chain_info["goplus_id"]
            chain_label = chain_info["label"]

            # Get token name from DexScreener pair
            pair = fetch_dexscreen(address)
            time.sleep(0.3)

            if not pair:
                continue

            name   = pair.get("baseToken", {}).get("name",   "Unknown")
            symbol = pair.get("baseToken", {}).get("symbol", "???")

            log.info("Analysing: %s (%s) on %s" % (name, symbol, chain_label))

            result = analyse_token(address, chain_id, chain_label)
            time.sleep(0.5)

            if result is None:
                continue

            passed, grade, score, checks, hard_fail = result

            if hard_fail:
                # Send danger alert for honeypots and severe tax traps
                if "HONEYPOT" in hard_fail or "TAX" in hard_fail:
                    try:
                        await bot.send_message(
                            chat_id=CHAT_ID,
                            text=build_hardfail_alert(address, chain_label, name, hard_fail),
                            disable_web_page_preview=True,
                        )
                        alerts_sent += 1
                        log.info("Hard fail alert: %s — %s" % (symbol, hard_fail))
                        await asyncio.sleep(2)
                    except Exception as e:
                        log.error("Alert error: %s" % e)
                continue

            if passed:
                msg = build_alert(address, chain_label, name, symbol, grade, score, checks, pair)
                try:
                    await bot.send_message(
                        chat_id=CHAT_ID,
                        text=msg,
                        disable_web_page_preview=True,
                    )
                    save_result({
                        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
                        "name": name, "symbol": symbol, "grade": grade,
                        "score": score, "chain": chain_label, "address": address,
                    })
                    alerts_sent += 1
                    log.info("Alert sent: %s grade=%s score=%d" % (symbol, grade, score))
                    await asyncio.sleep(2)
                except Exception as e:
                    log.error("Alert error: %s" % e)

        save_seen(seen)
        log.info("Scan #%d done. %d alerts sent." % (scan_count, alerts_sent))
        await asyncio.sleep(SCAN_INTERVAL)

# ── Manual /scan command ──────────────────────────────────────────────────────

async def handle_scan(bot, chat_id, args):
    if not args:
        await bot.send_message(
            chat_id=chat_id,
            text=(
                "Usage: /scan ADDRESS [CHAIN]\n"
                "Chains: eth, bsc, base\n\n"
                "Example:\n"
                "/scan 0xabc123... eth"
            )
        )
        return

    address = args[0].strip()
    chain_input = args[1].lower() if len(args) > 1 else "eth"

    chain_lookup = {"eth": "ethereum", "bsc": "bsc", "base": "base",
                    "ethereum": "ethereum", "bnb": "bsc"}
    chain = chain_lookup.get(chain_input, "ethereum")
    chain_info  = CHAIN_MAP[chain]
    chain_id    = chain_info["goplus_id"]
    chain_label = chain_info["label"]

    await bot.send_message(chat_id=chat_id,
                           text="Scanning %s on %s..." % (address[:12] + "...", chain_label))

    pair   = fetch_dexscreen(address)
    name   = pair.get("baseToken", {}).get("name",   "Unknown") if pair else "Unknown"
    symbol = pair.get("baseToken", {}).get("symbol", "???")     if pair else "???"

    result = analyse_token(address, chain_id, chain_label)

    if result is None:
        await bot.send_message(chat_id=chat_id,
                               text="Could not fetch data for this token. Check the address and chain.")
        return

    passed, grade, score, checks, hard_fail = result

    if hard_fail:
        await bot.send_message(
            chat_id=chat_id,
            text=build_hardfail_alert(address, chain_label, name, hard_fail),
            disable_web_page_preview=True,
        )
        return

    msg = build_alert(address, chain_label, name, symbol, grade, score, checks, pair)
    await bot.send_message(chat_id=chat_id, text=msg, disable_web_page_preview=True)

async def handle_recent(bot, chat_id):
    results = load_results()
    if not results:
        await bot.send_message(chat_id=chat_id,
                               text="No tokens have passed screening yet.")
        return
    recent = list(reversed(results[-10:]))
    lines  = ["RECENT PASSED TOKENS\n"]
    for r in recent:
        lines.append("%s  %s (%s)  Grade %s  Score %d  [%s]" % (
            r["time"], r["name"], r["symbol"], r["grade"], r["score"], r["chain"]))
    await bot.send_message(chat_id=chat_id, text="\n".join(lines))

# ── Dispatcher ────────────────────────────────────────────────────────────────

async def dispatch(bot, message):
    text = (message.get("text") or "").strip()
    if not text.startswith("/"):
        return
    chat_id = message["chat"]["id"]
    parts   = text.split()
    cmd     = parts[0].lower().split("@")[0]
    args    = parts[1:]

    if cmd == "/help":
        await bot.send_message(
            chat_id=chat_id,
            text=(
                "MEMECOIN SCANNER — COMMANDS\n\n"
                "/scan ADDRESS [CHAIN]\n"
                "  Scan any token manually\n"
                "  Chains: eth, bsc, base\n"
                "  Example: /scan 0xabc... eth\n\n"
                "/recent\n"
                "  Last 10 tokens that passed\n\n"
                "Auto-scan runs every 5 minutes\n"
                "across ETH, BSC, and Base.\n\n"
                "Grades:\n"
                "  A (80+)  — strong candidate\n"
                "  B (65+)  — moderate, be careful\n"
                "  C/D      — not alerted (too risky)\n\n"
                "26 checks across security,\n"
                "distribution, and market quality."
            )
        )
    elif cmd == "/scan":
        await handle_scan(bot, chat_id, args)
    elif cmd == "/recent":
        await handle_recent(bot, chat_id)

# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    log.info("Memecoin Scanner starting...")
    bot    = Bot(token=TELEGRAM_TOKEN)
    offset = 0

    await bot.send_message(
        chat_id=CHAT_ID,
        text=(
            "Memecoin Scanner Online!\n\n"
            "Auto-scanning ETH, BSC, and Base\n"
            "every 5 minutes for new tokens.\n\n"
            "Running 26 checks per token:\n"
            "  SECURITY  — honeypot, taxes, functions,\n"
            "              ownership, contract safety\n"
            "  DISTRIBUTION — dev wallet, top holders,\n"
            "                 LP lock status\n"
            "  MARKET    — MC range, liquidity depth,\n"
            "              volume quality, buy/sell ratio\n\n"
            "Alerts sent for Grade A (80+) and B (65+).\n"
            "Honeypots and tax traps flagged immediately.\n\n"
            "Commands:\n"
            "  /scan ADDRESS [eth/bsc/base]\n"
            "  /recent — last 10 passed tokens\n\n"
            "NOT financial advice. Always verify\n"
            "manually before entering any position."
        )
    )

    asyncio.create_task(scan_loop(bot))

    while True:
        try:
            updates = await bot.get_updates(
                offset=offset, timeout=30, allowed_updates=["message"])
            for update in updates:
                offset = update.update_id + 1
                if update.message:
                    await dispatch(bot, update.message.to_dict())
        except Exception as e:
            log.error("Poll error: %s" % e)
            await asyncio.sleep(5)
        await asyncio.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
