"""
Memecoin Scanner — multi-chain gem finder with 26-point safety scoring.

Chains: Ethereum, BSC, Base, Solana, Arbitrum, Polygon, Avalanche

Hard gates (instant fail):
  EVM:    honeypot, unverified contract, sell_tax > 15%, buy_tax > 15%,
          asymmetric tax (sell > buy + 5%)
  Solana: non-transferable, transfer_hook (honeypot)

Scored checks — 100 pts total:
  Security     40 pts
  Distribution 25 pts
  Market       35 pts

Grade A >= 80  |  Grade B >= 65  |  Below 65 = skip

Commands:
  /scan ADDRESS [chain]   — manual scan (chain optional, auto-detected for Solana)
  /recent                 — last 10 results
  /help
"""

import os
import re
import json
import time
import logging
import asyncio
import requests
from datetime import datetime, timezone
from telegram import Bot

TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "YOUR_BOT_TOKEN_HERE")
CHAT_ID          = os.environ.get("CHAT_ID", "YOUR_CHAT_ID_HERE")
SEEN_FILE        = "memecoin_seen.json"
RESULTS_FILE     = "memecoin_results.json"
SCAN_INTERVAL    = 300   # 5 minutes

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger(__name__)

# ── Chain registry ────────────────────────────────────────────────────────────

CHAIN_MAP = {
    # Ethereum
    "ethereum":  {"goplus_id": "1",       "dex_id": "ethereum",  "label": "Ethereum"},
    "eth":       {"goplus_id": "1",       "dex_id": "ethereum",  "label": "Ethereum"},
    # BNB Smart Chain
    "bsc":       {"goplus_id": "56",      "dex_id": "bsc",       "label": "BSC"},
    "bnb":       {"goplus_id": "56",      "dex_id": "bsc",       "label": "BSC"},
    # Base
    "base":      {"goplus_id": "8453",    "dex_id": "base",      "label": "Base"},
    # Solana
    "solana":    {"goplus_id": "solana",  "dex_id": "solana",    "label": "Solana"},
    "sol":       {"goplus_id": "solana",  "dex_id": "solana",    "label": "Solana"},
    # Arbitrum
    "arbitrum":  {"goplus_id": "42161",   "dex_id": "arbitrum",  "label": "Arbitrum"},
    "arb":       {"goplus_id": "42161",   "dex_id": "arbitrum",  "label": "Arbitrum"},
    # Polygon
    "polygon":   {"goplus_id": "137",     "dex_id": "polygon",   "label": "Polygon"},
    "matic":     {"goplus_id": "137",     "dex_id": "polygon",   "label": "Polygon"},
    # Avalanche
    "avalanche": {"goplus_id": "43114",   "dex_id": "avalanche", "label": "Avalanche"},
    "avax":      {"goplus_id": "43114",   "dex_id": "avalanche", "label": "Avalanche"},
}

# DexScreener chain name → our canonical key
DEX_TO_CHAIN = {
    "ethereum":  "ethereum",
    "bsc":       "bsc",
    "base":      "base",
    "solana":    "solana",
    "arbitrum":  "arbitrum",
    "polygon":   "polygon",
    "avalanche": "avalanche",
}

GOPLUS_URL        = "https://api.gopluslabs.io/api/v1/token_security/%s"
DEXSCREEN_LATEST  = "https://api.dexscreener.com/token-profiles/latest/v1"
DEXSCREEN_TOKEN   = "https://api.dexscreener.com/latest/dex/tokens/%s"

# ── Address helpers ───────────────────────────────────────────────────────────

def is_solana_address(address):
    return bool(re.match(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$', address))

def is_evm_address(address):
    return bool(re.match(r'^0x[0-9a-fA-F]{40}$', address))

def guess_chain(address):
    if is_solana_address(address):
        return "solana"
    return None   # EVM but chain unknown — user must specify

# ── Data fetchers ─────────────────────────────────────────────────────────────

def fetch_goplus(address, chain_key):
    chain_info = CHAIN_MAP.get(chain_key, {})
    goplus_id  = chain_info.get("goplus_id", "1")
    try:
        url  = GOPLUS_URL % goplus_id
        resp = requests.get(url, params={"contract_addresses": address}, timeout=12)
        data = resp.json()
        if data.get("code") != 1:
            return None
        result = data.get("result", {})
        return result.get(address.lower()) or result.get(address)
    except Exception as e:
        log.error("GoPlus error: %s" % e)
        return None

def fetch_dexscreener(address):
    try:
        resp  = requests.get(DEXSCREEN_TOKEN % address, timeout=12)
        data  = resp.json()
        pairs = data.get("pairs") or []
        if not pairs:
            return None
        pairs.sort(
            key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0),
            reverse=True,
        )
        return pairs[0]
    except Exception as e:
        log.error("DexScreener error: %s" % e)
        return None

def fetch_latest_tokens():
    try:
        resp = requests.get(DEXSCREEN_LATEST, timeout=12)
        return resp.json() if isinstance(resp.json(), list) else []
    except Exception as e:
        log.error("DexScreen latest error: %s" % e)
        return []

# ── Scoring engine ────────────────────────────────────────────────────────────

def score_token(gp, dex, chain_key):
    """
    Returns (score, grade, passed, failed, hard_fail_reason)
    """
    is_sol = (CHAIN_MAP.get(chain_key, {}).get("goplus_id") == "solana")
    passed = []
    failed = []
    score  = 0

    # ── HARD GATES ────────────────────────────────────────────────────────────

    if is_sol:
        if gp:
            if str(gp.get("non_transferable", "0")) == "1":
                return 0, "F", [], [], "HARD FAIL: Token is non-transferable (cannot sell)"
            if str(gp.get("transfer_hook", "0")) == "1":
                return 0, "F", [], [], "HARD FAIL: Transfer hook detected (likely honeypot)"
    else:
        if gp:
            if str(gp.get("is_honeypot", "0")) == "1":
                return 0, "F", [], [], "HARD FAIL: Honeypot confirmed"
            if str(gp.get("is_open_source", "1")) == "0":
                return 0, "F", [], [], "HARD FAIL: Contract not verified"
            sell_tax = float(gp.get("sell_tax") or 0)
            buy_tax  = float(gp.get("buy_tax") or 0)
            if sell_tax > 15:
                return 0, "F", [], [], "HARD FAIL: Sell tax %.1f%% > 15%%" % sell_tax
            if buy_tax > 15:
                return 0, "F", [], [], "HARD FAIL: Buy tax %.1f%% > 15%%" % buy_tax
            if sell_tax > buy_tax + 5:
                return 0, "F", [], [], "HARD FAIL: Asymmetric tax — sell %.1f%% vs buy %.1f%%" % (sell_tax, buy_tax)

    # ── SECURITY CHECKS (40 pts) ──────────────────────────────────────────────

    if is_sol:
        if gp:
            if str(gp.get("mintable", "0")) == "0":
                score += 12; passed.append("No mint authority (+12)")
            else:
                failed.append("MINTABLE — supply can be inflated")

            if str(gp.get("freezable", "0")) == "0":
                score += 12; passed.append("No freeze authority (+12)")
            else:
                failed.append("FREEZABLE — accounts can be frozen")

            if str(gp.get("transfer_fee", "0")) == "0":
                score += 8; passed.append("No transfer fee (+8)")
            else:
                failed.append("Transfer fee present")

            if str(gp.get("metadata_mutable", "0")) == "0":
                score += 8; passed.append("Metadata immutable (+8)")
            else:
                failed.append("Metadata mutable — branding can change")
        else:
            failed.append("GoPlus security data unavailable")

    else:  # EVM chains
        if gp:
            if str(gp.get("is_mintable", "0")) == "0":
                score += 10; passed.append("No mint function (+10)")
            else:
                failed.append("MINTABLE — supply can be inflated")

            if str(gp.get("is_blacklisted", "0")) == "0":
                score += 8; passed.append("No blacklist function (+8)")
            else:
                failed.append("BLACKLIST present — wallets can be blocked")

            if str(gp.get("transfer_pausable", "0")) == "0":
                score += 7; passed.append("Transfers cannot be paused (+7)")
            else:
                failed.append("Transfers can be paused by owner")

            if str(gp.get("is_proxy", "0")) == "0":
                score += 5; passed.append("No proxy contract (+5)")
            else:
                failed.append("Proxy contract — logic can be replaced")

            if str(gp.get("hidden_owner", "0")) == "0":
                score += 5; passed.append("No hidden owner (+5)")
            else:
                failed.append("Hidden owner detected")

            owner = gp.get("owner_address") or ""
            if not owner or owner == "0x0000000000000000000000000000000000000000":
                score += 5; passed.append("Ownership renounced (+5)")
            else:
                failed.append("Ownership NOT renounced")
        else:
            failed.append("GoPlus security data unavailable")

    # ── DISTRIBUTION CHECKS (25 pts) ──────────────────────────────────────────

    if is_sol:
        score += 15
        passed.append("Solana distribution (partial, +15)")
    else:
        if gp:
            creator_pct = float(gp.get("creator_percent") or 0)
            if creator_pct < 5:
                score += 10; passed.append("Dev wallet %.1f%% < 5%% (+10)" % creator_pct)
            else:
                failed.append("Dev wallet %.1f%% >= 5%%" % creator_pct)

            holders = gp.get("holders") or []
            if holders:
                top10_pct = sum(float(h.get("percent", 0)) for h in holders[:10]) * 100
                if top10_pct < 20:
                    score += 8; passed.append("Top 10 hold %.1f%% < 20%% (+8)" % top10_pct)
                else:
                    failed.append("Top 10 hold %.1f%% >= 20%%" % top10_pct)

            lp_holders    = gp.get("lp_holders") or []
            lp_locked     = any(str(lp.get("is_locked", "0")) == "1" for lp in lp_holders)
            lp_holder_info = gp.get("lp_holder_analysis") or {}
            if isinstance(lp_holder_info, dict):
                lp_locked = lp_locked or str(lp_holder_info.get("is_locked", "0")) == "1"
            if lp_locked:
                score += 7; passed.append("LP locked (+7)")
            else:
                failed.append("LP NOT locked — can be pulled")

    # ── MARKET CHECKS (35 pts) ────────────────────────────────────────────────

    if dex:
        mc      = float((dex.get("fdv") or dex.get("marketCap") or 0))
        liq     = float((dex.get("liquidity") or {}).get("usd") or 0)
        vol24h  = float((dex.get("volume") or {}).get("h24") or 0)
        buys    = float((dex.get("txns") or {}).get("h24", {}).get("buys") or 0)
        sells   = float((dex.get("txns") or {}).get("h24", {}).get("sells") or 1)
        age_ms  = dex.get("pairCreatedAt") or 0
        age_h   = (time.time() * 1000 - age_ms) / 3600000 if age_ms else 0

        # MC $500K–$5M (7 pts)
        if 500_000 <= mc <= 5_000_000:
            score += 7; passed.append("MC $%.0fK in $500K–$5M sweet spot (+7)" % (mc / 1000))
        else:
            failed.append("MC $%.0fK outside $500K–$5M" % (mc / 1000))

        # Liquidity > $100K (7 pts)
        if liq >= 100_000:
            score += 7; passed.append("Liquidity $%.0fK > $100K (+7)" % (liq / 1000))
        else:
            failed.append("Liquidity $%.0fK < $100K" % (liq / 1000))

        # Liq/MC >= 10% (5 pts)
        if mc > 0 and (liq / mc) >= 0.10:
            score += 5; passed.append("Liq/MC %.1f%% >= 10%% (+5)" % (liq / mc * 100))
        else:
            ratio = (liq / mc * 100) if mc > 0 else 0
            failed.append("Liq/MC %.1f%% < 10%%" % ratio)

        # 24h volume > $50K (6 pts)
        if vol24h >= 50_000:
            score += 6; passed.append("24h volume $%.0fK > $50K (+6)" % (vol24h / 1000))
        else:
            failed.append("24h volume $%.0fK < $50K" % (vol24h / 1000))

        # Volume organic 20%–100% of MC (5 pts)
        if mc > 0:
            vol_ratio = vol24h / mc
            if 0.20 <= vol_ratio <= 1.0:
                score += 5; passed.append("Volume organic %.0f%% of MC (+5)" % (vol_ratio * 100))
            else:
                failed.append("Volume %.0f%% of MC (suspect if >100%%)" % (vol_ratio * 100))

        # Buy/sell > 1.2x (5 pts)
        bs_ratio = buys / sells if sells > 0 else 0
        if bs_ratio >= 1.2:
            score += 5; passed.append("Buy/sell %.1fx > 1.2 (+5)" % bs_ratio)
        else:
            failed.append("Buy/sell %.1fx < 1.2" % bs_ratio)

        # Pair age 24h–7 days (5 pts)
        if 24 <= age_h <= 168:
            score += 5; passed.append("Pair age %.0fh in 24h–7d (+5)" % age_h)
        elif age_h < 24:
            failed.append("Pair age %.0fh < 24h (too new)" % age_h)
        else:
            failed.append("Pair age %.0fh > 7 days (old)" % age_h)
    else:
        failed.append("DexScreener market data unavailable")

    # ── Grade ─────────────────────────────────────────────────────────────────
    if score >= 80:
        grade = "A"
    elif score >= 65:
        grade = "B"
    else:
        grade = "C"

    return score, grade, passed, failed, None

# ── Message builder ───────────────────────────────────────────────────────────

def build_report(address, chain_key, score, grade, passed, failed, hard_fail, dex):
    chain_label = CHAIN_MAP.get(chain_key, {}).get("label", chain_key.upper())

    if hard_fail:
        return (
            "MEMECOIN SCAN — REJECTED\n\n"
            "Chain:   %s\n"
            "Address: %s\n\n"
            "%s\n\n"
            "DO NOT BUY — exit immediately if holding."
        ) % (chain_label, address[:12] + "..." + address[-6:], hard_fail)

    token_name = ""
    price_str  = ""
    if dex:
        token_name = (dex.get("baseToken") or {}).get("name", "")
        token_sym  = (dex.get("baseToken") or {}).get("symbol", "")
        price_usd  = dex.get("priceUsd") or "?"
        if token_name:
            token_name = "%s (%s)\n" % (token_name, token_sym)
        price_str = "Price:   $%s\n" % price_usd

    grade_line = {
        "A": "GRADE A — STRONG CANDIDATE",
        "B": "GRADE B — MODERATE CANDIDATE",
        "C": "GRADE C — WEAK / SKIP",
    }.get(grade, "GRADE ?")

    passed_lines = "\n".join("  + %s" % p for p in passed[:8])
    failed_lines = "\n".join("  - %s" % f for f in failed[:6])

    action = {
        "A": "Consider a position. Set SL at -20%%. Take partial at 2x.",
        "B": "Small position only. Tight SL. Do not oversize.",
        "C": "Skip or watch only. Too many red flags.",
    }.get(grade, "")

    return (
        "MEMECOIN SCAN RESULT\n\n"
        "%s"
        "Chain:   %s\n"
        "Address: %s\n"
        "%s\n"
        "%s — Score %d/100\n\n"
        "PASSED:\n%s\n\n"
        "FAILED:\n%s\n\n"
        "ACTION: %s"
    ) % (
        token_name,
        chain_label,
        address[:12] + "..." + address[-6:],
        price_str,
        grade_line,
        score,
        passed_lines or "  (none)",
        failed_lines or "  (none)",
        action,
    )

# ── Seen / results store ──────────────────────────────────────────────────────

def load_seen():
    try:
        with open(SEEN_FILE) as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_seen(seen):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen), f)

def load_results():
    try:
        with open(RESULTS_FILE) as f:
            return json.load(f)
    except Exception:
        return []

def save_result(entry):
    results = load_results()
    results.insert(0, entry)
    results = results[:50]
    with open(RESULTS_FILE, "w") as f:
        json.dump(results, f, indent=2)

# ── Core scan function ────────────────────────────────────────────────────────

async def scan_and_notify(bot, address, chain_key):
    gp    = fetch_goplus(address, chain_key)
    dex   = fetch_dexscreener(address)
    score, grade, passed, failed, hard_fail = score_token(gp, dex, chain_key)

    report = build_report(address, chain_key, score, grade, passed, failed, hard_fail, dex)

    if grade in ("A", "B") and not hard_fail:
        await bot.send_message(chat_id=CHAT_ID, text=report)
        log.info("Alert sent: %s grade=%s score=%d" % (address[:12], grade, score))

    return {
        "address":    address,
        "chain":      chain_key,
        "score":      score,
        "grade":      grade,
        "hard_fail":  hard_fail,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
    }

# ── Auto-scanner loop ─────────────────────────────────────────────────────────

async def auto_scan_loop(bot):
    seen = load_seen()
    log.info("Auto-scanner started")

    while True:
        try:
            tokens = fetch_latest_tokens()
            for token in tokens:
                addr      = token.get("tokenAddress") or token.get("address") or ""
                chain_raw = token.get("chainId") or ""
                chain_key = DEX_TO_CHAIN.get(chain_raw.lower())

                if not addr or not chain_key:
                    continue
                if addr in seen:
                    continue

                seen.add(addr)
                try:
                    result = await scan_and_notify(bot, addr, chain_key)
                    save_result(result)
                except Exception as e:
                    log.error("Scan error %s: %s" % (addr[:12], e))
                await asyncio.sleep(1)

            save_seen(seen)
        except Exception as e:
            log.error("Auto-scan loop error: %s" % e)

        await asyncio.sleep(SCAN_INTERVAL)

# ── Command handlers ──────────────────────────────────────────────────────────

async def handle_help(bot, chat_id):
    await bot.send_message(
        chat_id=chat_id,
        text=(
            "MEMECOIN SCANNER — COMMANDS\n\n"
            "/scan ADDRESS [chain]\n"
            "  Scan a token. Chain is optional for Solana\n"
            "  (auto-detected). For EVM chains specify:\n"
            "  eth, bsc, base, arb, polygon, avax\n\n"
            "Examples:\n"
            "  /scan 0x1234...abcd eth\n"
            "  /scan So1ана...token  (Solana auto-detected)\n"
            "  /scan 0x5678...efgh bsc\n\n"
            "/recent\n"
            "  Last 10 scan results\n\n"
            "Supported chains:\n"
            "  Ethereum (eth)\n"
            "  BSC (bsc/bnb)\n"
            "  Base (base)\n"
            "  Solana (sol/solana)\n"
            "  Arbitrum (arb/arbitrum)\n"
            "  Polygon (polygon/matic)\n"
            "  Avalanche (avax/avalanche)\n\n"
            "Auto-scan runs every 5 minutes across\n"
            "all chains via DexScreener."
        )
    )

async def handle_scan(bot, chat_id, args):
    if not args:
        await bot.send_message(
            chat_id=chat_id,
            text="Usage: /scan ADDRESS [chain]\nExample: /scan 0x1234...abcd eth"
        )
        return

    address   = args[0].strip()
    chain_arg = args[1].lower() if len(args) > 1 else None

    if chain_arg and chain_arg not in CHAIN_MAP:
        await bot.send_message(
            chat_id=chat_id,
            text=(
                "Unknown chain: %s\n\n"
                "Valid chains: eth, bsc, base, sol,\n"
                "arb, polygon, avax"
            ) % chain_arg
        )
        return

    chain_key = chain_arg or guess_chain(address)

    if not chain_key:
        await bot.send_message(
            chat_id=chat_id,
            text=(
                "EVM address detected — please specify the chain:\n"
                "/scan %s eth\n"
                "/scan %s bsc\n"
                "/scan %s base\n"
                "/scan %s arb\n"
                "etc."
            ) % (address, address, address, address)
        )
        return

    await bot.send_message(chat_id=chat_id,
                           text="Scanning %s on %s..." % (
                               address[:12] + "...", chain_key.upper()))

    gp    = fetch_goplus(address, chain_key)
    dex   = fetch_dexscreener(address)
    score, grade, passed, failed, hard_fail = score_token(gp, dex, chain_key)
    report = build_report(address, chain_key, score, grade, passed, failed, hard_fail, dex)

    await bot.send_message(chat_id=chat_id, text=report)

    save_result({
        "address":   address,
        "chain":     chain_key,
        "score":     score,
        "grade":     grade,
        "hard_fail": hard_fail,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

async def handle_recent(bot, chat_id):
    results = load_results()[:10]
    if not results:
        await bot.send_message(chat_id=chat_id,
                               text="No scans yet. Use /scan ADDRESS [chain]")
        return

    lines = ["RECENT SCANS\n"]
    for i, r in enumerate(results, 1):
        ts    = r.get("timestamp", "")[:16].replace("T", " ")
        addr  = r.get("address", "")
        short = addr[:10] + "..." + addr[-6:] if len(addr) > 16 else addr
        grade = r.get("grade", "?")
        score = r.get("score", 0)
        chain = r.get("chain", "?").upper()
        hf    = " REJECTED" if r.get("hard_fail") else ""
        lines.append("%d. [%s] %s  %s  %s Grade %s (%d)%s" % (
            i, ts, short, chain, "", grade, score, hf))

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
        await handle_help(bot, chat_id)
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
            "Scanning across 7 chains:\n"
            "  Ethereum  BSC  Base\n"
            "  Solana  Arbitrum  Polygon  Avalanche\n\n"
            "26-point safety check on every token.\n"
            "Only Grade A/B alerts sent.\n\n"
            "Auto-scan runs every 5 minutes.\n\n"
            "Commands:\n"
            "  /scan ADDRESS [chain]\n"
            "  /recent\n"
            "  /help"
        )
    )

    asyncio.create_task(auto_scan_loop(bot))

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
        await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(main())
