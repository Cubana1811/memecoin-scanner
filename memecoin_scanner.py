"""
Memecoin Scanner v2 — multi-chain gem finder with enhanced scoring.

Chains: Ethereum, BSC, Base, Solana, Arbitrum, Polygon, Avalanche

Hard gates (instant fail):
  EVM:    honeypot, unverified contract, sell_tax > 15%, buy_tax > 15%,
          asymmetric tax (sell > buy + 5%)
  Solana: non-transferable, transfer_hook (honeypot)

Scored checks — 100 pts total:
  Security         35 pts  (GoPlus)
  Distribution     25 pts  (GoPlus + Solscan for Solana)
  Market           25 pts  (DexScreener)
  Momentum         15 pts  (DexScreener multi-timeframe)

Grade A >= 80  |  Grade B >= 65  |  Below 65 = skip

Commands:
  /scan ADDRESS [chain]   — manual scan (Solana auto-detected)
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
    "ethereum":  {"goplus_id": "1",       "dex_id": "ethereum",  "label": "Ethereum"},
    "eth":       {"goplus_id": "1",       "dex_id": "ethereum",  "label": "Ethereum"},
    "bsc":       {"goplus_id": "56",      "dex_id": "bsc",       "label": "BSC"},
    "bnb":       {"goplus_id": "56",      "dex_id": "bsc",       "label": "BSC"},
    "base":      {"goplus_id": "8453",    "dex_id": "base",      "label": "Base"},
    "solana":    {"goplus_id": "solana",  "dex_id": "solana",    "label": "Solana"},
    "sol":       {"goplus_id": "solana",  "dex_id": "solana",    "label": "Solana"},
    "arbitrum":  {"goplus_id": "42161",   "dex_id": "arbitrum",  "label": "Arbitrum"},
    "arb":       {"goplus_id": "42161",   "dex_id": "arbitrum",  "label": "Arbitrum"},
    "polygon":   {"goplus_id": "137",     "dex_id": "polygon",   "label": "Polygon"},
    "matic":     {"goplus_id": "137",     "dex_id": "polygon",   "label": "Polygon"},
    "avalanche": {"goplus_id": "43114",   "dex_id": "avalanche", "label": "Avalanche"},
    "avax":      {"goplus_id": "43114",   "dex_id": "avalanche", "label": "Avalanche"},
}

DEX_TO_CHAIN = {
    "ethereum": "ethereum", "bsc": "bsc", "base": "base",
    "solana": "solana", "arbitrum": "arbitrum",
    "polygon": "polygon", "avalanche": "avalanche",
}

GOPLUS_URL       = "https://api.gopluslabs.io/api/v1/token_security/%s"
DEXSCREEN_LATEST = "https://api.dexscreener.com/token-profiles/latest/v1"
DEXSCREEN_TOKEN  = "https://api.dexscreener.com/latest/dex/tokens/%s"
SOLSCAN_HOLDERS  = "https://public-api.solscan.io/token/holders?tokenAddress=%s&limit=20&offset=0"

# ── Address helpers ───────────────────────────────────────────────────────────

def is_solana_address(address):
    return bool(re.match(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$', address))

def guess_chain(address):
    if is_solana_address(address):
        return "solana"
    return None

# ── Data fetchers ─────────────────────────────────────────────────────────────

def fetch_goplus(address, chain_key):
    goplus_id = CHAIN_MAP.get(chain_key, {}).get("goplus_id", "1")
    try:
        resp = requests.get(
            GOPLUS_URL % goplus_id,
            params={"contract_addresses": address},
            timeout=12,
        )
        data = resp.json()
        if not isinstance(data, dict) or data.get("code") != 1:
            return None
        result = data.get("result") or {}
        if not isinstance(result, dict):
            return None
        token_data = result.get(address.lower()) or result.get(address)
        if not isinstance(token_data, dict):
            return None
        return token_data
    except Exception as e:
        log.warning("GoPlus error: %s" % e)
        return None

def fetch_dexscreener(address):
    try:
        resp  = requests.get(DEXSCREEN_TOKEN % address, timeout=12)
        pairs = resp.json().get("pairs") or []
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

def fetch_solscan_holders(address):
    try:
        resp = requests.get(SOLSCAN_HOLDERS % address, timeout=8,
                            headers={"accept": "application/json"})
        if not resp.content:
            return [], 0
        data = resp.json()
        if not isinstance(data, dict):
            return [], 0
        return data.get("data") or [], data.get("total") or 0
    except Exception:
        return [], 0

def fetch_latest_tokens():
    try:
        data = requests.get(DEXSCREEN_LATEST, timeout=12).json()
        return data if isinstance(data, list) else []
    except Exception as e:
        log.error("DexScreen latest error: %s" % e)
        return []

# ── Scoring engine ────────────────────────────────────────────────────────────

def score_token(gp, dex, chain_key):
    """
    Returns (score, grade, passed, failed, hard_fail_reason)
    Total: 100 pts — Security(35) + Distribution(25) + Market(25) + Momentum(15)
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
                return 0, "F", [], [], "HARD FAIL: Transfer hook (honeypot)"
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
                return 0, "F", [], [], "HARD FAIL: Asymmetric tax sell %.1f%% vs buy %.1f%%" % (sell_tax, buy_tax)

    # ── SECURITY — 35 pts ─────────────────────────────────────────────────────

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
                score += 6; passed.append("No transfer fee (+6)")
            else:
                failed.append("Transfer fee present")

            if str(gp.get("metadata_mutable", "0")) == "0":
                score += 5; passed.append("Metadata immutable (+5)")
            else:
                failed.append("Metadata mutable")
        else:
            failed.append("GoPlus security data unavailable")

    else:
        if gp:
            if str(gp.get("is_mintable", "0")) == "0":
                score += 8; passed.append("No mint function (+8)")
            else:
                failed.append("MINTABLE — supply can be inflated")

            if str(gp.get("is_blacklisted", "0")) == "0":
                score += 7; passed.append("No blacklist (+7)")
            else:
                failed.append("BLACKLIST — wallets can be blocked")

            if str(gp.get("transfer_pausable", "0")) == "0":
                score += 6; passed.append("Transfers cannot be paused (+6)")
            else:
                failed.append("Transfers can be paused")

            if str(gp.get("is_proxy", "0")) == "0":
                score += 5; passed.append("No proxy contract (+5)")
            else:
                failed.append("Proxy contract — logic replaceable")

            if str(gp.get("hidden_owner", "0")) == "0":
                score += 5; passed.append("No hidden owner (+5)")
            else:
                failed.append("Hidden owner detected")

            owner = gp.get("owner_address") or ""
            if not owner or owner == "0x0000000000000000000000000000000000000000":
                score += 4; passed.append("Ownership renounced (+4)")
            else:
                failed.append("Ownership NOT renounced")
        else:
            failed.append("GoPlus security data unavailable")

    # ── DISTRIBUTION — 25 pts ─────────────────────────────────────────────────

    if is_sol:
        sol_holders, sol_total = fetch_solscan_holders(
            chain_key  # address passed via chain_key placeholder — handled in caller
        )
        # Note: address passed separately; handled below in the wrapper
        # Placeholder — real address is injected via score_token_full()

        if sol_total > 500:
            score += 8; passed.append("Holder count %d > 500 (+8)" % sol_total)
        elif sol_total > 200:
            score += 4; passed.append("Holder count %d > 200 (+4)" % sol_total)
        else:
            failed.append("Low holders %d < 200" % sol_total)

        if sol_holders:
            supply_vals = [float(h.get("amount", 0)) for h in sol_holders]
            total_supply = sum(supply_vals)
            if total_supply > 0:
                top3_pct = sum(supply_vals[:3]) / total_supply * 100
                if top3_pct < 15:
                    score += 10; passed.append("Top 3 hold %.1f%% < 15%% (+10)" % top3_pct)
                elif top3_pct < 25:
                    score += 5; passed.append("Top 3 hold %.1f%% < 25%% (+5)" % top3_pct)
                else:
                    failed.append("Top 3 hold %.1f%% — concentrated (+0)" % top3_pct)

                top10_pct = sum(supply_vals[:10]) / total_supply * 100
                if top10_pct < 30:
                    score += 7; passed.append("Top 10 hold %.1f%% < 30%% (+7)" % top10_pct)
                else:
                    failed.append("Top 10 hold %.1f%% — concentrated" % top10_pct)
        else:
            score += 10
            passed.append("Solana distribution (Solscan unavailable, partial +10)")

    else:
        if gp:
            # Dev wallet < 5%
            creator_pct = float(gp.get("creator_percent") or 0)
            if creator_pct < 5:
                score += 8; passed.append("Dev wallet %.1f%% < 5%% (+8)" % creator_pct)
            elif creator_pct < 10:
                score += 3; passed.append("Dev wallet %.1f%% < 10%% (+3)" % creator_pct)
            else:
                failed.append("Dev wallet %.1f%% >= 10%%" % creator_pct)

            # Top holder concentration (wash trading signal)
            holders = gp.get("holders") or []
            if holders:
                top3_pct  = sum(float(h.get("percent", 0)) for h in holders[:3]) * 100
                top10_pct = sum(float(h.get("percent", 0)) for h in holders[:10]) * 100

                if top3_pct < 15:
                    score += 7; passed.append("Top 3 hold %.1f%% < 15%% (+7)" % top3_pct)
                elif top3_pct < 25:
                    score += 3; passed.append("Top 3 hold %.1f%% < 25%% (+3)" % top3_pct)
                else:
                    failed.append("Top 3 hold %.1f%% — wash trading risk" % top3_pct)

                if top10_pct < 20:
                    score += 4; passed.append("Top 10 hold %.1f%% < 20%% (+4)" % top10_pct)
                else:
                    failed.append("Top 10 hold %.1f%% >= 20%%" % top10_pct)

            # Holder count
            holder_count = int(gp.get("holder_count") or 0)
            if holder_count > 500:
                score += 3; passed.append("Holder count %d > 500 (+3)" % holder_count)
            elif holder_count > 200:
                score += 1; passed.append("Holder count %d > 200 (+1)" % holder_count)
            else:
                failed.append("Low holder count %d" % holder_count)

            # LP locked
            lp_holders = gp.get("lp_holders") or []
            lp_locked  = any(str(lp.get("is_locked", "0")) == "1" for lp in lp_holders)
            lp_info    = gp.get("lp_holder_analysis") or {}
            if isinstance(lp_info, dict):
                lp_locked = lp_locked or str(lp_info.get("is_locked", "0")) == "1"
            if lp_locked:
                score += 3; passed.append("LP locked (+3)")
            else:
                failed.append("LP NOT locked — can be pulled")

    # ── MARKET — 25 pts ───────────────────────────────────────────────────────

    if dex:
        mc     = float((dex.get("fdv") or dex.get("marketCap") or 0))
        liq    = float((dex.get("liquidity") or {}).get("usd") or 0)
        vol24h = float((dex.get("volume") or {}).get("h24") or 0)
        vol1h  = float((dex.get("volume") or {}).get("h1") or 0)
        buys   = float((dex.get("txns") or {}).get("h24", {}).get("buys") or 0)
        sells  = float((dex.get("txns") or {}).get("h24", {}).get("sells") or 1)

        # MC $500K–$5M (5 pts)
        if 500_000 <= mc <= 5_000_000:
            score += 5; passed.append("MC $%.0fK in $500K–$5M sweet spot (+5)" % (mc / 1000))
        else:
            failed.append("MC $%.0fK outside $500K–$5M" % (mc / 1000))

        # Liquidity > $100K (5 pts)
        if liq >= 100_000:
            score += 5; passed.append("Liquidity $%.0fK > $100K (+5)" % (liq / 1000))
        elif liq >= 50_000:
            score += 2; passed.append("Liquidity $%.0fK > $50K (+2)" % (liq / 1000))
        else:
            failed.append("Liquidity $%.0fK < $50K" % (liq / 1000))

        # Liq/MC >= 10% (4 pts)
        if mc > 0 and (liq / mc) >= 0.10:
            score += 4; passed.append("Liq/MC %.1f%% >= 10%% (+4)" % (liq / mc * 100))
        else:
            ratio = (liq / mc * 100) if mc > 0 else 0
            failed.append("Liq/MC %.1f%% < 10%%" % ratio)

        # 24h volume > $50K (4 pts)
        if vol24h >= 50_000:
            score += 4; passed.append("24h volume $%.0fK > $50K (+4)" % (vol24h / 1000))
        else:
            failed.append("24h volume $%.0fK < $50K" % (vol24h / 1000))

        # Volume organic 20–100% of MC (3 pts)
        if mc > 0:
            vol_ratio = vol24h / mc
            if 0.20 <= vol_ratio <= 1.0:
                score += 3; passed.append("Volume organic %.0f%% of MC (+3)" % (vol_ratio * 100))
            elif vol_ratio > 1.0:
                failed.append("Volume %.0f%% of MC — possible wash trading" % (vol_ratio * 100))
            else:
                failed.append("Volume %.0f%% of MC — low activity" % (vol_ratio * 100))

        # Buy/sell ratio > 1.2 (4 pts)
        bs_ratio = buys / sells if sells > 0 else 0
        if bs_ratio >= 1.5:
            score += 4; passed.append("Buy/sell %.1fx > 1.5 (+4)" % bs_ratio)
        elif bs_ratio >= 1.2:
            score += 2; passed.append("Buy/sell %.1fx > 1.2 (+2)" % bs_ratio)
        else:
            failed.append("Buy/sell %.1fx < 1.2 — more selling than buying" % bs_ratio)

        # Volume spike detection — h1 > 40% of h24 = suspicious pump (no pts, gate)
        if vol24h > 0 and vol1h > 0:
            h1_share = vol1h / vol24h * 100
            if h1_share > 60:
                failed.append("Volume spike: %.0f%% of daily vol in last 1h — pump risk" % h1_share)
            elif h1_share > 0:
                passed.append("Volume spread normal (1h = %.0f%% of 24h)" % h1_share)

    else:
        failed.append("DexScreener market data unavailable")

    # ── MOMENTUM — 15 pts ─────────────────────────────────────────────────────

    if dex:
        pc1h  = float((dex.get("priceChange") or {}).get("h1") or 0)
        pc6h  = float((dex.get("priceChange") or {}).get("h6") or 0)
        pc24h = float((dex.get("priceChange") or {}).get("h24") or 0)
        age_ms = dex.get("pairCreatedAt") or 0
        age_h  = (time.time() * 1000 - age_ms) / 3600000 if age_ms else 0

        # 1h price not crashing (4 pts)
        if pc1h >= 5:
            score += 4; passed.append("1h price +%.1f%% — momentum (+4)" % pc1h)
        elif pc1h >= -10:
            score += 2; passed.append("1h price %.1f%% — stable (+2)" % pc1h)
        else:
            failed.append("1h price %.1f%% — dumping" % pc1h)

        # 6h price trend (4 pts)
        if pc6h >= 10:
            score += 4; passed.append("6h price +%.1f%% — uptrend (+4)" % pc6h)
        elif pc6h >= -15:
            score += 2; passed.append("6h price %.1f%% — neutral (+2)" % pc6h)
        else:
            failed.append("6h price %.1f%% — downtrend" % pc6h)

        # 24h price context (3 pts) — healthy gains not parabolic
        if 20 <= pc24h <= 300:
            score += 3; passed.append("24h price +%.0f%% — healthy gain (+3)" % pc24h)
        elif 0 <= pc24h < 20:
            score += 1; passed.append("24h price +%.0f%% — early (+1)" % pc24h)
        elif pc24h > 300:
            failed.append("24h price +%.0f%% — parabolic, late entry risk" % pc24h)
        else:
            failed.append("24h price %.0f%% — declining" % pc24h)

        # Pair age 24h–7 days (4 pts)
        if 24 <= age_h <= 168:
            score += 4; passed.append("Pair age %.0fh in 24h–7d sweet spot (+4)" % age_h)
        elif age_h < 24:
            failed.append("Pair age %.0fh < 24h — too new, high risk" % age_h)
        else:
            failed.append("Pair age %.0fh > 7 days — opportunity may have passed" % age_h)
    else:
        failed.append("Momentum data unavailable")

    # ── Grade ─────────────────────────────────────────────────────────────────
    score = min(score, 100)
    grade = "A" if score >= 80 else "B" if score >= 65 else "C"

    return score, grade, passed, failed, None


def score_token_full(address, gp, dex, chain_key):
    """Wrapper that injects address for Solana holder lookup."""
    is_sol = (CHAIN_MAP.get(chain_key, {}).get("goplus_id") == "solana")

    if is_sol:
        sol_holders, sol_total = fetch_solscan_holders(address)
    else:
        sol_holders, sol_total = [], 0

    passed = []
    failed = []
    score  = 0

    # ── HARD GATES ────────────────────────────────────────────────────────────

    if is_sol:
        if gp:
            if str(gp.get("non_transferable", "0")) == "1":
                return 0, "F", [], [], "HARD FAIL: Token is non-transferable (cannot sell)"
            if str(gp.get("transfer_hook", "0")) == "1":
                return 0, "F", [], [], "HARD FAIL: Transfer hook (honeypot)"
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
                return 0, "F", [], [], "HARD FAIL: Asymmetric tax sell %.1f%% vs buy %.1f%%" % (sell_tax, buy_tax)

    # ── SECURITY — 35 pts ─────────────────────────────────────────────────────

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
                score += 6; passed.append("No transfer fee (+6)")
            else:
                failed.append("Transfer fee present")

            if str(gp.get("metadata_mutable", "0")) == "0":
                score += 5; passed.append("Metadata immutable (+5)")
            else:
                failed.append("Metadata mutable")
        else:
            failed.append("GoPlus security data unavailable")

    else:
        if gp:
            if str(gp.get("is_mintable", "0")) == "0":
                score += 8; passed.append("No mint function (+8)")
            else:
                failed.append("MINTABLE — supply can be inflated")

            if str(gp.get("is_blacklisted", "0")) == "0":
                score += 7; passed.append("No blacklist (+7)")
            else:
                failed.append("BLACKLIST — wallets can be blocked")

            if str(gp.get("transfer_pausable", "0")) == "0":
                score += 6; passed.append("Transfers cannot be paused (+6)")
            else:
                failed.append("Transfers can be paused")

            if str(gp.get("is_proxy", "0")) == "0":
                score += 5; passed.append("No proxy contract (+5)")
            else:
                failed.append("Proxy contract — logic replaceable")

            if str(gp.get("hidden_owner", "0")) == "0":
                score += 5; passed.append("No hidden owner (+5)")
            else:
                failed.append("Hidden owner detected")

            owner = gp.get("owner_address") or ""
            if not owner or owner == "0x0000000000000000000000000000000000000000":
                score += 4; passed.append("Ownership renounced (+4)")
            else:
                failed.append("Ownership NOT renounced")
        else:
            failed.append("GoPlus security data unavailable")

    # ── DISTRIBUTION — 25 pts ─────────────────────────────────────────────────

    if is_sol:
        if sol_total > 500:
            score += 8; passed.append("Holder count %d > 500 (+8)" % sol_total)
        elif sol_total > 200:
            score += 4; passed.append("Holder count %d > 200 (+4)" % sol_total)
        elif sol_total > 0:
            failed.append("Low holder count %d" % sol_total)
        else:
            passed.append("Solana holder count unavailable")

        if sol_holders:
            supply_vals  = [float(h.get("amount", 0)) for h in sol_holders]
            total_supply = sum(supply_vals) or 1
            top3_pct     = supply_vals[0] / total_supply * 100 if supply_vals else 0
            top3_sum_pct = sum(supply_vals[:3]) / total_supply * 100
            top10_pct    = sum(supply_vals[:10]) / total_supply * 100

            if top3_sum_pct < 15:
                score += 10; passed.append("Top 3 wallets %.1f%% < 15%% (+10)" % top3_sum_pct)
            elif top3_sum_pct < 25:
                score += 5; passed.append("Top 3 wallets %.1f%% < 25%% (+5)" % top3_sum_pct)
            else:
                failed.append("Top 3 wallets %.1f%% — concentrated" % top3_sum_pct)

            if top10_pct < 30:
                score += 7; passed.append("Top 10 hold %.1f%% < 30%% (+7)" % top10_pct)
            else:
                failed.append("Top 10 hold %.1f%% >= 30%%" % top10_pct)
        else:
            score += 12; passed.append("Solana distribution unavailable (partial +12)")

    else:
        if gp:
            creator_pct = float(gp.get("creator_percent") or 0)
            if creator_pct < 5:
                score += 8; passed.append("Dev wallet %.1f%% < 5%% (+8)" % creator_pct)
            elif creator_pct < 10:
                score += 3; passed.append("Dev wallet %.1f%% < 10%% (+3)" % creator_pct)
            else:
                failed.append("Dev wallet %.1f%% >= 10%%" % creator_pct)

            holders = gp.get("holders") or []
            if holders:
                top3_pct  = sum(float(h.get("percent", 0)) for h in holders[:3]) * 100
                top10_pct = sum(float(h.get("percent", 0)) for h in holders[:10]) * 100

                if top3_pct < 15:
                    score += 7; passed.append("Top 3 hold %.1f%% < 15%% (+7)" % top3_pct)
                elif top3_pct < 25:
                    score += 3; passed.append("Top 3 hold %.1f%% < 25%% (+3)" % top3_pct)
                else:
                    failed.append("Top 3 hold %.1f%% — wash trading risk" % top3_pct)

                if top10_pct < 20:
                    score += 4; passed.append("Top 10 hold %.1f%% < 20%% (+4)" % top10_pct)
                else:
                    failed.append("Top 10 hold %.1f%% >= 20%%" % top10_pct)

            holder_count = int(gp.get("holder_count") or 0)
            if holder_count > 500:
                score += 3; passed.append("Holder count %d > 500 (+3)" % holder_count)
            elif holder_count > 200:
                score += 1; passed.append("Holder count %d > 200 (+1)" % holder_count)
            else:
                failed.append("Low holder count %d" % holder_count)

            lp_holders = gp.get("lp_holders") or []
            lp_locked  = any(str(lp.get("is_locked", "0")) == "1" for lp in lp_holders)
            lp_info    = gp.get("lp_holder_analysis") or {}
            if isinstance(lp_info, dict):
                lp_locked = lp_locked or str(lp_info.get("is_locked", "0")) == "1"
            if lp_locked:
                score += 3; passed.append("LP locked (+3)")
            else:
                failed.append("LP NOT locked — can be pulled")

    # ── MARKET — 25 pts ───────────────────────────────────────────────────────

    if dex:
        mc     = float((dex.get("fdv") or dex.get("marketCap") or 0))
        liq    = float((dex.get("liquidity") or {}).get("usd") or 0)
        vol24h = float((dex.get("volume") or {}).get("h24") or 0)
        vol1h  = float((dex.get("volume") or {}).get("h1") or 0)
        buys   = float((dex.get("txns") or {}).get("h24", {}).get("buys") or 0)
        sells  = float((dex.get("txns") or {}).get("h24", {}).get("sells") or 1)

        if 500_000 <= mc <= 5_000_000:
            score += 5; passed.append("MC $%.0fK in $500K–$5M sweet spot (+5)" % (mc / 1000))
        else:
            failed.append("MC $%.0fK outside $500K–$5M" % (mc / 1000))

        if liq >= 100_000:
            score += 5; passed.append("Liquidity $%.0fK > $100K (+5)" % (liq / 1000))
        elif liq >= 50_000:
            score += 2; passed.append("Liquidity $%.0fK > $50K (+2)" % (liq / 1000))
        else:
            failed.append("Liquidity $%.0fK < $50K" % (liq / 1000))

        if mc > 0 and (liq / mc) >= 0.10:
            score += 4; passed.append("Liq/MC %.1f%% >= 10%% (+4)" % (liq / mc * 100))
        else:
            ratio = (liq / mc * 100) if mc > 0 else 0
            failed.append("Liq/MC %.1f%% < 10%%" % ratio)

        if vol24h >= 50_000:
            score += 4; passed.append("24h volume $%.0fK > $50K (+4)" % (vol24h / 1000))
        else:
            failed.append("24h volume $%.0fK < $50K" % (vol24h / 1000))

        if mc > 0:
            vol_ratio = vol24h / mc
            if 0.20 <= vol_ratio <= 1.0:
                score += 3; passed.append("Volume organic %.0f%% of MC (+3)" % (vol_ratio * 100))
            elif vol_ratio > 1.0:
                failed.append("Volume %.0f%% of MC — possible wash trading" % (vol_ratio * 100))
            else:
                failed.append("Volume %.0f%% of MC — low activity" % (vol_ratio * 100))

        bs_ratio = buys / sells if sells > 0 else 0
        if bs_ratio >= 1.5:
            score += 4; passed.append("Buy/sell %.1fx > 1.5 (+4)" % bs_ratio)
        elif bs_ratio >= 1.2:
            score += 2; passed.append("Buy/sell %.1fx > 1.2 (+2)" % bs_ratio)
        else:
            failed.append("Buy/sell %.1fx < 1.2 — more selling" % bs_ratio)

        if vol24h > 0 and vol1h > 0:
            h1_share = vol1h / vol24h * 100
            if h1_share > 60:
                failed.append("Volume spike: %.0f%% of daily vol in 1h — pump risk" % h1_share)
            else:
                passed.append("Volume spread normal (1h = %.0f%% of 24h)" % h1_share)
    else:
        failed.append("DexScreener market data unavailable")

    # ── MOMENTUM — 15 pts ─────────────────────────────────────────────────────

    if dex:
        pc1h  = float((dex.get("priceChange") or {}).get("h1") or 0)
        pc6h  = float((dex.get("priceChange") or {}).get("h6") or 0)
        pc24h = float((dex.get("priceChange") or {}).get("h24") or 0)
        age_ms = dex.get("pairCreatedAt") or 0
        age_h  = (time.time() * 1000 - age_ms) / 3600000 if age_ms else 0

        if pc1h >= 5:
            score += 4; passed.append("1h price +%.1f%% — momentum (+4)" % pc1h)
        elif pc1h >= -10:
            score += 2; passed.append("1h price %.1f%% — stable (+2)" % pc1h)
        else:
            failed.append("1h price %.1f%% — dumping" % pc1h)

        if pc6h >= 10:
            score += 4; passed.append("6h price +%.1f%% — uptrend (+4)" % pc6h)
        elif pc6h >= -15:
            score += 2; passed.append("6h price %.1f%% — neutral (+2)" % pc6h)
        else:
            failed.append("6h price %.1f%% — downtrend" % pc6h)

        if 20 <= pc24h <= 300:
            score += 3; passed.append("24h price +%.0f%% — healthy gain (+3)" % pc24h)
        elif 0 <= pc24h < 20:
            score += 1; passed.append("24h price +%.0f%% — early (+1)" % pc24h)
        elif pc24h > 300:
            failed.append("24h +%.0f%% — parabolic, late entry risk" % pc24h)
        else:
            failed.append("24h price %.0f%% — declining" % pc24h)

        if 24 <= age_h <= 168:
            score += 4; passed.append("Pair age %.0fh in 24h–7d sweet spot (+4)" % age_h)
        elif age_h < 24:
            failed.append("Pair age %.0fh < 24h — very new, high risk" % age_h)
        else:
            failed.append("Pair age %.0fh > 7 days" % age_h)
    else:
        failed.append("Momentum data unavailable")

    score = min(score, 100)
    grade = "A" if score >= 80 else "B" if score >= 65 else "C"
    return score, grade, passed, failed, None

# ── Message builder ───────────────────────────────────────────────────────────

def build_report(address, chain_key, score, grade, passed, failed, hard_fail, dex):
    chain_label = CHAIN_MAP.get(chain_key, {}).get("label", chain_key.upper())
    short_addr  = address[:12] + "..." + address[-6:]

    if hard_fail:
        return (
            "MEMECOIN SCAN — REJECTED\n\n"
            "Chain:   %s\n"
            "Address: %s\n\n"
            "%s\n\n"
            "DO NOT BUY."
        ) % (chain_label, short_addr, hard_fail)

    name_line  = ""
    price_line = ""
    mc_line    = ""
    pc_line    = ""

    if dex:
        bt        = dex.get("baseToken") or {}
        name      = bt.get("name", "")
        sym       = bt.get("symbol", "")
        price_usd = dex.get("priceUsd") or "?"
        mc        = float((dex.get("fdv") or dex.get("marketCap") or 0))
        pc1h      = float((dex.get("priceChange") or {}).get("h1") or 0)
        pc24h     = float((dex.get("priceChange") or {}).get("h24") or 0)

        if name:
            name_line  = "%s (%s)\n" % (name, sym)
        price_line = "Price:   $%s\n" % price_usd
        mc_line    = "MC:      $%.0fK\n" % (mc / 1000) if mc else ""
        pc_line    = "Change:  1h %+.1f%%  24h %+.1f%%\n" % (pc1h, pc24h)

    grade_label = {
        "A": "GRADE A — STRONG CANDIDATE",
        "B": "GRADE B — MODERATE CANDIDATE",
        "C": "GRADE C — WEAK / SKIP",
    }.get(grade, "GRADE ?")

    action = {
        "A": "Consider entry. Set SL at -20%. Take partial profits at 2x.",
        "B": "Small position only. Tight SL. Do not oversize.",
        "C": "Skip or watch only.",
    }.get(grade, "")

    passed_lines = "\n".join("  + %s" % p for p in passed[:10])
    failed_lines = "\n".join("  - %s" % f for f in failed[:8])

    return (
        "MEMECOIN SCAN RESULT\n\n"
        "%s"
        "Chain:   %s\n"
        "Address: %s\n"
        "%s%s%s"
        "\n%s — Score %d/100\n\n"
        "PASSED:\n%s\n\n"
        "FAILED:\n%s\n\n"
        "ACTION: %s"
    ) % (
        name_line, chain_label, short_addr,
        price_line, mc_line, pc_line,
        grade_label, score,
        passed_lines or "  (none)",
        failed_lines or "  (none)",
        action,
    )

# ── Persistence ───────────────────────────────────────────────────────────────

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
    with open(RESULTS_FILE, "w") as f:
        json.dump(results[:50], f, indent=2)

# ── Core scan ─────────────────────────────────────────────────────────────────

async def scan_and_notify(bot, address, chain_key):
    gp  = fetch_goplus(address, chain_key)
    dex = fetch_dexscreener(address)
    score, grade, passed, failed, hard_fail = score_token_full(address, gp, dex, chain_key)
    report = build_report(address, chain_key, score, grade, passed, failed, hard_fail, dex)

    if grade in ("A", "B") and not hard_fail:
        await bot.send_message(chat_id=CHAT_ID, text=report)
        log.info("Alert: %s chain=%s grade=%s score=%d" % (address[:12], chain_key, grade, score))

    return {
        "address":   address,
        "chain":     chain_key,
        "score":     score,
        "grade":     grade,
        "hard_fail": hard_fail,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ── Auto-scanner ──────────────────────────────────────────────────────────────

async def auto_scan_loop(bot):
    seen = load_seen()
    log.info("Auto-scanner started — interval %ds" % SCAN_INTERVAL)
    while True:
        try:
            tokens = fetch_latest_tokens()
            for token in tokens:
                addr      = token.get("tokenAddress") or token.get("address") or ""
                chain_raw = (token.get("chainId") or "").lower()
                chain_key = DEX_TO_CHAIN.get(chain_raw)
                if not addr or not chain_key or addr in seen:
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
            log.error("Auto-scan error: %s" % e)
        await asyncio.sleep(SCAN_INTERVAL)

# ── Command handlers ──────────────────────────────────────────────────────────

async def handle_help(bot, chat_id):
    await bot.send_message(
        chat_id=chat_id,
        text=(
            "MEMECOIN SCANNER v2 — COMMANDS\n\n"
            "/scan ADDRESS [chain]\n"
            "  Scan any token. Chain optional for Solana.\n"
            "  EVM chains: eth bsc base arb polygon avax\n\n"
            "Examples:\n"
            "  /scan 0x1234...abcd eth\n"
            "  /scan So1ana...addr  (auto-detected)\n\n"
            "/recent  — last 10 scan results\n\n"
            "Scoring (100 pts):\n"
            "  Security     35 pts  (GoPlus)\n"
            "  Distribution 25 pts  (holders, LP)\n"
            "  Market       25 pts  (MC, liq, vol)\n"
            "  Momentum     15 pts  (price 1h/6h/24h)\n\n"
            "Grade A >= 80 — strong candidate\n"
            "Grade B >= 65 — moderate candidate\n"
            "Below 65 — skip\n\n"
            "Auto-scan runs every 5 minutes\n"
            "across all 7 chains."
        )
    )

async def handle_scan(bot, chat_id, args):
    if not args:
        await bot.send_message(chat_id=chat_id,
                               text="Usage: /scan ADDRESS [chain]")
        return

    address   = args[0].strip()
    chain_arg = args[1].lower() if len(args) > 1 else None

    if chain_arg and chain_arg not in CHAIN_MAP:
        await bot.send_message(
            chat_id=chat_id,
            text="Unknown chain: %s\nValid: eth bsc base sol arb polygon avax" % chain_arg
        )
        return

    chain_key = chain_arg or guess_chain(address)

    if not chain_key:
        await bot.send_message(
            chat_id=chat_id,
            text=(
                "EVM address — please specify chain:\n"
                "/scan %s eth\n"
                "/scan %s bsc\n"
                "/scan %s base\n"
                "/scan %s arb"
            ) % (address, address, address, address)
        )
        return

    await bot.send_message(chat_id=chat_id,
                           text="Scanning on %s..." % chain_key.upper())

    gp  = fetch_goplus(address, chain_key)
    dex = fetch_dexscreener(address)
    score, grade, passed, failed, hard_fail = score_token_full(address, gp, dex, chain_key)
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
                               text="No scans yet. Try /scan ADDRESS [chain]")
        return
    lines = ["RECENT SCANS\n"]
    for i, r in enumerate(results, 1):
        ts    = r.get("timestamp", "")[:16].replace("T", " ")
        addr  = r.get("address", "")
        short = addr[:10] + "..." + addr[-6:] if len(addr) > 16 else addr
        hf    = " REJECTED" if r.get("hard_fail") else ""
        lines.append("%d. [%s] %s %s Grade %s (%d)%s" % (
            i, ts, short,
            r.get("chain", "?").upper(),
            r.get("grade", "?"),
            r.get("score", 0), hf))
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
    log.info("Memecoin Scanner v2 starting...")
    bot    = Bot(token=TELEGRAM_TOKEN)
    offset = 0

    await bot.send_message(
        chat_id=CHAT_ID,
        text=(
            "Memecoin Scanner v2 Online!\n\n"
            "7 chains: ETH  BSC  Base\n"
            "          SOL  ARB  Polygon  AVAX\n\n"
            "Scoring (100 pts):\n"
            "  Security     35 pts\n"
            "  Distribution 25 pts\n"
            "  Market       25 pts\n"
            "  Momentum     15 pts\n\n"
            "New checks:\n"
            "  Price momentum 1h / 6h / 24h\n"
            "  Holder count\n"
            "  Wallet concentration\n"
            "  Volume spike detection\n"
            "  Wash trading signals\n\n"
            "Auto-scan every 5 min.\n"
            "Grade A/B alerts only.\n\n"
            "/scan ADDRESS [chain]\n"
            "/recent  /help"
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
