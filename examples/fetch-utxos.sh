#!/bin/bash
# Fetch UTXOs for an address, joining scriptPubKey from each funding tx so cold
# staking detection works (the UTXO endpoint never returns scripts).
#
# Usage: fetch-utxos.sh <address> [out.json]
#
# $TEST_CHAIN picks the explorer, matching examples/mainnet_test.rs: unset or
# `pivx` for PIVX, `litecoin`/`ltc` for Litecoin. Both are Blockbook instances,
# so one response shape feeds one parser and the harness cannot end up ingesting
# Litecoin through a PIVX-shaped code path.
#
# The scriptPubKey join is PIVX-only work: it exists for cold staking, which
# Litecoin does not have. It is skipped there, which also means one request
# instead of one per funding transaction.
set -euo pipefail

ADDR=$1; OUT=${2:-utxos.json}

case "$(echo "${TEST_CHAIN:-pivx}" | tr '[:upper:]' '[:lower:]')" in
  ""|pivx|piv)      API="https://explorer.pivxla.bz/api/v2"; JOIN_SCRIPTS=1 ;;
  # Trezor's Litecoin Blockbook instances sit behind Cloudflare and answer 403
  # to anything without a browser, so this uses an Esplora-shaped explorer and
  # reshapes the response below. Reshaping in the fetcher keeps the kit's single
  # UTXO parser untouched: one ingest path, already tested, for both chains.
  litecoin|ltc)     API="https://litecoinspace.org/api";     JOIN_SCRIPTS=0 ;;
  *) echo "unknown TEST_CHAIN '$TEST_CHAIN': want pivx or litecoin" >&2; exit 2 ;;
esac

case "$(echo "${TEST_CHAIN:-pivx}" | tr '[:upper:]' '[:lower:]')" in
  litecoin|ltc) RAW=$(curl -s --max-time 30 "$API/address/$ADDR/utxo") ;;
  *)            RAW=$(curl -s --max-time 30 "$API/utxo/$ADDR?confirmed=true") ;;
esac

# Fail loudly rather than writing an empty file the harness would read as
# "no funds", which looks identical to a broken explorer.
if ! echo "$RAW" | python3 -c 'import sys,json; json.load(sys.stdin)' 2>/dev/null; then
  echo "explorer did not return JSON for $ADDR at $API" >&2
  echo "$RAW" | head -c 300 >&2; echo >&2
  exit 1
fi

echo "$RAW" | API="$API" JOIN_SCRIPTS="$JOIN_SCRIPTS" CHAIN="${TEST_CHAIN:-pivx}" python3 -c '
import sys, os, json, urllib.request
api = os.environ["API"]
join = os.environ["JOIN_SCRIPTS"] == "1"
chain = os.environ["CHAIN"].lower()
utxos = json.load(sys.stdin)

# Esplora reports `value` as an integer and buries the height under `status`;
# Blockbook uses a top-level `height` and tolerates either for `value`. Normalise
# to the Blockbook shape so `parse_blockbook_utxos` stays the one ingest path,
# and drop anything unconfirmed, which Esplora returns and the PIVX query filters
# server-side.
if chain in ("litecoin", "ltc"):
    out = []
    for u in utxos:
        st = u.get("status", {})
        if not st.get("confirmed", False):
            continue
        out.append({
            "txid": u["txid"],
            "vout": u["vout"],
            "value": u["value"],
            "height": st.get("block_height", 0),
        })
    utxos = out
if join:
    scripts, cs_txids = {}, set()
    for txid in {u["txid"] for u in utxos}:
        tx = json.load(urllib.request.urlopen(f"{api}/tx/{txid}", timeout=30))
        for o in tx.get("vout", []):
            scripts[(txid, o["n"])] = o.get("hex", "")
        vout = tx.get("vout", [])
        if len(vout) >= 2 and vout[0].get("value") == "0" and tx.get("vin", [{}])[0].get("txid"):
            cs_txids.add(txid)
    for u in utxos:
        u["script"] = scripts.get((u["txid"], u["vout"]), "")
        u["coinstake"] = u["txid"] in cs_txids
print(json.dumps(utxos, indent=1))
' > "$OUT"
echo "wrote $OUT: $(python3 -c "import json;print(len(json.load(open('$OUT'))))") utxo(s)"
