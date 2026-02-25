#!/usr/bin/env bash
# run_proof.sh — Fetch a block witness from an Ethereum node and run MPT proof verification.
#
# Usage:
#   ./run_proof.sh <RPC_URL> <BLOCK_NUMBER>
#
# Examples:
#   ./run_proof.sh https://mainnet.infura.io/v3/<key> 21000000
#   ./run_proof.sh http://localhost:8545 latest
#
# The script calls:
#   1. eth_getBlockByNumber  — to get stateRoot and block number
#   2. debug_generateWitness — to get the flat proof witness
#      (falls back to debug_executionWitness if the first call returns an error)
# Then runs: zig-out/bin/zevm_stateless <block.json> <witness.json>
#
# Requirements: curl, jq

set -euo pipefail

# ─── Arguments ────────────────────────────────────────────────────────────────

RPC_URL="${1:?Error: RPC URL required.  Usage: $0 <RPC_URL> <BLOCK_NUMBER>}"
BLOCK_INPUT="${2:?Error: Block number required.  Usage: $0 <RPC_URL> <BLOCK_NUMBER>}"

# ─── Helpers ──────────────────────────────────────────────────────────────────

die() { echo "error: $*" >&2; exit 1; }

rpc_call() {
    local method="$1" params="$2"
    curl -sf --max-time 30 -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[$params],\"id\":1}"
}

# ─── Normalize block number ───────────────────────────────────────────────────

if [[ "$BLOCK_INPUT" == "latest" || "$BLOCK_INPUT" == "finalized" || "$BLOCK_INPUT" == "safe" ]]; then
    BLOCK_TAG="\"$BLOCK_INPUT\""
    BLOCK_HEX="$BLOCK_INPUT"
elif [[ "$BLOCK_INPUT" == 0x* ]]; then
    BLOCK_HEX="$BLOCK_INPUT"
    BLOCK_TAG="\"$BLOCK_HEX\""
else
    BLOCK_HEX=$(printf "0x%x" "$BLOCK_INPUT")
    BLOCK_TAG="\"$BLOCK_HEX\""
fi

# ─── 1. eth_getBlockByNumber ──────────────────────────────────────────────────

echo "Fetching block $BLOCK_HEX from $RPC_URL ..."

BLOCK_RESP=$(rpc_call "eth_getBlockByNumber" "$BLOCK_TAG, false") \
    || die "eth_getBlockByNumber request failed (curl error)"

if echo "$BLOCK_RESP" | jq -e '.error' > /dev/null 2>&1; then
    MSG=$(echo "$BLOCK_RESP" | jq -r '.error.message // .error')
    die "eth_getBlockByNumber: $MSG"
fi

STATE_ROOT=$(echo "$BLOCK_RESP" | jq -r '.result.stateRoot') \
    || die "could not parse stateRoot from block response"

BLOCK_NUMBER_HEX=$(echo "$BLOCK_RESP" | jq -r '.result.number')
BLOCK_NUMBER_DEC=$(printf "%d" "$BLOCK_NUMBER_HEX")

echo "  number:     $BLOCK_NUMBER_DEC  ($BLOCK_NUMBER_HEX)"
echo "  stateRoot:  $STATE_ROOT"

# ─── 2. debug_generateWitness (or debug_executionWitness) ────────────────────

echo ""
echo "Fetching execution witness ..."

WITNESS_METHOD="debug_generateWitness"
WITNESS_RESP=$(rpc_call "$WITNESS_METHOD" "\"$BLOCK_NUMBER_HEX\"") \
    || die "$WITNESS_METHOD request failed (curl error)"

# Fall back to debug_executionWitness if the first method returns an error
if echo "$WITNESS_RESP" | jq -e '.error' > /dev/null 2>&1; then
    echo "  $WITNESS_METHOD not available, trying debug_executionWitness ..."
    WITNESS_METHOD="debug_executionWitness"
    WITNESS_RESP=$(rpc_call "$WITNESS_METHOD" "\"$BLOCK_NUMBER_HEX\"") \
        || die "$WITNESS_METHOD request failed (curl error)"
fi

if echo "$WITNESS_RESP" | jq -e '.error' > /dev/null 2>&1; then
    MSG=$(echo "$WITNESS_RESP" | jq -r '.error.message // .error')
    die "$WITNESS_METHOD: $MSG"
fi

# The witness may be directly in .result, or nested under .result.witness
WITNESS=$(echo "$WITNESS_RESP" | jq -r '
    if .result | type == "object" then
        if .result | has("state") then .result
        elif .result | has("witness") then .result.witness
        else error("unexpected witness shape")
        end
    else error("witness result is not an object")
    end
') || die "could not extract witness from $WITNESS_METHOD response"

NODE_COUNT=$(echo "$WITNESS"  | jq '.state   | length')
CODE_COUNT=$(echo "$WITNESS"  | jq '.codes   | length')
KEY_COUNT=$(echo "$WITNESS"   | jq '.keys    | length')
HDR_COUNT=$(echo "$WITNESS"   | jq '.headers | length')

echo "  nodes:      $NODE_COUNT RLP node(s)"
echo "  codes:      $CODE_COUNT bytecode(s)"
echo "  keys:       $KEY_COUNT key(s)"
echo "  headers:    $HDR_COUNT header(s)"

# ─── 3. Write block.json and witness.json ────────────────────────────────────

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

BLOCK_JSON="$TMPDIR/block.json"
WITNESS_JSON="$TMPDIR/witness.json"

jq -n --argjson number "$BLOCK_NUMBER_DEC" --arg stateRoot "$STATE_ROOT" \
    '{"number": $number, "stateRoot": $stateRoot}' > "$BLOCK_JSON"

echo "$WITNESS" > "$WITNESS_JSON"

# ─── 4. Run the verifier ─────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/zig-out/bin/zevm_stateless"

if [ ! -f "$BINARY" ]; then
    echo ""
    echo "Binary not found, building ..."
    (cd "$SCRIPT_DIR" && zig build)
fi

echo ""
exec "$BINARY" "$BLOCK_JSON" "$WITNESS_JSON"
