#!/bin/bash
# Test: Restore from latest state on startup.
# 1) Start node with dedicated data dir, process blocks, note block number, stop.
# 2) Restart with same data dir; assert block number is restored.
# 3) Mine one more Bitcoin block; assert Core Lane block number advances.
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

RPC_USER="bitcoin"
RPC_PASSWORD="bitcoin123"
RPC_URL="http://127.0.0.1:18443"
JSON_RPC_PORT=8547
JSON_RPC_URL="http://127.0.0.1:$JSON_RPC_PORT"
DATA_DIR=".test-restore-state"
NODE_PID=0

print_status() { echo -e "${BLUE}[TEST]${NC} $1"; }
print_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
print_error() { echo -e "${RED}[FAIL]${NC} $1"; }

bitcoin_cli() {
  docker exec bitcoin-regtest bitcoin-cli -regtest -rpcuser=$RPC_USER -rpcpassword=$RPC_PASSWORD "$@"
}

call_json_rpc() {
  curl -s -X POST "$JSON_RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":[$2],\"id\":1}"
}

get_block_number() {
  call_json_rpc "eth_blockNumber" "[]" | jq -r '.result // empty'
}

cleanup() {
  [ -n "$NODE_PID" ] && [ "$NODE_PID" -ne 0 ] && kill "$NODE_PID" 2>/dev/null || true
  pkill -f "core-lane-node" 2>/dev/null || true
  rm -rf "$DATA_DIR"
}
trap cleanup EXIT

cd "$(dirname "$0")/.."
cargo build --bin core-lane-node 2>/dev/null || { print_error "Build failed"; exit 1; }

if ! docker ps --format '{{.Names}}' | grep -q '^bitcoin-regtest$'; then
  print_status "Starting Bitcoin regtest..."
  ./tests/test-environment.sh start
  sleep 5
fi
# After integration_test cleanup we have no .test-address and Bitcoin was reset; ensure wallet + blocks exist
if [ ! -f ".test-mnemonic" ] || [ ! -f ".test-address" ]; then
  print_status "Setting up wallet and mining blocks..."
  ./tests/test-environment.sh setup-wallet
fi
[ ! -f ".test-mnemonic" ] && { print_error "No .test-mnemonic"; exit 1; }
[ ! -f ".test-address" ] && { print_error "No .test-address"; exit 1; }

rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

print_status "First run: start node with data-dir $DATA_DIR"
NODE_PID=$( (
  RUST_LOG=warn ./target/debug/core-lane-node start \
    --data-dir "$DATA_DIR" \
    --bitcoin-rpc-read-url "$RPC_URL" \
    --bitcoin-rpc-read-user "$RPC_USER" \
    --bitcoin-rpc-read-password "$RPC_PASSWORD" \
    --mnemonic-file ".test-mnemonic" \
    --http-host 127.0.0.1 \
    --http-port $JSON_RPC_PORT > /tmp/restore_test_node.log 2>&1 &
  echo $!
); true )
NODE_PID=$(printf '%s' "$NODE_PID" | tr -d '\n')

print_status "Waiting for RPC and at least one Core Lane block..."
sleep 3
for i in $(seq 1 45); do
  BN=$(get_block_number 2>/dev/null) || BN=""
  [ -n "$BN" ] && [ "$BN" != "null" ] && [ "$BN" != "0x0" ] && break
  [ "$i" -eq 45 ] && { print_error "Timeout waiting for RPC/block"; cat /tmp/restore_test_node.log; exit 1; }
  sleep 1
done

mine_address=$(cat .test-address 2>/dev/null || echo "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqthqst8")
bitcoin_cli generatetoaddress 2 "$mine_address" > /dev/null 2>&1
sleep 14

BLOCK_BEFORE=$(get_block_number 2>/dev/null) || BLOCK_BEFORE=""
[ -z "$BLOCK_BEFORE" ] || [ "$BLOCK_BEFORE" = "null" ] && { print_error "No block number"; exit 1; }
print_success "Block number before stop: $BLOCK_BEFORE"

kill $NODE_PID 2>/dev/null || true
wait $NODE_PID 2>/dev/null || true
NODE_PID=0
sleep 2

[ -f "$DATA_DIR/tip" ] || { print_error "No tip file"; exit 1; }

print_status "Second run: restart (restore)"
NODE_PID=$( (
  RUST_LOG=warn ./target/debug/core-lane-node start \
    --data-dir "$DATA_DIR" \
    --bitcoin-rpc-read-url "$RPC_URL" \
    --bitcoin-rpc-read-user "$RPC_USER" \
    --bitcoin-rpc-read-password "$RPC_PASSWORD" \
    --mnemonic-file ".test-mnemonic" \
    --http-host 127.0.0.1 \
    --http-port $JSON_RPC_PORT >> /tmp/restore_test_node.log 2>&1 &
  echo $!
); true )
NODE_PID=$(printf '%s' "$NODE_PID" | tr -d '\n')

sleep 5
BLOCK_AFTER=$(get_block_number 2>/dev/null) || BLOCK_AFTER=""
[ -z "$BLOCK_AFTER" ] || [ "$BLOCK_AFTER" = "null" ] && { print_error "No block after restart"; exit 1; }

BN_BEFORE=$(echo "$BLOCK_BEFORE" | sed 's/^0x//')
BN_AFTER=$(echo "$BLOCK_AFTER" | sed 's/^0x//')
[ "$BN_BEFORE" = "$BN_AFTER" ] || { print_error "Block changed: $BLOCK_BEFORE -> $BLOCK_AFTER"; exit 1; }
print_success "Block number restored: $BLOCK_AFTER"

bitcoin_cli generatetoaddress 1 "$mine_address" > /dev/null 2>&1
sleep 12
BLOCK_FINAL=$(get_block_number 2>/dev/null) || BLOCK_FINAL=""
[[ -n "$BLOCK_FINAL" && "$BLOCK_FINAL" =~ ^0x[0-9a-fA-F]+$ ]] || { print_error "Invalid or empty block number from get_block_number: '$BLOCK_FINAL'"; exit 1; }
[[ -n "$BN_BEFORE" && "$BN_BEFORE" =~ ^[0-9a-fA-F]+$ ]] || { print_error "Invalid or empty BN_BEFORE for comparison: '$BN_BEFORE'"; exit 1; }
BN_FINAL=$((16#$(echo "$BLOCK_FINAL" | sed 's/^0x//')))
BN_BEFORE_NUM=$((16#$BN_BEFORE))
[ "$BN_FINAL" -gt "$BN_BEFORE_NUM" ] || { print_error "Block did not advance: $BLOCK_FINAL"; exit 1; }
print_success "Block advanced after mining: $BLOCK_FINAL"

print_success "Restore-from-state test passed."
