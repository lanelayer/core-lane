#!/usr/bin/env bash
# Test: Docker Compose volume cleanup, up, stop core-lane, restart, verify restore.
# 1) Clean docker compose volume
# 2) docker compose up
# 3) Wait for Core Lane to process some blocks
# 4) Stop core-lane
# 5) Start core-lane again
# 6) Verify block number restored correctly
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET_CORE_BLOCK="${TARGET_CORE_BLOCK:-2}"
JSON_RPC_URL="${JSON_RPC_URL:-http://127.0.0.1:8545}"
WAIT_FOR_BLOCK_TIMEOUT="${WAIT_FOR_BLOCK_TIMEOUT:-600}"
WAIT_AFTER_RESTART="${WAIT_AFTER_RESTART:-30}"

print_status() { echo -e "${BLUE}[TEST]${NC} $1"; }
print_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
print_error() { echo -e "${RED}[FAIL]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }

call_rpc() {
  curl -s -X POST "$JSON_RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}"
}

get_block_number() {
  local res
  res=$(call_rpc "eth_blockNumber" "[]" 2>/dev/null) || echo ""
  echo "$res" | jq -r '.result // empty'
}

block_hex_to_dec() {
  local hex="$1"
  if [[ "$hex" =~ ^0x[0-9a-fA-F]+$ ]]; then
    printf '%d' "$((16#${hex#0x}))"
  else
    echo "0"
  fi
}

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [ ! -f "docker-compose.yml" ]; then
  print_error "docker-compose.yml not found (run from repo root)"
  exit 1
fi

print_status "Step 1: Cleaning docker compose volume..."
docker compose down -v 2>/dev/null || true
print_success "Volume cleaned"

print_status "Step 2: Starting stack with docker compose up..."
docker compose up --wait -d
print_success "Stack started"

print_status "Step 3: Waiting for Core Lane RPC at $JSON_RPC_URL..."
for i in $(seq 1 60); do
  bn=$(get_block_number 2>/dev/null) || true
  if [ -n "$bn" ] && [ "$bn" != "null" ]; then
    print_success "RPC ready (current block: $bn)"
    break
  fi
  [ "$i" -eq 60 ] && { print_error "RPC not ready after 60s"; docker compose logs --tail=50 core-lane; exit 1; }
  sleep 2
done

print_status "Step 4: Waiting for Core Lane block >= $TARGET_CORE_BLOCK (timeout ${WAIT_FOR_BLOCK_TIMEOUT}s)..."
start_ts=$(date +%s)
while true; do
  bn_hex=$(get_block_number 2>/dev/null) || true
  bn_dec=$(block_hex_to_dec "$bn_hex")
  elapsed=$(($(date +%s) - start_ts))
  if [ -n "$bn_dec" ] && [ "$bn_dec" -ge "$TARGET_CORE_BLOCK" ] 2>/dev/null; then
    print_success "Reached Core Lane block $bn_dec"
    BLOCK_BEFORE="$bn_dec"
    break
  fi
  if [ "$elapsed" -ge "$WAIT_FOR_BLOCK_TIMEOUT" ]; then
    print_error "Timeout waiting for block >= $TARGET_CORE_BLOCK (last: $bn_hex / $bn_dec, elapsed ${elapsed}s)"
    docker compose logs --tail=80 core-lane
    exit 1
  fi
  if [ $((elapsed % 30)) -eq 0 ] && [ "$elapsed" -gt 0 ]; then
    print_status "  ... block $bn_dec, elapsed ${elapsed}s"
  fi
  sleep 5
done

print_status "Step 5: Bringing down core-lane (containers removed, volume preserved)..."
docker compose down
print_success "core-lane down"

print_status "Step 6: Starting core-lane again (should restore from disk)..."
docker compose up --wait -d core-lane
print_success "core-lane started"

print_status "Step 7: Waiting ${WAIT_AFTER_RESTART}s for core-lane to come back..."
sleep "$WAIT_AFTER_RESTART"

print_status "Step 8: Verifying restore..."
bn_hex=$(get_block_number 2>/dev/null) || true
bn_dec=$(block_hex_to_dec "$bn_hex")
if [ -z "$bn_dec" ] || [ "$bn_dec" = "0" ]; then
  print_error "No block number from RPC after restart (response: $bn_hex)"
  docker compose logs --tail=100 core-lane
  exit 1
fi
if [ "$bn_dec" -lt "$BLOCK_BEFORE" ]; then
  print_error "Block number after restart ($bn_dec) is below pre-stop ($BLOCK_BEFORE) - restore failed"
  docker compose logs --tail=100 core-lane
  exit 1
fi
print_success "Block number restored: $bn_dec (>= $BLOCK_BEFORE)"

LOGS=$(docker compose logs core-lane 2>/dev/null)
if echo "$LOGS" | grep -qE "Could not restore from disk|Wiped block data"; then
  print_error "Logs show restore failure (Could not restore / Wiped block data)"
  echo "$LOGS" | tail -100
  exit 1
fi
if echo "$LOGS" | grep -qE "Restored|Read tip"; then
  print_success "Logs show successful restore"
else
  print_error "Could not find 'Restored' or 'Read tip' in logs"
  echo "$LOGS" | tail -100
  exit 1
fi

print_success "Docker compose restore test passed."
print_status "Stack is still running. Use 'docker compose down' to stop."
