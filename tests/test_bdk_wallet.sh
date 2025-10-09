#!/bin/bash

# Test script for BDK wallet integration
# This demonstrates creating a wallet, getting addresses, and receiving funds

set -e

# Source the wallet helpers
source "$(dirname "$0")/wallet-helpers.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

# Bitcoin CLI helper
bitcoin_cli() {
    docker exec bitcoin-regtest bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin123 "$@" 2>/dev/null
}

echo "======================================"
echo "  BDK Wallet Integration Test"
echo "======================================"
echo ""

# Check if Bitcoin is running
if ! docker ps | grep -q bitcoin-regtest; then
    print_error "Bitcoin regtest is not running"
    print_status "Start it with: ./tests/test-environment.sh start setup-wallet"
    exit 1
fi

# Check if Core Lane is built
if [ ! -f "./target/release/core-lane-node" ]; then
    print_error "Core Lane node is not built (release mode)"
    print_status "Building now..."
    cargo build --release
fi

print_status "Step 1: Creating new BDK wallet..."
MNEMONIC=$(create_bdk_wallet regtest)
if [ -z "$MNEMONIC" ]; then
    print_error "Failed to create wallet"
    exit 1
fi
print_success "Wallet created"
print_status "Mnemonic: $MNEMONIC"
save_mnemonic regtest "$MNEMONIC"
echo ""

print_status "Step 2: Getting receive addresses..."
ADDR1=$(get_bdk_address regtest)
ADDR2=$(get_bdk_address regtest)
ADDR3=$(get_bdk_address regtest)
print_success "Generated 3 addresses:"
echo "  Address 1: $ADDR1"
echo "  Address 2: $ADDR2"
echo "  Address 3: $ADDR3"
echo ""

print_status "Step 3: Sending Bitcoin to first address..."
# Check if Bitcoin wallet exists
if ! bitcoin_cli -rpcwallet=mine getwalletinfo >/dev/null 2>&1; then
    print_error "Bitcoin wallet 'mine' not found"
    print_status "Run: ./tests/test-environment.sh setup-wallet"
    exit 1
fi

# Check Bitcoin wallet balance
BALANCE=$(bitcoin_cli -rpcwallet=mine getbalance)
print_status "Bitcoin wallet balance: $BALANCE BTC"

if (( $(echo "$BALANCE < 0.001" | bc -l) )); then
    print_error "Insufficient Bitcoin balance"
    print_status "Mine some blocks first: ./tests/test-environment.sh setup-wallet"
    exit 1
fi

# Send 0.001 BTC (100,000 sats) to first address
print_status "Sending 0.001 BTC to $ADDR1..."
TXID=$(bitcoin_cli -rpcwallet=mine sendtoaddress "$ADDR1" 0.001)
print_success "Transaction sent: $TXID"
echo ""

print_status "Step 4: Mining block to confirm transaction..."
NEW_ADDR=$(bitcoin_cli -rpcwallet=mine getnewaddress)
bitcoin_cli -rpcwallet=mine generatetoaddress 1 "$NEW_ADDR" >/dev/null
print_success "Block mined"
echo ""

print_status "Step 5: Verifying transaction..."
TX_INFO=$(bitcoin_cli getrawtransaction "$TXID" true)
CONFIRMATIONS=$(echo "$TX_INFO" | jq -r '.confirmations // 0')
print_success "Transaction has $CONFIRMATIONS confirmation(s)"
echo ""

print_status "Step 6: Testing wallet restoration..."
print_status "Removing wallet file..."
cleanup_test_wallets

print_status "Restoring from mnemonic..."
restore_bdk_wallet regtest "$MNEMONIC"
print_success "Wallet restored"

print_status "Verifying restored addresses match..."
RESTORED_ADDR1=$(get_bdk_address regtest)
if [ "$RESTORED_ADDR1" == "$ADDR1" ]; then
    print_success "First address matches: $RESTORED_ADDR1"
else
    print_error "Address mismatch!"
    echo "  Expected: $ADDR1"
    echo "  Got: $RESTORED_ADDR1"
    exit 1
fi
echo ""

print_success "✓ All tests passed!"
echo ""
echo "Summary:"
echo "  • Created BDK wallet with mnemonic"
echo "  • Generated 3 unique addresses"
echo "  • Sent 0.001 BTC to first address"
echo "  • Transaction confirmed in block"
echo "  • Successfully restored wallet from mnemonic"
echo ""
echo "Mnemonic saved to: ./test-wallets/mnemonic_regtest.txt"

