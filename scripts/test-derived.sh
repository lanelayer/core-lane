 #!/bin/bash

# Quick test script for derived lane
# This script walks you through testing the derived lane step by step

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CORE_LANE_RPC="http://127.0.0.1:8546"
DERIVED_LANE_RPC="http://127.0.0.1:9545"
CHAIN_ID=1281453634
BURN_ADDRESS="0x0000000000000000000000000000000000000666"
ANVIL_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
TEST_RECIPIENT="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

print_step() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Step $1: $2${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

# Step 1: Check Core Lane
print_step "1" "Checking Core Lane is running..."
if curl -s "$CORE_LANE_RPC" > /dev/null 2>&1; then
    print_success "Core Lane is running at $CORE_LANE_RPC"
else
    print_error "Core Lane is not running!"
    print_info "Please start it first: ./scripts/dev-environment.sh start"
    exit 1
fi

# Step 2: Check Derived Lane
print_step "2" "Checking Derived Lane is running..."
if curl -s "$DERIVED_LANE_RPC" > /dev/null 2>&1; then
    print_success "Derived Lane is running at $DERIVED_LANE_RPC"
else
    print_error "Derived Lane is not running!"
    print_info "Please start it first:"
    print_info "  export DERIVED_DA_ADDRESS=0x...  # Use any address for burn testing"
    print_info "  ./scripts/derived-dev-environment.sh start"
    exit 1
fi

# Step 3: Check initial balance
print_step "3" "Checking initial balance on Derived Lane..."
INITIAL_BALANCE=$(cast balance "$TEST_RECIPIENT" --rpc-url "$DERIVED_LANE_RPC" 2>/dev/null || echo "0")
print_info "Initial balance: $INITIAL_BALANCE wei"

# Step 4: Make a burn
print_step "4" "Making a Core Lane burn..."
BURN_DATA="0x4c616e42${TEST_RECIPIENT#0x}"  # chain_id + recipient

print_info "Burn data: $BURN_DATA"
print_info "Sending 10000000 wei to $BURN_ADDRESS..."

BURN_RESULT=$(cast send "$BURN_ADDRESS" \
    --rpc-url "$CORE_LANE_RPC" \
    --chain-id "$CHAIN_ID" \
    --private-key "$ANVIL_PK" \
    --value 10000000 \
    "$BURN_DATA" 2>&1)

if echo "$BURN_RESULT" | grep -q "transactionHash\|txHash"; then
    TX_HASH=$(echo "$BURN_RESULT" | grep -oE "0x[a-fA-F0-9]{64}" | head -1)
    print_success "Burn transaction created: $TX_HASH"
else
    print_error "Failed to create burn transaction"
    echo "$BURN_RESULT"
    exit 1
fi

# Step 5: Wait for burn to be picked up
print_step "5" "Waiting for Derived Lane to pick up the burn..."
print_info "Waiting 10 seconds for the burn to be processed..."
sleep 10

# Step 6: Check balance after burn
print_step "6" "Checking balance after burn..."
NEW_BALANCE=$(cast balance "$TEST_RECIPIENT" --rpc-url "$DERIVED_LANE_RPC" 2>/dev/null || echo "0")
print_info "New balance: $NEW_BALANCE wei"

if [ "$NEW_BALANCE" != "$INITIAL_BALANCE" ]; then
    print_success "Balance changed! Burn was picked up by Derived Lane"
    print_info "Balance increased by: $(($NEW_BALANCE - $INITIAL_BALANCE)) wei"
else
    print_error "Balance did not change. Burn may not have been picked up yet."
    print_info "Check Derived Lane logs: tail -f derived-lane.log"
    print_info "You may need to wait a bit longer or check if blocks are being mined"
fi

# Step 7: Test a transfer
if [ "$NEW_BALANCE" != "$INITIAL_BALANCE" ] && [ "$NEW_BALANCE" -gt 0 ]; then
    print_step "7" "Testing a transfer on Derived Lane..."
    TRANSFER_RECIPIENT="0x90F79bf6EB2c4f870365E785982E1f101E93b906"
    TRANSFER_AMOUNT=100000
    
    print_info "Sending $TRANSFER_AMOUNT wei to $TRANSFER_RECIPIENT..."
    
    TRANSFER_RESULT=$(cast send "$TRANSFER_RECIPIENT" \
        --rpc-url "$DERIVED_LANE_RPC" \
        --chain-id "$CHAIN_ID" \
        --private-key "$ANVIL_PK" \
        --value "$TRANSFER_AMOUNT" 2>&1)
    
    if echo "$TRANSFER_RESULT" | grep -q "transactionHash\|txHash"; then
        TX_HASH=$(echo "$TRANSFER_RESULT" | grep -oE "0x[a-fA-F0-9]{64}" | head -1)
        print_success "Transfer transaction created: $TX_HASH"
    else
        print_error "Failed to create transfer transaction"
        echo "$TRANSFER_RESULT"
    fi
else
    print_info "Skipping transfer test (insufficient balance or burn not processed)"
fi

print_step "DONE" "Test complete!"
print_info "Check Derived Lane logs: tail -f derived-lane.log"
print_info "Check balances: ./scripts/derived-dev-environment.sh balances"


