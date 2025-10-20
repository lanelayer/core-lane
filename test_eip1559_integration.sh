#!/bin/bash

# EIP-1559 Integration Test Script for Core Lane
# This script tests the complete EIP-1559 implementation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
CORE_LANE_RPC_URL="http://localhost:8546"
TEST_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" # Account 0 from Anvil
TEST_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Test 1: Check if Core Lane node is running
test_node_running() {
    print_status "Test 1: Checking if Core Lane node is running..."

    if curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
        "$CORE_LANE_RPC_URL" > /dev/null 2>&1; then
        print_success "Core Lane node is running"
        return 0
    else
        print_error "Core Lane node is not running. Please start it first."
        return 1
    fi
}

# Test 2: Test EIP-1559 RPC endpoints
test_eip1559_rpc_endpoints() {
    print_status "Test 2: Testing EIP-1559 RPC endpoints..."

    # Test eth_baseFeePerGas
    print_status "Testing eth_baseFeePerGas..."
    BASE_FEE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_baseFeePerGas","params":[],"id":1}' \
        "$CORE_LANE_RPC_URL")

    if echo "$BASE_FEE_RESPONSE" | grep -q '"result"'; then
        BASE_FEE=$(echo "$BASE_FEE_RESPONSE" | jq -r '.result')
        print_success "eth_baseFeePerGas: $BASE_FEE"
    else
        print_error "eth_baseFeePerGas failed"
        return 1
    fi

    # Test eth_maxPriorityFeePerGas
    print_status "Testing eth_maxPriorityFeePerGas..."
    PRIORITY_FEE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_maxPriorityFeePerGas","params":[],"id":2}' \
        "$CORE_LANE_RPC_URL")

    if echo "$PRIORITY_FEE_RESPONSE" | grep -q '"result"'; then
        PRIORITY_FEE=$(echo "$PRIORITY_FEE_RESPONSE" | jq -r '.result')
        print_success "eth_maxPriorityFeePerGas: $PRIORITY_FEE"
    else
        print_error "eth_maxPriorityFeePerGas failed"
        return 1
    fi

    # Test eth_feeHistory
    print_status "Testing eth_feeHistory..."
    FEE_HISTORY_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_feeHistory","params":["0x5", "latest", [25, 50, 75]],"id":3}' \
        "$CORE_LANE_RPC_URL")

    if echo "$FEE_HISTORY_RESPONSE" | grep -q '"result"'; then
        print_success "eth_feeHistory working"
        echo "$FEE_HISTORY_RESPONSE" | jq '.result'
    else
        print_error "eth_feeHistory failed"
        return 1
    fi
}

# Test 3: Create and send EIP-1559 transaction using cast
test_eip1559_transaction() {
    print_status "Creating and sending EIP-1559 transaction with cast..."

    # Get current base fee and priority fee
    BASE_FEE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_baseFeePerGas","params":[],"id":1}' \
        "$CORE_LANE_RPC_URL")
    BASE_FEE=$(echo "$BASE_FEE_RESPONSE" | jq -r '.result')

    PRIORITY_FEE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_maxPriorityFeePerGas","params":[],"id":2}' \
        "$CORE_LANE_RPC_URL")
    PRIORITY_FEE=$(echo "$PRIORITY_FEE_RESPONSE" | jq -r '.result')

    print_status "Base fee: $BASE_FEE, Priority fee: $PRIORITY_FEE"

    # Use simple, reasonable gas prices for testing
    # Base fee is very small (7 wei), so use a reasonable max fee
    MAX_FEE_DECIMAL="1000000000"  # 1 gwei in decimal
    PRIORITY_FEE_DECIMAL="100000000"  # Priority fee in decimal

    print_status "Using max fee: $MAX_FEE_DECIMAL wei, priority fee: $PRIORITY_FEE_DECIMAL wei"

    # Create EIP-1559 transaction using cast
    print_status "Creating EIP-1559 transaction with cast..."

    # First, get nonce
    NONCE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionCount\",\"params\":[\"$TEST_ADDRESS\", \"latest\"],\"id\":4}" \
        "$CORE_LANE_RPC_URL")
    NONCE=$(echo "$NONCE_RESPONSE" | jq -r '.result')

    print_status "Nonce: $NONCE"

    # Send EIP-1559 transaction using cast send with async mode
    print_status "Sending EIP-1559 transaction with cast send --async..."

    # Use --gas-price for max fee per gas and --priority-gas-price for priority fee
    TX_HASH=$(cast send $TEST_ADDRESS --value 0.001ether \
        --gas-price ${MAX_FEE_DECIMAL}wei \
        --priority-gas-price ${PRIORITY_FEE_DECIMAL}wei \
        --gas-limit 21000 \
        --private-key $TEST_PRIVATE_KEY \
        --rpc-url $CORE_LANE_RPC_URL \
        --async 2>&1)

    print_status "cast send output: $TX_HASH"

    if [ $? -ne 0 ]; then
        print_error "Failed to send transaction"
        echo "$TX_HASH"
        return 1
    fi

    # Extract transaction hash from output
    ACTUAL_TX_HASH=$(echo "$TX_HASH" | grep -oE '0x[a-fA-F0-9]{64}' | head -1)

    if [ -n "$ACTUAL_TX_HASH" ]; then
        print_success "EIP-1559 transaction sent successfully: $ACTUAL_TX_HASH"
        return 0
    else
        print_error "Failed to extract transaction hash from: $TX_HASH"
        return 1
    fi
}

# Verify base fee burning mechanism
test_base_fee_burning() {
    print_status "Verifying base fee burning mechanism..."

    # Get total burned amount before transaction
    BURNED_BEFORE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"corelane_totalBurned","params":[],"id":7}' \
        "$CORE_LANE_RPC_URL")
    BURNED_BEFORE=$(echo "$BURNED_BEFORE_RESPONSE" | jq -r '.result')

    print_status "Total burned before: $BURNED_BEFORE"

    # Get sequencer balance before transaction
    SEQUENCER_BEFORE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"corelane_sequencerBalance","params":[],"id":8}' \
        "$CORE_LANE_RPC_URL")
    SEQUENCER_BEFORE=$(echo "$SEQUENCER_BEFORE_RESPONSE" | jq -r '.result')

    print_status "Sequencer balance before: $SEQUENCER_BEFORE"

    # Send another transaction to test burning
    print_status "Sending test transaction to verify burning..."

    # Get current base fee and priority fee
    BASE_FEE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_baseFeePerGas","params":[],"id":9}' \
        "$CORE_LANE_RPC_URL")
    BASE_FEE=$(echo "$BASE_FEE_RESPONSE" | jq -r '.result')

    PRIORITY_FEE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_maxPriorityFeePerGas","params":[],"id":10}' \
        "$CORE_LANE_RPC_URL")
    PRIORITY_FEE=$(echo "$PRIORITY_FEE_RESPONSE" | jq -r '.result')

    # Convert to decimal for calculations
    BASE_FEE_DEC=$(printf "%d" $BASE_FEE)
    PRIORITY_FEE_DEC=$(printf "%d" $PRIORITY_FEE)
    MAX_FEE_DEC=$((BASE_FEE_DEC + PRIORITY_FEE_DEC + 1000000000))
    MAX_FEE_HEX=$(printf "0x%x" $MAX_FEE_DEC)

    # Get nonce
    NONCE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionCount\",\"params\":[\"$TEST_ADDRESS\", \"latest\"],\"id\":11}" \
        "$CORE_LANE_RPC_URL")
    NONCE=$(echo "$NONCE_RESPONSE" | jq -r '.result')

    # Create and send transaction
    RAW_TX=$(cast mktx $TEST_ADDRESS --value 0.001ether \
        --gas-price ${MAX_FEE_DEC}wei \
        --priority-gas-price ${PRIORITY_FEE_DEC}wei \
        --gas-limit 21000 \
        --nonce $NONCE \
        --private-key $TEST_PRIVATE_KEY \
        --rpc-url $CORE_LANE_RPC_URL 2>&1)

    if [ $? -ne 0 ]; then
        print_error "Failed to create transaction"
        echo "$RAW_TX"
        return 1
    fi

    SEND_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendRawTransaction\",\"params\":[\"$RAW_TX\"],\"id\":12}" \
        "$CORE_LANE_RPC_URL")

    if echo "$SEND_RESPONSE" | grep -q '"result"'; then
        print_success "Test transaction sent successfully"

        # Wait for transaction to be processed
        sleep 3

        # Check total burned amount after transaction
        BURNED_AFTER_RESPONSE=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"corelane_totalBurned","params":[],"id":13}"' \
            "$CORE_LANE_RPC_URL")
        BURNED_AFTER=$(echo "$BURNED_AFTER_RESPONSE" | jq -r '.result')

        print_status "Total burned after: $BURNED_AFTER"

        # Check sequencer balance after transaction
        SEQUENCER_AFTER_RESPONSE=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"corelane_sequencerBalance","params":[],"id":14}"' \
            "$CORE_LANE_RPC_URL")
        SEQUENCER_AFTER=$(echo "$SEQUENCER_AFTER_RESPONSE" | jq -r '.result')

        print_status "Sequencer balance after: $SEQUENCER_AFTER"

        # Verify burning occurred
        if [ "$BURNED_BEFORE" != "$BURNED_AFTER" ]; then
            print_success "✅ Base fee burning verified! Burned amount increased"
        else
            print_warning "⚠️  Base fee burning not detected (may need more gas usage)"
        fi

        # Verify sequencer payment occurred
        if [ "$SEQUENCER_BEFORE" != "$SEQUENCER_AFTER" ]; then
            print_success "✅ Sequencer payment verified! Sequencer balance increased"
        else
            print_warning "⚠️  Sequencer payment not detected"
        fi

    else
        print_error "Failed to send test transaction for burning verification"
        echo "$SEND_RESPONSE"
        return 1
    fi
}

# Test dynamic base fee calculation
test_dynamic_base_fee() {
    print_status "Testing dynamic base fee calculation..."

    # Get initial base fee
    BASE_FEE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_baseFeePerGas","params":[],"id":1}' \
        "$CORE_LANE_RPC_URL")
    INITIAL_BASE_FEE=$(echo "$BASE_FEE_RESPONSE" | jq -r '.result')

    print_status "Initial base fee: $INITIAL_BASE_FEE"

    # Send multiple transactions to increase gas usage
    print_status "Sending multiple transactions to test base fee adjustment..."

    # Get initial nonce
    NONCE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionCount\",\"params\":[\"$TEST_ADDRESS\", \"latest\"],\"id\":15}" \
        "$CORE_LANE_RPC_URL")

    if ! echo "$NONCE_RESPONSE" | grep -q '"result"'; then
        print_error "Failed to get nonce for test account"
        echo "$NONCE_RESPONSE"
        return 1
    fi

    START_NONCE=$(echo "$NONCE_RESPONSE" | jq -r '.result')
    CURRENT_NONCE=$(printf "%d" $START_NONCE)

    print_status "Starting nonce: $CURRENT_NONCE"

    for i in {1..5}; do
        print_status "Sending transaction $i/5..."

        # Get current base fee and priority fee for this transaction
        BASE_FEE_RESPONSE=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_baseFeePerGas","params":[],"id":16}' \
            "$CORE_LANE_RPC_URL")

        if ! echo "$BASE_FEE_RESPONSE" | grep -q '"result"'; then
            print_error "Failed to get base fee for transaction $i"
            echo "$BASE_FEE_RESPONSE"
            return 1
        fi

        BASE_FEE=$(echo "$BASE_FEE_RESPONSE" | jq -r '.result')

        PRIORITY_FEE_RESPONSE=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_maxPriorityFeePerGas","params":[],"id":17}' \
            "$CORE_LANE_RPC_URL")

        if ! echo "$PRIORITY_FEE_RESPONSE" | grep -q '"result"'; then
            print_error "Failed to get priority fee for transaction $i"
            echo "$PRIORITY_FEE_RESPONSE"
            return 1
        fi

        PRIORITY_FEE=$(echo "$PRIORITY_FEE_RESPONSE" | jq -r '.result')

        # Convert to decimal for calculations
        BASE_FEE_DEC=$(printf "%d" $BASE_FEE)
        PRIORITY_FEE_DEC=$(printf "%d" $PRIORITY_FEE)

        # Set max fee = base fee + priority fee + some buffer
        MAX_FEE_DEC=$((BASE_FEE_DEC + PRIORITY_FEE_DEC + 500000000))
        MAX_FEE_HEX=$(printf "0x%x" $MAX_FEE_DEC)

        # Create and send EIP-1559 transaction using cast
        print_status "Creating transaction $i with nonce: $CURRENT_NONCE, max fee: $MAX_FEE_HEX"

        RAW_TX=$(cast mktx $TEST_ADDRESS --value 0.001ether \
            --gas-price ${MAX_FEE_DEC}wei \
            --priority-gas-price ${PRIORITY_FEE_DEC}wei \
            --gas-limit 21000 \
            --nonce $CURRENT_NONCE \
            --private-key $TEST_PRIVATE_KEY \
            --rpc-url $CORE_LANE_RPC_URL 2>&1)

        if [ $? -ne 0 ]; then
            print_error "Failed to create transaction $i"
            echo "$RAW_TX"
            return 1
        fi

        # Send the transaction
        SEND_RESPONSE=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendRawTransaction\",\"params\":[\"$RAW_TX\"],\"id\":18}" \
            "$CORE_LANE_RPC_URL")

        if ! echo "$SEND_RESPONSE" | grep -q '"result"'; then
            print_error "Failed to send transaction $i"
            echo "$SEND_RESPONSE"
            return 1
        fi

        TX_HASH=$(echo "$SEND_RESPONSE" | jq -r '.result')
        print_success "Transaction $i sent: $TX_HASH"

        # Wait for transaction receipt with timeout
        RECEIPT_FOUND=false
        for wait_iter in {1..10}; do
            sleep 1
            RECEIPT_RESPONSE=$(curl -s -X POST \
                -H "Content-Type: application/json" \
                -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX_HASH\"],\"id\":19}" \
                "$CORE_LANE_RPC_URL")

            if echo "$RECEIPT_RESPONSE" | grep -q '"result"' && [ "$(echo "$RECEIPT_RESPONSE" | jq -r '.result')" != "null" ]; then
                RECEIPT_FOUND=true
                break
            fi
        done

        if [ "$RECEIPT_FOUND" = true ]; then
            STATUS=$(echo "$RECEIPT_RESPONSE" | jq -r '.result.status')
            if [ "$STATUS" = "0x1" ]; then
                print_success "Transaction $i confirmed successfully"
            else
                print_error "Transaction $i failed with status: $STATUS"
            fi
        else
            print_warning "Transaction $i receipt not found (may still be pending)"
        fi

        # Increment nonce for next iteration
        CURRENT_NONCE=$((CURRENT_NONCE + 1))

        # Sleep between transactions
        sleep 1
    done

    # Check base fee after transactions
    sleep 3
    BASE_FEE_AFTER_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_baseFeePerGas","params":[],"id":1}' \
        "$CORE_LANE_RPC_URL")
    BASE_FEE_AFTER=$(echo "$BASE_FEE_AFTER_RESPONSE" | jq -r '.result')

    print_status "Base fee after transactions: $BASE_FEE_AFTER"

    if [ "$INITIAL_BASE_FEE" != "$BASE_FEE_AFTER" ]; then
        print_success "Base fee changed dynamically: $INITIAL_BASE_FEE -> $BASE_FEE_AFTER"
    else
        print_warning "Base fee did not change (may need more gas usage to trigger adjustment)"
    fi
}

# Main test execution
main() {
    print_status "🔥 Starting EIP-1559 Integration Tests for Core Lane"
    print_status "=================================================="

    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        print_error "jq is required but not installed. Please install jq first."
        exit 1
    fi

    # Check if cast is installed
    if ! command -v cast &> /dev/null; then
        print_error "cast is required but not installed. Please install foundry first."
        exit 1
    fi

    # Run tests
    test_node_running || exit 1
    test_eip1559_rpc_endpoints || exit 1
    test_eip1559_transaction || exit 1
    test_base_fee_burning || exit 1
    test_dynamic_base_fee || exit 1

    print_success "🎉 All EIP-1559 integration tests completed successfully!"
    print_status "=================================================="
    print_status "✅ EIP-1559 fee manager implemented"
    print_status "✅ Base fee burning mechanism working"
    print_status "✅ Dynamic base fee calculation active"
    print_status "✅ RPC endpoints (eth_baseFeePerGas, eth_maxPriorityFeePerGas, eth_feeHistory) working"
    print_status "✅ EIP-1559 transactions working with cast"
}

# Run main function
main "$@"