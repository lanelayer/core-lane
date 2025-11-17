#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[EXIT-INTENT]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
EXIT_MARKETPLACE="0x0000000000000000000000000000000000000045"
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
RPC_URL="http://127.0.0.1:8546"

# Default values
BITCOIN_ADDRESS=""
AMOUNT=""
MAX_FEE="1000"
EXPIRE_BY=""
NONCE=""

# Parse arguments
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --bitcoin-address <address>   Bitcoin address to receive funds"
    echo "  --amount <sats>              Amount in satoshis to withdraw"
    echo "  --max-fee <sats>             Maximum fee in satoshis (default: 1000)"
    echo "  --expire-by <block>          Block number when intent expires"
    echo "  --nonce <nonce>              Nonce for the intent (default: current timestamp)"
    echo "  --help                       Show this help message"
    echo ""
    echo "Note:"
    echo "  The script will automatically lock (amount + max_fee) worth of laneBTC/ETH in the intent."
    echo "  This locked value pays the filler bot for executing the Bitcoin withdrawal."
    echo ""
    echo "Example:"
    echo "  $0 --bitcoin-address bcrt1qjx6x6ra7k3gwcmmcpgcm8cejjppcxqpjl0fkfr --amount 50000 --expire-by 1000"
    echo "  (This will lock 51000 sats worth of laneBTC and request a 50000 sat Bitcoin withdrawal)"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --bitcoin-address)
            BITCOIN_ADDRESS="$2"
            shift 2
            ;;
        --amount)
            AMOUNT="$2"
            shift 2
            ;;
        --max-fee)
            MAX_FEE="$2"
            shift 2
            ;;
        --expire-by)
            EXPIRE_BY="$2"
            shift 2
            ;;
        --nonce)
            NONCE="$2"
            shift 2
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$BITCOIN_ADDRESS" ]; then
    print_error "Bitcoin address is required"
    show_usage
    exit 1
fi

if [ -z "$AMOUNT" ]; then
    print_error "Amount is required"
    show_usage
    exit 1
fi

if [ -z "$EXPIRE_BY" ]; then
    print_error "Expire by block is required"
    show_usage
    exit 1
fi

# Use current timestamp as nonce if not provided
if [ -z "$NONCE" ]; then
    NONCE=$(date +%s)
fi

print_status "Creating exit intent..."
print_status "Bitcoin Address: $BITCOIN_ADDRESS"
print_status "Amount: $AMOUNT sats"
print_status "Max Fee: $MAX_FEE sats"
print_status "Expire By: Block $EXPIRE_BY"
print_status "Nonce: $NONCE"

# Check if core-lane-node binary exists
if [ ! -f "./target/debug/core-lane-node" ]; then
    print_error "core-lane-node binary not found. Please build with 'cargo build' first."
    exit 1
fi

# Construct the exit intent
print_status "Constructing exit intent data..."
INTENT_OUTPUT=$(./target/debug/core-lane-node construct-exit-intent \
    --bitcoin-address "$BITCOIN_ADDRESS" \
    --amount "$AMOUNT" \
    --max-fee "$MAX_FEE" \
    --expire-by "$EXPIRE_BY" 2>&1)

# Extract the intent data hex from the output
INTENT_DATA=$(echo "$INTENT_OUTPUT" | grep "Intent Data (CBOR" | sed -n 's/.*: \(0x[0-9a-fA-F]*\).*/\1/p')

if [ -z "$INTENT_DATA" ]; then
    print_error "Failed to extract intent data from output:"
    echo "$INTENT_OUTPUT"
    exit 1
fi

print_success "Intent data constructed: $INTENT_DATA"

# Check if cast is installed
CAST_BIN="cast"
if command -v cast &> /dev/null; then
    CAST_BIN="cast"
elif [ -f "$HOME/.foundry/bin/cast" ]; then
    CAST_BIN="$HOME/.foundry/bin/cast"
else
    print_error "cast (foundry) is not installed. Please install foundry: https://getfoundry.sh"
    exit 1
fi

# Calculate the value to send (amount + max_fee in wei, converted from sats)
# Each sat = 10^10 wei on Core Lane
VALUE_WEI=$((($AMOUNT + $MAX_FEE) * 10000000000))

# Call the intent function on the exit marketplace
print_status "Submitting exit intent to marketplace at $EXIT_MARKETPLACE..."
print_status "Using nonce: $NONCE"
print_status "Locking value: $VALUE_WEI wei ($(($AMOUNT + $MAX_FEE)) sats)"

CAST_OUTPUT=$($CAST_BIN send --legacy \
    --private-key "$PRIVATE_KEY" \
    --rpc-url "$RPC_URL" \
    --value "$VALUE_WEI" \
    --async \
    "$EXIT_MARKETPLACE" \
    "intent(bytes,uint256)(bytes32)" \
    "$INTENT_DATA" \
    "$NONCE" 2>&1)

if [ $? -eq 0 ]; then
    print_success "Exit intent submitted successfully!"

    # Extract transaction hash
    TX_HASH=$(echo "$CAST_OUTPUT" | grep "transactionHash" | awk '{print $2}')
    if [ -n "$TX_HASH" ]; then
        print_success "Transaction hash: $TX_HASH"
    fi

    # Try to extract the intent ID from logs
    print_status "Checking for intent ID in transaction receipt..."
    sleep 2

    RECEIPT=$($CAST_BIN receipt --rpc-url "$RPC_URL" "$TX_HASH" 2>/dev/null || echo "")
    if [ -n "$RECEIPT" ]; then
        echo "$RECEIPT"
    fi

    print_success "✅ Exit intent created successfully!"
    print_status "The filler bot should detect and process this intent."
else
    print_error "Failed to submit exit intent:"
    echo "$CAST_OUTPUT"
    exit 1
fi

