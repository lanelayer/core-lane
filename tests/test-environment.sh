#!/bin/bash

# Core MEL Test Environment Setup
# This script sets up a local Bitcoin regtest network for Core MEL development

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BITCOIN_CONTAINER="bitcoin-regtest"
BITCOIN_DATA_DIR="$HOME/bitcoin-regtest"
CORE_MEL_DIR="$(pwd)"
RPC_USER="bitcoin"
RPC_PASSWORD="bitcoin123"
RPC_URL="http://127.0.0.1:18443"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

# Function to check if Bitcoin container is running
is_bitcoin_running() {
    docker ps --format "table {{.Names}}" | grep -q "^${BITCOIN_CONTAINER}$"
}

# Function to run Bitcoin CLI command
bitcoin_cli() {
    docker exec $BITCOIN_CONTAINER bitcoin-cli -regtest -rpcuser=$RPC_USER -rpcpassword=$RPC_PASSWORD "$@"
}

# Function to start Bitcoin regtest
start_bitcoin() {
    print_status "Starting Bitcoin regtest network..."
    
    # Create data directory
    mkdir -p "$BITCOIN_DATA_DIR"
    
    # Pull Bitcoin Core image if not exists
    if ! docker images | grep -q "bitcoin/bitcoin.*29.0"; then
        print_status "Pulling Bitcoin Core 29.0 image..."
        docker pull bitcoin/bitcoin:29.0
    fi
    
    # Start Bitcoin container
    docker run --rm -d --name $BITCOIN_CONTAINER \
        -p 18443:18443 -p 18444:18444 \
        -v "$BITCOIN_DATA_DIR:/bitcoin/.bitcoin" \
        bitcoin/bitcoin:29.0 \
        -regtest \
        -fallbackfee=0.0002 \
        -maxtxfee=1.0 \
        -server=1 \
        -printtoconsole \
        -rpcuser=$RPC_USER \
        -rpcpassword=$RPC_PASSWORD \
        -rpcallowip=0.0.0.0/0 \
        -rpcbind=0.0.0.0 \
        -txindex=1
    
    # Wait for Bitcoin to start
    print_status "Waiting for Bitcoin to start..."
    sleep 5
    
    # Wait for RPC to be ready
    while ! bitcoin_cli getblockchaininfo > /dev/null 2>&1; do
        print_status "Waiting for Bitcoin RPC to be ready..."
        sleep 2
    done
    
    print_success "Bitcoin regtest network started!"
}

# Function to stop Bitcoin regtest
stop_bitcoin() {
    print_status "Stopping Bitcoin regtest network..."
    if is_bitcoin_running; then
        docker stop $BITCOIN_CONTAINER
        print_success "Bitcoin regtest network stopped!"
    else
        print_warning "Bitcoin container is not running."
    fi
}

# Function to reset Bitcoin regtest (clean slate)
reset_bitcoin() {
    print_status "Resetting Bitcoin regtest network..."
    stop_bitcoin
    
    if [ -d "$BITCOIN_DATA_DIR" ]; then
        print_status "Removing Bitcoin data directory..."
        rm -rf "$BITCOIN_DATA_DIR"
    fi
    
    print_success "Bitcoin regtest network reset!"
}

# Function to setup wallet and mine initial blocks
setup_wallet() {
    print_status "Setting up Bitcoin wallet..."
    
    # Create wallet
    bitcoin_cli createwallet "mine" || print_warning "Wallet 'mine' already exists"
    
    # Get new address
    ADDRESS=$(bitcoin_cli -rpcwallet=mine getnewaddress "" bech32)
    print_status "Generated address: $ADDRESS"
    
    # Mine 101 blocks to activate coinbase
    print_status "Mining 101 blocks to activate coinbase..."
    bitcoin_cli -rpcwallet=mine generatetoaddress 101 "$ADDRESS" > /dev/null
    
    # Check balance
    BALANCE=$(bitcoin_cli -rpcwallet=mine getbalances | grep -o '"mineable": [0-9.]*' | grep -o '[0-9.]*')
    print_success "Mined 101 blocks. Balance: $BALANCE BTC"
    
    echo "$ADDRESS" > .test-address
    print_status "Test address saved to .test-address"
}

# Function to build Core MEL
build_core_mel() {
    print_status "Building Core MEL node..."
    cd "$CORE_MEL_DIR"
    cargo build
    print_success "Core MEL node built successfully!"
}

# Function to test Core MEL connection
test_core_mel_connection() {
    print_status "Testing Core MEL connection to Bitcoin..."
    
    if [ ! -f "target/debug/core-mel-node" ]; then
        print_error "Core MEL node not built. Run 'build' first."
        return 1
    fi
    
    # Test connection by scanning a few blocks
    ./target/debug/core-mel-node scan-blocks \
        --rpc-url "$RPC_URL" \
        --rpc-user "$RPC_USER" \
        --rpc-password "$RPC_PASSWORD" \
        --blocks 5
    
    print_success "Core MEL connection test completed!"
}

# Function to create test burn transaction
create_test_burn() {
    print_status "Creating test Bitcoin burn transaction..."
    
    if [ ! -f ".test-address" ]; then
        print_error "No test address found. Run 'setup-wallet' first."
        return 1
    fi
    
    ADDRESS=$(cat .test-address)
    
    # Check if Core MEL is built
    if [ ! -f "target/debug/core-mel-node" ]; then
        print_error "Core MEL node not built. Run 'build' first."
        return 1
    fi
    
    print_status "Test address: $ADDRESS"
    print_status "To create a burn transaction, you just need an Ethereum address!"
    echo
    print_status "Example burn command (burns 500,000 sats):"
    echo "./target/debug/core-mel-node burn \\"
    echo "  --burn-amount 500000 \\"
    echo "  --chain-id 1 \\"
    echo "  --eth-address \"0x1234567890123456789012345678901234567890\" \\"
    echo "  --rpc-password bitcoin123"
    echo
    print_status "This will:"
    echo "1. Use your Bitcoin wallet (default: 'mine') to fund the transaction"
    echo "2. Create an OP_RETURN transaction burning 500,000 sats"
    echo "3. Automatically mint 500,000 Core MEL tokens to the ETH address"
    echo "4. Handle all transaction creation, signing, and broadcasting"
}

# Function to show status
show_status() {
    print_status "=== Core MEL Test Environment Status ==="
    
    echo
    print_status "Bitcoin Container:"
    if is_bitcoin_running; then
        print_success "✓ Running"
        echo "  Container: $BITCOIN_CONTAINER"
        echo "  RPC URL: $RPC_URL"
        echo "  RPC User: $RPC_USER"
        
        # Get blockchain info
        if bitcoin_cli getblockchaininfo > /dev/null 2>&1; then
            BLOCKS=$(bitcoin_cli getblockcount)
            print_success "  Blocks: $BLOCKS"
        fi
    else
        print_error "✗ Not running"
    fi
    
    echo
    print_status "Core MEL:"
    if [ -f "target/debug/core-mel-node" ]; then
        print_success "✓ Built"
    else
        print_error "✗ Not built"
    fi
    
    echo
    print_status "Test Data:"
    if [ -f ".test-address" ]; then
        ADDRESS=$(cat .test-address)
        print_success "✓ Test address: $ADDRESS"
    else
        print_error "✗ No test address"
    fi
}

# Function to show help
show_help() {
    echo "Core MEL Test Environment"
    echo
    echo "Usage: $0 <command>"
    echo
    echo "Commands:"
    echo "  start           Start Bitcoin regtest network"
    echo "  stop            Stop Bitcoin regtest network"
    echo "  reset           Reset Bitcoin regtest network (clean slate)"
    echo "  setup-wallet    Setup wallet and mine initial blocks"
    echo "  build           Build Core MEL node"
    echo "  test            Test Core MEL connection to Bitcoin"
    echo "  create-burn     Create test burn transaction"
    echo "  status          Show current status"
    echo "  help            Show this help"
    echo
    echo "Examples:"
    echo "  $0 start setup-wallet build test"
    echo "  $0 status"
    echo "  $0 reset"
}

# Main script logic
case "${1:-help}" in
    start)
        check_docker
        start_bitcoin
        ;;
    stop)
        stop_bitcoin
        ;;
    reset)
        check_docker
        reset_bitcoin
        ;;
    setup-wallet)
        if ! is_bitcoin_running; then
            print_error "Bitcoin is not running. Run 'start' first."
            exit 1
        fi
        setup_wallet
        ;;
    build)
        build_core_mel
        ;;
    test)
        test_core_mel_connection
        ;;
    create-burn)
        create_test_burn
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        echo
        show_help
        exit 1
        ;;
esac
