#!/bin/bash

set -e

trap cleanup EXIT

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

BITCOIN_CONTAINER="bitcoin-regtest"
BITCOIN_DATA_DIR="$HOME/bitcoin-regtest"
RPC_USER="bitcoin"
RPC_PASSWORD="bitcoin123"
RPC_URL="http://127.0.0.1:18443"
JSON_RPC_PORT=8546
JSON_RPC_URL="http://127.0.0.1:$JSON_RPC_PORT"
CORE_MEL_NODE_PID=0
MINING_PID=0

ANVIL_ADDRESSES=(
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
)

print_status() {
    echo -e "${BLUE}[DEV]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

is_bitcoin_running() {
    docker ps --format "table {{.Names}}" | grep -q "^${BITCOIN_CONTAINER}$"
}

bitcoin_cli() {
    docker exec $BITCOIN_CONTAINER bitcoin-cli -regtest -rpcuser=$RPC_USER -rpcpassword=$RPC_PASSWORD "$@"
}

start_bitcoin() {
    print_status "Starting Bitcoin regtest network..."

    mkdir -p "$BITCOIN_DATA_DIR"

    if ! docker images | grep -q "bitcoin/bitcoin.*29.0"; then
        print_status "Pulling Bitcoin Core 29.0 image..."
        docker pull bitcoin/bitcoin:29.0
    fi

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

    print_status "Waiting for Bitcoin to start..."
    sleep 5

    while ! bitcoin_cli getblockchaininfo > /dev/null 2>&1; do
        print_status "Waiting for Bitcoin RPC to be ready..."
        sleep 2
    done

    print_success "Bitcoin regtest network started!"
}

setup_bitcoin_wallet() {
    print_status "Setting up Bitcoin wallet..."

    bitcoin_cli createwallet "mine" 2>/dev/null || print_warning "Wallet 'mine' already exists"

    local address=$(bitcoin_cli -rpcwallet=mine getnewaddress "" bech32)
    print_status "Generated address: $address"

    print_status "Mining 101 blocks to activate coinbase..."
    bitcoin_cli -rpcwallet=mine generatetoaddress 101 "$address" >/dev/null 2>&1

    local balance_info=$(bitcoin_cli -rpcwallet=mine getbalances)
    local mineable_balance=$(echo "$balance_info" | grep -o '"mineable": [0-9.]*' | grep -o '[0-9.]*')
    print_status "Mined 101 blocks. Mineable balance: $mineable_balance BTC"

    bitcoin_cli -rpcwallet=mine generatetoaddress 10 "$address" >/dev/null 2>&1

    local final_balance=$(bitcoin_cli -rpcwallet=mine getbalances | grep -o '"mineable": [0-9.]*' | grep -o '[0-9.]*')
    print_success "Final balance: $final_balance BTC"
}

burn_btc_to_address() {
    local address="$1"
    local amount="$2"
    local chain_id="${3:-1}"

    print_status "Burning $amount sats to $address..."

    local burn_output=$(./target/debug/core-mel-node burn \
        --burn-amount $amount \
        --chain-id $chain_id \
        --eth-address $address \
        --rpc-password $RPC_PASSWORD 2>&1)

    if echo "$burn_output" | grep -q "✅ Burn transaction created and broadcast successfully"; then
        local txid=$(echo "$burn_output" | grep "📍 Transaction ID:" | grep -o '[a-f0-9]\{64\}')
        print_success "Burn transaction created: $txid"
        return 0
    else
        print_error "Failed to create burn transaction: $burn_output"
        return 1
    fi
}

start_core_mel_node() {
    print_status "Starting Core MEL node..."

    if [ ! -f "target/debug/core-mel-node" ]; then
        print_error "Core MEL node is not built. Run 'cargo build' first."
        exit 1
    fi

    RUST_LOG=info ./target/debug/core-mel-node start \
        --start-block 0 \
        --rpc-user $RPC_USER \
        --rpc-password $RPC_PASSWORD \
        --http-host 127.0.0.1 \
        --http-port $JSON_RPC_PORT > /tmp/core_mel_dev_output 2>&1 &

    CORE_MEL_NODE_PID=$!

    print_status "Waiting for Core MEL node to start..."
    sleep 3

    while ! curl -s "$JSON_RPC_URL" > /dev/null 2>&1; do
        print_status "Waiting for JSON-RPC server to be ready..."
        sleep 2
    done

    print_success "Core MEL node started with PID: $CORE_MEL_NODE_PID"
    print_status "JSON-RPC available at: $JSON_RPC_URL"
}

start_mining_loop() {
    print_status "Starting continuous mining loop (every 10 seconds)..."

    (
        while true; do
            sleep 10
            if is_bitcoin_running; then
                local address=$(bitcoin_cli -rpcwallet=mine getnewaddress "" bech32)
                bitcoin_cli -rpcwallet=mine generatetoaddress 1 "$address" >/dev/null 2>&1
                local block_count=$(bitcoin_cli getblockcount)
                print_status "Mined block $block_count"
            else
                print_warning "Bitcoin not running, stopping mining loop"
                break
            fi
        done
    ) &

    MINING_PID=$!
    print_success "Mining loop started with PID: $MINING_PID"
}

check_balances() {
    print_status "Checking Core MEL balances..."

    for i in "${!ANVIL_ADDRESSES[@]}"; do
        local address="${ANVIL_ADDRESSES[$i]}"
        local balance=$(curl -s -X POST "$JSON_RPC_URL" \
            -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$address\", \"latest\"],\"id\":1}" | \
            jq -r '.result // "0x0"')

        if [ "$balance" != "0x0" ] && [ "$balance" != "null" ]; then
            local balance_dec=$(printf "%d" "$balance")
            local balance_eth=$(echo "scale=18; $balance_dec / 1000000000000000000" | bc -l 2>/dev/null || echo "unknown")
            print_success "Address $i ($address): $balance_eth ETH ($balance wei)"
        else
            print_warning "Address $i ($address): 0 ETH"
        fi
    done
}

cleanup() {
    print_status "Cleaning up development environment..."

    if [ $MINING_PID -ne 0 ]; then
        print_status "Stopping mining loop (PID: $MINING_PID)..."
        kill $MINING_PID 2>/dev/null || true
    fi

    if [ $CORE_MEL_NODE_PID -ne 0 ]; then
        print_status "Stopping Core MEL node (PID: $CORE_MEL_NODE_PID)..."
        kill $CORE_MEL_NODE_PID 2>/dev/null || true
    fi

    if is_bitcoin_running; then
        print_status "Stopping Bitcoin regtest network..."
        docker stop $BITCOIN_CONTAINER >/dev/null 2>&1 || true
    fi

    print_success "Cleanup complete"
}

show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start     Start the complete development environment"
    echo "  stop      Stop the development environment"
    echo "  status    Show status of running services"
    echo "  balances  Check Core MEL balances for test addresses"
    echo "  help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start     # Start everything"
    echo "  $0 stop      # Stop everything"
    echo "  $0 balances # Check balances"
}

show_status() {
    echo "=== Core MEL Development Environment Status ==="

    if is_bitcoin_running; then
        echo "✅ Bitcoin: Running"
        local block_count=$(bitcoin_cli getblockcount 2>/dev/null || echo "unknown")
        echo "   Block height: $block_count"
    else
        echo "❌ Bitcoin: Not running"
    fi

    if [ $CORE_MEL_NODE_PID -ne 0 ] && kill -0 $CORE_MEL_NODE_PID 2>/dev/null; then
        echo "✅ Core MEL Node: Running (PID: $CORE_MEL_NODE_PID)"
        echo "   JSON-RPC: $JSON_RPC_URL"
    else
        echo "❌ Core MEL Node: Not running"
    fi

    if [ $MINING_PID -ne 0 ] && kill -0 $MINING_PID 2>/dev/null; then
        echo "✅ Mining Loop: Running (PID: $MINING_PID)"
    else
        echo "❌ Mining Loop: Not running"
    fi

    echo ""
    echo "Test addresses:"
    for i in "${!ANVIL_ADDRESSES[@]}"; do
        echo "  ($i) ${ANVIL_ADDRESSES[$i]}"
    done
}

start_dev_environment() {
    print_status "Starting Core MEL Development Environment..."

    check_docker

    if ! is_bitcoin_running; then
        start_bitcoin
    else
        print_warning "Bitcoin is already running"
    fi

    setup_bitcoin_wallet
    start_core_mel_node

    print_status "Burning BTC to test addresses..."
    for address in "${ANVIL_ADDRESSES[@]}"; do
        burn_btc_to_address "$address" 1000000 1
        sleep 2
    done

    start_mining_loop
    sleep 5
    check_balances

    print_success "Development environment started successfully!"
    echo ""
    echo "🌐 JSON-RPC Endpoint: $JSON_RPC_URL"
    echo "🔗 Connect with MetaMask, Cast, or other wallets using:"
    echo "   Network Name: Core MEL Dev"
    echo "   RPC URL: $JSON_RPC_URL"
    echo "   Chain ID: 1"
    echo "   Currency Symbol: MEL"
    echo ""
    echo "📱 Test addresses with balances:"
    for i in "${!ANVIL_ADDRESSES[@]}"; do
        echo "  ($i) ${ANVIL_ADDRESSES[$i]}"
    done
    echo ""
    echo "⛏️  Mining blocks every 10 seconds..."
    echo "🛑 Use '$0 stop' to stop the environment"
}

stop_dev_environment() {
    print_status "Stopping development environment..."
    cleanup
    print_success "Development environment stopped"
}

case "${1:-start}" in
    start)
        start_dev_environment
        print_status "Development environment is running. Press Ctrl+C to stop."
        wait
        ;;
    stop)
        stop_dev_environment
        ;;
    status)
        show_status
        ;;
    balances)
        check_balances
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        print_error "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac
