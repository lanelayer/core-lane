#!/bin/bash

set -e

# Trap will be set only when starting the environment

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CORE_LANE_RPC_URL="http://127.0.0.1:8546"
DERIVED_LANE_RPC_PORT=9545
DERIVED_LANE_RPC_URL="http://127.0.0.1:$DERIVED_LANE_RPC_PORT"
CHAIN_ID=1281453634
CORE_LANE_BURN_ADDRESS="0x0000000000000000000000000000000000000666"
DERIVED_LANE_NODE_PID=0
DERIVED_LANE_TAIL_PID=0

# Anvil test addresses and private keys (standard Anvil defaults)
ANVIL_ADDRESSES=(
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
)

# First Anvil account private key
ANVIL_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Derived DA address (required parameter - user should set this)
DERIVED_DA_ADDRESS="${DERIVED_DA_ADDRESS:-0x0000000000000000000000000000000000000000}"

print_status() {
    echo -e "${BLUE}[DERIVED-DEV]${NC} $1"
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

check_core_lane_running() {
    if ! curl -s "$CORE_LANE_RPC_URL" > /dev/null 2>&1; then
        print_error "Core Lane RPC is not accessible at $CORE_LANE_RPC_URL"
        print_status "Please start the core lane dev environment first:"
        print_status "  ./scripts/dev-environment.sh start"
        return 1
    fi
    return 0
}

check_dependencies() {
    if ! command -v cast &> /dev/null; then
        print_error "cast (foundry) is not installed. Please install foundry:"
        print_status "  curl -L https://foundry.paradigm.xyz | bash"
        print_status "  foundryup"
        exit 1
    fi

    if [ ! -f "./target/debug/core-lane-node" ]; then
        print_error "Core Lane node is not built (debug mode)"
        print_status "Building now..."
        cargo build
    fi
}

start_derived_lane_node() {
    print_status "Starting Derived Lane node..."

    if [ "$DERIVED_DA_ADDRESS" = "0x0000000000000000000000000000000000000000" ]; then
        print_error "DERIVED_DA_ADDRESS is not set!"
        print_status "Please set the derived DA address:"
        print_status "  export DERIVED_DA_ADDRESS=0x..."
        print_status "  $0 start"
        exit 1
    fi

    # Check if core lane is running
    if ! check_core_lane_running; then
        exit 1
    fi

    # Start derived lane node
    RUST_LOG=info,debug ./target/debug/core-lane-node derived-start \
        --core-rpc-url "$CORE_LANE_RPC_URL" \
        --chain-id "$CHAIN_ID" \
        --derived-da-address "$DERIVED_DA_ADDRESS" \
        --start-block 0 \
        --http-host 127.0.0.1 \
        --http-port "$DERIVED_LANE_RPC_PORT" \
        > derived-lane.log 2>&1 &

    DERIVED_LANE_NODE_PID=$!

    print_status "Waiting for Derived Lane node to start..."
    sleep 3

    local wait_count=0
    while ! curl -s "$DERIVED_LANE_RPC_URL" > /dev/null 2>&1 && [ $wait_count -lt 30 ]; do
        print_status "Waiting for JSON-RPC server to be ready..."
        sleep 2
        wait_count=$((wait_count + 1))
    done

    if [ $wait_count -ge 30 ]; then
        print_error "Derived Lane node failed to start (timeout)"
        exit 1
    fi

    print_success "Derived Lane node started with PID: $DERIVED_LANE_NODE_PID"
    print_status "JSON-RPC available at: $DERIVED_LANE_RPC_URL"
}

start_derived_lane_tail() {
    print_status "Starting Derived Lane log viewer..."

    # Wait for log file to exist
    local wait_count=0
    while [ ! -f "derived-lane.log" ] && [ $wait_count -lt 10 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done

    if [ ! -f "derived-lane.log" ]; then
        print_warning "Derived Lane log file not found, skipping log viewer"
        return 0
    fi

    # Start tailing the log with a prefix
    (
        tail -f derived-lane.log 2>/dev/null | while IFS= read -r line; do
            # Strip ANSI color codes and add our own prefix
            clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
            echo -e "${GREEN}[DERIVED-LANE]${NC} $clean_line"
        done
    ) &

    DERIVED_LANE_TAIL_PID=$!
    print_success "Derived Lane log viewer started (PID: $DERIVED_LANE_TAIL_PID)"
}

make_core_lane_burn() {
    local recipient_address="$1"
    local amount="${2:-10000000}"  # Default 10000000 wei

    print_status "Making Core Lane burn to $recipient_address (amount: $amount wei)..."

    # Build burn data: chain_id (4 bytes) + recipient address (20 bytes)
    # Chain ID 1281453634 = 0x4c616e42 in hex
    local recipient_no_0x="${recipient_address#0x}"
    local burn_data="0x4c616e42${recipient_no_0x}"

    print_status "Burn data: $burn_data"

    # Send burn transaction to core lane
    local burn_result=$(cast send "$CORE_LANE_BURN_ADDRESS" \
        --rpc-url "$CORE_LANE_RPC_URL" \
        --chain-id "$CHAIN_ID" \
        --private-key "$ANVIL_PRIVATE_KEY" \
        --value "$amount" \
        "$burn_data" 2>&1)

    if echo "$burn_result" | grep -q "transactionHash\|txHash"; then
        local tx_hash=$(echo "$burn_result" | grep -oE "0x[a-fA-F0-9]{64}" | head -1)
        print_success "Core Lane burn transaction created: $tx_hash"
        return 0
    else
        print_error "Failed to create burn transaction: $burn_result"
        return 1
    fi
}

test_derived_transfer() {
    local recipient="${1:-${ANVIL_ADDRESSES[2]}}"  # Default to third anvil address
    local amount="${2:-100000}"  # Default 100000 wei

    print_status "Testing transfer on Derived Lane..."
    print_status "Sending $amount wei from ${ANVIL_ADDRESSES[0]} to $recipient"

    local transfer_result=$(cast send "$recipient" \
        --rpc-url "$DERIVED_LANE_RPC_URL" \
        --chain-id "$CHAIN_ID" \
        --private-key "$ANVIL_PRIVATE_KEY" \
        --value "$amount" 2>&1)

    if echo "$transfer_result" | grep -q "transactionHash\|txHash"; then
        local tx_hash=$(echo "$transfer_result" | grep -oE "0x[a-fA-F0-9]{64}" | head -1)
        print_success "Derived Lane transfer transaction created: $tx_hash"
        return 0
    else
        print_error "Failed to create transfer transaction: $transfer_result"
        return 1
    fi
}

check_derived_balances() {
    print_status "Checking Derived Lane balances..."

    for i in "${!ANVIL_ADDRESSES[@]}"; do
        local address="${ANVIL_ADDRESSES[$i]}"
        local balance=$(cast balance "$address" --rpc-url "$DERIVED_LANE_RPC_URL" 2>/dev/null || echo "0")

        if [ "$balance" != "0" ] && [ "$balance" != "null" ]; then
            print_success "Address $i ($address): $balance wei"
        else
            print_warning "Address $i ($address): 0 wei"
        fi
    done
}

cleanup() {
    print_status "Cleaning up derived development environment..."

    # Stop Derived Lane log viewer
    if [ $DERIVED_LANE_TAIL_PID -ne 0 ] && kill -0 $DERIVED_LANE_TAIL_PID 2>/dev/null; then
        print_status "Stopping Derived Lane log viewer (PID: $DERIVED_LANE_TAIL_PID)..."
        kill $DERIVED_LANE_TAIL_PID 2>/dev/null || true
    else
        local derived_tail_pids=$(pgrep -f "tail -f derived-lane.log" 2>/dev/null || true)
        if [ -n "$derived_tail_pids" ]; then
            print_status "Stopping Derived Lane log viewer (found by pattern)..."
            echo "$derived_tail_pids" | xargs kill 2>/dev/null || true
        fi
    fi

    # Stop Derived Lane node
    if [ $DERIVED_LANE_NODE_PID -ne 0 ] && kill -0 $DERIVED_LANE_NODE_PID 2>/dev/null; then
        print_status "Stopping Derived Lane node (PID: $DERIVED_LANE_NODE_PID)..."
        kill $DERIVED_LANE_NODE_PID 2>/dev/null || true
    else
        local derived_pids=$(pgrep -f "core-lane-node.*derived-start" 2>/dev/null || true)
        if [ -n "$derived_pids" ]; then
            print_status "Stopping Derived Lane node (found by pattern)..."
            echo "$derived_pids" | xargs kill 2>/dev/null || true
        fi
    fi

    sleep 1

    local remaining_derived=$(pgrep -f "core-lane-node.*derived-start" 2>/dev/null || true)
    if [ -n "$remaining_derived" ]; then
        print_status "Force killing remaining Derived Lane node processes..."
        echo "$remaining_derived" | xargs kill -9 2>/dev/null || true
    fi

    print_success "Cleanup complete"
}

show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start     Start the derived lane development environment"
    echo "  stop      Stop the derived lane development environment"
    echo "  status    Show status of running services"
    echo "  burn      Make a Core Lane burn to test address"
    echo "  transfer  Test a transfer on Derived Lane"
    echo "  balances  Check Derived Lane balances for test addresses"
    echo "  help      Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  DERIVED_DA_ADDRESS  Derived DA feed address (required for start)"
    echo ""
    echo "Examples:"
    echo "  export DERIVED_DA_ADDRESS=0x..."
    echo "  $0 start                    # Start derived lane"
    echo "  $0 burn                     # Make a core lane burn"
    echo "  $0 transfer                 # Test a transfer on derived lane"
    echo "  $0 stop                     # Stop derived lane"
}

show_status() {
    echo "=== Derived Lane Development Environment Status ==="

    # Check Core Lane by checking if port is listening
    if curl -s "$CORE_LANE_RPC_URL" > /dev/null 2>&1; then
        echo "✅ Core Lane: Running"
        echo "   JSON-RPC: $CORE_LANE_RPC_URL"
    else
        echo "❌ Core Lane: Not running"
        echo "   Please start with: ./scripts/dev-environment.sh start"
    fi

    # Check Derived Lane Node
    local derived_pid=$(pgrep -f "core-lane-node.*derived-start" | head -1)
    if [ -n "$derived_pid" ] || (curl -s "$DERIVED_LANE_RPC_URL" > /dev/null 2>&1); then
        if [ -n "$derived_pid" ]; then
            echo "✅ Derived Lane Node: Running (PID: $derived_pid)"
        else
            echo "✅ Derived Lane Node: Running (detected via JSON-RPC)"
        fi
        echo "   JSON-RPC: $DERIVED_LANE_RPC_URL"
        echo "   Logs: derived-lane.log"
    else
        echo "❌ Derived Lane Node: Not running"
    fi

    echo ""
    echo "Test addresses:"
    for i in "${!ANVIL_ADDRESSES[@]}"; do
        echo "  ($i) ${ANVIL_ADDRESSES[$i]}"
    done
}

start_dev_environment() {
    print_status "Starting Derived Lane Development Environment..."

    # Set trap for cleanup on exit (only when starting)
    trap cleanup EXIT

    check_dependencies

    if ! check_core_lane_running; then
        exit 1
    fi

    start_derived_lane_node
    start_derived_lane_tail

    print_success "Derived Lane development environment started successfully!"
    echo ""
    echo "🌐 Core Lane JSON-RPC: $CORE_LANE_RPC_URL"
    echo "🌐 Derived Lane JSON-RPC: $DERIVED_LANE_RPC_URL"
    echo "🔗 Chain ID: $CHAIN_ID"
    echo ""
    echo "📱 Test addresses:"
    for i in "${!ANVIL_ADDRESSES[@]}"; do
        echo "  ($i) ${ANVIL_ADDRESSES[$i]}"
    done
    echo ""
    echo "📝 Derived Lane: Logs shown with [DERIVED-LANE] prefix (also in derived-lane.log)"
    echo ""
    echo "🧪 Next steps:"
    echo "  1. Make a Core Lane burn: $0 burn"
    echo "  2. Check balances: $0 balances"
    echo "  3. Test transfer: $0 transfer"
    echo ""
    echo "🛑 Use '$0 stop' or press Ctrl+C to stop the environment"
    echo ""
}

stop_dev_environment() {
    print_status "Stopping derived lane development environment..."
    cleanup
    print_success "Derived lane development environment stopped"
}

case "${1:-start}" in
    start)
        start_dev_environment
        print_status "Derived Lane development environment is running. Press Ctrl+C to stop."
        wait
        ;;
    stop)
        stop_dev_environment
        ;;
    status)
        show_status
        exit 0
        ;;
    burn)
        if ! check_core_lane_running; then
            exit 1
        fi
        make_core_lane_burn "${ANVIL_ADDRESSES[2]}" 10000000
        ;;
    transfer)
        if ! curl -s "$DERIVED_LANE_RPC_URL" > /dev/null 2>&1; then
            print_error "Derived Lane RPC is not accessible at $DERIVED_LANE_RPC_URL"
            print_status "Please start the derived lane first: $0 start"
            exit 1
        fi
        test_derived_transfer
        ;;
    balances)
        if ! curl -s "$DERIVED_LANE_RPC_URL" > /dev/null 2>&1; then
            print_error "Derived Lane RPC is not accessible at $DERIVED_LANE_RPC_URL"
            print_status "Please start the derived lane first: $0 start"
            exit 1
        fi
        check_derived_balances
        ;;
    help|--help|-h)
        show_usage
        exit 0
        ;;
    *)
        print_error "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac


