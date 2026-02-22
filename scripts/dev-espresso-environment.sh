#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration for Espresso-derived Core Lane
ESPRESSO_BASE_URL_DEFAULT="https://query.decaf.testnet.espresso.network"
ESPRESSO_NAMESPACE_DEFAULT=0

# JSON-RPC endpoint for the Espresso-derived Core Lane node itself
# Must be different from the upstream Core Lane RPC URL port.
DERIVED_CORE_LANE_RPC_PORT=8545
DERIVED_CORE_LANE_RPC_URL="http://127.0.0.1:${DERIVED_CORE_LANE_RPC_PORT}"

# Data directory for the Espresso-derived node state. Keep this separate from any
# Bitcoin-DA Core Lane node state to avoid mixing anchor/hash histories.
DERIVED_CORE_LANE_DATA_DIR_DEFAULT="./derived-espresso-data"

# Upstream Core Lane JSON-RPC URL for reorg detection (Bitcoin DA mode Core Lane)
# The Espresso-derived node anchors each block to the upstream Core Lane tip and follows its reorgs.
CORE_LANE_RPC_URL_DEFAULT=""

CORE_LANE_NODE_PID=0
CORE_LANE_TAIL_PID=0

ANVIL_ADDRESSES=(
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
)

print_status() {
    echo -e "${BLUE}[ESPRESSO-DEV]${NC} $1"
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

check_core_lane_built() {
    if [ ! -f "./target/debug/core-lane-node" ]; then
        print_error "Core Lane node is not built (debug mode)"
        print_status "Building now..."
        cargo build
    fi
}

start_espresso_core_lane_node() {
    local espresso_base_url="${ESPRESSO_BASE_URL:-$ESPRESSO_BASE_URL_DEFAULT}"
    local espresso_namespace="${ESPRESSO_NAMESPACE:-$ESPRESSO_NAMESPACE_DEFAULT}"
    local data_dir="${DERIVED_CORE_LANE_DATA_DIR:-$DERIVED_CORE_LANE_DATA_DIR_DEFAULT}"

    local core_lane_rpc_url="${CORE_LANE_RPC_URL:-}"
    if [ -z "$core_lane_rpc_url" ]; then
        print_error "CORE_LANE_RPC_URL environment variable is required"
        exit 1
    fi
    if [[ "$core_lane_rpc_url" == *":${DERIVED_CORE_LANE_RPC_PORT}"* ]]; then
        print_error "CORE_LANE_RPC_URL (${core_lane_rpc_url}) must not use the derived node port (${DERIVED_CORE_LANE_RPC_PORT})"
        print_error "Use a different port for the upstream Core Lane node (e.g. 8546) or change DERIVED_CORE_LANE_RPC_PORT in this script"
        exit 1
    fi

    print_status "Starting Espresso-derived Core Lane node..."
    print_status "  Espresso base URL: ${espresso_base_url}"
    print_status "  Espresso namespace: ${espresso_namespace}"
    print_status "  Upstream Core Lane RPC URL: ${core_lane_rpc_url} (reorg detection enabled)"
    print_status "  Derived Core Lane data dir: ${data_dir}"

    check_core_lane_built

    RUST_LOG=info,debug ./target/debug/core-lane-node \
        --data-dir "${data_dir}" \
        derived-espresso-start \
        --espresso-base-url "${espresso_base_url}" \
        --espresso-namespace "${espresso_namespace}" \
        --core-lane-rpc-url "${core_lane_rpc_url}" \
        --http-host 127.0.0.1 \
        --http-port "${DERIVED_CORE_LANE_RPC_PORT}" \
        > derived-espresso.log 2>&1 &

    CORE_LANE_NODE_PID=$!

    print_status "Waiting for Espresso-derived Core Lane node to start..."
    sleep 3

    local wait_count=0
    while ! curl -s "${DERIVED_CORE_LANE_RPC_URL}" > /dev/null 2>&1 && [ $wait_count -lt 30 ]; do
        print_status "Waiting for JSON-RPC server to be ready at ${DERIVED_CORE_LANE_RPC_URL}..."
        sleep 2
        wait_count=$((wait_count + 1))
    done

    if [ $wait_count -ge 30 ]; then
        print_error "Espresso-derived Core Lane node failed to start (timeout)"
        exit 1
    fi

    print_success "Espresso-derived Core Lane node started with PID: ${CORE_LANE_NODE_PID}"
    print_status "JSON-RPC available at: ${DERIVED_CORE_LANE_RPC_URL}"
}

start_espresso_core_lane_tail() {
    print_status "Starting Espresso-derived Core Lane log viewer..."

    local wait_count=0
    while [ ! -f "derived-espresso.log" ] && [ $wait_count -lt 10 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done

    if [ ! -f "derived-espresso.log" ]; then
        print_warning "derived-espresso.log not found, skipping log viewer"
        return 0
    fi

    (
        tail -f derived-espresso.log 2>/dev/null | while IFS= read -r line; do
            clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
            echo -e "${GREEN}[ESPRESSO-LANE]${NC} $line"
        done
    ) &

    CORE_LANE_TAIL_PID=$!
    print_success "Espresso-derived Core Lane log viewer started (PID: ${CORE_LANE_TAIL_PID})"
}

cleanup() {
    print_status "Cleaning up Espresso-derived development environment..."

    if [ $CORE_LANE_TAIL_PID -ne 0 ] && kill -0 $CORE_LANE_TAIL_PID 2>/dev/null; then
        print_status "Stopping Espresso-derived log viewer (PID: ${CORE_LANE_TAIL_PID})..."
        kill $CORE_LANE_TAIL_PID 2>/dev/null || true
    else
        local tail_pids
        tail_pids=$(pgrep -f "tail -f derived-espresso.log" 2>/dev/null || true)
        if [ -n "$tail_pids" ]; then
            print_status "Stopping Espresso-derived log viewer (found by pattern)..."
            echo "$tail_pids" | xargs kill 2>/dev/null || true
        fi
    fi

    if [ $CORE_LANE_NODE_PID -ne 0 ] && kill -0 $CORE_LANE_NODE_PID 2>/dev/null; then
        print_status "Stopping Espresso-derived Core Lane node (PID: ${CORE_LANE_NODE_PID})..."
        kill $CORE_LANE_NODE_PID 2>/dev/null || true
    else
        local node_pids
        node_pids=$(pgrep -f "core-lane-node.*derived-espresso-start" 2>/dev/null || true)
        if [ -n "$node_pids" ]; then
            print_status "Stopping Espresso-derived Core Lane node (found by pattern)..."
            echo "$node_pids" | xargs kill 2>/dev/null || true
        fi
    fi

    sleep 1

    local remaining
    remaining=$(pgrep -f "core-lane-node.*derived-espresso-start" 2>/dev/null || true)
    if [ -n "$remaining" ]; then
        print_status "Force killing remaining Espresso-derived Core Lane node processes..."
        echo "$remaining" | xargs kill -9 2>/dev/null || true
    fi

    print_success "Cleanup complete"
}

show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start          Start Espresso-derived Core Lane dev environment"
    echo "  stop           Stop Espresso-derived Core Lane dev environment"
    echo "  test-submit    Submit a test transaction via /submit (hex arg optional)"
    echo "  help           Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  ESPRESSO_BASE_URL        Base URL for Espresso DA (default: ${ESPRESSO_BASE_URL_DEFAULT})"
    echo "  ESPRESSO_NAMESPACE       Namespace ID to use (default: ${ESPRESSO_NAMESPACE_DEFAULT})"
    echo "  CORE_LANE_RPC_URL        Upstream Core Lane JSON-RPC URL for reorg detection (required)"
    echo "  DERIVED_CORE_LANE_DATA_DIR  Data directory for derived node state (default: ${DERIVED_CORE_LANE_DATA_DIR_DEFAULT})"
}

start_dev_environment() {
    print_status "Starting Espresso-derived Core Lane Development Environment..."

    trap cleanup EXIT

    local data_dir="${DERIVED_CORE_LANE_DATA_DIR:-$DERIVED_CORE_LANE_DATA_DIR_DEFAULT}"

    start_espresso_core_lane_node
    start_espresso_core_lane_tail

    print_success "Espresso-derived development environment started successfully!"
    echo ""
    echo "🌐 JSON-RPC Endpoint: ${DERIVED_CORE_LANE_RPC_URL}"
    echo "🔗 /submit endpoint:  ${DERIVED_CORE_LANE_RPC_URL}/submit"
    echo ""
    echo "  Espresso base URL:  ${ESPRESSO_BASE_URL:-$ESPRESSO_BASE_URL_DEFAULT}"
    echo "  Espresso namespace: ${ESPRESSO_NAMESPACE:-$ESPRESSO_NAMESPACE_DEFAULT}"
    echo "  Derived Core Lane data dir: ${data_dir}"
    echo "  Upstream Core Lane RPC URL: ${CORE_LANE_RPC_URL:-<required>}"
    echo ""
    echo "🛑 Use '$0 stop' or press Ctrl+C to stop the environment"
    echo ""
}

stop_dev_environment() {
    print_status "Stopping Espresso-derived development environment..."
    cleanup
    print_success "Espresso-derived development environment stopped"
}

case "${1:-start}" in
    start)
        start_dev_environment
        print_status "Espresso-derived development environment is running. Press Ctrl+C to stop."
        wait
        ;;
    stop)
        stop_dev_environment
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

