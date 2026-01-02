#!/bin/bash

set -e

# Trap will be set only when starting the environment

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
# Sequencer RPC URL for forwarding transactions (optional)
# Set via SEQUENCER_RPC_URL environment variable or --sequencer-rpc-url flag
SEQUENCER_RPC_URL="${SEQUENCER_RPC_URL:-}"
CORE_LANE_NODE_PID=0
CORE_LANE_TAIL_PID=0
MINING_PID=0
FILLER_BOT_PID=0
FILLER_BOT_TAIL_PID=0
FILLER_BOT_DIR="external/filler-bot"
FILLER_BOT_PRIVATE_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
FILLER_BOT_MNEMONIC="test test test test test test test test test test test junk"
EXIT_MARKETPLACE="0x0000000000000000000000000000000000000045"
BOT_WALLET="bot_wallet"

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

    if ! docker images | grep -q "bitcoin/bitcoin.*30.0"; then
        print_status "Pulling Bitcoin Core 30.0 image..."
        docker pull bitcoin/bitcoin:30.0
    fi

    docker run --rm -d --name $BITCOIN_CONTAINER \
        -p 18443:18443 -p 18444:18444 \
        -v "$BITCOIN_DATA_DIR:/bitcoin/.bitcoin" \
        bitcoin/bitcoin:30.0 \
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

setup_bdk_wallet() {
    print_status "Setting up BDK wallet..."

    # Check if core-lane-node is built
    if [ ! -f "./target/debug/core-lane-node" ]; then
        print_error "Core Lane node is not built (debug mode)"
        print_status "Building now..."
        cargo build
    fi

    # Clean up any existing wallet
    rm -rf .dev-wallets
    rm -f wallet_regtest.sqlite3

    # Create BDK wallet and capture mnemonic
    local mnemonic=$(./target/debug/core-lane-node --plain create-wallet --network regtest 2>/dev/null)

    if [ -z "$mnemonic" ]; then
        print_error "Failed to create BDK wallet"
        return 1
    fi

    # Save mnemonic to file
    mkdir -p .dev-wallets
    echo "$mnemonic" > .dev-wallets/mnemonic_regtest.txt

    print_success "BDK wallet created"
    print_status "Mnemonic saved to: .dev-wallets/mnemonic_regtest.txt"
    print_status "Mnemonic: $mnemonic"

    # Generate mining address from BDK wallet
    local mining_address=$(./target/debug/core-lane-node --plain get-address --network regtest 2>/dev/null)
    print_status "Mining address (BDK): $mining_address"

    # Mine 101 blocks to activate coinbase (maturity) - all to BDK wallet
    print_status "Mining 101 blocks to activate coinbase..."
    bitcoin_cli generatetoaddress 101 "$mining_address" >/dev/null 2>&1

    print_status "Mined 101 blocks to BDK wallet"

    # Mine 10 more blocks for good measure
    print_status "Mining 10 more blocks..."
    bitcoin_cli generatetoaddress 10 "$mining_address" >/dev/null 2>&1

    # Show block count
    local block_count=$(bitcoin_cli getblockcount)
    print_success "Total blocks: $block_count"
    print_success "BDK wallet funded with mining rewards"
}

burn_btc_to_address() {
    local address="$1"
    local amount="$2"
    local chain_id="${3:-1}"

    print_status "Burning $amount sats to $address..."

    # Check mnemonic file exists
    if [ ! -f ".dev-wallets/mnemonic_regtest.txt" ]; then
        print_error "Mnemonic not found! Setup BDK wallet first."
        return 1
    fi

    local burn_output=$(./target/debug/core-lane-node burn \
        --burn-amount $amount \
        --chain-id $chain_id \
        --eth-address $address \
        --network regtest \
        --mnemonic-file ".dev-wallets/mnemonic_regtest.txt" \
        --rpc-password $RPC_PASSWORD 2>&1)

    if echo "$burn_output" | grep -q "✅ Burn transaction broadcast successfully"; then
        local txid=$(echo "$burn_output" | grep "📍 Transaction ID:" | grep -o '[a-f0-9]\{64\}')
        print_success "Burn transaction created: $txid"
        return 0
    else
        print_error "Failed to create burn transaction: $burn_output"
        return 1
    fi
}

start_core_lane_node() {
    print_status "Starting Core Lane node..."

    if [ ! -f "target/debug/core-lane-node" ]; then
        print_error "Core Lane node is not built. Run 'cargo build' first."
        exit 1
    fi

    # Build command
    local cmd="RUST_LOG=info,debug ./target/debug/core-lane-node start \
        --start-block 0 \
        --bitcoin-rpc-read-user $RPC_USER \
        --bitcoin-rpc-read-password $RPC_PASSWORD \
        --http-host 127.0.0.1 \
        --http-port $JSON_RPC_PORT"

    # Add sequencer forwarding if configured
    if [ -n "$SEQUENCER_RPC_URL" ]; then
        cmd="$cmd --sequencer-rpc-url \"$SEQUENCER_RPC_URL\""
        print_status "Sequencer forwarding enabled: $SEQUENCER_RPC_URL"
        # When using sequencer forwarding, mnemonic is optional (core-lane won't post to Bitcoin)
        if [ -f ".dev-wallets/mnemonic_regtest.txt" ]; then
            print_warning "Mnemonic file exists but sequencer forwarding is enabled."
            print_warning "Mnemonic not needed when forwarding to sequencer (core-lane is read-only)."
        fi
    else
        # Check mnemonic file exists only if not using sequencer forwarding
        if [ ! -f ".dev-wallets/mnemonic_regtest.txt" ]; then
            print_error "Mnemonic not found! Setup BDK wallet first (or set SEQUENCER_RPC_URL for sequencer forwarding)."
            exit 1
        fi
        cmd="$cmd --mnemonic-file \".dev-wallets/mnemonic_regtest.txt\""
    fi

    cmd="$cmd > core-lane.log 2>&1 &"

    eval "$cmd"
    CORE_LANE_NODE_PID=$!

    print_status "Waiting for Core Lane node to start..."
    sleep 3

    while ! curl -s "$JSON_RPC_URL" > /dev/null 2>&1; do
        print_status "Waiting for JSON-RPC server to be ready..."
        sleep 2
    done

    print_success "Core Lane node started with PID: $CORE_LANE_NODE_PID"
    print_status "JSON-RPC available at: $JSON_RPC_URL"
    if [ -n "$SEQUENCER_RPC_URL" ]; then
        print_status "🔄 Sequencer RPC forwarding enabled: $SEQUENCER_RPC_URL"
    fi
}

start_core_lane_tail() {
    print_status "Starting Core Lane log viewer..."

    # Wait for log file to exist
    local wait_count=0
    while [ ! -f "core-lane.log" ] && [ $wait_count -lt 10 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done

    if [ ! -f "core-lane.log" ]; then
        print_warning "Core Lane log file not found, skipping log viewer"
        return 0
    fi

    # Start tailing the log with a prefix
    (
        tail -f core-lane.log 2>/dev/null | while IFS= read -r line; do
            # Strip ANSI color codes and add our own prefix
            clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
            echo -e "${GREEN}[CORE-LANE]${NC} $clean_line"
        done
    ) &

    CORE_LANE_TAIL_PID=$!
    print_success "Core Lane log viewer started (PID: $CORE_LANE_TAIL_PID)"
}

setup_filler_bot() {
    print_status "Setting up Filler Bot..."

    # Clone filler-bot if it doesn't exist
    if [ ! -d "$FILLER_BOT_DIR" ]; then
        print_status "Cloning filler-bot repository..."
        mkdir -p external
        git clone https://github.com/lanelayer/filler-bot "$FILLER_BOT_DIR"
    else
        print_status "Filler-bot repository already exists at $FILLER_BOT_DIR"
    fi

    # Clean up old wallet database for fresh start (created in project root)
    print_status "Cleaning up old bot wallet database..."
    rm -f "$BOT_WALLET-wallet.db"

    # Build filler-bot
    print_status "Building filler-bot..."
    (cd "$FILLER_BOT_DIR" && cargo build)

    if [ ! -f "$FILLER_BOT_DIR/target/debug/lanelayer-filler-bot" ]; then
        print_error "Failed to build filler-bot"
        return 1
    fi

    print_success "Filler bot setup complete"
}

start_filler_bot() {
    print_status "Starting Filler Bot..."

    if [ ! -f "$FILLER_BOT_DIR/target/debug/lanelayer-filler-bot" ]; then
        print_error "Filler bot is not built. Run setup_filler_bot first."
        return 1
    fi

    # Start the filler bot with debug logging
    RUST_LOG=debug "$FILLER_BOT_DIR/target/debug/lanelayer-filler-bot" start \
        --core-lane-url "$JSON_RPC_URL" \
        --core-lane-private-key "$FILLER_BOT_PRIVATE_KEY" \
        --bitcoin-backend "rpc" \
        --bitcoin-rpc-url "$RPC_URL" \
        --bitcoin-rpc-user "$RPC_USER" \
        --bitcoin-rpc-password "$RPC_PASSWORD" \
        --exit-marketplace "$EXIT_MARKETPLACE" \
        --bitcoin-mnemonic "$FILLER_BOT_MNEMONIC" \
        --bitcoin-wallet "$BOT_WALLET" \
        > external/filler-bot.log 2>&1 &

    FILLER_BOT_PID=$!

    print_status "Waiting for Filler Bot to start..."
    sleep 5

    print_success "Filler Bot started with PID: $FILLER_BOT_PID"
    print_status "Logs available at: external/filler-bot.log"

    # Get the first receive address from the bot logs if file exists
    if [ -f "external/filler-bot.log" ]; then
        print_status "Checking bot's Bitcoin receive address from logs..."
        local bot_address=$(grep -i "address\|receive" external/filler-bot.log 2>/dev/null | head -1 || echo "")
        if [ -n "$bot_address" ]; then
            print_status "Bot address info: $bot_address"
        fi
    fi
}

start_filler_bot_tail() {
    print_status "Starting Filler Bot log viewer..."

    # Wait for log file to exist
    local wait_count=0
    while [ ! -f "external/filler-bot.log" ] && [ $wait_count -lt 10 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done

    if [ ! -f "external/filler-bot.log" ]; then
        print_warning "Filler bot log file not found, skipping log viewer"
        return 0
    fi

    # Start tailing the log with a prefix
    (
        tail -f external/filler-bot.log 2>/dev/null | while IFS= read -r line; do
            # Strip ANSI color codes and add our own prefix
            clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
            echo -e "${BLUE}[FILLER-BOT]${NC} $clean_line"
        done
    ) &

    FILLER_BOT_TAIL_PID=$!
    print_success "Filler Bot log viewer started (PID: $FILLER_BOT_TAIL_PID)"
}

fund_filler_bot_wallet() {
    print_status "Funding Filler Bot wallet..."

    # Wait a bit more for the bot to initialize and log its address
    sleep 3

    # Try to extract the actual Bitcoin receive address from the filler bot logs
    local bot_btc_address=""

    if [ -f "external/filler-bot.log" ]; then
        # Look for Bitcoin address patterns in the logs
        # Try to find bech32 regtest addresses (bcrt1...)
        bot_btc_address=$(grep -o "bcrt1[a-z0-9]\{39,\}" external/filler-bot.log 2>/dev/null | head -1 || echo "")

        if [ -z "$bot_btc_address" ]; then
            # Try to find any address-like pattern
            bot_btc_address=$(grep -i "address.*bcrt1\|receive.*bcrt1" external/filler-bot.log 2>/dev/null | grep -o "bcrt1[a-z0-9]\{39,\}" | head -1 || echo "")
        fi
    fi

    if [ -z "$bot_btc_address" ]; then
        print_warning "Could not find bot's Bitcoin address in logs"
        print_status "Checking external/filler-bot.log for address information..."
        if [ -f "external/filler-bot.log" ]; then
            grep -i "address\|wallet\|receive" external/filler-bot.log | head -5 || true
        fi
        print_warning "Skipping automatic funding - please fund the bot manually once you identify its address"
        return 0
    fi

    print_success "Found bot's Bitcoin address: $bot_btc_address"
    print_status "Mining 100 blocks to bot wallet..."

    # Temporarily disable exit on error to handle failure gracefully
    set +e

    # Mine blocks directly to the bot's address
    local mine_result
    mine_result=$(bitcoin_cli generatetoaddress 100 "$bot_btc_address" 2>&1)
    local mine_exit_code=$?

    # Re-enable exit on error
    set -e

    if [ $mine_exit_code -eq 0 ]; then
        print_success "Successfully mined 100 blocks to filler bot wallet"
        local block_count=$(bitcoin_cli getblockcount)
        print_status "Current block height: $block_count"
    else
        print_error "Failed to mine blocks to bot address"
        print_error "Error: $mine_result"
        print_warning "The bot will need manual funding later"
        print_status "You can fund it manually with: docker exec bitcoin-regtest bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin123 generatetoaddress 100 $bot_btc_address"
    fi
}

start_mining_loop() {
    print_status "Starting continuous mining loop (every 10 seconds)..."

    (
        while true; do
            sleep 10
            if is_bitcoin_running; then
                # Get new address from BDK wallet for mining rewards
                local address=$(./target/debug/core-lane-node --plain get-address --network regtest 2>/dev/null)
                if [ -n "$address" ]; then
                    bitcoin_cli generatetoaddress 1 "$address" >/dev/null 2>&1
                    local block_count=$(bitcoin_cli getblockcount)
                    print_status "Mined block $block_count (reward to BDK wallet)"

                    # Occasionally trigger a hazardous 5-block reorg (only after block 130, if REORG=1)
                    if [ "${REORG:-0}" = "1" ] && [ "$block_count" -gt 130 ] && [ $((block_count % 7)) -eq 0 ]; then
                        print_warning "⚠️  HAZARDOUS ENVIRONMENT: Triggering 5-block reorg at height $block_count..."
                        trigger_reorg 5
                    fi
                else
                    print_warning "Failed to get BDK address, skipping block"
                fi
            else
                print_warning "Bitcoin not running, stopping mining loop"
                break
            fi
        done
    ) &

    MINING_PID=$!
    # Write PID to file for reliable cleanup from other shell sessions
    echo $MINING_PID > .dev-mining-loop.pid 2>/dev/null || true
    print_success "Mining loop started with PID: $MINING_PID"
}

# Hazardous environment: trigger a reorg of N blocks
trigger_reorg() {
    local reorg_depth="$1"

    print_warning "🔥 HAZARDOUS: Starting $reorg_depth-block reorg..."

    # Get current chain info
    local current_height=$(bitcoin_cli getblockcount)
    local current_tip=$(bitcoin_cli getbestblockhash)

    if [ $current_height -lt $((reorg_depth + 10)) ]; then
        print_warning "Chain too short for $reorg_depth-block reorg, need at least $((reorg_depth + 10)) blocks"
        return 1
    fi

    # Choose fork point (reorg_depth blocks back from current tip)
    local fork_height=$((current_height - reorg_depth))
    local old_hash=$(bitcoin_cli getblockhash $fork_height)

    print_status "Invalidating block at height $fork_height (hash: ${old_hash:0:8}...)"
    bitcoin_cli invalidateblock "$old_hash"

    # Wait for rewind to complete
    while [ "$(bitcoin_cli getblockcount)" -ne $((fork_height - 1)) ]; do
        sleep 0.1
    done

    print_status "Chain rewound to height $((fork_height - 1))"

    # Mine a replacement branch that's longer than the original
    local mining_address=$(./target/debug/core-lane-node --plain get-address --network regtest 2>/dev/null)
    local blocks_to_mine=$((current_height + 1 - (fork_height - 1)))

    print_status "Mining $blocks_to_mine blocks to create longer replacement branch..."
    bitcoin_cli generatetoaddress "$blocks_to_mine" "$mining_address" >/dev/null 2>&1

    local new_height=$(bitcoin_cli getblockcount)
    local new_tip=$(bitcoin_cli getbestblockhash)

    print_warning "✅ HAZARDOUS: $reorg_depth-block reorg complete!"
    print_status "New chain tip: ${new_tip:0:8}... at height $new_height"

    # Show chain tips to verify reorg
    local tips=$(bitcoin_cli getchaintips 2>/dev/null | jq -r '.[] | select(.status == "valid-fork") | .height' 2>/dev/null || echo "none")
    if [ "$tips" != "none" ]; then
        print_warning "Side chains detected at heights: $tips"
    fi

    return 0
}

check_balances() {
    print_status "Checking Core Lane balances..."

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

    # Stop Filler Bot log viewer - try PID first, then find by pattern
    if [ $FILLER_BOT_TAIL_PID -ne 0 ] && kill -0 $FILLER_BOT_TAIL_PID 2>/dev/null; then
        print_status "Stopping Filler Bot log viewer (PID: $FILLER_BOT_TAIL_PID)..."
        kill $FILLER_BOT_TAIL_PID 2>/dev/null || true
    else
        local filler_tail_pids=$(pgrep -f "tail -f external/filler-bot.log" 2>/dev/null || true)
        if [ -n "$filler_tail_pids" ]; then
            print_status "Stopping Filler Bot log viewer (found by pattern)..."
            echo "$filler_tail_pids" | xargs kill 2>/dev/null || true
        fi
    fi

    # Stop Filler Bot - try PID first, then find by pattern
    if [ $FILLER_BOT_PID -ne 0 ] && kill -0 $FILLER_BOT_PID 2>/dev/null; then
        print_status "Stopping Filler Bot (PID: $FILLER_BOT_PID)..."
        kill $FILLER_BOT_PID 2>/dev/null || true
    else
        local filler_bot_pids=$(pgrep -f "lanelayer-filler-bot.*start" 2>/dev/null || true)
        if [ -n "$filler_bot_pids" ]; then
            print_status "Stopping Filler Bot (found by pattern)..."
            echo "$filler_bot_pids" | xargs kill 2>/dev/null || true
        fi
    fi

    # Stop Core Lane log viewer - try PID first, then find by pattern
    if [ $CORE_LANE_TAIL_PID -ne 0 ] && kill -0 $CORE_LANE_TAIL_PID 2>/dev/null; then
        print_status "Stopping Core Lane log viewer (PID: $CORE_LANE_TAIL_PID)..."
        kill $CORE_LANE_TAIL_PID 2>/dev/null || true
    else
        local core_tail_pids=$(pgrep -f "tail -f core-lane.log" 2>/dev/null || true)
        if [ -n "$core_tail_pids" ]; then
            print_status "Stopping Core Lane log viewer (found by pattern)..."
            echo "$core_tail_pids" | xargs kill 2>/dev/null || true
        fi
    fi

    # Stop mining loop - try PID first, then read from PID file, then find by pattern
    if [ $MINING_PID -ne 0 ] && kill -0 $MINING_PID 2>/dev/null; then
        print_status "Stopping mining loop (PID: $MINING_PID)..."
        kill $MINING_PID 2>/dev/null || true
        rm -f .dev-mining-loop.pid 2>/dev/null || true
    elif [ -f ".dev-mining-loop.pid" ]; then
        local mining_loop_pid=$(cat .dev-mining-loop.pid 2>/dev/null | head -1 || true)
        if [ -n "$mining_loop_pid" ] && kill -0 $mining_loop_pid 2>/dev/null; then
            print_status "Stopping mining loop (PID from file: $mining_loop_pid)..."
            kill $mining_loop_pid 2>/dev/null || true
        fi
        rm -f .dev-mining-loop.pid 2>/dev/null || true
    else
        local mining_pids=$(pgrep -f "bitcoin_cli.*generatetoaddress.*1" 2>/dev/null | head -1 || true)
        if [ -n "$mining_pids" ]; then
            print_status "Stopping mining loop (found by pattern, PID: $mining_pids)..."
            kill $mining_pids 2>/dev/null || true
        fi
    fi

    if [ $CORE_LANE_NODE_PID -ne 0 ] && kill -0 $CORE_LANE_NODE_PID 2>/dev/null; then
        print_status "Stopping Core Lane node (PID: $CORE_LANE_NODE_PID)..."
        kill $CORE_LANE_NODE_PID 2>/dev/null || true
    else
        local core_lane_pids=$(pgrep -f "core-lane-node.*start" 2>/dev/null || true)
        if [ -n "$core_lane_pids" ]; then
            print_status "Stopping Core Lane node (found by pattern)..."
            echo "$core_lane_pids" | xargs kill 2>/dev/null || true
        fi
    fi

    sleep 1

    local remaining_filler=$(pgrep -f "lanelayer-filler-bot" 2>/dev/null || true)
    if [ -n "$remaining_filler" ]; then
        print_status "Force killing remaining Filler Bot processes..."
        echo "$remaining_filler" | xargs kill -9 2>/dev/null || true
    fi

    local remaining_core_lane=$(pgrep -f "core-lane-node.*start" 2>/dev/null || true)
    if [ -n "$remaining_core_lane" ]; then
        print_status "Force killing remaining Core Lane node processes..."
        echo "$remaining_core_lane" | xargs kill -9 2>/dev/null || true
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
    echo "Environment Variables:"
    echo "  SEQUENCER_RPC_URL    Set to enable sequencer forwarding (e.g., http://127.0.0.1:8545)"
    echo "                       When set, core-lane forwards eth_sendRawTransaction to the sequencer"
    echo ""
    echo ""
    echo "Commands:"
    echo "  start     Start the complete development environment (HAZARDOUS MODE)"
    echo "  stop      Stop the development environment"
    echo "  status    Show status of running services"
    echo "  balances  Check Core Lane balances for test addresses"
    echo "  help      Show this help message"
    echo ""
    echo "⚠️  HAZARDOUS ENVIRONMENT: This development setup can trigger"
    echo "   5-block reorganizations every 7 blocks (starting after block 130)"
    echo "   when REORG=1 environment variable is set."
    echo ""
    echo "Examples:"
    echo "  $0 start                                    # Start everything"
    echo "  REORG=1 $0 start                          # Start with hazardous reorgs enabled"
    echo "  SEQUENCER_RPC_URL=http://127.0.0.1:8545 $0 start  # Start with sequencer forwarding"
    echo "  $0 stop                                     # Stop everything"
    echo "  $0 balances                                # Check balances"
}

show_status() {
    echo "=== Core Lane Development Environment Status ==="

    if is_bitcoin_running; then
        echo "✅ Bitcoin: Running"
        local block_count=$(bitcoin_cli getblockcount 2>/dev/null || echo "unknown")
        echo "   Block height: $block_count"
    else
        echo "❌ Bitcoin: Not running"
    fi

    # Check Core Lane Node by checking if port is listening or process exists
    local core_lane_pid=$(pgrep -f "core-lane-node.*start" | head -1)
    if [ -n "$core_lane_pid" ] || (curl -s "$JSON_RPC_URL" > /dev/null 2>&1); then
        if [ -n "$core_lane_pid" ]; then
            echo "✅ Core Lane Node: Running (PID: $core_lane_pid)"
        else
            echo "✅ Core Lane Node: Running (detected via JSON-RPC)"
        fi
        echo "   JSON-RPC: $JSON_RPC_URL"
        echo "   Logs: core-lane.log"
    else
        echo "❌ Core Lane Node: Not running"
    fi

    local mining_pid=""
    if [ -f ".dev-mining-loop.pid" ]; then
        local pid_from_file=$(cat .dev-mining-loop.pid 2>/dev/null | head -1 || true)
        if [ -n "$pid_from_file" ] && kill -0 $pid_from_file 2>/dev/null; then
            mining_pid=$pid_from_file
        fi
    fi

    if is_bitcoin_running; then
        local mining_active=false
        local block1=$(bitcoin_cli getblockcount 2>/dev/null)
        sleep 2
        local block2=$(bitcoin_cli getblockcount 2>/dev/null)

        if [ -n "$block1" ] && [ -n "$block2" ] && [ "$block2" -le "$block1" ] 2>/dev/null; then
            block1=$block2
            sleep 2
            block2=$(bitcoin_cli getblockcount 2>/dev/null)
        fi

        if [ -n "$block1" ] && [ -n "$block2" ] && [ "$block2" -gt "$block1" ] 2>/dev/null; then
            mining_active=true
        else
            local secondary_check=false

            local mining_process=$(pgrep -f "bitcoin_cli.*generatetoaddress.*1" 2>/dev/null | head -1 || true)
            if [ -n "$mining_process" ]; then
                secondary_check=true
            fi

            if [ -f ".dev-mining-loop.pid" ]; then
                local pid_file_mtime=$(stat -c %Y ".dev-mining-loop.pid" 2>/dev/null || echo "0")
                local current_time=$(date +%s)
                local age=$((current_time - pid_file_mtime))
                if [ "$age" -lt 40 ] && [ -n "$mining_pid" ]; then
                    secondary_check=true
                fi
            fi

            if [ "$secondary_check" = true ]; then
                mining_active=true
            fi
        fi

        if [ "$mining_active" = true ]; then
            if [ -n "$mining_pid" ]; then
                echo "✅ Mining Loop: Running (PID: $mining_pid)"
            else
                echo "✅ Mining Loop: Running (detected via active mining)"
            fi
        elif [ -n "$mining_pid" ]; then
            echo "✅ Mining Loop: Running (PID: $mining_pid)"
        else
            echo "❌ Mining Loop: Not running"
        fi
    else
        echo "❌ Mining Loop: Not running"
    fi

    # Check Filler Bot by looking for the process
    local filler_bot_pid=$(pgrep -f "lanelayer-filler-bot.*start" | head -1)
    if [ -n "$filler_bot_pid" ]; then
        echo "✅ Filler Bot: Running (PID: $filler_bot_pid)"
        echo "   Logs: external/filler-bot.log"
    else
        echo "❌ Filler Bot: Not running"
    fi

    echo ""
    echo "Test addresses:"
    for i in "${!ANVIL_ADDRESSES[@]}"; do
        echo "  ($i) ${ANVIL_ADDRESSES[$i]}"
    done
}

start_dev_environment() {
    print_status "Starting Core Lane Development Environment..."

    # Set trap for cleanup on exit (only when starting)
    trap cleanup EXIT

    check_docker

    if ! is_bitcoin_running; then
        start_bitcoin
    else
        print_warning "Bitcoin is already running"
    fi

    # Setup BDK wallet (used for mining and Core Lane operations)
    setup_bdk_wallet

    start_core_lane_node

    # Start tailing core lane logs
    start_core_lane_tail

    # Setup and start filler bot
    setup_filler_bot
    start_filler_bot

    # Fund the filler bot's Bitcoin wallet
    fund_filler_bot_wallet

    # Start tailing filler bot logs
    start_filler_bot_tail

    start_mining_loop
    print_status "Burning BTC to test addresses..."
    for address in "${ANVIL_ADDRESSES[@]}"; do
        burn_btc_to_address "$address" 1000000 1281453634
    done
    sleep 5
    check_balances

    print_success "Development environment started successfully!"
    echo ""
    echo "🌐 JSON-RPC Endpoint: $JSON_RPC_URL"
    echo "🔗 Connect with MetaMask, Cast, or other wallets using:"
    echo "   Network Name: Core Lane Dev"
    echo "   RPC URL: $JSON_RPC_URL"
    echo "   Chain ID: 1281453634"
    echo "   Currency Symbol: laneBTC"
    echo ""
    echo "📱 Test addresses with balances:"
    for i in "${!ANVIL_ADDRESSES[@]}"; do
        echo "  ($i) ${ANVIL_ADDRESSES[$i]}"
    done
    echo ""
    echo "💰 BDK Wallet mnemonic: .dev-wallets/mnemonic_regtest.txt"
    echo "📝 Core Lane: Logs shown with [CORE-LANE] prefix (also in core-lane.log)"
    echo "🤖 Filler Bot: Logs shown with [FILLER-BOT] prefix (also in external/filler-bot.log)"
    echo "⛏️  Mining blocks every 10 seconds..."
    if [ "${REORG:-0}" = "1" ]; then
        echo "⚠️  HAZARDOUS MODE: 5-block reorganizations every 7 blocks (starting after block 130)"
    fi
    echo ""
    echo "🛑 Use '$0 stop' or press Ctrl+C to stop the environment"
    echo ""
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
        exit 0
        ;;
    balances)
        check_balances
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
