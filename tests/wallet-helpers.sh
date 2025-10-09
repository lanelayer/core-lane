#!/bin/bash

# BDK Wallet Helper Functions for Core Lane Tests
# This script provides functions to manage BDK wallets in tests

WALLET_DIR="./test-wallets"
CORE_LANE_NODE="./target/release/core-lane-node"

# Function to ensure wallet directory exists
ensure_wallet_dir() {
    mkdir -p "$WALLET_DIR"
}

# Function to create a new BDK wallet
# Usage: create_bdk_wallet <network>
# Returns: mnemonic phrase
create_bdk_wallet() {
    local network="${1:-regtest}"
    
    ensure_wallet_dir
    
    # Remove existing wallet file for clean start
    rm -f "${WALLET_DIR}/wallet_${network}.sqlite3"
    rm -f "wallet_${network}.sqlite3"
    
    # Create new wallet and capture mnemonic
    local mnemonic=$(${CORE_LANE_NODE} --plain create-wallet --network "$network" 2>/dev/null)
    
    # Move wallet file to test directory
    if [ -f "wallet_${network}.sqlite3" ]; then
        mv "wallet_${network}.sqlite3" "${WALLET_DIR}/"
    fi
    
    echo "$mnemonic"
}

# Function to restore a BDK wallet from mnemonic
# Usage: restore_bdk_wallet <network> <mnemonic>
restore_bdk_wallet() {
    local network="$1"
    local mnemonic="$2"
    
    ensure_wallet_dir
    
    # Remove existing wallet file
    rm -f "${WALLET_DIR}/wallet_${network}.sqlite3"
    rm -f "wallet_${network}.sqlite3"
    
    # Restore wallet
    ${CORE_LANE_NODE} --plain create-wallet --network "$network" --mnemonic "$mnemonic" 2>/dev/null
    
    # Move wallet file to test directory
    if [ -f "wallet_${network}.sqlite3" ]; then
        mv "wallet_${network}.sqlite3" "${WALLET_DIR}/"
    fi
}

# Function to get a new receive address from the wallet
# Usage: get_bdk_address <network>
# Returns: Bitcoin address
get_bdk_address() {
    local network="${1:-regtest}"
    
    # Temporarily move wallet file to current directory for the command
    if [ -f "${WALLET_DIR}/wallet_${network}.sqlite3" ]; then
        cp "${WALLET_DIR}/wallet_${network}.sqlite3" "wallet_${network}.sqlite3"
    fi
    
    # Get new address
    local address=$(${CORE_LANE_NODE} --plain get-address --network "$network" 2>/dev/null)
    
    # Move updated wallet file back
    if [ -f "wallet_${network}.sqlite3" ]; then
        mv "wallet_${network}.sqlite3" "${WALLET_DIR}/"
    fi
    
    echo "$address"
}

# Function to get multiple addresses
# Usage: get_bdk_addresses <network> <count>
# Returns: Space-separated list of addresses
get_bdk_addresses() {
    local network="${1:-regtest}"
    local count="${2:-1}"
    local addresses=()
    
    for ((i=0; i<count; i++)); do
        local addr=$(get_bdk_address "$network")
        addresses+=("$addr")
    done
    
    echo "${addresses[@]}"
}

# Function to cleanup test wallets
cleanup_test_wallets() {
    rm -rf "$WALLET_DIR"
    rm -f wallet_*.sqlite3
}

# Function to save mnemonic to file
# Usage: save_mnemonic <network> <mnemonic>
save_mnemonic() {
    local network="$1"
    local mnemonic="$2"
    
    ensure_wallet_dir
    echo "$mnemonic" > "${WALLET_DIR}/mnemonic_${network}.txt"
}

# Function to load mnemonic from file
# Usage: load_mnemonic <network>
# Returns: mnemonic phrase
load_mnemonic() {
    local network="$1"
    
    if [ -f "${WALLET_DIR}/mnemonic_${network}.txt" ]; then
        cat "${WALLET_DIR}/mnemonic_${network}.txt"
    fi
}

