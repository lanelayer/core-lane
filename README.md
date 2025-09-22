# Core Lane Node

A Bitcoin-anchored execution environment (L1.5) that provides Ethereum-style transactions anchored to Bitcoin blocks.

## Overview

Core Lane (Minimal Execution Lane) is a Bitcoin-anchored execution environment that provides the absolute minimum set of transaction types for building higher-level applications. It looks and feels like Ethereum JSON-RPC + EIP-155 transactions, but every block is anchored in Bitcoin (forced inclusion).

## Current Implementation Status

### Phase 1.1: Core Infrastructure Setup ✅ COMPLETED

- **Bitcoin RPC Integration**: Connected to Bitcoin Core via RPC
- **Block Scanning**: Continuous Bitcoin block monitoring
- **DA Extraction**: Core Lane transaction detection from Bitcoin DA envelopes
- **State Management**: Basic in-memory state for Core Lane accounts and transactions

### Phase 1.2: EIP-1559 Transaction Support ✅ COMPLETED

- **Alloy Primitives Integration**: Using alloy-primitives for Ethereum-compatible types
- **EIP-1559 Transaction Format**: Support for modern Ethereum transaction types
- **Account Model**: Ethereum-style account management with balances and nonces
- **Transaction Validation**: Basic transaction validation and gas calculation
- **Modular Architecture**: Separate modules for transaction and account management

### Phase 2.1: Transaction Processing Engine ✅ COMPLETED

- **Bitcoin Burn Detection**: Automatic detection of Bitcoin OP_RETURN burns with BRN1 format
- **Hybrid P2WSH + OP_RETURN Burn Method**: Reliable burn transactions with clear value separation
- **Automatic Minting**: Core Lane tokens minted 1:1 for Bitcoin burns (chain ID 1)
- **Transaction Execution**: Full execution engine for Burn (transfer to unspendable), Transfer, and Exit
- **State Transitions**: Proper balance updates, nonce increments, and account management
- **Gas System**: Gas metering and fee charging for transaction processing
- **Signature Framework**: Infrastructure for signature verification (currently placeholder)
- **Two-Phase Block Processing**: Process all burns before DA transactions for proper token availability

## Features

### Core Lane Transaction Detection
- Scans Bitcoin blocks for Core Lane transactions embedded in DA envelopes
- Recognizes transactions with `CORE_LANE` prefix in Bitcoin script data
- Processes EIP-1559 transaction format using alloy primitives
- Supports transaction validation and gas calculation

### Bitcoin Burn to Core Lane Bridge
- Detects Bitcoin OP_RETURN transactions with BRN1 format
- **Hybrid P2WSH + OP_RETURN burn method**: P2WSH output carries burn value, 0-value OP_RETURN carries BRN1 data
- Automatically mints Core Lane tokens when Bitcoin is burned (1:1 ratio)
- Supports chain ID filtering (Core Lane uses chain ID 1)
- Extracts Ethereum addresses from burn transactions for token distribution
- No manual mint transactions needed - fully automated via Bitcoin scanning
- **Two-phase block processing**: Ensures all burns are processed before DA transactions

### State Management
- Ethereum-style account management with U256 balances
- Transaction nonce tracking and validation
- Contract storage support
- Transaction history storage
- Block processing state tracking

### Bitcoin Integration
- Direct Bitcoin Core RPC connection
- Real-time block scanning
- DA envelope extraction and parsing
- Support for Bitcoin testnet/signet/regtest

## Usage

### Prerequisites
- Bitcoin Core node running with RPC enabled
- Rust toolchain (1.70+)

### Quick Start with Test Environment

For development and testing, use the provided test environment:

```bash
# Setup and start Bitcoin regtest network
./test-environment.sh start setup-wallet build test

# Check status
./test-environment.sh status

# See TESTING.md for detailed testing guide
```

### Building
```bash
cargo build
```

### Running

#### Start the Core Lane node (continuous block scanning)
```bash
# Start from recent blocks (default)
./target/debug/core-lane-node start --rpc-user bitcoin --rpc-password bitcoin123

# Start from a specific block
./target/debug/core-lane-node start --start-block 200 --rpc-user bitcoin --rpc-password bitcoin123
```

#### Scan recent blocks for Core Lane transactions
```bash
# Scan last 10 blocks (default)
./target/debug/core-lane-node scan-blocks --blocks 10 --rpc-user bitcoin --rpc-password bitcoin123

# Scan 5 blocks starting from block 200
./target/debug/core-lane-node scan-blocks --blocks 5 --start-block 200 --rpc-user bitcoin --rpc-password bitcoin123
```

#### Create Bitcoin burn transaction (for testing)
```bash
# Burn Bitcoin to mint Core Lane tokens (uses your Bitcoin wallet)
./target/debug/core-lane-node burn \
  --burn-amount 500000 \
  --chain-id 1 \
  --eth-address "0x1234567890123456789012345678901234567890" \
  --rpc-password bitcoin123

# Optional parameters:
# --wallet "wallet_name"    (default: "mine")
# --network "regtest"       (default: "regtest")

# The burn creates a hybrid transaction:
# - P2WSH output: Carries the burn value (e.g., 500,000 sats)
# - 0-value OP_RETURN output: Carries BRN1 data for Core Lane detection
```

### Configuration Options

- `--rpc-url`: Bitcoin Core RPC URL (default: http://127.0.0.1:18443)
- `--rpc-user`: Bitcoin Core RPC username (default: user)
- `--rpc-password`: Bitcoin Core RPC password (required)
- `--blocks`: Number of blocks to scan (for scan-blocks command, default: 10)
- `--start-block`: Starting block number for scanning (optional, defaults to recent blocks)

## Architecture

### Core Components

1. **CoreLaneNode**: Main node implementation
   - Bitcoin RPC client integration
   - Block scanner and processor
   - State management
   - Transaction processing

2. **CoreLaneState**: In-memory state storage
   - Account manager integration
   - Transaction history
   - Block processing state

3. **Transaction Module**: EIP-1559 transaction handling
   - TxEnvelope for transaction encoding/decoding
   - Transaction validation and gas calculation
   - Core Lane transaction type detection

4. **Account Module**: Ethereum-style account management
   - U256 balance handling
   - Nonce tracking and validation
   - Contract storage support

### Bitcoin DA Integration

Core Lane transactions are embedded in Bitcoin blocks using Taproot envelopes:

```
OP_FALSE OP_IF <data> OP_ENDIF OP_TRUE
```

Where `<data>` contains Core Lane transaction data prefixed with `CORE_LANE`.

## Development Status

### Completed (Phase 1.1 & 1.2)
- ✅ Basic Bitcoin RPC integration
- ✅ Block scanning infrastructure
- ✅ DA envelope detection and extraction
- ✅ Core Lane transaction parsing
- ✅ In-memory state management
- ✅ CLI interface
- ✅ EIP-1559 transaction support with alloy primitives
- ✅ Account management with balances and nonces

### Completed (Phase 2.1)
- ✅ **Bitcoin burn detection and automatic Core Lane token minting**
- ✅ **Hybrid P2WSH + OP_RETURN burn method**
- ✅ **Two-phase block processing (burns before DA transactions)**
- ✅ **Full transaction execution engine**
- ✅ **State transitions with balance updates and nonce management**
- ✅ **Gas metering and fee charging system**

### Next Steps (Phase 2.2)
- [ ] Advanced transfer operations with comprehensive validation
- [ ] Exit marketplace functionality for Bitcoin withdrawals
- [ ] Proper signature verification with ECDSA recovery
- [ ] Investigate and fix minting balance issues

### Future Phases
- Phase 3: JSON-RPC Interface
- Phase 4: Advanced Features (Bundles, Flash Loans)
- Phase 5: Developer Tools & Testing
- Phase 6: Production Readiness

## Contributing

This is an early implementation. The architecture and APIs may change significantly as development progresses.

## License

[Add your license here]
