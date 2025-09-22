# Core Lane Implementation Plan

## Overview
Core Lane is a Bitcoin-anchored execution environment that processes Ethereum-style (EIP-1559) transactions with forced inclusion in Bitcoin Data Availability (DA). This document outlines the phased implementation approach.

## Architecture Goals
- **Bitcoin Anchoring**: Every Core Lane block's commitments are embedded in Bitcoin transactions
- **Data Availability**: Core Lane transaction calldata is stored in Bitcoin using Taproot envelopes
- **EIP-1559 Compatibility**: Support for Ethereum-style transactions with proper gas pricing
- **Account Model**: Ethereum-compatible accounts with balances, nonces, and contract storage
- **Special Operations**: Mint, Burn, Transfer, Exit, and Contract Creation primitives

## Implementation Phases

### Phase 1: Core Infrastructure ✅ COMPLETED

#### Phase 1.1: Foundation Setup ✅ COMPLETED
- [x] Bitcoin RPC integration using `bitcoincore-rpc` crate
- [x] Block scanning functionality for detecting DA envelopes
- [x] Taproot envelope detection (`OP_FALSE OP_IF <data> OP_ENDIF OP_TRUE` pattern)
- [x] Basic Core Lane state management (in-memory)
- [x] CLI interface with `clap` for node control
- [x] Configurable starting block for scanning
- [x] Background block scanning with continuous monitoring

#### Phase 1.2: Transaction Processing ✅ COMPLETED
- [x] Integration with `alloy-primitives` for Ethereum-compatible types
- [x] `TxEnvelope` support for EIP-1559 transactions
- [x] Modular architecture with `transaction.rs` and `account.rs` modules
- [x] Ethereum-style account management with `AccountManager`
- [x] Transaction parsing, validation, and gas calculation
- [x] Special address definitions (Mint, Burn, Exit Marketplace)

#### Phase 1.3: Bitcoin Bridge ✅ COMPLETED
- [x] **Bitcoin Burn Detection**: Detect Bitcoin OP_RETURN burns with BRN1 format
- [x] **Hybrid P2WSH + OP_RETURN Burn Method**: Reliable burn transactions with clear value separation
- [x] **Automatic Minting**: Mint Core Lane tokens 1:1 for Bitcoin burns (chain ID 1)
- [x] **Two-Phase Block Processing**: Process all burns before DA transactions for proper token availability
- [x] **Full Transaction Execution**: Process Burn, Transfer, Exit, and Contract Creation types
- [x] **State Transitions**: Update account balances, nonces, and storage
- [x] **Gas Metering**: Implement gas consumption tracking and fee charging
- [x] **Signature Verification**: Full ECDSA signature validation and transaction execution

### Phase 2: Production Readiness (CURRENT)

#### Phase 2.1: Persistence & RPC (NEXT)
- [ ] **Database Integration**: Replace in-memory state with persistent storage
- [x] **JSON-RPC Interface**: Implement full Ethereum-compatible RPC methods
  - `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`
  - `eth_gasPrice`, `eth_estimateGas`, `eth_maxPriorityFeePerGas`, `eth_feeHistory`
  - `eth_blockNumber`, `eth_getBlockByNumber`, `eth_getBlockByHash`
  - `eth_getStorageAt`, `net_version`, `net_listening`, `net_peerCount`
  - `eth_chainId` and proper error handling for unimplemented methods
- [ ] **Error Handling**: Comprehensive error recovery mechanisms
- [ ] **Logging**: Structured logging for production debugging

#### Phase 2.2: Advanced Features
- [ ] **Exit Marketplace**: Complete Bitcoin withdrawal functionality
- [ ] **Advanced Transfer Operations**: Comprehensive transfer validation and edge cases
- [ ] **Contract Storage**: Advanced contract features and storage management
- [ ] **Performance Optimization**: Multi-threaded transaction execution and caching

### Phase 3: Network & Ecosystem (FUTURE)

#### Phase 3.1: P2P Networking
- [ ] **Transaction Pool**: Mempool for pending transactions
- [ ] **Peer Discovery**: Find and connect to other Core Lane nodes
- [ ] **Block Propagation**: Distribute new blocks across the network
- [ ] **Sync Protocol**: Initial sync and staying up-to-date

#### Phase 3.2: Developer Experience
- [ ] **SDK Development**: Developer tools and examples
- [ ] **Documentation**: Comprehensive API documentation
- [ ] **Testing**: More comprehensive test coverage
- [ ] **Monitoring**: Metrics, observability, and alerting

## Current Status

### ✅ Completed Features
- Bitcoin RPC integration with configurable credentials
- Block scanning from specified starting heights
- Taproot envelope detection and data extraction
- EIP-1559 transaction structure support with alloy primitives
- Modular codebase with transaction and account modules
- CLI interface for node operation and block scanning
- **Bitcoin burn detection and automatic Core Lane token minting**
- **Full transaction execution engine for all Core Lane transaction types**
- **State transitions with balance updates and nonce management**
- **Gas metering and fee charging system**
- **Complete signature verification with ECDSA validation**
- **Two-phase block processing (burns before DA transactions)**

### 🔧 Current Implementation Notes
- **Hybrid P2WSH + OP_RETURN burn method**: P2WSH output carries burn value, 0-value OP_RETURN carries BRN1 data
- **Automatic minting**: Creates Core Lane tokens 1:1 for Bitcoin burns to chain ID 1
- **Transaction execution**: Fully integrated with account management and signature validation
- **Gas fees**: Properly calculated and charged to transaction senders
- **All core Lane transaction types**: Burn, Transfer, Exit, Contract Creation implemented
- **Integration testing**: Full end-to-end workflow verified (all 10 tests passing)

### 🎯 Immediate Next Steps (Phase 2.1)
1. **Database Integration**: Replace in-memory state with persistent storage
2. **JSON-RPC Expansion**: Implement full Ethereum-compatible RPC methods
3. **Error Handling**: Comprehensive error recovery mechanisms
4. **Logging**: Structured logging for production debugging

## Test Environment ✅ COMPLETED

### Bitcoin Regtest Network
- **Docker-based setup**: Bitcoin Core 29.0 in regtest mode
- **Automated testing**: `test-environment.sh` script for easy setup and testing
- **Integration testing**: Full workflow from Bitcoin burns to Core Lane minting
- **Development tools**: Comprehensive testing documentation in `TESTING.md`

### Test Environment Features
- **One-command setup**: `./test-environment.sh start setup-wallet build test`
- **Bitcoin mining**: Automatic 101 block mining for coinbase activation
- **Core Lane integration**: Direct testing of burn detection and transaction processing
- **State verification**: Account balance and transaction state checking
- **Clean reset**: Easy environment reset for fresh testing

## Technical Dependencies

### Core Libraries
- `alloy-primitives`: Ethereum-compatible types (Address, U256, Bytes, B256)
- `alloy-consensus`: Transaction envelopes and EIP standards
- `alloy-rlp`: RLP encoding/decoding for transaction serialization
- `bitcoincore-rpc`: Bitcoin Core RPC client integration
- `tokio`: Async runtime for non-blocking operations
- `clap`: Command-line interface framework

### Bitcoin Integration
- Bitcoin Core node with RPC enabled (`-rpcuser=bitcoin -rpcpassword=bitcoin123`)
- Taproot-compatible Bitcoin network (regtest/testnet/mainnet)
- Block scanning from configurable starting heights

## Configuration

### Bitcoin RPC Settings
```bash
# Required Bitcoin Core RPC configuration
--rpc-user bitcoin
--rpc-password bitcoin123
--rpc-url http://localhost:8332  # default
```

### Core Lane Node Usage
```bash
# Start the node with continuous block scanning
./target/debug/core-lane-node start --rpc-user bitcoin --rpc-password bitcoin123

# Scan specific number of blocks from a starting point
./target/debug/core-lane-node scan-blocks --blocks 10 --start-block 800000 --rpc-user bitcoin --rpc-password bitcoin123
```

## Success Criteria

### Phase 1 Success Metrics ✅ ACHIEVED
- [x] Successfully connect to Bitcoin Core via RPC
- [x] Detect and parse Taproot envelopes containing Core Lane data
- [x] Parse EIP-1559 transaction structures using alloy libraries
- [x] Maintain in-memory state with account management
- [x] Provide CLI interface for node operation
- [x] **Detect Bitcoin burns and mint Core Lane tokens automatically**
- [x] **Execute all Core Lane transaction types with proper validation**
- [x] **Verify transaction signatures and recover sender addresses**
- [x] **Update account states (balances, nonces) based on transaction execution**
- [x] **Calculate and charge appropriate gas fees**

### Phase 2 Success Metrics (Target)
- [ ] Persistent state storage with database integration
- [ ] Full Ethereum JSON-RPC compatibility
- [ ] Comprehensive error handling and recovery
- [ ] Production-ready logging and monitoring
- [ ] Advanced transfer operations and exit marketplace

### Long-term Success Metrics
- [ ] Process 1000+ transactions per Core Lane block
- [ ] Maintain state consistency across Bitcoin reorgs
- [ ] Support Ethereum tooling via JSON-RPC compatibility
- [ ] Achieve sub-second transaction confirmation times
- [ ] Enable seamless BTC ↔ Core Lane value transfers

## Architecture Decisions

### State Management
- **Current**: In-memory HashMap-based storage with thread-safe access
- **Future**: Persistent database with state root commitments

### Transaction Format
- **Standard**: EIP-1559 transactions with proper gas pricing
- **DA Format**: `CORE_LANE` prefix + RLP-encoded transaction data
- **Bitcoin Embedding**: Taproot envelopes in Bitcoin transaction outputs

### Account Model
- **Compatible**: Ethereum-style accounts with balances, nonces, code, storage
- **Extensions**: Core Lane-specific addresses for system operations
- **Storage**: HashMap-based key-value storage for contract state

### Burn Method
- **Hybrid P2WSH + OP_RETURN**: P2WSH output carries burn value, 0-value OP_RETURN carries BRN1 data
- **Cost**: ~64-69 bytes (~3x more expensive than simple P2WPKH, but more reliable)
- **Detection**: Automatic detection and processing with proper value calculation

This plan provides a clear roadmap for building Core Lane from the current foundation to a fully functional Bitcoin-anchored execution environment.
