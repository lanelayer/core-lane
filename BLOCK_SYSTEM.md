# Core MEL Block System

This document describes the block system implementation in Core MEL, which provides a blockchain-like structure anchored to Bitcoin blocks.

## Overview

The Core MEL block system creates a sequence of blocks that correspond to Bitcoin blocks. Each Core MEL block contains:
- A reference to the corresponding Bitcoin block
- Core MEL transactions found in that Bitcoin block
- Standard Ethereum-compatible block structure

## Block Structure

### CoreMELBlock

```rust
struct CoreMELBlock {
    number: u64,                    // Block number (0 = genesis)
    hash: B256,                     // Block hash
    parent_hash: B256,              // Parent block hash
    timestamp: u64,                 // Unix timestamp
    transactions: Vec<String>,      // Transaction hashes
    transaction_count: u64,         // Number of transactions
    gas_used: U256,                 // Gas used by transactions
    gas_limit: U256,                // Gas limit (30M)
    base_fee_per_gas: Option<U256>, // Base fee per gas (1 gwei)
    difficulty: U256,               // Difficulty (always 1)
    total_difficulty: U256,         // Total difficulty
    extra_data: Vec<u8>,            // Extra data ("CORE-MEL")
    nonce: u64,                     // Nonce (always 0)
    miner: Address,                 // Miner address (always zero)
    state_root: B256,               // State root
    receipts_root: B256,            // Receipts root
    transactions_root: B256,        // Transactions root
    logs_bloom: Vec<u8>,            // Logs bloom filter
    bitcoin_block_hash: Option<String>,    // Bitcoin block hash
    bitcoin_block_height: Option<u64>,     // Bitcoin block height
}
```

## Genesis Block

The genesis block (block 0) is automatically created when the Core MEL node starts:

- **Number**: 0
- **Parent Hash**: Zero hash (no parent)
- **Timestamp**: January 1, 2024 00:00:00 UTC
- **Extra Data**: "CORE-MEL" (first 8 bytes)
- **State Root**: Zero hash
- **Receipts Root**: Zero hash
- **Transactions Root**: Zero hash

## Block Creation Process

1. **Bitcoin Block Processing**: When a Bitcoin block is processed, a new Core MEL block is created
2. **Transaction Processing**: Bitcoin burns and Core MEL DA transactions are added to the block
3. **Block Finalization**: The block is finalized with updated state roots and hash

## RPC Methods

### eth_blockNumber
Returns the latest Core MEL block number.

**Example**:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_blockNumber",
  "params": [],
  "id": 1
}
```

### eth_getBlockByNumber
Returns block information by block number.

**Parameters**:
- `block_id`: Block number (hex), "latest", "earliest", or "pending"
- `full`: Boolean to include full transaction objects

**Example**:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_getBlockByNumber",
  "params": ["0x0", false],
  "id": 2
}
```

### eth_getBlockByHash
Returns block information by block hash.

**Parameters**:
- `block_hash`: Block hash (hex)
- `full`: Boolean to include full transaction objects

**Example**:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_getBlockByHash",
  "params": ["0x...", false],
  "id": 3
}
```

### eth_getBlockTransactionCountByNumber
Returns the number of transactions in a block.

**Parameters**:
- `block_id`: Block number (hex), "latest", "earliest", or "pending"

**Example**:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_getBlockTransactionCountByNumber",
  "params": ["0x0"],
  "id": 4
}
```

## Block Querying Options

### Block Identifiers

- **Hex Number**: `"0x0"`, `"0x1"`, etc.
- **"latest"**: Latest block
- **"earliest"**: Genesis block (block 0)
- **"pending"**: Returns null (no pending blocks in Core MEL)

### Response Format

Blocks are returned in Ethereum-compatible JSON format:

```json
{
  "number": "0x0",
  "hash": "0x...",
  "parentHash": "0x...",
  "timestamp": "0x...",
  "gasUsed": "0x0",
  "gasLimit": "0x1c9c380",
  "difficulty": "0x1",
  "totalDifficulty": "0x0",
  "extraData": "0x434f52452d4d454c...",
  "nonce": "0x0",
  "miner": "0x0000000000000000000000000000000000000000",
  "stateRoot": "0x...",
  "receiptsRoot": "0x...",
  "transactionsRoot": "0x...",
  "logsBloom": "0x...",
  "size": "0x0",
  "uncles": [],
  "transactions": []
}
```

## Testing

Use the provided test script to verify block functionality:

```bash
./test_blocks.sh
```

This script tests:
- Genesis block initialization
- Block number queries
- Block retrieval by number and hash
- Transaction count queries
- Error handling for non-existent blocks

## Implementation Details

### Block Storage
- Blocks are stored in memory using `HashMap<u64, CoreMELBlock>`
- Block hashes are indexed using `HashMap<B256, u64>`
- Genesis block is automatically created on node startup

### Block Hashing
- Uses a simplified hash calculation for demonstration
- In production, should follow Ethereum's block header hashing algorithm

### Bitcoin Integration
- Each Core MEL block references a Bitcoin block
- Bitcoin block hash and height are stored in the block
- Core MEL blocks are created for each processed Bitcoin block

## Future Enhancements

1. **Persistent Storage**: Store blocks in a database
2. **Proper Hashing**: Implement Ethereum-compatible block header hashing
3. **Merkle Trees**: Add proper transaction and receipt Merkle trees
4. **Block Validation**: Add block validation and consensus rules
5. **Block Reorganization**: Handle Bitcoin chain reorganizations
