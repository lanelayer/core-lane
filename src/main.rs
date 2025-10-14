use alloy_primitives::Bytes;
use anyhow::{anyhow, Result};
use bitcoin::{
    blockdata::opcodes::all::{OP_ENDIF, OP_IF, OP_RETURN},
    blockdata::opcodes::{OP_FALSE, OP_TRUE},
    blockdata::script::Instruction,
    Script, Transaction,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use clap::{Parser, Subcommand};
use hex;
use serde_json::{self, json};
use std::collections::HashMap;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod account;
mod bitcoin_block;
mod bitcoin_cache_rpc;
mod block;
mod intents;
mod rpc;
mod state;
mod taproot_da;
mod transaction;

#[cfg(test)]
mod tests;

use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Decodable;
use bitcoin_cache_rpc::BitcoinCacheRpcServer;
use intents::{create_anchor_bitcoin_fill_intent, Intent};
use rpc::RpcServer;
use state::{BundleStateManager, StateManager, StoredTransaction, TransactionReceipt};
use taproot_da::TaprootDA;
use transaction::execute_transaction;

use crate::{bitcoin_block::process_bitcoin_block, block::CoreLaneBlockParsed};

/// Helper function to construct wallet database path
fn wallet_db_path(data_dir: &str, network: &str) -> String {
    let path = std::path::Path::new(data_dir);
    path.join(format!("wallet_{}.sqlite3", network))
        .to_string_lossy()
        .to_string()
}

/// Helper function to resolve mnemonic from various sources
/// Priority: explicit mnemonic > file > environment variable
fn resolve_mnemonic(
    explicit_mnemonic: Option<&str>,
    mnemonic_file: Option<&str>,
) -> Result<String> {
    // Priority 1: Explicit mnemonic flag
    if let Some(mnemonic) = explicit_mnemonic {
        return Ok(mnemonic.to_string());
    }

    // Priority 2: Mnemonic file
    if let Some(file_path) = mnemonic_file {
        let mnemonic = std::fs::read_to_string(file_path)
            .map_err(|e| anyhow::anyhow!("Failed to read mnemonic file '{}': {}", file_path, e))?;
        return Ok(mnemonic.trim().to_string());
    }

    // Priority 3: Environment variable
    if let Ok(mnemonic) = std::env::var("CORE_LANE_MNEMONIC") {
        return Ok(mnemonic.trim().to_string());
    }

    Err(anyhow::anyhow!(
        "Mnemonic required. Provide via:\n  \
         1. --mnemonic \"your words here\" (less secure, visible in process list)\n  \
         2. --mnemonic-file /path/to/file (recommended)\n  \
         3. CORE_LANE_MNEMONIC environment variable"
    ))
}

#[derive(Parser)]
#[command(name = "core-lane-node")]
#[command(about = "Core Lane Node - Bitcoin-anchored execution environment")]
struct Cli {
    /// Plain output mode (no emojis, machine-readable)
    #[arg(long, global = true)]
    plain: bool,

    /// Data directory for wallet databases and state
    #[arg(long, global = true, default_value = ".")]
    data_dir: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Start {
        /// Bitcoin RPC URL for reading blockchain data
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        bitcoin_rpc_read_url: String,
        /// Bitcoin RPC user for read operations
        #[arg(long, default_value = "user")]
        bitcoin_rpc_read_user: String,
        /// Bitcoin RPC password for read operations
        #[arg(long)]
        bitcoin_rpc_read_password: String,
        /// Bitcoin RPC URL for writing/wallet operations (optional, defaults to read URL)
        #[arg(long)]
        bitcoin_rpc_write_url: Option<String>,
        /// Bitcoin RPC user for write operations (optional, defaults to read user)
        #[arg(long)]
        bitcoin_rpc_write_user: Option<String>,
        /// Bitcoin RPC password for write operations (optional, defaults to read password)
        #[arg(long)]
        bitcoin_rpc_write_password: Option<String>,
        #[arg(long)]
        start_block: Option<u64>,
        #[arg(long, default_value = "127.0.0.1")]
        http_host: String,
        #[arg(long, default_value = "8545")]
        http_port: u16,
        #[arg(long, default_value = "mine")]
        rpc_wallet: String,
        /// Mnemonic phrase for signing (not recommended - visible in process list)
        #[arg(long)]
        mnemonic: Option<String>,
        /// Path to file containing mnemonic phrase (recommended, more secure)
        #[arg(long)]
        mnemonic_file: Option<String>,
        /// Electrum server URL (for mainnet/signet/testnet)
        #[arg(long)]
        electrum_url: Option<String>,
    },

    Burn {
        #[arg(long)]
        burn_amount: u64,
        #[arg(long)]
        chain_id: u32,
        #[arg(long)]
        eth_address: String,
        #[arg(long, default_value = "regtest")]
        network: String,
        /// Mnemonic phrase for signing (not recommended - visible in process list)
        #[arg(long)]
        mnemonic: Option<String>,
        /// Path to file containing mnemonic phrase (recommended, more secure)
        #[arg(long)]
        mnemonic_file: Option<String>,
        /// Bitcoin RPC URL (for regtest)
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        rpc_url: String,
        /// Bitcoin RPC user (for regtest)
        #[arg(long, default_value = "bitcoin")]
        rpc_user: String,
        /// Bitcoin RPC password (for regtest)
        #[arg(long)]
        rpc_password: Option<String>,
        /// Electrum server URL (for mainnet/signet/testnet)
        #[arg(long)]
        electrum_url: Option<String>,
    },
    SendTransaction {
        #[arg(long)]
        raw_tx_hex: String,
        #[arg(long, default_value = "regtest")]
        network: String,
        /// Mnemonic phrase for signing (not recommended - visible in process list)
        #[arg(long)]
        mnemonic: Option<String>,
        /// Path to file containing mnemonic phrase (recommended, more secure)
        #[arg(long)]
        mnemonic_file: Option<String>,
        /// Bitcoin RPC URL (for regtest)
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        rpc_url: String,
        /// Bitcoin RPC user (for regtest)
        #[arg(long, default_value = "bitcoin")]
        rpc_user: String,
        /// Bitcoin RPC password (for regtest)
        #[arg(long)]
        rpc_password: Option<String>,
        /// Electrum server URL (for mainnet/signet/testnet)
        #[arg(long)]
        electrum_url: Option<String>,
    },
    ConstructExitIntent {
        #[arg(long)]
        bitcoin_address: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "1000")]
        max_fee: u64,
        #[arg(long)]
        expire_by: u64,
    },
    BitcoinCache {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value = "8332")]
        port: u16,
        #[arg(long, default_value = "./bitcoin-cache")]
        cache_dir: String,
        #[arg(long)]
        bitcoin_rpc_url: String,
        #[arg(long, default_value = "")]
        bitcoin_rpc_user: String,
        #[arg(long, default_value = "")]
        bitcoin_rpc_password: String,
        #[arg(long)]
        no_rpc_auth: bool,
        #[arg(long, default_value = "http://144.76.56.210/blocks")]
        block_archive: String,
        #[arg(long)]
        starting_block_count: Option<u64>,
    },
    CreateWallet {
        /// Network to create wallet for (bitcoin, testnet, signet, regtest)
        #[arg(long, default_value = "regtest")]
        network: String,
        /// Optional mnemonic phrase to restore wallet (12 or 24 words)
        #[arg(long)]
        mnemonic: Option<String>,
        /// Only generate/output mnemonic, don't create database file
        #[arg(long)]
        mnemonic_only: bool,
    },
    GetAddress {
        /// Network of the wallet to load (bitcoin, testnet, signet, regtest)
        #[arg(long, default_value = "regtest")]
        network: String,
    },
}

#[derive(Debug, Clone)]
struct CoreLaneBlock {
    number: u64,
    hash: B256,
    parent_hash: B256,
    timestamp: u64,
    transactions: Vec<String>, // Transaction hashes
    transaction_count: u64,
    gas_used: U256,
    gas_limit: U256,
    #[allow(dead_code)]
    base_fee_per_gas: Option<U256>,
    difficulty: U256,
    total_difficulty: U256,
    extra_data: Vec<u8>,
    nonce: u64,
    miner: Address,
    state_root: B256,
    receipts_root: B256,
    transactions_root: B256,
    logs_bloom: Vec<u8>,
    block_origin: Option<CoreLaneBlockParsed>,
}

impl CoreLaneBlock {
    fn new(
        number: u64,
        parent_hash: B256,
        timestamp: u64,
        block_origin: Option<CoreLaneBlockParsed>,
    ) -> Self {
        let mut extra_data = vec![0u8; 32];
        extra_data[0] = b'C';
        extra_data[1] = b'O';
        extra_data[2] = b'R';
        extra_data[3] = b'E';
        extra_data[4] = b'-';
        extra_data[5] = b'M';
        extra_data[6] = b'E';
        extra_data[7] = b'L';

        Self {
            number,
            hash: B256::default(), // Will be calculated
            parent_hash,
            timestamp,
            transactions: Vec::new(),
            transaction_count: 0,
            gas_used: U256::ZERO,
            gas_limit: U256::from(30_000_000u64), // 30M gas limit
            base_fee_per_gas: Some(U256::from(1_000_000_000u64)), // 1 gwei
            difficulty: U256::from(1u64),
            total_difficulty: U256::from(number),
            extra_data,
            nonce: 0,
            miner: Address::ZERO, // No mining in Core Lane
            state_root: B256::default(),
            receipts_root: B256::default(),
            transactions_root: B256::default(),
            logs_bloom: vec![0u8; 256],
            block_origin: block_origin,
        }
    }

    fn genesis() -> Self {
        let mut block = Self::new(
            0,
            B256::default(), // Genesis has no parent
            1704067200,      // January 1, 2024 00:00:00 UTC
            None,
        );

        // Set genesis-specific values
        block.hash = block.calculate_hash();
        block.state_root = B256::from_slice(&[0u8; 32]);
        block.receipts_root = B256::from_slice(&[0u8; 32]);
        block.transactions_root = B256::from_slice(&[0u8; 32]);

        block
    }

    fn calculate_hash(&self) -> B256 {
        // Use keccak256 for block hash calculation (Ethereum-style)
        use alloy_primitives::keccak256;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.number.hash(&mut hasher);
        self.parent_hash.hash(&mut hasher);
        self.timestamp.hash(&mut hasher);
        self.transaction_count.hash(&mut hasher);
        self.gas_used.hash(&mut hasher);
        self.gas_limit.hash(&mut hasher);

        let hash_bytes = hasher.finish().to_le_bytes();
        let hash_bytes = keccak256(hash_bytes);
        B256::from_slice(hash_bytes.as_slice())
    }

    fn to_json(&self, full: bool) -> serde_json::Value {
        let mut block_json = json!({
            "number": format!("0x{:x}", self.number),
            "hash": format!("0x{:x}", self.hash),
            "parentHash": format!("0x{:x}", self.parent_hash),
            "timestamp": format!("0x{:x}", self.timestamp),
            "gasUsed": format!("0x{:x}", self.gas_used),
            "gasLimit": format!("0x{:x}", self.gas_limit),
            "difficulty": format!("0x{:x}", self.difficulty),
            "totalDifficulty": format!("0x{:x}", self.total_difficulty),
            "extraData": format!("0x{}", hex::encode(&self.extra_data)),
            "nonce": format!("0x{:016x}", self.nonce),
            "miner": format!("0x{:x}", self.miner),
            "stateRoot": format!("0x{:x}", self.state_root),
            "receiptsRoot": format!("0x{:x}", self.receipts_root),
            "transactionsRoot": format!("0x{:x}", self.transactions_root),
            "logsBloom": format!("0x{}", hex::encode(&self.logs_bloom)),
            "sha3Uncles": "0x0000000000000000000000000000000000000000000000000000000000000000", // Hash of empty array (32 zero bytes)
            "size": format!("0x{:x}", self.transaction_count * 32), // Approximate size
            "uncles": [],
        });

        if full {
            block_json["transactions"] = json!(self.transactions);
        } else {
            block_json["transactions"] = json!(self.transactions);
        }

        block_json
    }
}

#[derive(Debug, Clone)]
struct CoreLaneState {
    account_manager: StateManager,
    last_processed_block: u64,
    blocks: HashMap<u64, CoreLaneBlock>,  // Block number -> Block
    block_hashes: HashMap<B256, u64>,     // Block hash -> Block number
    current_block: Option<CoreLaneBlock>, // Current block being built
    genesis_block: CoreLaneBlock,         // Genesis block
    bitcoin_client_read: Arc<Client>,     // Client for reading blockchain data
    bitcoin_client_write: Arc<Client>,    // Client for writing/wallet operations
}

impl CoreLaneState {
    pub fn bitcoin_client_read(&self) -> Arc<Client> {
        self.bitcoin_client_read.clone()
    }

    pub fn bitcoin_client_write(&self) -> Arc<Client> {
        self.bitcoin_client_write.clone()
    }
}

struct CoreLaneNode {
    bitcoin_client_read: Arc<Client>,
    bitcoin_client_write: Arc<Client>,
    state: Arc<Mutex<CoreLaneState>>,
    data_dir: String,
}

impl CoreLaneNode {
    fn new(bitcoin_client_read: Client, bitcoin_client_write: Client, data_dir: String) -> Self {
        let genesis_block = CoreLaneBlock::genesis();
        let genesis_hash = genesis_block.hash;

        let mut blocks = HashMap::new();
        let mut block_hashes = HashMap::new();
        let bitcoin_client_read = Arc::new(bitcoin_client_read);
        let bitcoin_client_write = Arc::new(bitcoin_client_write);

        // Store genesis block
        blocks.insert(0, genesis_block.clone());
        block_hashes.insert(genesis_hash, 0);

        let state = Arc::new(Mutex::new(CoreLaneState {
            account_manager: StateManager::new(),
            last_processed_block: 0,
            blocks,
            block_hashes,
            current_block: None,
            genesis_block: genesis_block.clone(),
            bitcoin_client_read: bitcoin_client_read.clone(),
            bitcoin_client_write: bitcoin_client_write.clone(),
        }));

        // Write genesis state to disk
        if let Err(e) = Self::write_genesis_state(&data_dir) {
            error!("Failed to write genesis state to disk: {}", e);
        }

        Self {
            bitcoin_client_read: bitcoin_client_read.clone(),
            bitcoin_client_write: bitcoin_client_write.clone(),
            state,
            data_dir,
        }
    }

    async fn create_new_block(
        &self,
        block_origin: Option<CoreLaneBlockParsed>,
    ) -> Result<CoreLaneBlock> {
        let mut state = self.state.lock().await;

        // Get the latest block number
        let latest_number = state.blocks.keys().max().copied().unwrap_or(0);
        let next_number = latest_number + 1;

        // Get the latest block hash as parent
        let parent_hash = if let Some(latest_block) = state.blocks.get(&latest_number) {
            latest_block.hash
        } else {
            state.genesis_block.hash
        };

        let anchor_block_timestamp = if let Some(ref block_origin) = block_origin {
            block_origin.anchor_block_timestamp
        } else {
            0
        };

        // Create new block with Bitcoin block timestamp
        let mut new_block = CoreLaneBlock::new(
            next_number,
            parent_hash,
            anchor_block_timestamp,
            block_origin,
        );
        // Calculate hash
        new_block.hash = new_block.calculate_hash();
        // Set as current block
        info!(
            "🆕 Created Core Lane block {} (parent: {}) with timestamp {}",
            next_number, latest_number, new_block.timestamp
        );
        Ok(new_block)
    }

    /// Write the delta (BundleStateManager) to disk
    fn write_delta_to_disk(
        &self,
        block_number: u64,
        bundle_state: &state::BundleStateManager,
    ) -> Result<()> {
        use std::fs;
        use std::path::Path;

        // Create deltas directory if it doesn't exist
        let deltas_dir = Path::new(&self.data_dir).join("deltas");
        fs::create_dir_all(&deltas_dir)?;

        // Write the bundle state (delta) using borsh serialization
        let delta_file = deltas_dir.join(format!("{}", block_number));
        let serialized_delta = bundle_state.borsh_serialize()?;
        fs::write(&delta_file, serialized_delta)?;

        info!(
            "💾 Wrote delta for block {} to {}",
            block_number,
            delta_file.display()
        );
        Ok(())
    }

    /// Write the state (StateManager) to disk
    fn write_state_to_disk(&self, block_number: u64, state_manager: &StateManager) -> Result<()> {
        use std::fs;
        use std::path::Path;

        // Create blocks directory if it doesn't exist
        let blocks_dir = Path::new(&self.data_dir).join("blocks");
        fs::create_dir_all(&blocks_dir)?;

        // Write the full state manager using borsh serialization
        let block_file = blocks_dir.join(format!("{}", block_number));
        let serialized_state = state_manager.borsh_serialize()?;
        fs::write(&block_file, serialized_state)?;

        info!(
            "💾 Wrote state for block {} to {}",
            block_number,
            block_file.display()
        );
        Ok(())
    }

    /// Write the genesis state (block 0) to disk
    pub fn write_genesis_state(data_dir: &str) -> Result<()> {
        use std::fs;
        use std::path::Path;

        // Create blocks directory if it doesn't exist
        let blocks_dir = Path::new(data_dir).join("blocks");
        fs::create_dir_all(&blocks_dir)?;

        // Create initial empty state for genesis block
        let genesis_state = StateManager::new();

        // Write the genesis state using borsh serialization
        let block_file = blocks_dir.join("0");
        let serialized_state = genesis_state.borsh_serialize()?;
        fs::write(&block_file, serialized_state)?;

        info!(
            "💾 Wrote genesis state (block 0) to {}",
            block_file.display()
        );
        Ok(())
    }

    async fn finalize_current_block(
        &self,
        transactions: Vec<(StoredTransaction, TransactionReceipt, String)>,
        mut new_block: CoreLaneBlock,
    ) -> Result<()> {
        let mut state = self.state.lock().await;

        // Update state root, receipts root, etc.
        new_block.state_root = B256::from_slice(&[0u8; 32]); // Simplified for now
        new_block.receipts_root = B256::from_slice(&[0u8; 32]); // Simplified for now
        new_block.transactions_root = B256::from_slice(&[0u8; 32]); // Simplified for now
        for (_stored_tx, _receipt, tx_hash) in transactions.clone() {
            new_block.transactions.push(tx_hash.clone());
            new_block.transaction_count = new_block.transactions.len() as u64;
        }
        // Recalculate hash with updated roots
        new_block.hash = new_block.calculate_hash();

        // Update stored block
        state.blocks.insert(new_block.number, new_block.clone());
        state.block_hashes.insert(new_block.hash, new_block.number);

        // Transactions and receipts are already in bundle state and will be applied via apply_changes
        // Just need to update block metadata with transaction hashes
        for (_stored_tx, _receipt, tx_hash) in transactions.iter() {
            // Transaction hashes already added to new_block in the loop above
        }

        info!(
            "✅ Finalized Core Lane block {} with {} transactions",
            new_block.number, new_block.transaction_count
        );
        state.current_block = Some(new_block);
        Ok(())
    }

    async fn start_block_scanner(&self, start_block: Option<u64>) -> Result<()> {
        info!("Starting Core Lane block scanner...");
        info!("Connected to Bitcoin node successfully");
        info!("Core Lane state initialized");

        // Initialize starting block if provided
        if let Some(block) = start_block {
            let mut state = self.state.lock().await;
            state.last_processed_block = block.saturating_sub(1);
            info!("Starting from block: {}", block);
        }

        loop {
            match self.scan_new_blocks().await {
                Ok(_) => {
                    // Wait before next scan
                    sleep(Duration::from_secs(10)).await;
                }
                Err(e) => {
                    error!("Error scanning blocks: {}", e);
                    sleep(Duration::from_secs(30)).await;
                }
            }
        }
    }

    async fn scan_new_blocks(&self) -> Result<()> {
        let tip = self.bitcoin_client_read.get_block_count()?;

        // Get the starting block without holding the lock
        let start_block = {
            let state = self.state.lock().await;
            if state.last_processed_block == 0 {
                // First run - start from recent blocks
                tip.saturating_sub(10)
            } else {
                state.last_processed_block + 1
            }
        };

        if start_block > tip {
            return Ok(());
        }

        info!(
            "Scanning blocks {} to {} for Core Lane transactions...",
            start_block, tip
        );

        for height in start_block..=tip {
            let bitcoin_block = process_bitcoin_block(self.bitcoin_client_read.clone(), height)?;

            match self.process_block(bitcoin_block).await {
                Ok(_) => {
                    // Update the last processed block
                    let mut state = self.state.lock().await;
                    state.last_processed_block = height;
                    debug!("Processed block {} for Core Lane", height);
                }
                Err(e) => {
                    error!("Error processing block {}: {}", height, e);
                }
            }
        }

        Ok(())
    }

    async fn process_block(&self, bitcoin_block: CoreLaneBlockParsed) -> Result<()> {
        let new_block = self.create_new_block(Some(bitcoin_block)).await?;

        let new_block_clone = new_block.clone();
        let mut core_lane_transactions = Vec::new();

        // Create a single bundle state manager for the entire block
        let mut bundle_state = state::BundleStateManager::new();

        if let Some(block_origin) = new_block_clone.block_origin {
            debug!("🔥 Phase 1: Processing burns...");
            let state = self.state.lock().await;
            for burn in block_origin.burns.iter() {
                info!("🪙 Minting {} tokens to {}", burn.amount, burn.address);
                bundle_state.add_balance(&state.account_manager, burn.address, burn.amount)?;
            }
            drop(state);

            let mut tx_count = 0;
            for bundle in block_origin.bundles.iter() {
                if bundle.valid_for_block != u64::MAX && bundle.valid_for_block != new_block.number
                {
                    // skip this bundle because it's not valid for this block
                    continue;
                }
                for (_tx_index, tx) in bundle.transactions.iter().enumerate() {
                    let tx = self
                        .process_core_lane_transaction(
                            &mut bundle_state,
                            tx,
                            new_block.number,
                            tx_count,
                        )
                        .await;
                    if let Some((stored_tx, receipt, tx_hash)) = tx {
                        core_lane_transactions.push((stored_tx, receipt, tx_hash));
                        tx_count += 1;
                    }
                }
            }
        }

        // Apply all state changes atomically at the end of block processing
        let block_number = new_block.number;
        {
            let mut state = self.state.lock().await;

            // Write the delta (changes) to disk before applying them
            if let Err(e) = self.write_delta_to_disk(block_number, &bundle_state) {
                error!(
                    "Failed to write delta for block {} to disk: {}",
                    block_number, e
                );
            }

            // Apply the changes to the actual state
            state.account_manager.apply_changes(bundle_state);

            // Write the final state to disk after applying changes
            if let Err(e) = self.write_state_to_disk(block_number, &state.account_manager) {
                error!(
                    "Failed to write state for block {} to disk: {}",
                    block_number, e
                );
            }
        }

        // Finalize the Core Lane block
        self.finalize_current_block(core_lane_transactions, new_block)
            .await?;

        Ok(())
    }

    async fn process_core_lane_transaction(
        &self,
        bundle_state: &mut state::BundleStateManager,
        tx: &(TxEnvelope, Address, Vec<u8>),
        block_number: u64,
        tx_number: u64,
    ) -> Option<(StoredTransaction, TransactionReceipt, String)> {
        let gas_price = U256::from(214285714u64);

        let mut state = self.state.lock().await;

        //  Transaction size ≈ 150 byte
        // Fee rate = 3 sats/vbyte
        // Conversion rate: 1 sat = 10¹⁰ wei
        // Gas cost for comparable tx: 21,000 gas = 150 bytes
        //
        if tx.0.is_eip1559() {
            if gas_price > tx.0.as_eip1559().unwrap().tx().max_fee_per_gas {
                warn!("      ⚠️  Gas fee is greater than the EIP-1559 transaction max fee per gas, skipping: {:?}", tx.0);
                return None;
            }
        } else if tx.0.is_legacy() {
            if gas_price > tx.0.as_legacy().unwrap().tx().gas_price {
                warn!("      ⚠️  Gas fee is greater than the legacy transaction gas price, skipping: {:?}", tx.0);
                return None;
            }
        } else {
            warn!(
                "      ⚠️  Non-EIP 1559 or legacy transactions are not supported, skipping: {:?}",
                tx.0
            );
            return None;
        }

        // Charge gas fee first from bundle state
        let gas_fee = gas_price * U256::from(alloy_consensus::Transaction::gas_limit(&tx.0) as u64);
        if let Err(e) = bundle_state.sub_balance(&state.account_manager, tx.1, gas_fee) {
            warn!(
                "      ⚠️  Failed to charge gas fee ahead of tx execution: {}",
                e
            );
            return None;
        } else {
            info!("      💰 Charged gas fee: {} wei", gas_fee);
        }

        // Execute transaction with bundle state
        let _execution_result = execute_transaction(&tx.0, tx.1, bundle_state, &mut state);

        // XXX add gas refund later

        // Read balance after execution
        let final_balance = bundle_state.get_balance(&state.account_manager, tx.1);

        // Store the transaction with both envelope and raw data in bundle state
        let stored_tx = StoredTransaction {
            envelope: tx.0.clone(),
            raw_data: tx.2.clone(),
            block_number: block_number,
        };
        // Create and store transaction receipt in bundle state
        let tx_hash = format!("0x{}", hex::encode(alloy_primitives::keccak256(&tx.2)));

        let receipt = TransactionReceipt {
            transaction_hash: tx_hash.clone(),
            block_number: block_number,
            transaction_index: tx_number,
            from: format!("0x{}", hex::encode(tx.1.as_slice())),
            to: None, // Will be set based on transaction type
            cumulative_gas_used: "0x0".to_string(),
            gas_used: "0x0".to_string(),
            contract_address: None,
            logs: Vec::new(),
            status: "0x1".to_string(), // Success
            effective_gas_price: format!("0x{}", hex::encode(gas_price.to_be_bytes_vec())),
            tx_type: match &tx.0 {
                TxEnvelope::Legacy(_) => "0x0".to_string(),
                TxEnvelope::Eip2930(_) => "0x1".to_string(),
                TxEnvelope::Eip1559(_) => "0x2".to_string(),
                TxEnvelope::Eip4844(_) => "0x3".to_string(),
                _ => "0x0".to_string(),
            },
            logs_bloom: format!("0x{}", hex::encode(vec![0u8; 256])),
        };

        // Store in bundle state
        bundle_state.add_transaction(stored_tx.clone());
        bundle_state.add_receipt(tx_hash.clone(), receipt.clone());

        // Print account balances after execution
        debug!("   💰 Account balance after execution: {}", final_balance);

        drop(state); // Release lock
        Some((stored_tx, receipt, tx_hash))
    }

    async fn send_transaction_to_da(
        &self,
        raw_tx_hex: &str,
        mnemonic: &str,
        network: bitcoin::Network,
        network_str: &str,
        electrum_url: Option<&str>,
        data_dir: &str,
    ) -> Result<()> {
        // Delegate to the TaprootDA implementation which handles all validation and logic
        // Use write client for DA transactions (wallet operations)
        let taproot_da = TaprootDA::new(self.bitcoin_client_write.clone());
        let _bitcoin_txid = taproot_da
            .send_transaction_to_da(
                raw_tx_hex,
                mnemonic,
                network,
                network_str,
                electrum_url,
                data_dir,
            )
            .await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing only if not in plain mode
    if !cli.plain {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "core_lane_node=info,tower_http=debug".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

        info!("Starting Core Lane Node");
    }

    match &cli.command {
        Commands::Start {
            bitcoin_rpc_read_url,
            bitcoin_rpc_read_user,
            bitcoin_rpc_read_password,
            bitcoin_rpc_write_url,
            bitcoin_rpc_write_user,
            bitcoin_rpc_write_password,
            start_block,
            http_host,
            http_port,
            rpc_wallet,
            mnemonic,
            mnemonic_file,
            electrum_url,
        } => {
            // Resolve mnemonic from various sources
            let mnemonic_str = resolve_mnemonic(mnemonic.as_deref(), mnemonic_file.as_deref())?;

            let wallet = rpc_wallet.to_string();

            // Create read client (without wallet endpoint)
            let read_client = bitcoincore_rpc::Client::new(
                bitcoin_rpc_read_url,
                Auth::UserPass(
                    bitcoin_rpc_read_user.to_string(),
                    bitcoin_rpc_read_password.to_string(),
                ),
            )?;

            // Create write client - use write params if provided, otherwise use read params
            let write_url = bitcoin_rpc_write_url
                .as_ref()
                .unwrap_or(bitcoin_rpc_read_url);
            let write_user = bitcoin_rpc_write_user
                .as_ref()
                .unwrap_or(bitcoin_rpc_read_user);
            let write_password = bitcoin_rpc_write_password
                .as_ref()
                .unwrap_or(bitcoin_rpc_read_password);

            // Write client connects to wallet endpoint for wallet operations
            let write_client = bitcoincore_rpc::Client::new(
                &format!("{}/wallet/{}", write_url, rpc_wallet),
                Auth::UserPass(write_user.to_string(), write_password.to_string()),
            )?;

            // Get blockchain info from read client
            let blockchain_info: serde_json::Value = read_client.call("getblockchaininfo", &[])?;

            let network = if let Some(chain) = blockchain_info.get("chain") {
                match chain.as_str() {
                    Some("main") => bitcoincore_rpc::bitcoin::Network::Bitcoin,
                    Some("test") => bitcoincore_rpc::bitcoin::Network::Testnet,
                    Some("signet") => bitcoincore_rpc::bitcoin::Network::Signet,
                    Some("regtest") => bitcoincore_rpc::bitcoin::Network::Regtest,
                    Some(chain) => return Err(anyhow::anyhow!("Unknown chain type: {}", chain)),
                    None => return Err(anyhow::anyhow!("Chain field is not a string")),
                }
            } else {
                return Err(anyhow::anyhow!(
                    "No 'chain' field found in getblockchaininfo response"
                ));
            };

            info!("🔗 Bitcoin RPC connections configured:");
            info!("   📖 Read:  {}", bitcoin_rpc_read_url);
            info!("   ✍️  Write: {}/wallet/{}", write_url, rpc_wallet);

            let node = CoreLaneNode::new(read_client, write_client, cli.data_dir.clone());

            // Start HTTP server for JSON-RPC - share the same state
            let shared_state = Arc::clone(&node.state);
            let rpc_server = RpcServer::with_bitcoin_client(
                shared_state,
                node.bitcoin_client_write.clone(),
                network,
                wallet,
                mnemonic_str.clone(),
                electrum_url.clone(),
                cli.data_dir.clone(),
            );

            let app = rpc_server.router();

            let addr = format!("{}:{}", http_host, http_port);
            info!("🚀 Starting JSON-RPC server on http://{}", addr);

            // Start the HTTP server in a separate task
            let server_handle = tokio::spawn(async move {
                let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
                axum::serve(listener, app).await.unwrap();
            });

            // Start block scanner in main task
            let start_block = *start_block;
            let scanner_handle =
                tokio::spawn(async move { node.start_block_scanner(start_block).await });

            // Wait for both tasks
            let _ = tokio::try_join!(server_handle, scanner_handle)?;
        }

        Commands::Burn {
            burn_amount,
            chain_id,
            eth_address,
            network: network_str,
            mnemonic,
            mnemonic_file,
            rpc_url,
            rpc_user,
            rpc_password,
            electrum_url,
        } => {
            use bdk_wallet::bitcoin::Network as BdkNetwork;
            use bdk_wallet::keys::{bip39::Mnemonic, DerivableKey, ExtendedKey};
            use bdk_wallet::rusqlite::Connection;
            use bdk_wallet::{KeychainKind, Wallet};

            // Resolve mnemonic from various sources
            let mnemonic_str = resolve_mnemonic(mnemonic.as_deref(), mnemonic_file.as_deref())?;

            if !cli.plain {
                info!("🔥 Creating Bitcoin burn transaction...");
            }

            // Parse network
            let bdk_network = match network_str.as_str() {
                "bitcoin" | "mainnet" => BdkNetwork::Bitcoin,
                "testnet" => BdkNetwork::Testnet,
                "signet" => BdkNetwork::Signet,
                "regtest" => BdkNetwork::Regtest,
                _ => return Err(anyhow::anyhow!("Invalid network: {}", network_str)),
            };

            // Parse mnemonic and derive signing keys
            if !cli.plain {
                info!("🔑 Parsing mnemonic for signing keys...");
            }

            let mnemonic = Mnemonic::parse(mnemonic_str)
                .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {}", e))?;

            let xkey: ExtendedKey = mnemonic
                .into_extended_key()
                .map_err(|_| anyhow::anyhow!("Failed to derive extended key"))?;
            let xprv = xkey
                .into_xprv(bdk_network)
                .ok_or_else(|| anyhow::anyhow!("Failed to get xprv"))?;

            // Reconstruct descriptors with xprv for signing
            let external_descriptor = format!("wpkh({}/0/*)", xprv);
            let internal_descriptor = format!("wpkh({}/1/*)", xprv);

            // Ensure data directory exists
            std::fs::create_dir_all(&cli.data_dir)?;

            // Load BDK wallet with descriptors
            let wallet_path = wallet_db_path(&cli.data_dir, network_str);

            if !cli.plain {
                info!("📂 Loading wallet from: {}", wallet_path);
            }

            let mut conn = Connection::open(&wallet_path)?;

            // Load wallet with descriptors to ensure signing keys are available
            let wallet_opt = Wallet::load()
                .descriptor(KeychainKind::External, Some(external_descriptor.clone()))
                .descriptor(KeychainKind::Internal, Some(internal_descriptor.clone()))
                .extract_keys()
                .check_network(bdk_network)
                .load_wallet(&mut conn)?;

            let mut wallet = match wallet_opt {
                Some(w) => w,
                None => {
                    // Create wallet if it doesn't exist
                    Wallet::create(external_descriptor, internal_descriptor)
                        .network(bdk_network)
                        .create_wallet(&mut conn)?
                }
            };

            if !cli.plain {
                info!("✅ Wallet loaded with signing keys from mnemonic");
            }

            // Sync wallet based on network
            if network_str == "regtest" {
                // Use bitcoind RPC for regtest
                use bdk_bitcoind_rpc::bitcoincore_rpc::Auth as RpcAuth;
                use bdk_bitcoind_rpc::bitcoincore_rpc::Client;
                use bdk_bitcoind_rpc::Emitter;
                use std::sync::Arc;

                if !cli.plain {
                    info!("🔗 Syncing with Bitcoin RPC: {}", rpc_url);
                }

                let rpc_pass = rpc_password
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("bitcoin123");
                let rpc_client = Client::new(
                    rpc_url,
                    RpcAuth::UserPass(rpc_user.clone(), rpc_pass.to_string()),
                )?;

                let mut emitter = Emitter::new(
                    &rpc_client,
                    wallet.latest_checkpoint().clone(),
                    0,
                    std::iter::empty::<Arc<bitcoin::Transaction>>(), // No mempool txs
                );

                while let Some(block_emission) = emitter.next_block()? {
                    wallet.apply_block(&block_emission.block, block_emission.block_height())?;
                }

                wallet.persist(&mut conn)?;
            } else {
                // Use Electrum for other networks
                use bdk_electrum::electrum_client::ElectrumApi;
                use bdk_electrum::{electrum_client, BdkElectrumClient};

                let electrum_url = electrum_url.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("--electrum-url required for network: {}", network_str)
                })?;

                if !cli.plain {
                    info!("🔗 Syncing with Electrum: {}", electrum_url);
                }

                let electrum_client = electrum_client::Client::new(&electrum_url)?;
                let electrum = BdkElectrumClient::new(electrum_client);

                if !cli.plain {
                    info!("🔍 Scanning blockchain for wallet transactions...");
                }

                let request = wallet.start_full_scan().build();
                let response = electrum.full_scan(request, 5, 1, false)?;

                wallet.apply_update(response)?;
                wallet.persist(&mut conn)?;
            }

            if !cli.plain {
                info!("💰 Wallet synced successfully");
            }

            // Check balance
            let balance = wallet.balance();
            if !cli.plain {
                info!(
                    "💵 Balance: {} sats (confirmed: {}, pending: {})",
                    balance.total().to_sat(),
                    balance.confirmed.to_sat(),
                    balance.untrusted_pending.to_sat()
                );

                // Debug: Show UTXOs
                info!("🔍 Available UTXOs:");
                let utxos: Vec<_> = wallet.list_unspent().collect();
                for utxo in &utxos {
                    info!(
                        "  UTXO: {}:{} - {} sats (keychain: {:?})",
                        utxo.outpoint.txid,
                        utxo.outpoint.vout,
                        utxo.txout.value.to_sat(),
                        utxo.keychain
                    );
                }
                if utxos.is_empty() {
                    warn!("⚠️  No UTXOs found!");
                }
            }

            if balance.confirmed.to_sat() < *burn_amount {
                return Err(anyhow::anyhow!(
                    "Insufficient funds. Need {} sats, have {} sats confirmed",
                    burn_amount,
                    balance.confirmed.to_sat()
                ));
            }

            // Create burn transaction with BDK
            use bitcoin::{blockdata::opcodes::all::OP_RETURN, Amount, ScriptBuf};

            if !cli.plain {
                info!("🔥 Building burn transaction...");
            }

            // Validate ETH address
            let eth_addr = eth_address.trim_start_matches("0x");
            if eth_addr.len() != 40 {
                return Err(anyhow::anyhow!(
                    "Ethereum address must be 20 bytes (40 hex chars)"
                ));
            }

            // Create BRN1 payload
            let addr_bytes = hex::decode(&eth_addr)?;
            let mut payload = Vec::with_capacity(4 + 4 + 20);
            payload.extend_from_slice(b"BRN1");
            payload.extend_from_slice(&chain_id.to_be_bytes());
            payload.extend_from_slice(&addr_bytes);

            if payload.len() > 80 {
                return Err(anyhow::anyhow!(
                    "OP_RETURN payload {} bytes exceeds standard relay policy (80 bytes)",
                    payload.len()
                ));
            }

            // Create the burn script: OP_RETURN + BRN1 payload
            let payload_bytes = <&bitcoin::blockdata::script::PushBytes>::try_from(&payload[..])
                .map_err(|_| anyhow::anyhow!("Payload too large for OP_RETURN"))?;
            let burn_script = ScriptBuf::builder()
                .push_opcode(OP_RETURN)
                .push_slice(payload_bytes)
                .into_script();

            // Create P2WSH address from the burn script (Address::p2wsh does the hashing)
            let p2wsh_address = bitcoin::Address::p2wsh(&burn_script, bdk_network);

            if !cli.plain {
                info!("🔥 P2WSH burn address: {}", p2wsh_address);
            }

            // Build transaction using BDK
            use bdk_wallet::bitcoin::FeeRate;

            let mut tx_builder = wallet.build_tx();

            // Set fee rate (2 sat/vB for regtest, higher for other networks)
            let fee_rate = if network_str == "regtest" {
                FeeRate::from_sat_per_vb(2).expect("valid fee rate")
            } else {
                FeeRate::from_sat_per_vb(10).expect("valid fee rate")
            };
            tx_builder.fee_rate(fee_rate);

            // Add P2WSH burn output
            tx_builder.add_recipient(
                p2wsh_address.script_pubkey(),
                Amount::from_sat(*burn_amount),
            );

            // Add OP_RETURN output with BRN1 data (manually as a recipient)
            let opret_script = ScriptBuf::builder()
                .push_opcode(OP_RETURN)
                .push_slice(payload_bytes)
                .into_script();
            tx_builder.add_recipient(opret_script, Amount::from_sat(0));

            if !cli.plain {
                info!("💰 Fee rate: {} sat/vB", fee_rate.to_sat_per_vb_floor());
            }

            // Build PSBT with updated metadata
            let mut psbt = tx_builder.finish();
            let mut psbt =
                psbt.map_err(|e| anyhow::anyhow!("Failed to build transaction: {}", e))?;

            if !cli.plain {
                info!(
                    "📝 Transaction built ({} inputs, {} outputs)",
                    psbt.inputs.len(),
                    psbt.outputs.len()
                );

                // Debug: Show PSBT inputs before signing
                for (i, input) in psbt.inputs.iter().enumerate() {
                    info!("  Input {} before signing:", i);
                    info!("    witness_utxo: {:?}", input.witness_utxo.is_some());
                    info!(
                        "    non_witness_utxo: {:?}",
                        input.non_witness_utxo.is_some()
                    );
                    info!("    witness_script: {:?}", input.witness_script.is_some());
                    info!("    redeem_script: {:?}", input.redeem_script.is_some());
                    info!(
                        "    bip32_derivation: {} keys",
                        input.bip32_derivation.len()
                    );

                    // Show the derivation info
                    for (pubkey, derivation) in &input.bip32_derivation {
                        info!("      pubkey: {}, path: {:?}", pubkey, derivation.1);
                    }
                }

                info!("🖊️  Signing transaction...");
            }

            // Sign the transaction using BDK
            #[allow(deprecated)]
            let finalized = wallet.sign(
                &mut psbt,
                bdk_wallet::SignOptions {
                    trust_witness_utxo: true,
                    try_finalize: true,
                    ..Default::default()
                },
            )?;

            if !cli.plain {
                info!("✅ Transaction signed (finalized: {})", finalized);

                // Debug: Check PSBT state after signing
                for (i, input) in psbt.inputs.iter().enumerate() {
                    info!("  Input {} after signing:", i);
                    info!(
                        "    final_script_witness: {:?}",
                        input.final_script_witness.is_some()
                    );
                    info!(
                        "    final_script_sig: {:?}",
                        input.final_script_sig.is_some()
                    );
                    info!("    partial_sigs: {} sigs", input.partial_sigs.len());
                    if !input.partial_sigs.is_empty() {
                        info!("    ⚠️  Has partial signatures but not finalized!");
                    }
                }
            }

            if !finalized {
                if !cli.plain {
                    warn!("⚠️  Transaction not fully finalized by BDK, attempting manual finalization...");
                }

                // Try manual finalization with miniscript
                use bdk_wallet::bitcoin::secp256k1::Secp256k1;
                use bdk_wallet::miniscript::psbt::PsbtExt;

                if let Err(e) = psbt.finalize_mut(&Secp256k1::new()) {
                    return Err(anyhow::anyhow!("Failed to finalize PSBT manually: {:?}", e));
                }

                if !cli.plain {
                    info!("✅ Manual finalization completed");

                    // Check if we now have final witnesses
                    for (i, input) in psbt.inputs.iter().enumerate() {
                        info!("  Input {} after finalization:", i);
                        info!(
                            "    final_script_witness: {:?}",
                            input.final_script_witness.is_some()
                        );
                        info!(
                            "    final_script_sig: {:?}",
                            input.final_script_sig.is_some()
                        );
                    }
                }
            }

            // Extract the signed transaction
            let tx = psbt
                .extract_tx()
                .map_err(|e| anyhow::anyhow!("Failed to extract transaction: {:?}", e))?;
            let tx_bytes = bitcoin::consensus::serialize(&tx);
            let tx_hex = hex::encode(&tx_bytes);
            let txid = tx.compute_txid();

            if !cli.plain {
                info!("✅ Transaction signed: {}", txid);
                info!("📡 Broadcasting transaction...");
            }

            // Broadcast transaction based on network
            if network_str == "regtest" {
                // Use bitcoind RPC for regtest
                use bdk_bitcoind_rpc::bitcoincore_rpc::Auth as RpcAuth;
                use bdk_bitcoind_rpc::bitcoincore_rpc::Client;

                let rpc_pass = rpc_password
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("bitcoin123");
                let rpc_client = Client::new(
                    rpc_url,
                    RpcAuth::UserPass(rpc_user.clone(), rpc_pass.to_string()),
                )?;

                let broadcast_txid: bitcoin::Txid =
                    rpc_client.call("sendrawtransaction", &[serde_json::json!(tx_hex)])?;

                if !cli.plain {
                    info!("✅ Burn transaction broadcast successfully!");
                    info!("📍 Transaction ID: {}", broadcast_txid);
                    info!("🔥 Burned: {} sats", burn_amount);
                    info!("🎯 Chain ID: {}", chain_id);
                    info!("📫 ETH Address: 0x{}", eth_addr);
                }
            } else {
                // Use Electrum for other networks
                use bdk_electrum::electrum_client;
                use bdk_electrum::electrum_client::ElectrumApi;

                let electrum_url = electrum_url.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("--electrum-url required for network: {}", network_str)
                })?;

                let electrum_client = electrum_client::Client::new(&electrum_url)?;
                let broadcast_txid = electrum_client.transaction_broadcast_raw(&tx_bytes)?;

                if !cli.plain {
                    info!("✅ Burn transaction broadcast successfully!");
                    info!("📍 Transaction ID: {}", broadcast_txid);
                    info!("🔥 Burned: {} sats", burn_amount);
                    info!("🎯 Chain ID: {}", chain_id);
                    info!("📫 ETH Address: 0x{}", eth_addr);
                }
            }

            // Mark the transaction as broadcast in the wallet
            if !cli.plain {
                info!("📝 Updating wallet with broadcast transaction...");
            }

            // Apply the transaction as unconfirmed to mark inputs as spent
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // apply_unconfirmed_txs expects (Transaction, u64) where u64 is last_seen timestamp
            wallet.apply_unconfirmed_txs([(tx.clone(), now)]);

            // Persist wallet state to save the updated UTXO state
            wallet.persist(&mut conn)?;

            if cli.plain {
                println!("{}", txid);
            } else {
                info!("✅ Wallet updated - inputs marked as spent");
                info!("🪙 Core Lane will automatically mint {} tokens to 0x{} when this transaction is confirmed!", burn_amount, eth_addr);
            }
        }

        Commands::SendTransaction {
            raw_tx_hex,
            network: network_str,
            mnemonic,
            mnemonic_file,
            rpc_url,
            rpc_user,
            rpc_password,
            electrum_url,
        } => {
            // Resolve mnemonic from various sources
            let mnemonic_str = resolve_mnemonic(mnemonic.as_deref(), mnemonic_file.as_deref())?;

            // Parse network
            let network = match network_str.as_str() {
                "bitcoin" | "mainnet" => bitcoincore_rpc::bitcoin::Network::Bitcoin,
                "testnet" => bitcoincore_rpc::bitcoin::Network::Testnet,
                "signet" => bitcoincore_rpc::bitcoin::Network::Signet,
                "regtest" => bitcoincore_rpc::bitcoin::Network::Regtest,
                _ => return Err(anyhow::anyhow!("Invalid network: {}", network_str)),
            };

            // Create Bitcoin RPC clients (only used for regtest)
            let rpc_pass = rpc_password
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("bitcoin123");
            let read_client = bitcoincore_rpc::Client::new(
                rpc_url,
                Auth::UserPass(rpc_user.clone(), rpc_pass.to_string()),
            )?;
            let write_client = bitcoincore_rpc::Client::new(
                rpc_url,
                Auth::UserPass(rpc_user.clone(), rpc_pass.to_string()),
            )?;

            let node = CoreLaneNode::new(read_client, write_client, cli.data_dir.clone());
            node.send_transaction_to_da(
                raw_tx_hex,
                &mnemonic_str,
                network,
                network_str,
                electrum_url.as_deref(),
                &cli.data_dir,
            )
            .await?;
        }

        Commands::ConstructExitIntent {
            bitcoin_address,
            amount,
            max_fee,
            expire_by,
        } => {
            info!("🔧 Constructing exit intent data for bitcoin withdrawal...");
            info!("   Bitcoin Address: {}", bitcoin_address);
            info!("   Amount: {} sats", amount);
            info!("   Max Fee: {} sats", max_fee);
            info!("   Expire By: {}", expire_by);

            // Create the intent data
            let intent_data = create_anchor_bitcoin_fill_intent(
                bitcoin_address,
                U256::from(*amount),
                U256::from(*max_fee),
                *expire_by,
            )?;

            // Convert to CBOR (this is the serialized intent data)
            let intent_cbor = intent_data.to_cbor()?;
            let intent_data_hex = format!("0x{}", hex::encode(&intent_cbor));

            info!("✅ Exit intent data constructed successfully!");
            info!(
                "📝 Intent Data (CBOR, {} bytes): {}",
                intent_cbor.len(),
                intent_data_hex
            );
            info!("");
            info!("💡 To use this exit intent:");
            info!("   1. Send a transaction to the IntentSystem contract");
            info!(
                "   2. Call intent({}, nonce) with the intent data above",
                intent_data_hex
            );
            info!(
                "   3. The intent will be submitted for bitcoin withdrawal (exit from Core Lane)"
            );
        }

        Commands::BitcoinCache {
            host,
            port,
            cache_dir,
            bitcoin_rpc_url,
            bitcoin_rpc_user,
            bitcoin_rpc_password,
            no_rpc_auth,
            block_archive,
            starting_block_count,
        } => {
            info!("🚀 Starting Bitcoin Cache RPC server...");
            info!("📁 Cache directory: {}", cache_dir);
            info!("🔗 Bitcoin RPC: {}", bitcoin_rpc_url);
            info!("📦 Block archive: {}", block_archive);
            if let Some(start) = starting_block_count {
                info!("🎯 Starting block for prefetch: {}", start);
            }

            // Use HTTP client for public RPCs (no auth), bitcoincore-rpc for authenticated ones
            let cache_server = if *no_rpc_auth {
                info!("🔓 Using HTTP client (no authentication)");

                // Health check with HTTP client
                info!("🏥 Testing Bitcoin RPC connection...");
                let test_client = reqwest::Client::builder()
                    .connect_timeout(std::time::Duration::from_secs(5))
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to build health check HTTP client: {}", e)
                    })?;
                let test_body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getblockcount",
                    "params": []
                });

                match test_client
                    .post(bitcoin_rpc_url)
                    .json(&test_body)
                    .send()
                    .await
                {
                    Ok(response) => {
                        if response.status().is_success() {
                            match response.json::<serde_json::Value>().await {
                                Ok(json) => {
                                    if let Some(result) = json.get("result") {
                                        if let Some(count) = result.as_u64() {
                                            info!("✅ Bitcoin RPC connection successful! Current block height: {}", count);
                                        }
                                    } else if let Some(error) = json.get("error") {
                                        if !error.is_null() {
                                            error!("❌ RPC error: {}", error);
                                            return Err(anyhow::anyhow!(
                                                "Bitcoin RPC returned error: {}",
                                                error
                                            ));
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("❌ Failed to parse response: {}", e);
                                    return Err(anyhow::anyhow!(
                                        "Invalid JSON response from Bitcoin RPC: {}",
                                        e
                                    ));
                                }
                            }
                        } else {
                            error!("❌ HTTP error: {}", response.status());
                            return Err(anyhow::anyhow!(
                                "Bitcoin RPC returned HTTP {}",
                                response.status()
                            ));
                        }
                    }
                    Err(e) => {
                        error!("❌ Failed to connect to Bitcoin RPC: {}", e);
                        return Err(anyhow::anyhow!(
                            "Bitcoin RPC health check failed: {}. Please verify:\n\
                             - URL is correct: {}\n\
                             - Bitcoin node is running and accessible",
                            e,
                            bitcoin_rpc_url
                        ));
                    }
                }

                BitcoinCacheRpcServer::new_with_http(
                    cache_dir,
                    bitcoin_rpc_url.to_string(),
                    block_archive.to_string(),
                    *starting_block_count,
                )?
            } else {
                info!(
                    "🔐 Using bitcoincore-rpc client (user: {})",
                    bitcoin_rpc_user
                );

                let bitcoin_client = bitcoincore_rpc::Client::new(
                    bitcoin_rpc_url,
                    Auth::UserPass(
                        bitcoin_rpc_user.to_string(),
                        bitcoin_rpc_password.to_string(),
                    ),
                )?;

                // Health check with bitcoincore-rpc
                info!("🏥 Testing Bitcoin RPC connection...");
                match bitcoin_client.get_block_count() {
                    Ok(count) => {
                        info!(
                            "✅ Bitcoin RPC connection successful! Current block height: {}",
                            count
                        );
                    }
                    Err(e) => {
                        error!("❌ Failed to connect to Bitcoin RPC: {}", e);
                        return Err(anyhow::anyhow!(
                            "Bitcoin RPC health check failed: {}. Please verify:\n\
                             - URL is correct: {}\n\
                             - Authentication is configured properly\n\
                             - Bitcoin node is running and accessible",
                            e,
                            bitcoin_rpc_url
                        ));
                    }
                }

                BitcoinCacheRpcServer::new(
                    cache_dir,
                    bitcoin_client,
                    block_archive.to_string(),
                    *starting_block_count,
                )?
            };

            let app = cache_server.router();

            let addr = format!("{}:{}", host, port);
            info!("📡 Bitcoin Cache RPC listening on http://{}", addr);
            info!("📋 Available methods: getblockcount, getblockhash, getblock (verbosity=0 only), getblockchaininfo");

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
        }

        Commands::CreateWallet {
            network,
            mnemonic: mnemonic_opt,
            mnemonic_only,
        } => {
            use bdk_wallet::bitcoin::Network as BdkNetwork;
            use bdk_wallet::keys::{
                bip39::{Language, Mnemonic, WordCount},
                DerivableKey, ExtendedKey, GeneratableKey, GeneratedKey,
            };
            use bdk_wallet::rusqlite::Connection;
            use bdk_wallet::{KeychainKind, Wallet};

            // Parse network
            let bdk_network = match network.as_str() {
                "bitcoin" | "mainnet" => BdkNetwork::Bitcoin,
                "testnet" => BdkNetwork::Testnet,
                "signet" => BdkNetwork::Signet,
                "regtest" => BdkNetwork::Regtest,
                _ => return Err(anyhow::anyhow!("Invalid network: {}", network)),
            };

            // Either use provided mnemonic or generate a new one
            let (mnemonic_words, is_restored) = if let Some(mnemonic_str) = mnemonic_opt {
                if !cli.plain {
                    info!(
                        "🔐 Restoring BDK wallet from mnemonic for network: {}",
                        network
                    );
                }
                (mnemonic_str.clone(), true)
            } else {
                if !cli.plain {
                    info!("🔐 Creating new BDK wallet for network: {}", network);
                }
                // Generate new mnemonic (12 words)
                let mnemonic: GeneratedKey<_, bdk_wallet::miniscript::Segwitv0> =
                    Mnemonic::generate((WordCount::Words12, Language::English))
                        .map_err(|_| anyhow::anyhow!("Failed to generate mnemonic"))?;
                (mnemonic.to_string(), false)
            };

            if !is_restored && !cli.plain {
                println!("\n🔑 WALLET MNEMONIC (SAVE THIS SECURELY!)");
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("{}", mnemonic_words);
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            } else if is_restored && !cli.plain {
                info!("📝 Using provided mnemonic to restore wallet");
            }

            // Parse mnemonic string
            let mnemonic = Mnemonic::parse(&mnemonic_words)
                .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {}", e))?;

            // Derive extended key from mnemonic
            let xkey: ExtendedKey = mnemonic
                .into_extended_key()
                .map_err(|_| anyhow::anyhow!("Failed to derive extended key"))?;
            let xprv = xkey
                .into_xprv(bdk_network)
                .ok_or_else(|| anyhow::anyhow!("Failed to get xprv"))?;

            // If mnemonic-only mode, just output the mnemonic and exit
            if *mnemonic_only {
                if cli.plain {
                    // Plain mode: just print mnemonic
                    println!("{}", mnemonic_words);
                } else {
                    // Pretty mode: show mnemonic with message
                    if !is_restored {
                        println!("✅ Mnemonic generated (no database created)");
                    } else {
                        println!("✅ Mnemonic validated (no database created)");
                    }
                    println!(
                        "💡 To create wallet database later: create-wallet --network {} --mnemonic \"{}\"",
                        network, mnemonic_words
                    );
                }
                return Ok(());
            }

            // Create descriptor from xprv (using BIP84 path for native segwit)
            // Simple format without key origin - BDK will derive keys directly
            let external_descriptor = format!("wpkh({}/0/*)", xprv);
            let internal_descriptor = format!("wpkh({}/1/*)", xprv);

            // Ensure data directory exists
            std::fs::create_dir_all(&cli.data_dir)?;

            // Create wallet database file
            let db_path = wallet_db_path(&cli.data_dir, network);
            if !cli.plain {
                info!("💾 Creating wallet database: {}", db_path);
            }

            let mut conn = Connection::open(&db_path)
                .map_err(|e| anyhow::anyhow!("Failed to create database: {}", e))?;

            let _wallet = Wallet::create(external_descriptor, internal_descriptor)
                .network(bdk_network)
                .create_wallet(&mut conn)
                .map_err(|e| anyhow::anyhow!("Failed to create wallet: {}", e))?;

            // Output formatting based on plain flag
            if cli.plain {
                // Plain mode: just print mnemonic for new wallets, nothing for restored
                if !is_restored {
                    println!("{}", mnemonic_words);
                }
            } else {
                // Pretty mode with emojis
                if is_restored {
                    println!("✅ Wallet restored successfully!");
                } else {
                    println!("✅ Wallet created successfully!");
                }
                println!("📁 Database file: {}", db_path);

                if !is_restored {
                    println!("\n⚠️  IMPORTANT: Save your mnemonic phrase securely!");
                    println!("   Without it, you cannot recover your wallet.\n");
                }
            }
        }

        Commands::GetAddress { network } => {
            use bdk_wallet::rusqlite::Connection;
            use bdk_wallet::{KeychainKind, Wallet};

            let db_path = wallet_db_path(&cli.data_dir, network);

            if !std::path::Path::new(&db_path).exists() {
                return Err(anyhow::anyhow!(
                    "Wallet database not found: {}\nCreate a wallet first with: create-wallet --network {} --data-dir {}",
                    db_path,
                    network,
                    cli.data_dir
                ));
            }

            if !cli.plain {
                info!("📂 Loading wallet from: {}", db_path);
            }

            let mut conn = Connection::open(&db_path)
                .map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))?;

            let mut wallet = Wallet::load()
                .extract_keys() // Extract private keys from descriptor
                .load_wallet(&mut conn)
                .map_err(|e| anyhow::anyhow!("Failed to load wallet: {}", e))?
                .ok_or_else(|| anyhow::anyhow!("No wallet found in database"))?;

            // Get next unused address
            let address = wallet.reveal_next_address(KeychainKind::External);

            // Persist the wallet state to save the updated address index
            wallet
                .persist(&mut conn)
                .map_err(|e| anyhow::anyhow!("Failed to persist wallet: {}", e))?;

            if cli.plain {
                // Plain mode: just print the address
                println!("{}", address.address);
            } else {
                // Pretty mode with emojis
                println!("📍 Receive address: {}", address.address);
                println!("🔢 Address index: {}", address.index);
            }
        }
    }

    Ok(())
}
