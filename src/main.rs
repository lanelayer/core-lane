use crate::intents::IntentSystem;
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::TxKind;
use alloy_primitives::{hex, Address, Bytes, B256, U256};
use alloy_provider::Provider;
use alloy_provider::ProviderBuilder;
use alloy_rpc_types::TransactionRequest;
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use anyhow::Result;
use bitcoin::Network;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use clap::{Parser, Subcommand};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{self, json};
use std::collections::HashMap;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MetaState {
    eip1559_fee_manager: eip1559::Eip1559FeeManager,
    total_burned_amount: U256,
    sequencer_address: Address,
}

impl MetaState {
    /// Get the sequencer address for a given Core Lane block number
    /// In the future, this could support sequencer rotation based on block height
    #[allow(dead_code)]
    pub fn get_sequencer_address_for_block(&self, _block_number: u64) -> Address {
        // Currently returns a single sequencer address
        // Future enhancement: could implement rotation logic based on block_number
        self.sequencer_address
    }
}

/// Version byte for tip file format. Enables schema evolution; change when ChainTip/CoreLaneBlock layout changes.
const TIP_FORMAT_VERSION: u8 = 1;

/// Persisted chain tip for restore-from-disk on startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainTip {
    core_lane_block_number: u64,
    last_processed_bitcoin_height: u64,
    bitcoin_block_hash: B256,
    core_lane_block: CoreLaneBlock,
}

/// Per-block chain index entry for full restore (blocks 1..n; genesis is built from code).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainIndexEntry {
    core_lane_block: CoreLaneBlock,
    bitcoin_height: u64,
    bitcoin_block_hash: B256,
}

// Import modules from the library
use core_lane::{
    bitcoin_block, bitcoin_cache_rpc, block, cmio, intents, state, taproot_da, transaction,
};

// RPC module and EIP-1559 are specific to the binary (depends on CoreLaneState)
mod derived;
mod eip1559;
mod rpc;

// Default sequencer address that gets priority for bundle processing
// This is the first address from the default Hardhat/Anvil test accounts
// Used for initialization and testing
const DEFAULT_SEQUENCER_ADDRESS: Address = Address::new([
    0xf3, 0x9F, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xF6, 0xF4, 0xce, 0x6a, 0xB8, 0x82, 0x72, 0x79, 0xcf,
    0xFF, 0xb9, 0x22, 0x66,
]);

#[cfg(test)]
mod tests;

use alloy_consensus::TxEnvelope;
use bitcoin_cache_rpc::{BitcoinCacheRpcServer, S3Config};
use cmio::CmioMessage;
use intents::create_anchor_bitcoin_fill_intent;
use rpc::RpcServer;
use state::{StateManager, StoredTransaction, TransactionReceipt};
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

/// Helper function to create wallet database from mnemonic
/// Handles network parsing, mnemonic validation, key derivation, descriptor creation, and wallet creation
/// If electrum_url is provided for non-regtest networks, performs an initial full scan
fn create_wallet_from_mnemonic(
    data_dir: &str,
    network_str: &str,
    mnemonic_str: String,
    plain_mode: bool,
    electrum_url: Option<&str>,
) -> Result<()> {
    use bdk_wallet::bitcoin::Network as BdkNetwork;
    use bdk_wallet::keys::{bip39::Mnemonic, DerivableKey, ExtendedKey};
    use bdk_wallet::rusqlite::Connection;
    use bdk_wallet::Wallet;

    // Parse network (include "mainnet" mapping)
    let bdk_network = match network_str {
        "bitcoin" | "mainnet" => BdkNetwork::Bitcoin,
        "testnet" => BdkNetwork::Testnet,
        "testnet4" => BdkNetwork::Testnet4,
        "signet" => BdkNetwork::Signet,
        "regtest" => BdkNetwork::Regtest,
        _ => return Err(anyhow::anyhow!("Invalid network: {}", network_str)),
    };

    // Parse and validate mnemonic
    let mnemonic =
        Mnemonic::parse(mnemonic_str).map_err(|e| anyhow::anyhow!("Invalid mnemonic: {}", e))?;

    // Derive extended key and xprv
    let xkey: ExtendedKey = mnemonic
        .into_extended_key()
        .map_err(|_| anyhow::anyhow!("Failed to derive extended key"))?;
    let xprv = xkey
        .into_xprv(bdk_network)
        .ok_or_else(|| anyhow::anyhow!("Failed to get xprv"))?;

    // Build external and internal descriptors
    let external_descriptor = format!("wpkh({}/0/*)", xprv);
    let internal_descriptor = format!("wpkh({}/1/*)", xprv);

    // Ensure data directory exists
    std::fs::create_dir_all(data_dir)?;

    // Get wallet database path and create wallet
    let db_path = wallet_db_path(data_dir, network_str);
    let mut conn = Connection::open(&db_path)
        .map_err(|e| anyhow::anyhow!("Failed to create database: {}", e))?;

    let mut wallet = Wallet::create(external_descriptor, internal_descriptor)
        .network(bdk_network)
        .create_wallet(&mut conn)
        .map_err(|e| anyhow::anyhow!("Failed to create wallet: {}", e))?;

    // Log success when not in plain mode
    if !plain_mode {
        info!("✅ Wallet database created successfully");
    }

    // Perform initial soft sync with Electrum if URL is provided and network is not regtest
    if let Some(electrum_url_str) = electrum_url {
        if network_str != "regtest" {
            if !plain_mode {
                info!(
                    "🔄 Performing initial sync with Electrum: {}",
                    electrum_url_str
                );
            }

            use bdk_electrum::{electrum_client, BdkElectrumClient};

            let electrum_client = electrum_client::Client::new(electrum_url_str)
                .map_err(|e| anyhow::anyhow!("Failed to connect to Electrum server: {}", e))?;
            let electrum = BdkElectrumClient::new(electrum_client);

            // Use soft sync to sync revealed addresses (for new wallets, this will be empty)
            let request = wallet.start_sync_with_revealed_spks().build();
            let response = electrum
                .sync(request, 5, false)
                .map_err(|e| anyhow::anyhow!("Failed to perform sync: {}", e))?;

            wallet
                .apply_update(response)
                .map_err(|e| anyhow::anyhow!("Failed to apply sync results: {}", e))?;
            wallet
                .persist(&mut conn)
                .map_err(|e| anyhow::anyhow!("Failed to persist wallet: {}", e))?;

            if !plain_mode {
                info!("✅ Initial sync completed");
            }
        }
    }

    Ok(())
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
    StoreBlob {
        #[arg(long, default_value = "http://127.0.0.1:8546")]
        rpc_url: String,
        #[arg(long, default_value = "0x0000000000000000000000000000000000000045")]
        contract: String,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        file: String,
        #[arg(long)]
        max_fee_per_gas: Option<u128>,
        #[arg(long, default_value = "0")]
        max_priority_fee_per_gas: u128,
    },

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
        /// Mnemonic phrase for signing (not recommended - visible in process list)
        #[arg(long)]
        mnemonic: Option<String>,
        /// Path to file containing mnemonic phrase (recommended, more secure)
        #[arg(long)]
        mnemonic_file: Option<String>,
        /// Electrum server URL (for mainnet/testnet/testnet4/signet)
        #[arg(long)]
        electrum_url: Option<String>,
        /// Sequencer RPC URL - if set, eth_sendRawTransaction will forward transactions to this endpoint
        #[arg(long)]
        sequencer_rpc_url: Option<String>,
        /// Sequencer address that receives priority fees (hex format, e.g., 0x...)
        /// If not provided, defaults to a well-known test address (insecure for production)
        #[arg(long)]
        sequencer_address: Option<String>,
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
        /// Electrum server URL (for mainnet/testnet/testnet4/signet)
        #[arg(long)]
        electrum_url: Option<String>,
    },
    SendTransaction {
        #[arg(long)]
        raw_tx_hex: String,
        /// Network for the transaction (bitcoin, testnet, testnet4, signet, regtest)
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
        /// Electrum server URL (for mainnet/testnet/testnet4/signet)
        #[arg(long)]
        electrum_url: Option<String>,
    },
    SendBundle {
        /// Raw transaction hex strings (comma-separated or one per --raw-tx-hex flag)
        #[arg(long)]
        raw_tx_hex: Vec<String>,
        /// Network for the transaction (bitcoin, testnet, testnet4, signet, regtest)
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
        /// Electrum server URL (for mainnet/testnet/testnet4/signet)
        #[arg(long)]
        electrum_url: Option<String>,
        /// Sequencer payment recipient address (hex format)
        #[arg(long)]
        sequencer_payment_recipient: Option<String>,
        /// Bundle marker: "head" or "standard" (default: standard)
        #[arg(long, default_value = "standard")]
        marker: String,
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
        #[arg(long, default_value = "false")]
        disable_archive_fetch: bool,
        #[arg(long, default_value = "")]
        s3_bucket: String,
        #[arg(long, default_value = "us-east-1")]
        s3_region: String,
        #[arg(long, default_value = "")]
        s3_endpoint: String,
    },
    CreateWallet {
        /// Network to create wallet for (bitcoin, testnet, testnet4, signet, regtest)
        #[arg(long, default_value = "regtest")]
        network: String,
        /// Optional mnemonic phrase to restore wallet (12 or 24 words)
        #[arg(long)]
        mnemonic: Option<String>,
        /// Only generate/output mnemonic, don't create database file
        #[arg(long)]
        mnemonic_only: bool,
        /// Electrum server URL (for mainnet/testnet/testnet4/signet - performs initial full scan)
        #[arg(long)]
        electrum_url: Option<String>,
    },
    GetAddress {
        /// Network of the wallet to load (bitcoin, testnet, testnet4, signet, regtest)
        #[arg(long, default_value = "regtest")]
        network: String,
        /// Mnemonic phrase for signing (not recommended - visible in process list)
        #[arg(long)]
        mnemonic: Option<String>,
        /// Path to file containing mnemonic phrase (recommended, more secure)
        #[arg(long)]
        mnemonic_file: Option<String>,
    },
    GetBitcoinBalance {
        /// Network of the wallet to check (bitcoin, testnet, testnet4, signet, regtest)
        #[arg(long, default_value = "regtest")]
        network: String,
        /// Mnemonic phrase for signing (not recommended - visible in process list)
        #[arg(long)]
        mnemonic: Option<String>,
        /// Path to file containing mnemonic phrase (recommended, more secure)
        #[arg(long)]
        mnemonic_file: Option<String>,
        /// Electrum server URL (for mainnet/testnet/testnet4/signet)
        #[arg(long)]
        electrum_url: Option<String>,
        /// Bitcoin RPC URL (for regtest)
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        rpc_url: String,
        /// Bitcoin RPC username (for regtest)
        #[arg(long, default_value = "")]
        rpc_user: String,
        /// Bitcoin RPC password (for regtest)
        #[arg(long, default_value = "")]
        rpc_password: String,
    },
    DerivedStart {
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        core_rpc_url: String,
        #[arg(long, default_value_t = 1281453634)]
        chain_id: u32,
        #[arg(long)]
        start_block: Option<u64>,
        #[arg(long)]
        derived_da_address: String,
        #[arg(long, default_value = "127.0.0.1")]
        http_host: String,
        #[arg(long, default_value = "8545")]
        http_port: u16,
        /// Sequencer RPC URL - if set, eth_sendRawTransaction will forward transactions to this endpoint
        #[arg(long)]
        sequencer_rpc_url: Option<String>,
        /// Sequencer address that receives priority fees (hex format, e.g., 0x...)
        /// If not provided, defaults to a well-known test address (insecure for production)
        #[arg(long)]
        sequencer_address: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(skip)]
    block_origin: Option<CoreLaneBlockParsed>,
}

impl CoreLaneBlock {
    fn new(
        number: u64,
        parent_hash: B256,
        timestamp: u64,
        block_origin: Option<CoreLaneBlockParsed>,
        gas_limit: U256,
        base_fee_per_gas: U256,
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
            gas_limit, // EIP-1559 maximum block gas limit
            base_fee_per_gas: Some(base_fee_per_gas),
            difficulty: U256::from(1u64),
            total_difficulty: U256::from(number),
            extra_data,
            nonce: 0,
            miner: Address::ZERO, // No mining in Core Lane
            state_root: B256::default(),
            receipts_root: B256::default(),
            transactions_root: B256::default(),
            logs_bloom: vec![0u8; 256],
            block_origin,
        }
    }

    fn genesis(max_gas_limit: U256, initial_base_fee: U256) -> Self {
        let mut block = Self::new(
            0,
            B256::default(), // Genesis has no parent
            1704067200,      // January 1, 2024 00:00:00 UTC
            None,
            max_gas_limit,
            initial_base_fee,
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

    fn to_json(&self, _full: bool) -> serde_json::Value {
        let mut block_json = json!({
            "number": format!("0x{:x}", self.number),
            "hash": format!("0x{:x}", self.hash),
            "parentHash": format!("0x{:x}", self.parent_hash),
            "timestamp": format!("0x{:x}", self.timestamp),
            "gasUsed": format!("0x{:x}", self.gas_used),
            "gasLimit": format!("0x{:x}", self.gas_limit),
            "baseFeePerGas": match self.base_fee_per_gas {
                Some(fee) => serde_json::Value::String(format!("0x{:x}", fee)),
                None => serde_json::Value::Null,
            },
            "difficulty": format!("0x{:x}", self.difficulty),
            "totalDifficulty": format!("0x{:x}", self.total_difficulty),
            "extraData": format!("0x{}", hex::encode(&self.extra_data)),
            "nonce": format!("0x{:016x}", self.nonce),
            "miner": format!("0x{:x}", self.miner),
            "stateRoot": format!("0x{:x}", self.state_root),
            "receiptsRoot": format!("0x{:x}", self.receipts_root),
            "transactionsRoot": format!("0x{:x}", self.transactions_root),
            "logsBloom": format!("0x{}", hex::encode(&self.logs_bloom)),
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000", // Not used in non-PoW chains
            "sha3Uncles": "0x0000000000000000000000000000000000000000000000000000000000000000", // Hash of empty array (32 zero bytes)
            "size": format!("0x{:x}", self.transaction_count * 32), // Approximate size
            "uncles": [],
        });

        // Always include transaction hashes (full vs simple mode not yet differentiated)
        block_json["transactions"] = json!(self.transactions);

        block_json
    }
}

#[derive(Debug, Clone)]
struct CoreLaneState {
    account_manager: StateManager,
    last_processed_bitcoin_height: Option<u64>,
    blocks: HashMap<u64, CoreLaneBlock>, // Block number -> Block
    block_hashes: HashMap<B256, u64>,    // Block hash -> Block number
    bitcoin_height_to_hash: HashMap<u64, B256>, // Bitcoin height -> Bitcoin block hash (for reorg detection)
    bitcoin_height_to_core_block: HashMap<u64, u64>, // Bitcoin height -> Core Lane block number
    current_block: Option<CoreLaneBlock>,       // Current block being built
    genesis_block: CoreLaneBlock,
    bitcoin_client_read: Option<Arc<Client>>, // Client for reading blockchain data
    #[allow(dead_code)]
    bitcoin_client_write: Option<Arc<Client>>, // Client for writing/wallet operations
    eip1559_fee_manager: eip1559::Eip1559FeeManager, // EIP-1559 fee management
    sequencer_address: Address,               // Address that receives priority fees
    total_burned_amount: U256,                // Total amount burned from base fees
    bitcoin_network: bitcoin::Network,        // Bitcoin network (mainnet, testnet, regtest, etc.)
    // Metrics tracking
    reorgs_detected: u64, // Counter for blockchain reorganizations detected
    total_sequencer_payments: U256, // Cumulative priority fees paid to sequencers (in wei)
    last_block_processing_time_ms: Option<u64>, // Last block processing time in milliseconds
}

impl CoreLaneState {
    #[allow(dead_code)]
    pub fn bitcoin_client_read(&self) -> Option<Arc<Client>> {
        self.bitcoin_client_read.clone()
    }

    #[allow(dead_code)]
    pub fn bitcoin_client_write(&self) -> Option<Arc<Client>> {
        self.bitcoin_client_write.clone()
    }

    /// Rollback state to the specified Core Lane block number
    /// This loads the state from disk for the target block and updates tracking maps
    pub fn rollback_to_block(&mut self, target_block: u64, data_dir: &str) -> Result<()> {
        info!("🔄 Rolling back state to Core Lane block {}", target_block);

        // Load the state from disk for the target block
        let loaded_state = {
            use std::fs;
            use std::path::Path;

            let blocks_dir = Path::new(data_dir).join("blocks");
            let block_file = blocks_dir.join(format!("{}", target_block));

            info!("💾 Looking for state file: {}", block_file.display());
            if !block_file.exists() {
                return Err(anyhow::anyhow!(
                    "State file not found for block {}",
                    target_block
                ));
            }

            info!("💾 Reading state file for block {}", target_block);
            let serialized_state = fs::read(&block_file)?;
            info!(
                "💾 Deserializing state for block {} ({} bytes)",
                target_block,
                serialized_state.len()
            );

            match StateManager::borsh_deserialize(&serialized_state) {
                Ok(state) => {
                    info!("✅ Successfully loaded state for block {}", target_block);
                    state
                }
                Err(e) => {
                    error!(
                        "❌ Failed to deserialize state for block {}: {}",
                        target_block, e
                    );
                    return Err(e);
                }
            }
        };

        // Replace the current state with the loaded state
        info!("🔄 Replacing current state with loaded state");
        self.account_manager = loaded_state;

        // Resolve the Bitcoin height that corresponds to target_block
        // We need this because last_processed_bitcoin_height is a Bitcoin height, not a Core Lane block number
        let bitcoin_height = self
            .bitcoin_height_to_core_block
            .iter()
            .find(|(_, &core_block)| core_block == target_block)
            .map(|(&btc_height, _)| btc_height)
            .ok_or_else(|| {
                anyhow::anyhow!("No Bitcoin height maps to Core Lane block {}", target_block)
            })?;
        info!(
            "🔍 Resolved Core Lane block {} to Bitcoin height {}",
            target_block, bitcoin_height
        );

        // Remove all blocks after target_block
        let blocks_before = self.blocks.len();
        self.blocks
            .retain(|&block_num, _| block_num <= target_block);
        let blocks_after = self.blocks.len();
        info!(
            "🗑️  Removed {} blocks (kept {} blocks)",
            blocks_before - blocks_after,
            blocks_after
        );

        // Remove all block hashes after target_block
        let hashes_before = self.block_hashes.len();
        self.block_hashes
            .retain(|_, block_num| *block_num <= target_block);
        let hashes_after = self.block_hashes.len();
        info!(
            "🗑️  Removed {} block hashes (kept {} hashes)",
            hashes_before - hashes_after,
            hashes_after
        );

        // Remove bitcoin_height_to_core_block entries where Core Lane block > target_block
        // (filter based on VALUES, not keys)
        let btc_before = self.bitcoin_height_to_core_block.len();
        self.bitcoin_height_to_core_block
            .retain(|_, core_block| *core_block <= target_block);
        let btc_after = self.bitcoin_height_to_core_block.len();
        info!(
            "🗑️  Removed {} bitcoin height mappings (kept {} mappings)",
            btc_before - btc_after,
            btc_after
        );

        // Remove bitcoin_height_to_hash entries for Bitcoin heights that no longer have
        // corresponding Core Lane blocks (filter based on whether the Bitcoin height
        // still maps to a valid Core Lane block)
        let heights_before = self.bitcoin_height_to_hash.len();
        self.bitcoin_height_to_hash.retain(|btc_height, _| {
            self.bitcoin_height_to_core_block
                .get(btc_height)
                .is_some_and(|&core_block| core_block <= target_block)
        });
        let heights_after = self.bitcoin_height_to_hash.len();
        info!(
            "🗑️  Removed {} height mappings (kept {} mappings)",
            heights_before - heights_after,
            heights_after
        );

        // Update last_processed_bitcoin_height to the Bitcoin height (not the Core Lane block number)
        self.last_processed_bitcoin_height = Some(bitcoin_height);

        info!(
            "✅ Successfully rolled back to Core Lane block {} (Bitcoin height {})",
            target_block, bitcoin_height
        );
        Ok(())
    }
}

impl transaction::ProcessingContext for CoreLaneState {
    fn state_manager(&self) -> &state::StateManager {
        &self.account_manager
    }

    fn state_manager_mut(&mut self) -> &mut state::StateManager {
        &mut self.account_manager
    }

    fn bitcoin_client_read(&self) -> Option<Arc<Client>> {
        self.bitcoin_client_read.clone()
    }

    fn bitcoin_network(&self) -> bitcoin::Network {
        self.bitcoin_network
    }

    fn handle_cmio_query(
        &mut self,
        message: CmioMessage,
        current_intent_id: Option<B256>,
    ) -> Option<CmioMessage> {
        // Use the shared CMIO handler from the cmio module
        cmio::handle_cmio_query(message, &self.account_manager, current_intent_id)
    }
}

struct CoreLaneNode {
    bitcoin_client_read: Option<Arc<Client>>,
    bitcoin_client_write: Option<Arc<Client>>,
    state: Arc<Mutex<CoreLaneState>>,
    data_dir: String,
}

impl CoreLaneNode {
    fn new(
        bitcoin_client_read: Client,
        bitcoin_client_write: Client,
        data_dir: String,
        network: bitcoin::Network,
        sequencer_address: Option<Address>,
    ) -> Self {
        Self::new_with_clients(
            Some(bitcoin_client_read),
            Some(bitcoin_client_write),
            data_dir,
            network,
            sequencer_address,
        )
    }

    fn new_derived(
        data_dir: String,
        network: bitcoin::Network,
        sequencer_address: Option<Address>,
    ) -> Self {
        Self::new_with_clients(None, None, data_dir, network, sequencer_address)
    }

    fn new_with_clients(
        bitcoin_client_read: Option<Client>,
        bitcoin_client_write: Option<Client>,
        data_dir: String,
        network: bitcoin::Network,
        sequencer_address: Option<Address>,
    ) -> Self {
        // Create genesis block with EIP-1559 default configuration (always needed)
        let eip1559_config = eip1559::Eip1559Config::default();
        let genesis_block =
            CoreLaneBlock::genesis(eip1559_config.gas_limit, eip1559_config.initial_base_fee);
        let genesis_hash = genesis_block.hash;

        let bitcoin_client_read = bitcoin_client_read.map(Arc::new);
        let bitcoin_client_write = bitcoin_client_write.map(Arc::new);
        let sequencer_addr = sequencer_address.unwrap_or(DEFAULT_SEQUENCER_ADDRESS);

        // Restore from disk using tip as commit marker (tip is source of truth; do not use max block number).
        let mut state = None;
        let mut restored = false;
        if let Ok(Some(tip)) = Self::read_tip_from_disk_static(&data_dir) {
            let n = tip.core_lane_block_number;
            match (
                Self::load_state_from_disk(&data_dir, n),
                Self::load_metastate_from_disk_static(&data_dir, n),
            ) {
                (Ok(account_manager), Ok(metastate)) => {
                    let mut blocks = HashMap::new();
                    let mut block_hashes = HashMap::new();
                    let mut bitcoin_height_to_hash = HashMap::new();
                    let mut bitcoin_height_to_core_block = HashMap::new();

                    blocks.insert(0, genesis_block.clone());
                    block_hashes.insert(genesis_hash, 0);

                    let full_chain = (1..=n)
                        .map(|i| Self::load_chain_index_entry_static(&data_dir, i))
                        .collect::<Result<Vec<_>>>();

                    match full_chain {
                        Ok(entries) => {
                            for (i, entry) in entries.into_iter().enumerate() {
                                let block_num = (i + 1) as u64;
                                blocks.insert(block_num, entry.core_lane_block.clone());
                                block_hashes.insert(entry.core_lane_block.hash, block_num);
                                bitcoin_height_to_core_block
                                    .insert(entry.bitcoin_height, block_num);
                                bitcoin_height_to_hash
                                    .insert(entry.bitcoin_height, entry.bitcoin_block_hash);
                            }
                            info!(
                                "✅ Restored full chain from disk: Core Lane blocks 0..{} (Bitcoin height {})",
                                n, tip.last_processed_bitcoin_height
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Could not load full chain index ({}), falling back to tip-only restore: {}",
                                n, e
                            );
                            blocks.insert(n, tip.core_lane_block.clone());
                            block_hashes.insert(tip.core_lane_block.hash, n);
                            bitcoin_height_to_core_block
                                .insert(tip.last_processed_bitcoin_height, n);
                            bitcoin_height_to_hash
                                .insert(tip.last_processed_bitcoin_height, tip.bitcoin_block_hash);
                            info!(
                                "✅ Restored state from disk (tip only): Core Lane block {} (Bitcoin height {})",
                                n, tip.last_processed_bitcoin_height
                            );
                        }
                    }
                    state = Some(CoreLaneState {
                        account_manager,
                        last_processed_bitcoin_height: Some(tip.last_processed_bitcoin_height),
                        blocks,
                        block_hashes,
                        bitcoin_height_to_hash,
                        bitcoin_height_to_core_block,
                        current_block: None,
                        genesis_block: genesis_block.clone(),
                        bitcoin_client_read: bitcoin_client_read.clone(),
                        bitcoin_client_write: bitcoin_client_write.clone(),
                        eip1559_fee_manager: metastate.eip1559_fee_manager,
                        sequencer_address: metastate.sequencer_address,
                        total_burned_amount: metastate.total_burned_amount,
                        bitcoin_network: network,
                        reorgs_detected: 0,
                        total_sequencer_payments: U256::ZERO,
                        last_block_processing_time_ms: None,
                    });
                    restored = true;
                }
                (Err(e), _) | (_, Err(e)) => {
                    warn!(
                        "Could not restore from disk (state/metastate missing or invalid for block {}); starting from genesis: {}",
                        n, e
                    );
                }
            }
        } else {
            warn!("Could not restore from disk (tip missing or invalid); starting from genesis");
        }

        let state = state.unwrap_or_else(|| {
            let mut blocks = HashMap::new();
            let mut block_hashes = HashMap::new();
            blocks.insert(0, genesis_block.clone());
            block_hashes.insert(genesis_hash, 0);
            CoreLaneState {
                account_manager: StateManager::new(),
                last_processed_bitcoin_height: None,
                blocks,
                block_hashes,
                bitcoin_height_to_hash: HashMap::new(),
                bitcoin_height_to_core_block: HashMap::new(),
                current_block: None,
                genesis_block: genesis_block.clone(),
                bitcoin_client_read: bitcoin_client_read.clone(),
                bitcoin_client_write: bitcoin_client_write.clone(),
                eip1559_fee_manager: eip1559::Eip1559FeeManager::new(),
                sequencer_address: sequencer_addr,
                total_burned_amount: U256::ZERO,
                bitcoin_network: network,
                reorgs_detected: 0,
                total_sequencer_payments: U256::ZERO,
                last_block_processing_time_ms: None,
            }
        });

        let state = Arc::new(Mutex::new(state));

        // Write genesis state to disk only when we did not restore (so we don't overwrite existing state)
        if !restored {
            if let Err(e) = Self::write_genesis_state(&data_dir, sequencer_addr) {
                error!("Failed to write genesis state to disk: {}", e);
            }
        }

        Self {
            bitcoin_client_read,
            bitcoin_client_write,
            state,
            data_dir,
        }
    }

    async fn create_new_block(
        &self,
        block_origin: Option<CoreLaneBlockParsed>,
    ) -> Result<CoreLaneBlock> {
        let state = self.state.lock().await;

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

        // Get EIP-1559 maximum gas limit and current base fee
        let max_gas_limit = state.eip1559_fee_manager.max_gas_limit();
        let current_base_fee = state.eip1559_fee_manager.current_base_fee();

        // Get bundle count before moving block_origin
        let bundle_count = block_origin
            .as_ref()
            .map(|bo| bo.bundles.len())
            .unwrap_or(0);

        // Create new block with Bitcoin block timestamp and EIP-1559 gas limits
        let mut new_block = CoreLaneBlock::new(
            next_number,
            parent_hash,
            anchor_block_timestamp,
            block_origin,
            max_gas_limit,
            current_base_fee,
        );
        // Calculate hash
        new_block.hash = new_block.calculate_hash();
        // Set as current block
        info!(
            "🆕 Created Core Lane block {} (parent: {}) with timestamp {} (EIP-1559 max gas: {}, base fee: {} gwei) - {} bundle(s)",
            next_number,
            latest_number,
            new_block.timestamp,
            max_gas_limit,
            current_base_fee / U256::from(1_000_000_000u64),
            bundle_count
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

    /// Write the metadata state (MetaState) to disk
    fn write_metastate_to_disk(&self, block_number: u64, metastate: &MetaState) -> Result<()> {
        use std::fs;
        use std::path::Path;

        // Create metastate directory if it doesn't exist
        let metastate_dir = Path::new(&self.data_dir).join("metastate");
        fs::create_dir_all(&metastate_dir)?;

        // Write the metadata state using bincode serialization
        let metastate_file = metastate_dir.join(format!("{}", block_number));
        let serialized_metastate = bincode::serialize(metastate)?;
        fs::write(&metastate_file, serialized_metastate)?;

        info!(
            "💾 Wrote metastate for block {} to {}",
            block_number,
            metastate_file.display()
        );
        Ok(())
    }

    /// Read the metadata state (MetaState) from disk
    fn read_metastate_from_disk(&self, block_number: u64) -> Result<MetaState> {
        use std::fs;
        use std::path::Path;

        let metastate_dir = Path::new(&self.data_dir).join("metastate");
        let metastate_file = metastate_dir.join(format!("{}", block_number));

        if !metastate_file.exists() {
            return Err(anyhow::anyhow!(
                "Metastate file not found for block {}",
                block_number
            ));
        }

        let serialized_metastate = fs::read(&metastate_file)?;
        let metastate = bincode::deserialize(&serialized_metastate)?;

        info!(
            "💾 Read metastate for block {} from {}",
            block_number,
            metastate_file.display()
        );
        Ok(metastate)
    }

    /// Write the chain tip to disk for restore on startup.
    /// Writes to a temp file then atomically renames to avoid corrupted/truncated tip on crash.
    /// Format: [TIP_FORMAT_VERSION][bincode(ChainTip)] for schema evolution.
    fn write_tip_to_disk(&self, tip: &ChainTip) -> Result<()> {
        use std::io::Write;
        use std::path::Path;

        let tip_file = Path::new(&self.data_dir).join("tip");
        let temp_file = tip_file.with_extension("tmp");
        let payload = bincode::serialize(tip)?;
        let mut serialized = vec![TIP_FORMAT_VERSION];
        serialized.extend_from_slice(&payload);
        let mut f = fs::File::create(&temp_file)?;
        f.write_all(&serialized)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&temp_file, &tip_file)?;
        if let Some(parent) = tip_file.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        debug!(
            "💾 Wrote tip for Core Lane block {} to {}",
            tip.core_lane_block_number,
            tip_file.display()
        );
        Ok(())
    }

    /// Write a chain index entry for block_number (atomic write). Used for full restore of blocks 1..n.
    fn write_chain_index_entry(&self, block_number: u64, entry: &ChainIndexEntry) -> Result<()> {
        use std::io::Write;
        use std::path::Path;

        let index_dir = Path::new(&self.data_dir).join("chain_index");
        fs::create_dir_all(&index_dir)?;
        let entry_file = index_dir.join(format!("{}", block_number));
        let temp_file = entry_file.with_extension("tmp");
        let serialized = bincode::serialize(entry)?;
        let mut f = fs::File::create(&temp_file)?;
        f.write_all(&serialized)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&temp_file, &entry_file)?;
        if let Some(parent) = entry_file.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        debug!("💾 Wrote chain index entry for block {}", block_number);
        Ok(())
    }

    /// Read the chain tip from disk (shared impl). Format: [version byte][bincode(ChainTip)].
    fn read_tip_from_disk_impl(data_dir: &str) -> Result<Option<ChainTip>> {
        use std::path::Path;

        let tip_file = Path::new(data_dir).join("tip");
        if !tip_file.exists() {
            return Ok(None);
        }
        let serialized = fs::read(&tip_file)?;
        let tip = if serialized.is_empty() || serialized[0] != TIP_FORMAT_VERSION {
            if !serialized.is_empty() {
                warn!(
                    "Tip file {} has wrong version or is corrupt",
                    tip_file.display()
                );
            }
            None
        } else {
            match bincode::deserialize::<ChainTip>(&serialized[1..]) {
                Ok(t) => Some(t),
                Err(e) => {
                    warn!(
                        "Tip file {} version byte matched but payload failed to deserialize (corrupt tip): {}",
                        tip_file.display(),
                        e
                    );
                    None
                }
            }
        };
        if let Some(ref t) = tip {
            info!(
                "💾 Read tip from {} (Core Lane block {})",
                tip_file.display(),
                t.core_lane_block_number
            );
        }
        Ok(tip)
    }

    /// Read the chain tip from disk, if present.
    #[allow(dead_code)]
    fn read_tip_from_disk(&self) -> Result<Option<ChainTip>> {
        Self::read_tip_from_disk_impl(&self.data_dir)
    }

    /// Return the latest block number that has state on disk (max of blocks/ and metastate/), or None if empty/only genesis.
    #[allow(dead_code)]
    fn find_latest_block_number(data_dir: &str) -> Option<u64> {
        use std::path::Path;

        let mut max_block: Option<u64> = None;
        for dir_name in ["blocks", "metastate"] {
            let dir = Path::new(data_dir).join(dir_name);
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    if let Ok(n) = name.to_string_lossy().parse::<u64>() {
                        max_block = Some(max_block.map_or(n, |m| m.max(n)));
                    }
                }
            }
        }
        max_block
    }

    /// Read the chain tip from disk (static, for use at startup before node exists).
    fn read_tip_from_disk_static(data_dir: &str) -> Result<Option<ChainTip>> {
        Self::read_tip_from_disk_impl(data_dir)
    }

    /// Load chain index entry for a block (static, for use at startup). Returns error if missing.
    fn load_chain_index_entry_static(data_dir: &str, block_number: u64) -> Result<ChainIndexEntry> {
        use std::path::Path;

        let entry_file = Path::new(data_dir)
            .join("chain_index")
            .join(format!("{}", block_number));
        if !entry_file.exists() {
            return Err(anyhow::anyhow!(
                "Chain index entry not found for block {}",
                block_number
            ));
        }
        let serialized = fs::read(&entry_file)?;
        bincode::deserialize(&serialized).map_err(|e| {
            anyhow::anyhow!(
                "Failed to deserialize chain index for block {}: {}",
                block_number,
                e
            )
        })
    }

    /// Load StateManager for a block from disk (static, for use at startup).
    fn load_state_from_disk(data_dir: &str, block_number: u64) -> Result<StateManager> {
        use std::path::Path;

        let blocks_dir = Path::new(data_dir).join("blocks");
        let block_file = blocks_dir.join(format!("{}", block_number));
        if !block_file.exists() {
            return Err(anyhow::anyhow!(
                "State file not found for block {}",
                block_number
            ));
        }
        let serialized_state = fs::read(&block_file)?;
        StateManager::borsh_deserialize(&serialized_state).map_err(|e| {
            anyhow::anyhow!(
                "Failed to deserialize state for block {}: {}",
                block_number,
                e
            )
        })
    }

    /// Load MetaState for a block from disk (static, for use at startup).
    fn load_metastate_from_disk_static(data_dir: &str, block_number: u64) -> Result<MetaState> {
        use std::path::Path;

        let metastate_dir = Path::new(data_dir).join("metastate");
        let metastate_file = metastate_dir.join(format!("{}", block_number));
        if !metastate_file.exists() {
            return Err(anyhow::anyhow!(
                "Metastate file not found for block {}",
                block_number
            ));
        }
        let serialized_metastate = fs::read(&metastate_file)?;
        bincode::deserialize(&serialized_metastate)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize metastate: {}", e))
    }

    /// Write the genesis state (block 0) to disk
    pub fn write_genesis_state(data_dir: &str, sequencer_address: Address) -> Result<()> {
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

        // Create metastate directory if it doesn't exist
        let metastate_dir = Path::new(data_dir).join("metastate");
        fs::create_dir_all(&metastate_dir)?;

        // Create initial metastate for genesis block
        let genesis_metastate = MetaState {
            eip1559_fee_manager: eip1559::Eip1559FeeManager::new(),
            total_burned_amount: U256::ZERO,
            sequencer_address,
        };

        // Write the genesis metastate using bincode serialization
        let metastate_file = metastate_dir.join("0");
        let serialized_metastate = bincode::serialize(&genesis_metastate)?;
        fs::write(&metastate_file, serialized_metastate)?;

        info!(
            "💾 Wrote genesis metastate (block 0) to {}",
            metastate_file.display()
        );
        Ok(())
    }

    async fn finalize_current_block(
        &self,
        transactions: Vec<(StoredTransaction, TransactionReceipt, String)>,
        mut new_block: CoreLaneBlock,
    ) -> Result<CoreLaneBlock> {
        let mut state = self.state.lock().await;

        // Calculate total gas used from transactions
        let total_gas_used = transactions
            .iter()
            .fold(U256::ZERO, |acc, (_tx, receipt, _)| {
                let s = receipt.gas_used.as_str();
                let val = if let Some(hex) = s.strip_prefix("0x") {
                    let bytes = hex::decode(hex).unwrap_or_default();
                    U256::from_be_slice(&bytes)
                } else {
                    U256::from_str(s).unwrap_or(U256::ZERO)
                };
                acc + val
            });

        // EIP-1559: Validate and enforce maximum gas limit
        let max_gas_limit = state.eip1559_fee_manager.max_gas_limit();
        let target_gas_usage = state.eip1559_fee_manager.target_gas_usage();

        // Ensure gas_used doesn't exceed maximum (shouldn't happen due to pre-validation, but double-check)
        let final_gas_used = if total_gas_used > max_gas_limit {
            warn!(
                "⚠️  Block {} gas used ({}) exceeds EIP-1559 maximum gas limit ({}). Clamping to maximum.",
                new_block.number, total_gas_used, max_gas_limit
            );
            max_gas_limit
        } else {
            total_gas_used
        };

        // Update block gas usage
        new_block.gas_used = final_gas_used;
        new_block.gas_limit = max_gas_limit; // Ensure block reflects EIP-1559 maximum gas limit

        // Update base fee for the NEXT block using this block's gas usage
        let next_base_fee = state
            .eip1559_fee_manager
            .update_base_fee(new_block.number + 1, final_gas_used);

        // Log gas usage with EIP-1559 target/max information
        let gas_usage_ratio = if max_gas_limit > U256::ZERO {
            let used_u64 = final_gas_used.to::<u64>() as f64;
            let max_u64 = max_gas_limit.to::<u64>() as f64;
            (used_u64 / max_u64) * 100.0
        } else {
            0.0
        };

        let target_percentage = if target_gas_usage > U256::ZERO {
            let used_u64 = final_gas_used.to::<u64>() as f64;
            let target_u64 = target_gas_usage.to::<u64>() as f64;
            (used_u64 / target_u64) * 100.0
        } else {
            0.0
        };

        info!(
            "⛽ Block {} gas usage: {} / {} (EIP-1559 target: {}, max: {}) - {:.1}% of max, {:.1}% of target (base fee used: {} gwei, next: {} gwei)",
            new_block.number,
            final_gas_used,
            max_gas_limit,
            target_gas_usage,
            max_gas_limit,
            gas_usage_ratio,
            target_percentage,
            new_block.base_fee_per_gas.unwrap_or_default() / U256::from(1_000_000_000u64),
            next_base_fee / U256::from(1_000_000_000u64)
        );

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

        // Transactions and receipts are already in bundle state and applied via apply_changes.

        // Create metastate with current EIP-1559 fee manager, total burned amount, and sequencer address
        let metastate = MetaState {
            eip1559_fee_manager: state.eip1559_fee_manager.clone(),
            total_burned_amount: state.total_burned_amount,
            sequencer_address: state.sequencer_address,
        };

        // Persist metastate to disk
        drop(state);
        if let Err(e) = self.write_metastate_to_disk(new_block.number, &metastate) {
            error!(
                "Failed to write metastate for block {} to disk: {}",
                new_block.number, e
            );
        }

        info!(
            "✅ Finalized Core Lane block {} with {} transactions (base fee used: {} gwei, next: {} gwei)",
            new_block.number,
            new_block.transaction_count,
            new_block.base_fee_per_gas.unwrap_or_default() / U256::from(1_000_000_000u64),
            next_base_fee / U256::from(1_000_000_000u64)
        );

        let finalized_block = new_block.clone();
        {
            let mut state = self.state.lock().await;
            state.current_block = Some(new_block);
        }
        Ok(finalized_block)
    }

    async fn start_block_scanner(&self, start_block: Option<u64>) -> Result<()> {
        info!("Starting Core Lane block scanner...");
        info!("Connected to Bitcoin node successfully");
        info!("Core Lane state initialized");

        // Initialize starting block if provided
        if let Some(block) = start_block {
            let mut state = self.state.lock().await;
            // Set to Some(block - 1) since we'll add 1 when scanning
            // This allows --start_block 0 to actually start at 0
            state.last_processed_bitcoin_height = Some(block.saturating_sub(1));
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

    async fn start_core_lane_scanner(
        &self,
        core_rpc_url: String,
        chain_id: u32,
        start_block: Option<u64>,
        derived_da_address: Address,
    ) -> Result<()> {
        info!(
            "Starting derived Core Lane scanner with RPC URL: {}",
            core_rpc_url
        );
        if let Some(block) = start_block {
            let mut state = self.state.lock().await;
            state.last_processed_bitcoin_height = Some(block.saturating_sub(1));
        }

        loop {
            let latest_block = match derived::fetch_core_block_number(&core_rpc_url).await {
                Ok(height) => height,
                Err(err) => {
                    warn!("Failed to fetch derived block number: {err:?}");
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            let start_height = {
                let state = self.state.lock().await;
                match state.last_processed_bitcoin_height {
                    None => latest_block.saturating_sub(10),
                    Some(height) => height + 1,
                }
            };

            if start_height > latest_block {
                sleep(Duration::from_secs(5)).await;
                continue;
            }

            info!(
                "Scanning derived blocks {} to {}...",
                start_height, latest_block
            );

            for height in start_height..=latest_block {
                match derived::process_core_lane_block(
                    &core_rpc_url,
                    height,
                    chain_id,
                    derived_da_address,
                )
                .await
                {
                    Ok(parsed_block) => {
                        let anchor_hash = parsed_block.anchor_block_hash.clone();
                        match self.process_block(parsed_block).await {
                            Ok(core_lane_block_number) => {
                                if core_lane_block_number == 0 {
                                    info!("Derived backend encountered reorg, restarting scan");
                                    break;
                                }
                                let mut state = self.state.lock().await;
                                state.last_processed_bitcoin_height = Some(height);
                                let _block_hash = if anchor_hash.len() == 32 {
                                    let h = B256::from_slice(&anchor_hash);
                                    state.bitcoin_height_to_hash.insert(height, h);
                                    h
                                } else {
                                    B256::ZERO
                                };
                                state
                                    .bitcoin_height_to_core_block
                                    .insert(height, core_lane_block_number);
                                // Tip already written in process_block (state + tip committed together)
                            }
                            Err(err) => {
                                warn!("Failed to process derived block {}: {}", height, err);
                                break;
                            }
                        }
                    }
                    Err(err) => {
                        warn!("Failed to fetch derived block {}: {}", height, err);
                        break;
                    }
                }
            }

            sleep(Duration::from_secs(5)).await;
        }
    }

    async fn scan_new_blocks(&self) -> Result<()> {
        let bitcoin_client = self
            .bitcoin_client_read
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Bitcoin RPC client not configured"))?;
        let tip = bitcoin_client.get_block_count()?;

        // Get the starting block without holding the lock
        let start_block = {
            let state = self.state.lock().await;
            match state.last_processed_bitcoin_height {
                None => {
                    // First run (no start block specified) - start from recent blocks
                    tip.saturating_sub(10)
                }
                Some(height) => {
                    // Continue from where we left off
                    height + 1
                }
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
            let bitcoin_client = self
                .bitcoin_client_read
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Bitcoin RPC client not configured"))?;
            let bitcoin_block = process_bitcoin_block(bitcoin_client, height)?;

            match self.process_block(bitcoin_block.clone()).await {
                Ok(core_lane_block_number) => {
                    if core_lane_block_number == 0 {
                        info!("Scanning again, we encountered a reorg");
                        break;
                    }
                    // Update the last processed block and bitcoin_height_to_hash mapping (tip already written in process_block)
                    let mut state = self.state.lock().await;
                    state.last_processed_bitcoin_height = Some(height);
                    // anchor_block_hash is now raw 32-byte hash
                    let block_hash = B256::from_slice(&bitcoin_block.anchor_block_hash);
                    state.bitcoin_height_to_hash.insert(height, block_hash);
                    state
                        .bitcoin_height_to_core_block
                        .insert(height, core_lane_block_number); // Bitcoin height -> Core Lane block
                    debug!(
                        "Processed Bitcoin block {} -> Core Lane block {}",
                        height, core_lane_block_number
                    );
                }
                Err(e) => {
                    error!("Error processing block {}: {}", height, e);
                }
            }
        }

        Ok(())
    }

    async fn process_block(&self, bitcoin_block: CoreLaneBlockParsed) -> Result<u64> {
        let block_start_time = Instant::now();
        let bitcoin_height = bitcoin_block.anchor_block_height;
        info!(
            "Starting block execution for Bitcoin block height: {}",
            bitcoin_height
        );

        // 🔍 REORG DETECTION: Check for blockchain reorganizations
        {
            let mut state = self.state.lock().await;
            let height = bitcoin_block.anchor_block_height;

            // anchor_block_hash is now raw 32-byte hash
            let current_hash = B256::from_slice(&bitcoin_block.anchor_block_hash);

            // Check if we already have a hash for this height
            if let Some(existing_hash) = state.bitcoin_height_to_hash.get(&height) {
                if existing_hash != &current_hash {
                    warn!(
                        "🚨 REORG DETECTED! Height {} has different hash (same-height mismatch). Expected: {}, Got: {}",
                        height, existing_hash, current_hash
                    );

                    // Increment reorg counter
                    state.reorgs_detected += 1;

                    // Attempt to recover from reorg
                    match self.handle_reorg(&state).await {
                        Ok(fork_core_block) => {
                            info!("✅ Found fork point at block {}", fork_core_block);
                            // Drop the state lock before performing rollback
                            drop(state);

                            // Perform the actual rollback (acquires lock internally)
                            self.perform_rollback(fork_core_block).await?;

                            info!("🚫 Skipping processing of current block after reorg recovery");
                            return Ok(0); // Return dummy Core Lane block number since we skipped processing
                        }
                        Err(e) => {
                            error!("❌ Failed to recover from reorg: {}", e);
                            drop(state);
                            return Err(e);
                        }
                    }
                }
            }

            // Check if the previous height's hash matches this block's parent hash
            if height > 0 && !bitcoin_block.parent_hash.is_empty() {
                let prev_height = height - 1;
                if let Some(prev_hash) = state.bitcoin_height_to_hash.get(&prev_height) {
                    // parent_hash is now raw 32-byte hash
                    let expected_parent_hash = B256::from_slice(&bitcoin_block.parent_hash);

                    if prev_hash != &expected_parent_hash {
                        warn!(
                            "🚨 REORG DETECTED! Height {} parent hash mismatch. Expected: {}, Got: {}",
                            height, prev_hash, expected_parent_hash
                        );

                        // Increment reorg counter
                        state.reorgs_detected += 1;

                        // Attempt to recover from reorg
                        match self.handle_reorg(&state).await {
                            Ok(fork_core_block) => {
                                info!("✅ Found fork point at block {}", fork_core_block);
                                // Drop the state lock before performing rollback
                                drop(state);

                                // Perform the actual rollback (acquires lock internally)
                                self.perform_rollback(fork_core_block).await?;

                                info!(
                                    "🚫 Skipping processing of current block after reorg recovery"
                                );
                                return Ok(0); // Return dummy Core Lane block number since we skipped processing
                            }
                            Err(e) => {
                                error!("❌ Failed to recover from reorg: {}", e);
                                drop(state);
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }

        let new_block = self.create_new_block(Some(bitcoin_block.clone())).await?;

        let new_block_clone = new_block.clone();
        let mut core_lane_transactions = Vec::new();

        // Get EIP-1559 configuration and sequencer address for this block
        let state = self.state.lock().await;
        let max_gas_limit = state.eip1559_fee_manager.max_gas_limit();
        let target_gas_usage = state.eip1559_fee_manager.target_gas_usage();
        // Get the expected sequencer address for this block number
        let expected_sequencer_address = state.sequencer_address;
        drop(state);

        // Track cumulative gas used for this block (EIP-1559 maximum enforcement)
        let mut cumulative_gas_used = U256::ZERO;

        // Create a single bundle state manager for the entire block
        let mut bundle_state = state::BundleStateManager::new();

        if let Some(block_origin) = new_block_clone.block_origin {
            let mut tx_count = 0;

            // Phase 1: Process single HEAD bundle by sequencer only
            debug!("📦 Phase 1: Processing sequencer HEAD bundle...");

            let mut sequencer_bundle_processed = false;
            for (bundle_idx, bundle) in block_origin.bundles.iter().enumerate() {
                // Only process Head marker bundles
                if bundle.marker != block::BundleMarker::Head {
                    continue;
                }

                info!(
                    "📦 Processing bundle #{} (HEAD): {} transactions, sequencer_payment_recipient: {:?}, valid_for_block: {}, marker: {:?}",
                    bundle_idx,
                    bundle.transactions.len(),
                    bundle.sequencer_payment_recipient,
                    bundle.valid_for_block,
                    bundle.marker
                );

                // Check if valid for this block
                if bundle.valid_for_block != u64::MAX && bundle.valid_for_block != new_block.number
                {
                    continue;
                }

                // Verify this bundle is signed by the sequencer
                if let Some(_signature) = bundle.signature {
                    match bundle.recover_signer_address() {
                        Ok(signer) => {
                            if signer != expected_sequencer_address {
                                warn!(
                                    "HEAD bundle from non-sequencer address {}, expected {}",
                                    signer, expected_sequencer_address
                                );
                                continue;
                            }
                            info!("✅ Processing HEAD bundle from sequencer: {}", signer);
                        }
                        Err(e) => {
                            error!("Failed to recover signer from HEAD bundle: {}", e);
                            continue;
                        }
                    }
                } else {
                    warn!("Skipping unsigned HEAD bundle (expected signature from sequencer)");
                    continue;
                }

                // Process only the first sequencer HEAD bundle
                if sequencer_bundle_processed {
                    warn!(
                        "⚠️  Multiple sequencer HEAD bundles found, processing only the first one"
                    );
                    break;
                }

                for tx in bundle.transactions.iter() {
                    // EIP-1559: Check if adding this transaction would exceed maximum block gas limit
                    let tx_gas_limit = U256::from(alloy_consensus::Transaction::gas_limit(&tx.0));

                    // Check if this transaction would exceed the maximum block gas limit
                    if cumulative_gas_used + tx_gas_limit > max_gas_limit {
                        warn!(
                            "🚫 Block {} reached EIP-1559 maximum gas limit ({}/{}). Skipping transaction with gas_limit: {}",
                            new_block.number,
                            cumulative_gas_used,
                            max_gas_limit,
                            tx_gas_limit
                        );
                        // Skip remaining transactions as we've hit the maximum
                        break;
                    }

                    // Log when we exceed target (for informational purposes)
                    if cumulative_gas_used >= target_gas_usage
                        && cumulative_gas_used < target_gas_usage + tx_gas_limit
                    {
                        info!(
                            "🎯 Block {} exceeded EIP-1559 target gas usage (target: {}, max: {}, current: {})",
                            new_block.number,
                            target_gas_usage,
                            max_gas_limit,
                            cumulative_gas_used
                        );
                    }

                    let tx_result = self
                        .process_core_lane_transaction(
                            &mut bundle_state,
                            tx,
                            new_block.number,
                            tx_count,
                            max_gas_limit,
                            cumulative_gas_used,
                            Some(bundle.sequencer_payment_recipient),
                            new_block.timestamp,
                        )
                        .await;

                    if let Some((stored_tx, receipt, tx_hash)) = tx_result {
                        // Parse actual gas used from receipt
                        let gas_used_str = receipt.gas_used.as_str();
                        let actual_gas_used = if let Some(hex) = gas_used_str.strip_prefix("0x") {
                            let bytes = hex::decode(hex).unwrap_or_default();
                            U256::from_be_slice(&bytes)
                        } else {
                            U256::from_str(gas_used_str).unwrap_or(tx_gas_limit)
                        };

                        // Update cumulative gas used with actual gas consumed
                        cumulative_gas_used += actual_gas_used;

                        core_lane_transactions.push((stored_tx, receipt, tx_hash));
                        tx_count += 1;

                        // Double-check: if we've now exceeded the maximum after execution, stop
                        if cumulative_gas_used > max_gas_limit {
                            warn!(
                                "🚫 Block {} exceeded EIP-1559 maximum gas limit after execution ({}/{}). Stopping transaction processing.",
                                new_block.number,
                                cumulative_gas_used,
                                max_gas_limit
                            );
                            break;
                        }
                    }
                }

                // Mark sequencer bundle as processed
                sequencer_bundle_processed = true;

                // If we've hit the maximum, stop processing
                if cumulative_gas_used >= max_gas_limit {
                    break;
                }
            }

            // Phase 2: Process burns
            debug!("🔥 Phase 2: Processing burns...");
            let state = self.state.lock().await;
            for burn in block_origin.burns.iter() {
                info!("🪙 Minting {} tokens to {}", burn.amount, burn.address);
                if let Err(e) =
                    bundle_state.add_balance(&state.account_manager, burn.address, burn.amount)
                {
                    error!("Failed to process burn: {}", e);
                }
            }
            drop(state);

            // Phase 3: Process non-sequencer bundles
            if cumulative_gas_used < max_gas_limit {
                debug!("📦 Phase 3: Processing non-sequencer bundles...");

                for (bundle_idx, bundle) in block_origin.bundles.iter().enumerate() {
                    // Skip HEAD bundles (already processed in Phase 1)
                    if bundle.marker == block::BundleMarker::Head {
                        continue;
                    }

                    // Check if valid for this block
                    if bundle.valid_for_block != u64::MAX
                        && bundle.valid_for_block != new_block.number
                    {
                        continue;
                    }

                    info!(
                        "📦 Processing bundle #{} (STANDARD): {} transactions, sequencer_payment_recipient: {:?}, valid_for_block: {}, marker: {:?}",
                        bundle_idx,
                        bundle.transactions.len(),
                        bundle.sequencer_payment_recipient,
                        bundle.valid_for_block,
                        bundle.marker
                    );

                    for tx in bundle.transactions.iter() {
                        let tx_gas_limit =
                            U256::from(alloy_consensus::Transaction::gas_limit(&tx.0));

                        if cumulative_gas_used + tx_gas_limit > max_gas_limit {
                            warn!(
                                    "🚫 Block {} reached EIP-1559 maximum gas limit ({}/{}). Skipping non-sequencer transaction with gas_limit: {}",
                                    new_block.number,
                                    cumulative_gas_used,
                                    max_gas_limit,
                                    tx_gas_limit
                                );
                            break;
                        }

                        if cumulative_gas_used >= target_gas_usage
                            && cumulative_gas_used < target_gas_usage + tx_gas_limit
                        {
                            info!(
                                    "🎯 Block {} exceeded EIP-1559 target gas usage (target: {}, max: {}, current: {})",
                                    new_block.number,
                                    target_gas_usage,
                                    max_gas_limit,
                                    cumulative_gas_used
                                );
                        }

                        let tx_result = self
                            .process_core_lane_transaction(
                                &mut bundle_state,
                                tx,
                                new_block.number,
                                tx_count,
                                max_gas_limit,
                                cumulative_gas_used,
                                Some(bundle.sequencer_payment_recipient),
                                new_block.timestamp,
                            )
                            .await;

                        if let Some((stored_tx, receipt, tx_hash)) = tx_result {
                            let gas_used_str = receipt.gas_used.as_str();
                            let actual_gas_used = if let Some(hex) = gas_used_str.strip_prefix("0x")
                            {
                                let bytes = hex::decode(hex).unwrap_or_default();
                                U256::from_be_slice(&bytes)
                            } else {
                                U256::from_str(gas_used_str).unwrap_or(tx_gas_limit)
                            };

                            cumulative_gas_used += actual_gas_used;
                            core_lane_transactions.push((stored_tx, receipt, tx_hash));
                            tx_count += 1;

                            if cumulative_gas_used > max_gas_limit {
                                warn!(
                                        "🚫 Block {} exceeded EIP-1559 maximum gas limit after execution ({}/{}). Stopping transaction processing.",
                                        new_block.number,
                                        cumulative_gas_used,
                                        max_gas_limit
                                    );
                                break;
                            }
                        }
                    }

                    if cumulative_gas_used >= max_gas_limit {
                        break;
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

        // Finalize first (updates EIP-1559, inserts block, writes metastate). Tip is written last
        // so it acts as commit marker: if tip exists, state and metastate for that block are on disk.
        let core_lane_block_number = new_block.number;
        let finalized_block = self
            .finalize_current_block(core_lane_transactions, new_block)
            .await?;

        let bitcoin_block_hash = B256::from_slice(&bitcoin_block.anchor_block_hash);
        let tip = ChainTip {
            core_lane_block_number: block_number,
            last_processed_bitcoin_height: bitcoin_height,
            bitcoin_block_hash,
            core_lane_block: finalized_block.clone(),
        };
        if let Err(e) = self.write_tip_to_disk(&tip) {
            error!("Failed to write tip to disk: {}", e);
        }
        let chain_entry = ChainIndexEntry {
            core_lane_block: finalized_block,
            bitcoin_height,
            bitcoin_block_hash,
        };
        if let Err(e) = self.write_chain_index_entry(block_number, &chain_entry) {
            warn!(
                "Failed to write chain index entry for block {}: {}",
                block_number, e
            );
        }

        let block_execution_time = block_start_time.elapsed();
        info!(
            "Block execution completed in {:?} for Bitcoin block height: {} -> Core Lane block: {}",
            block_execution_time, bitcoin_height, core_lane_block_number
        );

        // Track block processing time
        {
            let mut state = self.state.lock().await;
            state.last_block_processing_time_ms = Some(block_execution_time.as_millis() as u64);
        }

        Ok(core_lane_block_number)
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_core_lane_transaction(
        &self,
        bundle_state: &mut state::BundleStateManager,
        tx: &(TxEnvelope, Address, Vec<u8>),
        block_number: u64,
        tx_number: u64,
        max_block_gas_limit: U256,
        cumulative_gas_used: U256,
        sequencer_payment_recipient: Option<Address>,
        block_timestamp: u64,
    ) -> Option<(StoredTransaction, TransactionReceipt, String)> {
        let tx_start_time = Instant::now();

        // Compute and log transaction hash early
        let tx_hash = format!("0x{}", hex::encode(alloy_primitives::keccak256(&tx.2)));
        info!("   📝 Processing transaction: {}", tx_hash);

        let mut state = self.state.lock().await;
        let gas_limit = U256::from(alloy_consensus::Transaction::gas_limit(&tx.0));

        // EIP-1559: Validate transaction doesn't exceed block maximum gas limit
        if cumulative_gas_used + gas_limit > max_block_gas_limit {
            warn!(
                "      ⚠️  Transaction would exceed EIP-1559 block maximum gas limit (current: {}, tx: {}, max: {}), skipping",
                cumulative_gas_used, gas_limit, max_block_gas_limit
            );
            return None;
        }

        // Handle EIP-1559 transactions with proper fee calculation and burning
        if tx.0.is_eip1559() {
            let eip1559_tx = tx.0.as_eip1559().unwrap();
            let max_fee_per_gas = eip1559_tx.tx().max_fee_per_gas;
            let max_priority_fee_per_gas = eip1559_tx.tx().max_priority_fee_per_gas;

            // Validate EIP-1559 transaction
            if let Err(e) = state.eip1559_fee_manager.validate_eip1559_transaction(
                U256::from(max_fee_per_gas),
                U256::from(max_priority_fee_per_gas),
                gas_limit,
            ) {
                warn!(
                    "      ⚠️  EIP-1559 transaction validation failed: {}, skipping: {:?}",
                    e, tx.0
                );
                return None;
            }

            // Calculate fee breakdown (total, base_fee_portion, priority_fee_portion)
            // Note: Using gas_limit as approximation since actual gas_used is not known yet
            let (total_fee, base_fee_portion, priority_fee_portion) =
                state.eip1559_fee_manager.calculate_fee_breakdown(
                    U256::from(max_fee_per_gas),
                    U256::from(max_priority_fee_per_gas),
                    gas_limit, // TODO: Use actual gas_used when available
                );

            // Charge total fee from sender
            if let Err(e) = bundle_state.sub_balance(&state.account_manager, tx.1, total_fee) {
                warn!(
                    "      ⚠️  Failed to charge EIP-1559 fee: {}, skipping: {:?}",
                    e, tx.0
                );
                return None;
            }

            // ACTUAL BURNING: Base fee portion is destroyed from total supply
            // We don't add it to any account - it's permanently removed
            state.total_burned_amount += base_fee_portion;
            info!(
                "      🔥 BURNED base fee: {} wei (total burned: {} wei)",
                base_fee_portion, state.total_burned_amount
            );

            // ACTUAL SEQUENCER PAYMENT: Priority fee goes to sequencer_payment_recipient
            // EIP-1559 Rule: Priority fee (max_fee_per_gas - base_fee_per_gas) goes to sequencer
            // This incentivizes sequencers to include transactions and provides economic security
            if priority_fee_portion > U256::ZERO {
                let sequencer_address = sequencer_payment_recipient
                    .filter(|addr| *addr != Address::ZERO)
                    .unwrap_or(state.sequencer_address);
                if let Err(e) = bundle_state.add_balance(
                    &state.account_manager,
                    sequencer_address,
                    priority_fee_portion,
                ) {
                    warn!("      ⚠️  Failed to pay sequencer priority fee: {}", e);
                } else {
                    info!(
                        "      💰 Paid sequencer priority fee: {} wei to {}",
                        priority_fee_portion, sequencer_address
                    );

                    // Track total sequencer payments
                    state.total_sequencer_payments += priority_fee_portion;
                }
            }

            info!(
                "      💰 Total EIP-1559 fee charged: {} wei (base: {}, priority: {})",
                total_fee, base_fee_portion, priority_fee_portion
            );
        } else if tx.0.is_legacy() {
            // Legacy transaction handling (fallback to fixed gas price)
            let gas_price = U256::from(214285714u64); // Fixed legacy gas price
            let legacy_tx = tx.0.as_legacy().unwrap();

            if gas_price > legacy_tx.tx().gas_price {
                warn!("      ⚠️  Gas fee is greater than the legacy transaction gas price, skipping: {:?}", tx.0);
                return None;
            }

            let gas_fee = gas_price * gas_limit;
            if let Err(e) = bundle_state.sub_balance(&state.account_manager, tx.1, gas_fee) {
                warn!(
                    "      ⚠️  Failed to charge legacy gas fee: {}, skipping: {:?}",
                    e, tx.0
                );
                return None;
            }

            info!("      💰 Charged legacy gas fee: {} wei", gas_fee);
        } else {
            warn!(
                "      ⚠️  Unsupported transaction type, skipping: {:?}",
                tx.0
            );
            return None;
        }

        // Execute transaction with bundle state
        let execution_result =
            match execute_transaction(&tx.0, tx.1, bundle_state, &mut *state, block_timestamp) {
                Ok(result) => result,
                Err(e) => {
                    warn!("      ⚠️  Transaction execution failed with error: {}", e);
                    // Return None to skip this transaction
                    return None;
                }
            };

        // Log execution outcome
        if execution_result.success {
            info!("      ✅ Transaction executed successfully");
        } else {
            warn!(
                "      ⚠️  Transaction execution failed: {:?}",
                execution_result.error
            );
        }

        // XXX add gas refund later

        // Read balance after execution
        let final_balance = bundle_state.get_balance(&state.account_manager, tx.1);

        // Store the transaction with both envelope and raw data in bundle state
        let stored_tx = StoredTransaction {
            envelope: tx.0.clone(),
            raw_data: tx.2.clone(),
            block_number,
        };
        // Create and store transaction receipt in bundle state (tx_hash already computed above)

        // Calculate effective gas price and gas used for receipt
        let (effective_gas_price, _gas_used) = if tx.0.is_eip1559() {
            let eip1559_tx = tx.0.as_eip1559().unwrap();
            let max_fee_per_gas = eip1559_tx.tx().max_fee_per_gas;
            let max_priority_fee_per_gas = eip1559_tx.tx().max_priority_fee_per_gas;
            let effective_price = state.eip1559_fee_manager.calculate_effective_gas_price(
                U256::from(max_fee_per_gas),
                U256::from(max_priority_fee_per_gas),
            );
            (effective_price, gas_limit)
        } else if tx.0.is_legacy() {
            let legacy_tx = tx.0.as_legacy().unwrap();
            (U256::from(legacy_tx.tx().gas_price), gas_limit)
        } else {
            (U256::from(214285714u64), gas_limit) // Default fallback
        };

        // Convert string logs to proper Log objects
        let logs: Vec<state::Log> = execution_result
            .logs
            .iter()
            .enumerate()
            .map(|(idx, log_str)| state::Log {
                address: "0x0000000000000000000000000000000000000000".to_string(), // Intent contract address
                topics: vec![], // No topics for now
                data: format!("0x{}", hex::encode(log_str.as_bytes())), // Encode log message as hex data
                block_number: format!("0x{:x}", block_number),
                transaction_hash: tx_hash.clone(),
                transaction_index: format!("0x{:x}", tx_number),
                block_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(), // Placeholder, will be updated when block is finalized
                log_index: format!("0x{:x}", idx),
                removed: false,
            })
            .collect();

        let receipt = TransactionReceipt {
            transaction_hash: tx_hash.clone(),
            block_number,
            transaction_index: tx_number,
            from: format!("0x{}", hex::encode(tx.1.as_slice())),
            to: None, // Will be set based on transaction type
            cumulative_gas_used: format!("0x{:x}", execution_result.gas_used),
            gas_used: format!("0x{:x}", execution_result.gas_used),
            contract_address: None,
            logs,
            status: if execution_result.success {
                "0x1"
            } else {
                "0x0"
            }
            .to_string(),
            effective_gas_price: format!("0x{:x}", effective_gas_price),
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

        let tx_execution_time = tx_start_time.elapsed();
        debug!(
            "Transaction executed in {:?} (tx #{})",
            tx_execution_time, tx_number
        );

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
        let bitcoin_client = self
            .bitcoin_client_write
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Bitcoin RPC write client not configured"))?;
        let taproot_da = TaprootDA::new(bitcoin_client);
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

    #[allow(clippy::too_many_arguments)]
    async fn send_bundle_to_da(
        &self,
        raw_tx_hex_vec: Vec<String>,
        mnemonic: &str,
        network: bitcoin::Network,
        network_str: &str,
        electrum_url: Option<&str>,
        data_dir: &str,
        sequencer_payment_recipient: alloy_primitives::Address,
        marker: crate::block::BundleMarker,
    ) -> Result<()> {
        // Delegate to the TaprootDA implementation which handles all validation and logic
        // Use write client for DA transactions (wallet operations)
        let bitcoin_client = self
            .bitcoin_client_write
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Bitcoin RPC write client not configured"))?;
        let taproot_da = TaprootDA::new(bitcoin_client);
        let _bitcoin_txid = taproot_da
            .send_bundle_to_da(
                raw_tx_hex_vec,
                mnemonic,
                network,
                network_str,
                electrum_url,
                data_dir,
                sequencer_payment_recipient,
                marker,
            )
            .await?;
        Ok(())
    }

    /// Find the fork point by comparing our stored Bitcoin hashes with current chain
    async fn find_fork_point(
        &self,
        bitcoin_client: Arc<Client>,
        state: &CoreLaneState,
    ) -> Result<Option<u64>> {
        use tokio::task;

        // Start from our last processed Bitcoin height and work backwards
        let mut current_bitcoin_height = match state.last_processed_bitcoin_height {
            Some(height) => height,
            None => {
                error!("❌ Cannot find fork point: no Bitcoin height has been processed yet");
                return Err(anyhow::anyhow!(
                    "Cannot find fork point when no blocks have been processed"
                ));
            }
        };
        let search_limit = 100; // Don't search more than 100 blocks back
        let mut blocks_checked = 0;

        info!(
            "🔍 Starting fork point search from Bitcoin height {} (limit: {} blocks)",
            current_bitcoin_height, search_limit
        );

        while current_bitcoin_height > 0 && blocks_checked < search_limit {
            blocks_checked += 1;

            // Check if we have a record for this Bitcoin height
            if let Some(&core_block) = state
                .bitcoin_height_to_core_block
                .get(&current_bitcoin_height)
            {
                // Get the Bitcoin hash we stored for this height
                if let Some(&stored_hash) =
                    state.bitcoin_height_to_hash.get(&current_bitcoin_height)
                {
                    debug!(
                        "🔍 Checking Bitcoin height {} (Core Lane block {})",
                        current_bitcoin_height, core_block
                    );

                    // Get the current Bitcoin hash for this height using spawn_blocking
                    match task::spawn_blocking({
                        let client = bitcoin_client.clone();
                        let height = current_bitcoin_height;
                        move || client.get_block_hash(height)
                    })
                    .await
                    {
                        Ok(Ok(current_hash)) => {
                            let current_hash_bytes: &[u8] = current_hash.as_ref();

                            if stored_hash.as_slice() == current_hash_bytes {
                                // This height matches - this is the last common ancestor (fork point)
                                info!("✅ Bitcoin height {} matches stored hash - this is the fork point (last common ancestor)", current_bitcoin_height);
                                info!(
                                    "🔍 Fork point found at Bitcoin height {} (Core Lane block {})",
                                    current_bitcoin_height, core_block
                                );
                                return Ok(Some(core_block));
                            } else {
                                // Hash mismatch found - continue searching backwards for the fork point
                                warn!(
                                    "⚠️  Hash mismatch at Bitcoin height {} (Core Lane block {})",
                                    current_bitcoin_height, core_block
                                );
                                info!(
                                    "🔍 Hash mismatch: stored={}, current=0x{}",
                                    stored_hash,
                                    hex::encode(current_hash_bytes)
                                );
                                current_bitcoin_height -= 1;
                                continue;
                            }
                        }
                        Ok(Err(e)) => {
                            warn!(
                                "⚠️  Failed to get block hash for height {}: {}",
                                current_bitcoin_height, e
                            );
                            // Continue searching - maybe this height is not accessible
                            current_bitcoin_height -= 1;
                            continue;
                        }
                        Err(e) => {
                            error!(
                                "❌ Task join error for height {}: {}",
                                current_bitcoin_height, e
                            );
                            // Continue searching
                            current_bitcoin_height -= 1;
                            continue;
                        }
                    }
                } else {
                    debug!(
                        "🔍 No stored hash for Bitcoin height {}",
                        current_bitcoin_height
                    );
                }
            } else {
                debug!(
                    "🔍 No Core Lane block record for Bitcoin height {}",
                    current_bitcoin_height
                );
            }

            // No record for this height, continue backwards
            current_bitcoin_height -= 1;
        }

        // If we reach the limit without finding a mismatch, something is wrong
        if blocks_checked >= search_limit {
            warn!(
                "⚠️  Could not find fork point within {} blocks (searched back to height {})",
                search_limit, current_bitcoin_height
            );
        } else {
            warn!("⚠️  Could not find fork point, reached height 0");
        }
        Ok(None)
    }

    /// Handle reorg by rolling back to fork point and restarting processing
    /// NOTE: This method returns the fork point block number for the caller to use
    /// The caller must DROP the state lock before calling this method's returned closure
    async fn handle_reorg(&self, state: &CoreLaneState) -> Result<u64> {
        info!("🔄 Starting reorg recovery...");

        // Find the fork point
        info!("🔍 Searching for fork point...");
        let fork_point = if let Some(bitcoin_client) = self.bitcoin_client_read.clone() {
            self.find_fork_point(bitcoin_client, state).await?
        } else {
            warn!("⚠️  Bitcoin RPC unavailable, deriving fork point from local Core Lane history");
            Self::derive_local_fork_point(state)?
        };
        info!("🔍 Fork point search completed");

        match fork_point {
            Some(fork_core_block) => {
                info!("🎯 Found fork point at Core Lane block {}", fork_core_block);
                // Return the fork point - the caller will handle the actual rollback after dropping their lock
                Ok(fork_core_block)
            }
            None => {
                error!("❌ Could not find fork point for reorg recovery");
                warn!("💡 This might indicate a deeper issue with the blockchain state");
                warn!("💡 Consider restarting the node to resync from a known good state");
                Err(anyhow::anyhow!(
                    "Unable to determine fork point for reorg recovery"
                ))
            }
        }
    }

    /// Perform the actual rollback after lock is released
    async fn perform_rollback(&self, fork_core_block: u64) -> Result<()> {
        // Rollback state to the fork point
        info!("💾 Loading state from disk for block {}", fork_core_block);
        {
            let mut state_mut = self.state.lock().await;
            state_mut.rollback_to_block(fork_core_block, &self.data_dir)?;
        }

        // Load and restore metastate (EIP-1559 fee manager and total burned amount)
        {
            let mut state_mut = self.state.lock().await;
            match self.read_metastate_from_disk(fork_core_block) {
                Ok(metastate) => {
                    info!(
                        "✅ Successfully loaded metastate for block {}",
                        fork_core_block
                    );
                    state_mut.eip1559_fee_manager = metastate.eip1559_fee_manager;
                    state_mut.total_burned_amount = metastate.total_burned_amount;
                    state_mut.sequencer_address = metastate.sequencer_address;
                    info!("✅ Restored EIP-1559 fee manager, total burned amount, and sequencer address");
                }
                Err(e) => {
                    warn!(
                        "⚠️ Failed to load metastate for block {}: {}",
                        fork_core_block, e
                    );
                    warn!("⚠️ Continuing with current metastate (may not match historical state)");
                }
            }
        }

        info!(
            "🔄 Successfully rolled back to Core Lane block {}",
            fork_core_block
        );

        // Get the actual Bitcoin height that we'll restart from (the rollback set last_processed_bitcoin_height)
        let restart_bitcoin_height = {
            let state = self.state.lock().await;
            match state.last_processed_bitcoin_height {
                Some(height) => height + 1,
                None => {
                    error!("❌ Rollback succeeded but last_processed_bitcoin_height is None");
                    return Err(anyhow::anyhow!(
                        "Invalid state after rollback: last_processed_bitcoin_height is None"
                    ));
                }
            }
        };

        info!(
            "🔄 Will restart processing from Bitcoin height {}",
            restart_bitcoin_height
        );

        // The scanning loop will detect that last_processed_bitcoin_height has been reset
        // and automatically restart from the correct point
        info!("✅ Reorg recovery completed successfully");
        info!(
            "🚀 Scanning loop will restart from Bitcoin height {}",
            restart_bitcoin_height
        );

        Ok(())
    }

    fn derive_local_fork_point(state: &CoreLaneState) -> Result<Option<u64>> {
        let mut search_height = state.last_processed_bitcoin_height.ok_or_else(|| {
            anyhow::anyhow!("Cannot recover from reorg without processed block history")
        })?;

        while search_height > 0 {
            if let Some(&core_block) = state.bitcoin_height_to_core_block.get(&search_height) {
                return Ok(Some(core_block));
            }
            search_height -= 1;
        }

        Ok(Some(0))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing only if not in plain mode
    if !cli.plain {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    "core_lane_node=info,core_lane=info,tower_http=debug".into()
                }),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

        info!("Starting Core Lane Node");
    }

    match &cli.command {
        Commands::StoreBlob {
            rpc_url,
            contract,
            private_key,
            file,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => {
            let to = Address::from_str(contract)?;
            let data_bytes = fs::read(file)?;
            let value_u256 = parse_u256_dec_or_hex("0")?;

            let calldata: Bytes = IntentSystem::storeBlobCall {
                data: data_bytes.into(),
                expiryTime: parse_u256_dec_or_hex("0")?,
            }
            .abi_encode()
            .into();

            let url = Url::parse(rpc_url)?;
            let provider = ProviderBuilder::new().connect_http(url);
            let wallet: PrivateKeySigner = private_key.parse()?;
            let sender = wallet.address();
            let chain_id = provider.get_chain_id().await?;

            let nonce_u64 = provider.get_transaction_count(sender).await? as u64;

            let req = TransactionRequest {
                from: Some(sender),
                to: Some(TxKind::Call(to)),
                input: calldata.clone().into(),
                value: Some(value_u256),
                ..Default::default()
            };

            let gas_limit = provider.estimate_gas(req.clone()).await?;
            let base_gas_price = provider.get_gas_price().await?;
            let max_fee_u128 = max_fee_per_gas.unwrap_or_else(|| base_gas_price);

            let tx = TxEip1559 {
                chain_id,
                nonce: nonce_u64,
                max_priority_fee_per_gas: *max_priority_fee_per_gas,
                max_fee_per_gas: max_fee_u128,
                gas_limit,
                to: TxKind::Call(to),
                value: value_u256,
                input: calldata.clone(),
                access_list: Default::default(),
            };

            let sighash = tx.signature_hash();
            let signature = wallet.sign_hash(&sighash).await?;
            let signed = tx.into_signed(signature);
            let envelope = alloy_consensus::TxEnvelope::Eip1559(signed);
            let raw = envelope.encoded_2718();

            let _ = provider.send_raw_transaction(&raw).await?;
        }

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
            mnemonic,
            mnemonic_file,
            electrum_url,
            sequencer_rpc_url,
            sequencer_address,
        } => {
            // Parse sequencer address if provided
            let sequencer_addr = sequencer_address
                .as_ref()
                .map(|addr_str| {
                    Address::from_str(addr_str).map_err(|e| {
                        anyhow::anyhow!("Invalid sequencer address '{}': {}", addr_str, e)
                    })
                })
                .transpose()?;

            if sequencer_addr.is_none() {
                warn!("⚠️  No --sequencer-address provided, using default test address (insecure for production)");
            } else {
                info!("✅ Using sequencer address: {:?}", sequencer_addr);
            }

            // Resolve mnemonic from various sources (optional if sequencer_rpc_url is provided)
            // If mnemonic parameters are explicitly provided, require successful resolution
            let mnemonic_str_opt = if mnemonic.is_some() || mnemonic_file.is_some() {
                // User explicitly provided mnemonic parameters - require successful resolution
                Some(resolve_mnemonic(
                    mnemonic.as_deref(),
                    mnemonic_file.as_deref(),
                )?)
            } else {
                // No explicit mnemonic parameters - try environment variable
                // Only allow failure if env var is not set
                match resolve_mnemonic(mnemonic.as_deref(), mnemonic_file.as_deref()) {
                    Ok(m) => {
                        // Validate that resolved mnemonic is non-empty
                        // Empty/whitespace-only mnemonics will fail later during BDK operations
                        if m.trim().is_empty() {
                            // If env var is set (even if empty), return error
                            // Otherwise, return None to allow sequencer_rpc_url path
                            if std::env::var("CORE_LANE_MNEMONIC").is_ok() {
                                return Err(anyhow::anyhow!(
                                    "CORE_LANE_MNEMONIC environment variable is set but contains only whitespace or is empty"
                                ));
                            }
                            None
                        } else {
                            Some(m)
                        }
                    }
                    Err(e) => {
                        // If env var exists but is invalid, propagate error
                        if std::env::var("CORE_LANE_MNEMONIC")
                            .map(|s| !s.trim().is_empty())
                            .unwrap_or(false)
                        {
                            return Err(e);
                        }
                        None
                    }
                }
            };

            // Validate: either mnemonic or sequencer_rpc_url must be provided
            if mnemonic_str_opt.is_none() && sequencer_rpc_url.is_none() {
                return Err(anyhow::anyhow!(
                    "Either mnemonic (for Bitcoin DA) or sequencer_rpc_url must be provided"
                ));
            }

            let mnemonic_str = mnemonic_str_opt.unwrap_or_default();

            // Always create read client (needed for reading blockchain data)
            let read_client = bitcoincore_rpc::Client::new(
                bitcoin_rpc_read_url,
                Auth::UserPass(
                    bitcoin_rpc_read_user.to_string(),
                    bitcoin_rpc_read_password.to_string(),
                ),
            )?;

            // Get blockchain info from read client to determine network
            let blockchain_info: serde_json::Value = read_client.call("getblockchaininfo", &[])?;

            let network = if let Some(chain) = blockchain_info.get("chain") {
                match chain.as_str() {
                    Some("main") => bitcoincore_rpc::bitcoin::Network::Bitcoin,
                    Some("test") => bitcoincore_rpc::bitcoin::Network::Testnet,
                    Some("testnet4") => bitcoincore_rpc::bitcoin::Network::Testnet4,
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

            // If sequencer is configured and mnemonic is not, we can skip write client setup
            let (shared_state, bitcoin_client_write, node_opt) =
                if sequencer_rpc_url.is_some() && mnemonic_str.is_empty() {
                    // Sequencer-only mode: read-only bitcoin client, no write client needed
                    // No block scanner needed in sequencer-only mode
                    let node = CoreLaneNode::new_with_clients(
                        Some(read_client),
                        None,
                        cli.data_dir.clone(),
                        network,
                        sequencer_addr,
                    );
                    (Arc::clone(&node.state), None, None) // node_opt = None to skip block scanner
                } else {
                    // Bitcoin DA mode: require write client and mnemonic
                    if mnemonic_str.is_empty() {
                        return Err(anyhow::anyhow!(
                            "Mnemonic is required when sequencer_rpc_url is not provided"
                        ));
                    }

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

                    // Write client - user can customize the URL themselves
                    let write_client = bitcoincore_rpc::Client::new(
                        write_url,
                        Auth::UserPass(write_user.to_string(), write_password.to_string()),
                    )?;

                    info!("   ✍️  Write: {}", write_url);

                    let node = CoreLaneNode::new(
                        read_client,
                        write_client,
                        cli.data_dir.clone(),
                        network,
                        sequencer_addr,
                    );
                    let shared_state = Arc::clone(&node.state);
                    let bitcoin_client_write = node
                        .bitcoin_client_write
                        .clone()
                        .expect("Bitcoin write client must be configured in start mode");
                    (shared_state, Some(bitcoin_client_write), Some(node))
                };

            let rpc_config = crate::rpc::BitcoinClientConfig {
                wallet: None, // wallet parameter no longer used
                mnemonic: if mnemonic_str.is_empty() {
                    None
                } else {
                    Some(mnemonic_str.clone())
                },
                electrum_url: electrum_url.clone(),
                data_dir: cli.data_dir.clone(),
                sequencer_rpc_url: sequencer_rpc_url.clone(),
            };
            let rpc_server = RpcServer::with_bitcoin_client(
                shared_state,
                bitcoin_client_write,
                Some(network),
                rpc_config,
            )
            .map_err(|e| anyhow::anyhow!("Failed to create RPC server: {}", e))?;

            if let Some(ref url) = sequencer_rpc_url {
                info!("🔄 Sequencer RPC forwarding enabled: {}", url);
            }

            let app = rpc_server.router();

            let addr = format!("{}:{}", http_host, http_port);
            info!("🚀 Starting JSON-RPC server on http://{}", addr);

            // Start the HTTP server in a separate task
            let server_handle = tokio::spawn(async move {
                let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
                axum::serve(listener, app).await.unwrap();
            });

            // Start block scanner in main task (only if bitcoin client is available)
            let start_block = *start_block;
            if let Some(node) = node_opt {
                let scanner_handle =
                    tokio::spawn(async move { node.start_block_scanner(start_block).await });
                let (_server_result, scanner_result) =
                    tokio::try_join!(server_handle, scanner_handle)?;
                scanner_result?;
            } else {
                // Sequencer-only mode: no block scanner needed
                info!("⏭️  Skipping block scanner (sequencer-only mode)");
                server_handle.await?;
            }
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
                "testnet4" => BdkNetwork::Testnet4,
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
                use bdk_electrum::{electrum_client, BdkElectrumClient};

                let electrum_url = electrum_url.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("--electrum-url required for network: {}", network_str)
                })?;

                if !cli.plain {
                    info!("🔗 Syncing with Electrum: {}", electrum_url);
                }

                let electrum_client = electrum_client::Client::new(electrum_url)?;
                let electrum = BdkElectrumClient::new(electrum_client);

                if !cli.plain {
                    info!("🔄 Performing soft sync (updating revealed addresses)...");
                }

                // Use soft sync for updates (only syncs revealed addresses)
                let request = wallet.start_sync_with_revealed_spks().build();
                let response = electrum.sync(request, 5, false)?;

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
            let addr_bytes = hex::decode(eth_addr)?;
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
            let psbt = tx_builder.finish();
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
                use bdk_electrum::electrum_client::{self, ElectrumApi};

                let electrum_url = electrum_url.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("--electrum-url required for network: {}", network_str)
                })?;

                let electrum_client = electrum_client::Client::new(electrum_url)?;
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
                "testnet4" => bitcoincore_rpc::bitcoin::Network::Testnet4,
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

            let node = CoreLaneNode::new(
                read_client,
                write_client,
                cli.data_dir.clone(),
                network,
                None,
            );
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

        Commands::SendBundle {
            raw_tx_hex: raw_tx_hex_vec,
            network: network_str,
            mnemonic,
            mnemonic_file,
            rpc_url,
            rpc_user,
            rpc_password,
            electrum_url,
            sequencer_payment_recipient,
            marker,
        } => {
            if raw_tx_hex_vec.is_empty() {
                return Err(anyhow::anyhow!(
                    "At least one transaction is required for a bundle"
                ));
            }

            // Resolve mnemonic from various sources
            let mnemonic_str = resolve_mnemonic(mnemonic.as_deref(), mnemonic_file.as_deref())?;

            // Parse network
            let network = match network_str.as_str() {
                "bitcoin" | "mainnet" => bitcoincore_rpc::bitcoin::Network::Bitcoin,
                "testnet" => bitcoincore_rpc::bitcoin::Network::Testnet,
                "testnet4" => bitcoincore_rpc::bitcoin::Network::Testnet4,
                "signet" => bitcoincore_rpc::bitcoin::Network::Signet,
                "regtest" => bitcoincore_rpc::bitcoin::Network::Regtest,
                _ => return Err(anyhow::anyhow!("Invalid network: {}", network_str)),
            };

            // Parse sequencer payment recipient
            let sequencer_addr = if let Some(addr_str) = sequencer_payment_recipient {
                alloy_primitives::Address::from_str(addr_str.trim_start_matches("0x")).map_err(
                    |e| anyhow::anyhow!("Invalid sequencer payment recipient address: {}", e),
                )?
            } else {
                alloy_primitives::Address::ZERO
            };

            // Parse bundle marker
            let bundle_marker = match marker.to_lowercase().as_str() {
                "head" => crate::block::BundleMarker::Head,
                "standard" => crate::block::BundleMarker::Standard,
                _ => {
                    return Err(anyhow::anyhow!(
                        "Invalid bundle marker: {}. Must be 'head' or 'standard'",
                        marker
                    ))
                }
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

            let node = CoreLaneNode::new(
                read_client,
                write_client,
                cli.data_dir.clone(),
                network,
                None,
            );
            node.send_bundle_to_da(
                raw_tx_hex_vec.clone(),
                &mnemonic_str,
                network,
                network_str,
                electrum_url.as_deref(),
                &cli.data_dir,
                sequencer_addr,
                bundle_marker,
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
            disable_archive_fetch,
            s3_bucket,
            s3_region,
            s3_endpoint,
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
                    *disable_archive_fetch,
                    S3Config::new(
                        s3_bucket.to_string(),
                        s3_region.to_string(),
                        s3_endpoint.to_string(),
                    ),
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
                    *disable_archive_fetch,
                    S3Config::new(
                        s3_bucket.to_string(),
                        s3_region.to_string(),
                        s3_endpoint.to_string(),
                    ),
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
            electrum_url,
        } => {
            use bdk_wallet::keys::{
                bip39::{Language, Mnemonic, WordCount},
                GeneratableKey, GeneratedKey,
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

            // Create wallet using helper function
            if !cli.plain {
                info!("💾 Creating wallet database...");
            }
            create_wallet_from_mnemonic(
                &cli.data_dir,
                network,
                mnemonic_words.clone(),
                cli.plain,
                electrum_url.as_deref(),
            )?;

            // Output formatting based on plain flag
            let db_path = wallet_db_path(&cli.data_dir, network);
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

        Commands::GetAddress {
            network,
            mnemonic,
            mnemonic_file,
        } => {
            use bdk_wallet::rusqlite::Connection;
            use bdk_wallet::{KeychainKind, Wallet};

            let db_path = wallet_db_path(&cli.data_dir, network);

            // Check if wallet database exists, create if missing
            if !std::path::Path::new(&db_path).exists() {
                if !cli.plain {
                    info!("📝 Wallet database not found, creating from mnemonic...");
                }

                // Resolve mnemonic from various sources
                // If no explicit mnemonic or file provided, fall back to old file naming convention
                let mnemonic_str = if mnemonic.is_some() || mnemonic_file.is_some() {
                    resolve_mnemonic(mnemonic.as_deref(), mnemonic_file.as_deref())?
                } else {
                    // Fall back to old file naming convention for backward compatibility
                    let old_mnemonic_file = std::path::Path::new(&cli.data_dir)
                        .join(format!("mnemonic_{}.txt", network));
                    resolve_mnemonic(None, old_mnemonic_file.to_str())?
                };

                // Create wallet using helper function (no electrum_url for GetAddress)
                create_wallet_from_mnemonic(&cli.data_dir, network, mnemonic_str, cli.plain, None)?;
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

        Commands::GetBitcoinBalance {
            network,
            mnemonic,
            mnemonic_file,
            electrum_url,
            rpc_url,
            rpc_user,
            rpc_password,
        } => {
            use bdk_wallet::rusqlite::Connection;
            use bdk_wallet::Wallet;

            let db_path = wallet_db_path(&cli.data_dir, network);

            // Check if wallet database exists, create if missing
            if !std::path::Path::new(&db_path).exists() {
                if !cli.plain {
                    info!("📝 Wallet database not found, creating from mnemonic...");
                }

                // Resolve mnemonic from various sources
                // If no explicit mnemonic or file provided, fall back to old file naming convention
                let mnemonic_str = if mnemonic.is_some() || mnemonic_file.is_some() {
                    resolve_mnemonic(mnemonic.as_deref(), mnemonic_file.as_deref())?
                } else {
                    // Fall back to old file naming convention for backward compatibility
                    let old_mnemonic_file = std::path::Path::new(&cli.data_dir)
                        .join(format!("mnemonic_{}.txt", network));
                    resolve_mnemonic(None, old_mnemonic_file.to_str())?
                };

                // Create wallet using helper function (no initial scan here, will sync below)
                create_wallet_from_mnemonic(&cli.data_dir, network, mnemonic_str, cli.plain, None)?;
            }

            if !cli.plain {
                info!("📂 Loading wallet from: {}", db_path);
            }

            let mut conn = Connection::open(&db_path)
                .map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))?;

            // Load wallet - it should exist since we created it above if missing
            let mut wallet = Wallet::load()
                .extract_keys()
                .load_wallet(&mut conn)
                .map_err(|e| anyhow::anyhow!("Failed to load wallet: {}", e))?
                .ok_or_else(|| anyhow::anyhow!("No wallet found in database"))?;

            // Sync wallet based on network
            if !cli.plain {
                info!("🔄 Syncing wallet with network...");
            }

            if network == "regtest" {
                // Use bitcoind RPC for regtest
                use bdk_bitcoind_rpc::bitcoincore_rpc::Auth as RpcAuth;
                use bdk_bitcoind_rpc::bitcoincore_rpc::Client;
                use bdk_bitcoind_rpc::Emitter;
                use std::sync::Arc;

                if !cli.plain {
                    info!("🔗 Syncing with Bitcoin RPC: {}", rpc_url);
                }

                let rpc_pass = if rpc_password.is_empty() {
                    "bitcoin123".to_string()
                } else {
                    rpc_password.clone()
                };
                let rpc_client =
                    Client::new(rpc_url, RpcAuth::UserPass(rpc_user.clone(), rpc_pass))?;

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
                use bdk_electrum::{electrum_client, BdkElectrumClient};

                let electrum_url = electrum_url.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("--electrum-url required for network: {}", network)
                })?;

                if !cli.plain {
                    info!("🔗 Syncing with Electrum: {}", electrum_url);
                }

                let electrum_client = electrum_client::Client::new(electrum_url)?;
                let electrum = BdkElectrumClient::new(electrum_client);

                if !cli.plain {
                    info!("🔄 Performing soft sync (updating revealed addresses)...");
                }

                // Use soft sync for updates (only syncs revealed addresses)
                let request = wallet.start_sync_with_revealed_spks().build();
                let response = electrum.sync(request, 5, false)?;

                wallet.apply_update(response)?;
                wallet.persist(&mut conn)?;
            }

            if !cli.plain {
                info!("💰 Wallet synced successfully");
            }

            // Get wallet balance
            let balance = wallet.balance();

            if cli.plain {
                // Plain mode: just print the balance in satoshis
                println!("{}", balance.total().to_sat());
            } else {
                // Pretty mode with emojis and formatted output
                let total_sats = balance.total().to_sat();
                let confirmed_sats = balance.confirmed.to_sat();
                let unconfirmed_sats = balance.untrusted_pending.to_sat();

                println!("💰 Bitcoin Balance Summary");
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("🌐 Network: {}", network);
                println!("📊 Total Balance: {} sats", total_sats);
                println!("✅ Confirmed: {} sats", confirmed_sats);
                println!("⏳ Unconfirmed: {} sats", unconfirmed_sats);

                // Convert to BTC for display
                let total_btc = total_sats as f64 / 100_000_000.0;
                let confirmed_btc = confirmed_sats as f64 / 100_000_000.0;
                let unconfirmed_btc = unconfirmed_sats as f64 / 100_000_000.0;

                println!("\n💎 Bitcoin Amounts");
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("📊 Total Balance: {:.8} BTC", total_btc);
                println!("✅ Confirmed: {:.8} BTC", confirmed_btc);
                println!("⏳ Unconfirmed: {:.8} BTC", unconfirmed_btc);
            }
        }

        Commands::DerivedStart {
            core_rpc_url,
            chain_id,
            start_block,
            derived_da_address,
            http_host,
            http_port,
            sequencer_rpc_url,
            sequencer_address,
        } => {
            // Parse sequencer address if provided
            let sequencer_addr = sequencer_address
                .as_ref()
                .map(|addr_str| {
                    Address::from_str(addr_str).map_err(|e| {
                        anyhow::anyhow!("Invalid sequencer address '{}': {}", addr_str, e)
                    })
                })
                .transpose()?;

            if sequencer_addr.is_none() {
                warn!("⚠️  No --sequencer-address provided, using default test address (insecure for production)");
            } else {
                info!("✅ Using sequencer address: {:?}", sequencer_addr);
            }

            let node =
                CoreLaneNode::new_derived(cli.data_dir.clone(), Network::Regtest, sequencer_addr);

            let da_address = Address::from_str(derived_da_address).map_err(|err| {
                anyhow::anyhow!(
                    "Invalid --derived-da-address '{}': {}",
                    derived_da_address,
                    err
                )
            })?;

            let shared_state = Arc::clone(&node.state);
            let rpc_server = RpcServer::with_derived(
                shared_state,
                core_rpc_url.clone(),
                da_address,
                cli.data_dir.clone(),
                sequencer_rpc_url.clone(),
            );

            if let Some(ref url) = sequencer_rpc_url {
                info!("🔄 Sequencer RPC forwarding enabled: {}", url);
            }

            let app = rpc_server.router();
            let addr = format!("{}:{}", http_host, http_port);
            info!(
                "🚀 Starting JSON-RPC server on http://{} (derived mode)",
                addr
            );

            let server_handle = tokio::spawn(async move {
                let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
                axum::serve(listener, app).await.unwrap();
            });

            let start_block = *start_block;
            let chain_id = *chain_id;
            let core_rpc_url = core_rpc_url.clone();
            let scanner_handle = tokio::spawn(async move {
                node.start_core_lane_scanner(core_rpc_url, chain_id, start_block, da_address)
                    .await
            });

            let _ = tokio::try_join!(server_handle, scanner_handle)?;
        }
    }

    Ok(())
}

fn parse_u256_dec_or_hex(s: &str) -> Result<U256> {
    if let Some(hexstr) = s.strip_prefix("0x") {
        let bytes = hex::decode(hexstr)?;
        Ok(U256::from_be_slice(&bytes))
    } else {
        let v: u128 = s.parse()?;
        Ok(U256::from(v))
    }
}
