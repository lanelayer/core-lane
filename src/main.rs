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
mod intents;
mod rpc;
mod taproot_da;
mod transaction;

#[cfg(test)]
mod tests;

use account::AccountManager;
use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Decodable;
use intents::{create_anchor_bitcoin_fill_intent, decode_intent_calldata, Intent};
use rpc::RpcServer;
use taproot_da::TaprootDA;
use transaction::{
    execute_transaction, get_transaction_input_bytes, recover_sender, validate_transaction,
};

#[derive(Parser)]
#[command(name = "core-lane-node")]
#[command(about = "Core Lane Node - Bitcoin-anchored execution environment")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Start {
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        rpc_url: String,
        #[arg(long, default_value = "user")]
        rpc_user: String,
        #[arg(long)]
        rpc_password: String,
        #[arg(long)]
        start_block: Option<u64>,
        #[arg(long, default_value = "127.0.0.1")]
        http_host: String,
        #[arg(long, default_value = "8545")]
        http_port: u16,
        #[arg(long, default_value = "mine")]
        rpc_wallet: String,
    },

    Burn {
        #[arg(long)]
        burn_amount: u64,
        #[arg(long)]
        chain_id: u32,
        #[arg(long)]
        eth_address: String,
        #[arg(long, default_value = "mine")]
        rpc_wallet: String,
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        rpc_url: String,
        #[arg(long, default_value = "bitcoin")]
        rpc_user: String,
        #[arg(long)]
        rpc_password: String,
    },
    SendTransaction {
        #[arg(long)]
        raw_tx_hex: String,
        #[arg(long, default_value = "mine")]
        rpc_wallet: String,
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        rpc_url: String,
        #[arg(long, default_value = "bitcoin")]
        rpc_user: String,
        #[arg(long)]
        rpc_password: String,
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
}

#[derive(Debug, Clone)]
struct TransactionReceipt {
    transaction_hash: String,
    block_number: u64,
    transaction_index: u64,
    from: String,
    to: Option<String>,
    cumulative_gas_used: String,
    gas_used: String,
    contract_address: Option<String>,
    logs: Vec<String>,
    status: String,
    effective_gas_price: String,
    tx_type: String,
    logs_bloom: String,
}

#[derive(Debug, Clone)]
struct StoredTransaction {
    envelope: TxEnvelope,
    raw_data: Vec<u8>, // Raw transaction data for hash calculation
    block_number: u64,
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
    bitcoin_block_hash: Option<String>, // Reference to Bitcoin block
    bitcoin_block_height: Option<u64>,
}

impl CoreLaneBlock {
    fn new(
        number: u64,
        parent_hash: B256,
        timestamp: u64,
        bitcoin_block_hash: Option<String>,
        bitcoin_block_height: Option<u64>,
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
            bitcoin_block_hash,
            bitcoin_block_height,
        }
    }

    fn genesis() -> Self {
        let mut block = Self::new(
            0,
            B256::default(), // Genesis has no parent
            1704067200,      // January 1, 2024 00:00:00 UTC
            None,
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
    account_manager: AccountManager,
    transactions: Vec<StoredTransaction>, // Store both envelope and raw data
    transaction_receipts: HashMap<String, TransactionReceipt>, // Store transaction receipts
    last_processed_block: u64,
    blocks: HashMap<u64, CoreLaneBlock>,  // Block number -> Block
    block_hashes: HashMap<B256, u64>,     // Block hash -> Block number
    current_block: Option<CoreLaneBlock>, // Current block being built
    genesis_block: CoreLaneBlock,         // Genesis block
    intents: HashMap<B256, Intent>,
    bitcoin_client: Arc<Client>,
    stored_blobs: HashSet<B256>,
}

impl CoreLaneState {
    pub fn bitcoin_client(&self) -> Arc<Client> {
        self.bitcoin_client.clone()
    }
}

struct CoreLaneNode {
    bitcoin_client: Arc<Client>,
    state: Arc<Mutex<CoreLaneState>>,
}

impl CoreLaneNode {
    fn new(bitcoin_client: Client) -> Self {
        let genesis_block = CoreLaneBlock::genesis();
        let genesis_hash = genesis_block.hash;

        let mut blocks = HashMap::new();
        let mut block_hashes = HashMap::new();
        let bitcoin_client = Arc::new(bitcoin_client);

        // Store genesis block
        blocks.insert(0, genesis_block.clone());
        block_hashes.insert(genesis_hash, 0);

        let state = Arc::new(Mutex::new(CoreLaneState {
            account_manager: AccountManager::new(),
            transactions: Vec::new(),
            transaction_receipts: HashMap::new(),
            last_processed_block: 0,
            blocks,
            block_hashes,
            current_block: None,
            genesis_block,
            intents: HashMap::new(),
            bitcoin_client: bitcoin_client.clone(),
            stored_blobs: HashSet::new(),
        }));

        Self {
            bitcoin_client: bitcoin_client.clone(),
            state,
        }
    }

    async fn create_new_block(
        &self,
        bitcoin_block_hash: String,
        bitcoin_block_height: u64,
        bitcoin_block_timestamp: u64,
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

        // Create new block with Bitcoin block timestamp
        let mut new_block = CoreLaneBlock::new(
            next_number,
            parent_hash,
            bitcoin_block_timestamp,
            Some(bitcoin_block_hash),
            Some(bitcoin_block_height),
        );

        // Calculate hash
        new_block.hash = new_block.calculate_hash();
        // Set as current block
        info!(
            "🆕 Created Core Lane block {} (parent: {}) with timestamp {}",
            next_number, latest_number, bitcoin_block_timestamp
        );
        Ok(new_block)
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

        for (stored_tx, receipt, tx_hash) in transactions {
            state.transactions.push(stored_tx);
            state.transaction_receipts.insert(tx_hash, receipt);
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
        let tip = self.bitcoin_client.get_block_count()?;

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
            match self.process_block(height).await {
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

    async fn process_block(&self, height: u64) -> Result<()> {
        let hash = self.bitcoin_client.get_block_hash(height)?;
        let block = self.bitcoin_client.get_block(&hash)?;

        info!(
            "📦 Processing Bitcoin block {} with {} transactions",
            height,
            block.txdata.len()
        );

        let mut burn_transactions_found = 0;
        let mut da_transactions_found = 0;
        let mut core_lane_transactions = Vec::new();
        // Create a new Core Lane block for this Bitcoin block
        let bitcoin_block_hash = hash.to_string();
        let bitcoin_block_timestamp = block.header.time as u64;
        info!(
            "📅 Using Bitcoin block timestamp: {} (block {})",
            bitcoin_block_timestamp, height
        );
        let new_block = self
            .create_new_block(bitcoin_block_hash, height, bitcoin_block_timestamp)
            .await?;

        // Phase 1: Process ALL Bitcoin burns first to mint Core Lane tokens
        debug!("🔥 Phase 1: Processing Bitcoin burns...");
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            let txid = tx.compute_txid();

            if let Some((payload, burn_value)) = self.extract_burn_payload_from_tx(&tx) {
                burn_transactions_found += 1;
                info!(
                    "   🔥 Found Bitcoin burn in tx {}: {} ({}sats)",
                    tx_index, txid, burn_value
                );
                self.process_bitcoin_burn(payload, burn_value, txid.to_string(), "regtest")
                    .await?;
            }
        }
        let mut tx_count = 0;
        // Phase 2: Process ALL Core Lane DA transactions after all burns are complete
        debug!("🔍 Phase 2: Processing Core Lane DA transactions...");
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            let txid = tx.compute_txid();

            if let Some(lane_tx) = self.extract_core_lane_transaction(tx) {
                da_transactions_found += 1;
                info!(
                    "   🔍 Found Core Lane DA transaction in tx {}: {}",
                    tx_index, txid
                );
                let tx = self
                    .process_core_lane_transaction(lane_tx, new_block.number, tx_count)
                    .await;
                if let Some((stored_tx, receipt, tx_hash)) = tx {
                    core_lane_transactions.push((stored_tx, receipt, tx_hash));
                    tx_count += 1;
                }
            }
        }

        // Finalize the Core Lane block
        self.finalize_current_block(core_lane_transactions, new_block)
            .await?;

        if burn_transactions_found > 0 {
            info!(
                "   🔥 Found {} Bitcoin burn transactions in block {}",
                burn_transactions_found, height
            );
        }
        if da_transactions_found > 0 {
            info!(
                "   ✅ Found {} Core Lane DA transactions in block {}",
                da_transactions_found, height
            );
        }
        if burn_transactions_found == 0 && da_transactions_found == 0 {
            debug!("   ℹ️  No Core Lane activity found in block {}", height);
        }

        info!(
            "🏁 Finalized Core Lane block for Bitcoin block {} with {} total transactions",
            height,
            burn_transactions_found + da_transactions_found
        );

        Ok(())
    }

    fn extract_core_lane_transaction(&self, tx: &Transaction) -> Option<Vec<u8>> {
        // Look for Core Lane transactions in Bitcoin DA envelopes
        // Check inputs for witness data (revealed Taproot envelopes)
        for (input_idx, input) in tx.input.iter().enumerate() {
            if input.witness.len() >= 2 {
                trace!(
                    "   🔍 Input {} has witness with {} elements",
                    input_idx,
                    input.witness.len()
                );

                // Debug: print witness elements
                for (i, witness_elem) in input.witness.to_vec().iter().enumerate() {
                    trace!("     Witness[{}]: {} bytes", i, witness_elem.len());
                    if witness_elem.len() < 100 {
                        trace!("     Witness[{}] hex: {}", i, hex::encode(witness_elem));
                    } else if witness_elem.len() >= 50 {
                        // This might be our Core Lane envelope script
                        trace!(
                            "     Witness[{}] (first 50 bytes): {}",
                            i,
                            hex::encode(&witness_elem[..50])
                        );
                        if witness_elem.len() >= 100 {
                            trace!(
                                "     Witness[{}] (last 50 bytes): {}",
                                i,
                                hex::encode(&witness_elem[witness_elem.len() - 50..])
                            );
                        }
                    }
                }

                if let Some(script_bytes) = input.witness.to_vec().get(0) {
                    let script = Script::from_bytes(script_bytes);

                    // Use the bitcoin-data-layer extraction logic
                    if let Some(data) = self.extract_envelope_data_bitcoin_da_style(&script) {
                        // If we got data back, it means we found a Core Lane transaction
                        if !data.is_empty() {
                            info!("   🎯 Found Core Lane transaction in Taproot envelope!");
                            return Some(data);
                        }
                    }
                }
            }
        }

        // Also check outputs (for newly created Taproot envelopes)
        for output in &tx.output {
            // For Taproot outputs, we need to check if this is a P2TR address
            // and then try to extract the embedded data
            let script_pubkey = &output.script_pubkey;

            // Check if this is a P2TR output
            if script_pubkey.as_bytes().len() == 34 && script_pubkey.as_bytes()[0] == 0x51 {
                // This is a P2TR output, but we can't directly extract the data
                // because it's committed in the Taproot tree
                // We'll need to look for the actual spend transaction later
                debug!("   🔍 Found P2TR output (potential Core Lane envelope)");
            }
        }

        None
    }

    // Use the bitcoin-data-layer extraction logic but be more selective about data extraction
    fn extract_envelope_data_bitcoin_da_style(&self, script: &Script) -> Option<Vec<u8>> {
        let mut instr = script.instructions();

        let first = instr.next().and_then(|r| r.ok());
        if first != Some(Instruction::Op(OP_FALSE))
            && first
                != Some(Instruction::PushBytes(
                    bitcoin::blockdata::script::PushBytes::empty(),
                ))
        {
            return None;
        }

        if instr.next().and_then(|r| r.ok()) != Some(Instruction::Op(OP_IF)) {
            return None;
        }

        // Collect all push operations between OP_IF and OP_ENDIF
        let mut push_operations: Vec<Vec<u8>> = Vec::new();
        loop {
            match instr.next().and_then(|r| r.ok()) {
                Some(Instruction::Op(OP_ENDIF)) => break,
                Some(Instruction::PushBytes(b)) => {
                    push_operations.push(b.as_bytes().to_vec());
                }
                _ => return None,
            }
        }

        let last = instr.next().and_then(|r| r.ok());
        if last != Some(Instruction::Op(OP_TRUE))
            && last
                != Some(Instruction::Op(
                    bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1,
                ))
        {
            return None;
        }

        trace!(
            "   🔍 Script analysis: found {} push operations",
            push_operations.len()
        );
        for (i, push_op) in push_operations.iter().enumerate() {
            trace!("     Push[{}]: {} bytes", i, push_op.len());
            if push_op.len() < 100 {
                trace!("     Push[{}] hex: {}", i, hex::encode(push_op));
            } else {
                trace!(
                    "     Push[{}] (first 50): {}",
                    i,
                    hex::encode(&push_op[..50])
                );
                trace!(
                    "     Push[{}] (last 50): {}",
                    i,
                    hex::encode(&push_op[push_op.len() - 50..])
                );
            }
        }

        // Concatenate all push operations to get the complete data
        let mut data: Vec<u8> = Vec::new();
        for push_op in push_operations {
            data.extend_from_slice(&push_op);
        }

        trace!("   🔍 Concatenated data: {} bytes", data.len());
        if data.len() < 100 {
            trace!("   🔍 Concatenated hex: {}", hex::encode(&data));
        } else {
            trace!(
                "   🔍 Concatenated (first 50): {}",
                hex::encode(&data[..50])
            );
            trace!(
                "   🔍 Concatenated (last 50): {}",
                hex::encode(&data[data.len() - 50..])
            );
        }

        // For Core Lane, check if the concatenated data starts with "CORE_LANE"
        if data.starts_with(b"CORE_LANE") {
            // Return just the transaction data (after CORE_LANE prefix)
            let tx_data = &data[9..];

            // Remove padding from the end (look for 0xf0 padding pattern)
            let mut clean_end = tx_data.len();
            for i in (0..tx_data.len()).rev() {
                if tx_data[i] == 0xf0 {
                    clean_end = i;
                } else {
                    break;
                }
            }

            let clean_tx_data = &tx_data[..clean_end];
            trace!(
                "   🔍 Extracted transaction data: {} bytes (removed {} padding bytes)",
                clean_tx_data.len(),
                tx_data.len() - clean_tx_data.len()
            );
            if clean_tx_data.len() < 100 {
                trace!("   🔍 Transaction hex: {}", hex::encode(clean_tx_data));
            } else {
                trace!(
                    "   🔍 Transaction (first 50): {}",
                    hex::encode(&clean_tx_data[..50])
                );
                trace!(
                    "   🔍 Transaction (last 50): {}",
                    hex::encode(&clean_tx_data[clean_tx_data.len() - 50..])
                );
            }

            return Some(clean_tx_data.to_vec());
        }

        Some(data)
    }

    /// Extract burn payload from Bitcoin transaction (BRN1 format)
    fn extract_burn_payload_from_tx(&self, tx: &Transaction) -> Option<(Vec<u8>, u64)> {
        // Look for hybrid P2WSH + OP_RETURN burn pattern
        let mut p2wsh_burn_value = 0u64;
        let mut brn1_payload = None;

        for output in &tx.output {
            // Check for P2WSH burn outputs
            if self.is_p2wsh_script(&output.script_pubkey) {
                let burnt_value = output.value.to_sat();
                if burnt_value > 0 {
                    p2wsh_burn_value = burnt_value;
                    debug!("   🔍 Found P2WSH burn output: {} sats", burnt_value);
                }
            }

            // Check for OP_RETURN with BRN1 data
            if self.is_op_return_script(&output.script_pubkey) {
                let payload_bytes = output.script_pubkey.as_bytes();

                // OP_RETURN script structure: [OP_RETURN] [push_opcode] [data...]
                if payload_bytes.len() >= 30 && payload_bytes[0] == 0x6a {
                    let data = &payload_bytes[2..]; // Skip OP_RETURN and push opcode

                    // Check for BRN1 prefix
                    if data.len() >= 28 && &data[0..4] == b"BRN1" {
                        let mut payload = Vec::with_capacity(28);
                        payload.extend_from_slice(b"BRN1");
                        payload.extend_from_slice(&data[4..8]); // chain_id
                        payload.extend_from_slice(&data[8..28]); // eth_address
                        brn1_payload = Some(payload);
                        debug!("   🔍 Found BRN1 data in OP_RETURN");
                    }
                }
            }
        }

        // If we found both P2WSH burn and BRN1 data, this is our hybrid burn
        if p2wsh_burn_value > 0 && brn1_payload.is_some() {
            info!(
                "   ✅ Found hybrid P2WSH + OP_RETURN burn: {} sats",
                p2wsh_burn_value
            );
            return Some((brn1_payload.unwrap(), p2wsh_burn_value));
        }

        // Fallback: legacy OP_RETURN only burns
        for output in &tx.output {
            if self.is_op_return_script(&output.script_pubkey) {
                let payload_bytes = output.script_pubkey.as_bytes();

                if payload_bytes.len() >= 30 && payload_bytes[0] == 0x6a {
                    let data = &payload_bytes[2..];

                    if data.len() >= 28 && &data[0..4] == b"BRN1" {
                        let mut payload = Vec::with_capacity(28);
                        payload.extend_from_slice(b"BRN1");
                        payload.extend_from_slice(&data[4..8]);
                        payload.extend_from_slice(&data[8..28]);

                        let burnt_value = self.calculate_intended_burn_amount(tx);
                        return Some((payload, burnt_value));
                    }
                }
            }
        }

        None
    }

    /// Check if script is OP_RETURN
    fn is_op_return_script(&self, script: &Script) -> bool {
        let mut instr = script.instructions();
        if let Some(Ok(Instruction::Op(op))) = instr.next() {
            op == OP_RETURN
        } else {
            false
        }
    }

    /// Check if script is P2WSH
    fn is_p2wsh_script(&self, script: &Script) -> bool {
        let bytes = script.as_bytes();
        // P2WSH: OP_0 (0x00) + 32-byte hash
        bytes.len() == 34 && bytes[0] == 0x00
    }

    /// Calculate the intended burn amount from transaction structure
    /// This is the amount that was intended to be burned, not including fees
    fn calculate_intended_burn_amount(&self, tx: &Transaction) -> u64 {
        // For BRN1 burns, we need to determine the intended burn amount
        // Since the OP_RETURN output has 0 value, we need to look at the transaction structure

        // Calculate total input value
        let mut total_input: u64 = 0;
        for input in &tx.input {
            match self
                .bitcoin_client
                .get_raw_transaction(&input.previous_output.txid, None)
            {
                Ok(prev_tx) => {
                    let prev_output = &prev_tx.output[input.previous_output.vout as usize];
                    total_input += prev_output.value.to_sat();
                }
                Err(e) => {
                    warn!(
                        "   ⚠️  Could not fetch previous transaction {}: {}",
                        input.previous_output.txid, e
                    );
                }
            }
        }

        // Calculate total spendable output (exclude OP_RETURN outputs)
        let total_spendable_output: u64 = tx
            .output
            .iter()
            .filter(|output| !output.script_pubkey.is_op_return())
            .map(|output| output.value.to_sat())
            .sum();

        // The intended burn amount is the difference between input and spendable output
        // This excludes the transaction fee
        if total_input > total_spendable_output {
            let intended_burn = total_input - total_spendable_output;
            info!(
                "   💰 Intended burn amount: {} sats (input: {} sats, spendable: {} sats)",
                intended_burn, total_input, total_spendable_output
            );
            intended_burn
        } else {
            warn!(
                "   ⚠️  No intended burn: {} sats input <= {} sats spendable output",
                total_input, total_spendable_output
            );
            0u64
        }
    }

    /// Process Bitcoin burn transaction and mint Core Lane tokens
    async fn process_bitcoin_burn(
        &self,
        payload: Vec<u8>,
        burn_value: u64,
        txid: String,
        _network: &str,
    ) -> Result<()> {
        // Extract chain ID and ETH address from BRN1 payload
        if payload.len() >= 28 && &payload[0..4] == b"BRN1" {
            let chain_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            let eth_address_bytes = &payload[8..28];
            let eth_address = Address::from_slice(eth_address_bytes);

            info!("🔥 Processing Bitcoin burn:");
            info!("   Transaction: {}", txid);
            info!("   Burnt value: {} sats", burn_value);
            info!("   Chain ID: {}", chain_id);
            info!("   ETH Address: {}", eth_address);

            // Check if this is for Core Lane (chain ID 1 for example)
            if chain_id == 1 {
                // Convert Bitcoin sats to Core Lane tokens with proper decimal scaling
                // Bitcoin: 1 BTC = 100,000,000 sats (8 decimals)
                // Core Lane: 1 CMEL = 10^18 wei (18 decimals)
                // Conversion: 1 sat = 10^10 wei (to maintain reasonable exchange rate)
                let conversion_factor = U256::from(10_000_000_000u64); // 10^10
                let mint_amount = U256::from(burn_value) * conversion_factor;

                info!(
                    "   🪙 Attempting to mint {} tokens to {}",
                    mint_amount, eth_address
                );

                debug!("   🔒 Acquiring state lock...");
                let mut state = self.state.lock().await;
                debug!("   🔓 State lock acquired, adding balance...");

                match state.account_manager.add_balance(eth_address, mint_amount) {
                    Ok(_) => {
                        info!(
                            "   ✅ Minted {} Core Lane tokens to {}",
                            mint_amount, eth_address
                        );
                        let new_balance = state.account_manager.get_balance(eth_address);
                        info!("   💰 New balance: {}", new_balance);
                        info!("   🎯 Minting successful! Balance updated.");
                    }
                    Err(e) => {
                        error!("   ❌ Failed to mint tokens: {}", e);
                        error!("   🔍 Error details: {:?}", e);
                    }
                }

                debug!("   🔓 Releasing state lock...");
            } else {
                warn!(
                    "   ⚠️  Burn for different chain ID ({}), ignoring",
                    chain_id
                );
            }
        } else {
            error!("   ❌ Invalid BRN1 payload format");
        }

        Ok(())
    }

    async fn process_core_lane_transaction(
        &self,
        tx_data: Vec<u8>,
        block_number: u64,
        tx_number: u64,
    ) -> Option<(StoredTransaction, TransactionReceipt, String)> {
        // The tx_data now contains the raw Ethereum transaction bytes (without CORE_LANE prefix)
        debug!(
            "   📝 Processing {} bytes of Ethereum transaction data",
            tx_data.len()
        );
        debug!("   📝 Full transaction hex: {}", hex::encode(&tx_data));

        // Try to parse as Ethereum transaction directly
        match TxEnvelope::decode(&mut tx_data.as_slice()) {
            Ok(tx) => {
                info!("✅ Successfully parsed Core Lane transaction!");

                // Print transaction details
                match &tx {
                    TxEnvelope::Legacy(_) => debug!("   Type: Legacy"),
                    TxEnvelope::Eip1559(_) => debug!("   Type: EIP-1559"),
                    TxEnvelope::Eip2930(_) => debug!("   Type: EIP-2930"),
                    TxEnvelope::Eip4844(_) => debug!("   Type: EIP-4844"),
                    _ => debug!("   Type: Other"),
                }

                // Validate the transaction
                if let Err(e) = validate_transaction(&tx) {
                    error!("   ❌ Transaction validation failed: {}", e);
                    return None;
                }
                debug!("   ✅ Transaction validation passed");

                // Recover sender address
                let sender = match recover_sender(&tx) {
                    Ok(addr) => {
                        info!("   📧 Sender: {}", addr);
                        addr
                    }
                    Err(e) => {
                        error!("   ❌ Failed to recover sender: {}", e);
                        return None;
                    }
                };

                let input_bytes = get_transaction_input_bytes(&tx);
                if !input_bytes.is_empty() {
                    if let Some(intent_call) = decode_intent_calldata(&input_bytes) {
                        info!("Decoded IntentSystem call: {:?}", intent_call);
                    }
                }
                let execution_result = {
                    let mut state = self.state.lock().await;
                    execute_transaction(&tx, sender, &mut state)
                };

                match execution_result {
                    Ok(result) => {
                        if result.success {
                            info!("   ✅ Transaction executed successfully!");
                            info!("      Gas used: {}", result.gas_used);
                            if let Some(error) = &result.error {
                                warn!("      Error: {}", error);
                            }
                            for log in &result.logs {
                                debug!("      📝 {}", log);
                            }

                            // Charge gas fees (using a reasonable gas price for testing)
                            let gas_fee = result.gas_used * U256::from(1000000000u64); // 1 gwei per gas
                            {
                                let mut state = self.state.lock().await;
                                if let Err(e) = state.account_manager.sub_balance(sender, gas_fee) {
                                    warn!("      ⚠️  Failed to charge gas fee: {}", e);
                                } else {
                                    info!("      💰 Charged gas fee: {} wei", gas_fee);
                                }
                            }
                        } else {
                            error!("   ❌ Transaction execution failed!");
                            if let Some(error) = &result.error {
                                error!("      Error: {}", error);
                            }
                            for log in &result.logs {
                                debug!("      📝 {}", log);
                            }
                        }
                    }
                    Err(e) => {
                        error!("   ❌ Transaction execution error: {}", e);
                    }
                }

                // Store the transaction with both envelope and raw data
                let state = self.state.lock().await;
                let stored_tx = StoredTransaction {
                    envelope: tx.clone(),
                    raw_data: tx_data.clone(),
                    block_number: block_number,
                };
                // Create and store transaction receipt
                let tx_hash = format!("0x{}", hex::encode(alloy_primitives::keccak256(&tx_data)));

                let receipt = TransactionReceipt {
                    transaction_hash: tx_hash.clone(),
                    block_number: block_number,
                    transaction_index: tx_number,
                    from: format!("0x{}", hex::encode(sender.as_slice())),
                    to: None, // Will be set based on transaction type
                    cumulative_gas_used: "0x0".to_string(),
                    gas_used: "0x0".to_string(),
                    contract_address: None,
                    logs: Vec::new(),
                    status: "0x1".to_string(), // Success
                    effective_gas_price: "0x3b9aca00".to_string(), // 1 gwei
                    tx_type: match &tx {
                        TxEnvelope::Legacy(_) => "0x0".to_string(),
                        TxEnvelope::Eip2930(_) => "0x1".to_string(),
                        TxEnvelope::Eip1559(_) => "0x2".to_string(),
                        TxEnvelope::Eip4844(_) => "0x3".to_string(),
                        _ => "0x0".to_string(),
                    },
                    logs_bloom: format!("0x{}", hex::encode(vec![0u8; 256])),
                };

                // Print account balances after execution
                debug!(
                    "   💰 Account balance after execution: {}",
                    state.account_manager.get_balance(sender)
                );
                Some((stored_tx.clone(), receipt.clone(), tx_hash.clone()))
            }
            Err(e) => {
                error!("❌ Failed to parse Ethereum transaction: {}", e);
                None
            }
        }
    }

    /// Create a Bitcoin burn transaction using RPC wallet
    async fn create_burn_transaction_from_wallet(
        &self,
        burn_amount: u64,
        chain_id: u32,
        eth_address: &str,
        wallet: &str,
        network: bitcoin::Network,
    ) -> Result<()> {
        info!(
            "🔥 Creating Bitcoin burn transaction using wallet '{}'...",
            wallet
        );

        // Validate ETH address
        let eth_addr = eth_address.trim_start_matches("0x").to_string();
        if eth_addr.len() != 40 {
            return Err(anyhow!("Ethereum address must be 20 bytes (40 hex chars)"));
        }

        // Create BRN1 payload
        let addr_bytes = hex::decode(&eth_addr)?;
        let mut payload = Vec::with_capacity(4 + 4 + 20);
        payload.extend_from_slice(b"BRN1");
        payload.extend_from_slice(&chain_id.to_be_bytes());
        payload.extend_from_slice(&addr_bytes);

        if payload.len() > 80 {
            return Err(anyhow!(
                "OP_RETURN payload {} bytes exceeds standard relay policy (80 bytes)",
                payload.len()
            ));
        }

        // Convert network string to Bitcoin Network enum

        info!("📋 Burn Details:");
        info!("   Wallet: {}", wallet);
        info!("   Network: {}", network.to_string());
        info!("   Burn amount: {} sats", burn_amount);
        info!("   Chain ID: {}", chain_id);
        info!("   ETH address: {}", eth_address);
        info!("   Payload: {} bytes", payload.len());

        // Check wallet balance
        let balance_result: Result<serde_json::Value, _> =
            self.bitcoin_client.call("getbalances", &[]);

        match balance_result {
            Ok(balances) => {
                if let Some(trusted) = balances.get(wallet).and_then(|m| m.get("trusted")) {
                    let balance_btc = trusted.as_f64().unwrap_or(0.0);
                    let balance_sats = (balance_btc * 100_000_000.0) as u64;
                    info!(
                        "💰 Wallet balance: {} sats ({:.8} BTC)",
                        balance_sats, balance_btc
                    );

                    if balance_sats < burn_amount + 1000 {
                        // +1000 for estimated fee
                        return Err(anyhow!(
                            "Insufficient balance. Have {} sats, need {} sats + fees",
                            balance_sats,
                            burn_amount
                        ));
                    }
                }
            }
            Err(e) => {
                warn!("⚠️  Could not check wallet balance: {}", e);
            }
        }

        info!("📡 Creating burn transaction...");

        // Get list of unspent outputs
        let unspent_result: Result<serde_json::Value, _> = self.bitcoin_client.call(
            "listunspent",
            &[
                serde_json::json!(0),
                serde_json::json!(9999999),
                serde_json::json!([]),
                serde_json::json!(true),
                serde_json::json!({"minimumAmount": (burn_amount as f64 + 1000.0) / 100_000_000.0}),
            ],
        );

        let unspent = match unspent_result {
            Ok(utxos) => utxos,
            Err(e) => return Err(anyhow!("Failed to get unspent outputs: {}", e)),
        };

        if !unspent.is_array() || unspent.as_array().unwrap().is_empty() {
            return Err(anyhow!("No suitable unspent outputs found for burn amount"));
        }

        // Use the first suitable UTXO
        let utxo = &unspent.as_array().unwrap()[0];
        let prev_txid = utxo["txid"].as_str().unwrap();
        let prev_vout = utxo["vout"].as_u64().unwrap() as u32;
        let prev_amount = (utxo["amount"].as_f64().unwrap() * 100_000_000.0) as u64;

        println!(
            "📍 Using UTXO: {}:{} ({} sats)",
            prev_txid, prev_vout, prev_amount
        );

        // Create inputs
        let _inputs = vec![serde_json::json!({
            "txid": prev_txid,
            "vout": prev_vout
        })];

        // Create OP_RETURN output
        let hex_payload = hex::encode(&payload);
        let _opreturn_script = format!("6a{:02x}{}", payload.len(), hex_payload);

        // Calculate change (input - burn_amount - estimated fee)
        let estimated_fee = 500u64; // 500 sats estimated fee
        let change_amount = prev_amount
            .saturating_sub(burn_amount)
            .saturating_sub(estimated_fee);

        // Create P2WSH burn transaction with OP_RETURN wrapped inside
        // This is the standard, reliable way to burn Bitcoin without turning it into fee
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::{
            blockdata::opcodes::all::OP_RETURN, blockdata::witness::Witness, Amount, OutPoint,
            ScriptBuf, Transaction, TxIn, TxOut,
        };

        // Create the burn script: OP_RETURN + BRN1 payload
        let payload_bytes = <&bitcoin::blockdata::script::PushBytes>::try_from(&payload[..])
            .map_err(|_| anyhow!("Payload too large for OP_RETURN"))?;
        let burn_script = ScriptBuf::builder()
            .push_opcode(OP_RETURN)
            .push_slice(payload_bytes)
            .into_script();

        // Create P2WSH address from the burn script
        let script_hash = sha256::Hash::hash(burn_script.as_bytes());
        let wscript_hash =
            bitcoin::blockdata::script::WScriptHash::from_slice(&script_hash.to_byte_array())?;
        let p2wsh_address = bitcoin::Address::p2wsh(&ScriptBuf::new_p2wsh(&wscript_hash), network);

        info!("🔥 Created P2WSH burn address: {}", p2wsh_address);
        debug!("📝 Burn script: {}", burn_script);

        // Create transaction outputs
        let mut tx_outputs = Vec::new();

        // Add P2WSH burn output with the burn amount
        tx_outputs.push(TxOut {
            value: Amount::from_sat(burn_amount),
            script_pubkey: p2wsh_address.script_pubkey(),
        });

        // Add 0-value OP_RETURN output with BRN1 data
        let opret_script = ScriptBuf::builder()
            .push_opcode(OP_RETURN)
            .push_slice(payload_bytes)
            .into_script();
        tx_outputs.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: opret_script,
        });

        // Add change output if substantial enough
        if change_amount > 546 {
            // dust threshold
            let change_addr_result: Result<serde_json::Value, _> = self.bitcoin_client.call(
                "getnewaddress",
                &[serde_json::json!(wallet), serde_json::json!("bech32")],
            );

            if let Ok(change_addr) = change_addr_result {
                let change_addr_str = change_addr.as_str().unwrap();
                let change_address =
                    bitcoin::Address::from_str(change_addr_str)?.require_network(network)?;
                tx_outputs.push(TxOut {
                    value: Amount::from_sat(change_amount),
                    script_pubkey: change_address.script_pubkey(),
                });
                info!("💰 Change: {} sats -> {}", change_amount, change_addr_str);
            }
        }

        // Create transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_str(prev_txid)?,
                    vout: prev_vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: Witness::new(),
            }],
            output: tx_outputs,
        };

        // Get the raw transaction hex
        let raw_tx = hex::encode(bitcoin::consensus::serialize(&tx));

        // Now we need to sign the transaction using the wallet
        // We'll use the signrawtransactionwithwallet RPC call

        // Sign the transaction
        let signed_result: Result<serde_json::Value, _> = self
            .bitcoin_client
            .call("signrawtransactionwithwallet", &[serde_json::json!(raw_tx)]);

        let signed_tx = match signed_result {
            Ok(result) => {
                if result["complete"].as_bool().unwrap_or(false) {
                    result["hex"].as_str().unwrap().to_string()
                } else {
                    return Err(anyhow!("Failed to sign transaction: {}", result["errors"]));
                }
            }
            Err(e) => return Err(anyhow!("Failed to sign transaction: {}", e)),
        };

        // Broadcast the transaction
        let tx_result: Result<bitcoin::Txid, _> = self
            .bitcoin_client
            .call("sendrawtransaction", &[serde_json::json!(signed_tx)]);

        match tx_result {
            Ok(txid) => {
                info!("✅ Burn transaction created and broadcast successfully!");
                info!("📍 Transaction ID: {}", txid);
                info!("🔥 Burned: {} sats", burn_amount);
                info!("🎯 Chain ID: {}", chain_id);
                info!("📫 ETH Address: 0x{}", eth_address);
                info!("🪙 Core Lane will automatically mint {} tokens to 0x{} when this transaction is confirmed!", burn_amount, eth_address);
                info!("🔍 Monitor with: ./target/debug/core-mel-node start --start-block {} --rpc-password {}", "latest", "bitcoin123");
            }
            Err(e) => {
                // Try alternative approach with raw transaction if sendmany fails
                error!("❌ sendmany failed: {}", e);
                warn!("💡 Try using a manual approach with listunspent and createrawtransaction");
                return Err(anyhow!("Failed to create burn transaction: {}", e));
            }
        }

        Ok(())
    }

    async fn send_transaction_to_da(
        &self,
        raw_tx_hex: &str,
        wallet: &str,
        network: bitcoin::Network,
    ) -> Result<()> {
        // Delegate to the TaprootDA implementation which handles all validation and logic
        let taproot_da = TaprootDA::new(self.bitcoin_client.clone());
        let _bitcoin_txid = taproot_da
            .send_transaction_to_da(raw_tx_hex, wallet, network)
            .await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "core_lane_node=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Core Lane Node");

    let cli = Cli::parse();

    match &cli.command {
        Commands::Start {
            rpc_url,
            rpc_user,
            rpc_password,
            start_block,
            http_host,
            http_port,
            rpc_wallet,
        } => {
            let wallet = rpc_wallet.to_string();
            let client = bitcoincore_rpc::Client::new(
                &format!("{}/wallet/{}", rpc_url, rpc_wallet),
                Auth::UserPass(rpc_user.to_string(), rpc_password.to_string()),
            )?;
            let blockchain_info: serde_json::Value = client.call("getblockchaininfo", &[])?;

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
            let node = CoreLaneNode::new(client);

            // Start HTTP server for JSON-RPC - share the same state
            let shared_state = Arc::clone(&node.state);
            let rpc_server = RpcServer::with_bitcoin_client(
                shared_state,
                node.bitcoin_client.clone(),
                network,
                wallet,
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
            rpc_wallet,
            rpc_url,
            rpc_user,
            rpc_password,
        } => {
            // add /wallet/<rpc_wallet> to the rpc_url
            let rpc_url = format!("{}/wallet/{}", rpc_url, rpc_wallet);
            let client = bitcoincore_rpc::Client::new(
                &rpc_url,
                Auth::UserPass(rpc_user.to_string(), rpc_password.to_string()),
            )?;

            let blockchain_info: serde_json::Value = client.call("getblockchaininfo", &[])?;

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
            let node = CoreLaneNode::new(client);
            node.create_burn_transaction_from_wallet(
                *burn_amount,
                *chain_id,
                eth_address,
                rpc_wallet,
                network,
            )
            .await?;
        }

        Commands::SendTransaction {
            raw_tx_hex,
            rpc_wallet,
            rpc_url,
            rpc_user,
            rpc_password,
        } => {
            let client = bitcoincore_rpc::Client::new(
                rpc_url,
                Auth::UserPass(rpc_user.to_string(), rpc_password.to_string()),
            )?;

            let blockchain_info: serde_json::Value = client.call("getblockchaininfo", &[])?;

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

            let node = CoreLaneNode::new(client);
            node.send_transaction_to_da(raw_tx_hex, rpc_wallet, network)
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
    }

    Ok(())
}
