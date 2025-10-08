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
mod block;
mod rpc;
mod bitcoin_block;
mod taproot_da;
mod transaction;

#[cfg(test)]
mod tests;

use account::AccountManager;
use alloy_consensus::{TxEnvelope};
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Decodable;
use intents::{create_anchor_bitcoin_fill_intent, Intent};
use rpc::RpcServer;
use taproot_da::TaprootDA;
use transaction::{
    execute_transaction,
};

use crate::{bitcoin_block::process_bitcoin_block, block::CoreLaneBlockParsed};

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


        let anchor_block_timestamp = if let Some(ref block_origin) = block_origin { block_origin.anchor_block_timestamp } else { 0 };

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

        for (stored_tx, receipt, tx_hash) in transactions.clone() {
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
            let bitcoin_block = process_bitcoin_block(self.bitcoin_client.clone(), height)?;
            
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
        let new_block = self
            .create_new_block(Some(bitcoin_block))
            .await?;

        let new_block_clone = new_block.clone();
        let mut core_lane_transactions = Vec::new();

        if let Some(block_origin) = new_block_clone.block_origin {
            debug!("🔥 Phase 1: Processing burns...");
            for burn in  block_origin.burns.iter() {
                let mut state = self.state.lock().await;
                info!("🪙 Minting {} tokens to {}", burn.amount, burn.address);
                state.account_manager.add_balance(burn.address, burn.amount)?;
            }
            let mut tx_count = 0;
            for bundle in block_origin.bundles.iter() {
                if bundle.valid_for_block != u64::MAX && bundle.valid_for_block != new_block.number {
                    // skip this bundle because it's not valid for this block
                    continue;
                }
                for (tx_index, tx) in bundle.transactions.iter().enumerate() {
                    let tx = self
                        .process_core_lane_transaction(tx, new_block.number, tx_count)
                        .await;
                    if let Some((stored_tx, receipt, tx_hash)) = tx {
                        core_lane_transactions.push((stored_tx, receipt, tx_hash));
                        tx_count += 1;
                    }
                }
            }
    
        }
        // Finalize the Core Lane block
        self.finalize_current_block(core_lane_transactions, new_block)
            .await?;                
        // Phase 1: Process ALL Bitcoin burns first to mint Core Lane tokens

        Ok(())
    }

    async fn process_core_lane_transaction(
        &self,
        tx: &(TxEnvelope, Address, Vec<u8>),
        block_number: u64,
        tx_number: u64,
    ) -> Option<(StoredTransaction, TransactionReceipt, String)> {
        let gas_price = U256::from(214285714u64);
        // charge gas fee first, we return unused gas later
        {
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
                warn!("      ⚠️  Non-EIP 1559 or legacy transactions are not supported, skipping: {:?}", tx.0);
                return None;
            }
            let gas_fee =  gas_price * U256::from(alloy_consensus::Transaction::gas_limit(&tx.0) as u64);
            if let Err(e) = state.account_manager.sub_balance(tx.1, gas_fee) {
                warn!("      ⚠️  Failed to charge gas fee ahead of tx execution: {}", e);
                return None;
            } else {
                info!("      💰 Charged gas fee: {} wei", gas_fee);
            }
        }

        let _execution_result = {
            let mut state = self.state.lock().await;
            execute_transaction(&tx.0, tx.1, &mut state)
        };

        // XXX add gas refund later

        // Store the transaction with both envelope and raw data
        let state = self.state.lock().await;
        let stored_tx = StoredTransaction {
            envelope: tx.0.clone(),
            raw_data: tx.2.clone(),
            block_number: block_number,
        };
        // Create and store transaction receipt
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

        // Print account balances after execution
        debug!(
            "   💰 Account balance after execution: {}",
            state.account_manager.get_balance(tx.1)
        );
        Some((stored_tx.clone(), receipt.clone(), tx_hash.clone()))
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
