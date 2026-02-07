use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Decodable;
use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;

use crate::account::CoreLaneAccount;
use crate::intents::Intent;

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Log {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "transactionIndex")]
    pub transaction_index: String,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "logIndex")]
    pub log_index: String,
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TransactionReceipt {
    pub transaction_hash: String,
    pub block_number: u64,
    pub transaction_index: u64,
    pub from: String,
    pub to: Option<String>,
    pub cumulative_gas_used: String,
    pub gas_used: String,
    pub contract_address: Option<String>,
    pub logs: Vec<Log>,
    pub status: String,
    pub effective_gas_price: String,
    pub tx_type: String,
    pub logs_bloom: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTransaction {
    pub envelope: TxEnvelope,
    pub raw_data: Vec<u8>, // Raw transaction data for hash calculation
    pub block_number: u64,
}

impl BorshSerialize for StoredTransaction {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // Serialize raw_data and block_number
        // The envelope can be reconstructed from raw_data
        BorshSerialize::serialize(&self.raw_data, writer)?;
        BorshSerialize::serialize(&self.block_number, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for StoredTransaction {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // Use deserialize_reader, NOT from_reader: from_reader uses try_from_reader which
        // requires no bytes remain after deserializing. We're in the middle of deserializing
        // StateManager (transactions Vec); block_number and more data follow.
        let raw_data: Vec<u8> = borsh::BorshDeserialize::deserialize_reader(reader)?;
        let block_number: u64 = borsh::BorshDeserialize::deserialize_reader(reader)?;

        // Reconstruct envelope from raw_data
        let envelope = TxEnvelope::decode(&mut raw_data.as_slice())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(StoredTransaction {
            envelope,
            raw_data,
            block_number,
        })
    }
}

/// State manager for Core Lane
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Default)]
pub struct StateManager {
    accounts: BTreeMap<Address, CoreLaneAccount>,
    stored_blobs: BTreeMap<B256, Vec<u8>>,
    kv_storage: BTreeMap<String, Vec<u8>>,
    intents: BTreeMap<B256, Intent>,
    transactions: Vec<StoredTransaction>,
    transaction_receipts: BTreeMap<String, TransactionReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Default)]
pub struct BundleStateManager {
    pub accounts: BTreeMap<Address, CoreLaneAccount>,
    pub stored_blobs: BTreeMap<B256, Vec<u8>>,
    pub kv_storage: BTreeMap<String, Vec<u8>>,
    pub removed_keys: Vec<String>,
    pub intents: BTreeMap<B256, Intent>,
    pub transactions: Vec<StoredTransaction>,
    pub transaction_receipts: BTreeMap<String, TransactionReceipt>,
}

#[allow(dead_code)]
impl BundleStateManager {
    pub fn new() -> Self {
        Self::default()
    }

    // XXX in future this may be a expired blob?
    pub fn contains_blob(&self, original: &StateManager, blob_hash: &B256) -> bool {
        self.stored_blobs.contains_key(blob_hash) || original.contains_blob(blob_hash)
    }

    pub fn insert_blob(&mut self, blob_hash: B256, data: Vec<u8>) {
        self.stored_blobs.insert(blob_hash, data);
    }

    pub fn get_kv(&self, key: &str) -> Option<&Vec<u8>> {
        self.kv_storage.get(key)
    }

    pub fn insert_kv(&mut self, key: String, value: Vec<u8>) {
        self.kv_storage.insert(key.clone(), value);
        self.removed_keys.retain(|k| k != &key);
    }

    pub fn remove_kv(&mut self, key: &str) -> Option<Vec<u8>> {
        let removed = self.kv_storage.remove(key);
        let key_string = key.to_string();
        if !self.removed_keys.iter().any(|k| k == &key_string) {
            self.removed_keys.push(key_string);
        }
        removed
    }

    pub fn get_intent<'a>(
        &'a self,
        original: &'a StateManager,
        intent_id: &B256,
    ) -> Option<&'a Intent> {
        self.intents
            .get(intent_id)
            .or_else(|| original.get_intent(intent_id))
    }

    pub fn get_intent_mut(
        &mut self,
        original: &StateManager,
        intent_id: &B256,
    ) -> Option<&mut Intent> {
        // Ensure the intent exists in our bundle before getting a mutable reference
        if !self.intents.contains_key(intent_id) {
            if let Some(orig_intent) = original.get_intent(intent_id) {
                self.intents.insert(*intent_id, orig_intent.clone());
            } else {
                return None;
            }
        }
        self.intents.get_mut(intent_id)
    }

    pub fn insert_intent(&mut self, intent_id: B256, intent: Intent) {
        self.intents.insert(intent_id, intent);
    }

    pub fn add_transaction(&mut self, transaction: StoredTransaction) {
        self.transactions.push(transaction);
    }

    pub fn add_receipt(&mut self, tx_hash: String, receipt: TransactionReceipt) {
        self.transaction_receipts.insert(tx_hash, receipt);
    }

    pub fn get_account<'a>(
        &'a self,
        original: &'a StateManager,
        address: Address,
    ) -> Option<&'a CoreLaneAccount> {
        self.accounts
            .get(&address)
            .or_else(|| original.get_account(address))
    }

    pub fn get_account_mut(
        &mut self,
        original: &StateManager,
        address: Address,
    ) -> Option<&mut CoreLaneAccount> {
        // Ensure the account exists in our bundle before getting a mutable reference
        self.accounts.entry(address).or_insert_with(|| {
            original
                .get_account(address)
                .cloned()
                .unwrap_or_else(CoreLaneAccount::new)
        });

        // Now get the mutable reference (account definitely exists)
        self.accounts.get_mut(&address)
    }

    fn set_account(
        &mut self,
        _original: &StateManager,
        address: Address,
        account: CoreLaneAccount,
    ) {
        self.accounts.insert(address, account);
    }

    pub fn get_balance(&self, original: &StateManager, address: Address) -> U256 {
        if let Some(account) = self.accounts.get(&address) {
            return account.balance;
        }
        original.get_balance(address)
    }

    pub fn get_nonce(&self, original: &StateManager, address: Address) -> U256 {
        if let Some(account) = self.accounts.get(&address) {
            return account.nonce;
        }
        original.get_nonce(address)
    }

    pub fn add_balance(
        &mut self,
        original: &StateManager,
        address: Address,
        amount: U256,
    ) -> Result<()> {
        let account = self.get_account_mut(original, address);
        if let Some(account) = account {
            account.add_balance(amount)?;
        } else {
            let mut account = CoreLaneAccount::new();
            account.add_balance(amount)?;
            self.accounts.insert(address, account);
        }
        Ok(())
    }

    pub fn sub_balance(
        &mut self,
        original: &StateManager,
        address: Address,
        amount: U256,
    ) -> Result<()> {
        let account = self.get_account_mut(original, address);
        if let Some(account) = account {
            account.sub_balance(amount)?;
        } else {
            return Err(anyhow::anyhow!("Account not found"));
        }
        Ok(())
    }

    pub fn increment_nonce(&mut self, original: &StateManager, address: Address) -> Result<()> {
        let account = self.get_account_mut(original, address);
        if let Some(account) = account {
            account.increment_nonce()?;
        } else {
            let mut account = CoreLaneAccount::new();
            account.increment_nonce()?;
            self.accounts.insert(address, account);
        }
        Ok(())
    }

    /// Serialize the BundleStateManager to a writer using bincode
    pub fn serialize_to_writer<W: Write>(&self, writer: &mut W) -> Result<()> {
        bincode::serialize_into(writer, self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize BundleStateManager: {}", e))
    }

    /// Deserialize a BundleStateManager from a reader using bincode
    pub fn deserialize_from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        bincode::deserialize_from(reader)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize BundleStateManager: {}", e))
    }

    /// Serialize the BundleStateManager to a writer using borsh
    pub fn borsh_serialize_to_writer<W: Write>(&self, writer: &mut W) -> Result<()> {
        borsh::to_writer(writer, self)
            .map_err(|e| anyhow::anyhow!("Failed to borsh serialize BundleStateManager: {}", e))
    }

    /// Deserialize a BundleStateManager from a reader using borsh
    pub fn borsh_deserialize_from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        borsh::from_reader(reader)
            .map_err(|e| anyhow::anyhow!("Failed to borsh deserialize BundleStateManager: {}", e))
    }

    /// Serialize the BundleStateManager to a byte vector using borsh
    pub fn borsh_serialize(&self) -> Result<Vec<u8>> {
        borsh::to_vec(self)
            .map_err(|e| anyhow::anyhow!("Failed to borsh serialize BundleStateManager: {}", e))
    }

    /// Deserialize a BundleStateManager from a byte slice using borsh
    pub fn borsh_deserialize(bytes: &[u8]) -> Result<Self> {
        borsh::from_slice(bytes)
            .map_err(|e| anyhow::anyhow!("Failed to borsh deserialize BundleStateManager: {}", e))
    }
}

impl StateManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_account(&self, address: Address) -> Option<&CoreLaneAccount> {
        self.accounts.get(&address)
    }

    pub fn contains_blob(&self, blob_hash: &B256) -> bool {
        self.stored_blobs.contains_key(blob_hash)
    }

    pub fn get_blob(&self, blob_hash: &B256) -> Option<&Vec<u8>> {
        self.stored_blobs.get(blob_hash)
    }

    pub fn insert_blob(&mut self, blob_hash: B256, data: Vec<u8>) {
        self.stored_blobs.insert(blob_hash, data);
    }

    pub fn get_intent(&self, intent_id: &B256) -> Option<&Intent> {
        self.intents.get(intent_id)
    }

    pub fn insert_intent(&mut self, intent_id: B256, intent: Intent) {
        self.intents.insert(intent_id, intent);
    }

    pub fn add_transaction(&mut self, transaction: StoredTransaction) {
        self.transactions.push(transaction);
    }

    pub fn add_receipt(&mut self, tx_hash: String, receipt: TransactionReceipt) {
        self.transaction_receipts.insert(tx_hash, receipt);
    }

    pub fn get_transactions(&self) -> &Vec<StoredTransaction> {
        &self.transactions
    }

    pub fn accounts_count(&self) -> usize {
        self.accounts.len()
    }

    pub fn get_receipt(&self, tx_hash: &str) -> Option<&TransactionReceipt> {
        self.transaction_receipts.get(tx_hash)
    }

    pub fn set_account(&mut self, address: Address, account: CoreLaneAccount) {
        self.accounts.insert(address, account);
    }

    pub fn get_balance(&self, address: Address) -> U256 {
        self.accounts
            .get(&address)
            .map(|acc| acc.balance)
            .unwrap_or(U256::ZERO)
    }

    pub fn get_nonce(&self, address: Address) -> U256 {
        self.accounts
            .get(&address)
            .map(|acc| acc.nonce)
            .unwrap_or(U256::ZERO)
    }

    pub fn get_kv(&self, key: &str) -> Option<&Vec<u8>> {
        self.kv_storage.get(key)
    }

    pub fn insert_kv(&mut self, key: String, value: Vec<u8>) {
        self.kv_storage.insert(key, value);
    }

    pub fn remove_kv(&mut self, key: &str) -> Option<Vec<u8>> {
        self.kv_storage.remove(key)
    }

    pub fn apply_changes(&mut self, bundle_state_manager: BundleStateManager) {
        for (address, account) in bundle_state_manager.accounts.into_iter() {
            tracing::info!("Applying changes for account {}", address);
            self.set_account(address, account);
        }

        // Apply blob storage changes
        for (blob_hash, data) in bundle_state_manager.stored_blobs.into_iter() {
            self.insert_blob(blob_hash, data);
        }

        // Apply intent changes
        for (intent_id, intent) in bundle_state_manager.intents.into_iter() {
            self.insert_intent(intent_id, intent);
        }

        for key in bundle_state_manager.removed_keys.into_iter() {
            self.remove_kv(&key);
        }

        for (key, value) in bundle_state_manager.kv_storage.into_iter() {
            self.insert_kv(key, value);
        }

        // Apply transaction storage
        for transaction in bundle_state_manager.transactions.into_iter() {
            self.add_transaction(transaction);
        }

        // Apply transaction receipts
        for (tx_hash, receipt) in bundle_state_manager.transaction_receipts.into_iter() {
            self.add_receipt(tx_hash, receipt);
        }
    }
    /// Serialize the StateManager to a writer using borsh
    #[allow(dead_code)]
    pub fn borsh_serialize_to_writer<W: Write>(&self, writer: &mut W) -> Result<()> {
        borsh::to_writer(writer, self)
            .map_err(|e| anyhow::anyhow!("Failed to borsh serialize StateManager: {}", e))
    }

    /// Deserialize a StateManager from a reader using borsh
    #[allow(dead_code)]
    pub fn borsh_deserialize_from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        borsh::from_reader(reader)
            .map_err(|e| anyhow::anyhow!("Failed to borsh deserialize StateManager: {}", e))
    }

    /// Serialize the StateManager to a byte vector using borsh
    pub fn borsh_serialize(&self) -> Result<Vec<u8>> {
        borsh::to_vec(self)
            .map_err(|e| anyhow::anyhow!("Failed to borsh serialize StateManager: {}", e))
    }

    /// Deserialize a StateManager from a byte slice using borsh.
    /// On "not all bytes read" style errors, the error message includes file length and bytes consumed.
    pub fn borsh_deserialize(bytes: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(bytes);
        let result = borsh::BorshDeserialize::deserialize_reader(&mut cursor);
        let consumed = cursor.position() as usize;
        match result {
            Ok(value) => {
                if consumed != bytes.len() {
                    return Err(anyhow::anyhow!(
                        "Not all bytes read: state file length {} bytes, consumed {} bytes ({} trailing)",
                        bytes.len(),
                        consumed,
                        bytes.len().saturating_sub(consumed)
                    ));
                }
                Ok(value)
            }
            Err(e) => Err(anyhow::anyhow!(
                "Failed to borsh deserialize StateManager (file length {} bytes, consumed {} bytes before error): {}",
                bytes.len(),
                consumed,
                e
            )),
        }
    }
}
