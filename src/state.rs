use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, B256, U256};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;

use crate::account::{BundleCoreLaneAccount, CoreLaneAccount};
use crate::intents::Intent;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub transaction_hash: String,
    pub block_number: u64,
    pub transaction_index: u64,
    pub from: String,
    pub to: Option<String>,
    pub cumulative_gas_used: String,
    pub gas_used: String,
    pub contract_address: Option<String>,
    pub logs: Vec<String>,
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

/// State manager for Core Lane
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateManager {
    accounts: HashMap<Address, CoreLaneAccount>,
    stored_blobs: HashMap<B256, Vec<u8>>,
    intents: HashMap<B256, Intent>,
    transactions: Vec<StoredTransaction>,
    transaction_receipts: HashMap<String, TransactionReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleStateManager {
    pub accounts: HashMap<Address, BundleCoreLaneAccount>,
    pub stored_blobs: HashMap<B256, Vec<u8>>,
    pub intents: HashMap<B256, Intent>,
    pub transactions: Vec<StoredTransaction>,
    pub transaction_receipts: HashMap<String, TransactionReceipt>,
}

impl BundleStateManager {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            stored_blobs: HashMap::new(),
            intents: HashMap::new(),
            transactions: Vec::new(),
            transaction_receipts: HashMap::new(),
        }
    }

    // XXX in future this may be a expired blob?
    pub fn contains_blob(&self, original: &StateManager, blob_hash: &B256) -> bool {
        self.stored_blobs.contains_key(blob_hash) || original.contains_blob(blob_hash)
    }

    pub fn insert_blob(&mut self, blob_hash: B256, data: Vec<u8>) {
        self.stored_blobs.insert(blob_hash, data);
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
        if let Some(account) = self.accounts.get(&address) {
            return Some(&account.info);
        }
        original.get_account(address)
    }

    pub fn get_account_mut(
        &mut self,
        original: &StateManager,
        address: Address,
    ) -> Option<&mut CoreLaneAccount> {
        // Ensure the account exists in our bundle before getting a mutable reference
        if !self.accounts.contains_key(&address) {
            let orig = original.get_account(address);
            let bundle_account = if let Some(orig) = orig {
                BundleCoreLaneAccount {
                    original: Some(orig.clone()),
                    info: orig.clone(),
                }
            } else {
                BundleCoreLaneAccount {
                    original: None,
                    info: CoreLaneAccount::new(),
                }
            };
            self.accounts.insert(address, bundle_account);
        }

        // Now get the mutable reference (account definitely exists)
        self.accounts
            .get_mut(&address)
            .map(|account| &mut account.info)
    }

    fn set_account(&mut self, original: &StateManager, address: Address, account: CoreLaneAccount) {
        let orig = original.get_account(address).cloned();
        let bundle_account = BundleCoreLaneAccount {
            original: orig,
            info: account,
        };
        self.accounts.insert(address, bundle_account);
    }

    pub fn get_balance(&self, original: &StateManager, address: Address) -> U256 {
        if let Some(account) = self.accounts.get(&address) {
            return account.info.balance;
        }
        original.get_balance(address)
    }

    pub fn get_nonce(&self, original: &StateManager, address: Address) -> U256 {
        if let Some(account) = self.accounts.get(&address) {
            return account.info.nonce;
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
            self.set_account(original, address, account);
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
            self.set_account(original, address, account);
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
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            stored_blobs: HashMap::new(),
            intents: HashMap::new(),
            transactions: Vec::new(),
            transaction_receipts: HashMap::new(),
        }
    }

    pub fn get_account(&self, address: Address) -> Option<&CoreLaneAccount> {
        self.accounts.get(&address)
    }

    pub fn contains_blob(&self, blob_hash: &B256) -> bool {
        self.stored_blobs.contains_key(blob_hash)
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
    pub fn apply_changes(&mut self, bundle_state_manager: BundleStateManager) {
        for (address, bundle_account) in bundle_state_manager.accounts.into_iter() {
            tracing::info!("Applying changes for account {}", address);
            self.set_account(address, bundle_account.info);
        }

        // Apply blob storage changes
        for (blob_hash, data) in bundle_state_manager.stored_blobs.into_iter() {
            self.insert_blob(blob_hash, data);
        }

        // Apply intent changes
        for (intent_id, intent) in bundle_state_manager.intents.into_iter() {
            self.insert_intent(intent_id, intent);
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
}
