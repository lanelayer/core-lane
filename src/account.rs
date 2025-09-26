use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::{anyhow, Result};
use std::collections::HashMap;

/// Core Lane account structure
#[derive(Debug, Clone)]
pub struct CoreLaneAccount {
    pub balance: U256,
    pub nonce: U256,
    pub code: Bytes,
    pub storage: HashMap<B256, B256>,
}

impl CoreLaneAccount {
    pub fn new() -> Self {
        Self {
            balance: U256::ZERO,
            nonce: U256::ZERO,
            code: Bytes::new(),
            storage: HashMap::new(),
        }
    }

    pub fn with_balance(balance: U256) -> Self {
        Self {
            balance,
            nonce: U256::ZERO,
            code: Bytes::new(),
            storage: HashMap::new(),
        }
    }

    pub fn is_contract(&self) -> bool {
        !self.code.is_empty()
    }

    pub fn increment_nonce(&mut self) -> Result<()> {
        self.nonce = self
            .nonce
            .checked_add(U256::from(1))
            .ok_or_else(|| anyhow!("Nonce overflow"))?;
        Ok(())
    }

    pub fn add_balance(&mut self, amount: U256) -> Result<()> {
        self.balance = self
            .balance
            .checked_add(amount)
            .ok_or_else(|| anyhow!("Balance overflow"))?;
        Ok(())
    }

    pub fn sub_balance(&mut self, amount: U256) -> Result<()> {
        if self.balance < amount {
            return Err(anyhow!("Insufficient balance"));
        }
        self.balance = self
            .balance
            .checked_sub(amount)
            .ok_or_else(|| anyhow!("Balance underflow"))?;
        Ok(())
    }

    pub fn set_storage(&mut self, key: B256, value: B256) {
        self.storage.insert(key, value);
    }

    pub fn get_storage(&self, key: B256) -> B256 {
        self.storage.get(&key).copied().unwrap_or(B256::ZERO)
    }
}

/// Account manager for Core Lane
#[derive(Debug, Clone)]
pub struct AccountManager {
    accounts: HashMap<Address, CoreLaneAccount>,
}

impl AccountManager {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    pub fn get_account(&self, address: Address) -> Option<&CoreLaneAccount> {
        self.accounts.get(&address)
    }

    pub fn get_account_mut(&mut self, address: Address) -> &mut CoreLaneAccount {
        self.accounts
            .entry(address)
            .or_insert_with(CoreLaneAccount::new)
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

    pub fn set_balance(&mut self, address: Address, balance: U256) -> Result<()> {
        let account = self.get_account_mut(address);
        account.balance = balance;
        Ok(())
    }

    pub fn add_balance(&mut self, address: Address, amount: U256) -> Result<()> {
        let account = self.get_account_mut(address);
        account.add_balance(amount)
    }

    pub fn sub_balance(&mut self, address: Address, amount: U256) -> Result<()> {
        let account = self.get_account_mut(address);
        account.sub_balance(amount)
    }

    pub fn increment_nonce(&mut self, address: Address) -> Result<()> {
        let account = self.get_account_mut(address);
        account.increment_nonce()
    }

    pub fn deploy_contract(&mut self, address: Address, code: Bytes) -> Result<()> {
        let account = self.get_account_mut(address);
        account.code = code;
        Ok(())
    }

    pub fn set_storage(&mut self, address: Address, key: B256, value: B256) -> Result<()> {
        let account = self.get_account_mut(address);
        account.set_storage(key, value);
        Ok(())
    }

    pub fn get_storage(&self, address: Address, key: B256) -> B256 {
        self.accounts
            .get(&address)
            .map(|acc| acc.get_storage(key))
            .unwrap_or(B256::ZERO)
    }

    pub fn account_exists(&self, address: Address) -> bool {
        self.accounts.contains_key(&address)
    }

    pub fn is_contract(&self, address: Address) -> bool {
        self.accounts
            .get(&address)
            .map(|acc| acc.is_contract())
            .unwrap_or(false)
    }

    pub fn get_all_accounts(&self) -> &HashMap<Address, CoreLaneAccount> {
        &self.accounts
    }

    pub fn clear_account(&mut self, address: Address) {
        self.accounts.remove(&address);
    }
}
