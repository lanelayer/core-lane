use alloy_primitives::U256;
use anyhow::{anyhow, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Core Lane account structure
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Default)]
pub struct CoreLaneAccount {
    pub balance: U256,
    pub nonce: U256,
}

impl CoreLaneAccount {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn with_balance(balance: U256) -> Self {
        Self {
            balance,
            nonce: U256::ZERO,
        }
    }

    pub fn increment_nonce(&mut self) -> Result<()> {
        self.nonce = self
            .nonce
            .checked_add(U256::ONE)
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
}
