use alloy_primitives::U256;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// EIP-1559 fee parameters and state management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip1559Config {
    /// Initial base fee per gas (in wei)
    pub initial_base_fee: U256,
    /// Maximum base fee per gas (in wei)
    pub max_base_fee: U256,
    /// Gas limit per block
    pub gas_limit: U256,
    /// Target gas usage per block (typically 50% of gas_limit)
    pub target_gas_usage: U256,
    /// Base fee change denominator (typically 8)
    pub base_fee_change_denominator: U256,
    /// Elasticity multiplier (typically 2)
    pub elasticity_multiplier: U256,
}

impl Default for Eip1559Config {
    fn default() -> Self {
        Self {
            initial_base_fee: U256::from(1_000_000_000u64), // 1 gwei
            max_base_fee: U256::from(1_000_000_000_000_000u64), // 1,000,000 gwei
            gas_limit: U256::from(30_000_000u64),           // 30M gas
            target_gas_usage: U256::from(15_000_000u64),    // 15M gas (50% of limit)
            base_fee_change_denominator: U256::from(8u64),
            elasticity_multiplier: U256::from(2u64),
        }
    }
}

/// EIP-1559 fee manager for Core Lane
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip1559FeeManager {
    #[serde(default)]
    config: Eip1559Config,
    /// Current base fee per gas
    current_base_fee: U256,
    /// Block number to base fee mapping for historical tracking
    base_fee_history: HashMap<u64, U256>,
}

impl Eip1559FeeManager {
    /// Create a new EIP-1559 fee manager with default configuration
    pub fn new() -> Self {
        let config = Eip1559Config::default();
        Self {
            current_base_fee: config.initial_base_fee,
            base_fee_history: HashMap::new(),
            config,
        }
    }

    /// Create a new EIP-1559 fee manager with custom configuration
    #[allow(dead_code)]
    pub fn with_config(config: Eip1559Config) -> Self {
        Self {
            current_base_fee: config.initial_base_fee,
            base_fee_history: HashMap::new(),
            config,
        }
    }

    /// Get the current base fee per gas
    pub fn current_base_fee(&self) -> U256 {
        self.current_base_fee
    }

    /// Get the base fee for a specific block number
    pub fn get_base_fee_for_block(&self, block_number: u64) -> Option<U256> {
        self.base_fee_history.get(&block_number).copied()
    }

    /// Calculate the base fee for the next block based on current block's gas usage
    /// This implements the EIP-1559 base fee calculation formula:
    /// base_fee = parent_base_fee + parent_base_fee * gas_used_delta / parent_gas_limit / base_fee_change_denominator
    /// where gas_used_delta = parent_gas_used - parent_gas_target
    pub fn calculate_next_base_fee(&self, gas_used: U256) -> U256 {
        let parent_base_fee = self.current_base_fee;
        let _parent_gas_limit = self.config.gas_limit;
        let parent_gas_target = self.config.target_gas_usage;
        let base_fee_change_denominator = self.config.base_fee_change_denominator;

        // Calculate gas used delta
        let _gas_used_delta = if gas_used > parent_gas_target {
            gas_used - parent_gas_target
        } else {
            U256::ZERO
        };

        // Calculate base fee change
        let base_fee_change = if gas_used > parent_gas_target {
            // Base fee increases when block is more than 50% full
            let excess_gas = gas_used - parent_gas_target;
            parent_base_fee * excess_gas / parent_gas_target / base_fee_change_denominator
        } else {
            // Base fee decreases when block is less than 50% full
            let gas_shortage = parent_gas_target - gas_used;
            parent_base_fee * gas_shortage / parent_gas_target / base_fee_change_denominator
        };

        // Calculate new base fee
        let new_base_fee = if gas_used > parent_gas_target {
            // Base fee increases when block is more than 50% full
            parent_base_fee + base_fee_change
        } else {
            // Base fee decreases when block is less than 50% full
            if parent_base_fee > base_fee_change {
                parent_base_fee - base_fee_change
            } else {
                U256::ZERO
            }
        };

        // Cap the base fee at the maximum
        if new_base_fee > self.config.max_base_fee {
            self.config.max_base_fee
        } else {
            new_base_fee
        }
    }

    /// Update the base fee for a new block
    pub fn update_base_fee(&mut self, block_number: u64, gas_used: U256) -> U256 {
        let new_base_fee = self.calculate_next_base_fee(gas_used);

        // Store the base fee for this block
        self.base_fee_history.insert(block_number, new_base_fee);

        // Update current base fee
        self.current_base_fee = new_base_fee;

        new_base_fee
    }

    /// Validate that a transaction's max_fee_per_gas is sufficient for EIP-1559
    pub fn validate_eip1559_transaction(
        &self,
        max_fee_per_gas: U256,
        max_priority_fee_per_gas: U256,
        gas_limit: U256,
    ) -> Result<()> {
        let current_base_fee = self.current_base_fee;

        // Validate gas_limit
        if gas_limit == U256::ZERO {
            return Err(anyhow!("gas_limit must be greater than zero"));
        }

        if gas_limit > self.config.gas_limit {
            return Err(anyhow!(
                "gas_limit ({}) exceeds block gas limit ({})",
                gas_limit,
                self.config.gas_limit
            ));
        }

        // EIP-1559 validation rules:
        // 1. max_fee_per_gas >= base_fee_per_gas
        // 2. max_fee_per_gas >= max_priority_fee_per_gas

        if max_fee_per_gas < current_base_fee {
            return Err(anyhow!(
                "max_fee_per_gas ({}) must be >= base_fee_per_gas ({})",
                max_fee_per_gas,
                current_base_fee
            ));
        }

        if max_fee_per_gas < max_priority_fee_per_gas {
            return Err(anyhow!(
                "max_fee_per_gas ({}) must be >= max_priority_fee_per_gas ({})",
                max_fee_per_gas,
                max_priority_fee_per_gas
            ));
        }

        // Calculate effective priority as the minimum of max_priority_fee_per_gas
        // and (max_fee_per_gas - current_base_fee)
        let available_room = max_fee_per_gas.saturating_sub(current_base_fee);
        let effective_priority = if max_priority_fee_per_gas > available_room {
            available_room
        } else {
            max_priority_fee_per_gas
        };

        // Calculate effective gas price as current_base_fee + effective_priority,
        // clamped so it never exceeds max_fee_per_gas
        let effective_gas_price = current_base_fee + effective_priority;
        let effective_gas_price = if effective_gas_price > max_fee_per_gas {
            max_fee_per_gas
        } else {
            effective_gas_price
        };

        // Validate that the effective gas price is reasonable
        if effective_gas_price < current_base_fee {
            return Err(anyhow!(
                "Effective gas price ({}) must be >= base_fee_per_gas ({})",
                effective_gas_price,
                current_base_fee
            ));
        }

        Ok(())
    }

    /// Calculate the effective gas price for a transaction
    pub fn calculate_effective_gas_price(
        &self,
        max_fee_per_gas: U256,
        max_priority_fee_per_gas: U256,
    ) -> U256 {
        let current_base_fee = self.current_base_fee;

        if max_fee_per_gas > current_base_fee + max_priority_fee_per_gas {
            current_base_fee + max_priority_fee_per_gas
        } else {
            max_fee_per_gas
        }
    }

    /// Calculate base fee and priority fee portions for burning and sequencer rewards
    pub fn calculate_fee_breakdown(
        &self,
        max_fee_per_gas: U256,
        max_priority_fee_per_gas: U256,
        gas_used: U256,
    ) -> (U256, U256, U256) {
        let current_base_fee = self.current_base_fee;
        let effective_gas_price =
            self.calculate_effective_gas_price(max_fee_per_gas, max_priority_fee_per_gas);

        let total_fee = effective_gas_price * gas_used;
        let base_fee_portion = current_base_fee * gas_used;
        let priority_fee_portion = total_fee - base_fee_portion;

        (total_fee, base_fee_portion, priority_fee_portion)
    }

    /// Get the configuration
    #[allow(dead_code)]
    pub fn config(&self) -> &Eip1559Config {
        &self.config
    }

    /// Update the configuration
    #[allow(dead_code)]
    pub fn update_config(&mut self, config: Eip1559Config) {
        self.config = config;
    }

    /// Get the base fee history for a range of blocks
    pub fn get_base_fee_history(&self, start_block: u64, end_block: u64) -> Vec<(u64, U256)> {
        (start_block..=end_block)
            .filter_map(|block_num| {
                self.base_fee_history
                    .get(&block_num)
                    .map(|&base_fee| (block_num, base_fee))
            })
            .collect()
    }

    /// Get gas used ratio for a block (for fee history)
    pub fn get_gas_used_ratio(&self, gas_used: U256) -> f64 {
        let gas_limit = self.config.gas_limit;
        let gas_used_u64 = gas_used.to::<u64>();
        let gas_limit_u64 = gas_limit.to::<u64>();

        if gas_limit_u64 == 0 {
            0.0
        } else {
            gas_used_u64 as f64 / gas_limit_u64 as f64
        }
    }
}

impl Default for Eip1559FeeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_base_fee() {
        let manager = Eip1559FeeManager::new();
        assert_eq!(manager.current_base_fee(), U256::from(1_000_000_000u64)); // 1 gwei
    }

    #[test]
    fn test_base_fee_calculation_target_usage() {
        let manager = Eip1559FeeManager::new();
        let target_gas = manager.config().target_gas_usage;

        // When gas used equals target, base fee should remain the same
        let new_base_fee = manager.calculate_next_base_fee(target_gas);
        assert_eq!(new_base_fee, manager.current_base_fee());
    }

    #[test]
    fn test_base_fee_calculation_high_usage() {
        let manager = Eip1559FeeManager::new();
        let high_gas = manager.config().gas_limit; // 100% usage

        // When gas used is at limit, base fee should increase
        let new_base_fee = manager.calculate_next_base_fee(high_gas);
        assert!(new_base_fee > manager.current_base_fee());
    }

    #[test]
    fn test_base_fee_calculation_low_usage() {
        let manager = Eip1559FeeManager::new();
        let low_gas = U256::from(1_000_000u64); // Very low usage

        // When gas used is low, base fee should decrease
        let new_base_fee = manager.calculate_next_base_fee(low_gas);
        assert!(new_base_fee < manager.current_base_fee());
    }

    #[test]
    fn test_eip1559_transaction_validation() {
        let manager = Eip1559FeeManager::new();
        let base_fee = manager.current_base_fee();

        // Valid transaction
        let result = manager.validate_eip1559_transaction(
            base_fee + U256::from(1_000_000_000u64), // max_fee > base_fee
            U256::from(1_000_000_000u64),            // priority_fee
            U256::from(21_000u64),                   // gas_limit
        );
        assert!(result.is_ok());

        // Invalid transaction: max_fee < base_fee
        let result = manager.validate_eip1559_transaction(
            base_fee - U256::from(1u64), // max_fee < base_fee
            U256::from(1_000_000_000u64),
            U256::from(21_000u64),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_effective_gas_price_calculation() {
        let manager = Eip1559FeeManager::new();
        let base_fee = manager.current_base_fee();
        let priority_fee = U256::from(1_000_000_000u64);
        let max_fee = base_fee + priority_fee + U256::from(1_000_000_000u64);

        let effective_price = manager.calculate_effective_gas_price(max_fee, priority_fee);
        assert_eq!(effective_price, base_fee + priority_fee);
    }

    #[test]
    fn test_fee_breakdown_calculation() {
        let manager = Eip1559FeeManager::new();
        let base_fee = manager.current_base_fee();
        let priority_fee = U256::from(1_000_000_000u64);
        let max_fee = base_fee + priority_fee + U256::from(1_000_000_000u64);
        let gas_limit = U256::from(21_000u64);

        let (total_fee, base_fee_portion, priority_fee_portion) =
            manager.calculate_fee_breakdown(max_fee, priority_fee, gas_limit);

        assert_eq!(base_fee_portion, base_fee * gas_limit);
        assert_eq!(priority_fee_portion, priority_fee * gas_limit);
        assert_eq!(total_fee, base_fee_portion + priority_fee_portion);
    }
}
