//! Core Lane - Bitcoin-anchored execution environment library
//!
//! This library provides the core functionality for processing Core Lane transactions,
//! managing state, and constructing DA payloads for Bitcoin anchoring.
//!
//! # Usage
//!
//! ```no_run
//! use core_lane::{StateManager, BundleStateManager};
//!
//! let state_manager = StateManager::new();
//! let mut bundle_state = BundleStateManager::new();
//! // Process transactions into the bundle state
//! ```

pub mod account;
pub mod bitcoin_block;
pub mod bitcoin_cache_rpc;
pub mod bitcoin_rpc_client;
pub mod block;
pub mod cmio;
pub mod intents;
pub mod state;
pub mod taproot_da;
pub mod transaction;

// RPC module is not included in the library - it's only used by the binary
// and depends on types defined in main.rs

// Re-export commonly used types for convenience
pub use account::CoreLaneAccount;
pub use block::BundleMarker;
pub use intents::{
    create_anchor_bitcoin_fill_intent, decode_intent_calldata, AnchorBitcoinFill, Intent,
    IntentCall, IntentCommandType, IntentData, IntentStatus, IntentSystem, IntentType,
    RiscVProgramIntent,
};
pub use state::{BundleStateManager, StateManager, StoredTransaction, TransactionReceipt};
pub use transaction::{
    execute_transaction, get_transaction_input_bytes, get_transaction_nonce, CoreLaneAddresses,
    ExecutionResult, ProcessingContext,
};

// Re-export key external types for convenience
pub use alloy_consensus::TxEnvelope;
pub use alloy_primitives::{Address, Bytes, B256, U256};

use std::sync::Arc;

/// Bitcoin RPC client (corepc). Use for read and write operations.
pub use bitcoin_rpc_client::{create_bitcoin_rpc_client, BitcoinRpcClient};

/// A simple state context for processing transactions in external applications
///
/// This provides the same interface as the main node's CoreLaneState but
/// without the block tracking and other node-specific features.
///
/// # Example
///
/// ```no_run
/// use core_lane::{CoreLaneStateForLib, StateManager, BundleStateManager};
/// use core_lane::{execute_transaction, TxEnvelope, Address};
/// use core_lane::bitcoin_rpc_client::{create_bitcoin_read_client, BitcoinRpcReadClient};
/// use core_lane::{create_bitcoin_rpc_client, BitcoinRpcClient};
/// use std::sync::Arc;
///
/// let rpc_client = create_bitcoin_rpc_client(
///     "http://127.0.0.1:18443",
///     "user",
///     "pass"
/// ).unwrap();
/// let read_client = rpc_client.clone() as Arc<dyn BitcoinRpcReadClient>;
///
/// let mut state = CoreLaneStateForLib::new(
///     StateManager::new(),
///     read_client,
///     rpc_client,
///     bitcoin::Network::Regtest
/// );
///
/// let mut bundle = BundleStateManager::new();
/// // Process transactions using execute_transaction()
/// ```
pub struct CoreLaneStateForLib {
    account_manager: StateManager,
    bitcoin_client_read: Arc<dyn bitcoin_rpc_client::BitcoinRpcReadClient>,
    bitcoin_client_write: Arc<BitcoinRpcClient>,
    bitcoin_network: bitcoin::Network,
}

impl CoreLaneStateForLib {
    /// Create a new state context with separate read and write Bitcoin RPC clients.
    pub fn new(
        state_manager: StateManager,
        bitcoin_client_read: Arc<dyn bitcoin_rpc_client::BitcoinRpcReadClient>,
        bitcoin_client_write: Arc<BitcoinRpcClient>,
        network: bitcoin::Network,
    ) -> Self {
        Self {
            account_manager: state_manager,
            bitcoin_client_read,
            bitcoin_client_write,
            bitcoin_network: network,
        }
    }
}

impl CoreLaneStateForLib {
    pub fn bitcoin_client_read(&self) -> Arc<dyn bitcoin_rpc_client::BitcoinRpcReadClient> {
        self.bitcoin_client_read.clone()
    }

    #[allow(dead_code)]
    pub fn bitcoin_client_write(&self) -> Arc<BitcoinRpcClient> {
        self.bitcoin_client_write.clone()
    }

    /// Replace the internal state manager with a new one
    ///
    /// This is useful when you've applied changes to a StateManager
    /// and want to update the context to use the new state.
    pub fn replace_state_manager(&mut self, new_state: StateManager) {
        self.account_manager = new_state;
    }
}

impl transaction::ProcessingContext for CoreLaneStateForLib {
    fn state_manager(&self) -> &StateManager {
        &self.account_manager
    }

    fn state_manager_mut(&mut self) -> &mut StateManager {
        &mut self.account_manager
    }

    fn bitcoin_client_read(
        &self,
    ) -> Option<Arc<dyn crate::bitcoin_rpc_client::BitcoinRpcReadClient>> {
        Some(self.bitcoin_client_read.clone())
    }

    fn bitcoin_network(&self) -> bitcoin::Network {
        self.bitcoin_network
    }

    fn handle_cmio_query(
        &mut self,
        message: cmio::CmioMessage,
        current_intent_id: Option<B256>,
    ) -> Option<cmio::CmioMessage> {
        // Use the shared CMIO handler from the cmio module
        cmio::handle_cmio_query(message, &self.account_manager, current_intent_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_manager_basic() {
        let state = StateManager::new();
        assert_eq!(state.get_balance(Address::ZERO), U256::ZERO);
        assert_eq!(state.get_nonce(Address::ZERO), U256::ZERO);
    }

    #[test]
    fn test_bundle_state_manager() {
        let state = StateManager::new();
        let mut bundle = BundleStateManager::new();

        let test_addr = Address::from([1u8; 20]);
        let amount = U256::from(1000);

        // Add balance in bundle
        bundle.add_balance(&state, test_addr, amount).unwrap();

        // Check it's reflected in bundle
        assert_eq!(bundle.get_balance(&state, test_addr), amount);

        // Original state should be unchanged
        assert_eq!(state.get_balance(test_addr), U256::ZERO);

        // Apply changes
        let mut new_state = state;
        new_state.apply_changes(bundle);
        assert_eq!(new_state.get_balance(test_addr), amount);
    }

    #[test]
    fn test_state_serialization() {
        let mut state = StateManager::new();
        let test_addr = Address::from([1u8; 20]);
        let amount = U256::from(1000);

        // Add balance
        let mut bundle = BundleStateManager::new();
        bundle.add_balance(&state, test_addr, amount).unwrap();
        state.apply_changes(bundle);

        // Serialize
        let serialized = state.borsh_serialize().unwrap();

        // Deserialize
        let deserialized = StateManager::borsh_deserialize(&serialized).unwrap();
        assert_eq!(deserialized.get_balance(test_addr), amount);
    }
}
