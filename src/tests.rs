#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{BundleStateManager, StateManager};
    use alloy_consensus::{TxEnvelope, TxLegacy};
    use alloy_primitives::{Address, Bytes, U256};
    use std::str::FromStr;

    // Test data
    const TEST_ETH_ADDRESS: &str = "0x1234567890123456789012345678901234567890";
    const TEST_CHAIN_ID: u32 = 1;
    const TEST_BURN_AMOUNT: u64 = 1000000;

    #[test]
    fn test_burn_payload_creation() {
        let eth_address = Address::from_str(TEST_ETH_ADDRESS).unwrap();
        let payload = create_burn_payload(TEST_CHAIN_ID, &eth_address);

        // Verify payload structure: BRN1 + chain_id (4 bytes) + eth_address (20 bytes)
        assert_eq!(payload.len(), 28); // 4 + 4 + 20 = 28 bytes

        // Check BRN1 prefix
        assert_eq!(&payload[0..4], b"BRN1");

        // Check chain ID (little endian)
        assert_eq!(&payload[4..8], &TEST_CHAIN_ID.to_le_bytes());

        // Check ETH address
        assert_eq!(&payload[8..28], eth_address.as_slice());
    }

    #[test]
    fn test_burn_payload_hex_encoding() {
        let eth_address = Address::from_str(TEST_ETH_ADDRESS).unwrap();
        let payload = create_burn_payload(TEST_CHAIN_ID, &eth_address);
        let hex_payload = hex::encode(&payload);

        // Expected: BRN1 (42524e31) + chain_id (01000000) + eth_address
        let expected_prefix = "42524e3101000000";
        assert!(hex_payload.starts_with(expected_prefix));
    }

    #[test]
    fn test_op_return_script_creation() {
        let eth_address = Address::from_str(TEST_ETH_ADDRESS).unwrap();
        let payload = create_burn_payload(TEST_CHAIN_ID, &eth_address);
        let hex_payload = hex::encode(&payload);
        let opreturn_script = format!("6a{:02x}{}", payload.len(), hex_payload);

        // Script should start with 6a (OP_RETURN) + length + payload
        assert!(opreturn_script.starts_with("6a1c")); // 28 bytes = 0x1c
        assert_eq!(opreturn_script.len(), 2 + 2 + hex_payload.len()); // 6a + length + payload
    }

    #[test]
    fn test_burn_payload_parsing() {
        let eth_address = Address::from_str(TEST_ETH_ADDRESS).unwrap();
        let original_payload = create_burn_payload(TEST_CHAIN_ID, &eth_address);

        // Simulate parsing the payload back
        if original_payload.len() >= 28 {
            let chain_id_bytes = &original_payload[4..8];
            let chain_id = u32::from_le_bytes(chain_id_bytes.try_into().unwrap());
            let address_bytes = &original_payload[8..28];
            let parsed_address = Address::from_slice(address_bytes);

            assert_eq!(chain_id, TEST_CHAIN_ID);
            assert_eq!(parsed_address, eth_address);
        } else {
            panic!("Payload too short");
        }
    }

    // Helper function to create burn payload (simplified version)
    fn create_burn_payload(chain_id: u32, eth_address: &Address) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"BRN1"); // 4 bytes
        payload.extend_from_slice(&chain_id.to_le_bytes()); // 4 bytes
        payload.extend_from_slice(eth_address.as_slice()); // 20 bytes
        payload
    }

    // TODO: Re-add transaction creation when TxLegacy structure is clarified
    // fn create_test_transaction() -> TxEnvelope { ... }
}

// Integration tests
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::state::{BundleStateManager, StateManager};
    use alloy_primitives::{Address, U256};
    use std::str::FromStr;

    const TEST_ETH_ADDRESS: &str = "0x1234567890123456789012345678901234567890";
    const TEST_CHAIN_ID: u32 = 1;

    #[test]
    fn test_complete_burn_workflow() {
        // This test would simulate the complete burn workflow
        // 1. Create burn payload
        // 2. Create OP_RETURN script
        // 3. Verify script format
        // 4. Test parsing back

        let eth_address = Address::from_str(TEST_ETH_ADDRESS).unwrap();
        let payload = create_burn_payload(TEST_CHAIN_ID, &eth_address);
        let hex_payload = hex::encode(&payload);
        let opreturn_script = format!("6a{:02x}{}", payload.len(), hex_payload);

        // Verify the complete workflow
        assert!(opreturn_script.starts_with("6a1c42524e31")); // OP_RETURN + length + BRN1
        assert_eq!(opreturn_script.len(), 2 + 2 + hex_payload.len());

        // Verify we can parse it back
        let script_bytes = hex::decode(&opreturn_script[4..]).unwrap(); // Skip 6a1c
        assert_eq!(&script_bytes[0..4], b"BRN1");
    }

    #[test]
    fn test_account_state_consistency() {
        let mut state_manager = StateManager::new();
        let mut bundle_state = BundleStateManager::new();
        let address = Address::from_str(TEST_ETH_ADDRESS).unwrap();

        // Test that account state remains consistent using bundle state
        bundle_state
            .add_balance(&state_manager, address, U256::from(1000u64))
            .unwrap();
        bundle_state
            .increment_nonce(&state_manager, address)
            .unwrap();

        // Apply changes to state manager
        state_manager.apply_changes(bundle_state);

        let account = state_manager.get_account(address).unwrap();
        assert_eq!(account.balance, U256::from(1000u64));
        assert_eq!(account.nonce, U256::from(1u64));
    }

    #[test]
    fn test_borsh_serialization_state_manager() {
        // Create a state manager with some data
        let mut state_manager = StateManager::new();
        let address = Address::from_str(TEST_ETH_ADDRESS).unwrap();

        // Add an account with balance and nonce
        let mut bundle_state = BundleStateManager::new();
        bundle_state
            .add_balance(&state_manager, address, U256::from(5000u64))
            .unwrap();
        bundle_state
            .increment_nonce(&state_manager, address)
            .unwrap();
        bundle_state
            .increment_nonce(&state_manager, address)
            .unwrap();

        state_manager.apply_changes(bundle_state);

        // Serialize using borsh
        let serialized = state_manager.borsh_serialize().unwrap();

        // Deserialize using borsh
        let deserialized = StateManager::borsh_deserialize(&serialized).unwrap();

        // Verify the data is the same
        let account = deserialized.get_account(address).unwrap();
        assert_eq!(account.balance, U256::from(5000u64));
        assert_eq!(account.nonce, U256::from(2u64));
    }

    #[test]
    fn test_borsh_serialization_bundle_state_manager() {
        // Create a bundle state manager with some data
        let state_manager = StateManager::new();
        let mut bundle_state = BundleStateManager::new();
        let address = Address::from_str(TEST_ETH_ADDRESS).unwrap();

        // Add balance and nonce
        bundle_state
            .add_balance(&state_manager, address, U256::from(10000u64))
            .unwrap();
        bundle_state
            .increment_nonce(&state_manager, address)
            .unwrap();

        // Serialize using borsh
        let serialized = bundle_state.borsh_serialize().unwrap();

        // Deserialize using borsh
        let deserialized = BundleStateManager::borsh_deserialize(&serialized).unwrap();

        // Verify the data is the same
        let account = deserialized.get_account(&state_manager, address).unwrap();
        assert_eq!(account.balance, U256::from(10000u64));
        assert_eq!(account.nonce, U256::from(1u64));
    }

    #[test]
    fn test_block_and_delta_roundtrip() {
        use std::fs;

        // Create a temporary directory for testing
        let temp_dir = std::env::temp_dir().join("core-lane-test-blocks");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create initial state
        let mut state_manager = StateManager::new();
        let address = Address::from_str(TEST_ETH_ADDRESS).unwrap();

        // Create a bundle with changes
        let mut bundle_state = BundleStateManager::new();
        bundle_state
            .add_balance(&state_manager, address, U256::from(20000u64))
            .unwrap();
        bundle_state
            .increment_nonce(&state_manager, address)
            .unwrap();

        // Apply changes to get final state
        state_manager.apply_changes(bundle_state.clone());

        // Write delta and state to disk (as would happen in the actual implementation)
        let block_number = 123;
        let blocks_dir = temp_dir.join("blocks");
        let deltas_dir = temp_dir.join("deltas");
        let block_file = blocks_dir.join(format!("{}", block_number));
        let delta_file = deltas_dir.join(format!("{}", block_number));

        // Create directories
        fs::create_dir_all(&blocks_dir).unwrap();
        fs::create_dir_all(&deltas_dir).unwrap();

        // Write delta first (before applying changes)
        let delta_bytes = bundle_state.borsh_serialize().unwrap();
        fs::write(&delta_file, delta_bytes).unwrap();

        // Apply changes and write final state
        state_manager.apply_changes(bundle_state);
        let state_bytes = state_manager.borsh_serialize().unwrap();
        fs::write(&block_file, state_bytes).unwrap();

        // Read back and verify
        let state_read_bytes = fs::read(&block_file).unwrap();
        let state_read = StateManager::borsh_deserialize(&state_read_bytes).unwrap();

        let delta_read_bytes = fs::read(&delta_file).unwrap();
        let delta_read = BundleStateManager::borsh_deserialize(&delta_read_bytes).unwrap();

        // Verify state
        let account = state_read.get_account(address).unwrap();
        assert_eq!(account.balance, U256::from(20000u64));
        assert_eq!(account.nonce, U256::from(1u64));

        // Verify delta can be used to reconstruct state
        let empty_state = StateManager::new();
        let delta_account = delta_read.get_account(&empty_state, address).unwrap();
        assert_eq!(delta_account.balance, U256::from(20000u64));
        assert_eq!(delta_account.nonce, U256::from(1u64));

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_genesis_state_persistence() {
        use std::fs;

        // Create a temporary directory for testing
        let temp_dir = std::env::temp_dir().join("core-lane-genesis-test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Write genesis state (as would happen during node initialization)
        if let Err(e) = crate::CoreLaneNode::write_genesis_state(temp_dir.to_str().unwrap()) {
            panic!("Failed to write genesis state: {}", e);
        }

        // Verify genesis state was written
        let blocks_dir = temp_dir.join("blocks");
        let genesis_file = blocks_dir.join("0");
        assert!(
            genesis_file.exists(),
            "Genesis state file should exist at blocks/0"
        );

        // Read back and verify it's a valid StateManager
        let genesis_bytes = fs::read(&genesis_file).unwrap();
        let genesis_state = StateManager::borsh_deserialize(&genesis_bytes).unwrap();

        // Genesis state should be empty - we can verify this by checking that
        // we can create a new empty state and they should be equivalent in size
        let empty_state = StateManager::new();
        assert_eq!(
            genesis_state.borsh_serialize().unwrap().len(),
            empty_state.borsh_serialize().unwrap().len()
        );

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    // Helper function for tests
    fn create_burn_payload(chain_id: u32, eth_address: &Address) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"BRN1"); // 4 bytes
        payload.extend_from_slice(&chain_id.to_le_bytes()); // 4 bytes
        payload.extend_from_slice(eth_address.as_slice()); // 20 bytes
        payload
    }
}
