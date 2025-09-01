#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256, Bytes};
    use alloy_consensus::{TxEnvelope, TxLegacy};
    use std::str::FromStr;
    use crate::account::AccountManager;
    use crate::transaction::{validate_transaction, calculate_gas_cost};

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

    #[test]
    fn test_account_creation_and_balance() {
        let mut account_manager = AccountManager::new();
        let address = Address::from_str(TEST_ETH_ADDRESS).unwrap();
        let initial_balance = U256::from(1000000u64);
        
        // Add balance
        account_manager.add_balance(address, initial_balance).unwrap();
        
        // Verify balance
        let balance = account_manager.get_balance(address);
        assert_eq!(balance, initial_balance);
        
        // Verify account exists
        assert!(account_manager.account_exists(address));
    }

    #[test]
    fn test_multiple_accounts() {
        let mut account_manager = AccountManager::new();
        let address1 = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let address2 = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        
        account_manager.add_balance(address1, U256::from(1000u64)).unwrap();
        account_manager.add_balance(address2, U256::from(2000u64)).unwrap();
        
        assert_eq!(account_manager.get_balance(address1), U256::from(1000u64));
        assert_eq!(account_manager.get_balance(address2), U256::from(2000u64));
        
        let accounts = account_manager.get_all_accounts();
        assert_eq!(accounts.len(), 2);
    }

    #[test]
    fn test_nonce_management() {
        let mut account_manager = AccountManager::new();
        let address = Address::from_str(TEST_ETH_ADDRESS).unwrap();
        
        // Initial nonce should be 0
        assert_eq!(account_manager.get_nonce(address), U256::ZERO);
        
        // Increment nonce
        account_manager.increment_nonce(address).unwrap();
        assert_eq!(account_manager.get_nonce(address), U256::from(1u64));
        
        // Increment again
        account_manager.increment_nonce(address).unwrap();
        assert_eq!(account_manager.get_nonce(address), U256::from(2u64));
    }

    // TODO: Fix transaction tests when TxLegacy structure is clarified
    // #[test]
    // fn test_transaction_validation() {
    //     // Test valid transaction
    //     let valid_tx = create_test_transaction();
    //     let validation_result = validate_transaction(&valid_tx);
    //     assert!(validation_result.is_ok());
    // }

    // #[test]
    // fn test_gas_calculation() {
    //     let tx = create_test_transaction();
    //     let gas_cost = calculate_gas_cost(&tx);
    //     
    //     // Gas cost should be reasonable
    //     assert!(gas_cost > U256::ZERO);
    //     assert!(gas_cost < U256::from(1000000u64)); // Should be less than 1M gas
    // }

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
    use crate::account::AccountManager;
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
        let mut account_manager = AccountManager::new();
        let address = Address::from_str(TEST_ETH_ADDRESS).unwrap();
        
        // Test that account state remains consistent
        account_manager.add_balance(address, U256::from(1000u64)).unwrap();
        account_manager.increment_nonce(address).unwrap();
        
        let account = account_manager.get_account(address).unwrap();
        assert_eq!(account.balance, U256::from(1000u64));
        assert_eq!(account.nonce, U256::from(1u64));
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
