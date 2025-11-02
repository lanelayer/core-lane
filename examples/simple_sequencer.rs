use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{Bytes, TxKind};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::Result;
use bitcoincore_rpc::{Auth, Client};
/// Simple Sequencer Example
///
/// This example demonstrates how to use core-lane as a library to build
/// a simple sequencer that processes transactions.
///
/// Run with: cargo run --example simple_sequencer
use core_lane::{
    execute_transaction, Address, BundleStateManager, CoreLaneStateForLib, StateManager,
    TxEnvelope, U256,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Core Lane Simple Sequencer Example\n");

    // 1. Setup Bitcoin RPC client
    println!("📡 Connecting to Bitcoin RPC...");
    let bitcoin_client = Client::new(
        "http://127.0.0.1:18443",
        Auth::UserPass("user".to_string(), "password".to_string()),
    );

    // Note: This will fail if Bitcoin isn't running, but that's ok for the example
    match bitcoin_client {
        Ok(client) => {
            println!("✅ Connected to Bitcoin RPC\n");

            let client = Arc::new(client);

            // 2. Initialize state manager and context (same pattern as the main node)
            println!("💾 Initializing state manager...");
            let mut state = StateManager::new();
            let mut state_context = CoreLaneStateForLib::new(
                state.clone(),
                Arc::clone(&client),
                bitcoincore_rpc::bitcoin::Network::Regtest,
            );
            println!("✅ State manager initialized\n");

            // 3. Show account balances
            let test_address = Address::from([0x42; 20]);
            let balance = state.get_balance(test_address);
            let nonce = state.get_nonce(test_address);

            println!("📊 Account Status:");
            println!("   Address: {:#x}", test_address);
            println!("   Balance: {} wei", balance);
            println!("   Nonce:   {}", nonce);
            println!();

            // 4. Create a bundle for batch processing (same pattern as the main node)
            println!("📦 Creating transaction bundle...");
            let mut bundle = BundleStateManager::new();

            // Simulate adding some balance (like from a burn)
            let mint_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
            bundle.add_balance(&state, test_address, mint_amount)?;
            println!("   Added {} wei to address", mint_amount);

            // 5. Apply the bundle (same as the main node does)
            println!("✨ Applying bundle to state...");
            state.apply_changes(bundle);

            let new_balance = state.get_balance(test_address);
            println!("   New balance: {} wei", new_balance);
            println!();

            // 6. Create and process a real transaction with Alloy
            println!("🔐 Creating a real transaction with Alloy...");

            // Create a signer (using a test private key)
            let signer: PrivateKeySigner =
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
            let sender = signer.address();
            let recipient = Address::from([0x99; 20]);

            println!("   Sender:    {:#x}", sender);
            println!("   Recipient: {:#x}", recipient);

            // Give the sender some balance first
            let mut setup_bundle = BundleStateManager::new();
            let initial_balance = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
            setup_bundle.add_balance(&state, sender, initial_balance)?;
            state.apply_changes(setup_bundle);
            state_context.replace_state_manager(state.clone());
            println!(
                "   Sender initial balance: {} wei",
                state.get_balance(sender)
            );

            // Build a transaction
            let tx = TxEip1559 {
                chain_id: 1,
                nonce: 0,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 20_000_000_000,
                gas_limit: 21000,
                to: TxKind::Call(recipient),
                value: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
                input: Bytes::new(),
                access_list: Default::default(),
            };

            println!("   Transfer amount: 1 ETH");

            // Sign the transaction
            let signature = signer.sign_hash_sync(&tx.signature_hash())?;
            let signed = tx.into_signed(signature);
            let envelope = TxEnvelope::Eip1559(signed);

            println!("   ✅ Transaction signed");

            // 7. Process the transaction (same pattern as the main node)
            println!("\n⚙️  Processing transaction...");
            let mut tx_bundle = BundleStateManager::new();

            // Call execute_transaction directly, just like the main node does
            let result =
                execute_transaction(&envelope, sender, &mut tx_bundle, &mut state_context)?;

            if result.success {
                println!("   ✅ Transaction executed successfully!");
                println!("   Gas used: {}", result.gas_used);

                // Apply the transaction bundle to state
                state.apply_changes(tx_bundle);

                let sender_balance = state.get_balance(sender);
                let recipient_balance = state.get_balance(recipient);
                let sender_nonce = state.get_nonce(sender);

                println!("\n📊 Final Balances:");
                println!(
                    "   Sender:    {} wei (nonce: {})",
                    sender_balance, sender_nonce
                );
                println!("   Recipient: {} wei", recipient_balance);
            } else {
                println!("   ❌ Transaction failed: {:?}", result.error);
                for log in result.logs {
                    println!("      {}", log);
                }
            }
            println!();

            // 8. Demonstrate state serialization
            println!("\n💾 Demonstrating state serialization...");
            let serialized = state.borsh_serialize()?;
            println!("   Serialized state size: {} bytes", serialized.len());

            let deserialized = StateManager::borsh_deserialize(&serialized)?;
            let restored_sender = deserialized.get_balance(sender);
            let restored_recipient = deserialized.get_balance(recipient);
            println!("   Restored sender balance: {} wei", restored_sender);
            println!("   Restored recipient balance: {} wei", restored_recipient);
            assert_eq!(state.get_balance(sender), restored_sender);
            assert_eq!(state.get_balance(recipient), restored_recipient);
            println!("✅ Serialization/deserialization verified\n");

            println!("🎉 Example completed successfully!");
        }
        Err(e) => {
            println!("⚠️  Could not connect to Bitcoin RPC: {}", e);
            println!("   (This is expected if Bitcoin node is not running)");
            println!();

            // Still demonstrate state management without Bitcoin
            println!("💾 Demonstrating state management (without Bitcoin)...");
            let state = StateManager::new();
            let test_address = Address::from([0x42; 20]);

            let mut bundle = BundleStateManager::new();
            let mint_amount = U256::from(1_000_000_000_000_000_000u128);
            bundle.add_balance(&state, test_address, mint_amount)?;

            // Apply changes
            let mut new_state = state.clone();
            new_state.apply_changes(bundle);

            let balance = new_state.get_balance(test_address);
            println!("   Created account with balance: {} wei", balance);
            println!();
            println!("✅ State management works without Bitcoin RPC!");
        }
    }

    Ok(())
}
