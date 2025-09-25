use anyhow::{anyhow, Result};
use bitcoin::{
    blockdata::opcodes::all::{OP_ENDIF, OP_IF},
    blockdata::opcodes::{OP_FALSE, OP_TRUE},
    blockdata::script::Builder,
    Address as BitcoinAddress, Network, ScriptBuf, Transaction, Witness,
};
use bitcoincore_rpc::{Client, RpcApi};
use serde_json;
use std::sync::Arc;

pub struct TaprootDA {
    bitcoin_client: Arc<Client>,
}

impl TaprootDA {
    pub fn new(bitcoin_client: Arc<Client>) -> Self {
        Self { bitcoin_client }
    }

    pub async fn send_transaction_to_da(
        &self,
        raw_tx_hex: &str,
        fee_sats: u64,
        wallet: &str,
        network: bitcoin::Network,
    ) -> Result<String> {
        println!("🚀 Creating Core Lane transaction in Bitcoin DA (commit + reveal in one tx)...");
        println!(
            "📝 Ethereum transaction: {}...",
            &raw_tx_hex[..64.min(raw_tx_hex.len())]
        );
        println!("💰 Fee: {} sats", fee_sats);

        // Validate the Ethereum transaction hex
        let tx_bytes = hex::decode(raw_tx_hex).map_err(|e| anyhow!("Invalid hex format: {}", e))?;

        println!("🔍 Raw Ethereum transaction:");
        println!("   📝 Input hex: {}", raw_tx_hex);
        println!(
            "   📏 Input length: {} chars ({} bytes)",
            raw_tx_hex.len(),
            tx_bytes.len()
        );
        println!("   📝 Decoded bytes: {}", hex::encode(&tx_bytes));

        // Create Core Lane payload: CORE_LANE prefix + Ethereum transaction
        let mut payload = Vec::new();
        payload.extend_from_slice(b"CORE_LANE");
        payload.extend_from_slice(&tx_bytes);

        println!("📦 Core Lane payload size: {} bytes", payload.len());
        println!("📦 Core Lane payload hex: {}", hex::encode(&payload));

        // Check wallet balance
        let balance_result: Result<serde_json::Value, _> =
            self.bitcoin_client.call("getbalances", &[]);

        let available_balance = match balance_result {
            Ok(balances) => {
                if let Some(mine_wallet) = balances.get("mine") {
                    if let Some(trusted) = mine_wallet.get("trusted") {
                        let balance_btc = trusted.as_f64().unwrap_or(0.0);
                        (balance_btc * 100_000_000.0) as u64
                    } else {
                        0u64
                    }
                } else {
                    0u64
                }
            }
            Err(e) => return Err(anyhow!("Failed to get wallet balance: {}", e)),
        };

        println!("💰 Available balance: {} sats", available_balance);

        if available_balance < fee_sats {
            return Err(anyhow!(
                "Insufficient balance: {} sats available, {} sats needed",
                available_balance,
                fee_sats
            ));
        }

        // Get unspent outputs
        let unspent_result: Result<serde_json::Value, _> = self.bitcoin_client.call(
            "listunspent",
            &[
                serde_json::json!(0),
                serde_json::json!(9999999),
                serde_json::json!([]),
                serde_json::json!(true),
                serde_json::json!({"minimumAmount": (fee_sats as f64 + 1000.0) / 100_000_000.0}),
            ],
        );

        let unspent = match unspent_result {
            Ok(utxos) => utxos,
            Err(e) => return Err(anyhow!("Failed to get unspent outputs: {}", e)),
        };

        if !unspent.is_array() || unspent.as_array().unwrap().is_empty() {
            return Err(anyhow!("No suitable unspent outputs found"));
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

        // Create a Taproot output with Core Lane data embedded
        let envelope_script = self.create_taproot_envelope_script(&payload)?;
        let (taproot_address, internal_key, control_block) =
            self.create_taproot_address_with_info(&payload, network)?;

        println!("🎯 Created Taproot address: {}", taproot_address);
        println!("🔑 Internal key: {}", internal_key);

        // Create inputs using RPC
        let inputs = vec![serde_json::json!({
            "txid": prev_txid,
            "vout": prev_vout
        })];

        // Create outputs with Core Lane data in Taproot envelope
        let mut outputs = serde_json::Map::new();

        // Add the Taproot output with the Core Lane data
        outputs.insert(
            taproot_address.to_string(),
            serde_json::json!(fee_sats as f64 / 100_000_000.0),
        );

        // Add change output if substantial enough
        let estimated_tx_fee = 2000u64; // Higher fee for complex transaction
        let change_amount = prev_amount
            .saturating_sub(fee_sats)
            .saturating_sub(estimated_tx_fee);
        if change_amount > 546 {
            // dust threshold
            let change_addr_result: Result<serde_json::Value, _> = self.bitcoin_client.call(
                "getnewaddress",
                &[serde_json::json!(wallet), serde_json::json!("bech32")],
            );

            if let Ok(change_addr) = change_addr_result {
                let change_addr_str = change_addr.as_str().unwrap();
                outputs.insert(
                    change_addr_str.to_string(),
                    serde_json::json!(change_amount as f64 / 100_000_000.0),
                );
                println!("💰 Change: {} sats -> {}", change_amount, change_addr_str);
            }
        }

        // Create and sign the commit transaction using RPC
        let rawtx_result: Result<serde_json::Value, _> = self.bitcoin_client.call(
            "createrawtransaction",
            &[serde_json::json!(inputs), serde_json::json!(outputs)],
        );

        let raw_tx = match rawtx_result {
            Ok(tx) => tx.as_str().unwrap().to_string(),
            Err(e) => return Err(anyhow!("Failed to create raw transaction: {}", e)),
        };

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

        // Broadcast the commit transaction
        let commit_tx_result: Result<bitcoin::Txid, _> = self
            .bitcoin_client
            .call("sendrawtransaction", &[serde_json::json!(signed_tx)]);

        let commit_txid = match commit_tx_result {
            Ok(txid) => {
                println!("✅ Commit transaction broadcast: {}", txid);
                println!("📦 Core Lane data embedded in Taproot envelope");
                txid
            }
            Err(e) => {
                println!("❌ Failed to broadcast commit transaction: {}", e);
                return Err(anyhow!("Failed to broadcast commit transaction: {}", e));
            }
        };

        // Now immediately create a reveal transaction that spends the Taproot output
        println!("🔍 Creating reveal transaction to immediately expose Core Lane data...");

        // Get a new address for the reveal output
        let reveal_addr_result: Result<serde_json::Value, _> = self.bitcoin_client.call(
            "getnewaddress",
            &[serde_json::json!(wallet), serde_json::json!("bech32")],
        );

        let reveal_addr = match reveal_addr_result {
            Ok(addr) => addr.as_str().unwrap().to_string(),
            Err(e) => return Err(anyhow!("Failed to get reveal address: {}", e)),
        };

        // Create reveal transaction inputs (spending the Taproot output we just created)
        let reveal_inputs = vec![serde_json::json!({
            "txid": commit_txid.to_string(),
            "vout": 0  // The Taproot output is at index 0
        })];

        // Create reveal transaction outputs
        let mut reveal_outputs = serde_json::Map::new();
        let reveal_amount = fee_sats.saturating_sub(1000); // Small fee for reveal tx
        let output_amount = if reveal_amount >= 546 {
            reveal_amount
        } else {
            546
        };

        reveal_outputs.insert(
            reveal_addr,
            serde_json::json!(output_amount as f64 / 100_000_000.0),
        );

        // Create raw reveal transaction
        let reveal_raw_result: Result<serde_json::Value, _> = self.bitcoin_client.call(
            "createrawtransaction",
            &[
                serde_json::json!(reveal_inputs),
                serde_json::json!(reveal_outputs),
            ],
        );

        let reveal_raw_tx = match reveal_raw_result {
            Ok(tx) => tx.as_str().unwrap().to_string(),
            Err(e) => return Err(anyhow!("Failed to create reveal transaction: {}", e)),
        };

        if reveal_outputs.is_empty() {
            println!("⚠️  Reveal amount below dust threshold, creating zero-fee transaction");
        }

        // Sign the reveal transaction with the internal key
        let mut reveal_tx: Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&reveal_raw_tx)?)?;

        // Add the witness data to reveal the Core Lane transaction
        let mut witness = Witness::new();
        witness.push(&envelope_script.as_bytes());
        witness.push(&control_block);
        reveal_tx.input[0].witness = witness;

        let reveal_final_hex = hex::encode(bitcoin::consensus::serialize(&reveal_tx));

        // Broadcast the reveal transaction
        let reveal_tx_result: Result<bitcoin::Txid, _> = self
            .bitcoin_client
            .call("sendrawtransaction", &[serde_json::json!(reveal_final_hex)]);

        match reveal_tx_result {
            Ok(reveal_txid) => {
                println!(
                    "✅ Core Lane transaction (commit + reveal in same block) created successfully!"
                );
                println!("📍 Commit transaction ID: {}", commit_txid);
                println!("📍 Reveal transaction ID: {}", reveal_txid);
                println!("📦 Core Lane data embedded AND revealed in the same block");
                println!("🎯 Taproot address: {}", taproot_address);
                println!("💰 Fee paid: {} sats", fee_sats);
                println!(
                    "\n🔍 Core Lane node will detect the reveal transaction when scanning blocks!"
                );

                Ok(commit_txid.to_string())
            }
            Err(e) => {
                println!("❌ Failed to broadcast reveal transaction: {}", e);
                Err(anyhow!("Failed to broadcast reveal transaction: {}", e))
            }
        }
    }

    fn create_taproot_envelope_script(&self, data: &[u8]) -> Result<ScriptBuf> {
        // Create Taproot envelope script: OP_FALSE OP_IF <data> OP_ENDIF OP_TRUE
        let mut script = Builder::new();
        script = script.push_opcode(OP_FALSE).push_opcode(OP_IF);

        // Add data in chunks of 520 bytes (Bitcoin script push limit)
        for chunk in data.chunks(520) {
            if let Ok(push_bytes) = <&bitcoin::blockdata::script::PushBytes>::try_from(chunk) {
                script = script.push_slice(push_bytes);
            }
        }

        script = script.push_opcode(OP_ENDIF).push_opcode(OP_TRUE);
        Ok(script.into_script())
    }

    fn create_taproot_address_with_info(
        &self,
        data: &[u8],
        network: bitcoin::Network,
    ) -> Result<(BitcoinAddress, String, Vec<u8>)> {
        use bitcoin::secp256k1::{Keypair, Secp256k1};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};
        use secp256k1::rand::rngs::OsRng;

        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut OsRng);
        let (xonly, _parity) = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&keypair);

        // Create envelope script for the data
        let envelope_script = self.create_taproot_envelope_script(data)?;

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, envelope_script.clone().into())
            .map_err(|e| anyhow!("Failed to add leaf to Taproot builder: {}", e))?
            .finalize(&secp, xonly)
            .map_err(|e| anyhow!("Failed to finalize Taproot spend info: {:?}", e))?;

        let output_key = spend_info.output_key();
        let address = BitcoinAddress::p2tr_tweaked(output_key, network);

        let control_block = spend_info
            .control_block(&(envelope_script.clone().into(), LeafVersion::TapScript))
            .ok_or_else(|| anyhow!("Failed to get control block"))?;

        let internal_key_hex = keypair.display_secret().to_string();
        let control_block_bytes = control_block.serialize();

        Ok((address, internal_key_hex, control_block_bytes))
    }
}
