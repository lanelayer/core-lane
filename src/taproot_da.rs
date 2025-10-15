use anyhow::{anyhow, Result};
use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{
    blockdata::opcodes::all::{OP_ENDIF, OP_IF},
    blockdata::opcodes::{OP_FALSE, OP_TRUE},
    blockdata::script::Builder,
    Address as BitcoinAddress, Amount, FeeRate, ScriptBuf, Transaction, Witness,
};
use bitcoincore_rpc::{Client, RpcApi};
use secp256k1::rand::rngs::OsRng;
use std::sync::Arc;

// BDK imports for wallet operations
use bdk_wallet::keys::{bip39::Mnemonic, DerivableKey, ExtendedKey};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, Wallet};

pub struct TaprootDA {
    // Keep bitcoin_client for RPC operations (fee estimation, broadcasting)
    bitcoin_client: Arc<Client>,
}

impl TaprootDA {
    pub fn new(bitcoin_client: Arc<Client>) -> Self {
        Self { bitcoin_client }
    }

    /// Calculate exact reveal transaction fee based on payload size
    fn calculate_exact_reveal_fee(
        &self,
        envelope_script: &ScriptBuf,
        control_block: &[u8],
        sat_per_vb: u64,
        available_amount: u64,
    ) -> Result<u64> {
        // Create a temporary reveal transaction to calculate its exact size
        let temp_reveal_tx = self.create_temp_reveal_transaction(envelope_script, control_block)?;
        let temp_reveal_hex = hex::encode(bitcoin::consensus::serialize(&temp_reveal_tx));

        // Calculate exact transaction size in vB
        let exact_tx_size_vb = self.calculate_actual_tx_size_vb(&temp_reveal_hex)?;

        // Calculate fee based on exact size
        let mut reveal_fee = sat_per_vb * exact_tx_size_vb;

        // Ensure reveal transaction meets minimum relay fee requirement (16 sats for Bitcoin Core 30.0.0)
        let min_relay_fee_sats = 16;
        if reveal_fee < min_relay_fee_sats {
            tracing::warn!(
                "💰 Reveal fee {} sats below minimum relay fee {} sats, adjusting",
                reveal_fee,
                min_relay_fee_sats
            );
            let adjusted_sat_per_vb = min_relay_fee_sats.div_ceil(exact_tx_size_vb);
            reveal_fee = adjusted_sat_per_vb * exact_tx_size_vb;
            tracing::info!(
                "🔧 Adjusted reveal fee rate: {} sat/vB (was {} sat/vB)",
                adjusted_sat_per_vb,
                sat_per_vb
            );
            tracing::info!(
                "💰 Adjusted reveal fee: {} sats (was {} sats)",
                reveal_fee,
                sat_per_vb * exact_tx_size_vb
            );
        }

        // Cap the fee to the available Taproot output amount
        if reveal_fee > available_amount {
            reveal_fee = available_amount;
            tracing::warn!(
                "💰 Capping reveal fee to available amount: {} sats",
                reveal_fee
            );
        }

        tracing::info!(
            "🔍 Exact reveal transaction fee: {} sats ({} sat/vB × {} vB)",
            reveal_fee,
            reveal_fee / exact_tx_size_vb,
            exact_tx_size_vb
        );
        tracing::info!("📏 Exact reveal transaction size: {} vB", exact_tx_size_vb);

        Ok(reveal_fee)
    }

    /// Create a temporary reveal transaction for size calculation
    fn create_temp_reveal_transaction(
        &self,
        envelope_script: &ScriptBuf,
        control_block: &[u8],
    ) -> Result<Transaction> {
        // Create OP_RETURN output with Core Lane reveal data
        let op_return_data = b"CORELANE";
        let op_return_script = Builder::new()
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_RETURN)
            .push_slice(op_return_data)
            .into_script();

        // Create the transaction structure with minimal input
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(), // Use null outpoint
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: Witness::new(), // Will be filled below
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(0), // Zero value for OP_RETURN
                script_pubkey: op_return_script,
            }],
        };

        // Add the witness data (this is what we're measuring)
        let mut witness = Witness::new();
        witness.push(envelope_script.as_bytes());
        witness.push(control_block);
        tx.input[0].witness = witness;

        Ok(tx)
    }

    /// Calculate actual transaction size in virtual bytes (vB) from raw transaction hex
    fn calculate_actual_tx_size_vb(&self, raw_tx_hex: &str) -> Result<u64> {
        // Decode the raw transaction hex
        let tx_bytes = hex::decode(raw_tx_hex).map_err(|e| anyhow!("Invalid hex format: {}", e))?;

        // Parse the transaction to get its structure
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
            .map_err(|e| anyhow!("Failed to deserialize transaction: {}", e))?;

        // Use the battle-tested weight calculation from rust-bitcoin (BIP-141 exact)
        let weight = tx.weight();
        let vsize = weight.to_wu().div_ceil(4);

        tracing::info!(
            "📏 Actual transaction size: {} vB (weight: {} WU)",
            vsize,
            weight.to_wu()
        );
        Ok(vsize)
    }

    async fn calculate_optimal_fee_rate(&self) -> Result<u64> {
        // Get the minimum relay fee from the Bitcoin node
        let minrelayfee_result: Result<serde_json::Value, _> =
            self.bitcoin_client.call("getnetworkinfo", &[]);
        let min_relay_fee_sat_vb = match minrelayfee_result {
            Ok(network_info) => {
                if let Some(minrelayfee) = network_info.get("relayfee").and_then(|v| v.as_f64()) {
                    // Convert from BTC/kB to sat/vB
                    let minrelayfee_sats = (minrelayfee * 100_000_000.0) as u64;
                    let min_relay_fee_sat_vb = minrelayfee_sats / 1000; // Convert kB to vB
                    tracing::info!(
                        "🔍 Bitcoin node minrelayfee: {} sat/vB",
                        min_relay_fee_sat_vb
                    );
                    min_relay_fee_sat_vb
                } else {
                    tracing::warn!("🔍 No relayfee in network info, using fallback");
                    2 // Fallback to 2 sat/vB
                }
            }
            Err(e) => {
                tracing::warn!("🔍 Failed to get network info: {}, using fallback", e);
                2 // Fallback to 2 sat/vB
            }
        };

        // Get fee rate from estimatesmartfee
        let fee_estimate: Result<serde_json::Value, _> = self.bitcoin_client.call(
            "estimatesmartfee",
            &[serde_json::json!(6), serde_json::json!("ECONOMICAL")],
        );

        let sat_per_vb = match fee_estimate {
            Ok(result) => {
                tracing::debug!("🔍 Fee estimate result: {:?}", result);
                if let Some(fee_rate) = result.get("feerate").and_then(|v| v.as_f64()) {
                    tracing::info!("🔍 Raw fee rate from estimatesmartfee: {} BTC/kB", fee_rate);
                    // Convert from BTC/kB to sat/vB
                    let fee_per_kb_sats = (fee_rate * 100_000_000.0) as u64;
                    let sat_per_vb = fee_per_kb_sats / 1000; // Convert kB to vB
                    tracing::info!("🔍 Before capping: {} sat/vB", sat_per_vb);
                    let capped_sat_per_vb = sat_per_vb.max(min_relay_fee_sat_vb).min(50); // Cap at 50 sat/vB max, min relay fee
                    tracing::info!(
                        "🔍 After capping: {} sat/vB (was {})",
                        capped_sat_per_vb,
                        sat_per_vb
                    );
                    capped_sat_per_vb
                } else {
                    tracing::warn!("🔍 No feerate in result, using min relay fee");
                    min_relay_fee_sat_vb // Use min relay fee as fallback
                }
            }
            Err(e) => {
                tracing::warn!("🔍 Fee estimate error: {}, using min relay fee", e);
                min_relay_fee_sat_vb // Use min relay fee as fallback
            }
        };

        let final_sat_per_vb = sat_per_vb.clamp(1, 10);
        tracing::info!(
            "🔧 FORCED fee rate: {} sat/vB (was {})",
            final_sat_per_vb,
            sat_per_vb
        );
        tracing::info!("💰 Final fee rate: {} sat/vB", final_sat_per_vb);

        Ok(final_sat_per_vb)
    }

    pub async fn send_transaction_to_da(
        &self,
        raw_tx_hex: &str,
        mnemonic_str: &str,
        network: bitcoin::Network,
        network_str: &str,
        electrum_url: Option<&str>,
        data_dir: &str,
    ) -> Result<String> {
        tracing::info!(
            "🚀 Creating Core Lane transaction in Bitcoin DA (commit + reveal in one tx)..."
        );
        tracing::info!(
            "📝 Ethereum transaction: {}...",
            &raw_tx_hex[..64.min(raw_tx_hex.len())]
        );

        // Load BDK wallet for commit transaction
        tracing::info!("🔑 Loading BDK wallet for commit transaction...");

        // Parse mnemonic and derive signing keys
        let mnemonic =
            Mnemonic::parse(mnemonic_str).map_err(|e| anyhow!("Invalid mnemonic: {}", e))?;

        let xkey: ExtendedKey = mnemonic
            .into_extended_key()
            .map_err(|_| anyhow!("Failed to derive extended key"))?;
        let xprv = xkey
            .into_xprv(network)
            .ok_or_else(|| anyhow!("Failed to get xprv"))?;

        // Reconstruct descriptors with xprv for signing
        let external_descriptor = format!("wpkh({}/0/*)", xprv);
        let internal_descriptor = format!("wpkh({}/1/*)", xprv);

        // Ensure data directory exists
        std::fs::create_dir_all(data_dir)?;

        // Load wallet
        let wallet_path =
            std::path::Path::new(data_dir).join(format!("wallet_{}.sqlite3", network_str));
        let mut conn = Connection::open(&wallet_path)?;

        let wallet_opt = Wallet::load()
            .descriptor(KeychainKind::External, Some(external_descriptor.clone()))
            .descriptor(KeychainKind::Internal, Some(internal_descriptor.clone()))
            .extract_keys()
            .check_network(network)
            .load_wallet(&mut conn)?;

        let mut wallet = match wallet_opt {
            Some(w) => {
                tracing::info!("📂 Existing wallet database loaded");
                w
            }
            None => {
                // Wallet doesn't exist, create it from mnemonic
                tracing::info!("📝 Wallet database not found, creating from mnemonic...");

                // Create wallet in database
                let created_wallet =
                    Wallet::create(external_descriptor.clone(), internal_descriptor.clone())
                        .network(network)
                        .create_wallet(&mut conn)?;

                // Drop and reload with extract_keys to ensure we can sign
                drop(created_wallet);

                Wallet::load()
                    .descriptor(KeychainKind::External, Some(external_descriptor))
                    .descriptor(KeychainKind::Internal, Some(internal_descriptor))
                    .extract_keys()
                    .check_network(network)
                    .load_wallet(&mut conn)?
                    .expect("Wallet we just created must exist")
            }
        };

        tracing::info!("✅ BDK wallet loaded");

        // Sync wallet based on network
        tracing::info!("🔗 Syncing wallet...");
        if network_str == "regtest" {
            // Use Bitcoin RPC for regtest
            use bdk_bitcoind_rpc::Emitter;
            let mut emitter = Emitter::new(
                self.bitcoin_client.as_ref(),
                wallet.latest_checkpoint().clone(),
                0,
                std::iter::empty::<Arc<Transaction>>(),
            );

            while let Some(block_emission) = emitter.next_block()? {
                wallet.apply_block(&block_emission.block, block_emission.block_height())?;
            }

            wallet.persist(&mut conn)?;
        } else {
            // Use Electrum for other networks
            use bdk_electrum::{electrum_client, BdkElectrumClient};

            let electrum_url = electrum_url
                .ok_or_else(|| anyhow!("--electrum-url required for network: {}", network_str))?;

            tracing::info!("🔗 Connecting to Electrum: {}", electrum_url);

            let electrum_client = electrum_client::Client::new(electrum_url)?;
            let electrum = BdkElectrumClient::new(electrum_client);

            tracing::info!("🔍 Scanning blockchain for wallet transactions...");

            let request = wallet.start_full_scan().build();
            let response = electrum.full_scan(request, 5, 1, false)?;

            wallet.apply_update(response)?;
            wallet.persist(&mut conn)?;
        }
        tracing::info!("✅ Wallet synced");

        // Calculate optimal fee rate
        let sat_per_vb = self.calculate_optimal_fee_rate().await?;
        tracing::info!("💰 Fee rate: {} sat/vB", sat_per_vb);

        // Validate the Ethereum transaction hex
        let tx_bytes = hex::decode(raw_tx_hex).map_err(|e| anyhow!("Invalid hex format: {}", e))?;

        tracing::debug!("🔍 Raw Ethereum transaction:");
        tracing::debug!("   📝 Input hex: {}", raw_tx_hex);
        tracing::debug!(
            "   📏 Input length: {} chars ({} bytes)",
            raw_tx_hex.len(),
            tx_bytes.len()
        );
        tracing::debug!("   📝 Decoded bytes: {}", hex::encode(&tx_bytes));

        let mut payload = Vec::new();
        payload.extend_from_slice(b"CORE_LANE");
        payload.extend_from_slice(&tx_bytes);

        tracing::info!("📦 Core Lane payload size: {} bytes", payload.len());
        tracing::debug!("📦 Core Lane payload hex: {}", hex::encode(&payload));

        // Check wallet balance

        // fundrawtransaction will handle UTXO selection automatically

        // Create a Taproot output with Core Lane data embedded
        let envelope_script = self.create_taproot_envelope_script(&payload)?;
        let (taproot_address, internal_key, control_block) =
            self.create_taproot_address_with_info(&payload, network)?;

        tracing::info!("🎯 Created Taproot address: {}", taproot_address);
        tracing::debug!("🔑 Internal key: {}", internal_key);

        // Calculate exact Taproot output amount needed for the reveal transaction
        let exact_reveal_fee = self.calculate_exact_reveal_fee(
            &envelope_script,
            &control_block,
            sat_per_vb,
            u64::MAX, // No limit for calculation
        )?;

        // Ensure Taproot output meets minimum requirements
        // Bitcoin dust threshold for Taproot outputs is 330 sats
        let dust_threshold = 330;
        // Use the exact reveal fee, but ensure it meets dust threshold
        let min_taproot_output = exact_reveal_fee.max(dust_threshold);

        tracing::info!("🔍 Calculated exact Taproot output: {} sats for reveal tx needs (dust threshold: {} sats)", min_taproot_output, dust_threshold);

        // Check wallet balance
        let balance = wallet.balance();
        tracing::info!(
            "💰 Wallet balance: {} sats (confirmed: {})",
            balance.total().to_sat(),
            balance.confirmed.to_sat()
        );

        // Build commit transaction using BDK
        tracing::info!("🔨 Building commit transaction with BDK...");

        let mut tx_builder = wallet.build_tx();

        // Set fee rate
        let fee_rate = FeeRate::from_sat_per_vb(sat_per_vb).expect("valid fee rate");
        tx_builder.fee_rate(fee_rate);

        // Add Taproot output
        tx_builder.add_recipient(
            taproot_address.script_pubkey(),
            Amount::from_sat(min_taproot_output),
        );

        // Build and sign PSBT
        let mut psbt = tx_builder.finish()?;

        tracing::info!("📝 Commit transaction built, signing...");

        #[allow(deprecated)]
        let finalized = wallet.sign(&mut psbt, bdk_wallet::SignOptions::default())?;

        if !finalized {
            use bdk_wallet::bitcoin::secp256k1::Secp256k1;
            use bdk_wallet::miniscript::psbt::PsbtExt;
            psbt.finalize_mut(&Secp256k1::new())
                .map_err(|e| anyhow!("Failed to finalize commit PSBT: {:?}", e))?;
        }

        // Extract commit transaction
        let commit_tx = psbt
            .extract_tx()
            .map_err(|e| anyhow!("Failed to extract commit transaction: {:?}", e))?;
        let commit_tx_hex = hex::encode(bitcoin::consensus::serialize(&commit_tx));

        tracing::info!("✅ Commit transaction signed");

        // Mark transaction as spent in wallet
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        wallet.apply_unconfirmed_txs([(commit_tx.clone(), now)]);
        wallet.persist(&mut conn)?;

        // Now immediately create a reveal transaction that spends the Taproot output
        tracing::info!("🔍 Creating reveal transaction to immediately expose Core Lane data...");

        // Get the Taproot output amount from the commit transaction (parse it directly)
        let commit_tx_bytes = hex::decode(&commit_tx_hex)?;
        let commit_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&commit_tx_bytes)?;

        // Find the Taproot output (it should be the one going to our Taproot address)
        let mut taproot_output_amount = 0u64;
        let mut taproot_vout_index = 0;
        for (vout_index, vout) in commit_tx.output.iter().enumerate() {
            // Check if this output matches our Taproot address
            if vout.script_pubkey == taproot_address.script_pubkey() {
                taproot_output_amount = vout.value.to_sat();
                taproot_vout_index = vout_index;
                tracing::info!(
                    "🔍 Found Taproot output at vout {}: {} sats",
                    vout_index,
                    taproot_output_amount
                );
                tracing::info!(
                    "📊 Total input value for reveal transaction: {} sats (from Taproot output)",
                    taproot_output_amount
                );
                break;
            }
        }

        if taproot_output_amount == 0 {
            return Err(anyhow!(
                "Could not find Taproot output in commit transaction"
            ));
        }

        // Get the commit transaction ID from the transaction hash
        let commit_txid = commit_tx.compute_txid();

        // Calculate exact reveal transaction fee based on payload size (capped to available amount)
        let exact_reveal_fee = self.calculate_exact_reveal_fee(
            &envelope_script,
            &control_block,
            sat_per_vb,
            taproot_output_amount,
        )?;

        // Use the exact fee calculated, not the entire Taproot output amount
        // This ensures we don't overpay fees
        tracing::info!(
            "🔍 Using exact reveal fee: {} sats (Taproot output: {} sats)",
            exact_reveal_fee,
            taproot_output_amount
        );

        tracing::info!("🔍 Using OP_RETURN output with zero value");

        // Create OP_RETURN output with Core Lane reveal data
        let op_return_data = b"CORELANE";
        let op_return_script = Builder::new()
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_RETURN)
            .push_slice(op_return_data)
            .into_script();

        // Construct reveal transaction directly using bitcoin crate
        let mut reveal_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: commit_txid,
                    vout: taproot_vout_index as u32,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: Witness::new(), // Will be set below
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(0),
                script_pubkey: op_return_script,
            }],
        };

        // Add the witness data to reveal the Core Lane transaction
        let mut witness = Witness::new();
        witness.push(envelope_script.as_bytes());
        witness.push(&control_block);
        reveal_tx.input[0].witness = witness;

        let reveal_final_hex = hex::encode(bitcoin::consensus::serialize(&reveal_tx));

        // Submit both transactions as a package using submitpackage
        let package_txs = vec![
            serde_json::json!(commit_tx_hex),
            serde_json::json!(reveal_final_hex),
        ];

        tracing::info!("📦 Submitting commit + reveal transactions as package...");
        let package_result: Result<serde_json::Value, _> = self
            .bitcoin_client
            .call("submitpackage", &[serde_json::json!(package_txs)]);

        match package_result {
            Ok(result) => {
                tracing::info!(
                    "🔍 Package result: {}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );

                // Extract transaction IDs from the package result
                let tx_results = result["tx-results"]
                    .as_object()
                    .ok_or_else(|| anyhow!("Package result missing 'tx-results' object"))?;

                if tx_results.len() < 2 {
                    return Err(anyhow!(
                        "Package result has insufficient transactions: {}",
                        tx_results.len()
                    ));
                }

                // Get the transaction IDs from the tx-results object keys
                let mut tx_ids: Vec<&str> = tx_results.keys().map(|k| k.as_str()).collect();
                tx_ids.sort(); // Sort for consistent ordering

                let commit_txid = tx_ids[0];
                let reveal_txid = tx_ids[1];

                tracing::info!("✅ Core Lane transaction package submitted successfully!");
                tracing::info!("📍 Commit transaction ID: {}", commit_txid);
                tracing::info!("📍 Reveal transaction ID: {}", reveal_txid);
                tracing::info!(
                    "📦 Core Lane data embedded AND revealed atomically in the same block"
                );
                tracing::info!("🎯 Taproot address: {}", taproot_address);
                tracing::info!(
                    "\n🔍 Core Lane node will detect the reveal transaction when scanning blocks!"
                );

                Ok(commit_txid.to_string())
            }
            Err(e) => {
                tracing::error!("❌ Failed to submit transaction package: {}", e);
                Err(anyhow!("Failed to submit transaction package: {}", e))
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
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut OsRng);
        let (xonly, _parity) = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&keypair);

        // Create envelope script for the data
        let envelope_script = self.create_taproot_envelope_script(data)?;

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, envelope_script.clone())
            .map_err(|e| anyhow!("Failed to add leaf to Taproot builder: {}", e))?
            .finalize(&secp, xonly)
            .map_err(|e| anyhow!("Failed to finalize Taproot spend info: {:?}", e))?;

        let output_key = spend_info.output_key();
        let address = BitcoinAddress::p2tr_tweaked(output_key, network);

        let control_block = spend_info
            .control_block(&(envelope_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| anyhow!("Failed to get control block"))?;

        let internal_key_hex = keypair.display_secret().to_string();
        let control_block_bytes = control_block.serialize();

        Ok((address, internal_key_hex, control_block_bytes))
    }
}
