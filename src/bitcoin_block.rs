use std::sync::Arc;
use std::time::Instant;

use crate::bitcoin_rpc_client::BitcoinRpcReadClient;
use alloy_primitives::{Address, U256};
use bitcoin::{
    hashes::Hash,
    opcodes::{
        all::{OP_ENDIF, OP_IF, OP_RETURN},
        OP_FALSE, OP_TRUE,
    },
    script::Instruction,
    Script, Transaction,
};
use tracing::{debug, info, trace, warn};

use crate::block::{decode_tx_envelope, CoreLaneBlockParsed, CoreLaneBundleCbor, CoreLaneBurn};

pub fn process_bitcoin_block(
    bitcoin_client: Arc<dyn BitcoinRpcReadClient>,
    height: u64,
) -> Result<CoreLaneBlockParsed, anyhow::Error> {
    let bitcoin_start_time = Instant::now();
    info!(
        "📦 Processing Bitcoin block {} with height {}",
        height, height
    );
    let hash_hex = bitcoin_client.get_block_hash_hex(height)?;
    let block = bitcoin_client.get_block_by_hash_hex(&hash_hex)?;

    info!(
        "📦 Processing Bitcoin block {} with {} transactions",
        height,
        block.txdata.len()
    );

    // Use hashes from the decoded block - avoids RPC roundtrip and byte-order issues
    let hash = block.block_hash();
    let bitcoin_block_hash_bytes: Vec<u8> = hash.as_raw_hash().to_byte_array().to_vec();
    let bitcoin_block_timestamp = block.header.time as u64;

    let parent_hash: Vec<u8> = if height > 0 {
        block
            .header
            .prev_blockhash
            .as_raw_hash()
            .to_byte_array()
            .to_vec()
    } else {
        Vec::new()
    };

    let mut core_lane_block = CoreLaneBlockParsed::new(
        bitcoin_block_hash_bytes,
        bitcoin_block_timestamp,
        height,
        parent_hash,
    );

    for (tx_index, tx) in block.txdata.iter().enumerate() {
        let txid = tx.compute_txid();

        if let Some((payload, burn_value)) =
            extract_burn_payload_from_tx(bitcoin_client.as_ref(), tx)
        {
            info!(
                "   🔥 Found Bitcoin burn in tx {}: {} ({}sats)",
                tx_index, txid, burn_value
            );
            let burn = process_bitcoin_burn(payload, burn_value, txid.to_string());
            if let Ok(burn) = burn {
                core_lane_block.add_burn(burn);
            }
        }
    }
    for (tx_index, tx) in block.txdata.iter().enumerate() {
        let txid = tx.compute_txid();

        if let Some(lane_tx) = extract_core_lane_transaction(tx) {
            info!(
                "   🔍 Found Core Lane DA transaction in tx {}: {}",
                tx_index, txid
            );

            if let Some((tx, sender)) = decode_tx_envelope(&lane_tx) {
                core_lane_block.add_bundle_from_single_tx(tx, sender, lane_tx);
            } else {
                warn!(
                    "   ❌ Failed to decode Core Lane DA transaction in tx {}: {}",
                    tx_index, txid
                );
            }
        }
    }

    // Third pass: Look for CORE_BNDL bundles
    for (tx_index, tx) in block.txdata.iter().enumerate() {
        let txid = tx.compute_txid();

        if let Some(bundle_data) = extract_core_bndl_transaction(tx) {
            info!(
                "   📦 Found Core Lane Bundle (CORE_BNDL) in tx {}: {}",
                tx_index, txid
            );

            match CoreLaneBundleCbor::from_cbor(&bundle_data) {
                Ok(cbor_bundle) => {
                    info!(
                        "   📦 Bundle contains {} transactions",
                        cbor_bundle.transactions.len()
                    );
                    if let Err(e) = core_lane_block.add_bundle_from_cbor(cbor_bundle) {
                        warn!(
                            "   ❌ Failed to process Core Lane Bundle in tx {}: {} - {}",
                            tx_index, txid, e
                        );
                    } else {
                        info!("   ✅ Successfully processed Core Lane Bundle");
                    }
                }
                Err(e) => {
                    warn!(
                        "   ❌ Failed to parse CORE_BNDL data in tx {}: {} - {}",
                        tx_index, txid, e
                    );
                }
            }
        }
    }

    let bitcoin_processing_time = bitcoin_start_time.elapsed();
    info!(
        "Bitcoin block processing completed in {:?} for height: {}",
        bitcoin_processing_time, height
    );

    Ok(core_lane_block)
}

fn process_bitcoin_burn(
    payload: Vec<u8>,
    burn_value: u64,
    txid: String,
) -> Result<CoreLaneBurn, anyhow::Error> {
    // Extract chain ID and ETH address from BRN1 payload
    if payload.len() >= 28 && &payload[0..4] == b"BRN1" {
        let chain_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let eth_address_bytes = &payload[8..28];
        let eth_address = Address::from_slice(eth_address_bytes);

        info!("🔥 Processing Bitcoin burn:");
        info!("   Transaction: {}", txid);
        info!("   Burnt value: {} sats", burn_value);
        info!("   Chain ID: {}", chain_id);
        info!("   ETH Address: {}", eth_address);

        // Check if this is for Core Lane chain ID 1281453634 or Ethereum mainnet chain ID 1
        if chain_id == 1281453634 || chain_id == 1 {
            // Convert Bitcoin sats to Core Lane tokens with proper decimal scaling
            // Bitcoin: 1 BTC = 100,000,000 sats (8 decimals)
            // Core Lane: 1 laneBTC = 10^18 wei (18 decimals)
            // Conversion: 1 sat = 10^10 wei (to maintain reasonable exchange rate)
            let conversion_factor = U256::from(10_000_000_000u64); // 10^10
            let mint_amount = U256::from(burn_value) * conversion_factor;

            info!(
                "   🪙 Attempting to mint {} tokens to {}",
                mint_amount, eth_address
            );

            Ok(CoreLaneBurn::new(mint_amount, eth_address))
        } else {
            Err(anyhow::anyhow!(
                "   ⚠️  Burn for different chain ID ({}), ignoring",
                chain_id
            ))
        }
    } else {
        Err(anyhow::anyhow!("   ❌ Invalid BRN1 payload format"))
    }
}

fn extract_burn_payload_from_tx(
    _client: &dyn BitcoinRpcReadClient,
    tx: &Transaction,
) -> Option<(Vec<u8>, u64)> {
    // Look for hybrid P2WSH + OP_RETURN burn pattern
    let mut p2wsh_burn_value = 0u64;
    let mut brn1_payload = None;

    for output in &tx.output {
        // Check for P2WSH burn outputs
        if is_p2wsh_script(&output.script_pubkey) {
            let burnt_value = output.value.to_sat();
            if burnt_value > 0 {
                p2wsh_burn_value = burnt_value;
                debug!("   🔍 Found P2WSH burn output: {} sats", burnt_value);
            }
        }

        // Check for OP_RETURN with BRN1 data
        if is_op_return_script(&output.script_pubkey) {
            let payload_bytes = output.script_pubkey.as_bytes();

            // OP_RETURN script structure: [OP_RETURN] [push_opcode] [data...]
            if payload_bytes.len() >= 30 && payload_bytes[0] == 0x6a {
                let data = &payload_bytes[2..]; // Skip OP_RETURN and push opcode

                // Check for BRN1 prefix
                if data.len() >= 28 && &data[0..4] == b"BRN1" {
                    let mut payload = Vec::with_capacity(28);
                    payload.extend_from_slice(b"BRN1");
                    payload.extend_from_slice(&data[4..8]); // chain_id
                    payload.extend_from_slice(&data[8..28]); // eth_address
                    brn1_payload = Some(payload);
                    debug!("   🔍 Found BRN1 data in OP_RETURN");
                }
            }
        }
    }

    // If we found both P2WSH burn and BRN1 data, this is our hybrid burn
    if p2wsh_burn_value > 0 {
        if let Some(payload) = brn1_payload {
            info!(
                "   ✅ Found hybrid P2WSH + OP_RETURN burn: {} sats",
                p2wsh_burn_value
            );
            return Some((payload, p2wsh_burn_value));
        }
    }

    None
}

/// Check if script is OP_RETURN
fn is_op_return_script(script: &Script) -> bool {
    let mut instr = script.instructions();
    if let Some(Ok(Instruction::Op(op))) = instr.next() {
        op == OP_RETURN
    } else {
        false
    }
}

/// Check if script is P2WSH
fn is_p2wsh_script(script: &Script) -> bool {
    let bytes = script.as_bytes();
    // P2WSH: OP_0 (0x00) + 32-byte hash
    bytes.len() == 34 && bytes[0] == 0x00
}

/// Generic function to extract prefixed transaction data from Bitcoin Taproot witnesses/outputs
/// Scans a Transaction for Taproot witnesses and outputs, looking for the specified prefix
fn extract_prefixed_transaction(tx: &Transaction, prefix: &[u8]) -> Option<Vec<u8>> {
    let prefix_str = std::str::from_utf8(prefix).unwrap_or("UNKNOWN");

    // Check inputs for witness data (revealed Taproot envelopes)
    for (input_idx, input) in tx.input.iter().enumerate() {
        if input.witness.len() >= 2 {
            trace!(
                "   🔍 Input {} has witness with {} elements ({} check)",
                input_idx,
                input.witness.len(),
                prefix_str
            );

            // Use zero-copy taproot_leaf_script() to avoid duplicating potentially large payloads
            if let Some(leaf_script) = input.witness.taproot_leaf_script() {
                // Use the generic extraction logic with prefix (zero-copy)
                if let Some(data) = extract_envelope_data_with_prefix(leaf_script.script, prefix) {
                    // If we got data back, it means we found a transaction with the prefix
                    if !data.is_empty() {
                        info!(
                            "   🎯 Found {} transaction in Taproot envelope!",
                            prefix_str
                        );
                        return Some(data);
                    }
                }
            }
        }
    }

    // Also check outputs (for newly created Taproot envelopes)
    for output in &tx.output {
        let script_pubkey = &output.script_pubkey;

        // Check if this is a P2TR output
        if script_pubkey.as_bytes().len() == 34 && script_pubkey.as_bytes()[0] == 0x51 {
            // This is a P2TR output, but we can't directly extract the data
            // because it's committed in the Taproot tree
            // We'll need to look for the actual spend transaction later
            debug!(
                "   🔍 Found P2TR output (potential {} envelope)",
                prefix_str
            );
        }
    }

    None
}

fn extract_core_lane_transaction(tx: &Transaction) -> Option<Vec<u8>> {
    extract_prefixed_transaction(tx, b"CORE_LANE")
}

/// Generic function to extract envelope data with a specified prefix
/// Parses a Script and returns the payload after validating the provided prefix
fn extract_envelope_data_with_prefix(script: &Script, prefix: &[u8]) -> Option<Vec<u8>> {
    let prefix_str = std::str::from_utf8(prefix).unwrap_or("UNKNOWN");
    let mut instr = script.instructions();

    let first = instr.next().and_then(|r| r.ok());
    if first != Some(Instruction::Op(OP_FALSE))
        && first
            != Some(Instruction::PushBytes(
                bitcoin::blockdata::script::PushBytes::empty(),
            ))
    {
        return None;
    }

    if instr.next().and_then(|r| r.ok()) != Some(Instruction::Op(OP_IF)) {
        return None;
    }

    // Collect all push operations between OP_IF and OP_ENDIF
    let mut push_operations: Vec<Vec<u8>> = Vec::new();
    loop {
        match instr.next().and_then(|r| r.ok()) {
            Some(Instruction::Op(OP_ENDIF)) => break,
            Some(Instruction::PushBytes(b)) => {
                push_operations.push(b.as_bytes().to_vec());
            }
            _ => return None,
        }
    }

    let last = instr.next().and_then(|r| r.ok());
    if last != Some(Instruction::Op(OP_TRUE))
        && last
            != Some(Instruction::Op(
                bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1,
            ))
    {
        return None;
    }

    trace!(
        "   🔍 {} Script analysis: found {} push operations",
        prefix_str,
        push_operations.len()
    );
    for (i, push_op) in push_operations.iter().enumerate() {
        trace!("     Push[{}]: {} bytes", i, push_op.len());
        if push_op.len() < 100 {
            trace!("     Push[{}] hex: {}", i, hex::encode(push_op));
        } else {
            trace!(
                "     Push[{}] (first 50): {}",
                i,
                hex::encode(&push_op[..50])
            );
            trace!(
                "     Push[{}] (last 50): {}",
                i,
                hex::encode(&push_op[push_op.len() - 50..])
            );
        }
    }

    // Concatenate all push operations to get the complete data
    let mut data: Vec<u8> = Vec::new();
    for push_op in push_operations {
        data.extend_from_slice(&push_op);
    }

    trace!(
        "   🔍 {} Concatenated data: {} bytes",
        prefix_str,
        data.len()
    );
    if data.len() < 100 {
        trace!(
            "   🔍 {} Concatenated hex: {}",
            prefix_str,
            hex::encode(&data)
        );
    } else {
        trace!(
            "   🔍 {} Concatenated (first 50): {}",
            prefix_str,
            hex::encode(&data[..50])
        );
        trace!(
            "   🔍 {} Concatenated (last 50): {}",
            prefix_str,
            hex::encode(&data[data.len() - 50..])
        );
    }

    // Check if the concatenated data starts with the specified prefix
    if data.starts_with(prefix) {
        // Return just the payload data (after prefix)
        let prefix_len = prefix.len();
        let payload_data = &data[prefix_len..];

        // Remove padding from the end (look for 0xf0 padding pattern)
        let mut clean_end = payload_data.len();
        for i in (0..payload_data.len()).rev() {
            if payload_data[i] == 0xf0 {
                clean_end = i;
            } else {
                break;
            }
        }

        let clean_payload = &payload_data[..clean_end];
        trace!(
            "   🔍 {} Extracted payload: {} bytes (removed {} padding bytes)",
            prefix_str,
            clean_payload.len(),
            payload_data.len() - clean_payload.len()
        );
        if clean_payload.len() < 100 {
            trace!(
                "   🔍 {} Payload hex: {}",
                prefix_str,
                hex::encode(clean_payload)
            );
        } else {
            trace!(
                "   🔍 {} Payload (first 50): {}",
                prefix_str,
                hex::encode(&clean_payload[..50])
            );
            trace!(
                "   🔍 {} Payload (last 50): {}",
                prefix_str,
                hex::encode(&clean_payload[clean_payload.len() - 50..])
            );
        }

        return Some(clean_payload.to_vec());
    }

    None
}

fn extract_core_bndl_transaction(tx: &Transaction) -> Option<Vec<u8>> {
    extract_prefixed_transaction(tx, b"CORE_BNDL")
}
