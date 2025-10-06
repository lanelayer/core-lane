use crate::intents::{decode_intent_calldata, Intent, IntentCall, IntentData, IntentStatus};
use crate::CoreLaneState;
use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::TxEnvelope;
use alloy_primitives::B256;
use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_rlp::Decodable;
use anyhow::{anyhow, Result};
use bitcoin::Address as BitcoinAddress;
use bitcoincore_rpc::RpcApi;
use std::str::FromStr;
use tracing::{debug, info};

/// Get the calldata bytes from a transaction envelope (the EVM input payload)
pub fn get_transaction_input_bytes(tx: &TxEnvelope) -> Vec<u8> {
    match tx {
        TxEnvelope::Legacy(signed) => signed.tx().input.as_ref().to_vec(),
        TxEnvelope::Eip1559(signed) => signed.tx().input.as_ref().to_vec(),
        TxEnvelope::Eip2930(signed) => signed.tx().input.as_ref().to_vec(),
        TxEnvelope::Eip4844(_signed) => Vec::new(),
        _ => Vec::new(),
    }
}

/// Get the transaction nonce
fn get_transaction_nonce(tx: &TxEnvelope) -> u64 {
    match tx {
        TxEnvelope::Legacy(signed) => signed.tx().nonce,
        TxEnvelope::Eip1559(signed) => signed.tx().nonce,
        TxEnvelope::Eip2930(signed) => signed.tx().nonce,
        _ => 0,
    }
}

/// Core Lane specific addresses for special operations
#[derive(Debug, Clone)]
pub struct CoreLaneAddresses;

impl CoreLaneAddresses {
    /// Burn address: 0x000000000000000000000000000000000000dead
    pub fn burn() -> Address {
        Address::from([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xde,
        ])
    }

    /// Exit marketplace address: 0x0000000000000000000000000000000000ExitMkT
    pub fn exit_marketplace() -> Address {
        Address::from([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x45,
        ])
    }
}

/// Parse Core Lane transaction from Bitcoin DA data
pub fn parse_core_lane_transaction(data: &[u8]) -> Result<TxEnvelope> {
    if data.len() < 8 || !data.starts_with(b"CORE_LANE") {
        return Err(anyhow!(
            "Invalid Core Lane transaction format - missing CORE_LANE prefix"
        ));
    }

    // Extract the Ethereum transaction data (skip CORE_LANE prefix)
    let tx_data = &data[8..];

    // Try to decode as RLP-encoded Ethereum transaction envelope
    match TxEnvelope::decode(&mut &tx_data[..]) {
        Ok(tx) => {
            // Validate that this is a properly signed transaction
            match &tx {
                TxEnvelope::Legacy(signed_tx) => {
                    // Check if the transaction has a valid signature
                    if signed_tx.signature().r() == U256::ZERO
                        && signed_tx.signature().s() == U256::ZERO
                    {
                        return Err(anyhow!("Invalid signature: r and s cannot be zero"));
                    }
                }
                TxEnvelope::Eip1559(signed_tx) => {
                    if signed_tx.signature().r() == U256::ZERO
                        && signed_tx.signature().s() == U256::ZERO
                    {
                        return Err(anyhow!("Invalid signature: r and s cannot be zero"));
                    }
                }
                TxEnvelope::Eip2930(signed_tx) => {
                    if signed_tx.signature().r() == U256::ZERO
                        && signed_tx.signature().s() == U256::ZERO
                    {
                        return Err(anyhow!("Invalid signature: r and s cannot be zero"));
                    }
                }
                _ => {
                    // For other transaction types, we'll accept them for now
                }
            }
            Ok(tx)
        }
        Err(e) => Err(anyhow!(
            "Failed to decode Ethereum transaction after CORE_LANE prefix: {}",
            e
        )),
    }
}
/// Validate Core Lane transaction
pub fn validate_transaction(tx: &TxEnvelope) -> Result<()> {
    // Basic validation - check that we have a valid transaction envelope
    // In a full implementation, this would validate the signed transaction fields
    match tx {
        TxEnvelope::Legacy(_) => debug!("Validating Legacy transaction"),
        TxEnvelope::Eip2930(_) => debug!("Validating EIP-2930 transaction"),
        TxEnvelope::Eip1559(_) => debug!("Validating EIP-1559 transaction"),
        TxEnvelope::Eip4844(_) => debug!("Validating EIP-4844 transaction"),
        _ => debug!("Validating other transaction type"),
    }

    Ok(())
}

/// Calculate transaction gas cost
pub fn calculate_gas_cost(tx: &TxEnvelope) -> U256 {
    // For now, return a basic gas cost
    // In a full implementation, this would calculate actual gas used from the signed transaction
    match tx {
        TxEnvelope::Legacy(_) => U256::from(21000u64) * U256::from(1000000000u64), // 21k gas * 1 gwei
        TxEnvelope::Eip2930(_) => U256::from(21000u64) * U256::from(1000000000u64),
        TxEnvelope::Eip1559(_) => U256::from(21000u64) * U256::from(1000000000u64),
        TxEnvelope::Eip4844(_) => U256::from(21000u64) * U256::from(1000000000u64),
        _ => U256::from(21000u64) * U256::from(1000000000u64),
    }
}

/// Extract sender address from transaction signature using alloy's built-in recovery
pub fn recover_sender(tx: &TxEnvelope) -> Result<Address> {
    match tx {
        TxEnvelope::Legacy(signed_tx) => {
            // Use alloy's built-in signature recovery method
            match signed_tx.recover_signer() {
                Ok(address) => Ok(address),
                Err(e) => Err(anyhow!("Failed to recover signer from Legacy tx: {:?}", e)),
            }
        }
        TxEnvelope::Eip1559(signed_tx) => {
            // Use alloy's built-in signature recovery method
            match signed_tx.recover_signer() {
                Ok(address) => Ok(address),
                Err(e) => Err(anyhow!(
                    "Failed to recover signer from EIP-1559 tx: {:?}",
                    e
                )),
            }
        }
        TxEnvelope::Eip2930(signed_tx) => {
            // Use alloy's built-in signature recovery method
            match signed_tx.recover_signer() {
                Ok(address) => Ok(address),
                Err(e) => Err(anyhow!(
                    "Failed to recover signer from EIP-2930 tx: {:?}",
                    e
                )),
            }
        }
        _ => Err(anyhow!("Unsupported transaction type for sender recovery")),
    }
}
/// Transaction execution result
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub success: bool,
    pub gas_used: U256,
    pub gas_refund: U256,
    pub output: Bytes,
    pub logs: Vec<String>, // Simplified logs for now
    pub error: Option<String>,
}

/// Execute a Core Lane transaction
pub fn execute_transaction(
    tx: &TxEnvelope,
    sender: Address,
    //account_manager: &mut crate::account::AccountManager,
    //intents: &mut HashMap<B256, (Bytes, u64)>,
    state: &mut CoreLaneState,
) -> Result<ExecutionResult> {
    // Basic execution framework
    let gas_limit = get_gas_limit(tx);
    let gas_price = get_gas_price(tx);

    info!("🔄 Executing transaction:");
    info!("   Sender: {}", sender);
    info!("   Gas limit: {}", gas_limit);
    info!("   Gas price: {}", gas_price);

    // Check if sender has enough balance for gas
    let sender_balance = state.account_manager.get_balance(sender);
    let max_gas_cost = U256::from(gas_limit) * U256::from(gas_price);

    if sender_balance < max_gas_cost {
        return Ok(ExecutionResult {
            success: false,
            gas_used: U256::ZERO,
            gas_refund: U256::ZERO,
            output: Bytes::new(),
            logs: vec!["Insufficient balance for gas".to_string()],
            error: Some("Insufficient balance for gas".to_string()),
        });
    }

    execute_transfer(tx, sender, state)
}

/// Get gas limit from transaction
fn get_gas_limit(tx: &TxEnvelope) -> u64 {
    match tx {
        TxEnvelope::Legacy(signed_tx) => signed_tx.tx().gas_limit,
        TxEnvelope::Eip1559(signed_tx) => signed_tx.tx().gas_limit,
        TxEnvelope::Eip2930(signed_tx) => signed_tx.tx().gas_limit,
        TxEnvelope::Eip4844(_signed_tx) => {
            // EIP-4844 has different structure, use a default for now
            21000 // Default gas limit
        }
        _ => 21000, // Default
    }
}

/// Get gas price from transaction
fn get_gas_price(tx: &TxEnvelope) -> u64 {
    match tx {
        TxEnvelope::Legacy(signed_tx) => signed_tx.tx().gas_price.try_into().unwrap_or(1000000000),
        TxEnvelope::Eip1559(signed_tx) => signed_tx
            .tx()
            .max_fee_per_gas
            .try_into()
            .unwrap_or(1000000000),
        TxEnvelope::Eip2930(signed_tx) => signed_tx.tx().gas_price.try_into().unwrap_or(1000000000),
        TxEnvelope::Eip4844(_signed_tx) => {
            // EIP-4844 has different structure, use a default for now
            1000000000 // Default 1 gwei
        }
        _ => 1000000000, // Default 1 gwei
    }
}

/// Get transaction value
fn get_transaction_value(tx: &TxEnvelope) -> U256 {
    match tx {
        TxEnvelope::Legacy(signed_tx) => signed_tx.tx().value,
        TxEnvelope::Eip1559(signed_tx) => signed_tx.tx().value,
        TxEnvelope::Eip2930(signed_tx) => signed_tx.tx().value,
        TxEnvelope::Eip4844(_signed_tx) => {
            // EIP-4844 has different structure, use zero for now
            U256::ZERO
        }
        _ => U256::ZERO,
    }
}

/// Get transaction recipient
fn get_transaction_to(tx: &TxEnvelope) -> Option<Address> {
    match tx {
        TxEnvelope::Legacy(signed_tx) => signed_tx.tx().to.into(),
        TxEnvelope::Eip1559(signed_tx) => signed_tx.tx().to.into(),
        TxEnvelope::Eip2930(signed_tx) => signed_tx.tx().to.into(),
        TxEnvelope::Eip4844(_signed_tx) => {
            // EIP-4844 has different structure, return None for now
            None
        }
        _ => None,
    }
}

/// Execute transfer operation
fn execute_transfer(
    tx: &TxEnvelope,
    sender: Address,
    state: &mut CoreLaneState,
) -> Result<ExecutionResult> {
    let value = get_transaction_value(tx);
    let gas_used = U256::from(21000u64);

    let to = match get_transaction_to(tx) {
        Some(addr) => addr,
        None => {
            return Ok(ExecutionResult {
                success: false,
                gas_used,
                gas_refund: U256::ZERO,
                output: Bytes::new(),
                logs: vec!["No recipient specified for transfer".to_string()],
                error: Some("No recipient specified for transfer".to_string()),
            });
        }
    };

    if to == CoreLaneAddresses::exit_marketplace() {
        let input = Bytes::from(get_transaction_input_bytes(tx));
        let nonce = get_transaction_nonce(tx);
        if input.len() < 4 {
            return Ok(ExecutionResult {
                success: false,
                gas_used,
                gas_refund: U256::ZERO,
                output: Bytes::new(),
                logs: vec!["Intent ABI: calldata too short".to_string()],
                error: Some("Malformed calldata".to_string()),
            });
        }

        match decode_intent_calldata(&input) {
            Some(IntentCall::StoreBlob { data, .. }) => {
                let blob_hash = keccak256(&data);
                if state.stored_blobs.contains(&blob_hash) {
                    return Ok(ExecutionResult {
                        success: true,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec![format!("Blob already stored: blob_hash = {}", blob_hash)],
                        error: None,
                    });
                }
                state.stored_blobs.insert(blob_hash);
                let _ = state.account_manager.increment_nonce(sender);
                return Ok(ExecutionResult {
                    success: true,
                    gas_used,
                    gas_refund: U256::ZERO,
                    output: Bytes::new(),
                    logs: vec![format!("Blob stored: blob_hash = {}", blob_hash)],
                    error: None,
                });
            }
            Some(IntentCall::IntentFromBlob {
                blob_hash,
                extra_data,
                ..
            }) => {
                if !state.stored_blobs.contains(&blob_hash) {
                    return Ok(ExecutionResult {
                        success: false,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec!["intentFromBlob: blob not stored".to_string()],
                        error: Some("Blob not stored".to_string()),
                    });
                }

                if state.account_manager.get_balance(sender) < value {
                    return Ok(ExecutionResult {
                        success: false,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec!["Insufficient balance for intent lock".to_string()],
                        error: Some("Insufficient balance".to_string()),
                    });
                }

                let mut preimage = Vec::new();
                preimage.extend_from_slice(blob_hash.as_slice());
                preimage.extend_from_slice(&extra_data);

                state.account_manager.sub_balance(sender, value)?;
                state.account_manager.increment_nonce(sender)?;
                let value_u64: u64 = value.try_into().unwrap();
                let intent_id = calculate_intent_id(sender, nonce, Bytes::from(preimage));
                state.intents.insert(
                    intent_id,
                    Intent {
                        data: Bytes::from(extra_data),
                        value: value_u64,
                        status: IntentStatus::Submitted,
                    },
                );
                return Ok(ExecutionResult {
                    success: true,
                    gas_used,
                    gas_refund: U256::ZERO,
                    output: Bytes::new(),
                    logs: vec![format!(
                        "Intent from blob submitted: intent_id = {}",
                        intent_id
                    )],
                    error: None,
                });
            }
            Some(IntentCall::Intent { intent_data, .. }) => {
                // Explicit intent submission via ABI: use the intent payload for ID
                if state.account_manager.get_balance(sender) < value {
                    return Ok(ExecutionResult {
                        success: false,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec!["Insufficient balance for intent lock".to_string()],
                        error: Some("Insufficient balance".to_string()),
                    });
                }
                state.account_manager.sub_balance(sender, value)?;
                state.account_manager.increment_nonce(sender)?;
                let value_u64: u64 = value.try_into().unwrap_or(u64::MAX);
                let intent_id =
                    calculate_intent_id(sender, nonce, Bytes::from(intent_data.clone()));
                state.intents.insert(
                    intent_id,
                    Intent {
                        data: Bytes::from(intent_data),
                        value: value_u64,
                        status: IntentStatus::Submitted,
                    },
                );
                return Ok(ExecutionResult {
                    success: true,
                    gas_used,
                    gas_refund: U256::ZERO,
                    output: Bytes::new(),
                    logs: vec![format!("Intent submitted: intent_id = {}", intent_id)],
                    error: None,
                });
            }
            Some(IntentCall::IsIntentSolved { intent_id }) => {
                let solved = match state.intents.get(&intent_id) {
                    Some(intent) => matches!(intent.status, IntentStatus::Solved),
                    None => false,
                };
                let mut ret = vec![0u8; 32];
                if solved {
                    ret[31] = 1;
                }
                return Ok(ExecutionResult {
                    success: true,
                    gas_used,
                    gas_refund: U256::ZERO,
                    output: Bytes::from(ret),
                    logs: vec!["isIntentSolved".to_string()],
                    error: None,
                });
            }
            Some(IntentCall::LockIntentForSolving { intent_id, .. }) => {
                if let Some(intent) = state.intents.get_mut(&intent_id) {
                    match intent.status {
                        IntentStatus::Submitted => {
                            intent.status = IntentStatus::Locked(sender);
                            let _ = state.account_manager.increment_nonce(sender);
                            return Ok(ExecutionResult {
                                success: true,
                                gas_used,
                                gas_refund: U256::ZERO,
                                output: Bytes::new(),
                                logs: vec!["Intent locked".to_string()],
                                error: None,
                            });
                        }
                        IntentStatus::Locked(_) => {
                            return Ok(ExecutionResult {
                                success: false,
                                gas_used,
                                gas_refund: U256::ZERO,
                                output: Bytes::new(),
                                logs: vec!["lockIntentForSolving: already locked".to_string()],
                                error: Some("Already locked".to_string()),
                            });
                        }
                        IntentStatus::Solved => {
                            return Ok(ExecutionResult {
                                success: false,
                                gas_used,
                                gas_refund: U256::ZERO,
                                output: Bytes::new(),
                                logs: vec!["lockIntentForSolving: already solved".to_string()],
                                error: Some("Already solved".to_string()),
                            });
                        }
                    }
                } else {
                    return Ok(ExecutionResult {
                        success: false,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec!["lockIntentForSolving: intent not found".to_string()],
                        error: Some("Intent not found".to_string()),
                    });
                }
            }
            Some(IntentCall::SolveIntent { intent_id, data }) => {
                let block_number = u64::from_le_bytes(
                    data[..8].try_into().expect("data must be at least 8 bytes"),
                );

                if let Some(intent) = state.intents.get(&intent_id) {
                    if !matches!(intent.status, IntentStatus::Locked(_)) {
                        return Ok(ExecutionResult {
                            success: false,
                            gas_used,
                            gas_refund: U256::ZERO,
                            output: Bytes::new(),
                            logs: vec!["solveIntent: intent not locked".to_string()],
                            error: Some("Not locked".to_string()),
                        });
                    }
                } else {
                    return Ok(ExecutionResult {
                        success: false,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec!["solveIntent: intent not found".to_string()],
                        error: Some("Intent not found".to_string()),
                    });
                }

                match verify_intent_fill_on_bitcoin(state, intent_id, block_number) {
                    Ok(true) => {
                        if let Some(intent) = state.intents.get_mut(&intent_id) {
                            state
                                .account_manager
                                .add_balance(sender, U256::from(intent.value))?;
                            intent.status = IntentStatus::Solved;
                            let _ = state.account_manager.increment_nonce(sender);
                            return Ok(ExecutionResult {
                                success: true,
                                gas_used,
                                gas_refund: U256::ZERO,
                                output: Bytes::new(),
                                logs: vec!["Intent solved (Bitcoin L1 proof verified)".to_string()],
                                error: None,
                            });
                        }
                        return Ok(ExecutionResult {
                            success: false,
                            gas_used,
                            gas_refund: U256::ZERO,
                            output: Bytes::new(),
                            logs: vec!["solveIntent: intent disappeared".to_string()],
                            error: Some("Intent not found".to_string()),
                        });
                    }
                    Ok(false) => {
                        return Ok(ExecutionResult {
                            success: false,
                            gas_used,
                            gas_refund: U256::ZERO,
                            output: Bytes::new(),
                            logs: vec!["solveIntent: L1 fill not found in block".to_string()],
                            error: Some("L1 fill not found".to_string()),
                        });
                    }
                    Err(e) => {
                        return Ok(ExecutionResult {
                            success: false,
                            gas_used,
                            gas_refund: U256::ZERO,
                            output: Bytes::new(),
                            logs: vec![format!("solveIntent: verifier error: {}", e)],
                            error: Some("Verifier error".to_string()),
                        });
                    }
                }
            }
            _ => {
                return Ok(ExecutionResult {
                    success: false,
                    gas_used,
                    gas_refund: U256::ZERO,
                    output: Bytes::new(),
                    logs: vec!["Unsupported intent call".to_string()],
                    error: Some("Unsupported intent call".to_string()),
                });
            }
        }
    }

    if state.account_manager.get_balance(sender) < value {
        return Ok(ExecutionResult {
            success: false,
            gas_used,
            gas_refund: U256::ZERO,
            output: Bytes::new(),
            logs: vec!["Insufficient balance for transfer".to_string()],
            error: Some("Insufficient balance for transfer".to_string()),
        });
    }

    state.account_manager.sub_balance(sender, value)?;
    state.account_manager.add_balance(to, value)?;
    state.account_manager.increment_nonce(sender)?;

    Ok(ExecutionResult {
        success: true,
        gas_used,
        gas_refund: U256::ZERO,
        output: Bytes::new(),
        logs: vec![format!(
            "Transferred {} tokens from {} to {}",
            value, sender, to
        )],
        error: None,
    })
}

fn calculate_intent_id(sender: Address, nonce: u64, input: Bytes) -> B256 {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(sender.as_slice());
    preimage.extend_from_slice(&nonce.to_be_bytes());
    preimage.extend_from_slice(&input);
    keccak256(preimage)
}

fn verify_intent_fill_on_bitcoin(
    state: &crate::CoreLaneState,
    intent_id: B256,
    block_number: u64,
) -> Result<bool> {
    let client = state.bitcoin_client();

    let network = bitcoin::Network::Regtest;
    let intent = state
        .intents
        .get(&intent_id)
        .ok_or_else(|| anyhow!("Intent not found for verification"))
        .unwrap();

    let cbor_intent = IntentData::from_cbor(&intent.data)?;
    let fill = cbor_intent.parse_anchor_bitcoin_fill()?;
    let dest_script = {
        let addr_str = fill.parse_bitcoin_address()?;
        let addr = BitcoinAddress::from_str(&addr_str).unwrap();
        let addr_checked = addr.require_network(network).unwrap();
        addr_checked.script_pubkey()
    };
    let expected_amount_u256 = fill.amount;

    let hash = client.get_block_hash(block_number).unwrap();
    let block = client.get_block(&hash)?;
    let tag = intent_id.as_slice();
    for tx in block.txdata.iter() {
        // We expect exactly two outputs: one payment and one OP_RETURN with the intent id
        if tx.output.len() == 2 {
            let mut has_correct_payment = false;
            let mut has_matching_tag = false;
            for out in &tx.output {
                // Check payment output to the expected address with exact amount
                if out.script_pubkey == dest_script {
                    let out_amount_u256 = U256::from(out.value.to_sat());
                    if out_amount_u256 == expected_amount_u256 {
                        has_correct_payment = true;
                    } else {
                        has_correct_payment = false;
                    }
                } else if out.script_pubkey.is_op_return() {
                    // Check the OP_RETURN output contains the intent id bytes
                    let script = out.script_pubkey.as_bytes();
                    if script.len() >= 2 {
                        let data = &script[2..];
                        let tag_found = data.windows(tag.len()).any(|window| window == tag);
                        if tag_found {
                            has_matching_tag = true;
                        }
                    }
                }
            }

            if has_correct_payment && has_matching_tag {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
