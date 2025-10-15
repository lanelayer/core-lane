use crate::intents::{decode_intent_calldata, Intent, IntentCall, IntentData, IntentStatus};
use crate::state::BundleStateManager;
use crate::CoreLaneState;
use alloy_consensus::TxEnvelope;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use anyhow::{anyhow, Result};
use bitcoin::Address as BitcoinAddress;
use bitcoincore_rpc::RpcApi;
use std::str::FromStr;

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
    #[allow(dead_code)]
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

/// Transaction execution result
#[derive(Debug, Clone)]
#[allow(dead_code)]
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
    bundle_state: &mut BundleStateManager,
    state: &mut CoreLaneState,
) -> Result<ExecutionResult> {
    execute_transfer(tx, sender, bundle_state, state)
}

/// Get gas limit from transaction
#[allow(dead_code)]
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
#[allow(dead_code)]
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
    bundle_state: &mut BundleStateManager,
    state: &mut CoreLaneState,
) -> Result<ExecutionResult> {
    let value = get_transaction_value(tx);
    let gas_used = U256::from(21000u64);

    // Validate nonce to prevent replay attacks and ensure transaction ordering
    let tx_nonce = get_transaction_nonce(tx);
    let expected_nonce = bundle_state.get_nonce(&state.account_manager, sender);

    if U256::from(tx_nonce) != expected_nonce {
        return Ok(ExecutionResult {
            success: false,
            gas_used,
            gas_refund: U256::ZERO,
            output: Bytes::new(),
            logs: vec![format!(
                "Invalid nonce: expected {}, got {}",
                expected_nonce, tx_nonce
            )],
            error: Some(format!(
                "Invalid nonce: expected {}, got {}",
                expected_nonce, tx_nonce
            )),
        });
    }

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
                if bundle_state.contains_blob(&state.account_manager, &blob_hash) {
                    return Ok(ExecutionResult {
                        success: true,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec![format!("Blob already stored: blob_hash = {}", blob_hash)],
                        error: None,
                    });
                }
                bundle_state.insert_blob(blob_hash, data.clone());
                if let Err(e) = bundle_state.increment_nonce(&state.account_manager, sender) {
                    return Ok(ExecutionResult {
                        success: false,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec![format!("Failed to increment nonce: {}", e)],
                        error: Some(e.to_string()),
                    });
                }
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
                if !bundle_state.contains_blob(&state.account_manager, &blob_hash) {
                    return Ok(ExecutionResult {
                        success: false,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec!["intentFromBlob: blob not stored".to_string()],
                        error: Some("Blob not stored".to_string()),
                    });
                }

                if bundle_state.get_balance(&state.account_manager, sender) < value {
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

                bundle_state.sub_balance(&state.account_manager, sender, value)?;
                bundle_state.increment_nonce(&state.account_manager, sender)?;
                let value_u64: u64 = value.try_into().unwrap();
                let intent_id = calculate_intent_id(sender, nonce, Bytes::from(preimage));
                bundle_state.insert_intent(
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
                if bundle_state.get_balance(&state.account_manager, sender) < value {
                    return Ok(ExecutionResult {
                        success: false,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec!["Insufficient balance for intent lock".to_string()],
                        error: Some("Insufficient balance".to_string()),
                    });
                }
                bundle_state.sub_balance(&state.account_manager, sender, value)?;
                bundle_state.increment_nonce(&state.account_manager, sender)?;
                let value_u64: u64 = value.try_into().unwrap_or(u64::MAX);
                let intent_id =
                    calculate_intent_id(sender, nonce, Bytes::from(intent_data.clone()));
                bundle_state.insert_intent(
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
                let solved = match bundle_state.get_intent(&state.account_manager, &intent_id) {
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
                if let Some(intent) =
                    bundle_state.get_intent_mut(&state.account_manager, &intent_id)
                {
                    match intent.status {
                        IntentStatus::Submitted => {
                            intent.status = IntentStatus::Locked(sender);
                            if let Err(e) =
                                bundle_state.increment_nonce(&state.account_manager, sender)
                            {
                                return Ok(ExecutionResult {
                                    success: false,
                                    gas_used,
                                    gas_refund: U256::ZERO,
                                    output: Bytes::new(),
                                    logs: vec![format!("Failed to increment nonce: {}", e)],
                                    error: Some(e.to_string()),
                                });
                            }
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

                if let Some(intent) = bundle_state.get_intent(&state.account_manager, &intent_id) {
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
                        // Extract intent value first to avoid borrow checker issues
                        let intent_value = if let Some(intent) =
                            bundle_state.get_intent(&state.account_manager, &intent_id)
                        {
                            intent.value
                        } else {
                            return Ok(ExecutionResult {
                                success: false,
                                gas_used,
                                gas_refund: U256::ZERO,
                                output: Bytes::new(),
                                logs: vec!["solveIntent: intent disappeared".to_string()],
                                error: Some("Intent disappeared".to_string()),
                            });
                        };

                        // Add balance using the extracted value
                        bundle_state.add_balance(
                            &state.account_manager,
                            sender,
                            U256::from(intent_value),
                        )?;

                        // Now update the intent status
                        if let Some(intent) =
                            bundle_state.get_intent_mut(&state.account_manager, &intent_id)
                        {
                            intent.status = IntentStatus::Solved;
                            if let Err(e) =
                                bundle_state.increment_nonce(&state.account_manager, sender)
                            {
                                return Ok(ExecutionResult {
                                    success: false,
                                    gas_used,
                                    gas_refund: U256::ZERO,
                                    output: Bytes::new(),
                                    logs: vec![format!("Failed to increment nonce: {}", e)],
                                    error: Some(e.to_string()),
                                });
                            }
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

    if bundle_state.get_balance(&state.account_manager, sender) < value {
        return Ok(ExecutionResult {
            success: false,
            gas_used,
            gas_refund: U256::ZERO,
            output: Bytes::new(),
            logs: vec!["Insufficient balance for transfer".to_string()],
            error: Some("Insufficient balance for transfer".to_string()),
        });
    }

    bundle_state.sub_balance(&state.account_manager, sender, value)?;
    bundle_state.add_balance(&state.account_manager, to, value)?;
    bundle_state.increment_nonce(&state.account_manager, sender)?;

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
    let client = state.bitcoin_client_read();

    let network = bitcoin::Network::Regtest;
    let intent = state
        .account_manager
        .get_intent(&intent_id)
        .ok_or_else(|| anyhow!("Intent not found for verification"))?;

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
                    has_correct_payment = out_amount_u256 == expected_amount_u256;
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
