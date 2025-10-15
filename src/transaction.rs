use crate::cmio::CmioMessage;
use crate::intents::{
    decode_intent_calldata, Intent, IntentCall, IntentCommandType, IntentData, IntentStatus,
};
use crate::intents::{IntentType, RiscVProgramIntent};
use crate::state::BundleStateManager;
use crate::CoreLaneState;
use cartesi_machine::config::machine::{MachineConfig, RAMConfig};
use cartesi_machine::config::runtime::RuntimeConfig;
use cartesi_machine::machine::Machine;
use cartesi_machine::types::cmio::CmioResponseReason;

use alloy_consensus::TxEnvelope;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use anyhow::{anyhow, Result};
use bitcoin::Address as BitcoinAddress;
use bitcoincore_rpc::RpcApi;
use cartesi_machine::types::cmio::AutomaticReason;
use cartesi_machine::types::cmio::CmioRequest;
use cartesi_machine::types::cmio::ManualReason;
use ciborium::into_writer;
use std::str::FromStr;
use tracing::info;

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
                // Build and log the extra_data hex for a RISC-V program intent using this blob
                let mut blob_hash_bytes = [0u8; 32];
                blob_hash_bytes.copy_from_slice(blob_hash.as_slice());
                let riscv_intent = RiscVProgramIntent {
                    blob_hash: blob_hash_bytes,
                    extra_data: Vec::new(),
                };
                let mut inner_cbor = Vec::new();
                let _ = into_writer(&riscv_intent, &mut inner_cbor);
                let intent_data = IntentData {
                    intent_type: IntentType::RiscVProgram,
                    data: inner_cbor,
                };
                if let Ok(extra_data_bytes) = intent_data.to_cbor() {
                    info!(
                        "extra_data_hex for RiscVProgram: 0x{}",
                        hex::encode(extra_data_bytes)
                    );
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
                info!("Calculated intent id: {:?}", intent_id);
                bundle_state.insert_intent(
                    intent_id,
                    Intent {
                        data: Bytes::from(extra_data),
                        value: value_u64,
                        status: IntentStatus::Submitted,
                        last_command: IntentCommandType::Created,
                        creator: sender,
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
                        last_command: IntentCommandType::Created,
                        creator: sender,
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
                            intent.last_command = IntentCommandType::LockIntentForSolving;
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
                        IntentStatus::Cancelled => {
                            return Ok(ExecutionResult {
                                success: false,
                                gas_used,
                                gas_refund: U256::ZERO,
                                output: Bytes::new(),
                                logs: vec!["lockIntentForSolving: cancelled".to_string()],
                                error: Some("Cancelled".to_string()),
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
                // Branch by intent type: AnchorBitcoinFill requires L1 verification, RiscVProgram does not
                let current_intent =
                    match bundle_state.get_intent(&state.account_manager, &intent_id) {
                        Some(i) => i,
                        None => {
                            info!("solveIntent: intent disappeared");
                            return Ok(ExecutionResult {
                                success: false,
                                gas_used,
                                gas_refund: U256::ZERO,
                                output: Bytes::new(),
                                logs: vec!["solveIntent: intent disappeared".to_string()],
                                error: Some("Intent disappeared".to_string()),
                            });
                        }
                    };
                let cbor_intent = IntentData::from_cbor(&current_intent.data)?;
                match cbor_intent.intent_type {
                    IntentType::AnchorBitcoinFill => {
                        match verify_intent_fill_on_bitcoin(state, intent_id, block_number) {
                            Ok(true) => {
                                // Extract intent value first to avoid borrow checker issues
                                let intent_value = bundle_state
                                    .get_intent(&state.account_manager, &intent_id)
                                    .ok_or_else(|| anyhow!("Intent disappeared"))?
                                    .value;
                                bundle_state.add_balance(
                                    &state.account_manager,
                                    sender,
                                    U256::from(intent_value),
                                )?;

                                if let Some(intent) =
                                    bundle_state.get_intent_mut(&state.account_manager, &intent_id)
                                {
                                    intent.status = IntentStatus::Solved;
                                    intent.last_command = IntentCommandType::SolveIntent;
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
                                        logs: vec![
                                            "Intent solved (Bitcoin L1 proof verified)".to_string()
                                        ],
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
                                    logs: vec![
                                        "solveIntent: L1 fill not found in block".to_string()
                                    ],
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
                    IntentType::RiscVProgram => {
                        let intent_value = bundle_state
                            .get_intent(&state.account_manager, &intent_id)
                            .ok_or_else(|| anyhow!("Intent disappeared"))?
                            .value;
                        bundle_state.add_balance(
                            &state.account_manager,
                            sender,
                            U256::from(intent_value),
                        )?;
                        if let Some(intent) =
                            bundle_state.get_intent_mut(&state.account_manager, &intent_id)
                        {
                            intent.status = IntentStatus::Solved;
                            intent.last_command = IntentCommandType::SolveIntent;
                            bundle_state.increment_nonce(&state.account_manager, sender)?;
                            run_intent_for(bundle_state, state, intent_id)?;
                        }
                        return Ok(ExecutionResult {
                            success: true,
                            gas_used,
                            gas_refund: U256::ZERO,
                            output: Bytes::new(),
                            logs: vec!["Intent solved (program executed)".to_string()],
                            error: None,
                        });
                    }
                }
            }
            Some(IntentCall::CancelIntent { intent_id, .. }) => {
                let (creator, value) = {
                    if let Some(intent) =
                        bundle_state.get_intent(&state.account_manager, &intent_id)
                    {
                        if matches!(intent.status, IntentStatus::Solved) {
                            return Ok(ExecutionResult {
                                success: false,
                                gas_used,
                                gas_refund: U256::ZERO,
                                output: Bytes::new(),
                                logs: vec!["cancelIntent: already solved".to_string()],
                                error: Some("Already solved".to_string()),
                            });
                        }
                        if intent.creator != sender {
                            return Ok(ExecutionResult {
                                success: false,
                                gas_used,
                                gas_refund: U256::ZERO,
                                output: Bytes::new(),
                                logs: vec!["cancelIntent: not creator".to_string()],
                                error: Some("Not creator".to_string()),
                            });
                        }
                        (intent.creator, intent.value)
                    } else {
                        return Ok(ExecutionResult {
                            success: false,
                            gas_used,
                            gas_refund: U256::ZERO,
                            output: Bytes::new(),
                            logs: vec!["cancelIntent: intent not found".to_string()],
                            error: Some("Intent not found".to_string()),
                        });
                    }
                };
                {
                    let intent = bundle_state
                        .get_intent_mut(&state.account_manager, &intent_id)
                        .unwrap();

                    intent.status = IntentStatus::Cancelled;
                    intent.last_command = IntentCommandType::CancelIntent;
                }
                bundle_state.add_balance(&state.account_manager, creator, U256::from(value))?;
                bundle_state.increment_nonce(&state.account_manager, sender)?;

                return Ok(ExecutionResult {
                    success: true,
                    gas_used,
                    gas_refund: U256::ZERO,
                    output: Bytes::new(),
                    logs: vec!["Intent canceled".to_string()],
                    error: None,
                });
            }
            Some(IntentCall::CancelIntentLock { intent_id, .. }) => {
                if let Some(intent) =
                    bundle_state.get_intent_mut(&state.account_manager, &intent_id)
                {
                    match intent.status {
                        IntentStatus::Locked(locker) => {
                            if locker != sender {
                                return Ok(ExecutionResult {
                                    success: false,
                                    gas_used,
                                    gas_refund: U256::ZERO,
                                    output: Bytes::new(),
                                    logs: vec!["cancelIntentLock: not current locker".to_string()],
                                    error: Some("Not locker".to_string()),
                                });
                            }
                            intent.status = IntentStatus::Submitted;
                            intent.last_command = IntentCommandType::CancelIntentLock;
                            bundle_state.increment_nonce(&state.account_manager, sender)?;
                            return Ok(ExecutionResult {
                                success: true,
                                gas_used,
                                gas_refund: U256::ZERO,
                                output: Bytes::new(),
                                logs: vec!["Intent lock canceled".to_string()],
                                error: None,
                            });
                        }
                        _ => {
                            return Ok(ExecutionResult {
                                success: false,
                                gas_used,
                                gas_refund: U256::ZERO,
                                output: Bytes::new(),
                                logs: vec!["cancelIntentLock: not locked".to_string()],
                                error: Some("Not locked".to_string()),
                            });
                        }
                    }
                }
                return Ok(ExecutionResult {
                    success: false,
                    gas_used,
                    gas_refund: U256::ZERO,
                    output: Bytes::new(),
                    logs: vec!["cancelIntentLock: intent not found".to_string()],
                    error: Some("Intent not found".to_string()),
                });
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

fn run_intent_with_image(state: &mut CoreLaneState, program_blob: Option<Vec<u8>>) -> Result<()> {
    let mut machine = Machine::create(
        &MachineConfig::new_with_ram(RAMConfig {
            length: 134217728,
            image_filename: "".into(),
        }),
        &RuntimeConfig::default(),
    )?;

    let opensbi = include_bytes!("../opensbi.bin");

    machine.write_memory(0x8000_0000u64, opensbi.as_ref())?;
    machine.write_memory(0x8020_0000u64, program_blob.unwrap().as_ref())?;

    loop {
        let reason = machine.run(u64::MAX)?;
        if reason == 1 {
            break;
        }
        match machine.receive_cmio_request() {
            Ok(req) => {
                info!("Handling CMIO request: {:?}", req);
                let data = match req {
                    CmioRequest::Automatic(AutomaticReason::TxOutput { data }) => data,
                    CmioRequest::Manual(ManualReason::GIO { data, .. }) => data,
                    _ => {
                        let _ = machine.send_cmio_response(CmioResponseReason::Advance, &[]);
                        continue;
                    }
                };
                info!("Handling CMIO data: {:?}", data);

                if let Ok(msg) = CmioMessage::from_bytes(&data) {
                    if let CmioMessage::Exit { code: _ } = msg {
                        machine.send_cmio_response(CmioResponseReason::Advance, &[])?;
                        break;
                    }
                    info!("Handling CMIO query: {:?}", msg);
                    let response = state.handle_cmio_query(msg);
                    let resp_bytes = response
                        .map(|r| r.to_bytes().unwrap_or_default())
                        .unwrap_or_default();
                    machine.send_cmio_response(CmioResponseReason::Advance, &resp_bytes)?;
                    // keep running until Exit
                    continue;
                } else {
                    machine.send_cmio_response(CmioResponseReason::Advance, &[])?;
                    continue;
                }
            }
            Err(_) => continue,
        }
    }

    let _ = machine.run(u64::MAX)?;

    Ok(())
}

fn run_intent_for(
    bundle_state: &mut BundleStateManager,
    state: &mut CoreLaneState,
    intent_id: B256,
) -> Result<()> {
    let mut program_blob: Option<Vec<u8>> = None;
    if let Some(intent) = bundle_state.get_intent(&state.account_manager, &intent_id) {
        if let Ok(intent_data) = IntentData::from_cbor(&intent.data) {
            if intent_data.intent_type == crate::intents::IntentType::RiscVProgram {
                if let Ok(prog) = intent_data.parse_riscv_program() {
                    let blob_hash = B256::from_slice(&prog.blob_hash);
                    if let Some(bytes) = state.account_manager.get_blob(&blob_hash) {
                        bundle_state.insert_blob(blob_hash, bytes.clone());
                        program_blob = Some(bytes.clone());
                    }
                }
            }
        }
    }

    if program_blob.is_none() {
        return Err(anyhow::anyhow!(
            "Program blob not found for intent {:?}",
            intent_id
        ));
    }
    run_intent_with_image(state, program_blob)?;
    Ok(())
}
