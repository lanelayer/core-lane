use crate::cmio::CmioMessage;
use crate::intents::{
    decode_intent_calldata, Intent, IntentCall, IntentCommandType, IntentData, IntentStatus,
    IntentType,
};
use crate::state::BundleStateManager;
use crate::state::StateManager;
use cartesi_machine::config::machine::{MachineConfig, RAMConfig};
use cartesi_machine::config::runtime::RuntimeConfig;
use cartesi_machine::types::cmio::CmioResponseReason;

use alloy_consensus::TxEnvelope;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use anyhow::{anyhow, Result};
use bitcoin::Address as BitcoinAddress;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use cartesi_machine::types::cmio::AutomaticReason;
use cartesi_machine::types::cmio::CmioRequest;
use cartesi_machine::types::cmio::ManualReason;
use cartesi_machine::Machine;
use std::str::FromStr;
use std::sync::Arc;
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
pub fn get_transaction_nonce(tx: &TxEnvelope) -> u64 {
    match tx {
        TxEnvelope::Legacy(signed) => signed.tx().nonce,
        TxEnvelope::Eip1559(signed) => signed.tx().nonce,
        TxEnvelope::Eip2930(signed) => signed.tx().nonce,
        _ => 0,
    }
}

/// Trait for contexts that can process transactions
/// This allows both the node (CoreLaneState) and external sequencers to process transactions
pub trait ProcessingContext {
    fn state_manager(&self) -> &StateManager;
    fn state_manager_mut(&mut self) -> &mut StateManager;
    fn bitcoin_client_read(&self) -> Arc<Client>;
    fn handle_cmio_query(
        &mut self,
        message: CmioMessage,
        current_intent_id: Option<B256>,
    ) -> Option<CmioMessage>;
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
pub fn execute_transaction<T: ProcessingContext>(
    tx: &TxEnvelope,
    sender: Address,
    bundle_state: &mut BundleStateManager,
    state: &mut T,
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
fn execute_transfer<T: ProcessingContext>(
    tx: &TxEnvelope,
    sender: Address,
    bundle_state: &mut BundleStateManager,
    state: &mut T,
) -> Result<ExecutionResult> {
    let value = get_transaction_value(tx);
    let gas_used = U256::from(21000u64);

    // Validate nonce to prevent replay attacks and ensure transaction ordering
    let tx_nonce = get_transaction_nonce(tx);
    let expected_nonce = bundle_state.get_nonce(state.state_manager(), sender);

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
                if bundle_state.contains_blob(state.state_manager(), &blob_hash) {
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
                if let Err(e) = bundle_state.increment_nonce(state.state_manager(), sender) {
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

                info!(
                    "storeBlob: RiscVProgram intentData constructed; blob_hash = {}",
                    blob_hash
                );

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
                if !bundle_state.contains_blob(state.state_manager(), &blob_hash) {
                    return Ok(ExecutionResult {
                        success: false,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec!["intentFromBlob: blob not stored".to_string()],
                        error: Some("Blob not stored".to_string()),
                    });
                }

                if bundle_state.get_balance(state.state_manager(), sender) < value {
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

                // Safely convert value to u64 - reject if too large
                let value_u64: u64 = match u64::try_from(value) {
                    Ok(v) => v,
                    Err(_) => {
                        return Ok(ExecutionResult {
                            success: false,
                            gas_used,
                            gas_refund: U256::ZERO,
                            output: Bytes::new(),
                            logs: vec![
                                "intentFromBlob: value exceeds u64::MAX (18.4 ETH)".to_string()
                            ],
                            error: Some("Value too large for intent".to_string()),
                        });
                    }
                };

                bundle_state.sub_balance(state.state_manager(), sender, value)?;
                bundle_state.increment_nonce(state.state_manager(), sender)?;
                let intent_id = calculate_intent_id(sender, nonce, Bytes::from(preimage));
                info!(
                    "📝 Intent created (from blob): intent_id = {}, creator = {:?}, value = {} wei",
                    intent_id, sender, value_u64
                );
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
                if bundle_state.get_balance(state.state_manager(), sender) < value {
                    return Ok(ExecutionResult {
                        success: false,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec!["Insufficient balance for intent lock".to_string()],
                        error: Some("Insufficient balance".to_string()),
                    });
                }

                // Safely convert value to u64 - reject if too large
                let value_u64: u64 = match u64::try_from(value) {
                    Ok(v) => v,
                    Err(_) => {
                        return Ok(ExecutionResult {
                            success: false,
                            gas_used,
                            gas_refund: U256::ZERO,
                            output: Bytes::new(),
                            logs: vec!["intent: value exceeds u64::MAX (18.4 ETH)".to_string()],
                            error: Some("Value too large for intent".to_string()),
                        });
                    }
                };

                bundle_state.sub_balance(state.state_manager(), sender, value)?;
                bundle_state.increment_nonce(state.state_manager(), sender)?;
                let intent_id =
                    calculate_intent_id(sender, nonce, Bytes::from(intent_data.clone()));
                info!(
                    "📝 Intent created: intent_id = {}, creator = {:?}, value = {} wei",
                    intent_id, sender, value_u64
                );
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
                info!("Intent submitted: intent_id = {}", intent_id);
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
                let solved = match bundle_state.get_intent(state.state_manager(), &intent_id) {
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
                let (status_snapshot, intent_data) =
                    match bundle_state.get_intent(state.state_manager(), &intent_id) {
                        Some(i) => (Some(i.status), IntentData::from_cbor(&i.data).ok()),
                        None => (None, None),
                    };

                if status_snapshot.is_none() {
                    return Ok(ExecutionResult {
                        success: false,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec!["lockIntentForSolving: intent not found".to_string()],
                        error: Some("Intent not found".to_string()),
                    });
                }

                match status_snapshot.unwrap() {
                    IntentStatus::Submitted => {
                        let original_main_intent =
                            state.state_manager().get_intent(&intent_id).cloned();
                        if let Some(mut updated_intent) = original_main_intent.clone() {
                            updated_intent.last_command = IntentCommandType::LockIntentForSolving;
                            state
                                .state_manager_mut()
                                .insert_intent(intent_id, updated_intent);
                        }

                        if let Some(intent_data) = intent_data.as_ref() {
                            if intent_data.intent_type == IntentType::RiscVProgram {
                                let permission = check_riscv_intent_permission(
                                    bundle_state,
                                    state,
                                    intent_data,
                                    intent_id,
                                )?;
                                if permission == 1 {
                                    if let Some(original_intent) = original_main_intent {
                                        state
                                            .state_manager_mut()
                                            .insert_intent(intent_id, original_intent);
                                    }
                                    return Ok(ExecutionResult {
                                        success: false,
                                        gas_used,
                                        gas_refund: U256::ZERO,
                                        output: Bytes::new(),
                                        logs: vec!["Permission denied".to_string()],
                                        error: Some("Permission denied".to_string()),
                                    });
                                }
                            }
                        }

                        if let Some(intent) =
                            bundle_state.get_intent_mut(state.state_manager(), &intent_id)
                        {
                            intent.status = IntentStatus::Locked(sender);
                            intent.last_command = IntentCommandType::LockIntentForSolving;
                        }
                        if let Err(e) = bundle_state.increment_nonce(state.state_manager(), sender)
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
            }
            Some(IntentCall::SolveIntent { intent_id, data }) => {
                // Parse block height (u64, 8 bytes) and txid (32 bytes)
                if data.len() < 40 {
                    return Ok(ExecutionResult {
                        success: false,
                        gas_used,
                        gas_refund: U256::ZERO,
                        output: Bytes::new(),
                        logs: vec!["solveIntent: data must contain block_height (8 bytes) and txid (32 bytes)".to_string()],
                        error: Some("Invalid solve data length".to_string()),
                    });
                }
                let block_number = u64::from_le_bytes(
                    data[..8].try_into().expect("data must be at least 8 bytes"),
                );
                let txid_bytes: [u8; 32] = data[8..40].try_into().expect("txid must be 32 bytes");

                if let Some(intent) = bundle_state.get_intent(state.state_manager(), &intent_id) {
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
                    match bundle_state.get_intent(state.state_manager(), &intent_id) {
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
                let cbor_intent: IntentData = IntentData::from_cbor(&current_intent.data)?;
                match cbor_intent.intent_type {
                    IntentType::AnchorBitcoinFill => {
                        match verify_intent_fill_on_bitcoin(
                            state,
                            intent_id,
                            block_number,
                            txid_bytes,
                        ) {
                            Ok(true) => {
                                // Extract intent value first to avoid borrow checker issues
                                let intent_value = bundle_state
                                    .get_intent(state.state_manager(), &intent_id)
                                    .ok_or_else(|| anyhow!("Intent disappeared"))?
                                    .value;
                                bundle_state.add_balance(
                                    state.state_manager(),
                                    sender,
                                    U256::from(intent_value),
                                )?;

                                if let Some(intent) =
                                    bundle_state.get_intent_mut(state.state_manager(), &intent_id)
                                {
                                    intent.status = IntentStatus::Solved;
                                    intent.last_command = IntentCommandType::SolveIntent;
                                    if let Err(e) =
                                        bundle_state.increment_nonce(state.state_manager(), sender)
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
                        if let Some(main_intent) = state.state_manager().get_intent(&intent_id) {
                            let mut updated_intent = main_intent.clone();
                            updated_intent.last_command = IntentCommandType::SolveIntent;
                            state
                                .state_manager_mut()
                                .insert_intent(intent_id, updated_intent);
                        }

                        let intent_value = bundle_state
                            .get_intent(state.state_manager(), &intent_id)
                            .ok_or_else(|| anyhow!("Intent disappeared"))?
                            .value;
                        bundle_state.add_balance(
                            state.state_manager(),
                            sender,
                            U256::from(intent_value),
                        )?;
                        if let Some(intent) =
                            bundle_state.get_intent_mut(state.state_manager(), &intent_id)
                        {
                            intent.status = IntentStatus::Solved;
                            intent.last_command = IntentCommandType::SolveIntent;
                            bundle_state.increment_nonce(state.state_manager(), sender)?;
                            let permission = check_riscv_intent_permission(
                                bundle_state,
                                state,
                                &cbor_intent,
                                intent_id,
                            )?;

                            if permission == 1 {
                                return Ok(ExecutionResult {
                                    success: false,
                                    gas_used,
                                    gas_refund: U256::ZERO,
                                    output: Bytes::new(),
                                    logs: vec!["solveIntent: permission denied by RISC-V program"
                                        .to_string()],
                                    error: Some("Permission denied".to_string()),
                                });
                            }
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
                    if let Some(intent) = bundle_state.get_intent(state.state_manager(), &intent_id)
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
                    let intent_data = {
                        let intent = bundle_state
                            .get_intent(state.state_manager(), &intent_id)
                            .ok_or_else(|| anyhow!("Intent disappeared"))?;
                        IntentData::from_cbor(&intent.data)?
                    };
                    if intent_data.intent_type == IntentType::RiscVProgram {
                        let original_main_intent =
                            state.state_manager().get_intent(&intent_id).cloned();
                        if let Some(mut updated_intent) = original_main_intent.clone() {
                            updated_intent.last_command = IntentCommandType::CancelIntent;
                            state
                                .state_manager_mut()
                                .insert_intent(intent_id, updated_intent);
                        }

                        let permission = check_riscv_intent_permission(
                            bundle_state,
                            state,
                            &intent_data,
                            intent_id,
                        )?;

                        if permission == 1 {
                            if let Some(original_intent) = original_main_intent {
                                state
                                    .state_manager_mut()
                                    .insert_intent(intent_id, original_intent);
                            }
                            return Ok(ExecutionResult {
                                success: false,
                                gas_used,
                                gas_refund: U256::ZERO,
                                output: Bytes::new(),
                                logs: vec![
                                    "cancelIntent: permission denied by RISC-V program".to_string()
                                ],
                                error: Some("Permission denied".to_string()),
                            });
                        }
                    }

                    if let Some(intent_mut) =
                        bundle_state.get_intent_mut(state.state_manager(), &intent_id)
                    {
                        intent_mut.status = IntentStatus::Cancelled;
                        intent_mut.last_command = IntentCommandType::CancelIntent;
                    }
                }
                bundle_state.add_balance(state.state_manager(), creator, U256::from(value))?;
                bundle_state.increment_nonce(state.state_manager(), sender)?;

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
                if let Some(intent) = bundle_state.get_intent(state.state_manager(), &intent_id) {
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

                            let intent_data = IntentData::from_cbor(&intent.data)?;
                            if intent_data.intent_type == IntentType::RiscVProgram {
                                let original_main_intent =
                                    state.state_manager().get_intent(&intent_id).cloned();
                                if let Some(mut updated_intent) = original_main_intent.clone() {
                                    updated_intent.last_command =
                                        IntentCommandType::CancelIntentLock;
                                    state
                                        .state_manager_mut()
                                        .insert_intent(intent_id, updated_intent);
                                }

                                let permission = check_riscv_intent_permission(
                                    bundle_state,
                                    state,
                                    &intent_data,
                                    intent_id,
                                )?;

                                if permission == 1 {
                                    if let Some(original_intent) = original_main_intent {
                                        state
                                            .state_manager_mut()
                                            .insert_intent(intent_id, original_intent);
                                    }
                                    return Ok(ExecutionResult {
                                        success: false,
                                        gas_used,
                                        gas_refund: U256::ZERO,
                                        output: Bytes::new(),
                                        logs: vec![
                                            "cancelIntentLock: permission denied by RISC-V program"
                                                .to_string(),
                                        ],
                                        error: Some("Permission denied".to_string()),
                                    });
                                }
                            }

                            if let Some(intent_mut) =
                                bundle_state.get_intent_mut(state.state_manager(), &intent_id)
                            {
                                intent_mut.status = IntentStatus::Submitted;
                                intent_mut.last_command = IntentCommandType::CancelIntentLock;
                            }
                            bundle_state.increment_nonce(state.state_manager(), sender)?;
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

    if bundle_state.get_balance(state.state_manager(), sender) < value {
        return Ok(ExecutionResult {
            success: false,
            gas_used,
            gas_refund: U256::ZERO,
            output: Bytes::new(),
            logs: vec!["Insufficient balance for transfer".to_string()],
            error: Some("Insufficient balance for transfer".to_string()),
        });
    }

    bundle_state.sub_balance(state.state_manager(), sender, value)?;
    bundle_state.add_balance(state.state_manager(), to, value)?;
    bundle_state.increment_nonce(state.state_manager(), sender)?;

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
    debug!(
        "Calculating intent ID: sender={:?}, nonce={}, input_len={}",
        sender,
        nonce,
        input.len()
    );
    let intent_id = keccak256(preimage);
    debug!("Calculated intent_id: {:?}", intent_id);
    intent_id
}

fn verify_intent_fill_on_bitcoin<T: ProcessingContext>(
    state: &T,
    intent_id: B256,
    block_number: u64,
    txid_bytes: [u8; 32],
) -> Result<bool> {
    let client = state.bitcoin_client_read();

    let network = bitcoin::Network::Regtest;
    let intent = state
        .state_manager()
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

    // Convert block height to hash
    let block_hash = client.get_block_hash(block_number)?;

    // Convert txid bytes to Txid (note: Bitcoin txids are in internal byte order)
    use bitcoin::hashes::{sha256d, Hash};
    let txid = bitcoin::Txid::from_raw_hash(sha256d::Hash::from_byte_array(txid_bytes));

    info!(
        "Verifying intent {} with txid {} in Bitcoin block {}",
        intent_id, txid, block_number
    );
    debug!("Expected block hash: {}", block_hash);

    // Get the raw transaction - include the block hash to verify it's in the specified block
    debug!(
        "Calling get_raw_transaction_info for txid {} in block {}",
        txid, block_hash
    );
    let tx_info = client
        .get_raw_transaction_info(&txid, Some(&block_hash))
        .map_err(|e| {
            anyhow!(
                "Failed to get transaction {} from block {}: {}",
                txid,
                block_number,
                e
            )
        })?;

    // Verify the transaction is in the correct block
    if let Some(tx_block_hash) = tx_info.blockhash {
        if tx_block_hash != block_hash {
            info!("Transaction {} not in expected block", txid);
            return Ok(false);
        }
    } else {
        info!("Transaction {} not confirmed in any block", txid);
        return Ok(false);
    }

    let tx = &tx_info
        .transaction()
        .map_err(|e| anyhow!("Failed to decode transaction: {}", e))?;
    let tag = intent_id.as_slice();

    // We expect at least two outputs: one payment and one OP_RETURN with the intent id
    // There may be a 3rd output for change
    if tx.output.len() < 2 {
        info!(
            "Transaction {} has only {} output(s), need at least 2 (payment + OP_RETURN)",
            txid,
            tx.output.len()
        );
        return Ok(false);
    }

    debug!("Transaction has {} outputs", tx.output.len());
    let mut total_payment_amount = U256::ZERO;
    let mut has_matching_tag = false;

    for (idx, out) in tx.output.iter().enumerate() {
        debug!(
            "Output {}: {} sats, script_pubkey={}",
            idx,
            out.value.to_sat(),
            hex::encode(out.script_pubkey.as_bytes())
        );

        // Accumulate amounts for all outputs to the expected destination address
        if out.script_pubkey == dest_script {
            let out_amount_u256 = U256::from(out.value.to_sat());
            debug!(
                "Found payment output to dest address: {} sats",
                out_amount_u256
            );
            total_payment_amount += out_amount_u256;
        } else if out.script_pubkey.is_op_return() {
            // Check the OP_RETURN output contains the intent id bytes
            let script = out.script_pubkey.as_bytes();
            debug!("Found OP_RETURN output: {} bytes", script.len());
            if script.len() >= 2 {
                let data = &script[2..];
                let tag_found = data.windows(tag.len()).any(|window| window == tag);
                if tag_found {
                    debug!("✅ Intent ID tag found in OP_RETURN");
                    has_matching_tag = true;
                }
            }
        } else {
            debug!("Output {}: Other type (likely change)", idx);
        }
    }

    // Check if total payment amount matches expected
    let has_correct_payment = total_payment_amount == expected_amount_u256;
    debug!(
        "Total payment to dest address: {} sats (expected {})",
        total_payment_amount, expected_amount_u256
    );

    if has_correct_payment && has_matching_tag {
        info!(
            "✅ Intent {} verified successfully in transaction {} ({} outputs)",
            intent_id,
            txid,
            tx.output.len()
        );
        return Ok(true);
    }

    info!(
        "❌ Intent {} verification failed for transaction {} (payment={}, tag={})",
        intent_id, txid, has_correct_payment, has_matching_tag
    );
    Ok(false)
}

fn check_riscv_intent_permission<T: ProcessingContext>(
    bundle_state: &BundleStateManager,
    state: &mut T,
    intent_data: &IntentData,
    intent_id: B256,
) -> Result<u32> {
    let riscv_program_intent = intent_data.parse_riscv_program()?;
    let blob_hash = B256::from_slice(&riscv_program_intent.blob_hash);
    // Look up program blob from pending bundle if available, fall back to persisted state
    let program_blob = bundle_state
        .stored_blobs
        .get(&blob_hash)
        .or_else(|| state.state_manager().get_blob(&blob_hash))
        .ok_or_else(|| anyhow::anyhow!("Program blob not found for hash {:?}", blob_hash))?;

    let mut machine = Machine::create(
        &MachineConfig::new_with_ram(RAMConfig {
            length: 134217728,
            image_filename: "".into(),
        }),
        &RuntimeConfig::default(),
    )?;

    let opensbi = include_bytes!("../opensbi.bin");
    machine.write_memory(0x8000_0000u64, opensbi.as_ref())?;
    machine.write_memory(0x8020_0000u64, program_blob)?;

    let mut permission = 1;

    loop {
        let reason = machine.run(u64::MAX)?;
        if reason == 1 {
            break;
        }
        match machine.receive_cmio_request() {
            Ok(req) => {
                let data = match req {
                    CmioRequest::Automatic(AutomaticReason::TxOutput { data }) => data,
                    CmioRequest::Manual(ManualReason::GIO { data, .. }) => data,
                    _ => {
                        let _ = machine.send_cmio_response(CmioResponseReason::Advance, &[]);
                        continue;
                    }
                };

                if let Ok(msg) = CmioMessage::from_bytes(&data) {
                    info!(
                        "Handling CMIO query: {:?} machine m_cycles: {}",
                        msg,
                        machine.mcycle()?
                    );
                    let response = state.handle_cmio_query(msg, Some(intent_id));
                    if let Some(CmioMessage::Exit { code }) = response {
                        info!("Permission granted: {}", code);
                        permission = code;
                        break;
                    } else if let Some(response_msg) = response {
                        let resp_bytes = response_msg.to_bytes().unwrap_or_default();
                        machine.send_cmio_response(CmioResponseReason::Advance, &resp_bytes)?;
                        continue;
                    }
                } else {
                    machine.send_cmio_response(CmioResponseReason::Advance, &[])?;
                    continue;
                }
            }
            Err(_) => continue,
        }
    }

    Ok(permission)
}
