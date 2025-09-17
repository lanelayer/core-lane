use crate::{CoreMELState, Intent, IntentStatus};
use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{SignableTransaction, Signed, TxEnvelope};
use alloy_primitives::B256;
use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_sol_types::{sol, SolCall};
use anyhow::{anyhow, Result};
use bitcoin::Address as BitcoinAddress;
use bitcoincore_rpc::RpcApi;
use ciborium::de::from_reader;
use ciborium::into_writer;
use secp256k1::{ecdsa::RecoverableSignature, ecdsa::RecoveryId, Message, SECP256K1};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tracing::{debug, info};
sol! {
    #[allow(missing_docs)]
    interface IntentSystem {
        function storeBlob(bytes data, uint256 expiryTime) payable;
        function prolongBlob(bytes32 blobHash) payable;
        function blobStored(bytes32 blobHash) view returns (bool);
        function intent(bytes intentData, uint256 nonce) payable returns (bytes32 intentId);
        function intentFromBlob(bytes32 blobHash, uint256 nonce, bytes extraData) payable returns (bytes32 encumberFromBlob);
        function cancelIntent(bytes32 intentId, bytes data) payable;
        function lockIntentForSolving(bytes32 intentId, bytes data) payable;
        function solveIntent(bytes32 intentId, bytes data) payable;
        function cancelIntentLock(bytes32 intentId, bytes data) payable;
        function isIntentSolved(bytes32 intentId) view returns (bool);
        function intentLocker(bytes32 intentId) view returns (address);
        function valueStoredInIntent(bytes32 intentId) view returns (uint256);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IntentType {
    AnchorBitcoinFill = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentData {
    pub intent_type: IntentType,
    pub data: Vec<u8>,
}

impl IntentData {
    pub fn from_cbor(cbor_bytes: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(cbor_bytes);
        let intent_data: IntentData = from_reader(&mut cursor)?;
        Ok(intent_data)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        into_writer(&self, &mut buffer)?;
        Ok(buffer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorBitcoinFill {
    pub bitcoin_address: Vec<u8>,
    pub amount: U256,
    pub max_fee: U256,
    pub expire_by: u64,
}

impl IntentData {
    pub fn parse_anchor_bitcoin_fill(&self) -> Result<AnchorBitcoinFill> {
        if self.intent_type != IntentType::AnchorBitcoinFill {
            return Err(anyhow!("Expected AnchorBitcoinFill intent type"));
        }
        let mut cursor = std::io::Cursor::new(&self.data);
        let fill_data: AnchorBitcoinFill = from_reader(&mut cursor).unwrap();
        Ok(fill_data)
    }
}

impl AnchorBitcoinFill {
    pub fn from_cbor(cbor_bytes: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(cbor_bytes);
        let fill_data: AnchorBitcoinFill = from_reader(&mut cursor)?;
        Ok(fill_data)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        into_writer(&self, &mut buffer)?;
        Ok(buffer)
    }

    pub fn parse_bitcoin_address(&self) -> Result<String> {
        let address_str = String::from_utf8(self.bitcoin_address.clone())
            .map_err(|e| anyhow!("Invalid UTF-8 in bitcoin_address: {}", e))?;
        let _ = BitcoinAddress::from_str(&address_str)
            .map_err(|e| anyhow!("Invalid Bitcoin address in intent data: {}", e))?;
        Ok(address_str)
    }

    pub fn from_bitcoin_address(
        bitcoin_address: &str,
        amount: U256,
        max_fee: U256,
        expire_by: u64,
    ) -> Result<Self> {
        Ok(AnchorBitcoinFill {
            bitcoin_address: bitcoin_address.as_bytes().to_vec(),
            amount,
            max_fee,
            expire_by,
        })
    }
}

pub fn create_anchor_bitcoin_fill_intent(
    bitcoin_address: &str,
    amount: U256,
    max_fee: U256,
    expire_by: u64,
) -> Result<IntentData> {
    let fill_data =
        AnchorBitcoinFill::from_bitcoin_address(bitcoin_address, amount, max_fee, expire_by)?;
    let fill_cbor = fill_data.to_cbor()?;

    Ok(IntentData {
        intent_type: IntentType::AnchorBitcoinFill,
        data: fill_cbor,
    })
}

pub fn parse_bitcoin_address_from_cbor_intent(cbor_intent: &IntentData) -> Result<String> {
    match cbor_intent.intent_type {
        IntentType::AnchorBitcoinFill => {
            let fill_data = cbor_intent.parse_anchor_bitcoin_fill().unwrap();
            let address_str = fill_data.parse_bitcoin_address().unwrap();
            info!("Address string: {}", address_str);
            Ok(address_str)
        }
    }
}

/// IntentSystem ABI decoding using alloy-sol-types
#[derive(Debug, Clone)]
pub enum IntentCall {
    StoreBlob {
        data: Vec<u8>,
        expiry_time: U256,
    },
    ProlongBlob {
        blob_hash: B256,
    },
    BlobStored {
        blob_hash: B256,
    },
    Intent {
        intent_data: Vec<u8>,
        nonce: U256,
    },
    IntentFromBlob {
        blob_hash: B256,
        nonce: U256,
        extra_data: Vec<u8>,
    },
    CancelIntent {
        intent_id: B256,
        data: Vec<u8>,
    },
    CancelIntentLock {
        intent_id: B256,
        data: Vec<u8>,
    },
    LockIntentForSolving {
        intent_id: B256,
        data: Vec<u8>,
    },
    SolveIntent {
        intent_id: B256,
        data: Vec<u8>,
    },
    IsIntentSolved {
        intent_id: B256,
    },
    IntentLocker {
        intent_id: B256,
    },
    ValueStoredInIntent {
        intent_id: B256,
    },
}

fn extract_selector(calldata: &[u8]) -> Option<[u8; 4]> {
    if calldata.len() < 4 {
        return None;
    }
    Some([calldata[0], calldata[1], calldata[2], calldata[3]])
}

pub fn decode_intent_calldata(calldata: &[u8]) -> Option<IntentCall> {
    let selector = extract_selector(calldata)?;

    match selector {
        IntentSystem::storeBlobCall::SELECTOR => {
            let Ok(call) = IntentSystem::storeBlobCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::StoreBlob {
                data: call.data.to_vec(),
                expiry_time: call.expiryTime,
            })
        }
        IntentSystem::prolongBlobCall::SELECTOR => {
            let Ok(call) = IntentSystem::prolongBlobCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::ProlongBlob {
                blob_hash: B256::from_slice(call.blobHash.as_slice()),
            })
        }
        IntentSystem::blobStoredCall::SELECTOR => {
            let Ok(call) = IntentSystem::blobStoredCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::BlobStored {
                blob_hash: B256::from_slice(call.blobHash.as_slice()),
            })
        }
        IntentSystem::intentCall::SELECTOR => {
            let Ok(call) = IntentSystem::intentCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::Intent {
                intent_data: call.intentData.to_vec(),
                nonce: call.nonce,
            })
        }
        IntentSystem::intentFromBlobCall::SELECTOR => {
            let Ok(call) = IntentSystem::intentFromBlobCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::IntentFromBlob {
                blob_hash: B256::from_slice(call.blobHash.as_slice()),
                nonce: call.nonce,
                extra_data: call.extraData.to_vec(),
            })
        }
        IntentSystem::cancelIntentCall::SELECTOR => {
            let Ok(call) = IntentSystem::cancelIntentCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::CancelIntent {
                intent_id: B256::from_slice(call.intentId.as_slice()),
                data: call.data.to_vec(),
            })
        }
        IntentSystem::lockIntentForSolvingCall::SELECTOR => {
            let Ok(call) = IntentSystem::lockIntentForSolvingCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::LockIntentForSolving {
                intent_id: B256::from_slice(call.intentId.as_slice()),
                data: call.data.to_vec(),
            })
        }
        IntentSystem::solveIntentCall::SELECTOR => {
            let Ok(call) = IntentSystem::solveIntentCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::SolveIntent {
                intent_id: B256::from_slice(call.intentId.as_slice()),
                data: call.data.to_vec(),
            })
        }
        IntentSystem::cancelIntentLockCall::SELECTOR => {
            let Ok(call) = IntentSystem::cancelIntentLockCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::CancelIntentLock {
                intent_id: B256::from_slice(call.intentId.as_slice()),
                data: call.data.to_vec(),
            })
        }
        IntentSystem::isIntentSolvedCall::SELECTOR => {
            let Ok(call) = IntentSystem::isIntentSolvedCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::IsIntentSolved {
                intent_id: B256::from_slice(call.intentId.as_slice()),
            })
        }
        IntentSystem::intentLockerCall::SELECTOR => {
            let Ok(call) = IntentSystem::intentLockerCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::IntentLocker {
                intent_id: B256::from_slice(call.intentId.as_slice()),
            })
        }
        IntentSystem::valueStoredInIntentCall::SELECTOR => {
            let Ok(call) = IntentSystem::valueStoredInIntentCall::abi_decode(calldata) else {
                return None;
            };
            Some(IntentCall::ValueStoredInIntent {
                intent_id: B256::from_slice(call.intentId.as_slice()),
            })
        }
        _ => None,
    }
}

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

/// Core MEL specific addresses for special operations
#[derive(Debug, Clone)]
pub struct CoreMELAddresses;

impl CoreMELAddresses {
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

/// Parse Core MEL transaction from Bitcoin DA data
pub fn parse_core_mel_transaction(data: &[u8]) -> Result<TxEnvelope> {
    if data.len() < 8 || !data.starts_with(b"CORE_MEL") {
        return Err(anyhow!(
            "Invalid Core MEL transaction format - missing CORE_MEL prefix"
        ));
    }

    // Extract the Ethereum transaction data (skip CORE_MEL prefix)
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
            "Failed to decode Ethereum transaction after CORE_MEL prefix: {}",
            e
        )),
    }
}

/// Encode Core MEL transaction for Bitcoin DA
pub fn encode_core_mel_transaction(tx: &TxEnvelope) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    data.extend_from_slice(b"CORE_MEL");

    // Encode the full Ethereum transaction as RLP
    let mut tx_bytes = Vec::new();
    tx.encode(&mut tx_bytes);

    // Append the encoded transaction
    data.extend_from_slice(&tx_bytes);

    Ok(data)
}

/// Validate Core MEL transaction
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

/// Manual ECDSA signature recovery for Ethereum transactions
fn recover_sender_manual<T>(signed_tx: &Signed<T>) -> Result<Address>
where
    T: SignableTransaction<alloy_primitives::Signature>,
{
    // Get the signature from the signed transaction
    let signature = signed_tx.signature();

    // Get the signature hash (this is what was actually signed)
    let sig_hash = signed_tx.signature_hash();

    // Extract r, s, and recovery_id from the signature
    let r = signature.r();
    let s = signature.s();
    let recovery_id = signature.v();

    // Convert to secp256k1 format for recovery
    let recovery_id = RecoveryId::from_i32(recovery_id as i32)
        .map_err(|e| anyhow!("Invalid recovery ID {}: {}", recovery_id, e))?;

    // Create secp256k1 signature from r and s components
    let r_bytes: [u8; 32] = r.to_be_bytes();
    let s_bytes: [u8; 32] = s.to_be_bytes();

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_bytes);
    sig_bytes[32..].copy_from_slice(&s_bytes);

    let sig = RecoverableSignature::from_compact(&sig_bytes, recovery_id)
        .map_err(|e| anyhow!("Invalid signature format: {}", e))?;

    // Convert message hash to secp256k1 message
    let message = Message::from_digest_slice(sig_hash.as_slice())
        .map_err(|e| anyhow!("Invalid message hash: {}", e))?;

    // Recover public key
    let public_key = SECP256K1
        .recover_ecdsa(&message, &sig)
        .map_err(|e| anyhow!("Signature recovery failed: {}", e))?;

    // Convert public key to Ethereum address
    let public_key_bytes = public_key.serialize_uncompressed();

    // Ethereum address is last 20 bytes of Keccak256 hash of public key (excluding 0x04 prefix)
    let hash = keccak256(&public_key_bytes[1..]); // Skip the 0x04 prefix

    // Take last 20 bytes as the address
    let mut address_bytes = [0u8; 20];
    address_bytes.copy_from_slice(&hash[12..]);

    Ok(Address::from(address_bytes))
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

/// Execute a Core MEL transaction
pub fn execute_transaction(
    tx: &TxEnvelope,
    sender: Address,
    //account_manager: &mut crate::account::AccountManager,
    //intents: &mut HashMap<B256, (Bytes, u64)>,
    state: &mut CoreMELState,
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
    state: &mut CoreMELState,
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

    if to == CoreMELAddresses::exit_marketplace() {
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
                            intent.status = IntentStatus::Locked;
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
                        IntentStatus::Locked => {
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
                    if !matches!(intent.status, IntentStatus::Locked) {
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
    state: &crate::CoreMELState,
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
