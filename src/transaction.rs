use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{SignableTransaction, Signed, TxEnvelope};
use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_rlp::{Decodable, Encodable};
use anyhow::{anyhow, Result};
use secp256k1::{ecdsa::RecoverableSignature, ecdsa::RecoveryId, Message, SECP256K1};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Core MEL transaction types that can be embedded in Bitcoin DA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoreMELTransactionType {
    Burn,
    Transfer,
    Exit,
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

/// Get transaction type based on destination address
pub fn get_transaction_type(_tx: &TxEnvelope) -> CoreMELTransactionType {
    // For now, return Transfer as default since we need to properly access Signed transaction fields
    // In a full implementation, this would extract the 'to' address from the signed transaction
    CoreMELTransactionType::Transfer
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
    account_manager: &mut crate::account::AccountManager,
) -> Result<ExecutionResult> {
    // Basic execution framework
    let tx_type = get_transaction_type(tx);
    let gas_limit = get_gas_limit(tx);
    let gas_price = get_gas_price(tx);

    info!("🔄 Executing transaction:");
    info!("   Sender: {}", sender);
    info!("   Type: {:?}", tx_type);
    info!("   Gas limit: {}", gas_limit);
    info!("   Gas price: {}", gas_price);

    // Check if sender has enough balance for gas
    let sender_balance = account_manager.get_balance(sender);
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

    // Execute based on transaction type
    match tx_type {
        CoreMELTransactionType::Burn => execute_burn(tx, sender, account_manager),
        CoreMELTransactionType::Transfer => execute_transfer(tx, sender, account_manager),
        CoreMELTransactionType::Exit => execute_exit(tx, sender, account_manager),
    }
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

/// Execute burn operation
fn execute_burn(
    tx: &TxEnvelope,
    sender: Address,
    account_manager: &mut crate::account::AccountManager,
) -> Result<ExecutionResult> {
    let value = get_transaction_value(tx);
    let gas_used = U256::from(21000u64);

    // Check if sender has enough balance to burn
    if account_manager.get_balance(sender) < value {
        return Ok(ExecutionResult {
            success: false,
            gas_used,
            gas_refund: U256::ZERO,
            output: Bytes::new(),
            logs: vec!["Insufficient balance to burn".to_string()],
            error: Some("Insufficient balance to burn".to_string()),
        });
    }

    // Burn tokens from sender
    account_manager.sub_balance(sender, value)?;
    account_manager.increment_nonce(sender)?;

    Ok(ExecutionResult {
        success: true,
        gas_used,
        gas_refund: U256::ZERO,
        output: Bytes::new(),
        logs: vec![format!("Burned {} tokens from {}", value, sender)],
        error: None,
    })
}

/// Execute transfer operation
fn execute_transfer(
    tx: &TxEnvelope,
    sender: Address,
    account_manager: &mut crate::account::AccountManager,
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

    // Check if sender has enough balance
    if account_manager.get_balance(sender) < value {
        return Ok(ExecutionResult {
            success: false,
            gas_used,
            gas_refund: U256::ZERO,
            output: Bytes::new(),
            logs: vec!["Insufficient balance for transfer".to_string()],
            error: Some("Insufficient balance for transfer".to_string()),
        });
    }

    // Transfer tokens
    account_manager.sub_balance(sender, value)?;
    account_manager.add_balance(to, value)?;
    account_manager.increment_nonce(sender)?;

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

/// Execute exit operation (withdrawal to Bitcoin)
fn execute_exit(
    tx: &TxEnvelope,
    sender: Address,
    account_manager: &mut crate::account::AccountManager,
) -> Result<ExecutionResult> {
    let value = get_transaction_value(tx);
    let gas_used = U256::from(30000u64); // Higher gas for exit operations

    // Check if sender has enough balance to exit
    if account_manager.get_balance(sender) < value {
        return Ok(ExecutionResult {
            success: false,
            gas_used,
            gas_refund: U256::ZERO,
            output: Bytes::new(),
            logs: vec!["Insufficient balance for exit".to_string()],
            error: Some("Insufficient balance for exit".to_string()),
        });
    }

    // Lock tokens for exit (in practice, this would trigger Bitcoin withdrawal)
    account_manager.sub_balance(sender, value)?;
    account_manager.increment_nonce(sender)?;

    Ok(ExecutionResult {
        success: true,
        gas_used,
        gas_refund: U256::ZERO,
        output: Bytes::new(),
        logs: vec![format!(
            "Initiated exit of {} tokens from {}",
            value, sender
        )],
        error: None,
    })
}
