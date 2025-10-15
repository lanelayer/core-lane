use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, U256};
use alloy_rlp::Decodable;
use anyhow::anyhow;
use tracing::{error, info};

#[derive(Debug, Clone)]
pub struct CoreLaneBundle {
    pub valid_for_block: u64,
    #[allow(dead_code)]
    pub flash_loan_amount: U256,
    #[allow(dead_code)]
    pub flash_loaner_address: Address,
    pub transactions: Vec<(TxEnvelope, Address, Vec<u8>)>,
}

impl CoreLaneBundle {
    pub fn new(transaction: TxEnvelope, sender: Address, raw_tx: Vec<u8>) -> Self {
        Self {
            valid_for_block: u64::MAX,
            flash_loan_amount: U256::ZERO,
            flash_loaner_address: Address::ZERO,
            transactions: vec![(transaction, sender, raw_tx)],
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreLaneBurn {
    pub amount: U256,
    pub address: Address,
}

impl CoreLaneBurn {
    pub fn new(amount: U256, address: Address) -> Self {
        Self { amount, address }
    }
}
#[derive(Debug, Clone)]
pub struct CoreLaneBlockParsed {
    pub bundles: Vec<CoreLaneBundle>,
    pub burns: Vec<CoreLaneBurn>,
    pub anchor_block_hash: Vec<u8>,
    pub anchor_block_timestamp: u64,
    pub anchor_block_height: u64,
    pub parent_hash: Vec<u8>,
}

impl CoreLaneBlockParsed {
    pub fn new(
        anchor_block_hash: Vec<u8>,
        anchor_block_timestamp: u64,
        anchor_block_height: u64,
        parent_hash: Vec<u8>,
    ) -> Self {
        Self {
            bundles: Vec::new(),
            burns: Vec::new(),
            anchor_block_hash,
            anchor_block_timestamp,
            anchor_block_height,
            parent_hash,
        }
    }

    pub fn add_burn(&mut self, burn: CoreLaneBurn) {
        self.burns.push(burn);
    }

    pub fn add_bundle_from_single_tx(&mut self, tx: TxEnvelope, sender: Address, raw_tx: Vec<u8>) {
        self.bundles.push(CoreLaneBundle::new(tx, sender, raw_tx));
    }
}

pub fn decode_tx_envelope(tx_data: &[u8]) -> Option<(TxEnvelope, Address)> {
    let mut slice: &[u8] = tx_data;
    match TxEnvelope::decode(&mut slice) {
        Ok(tx) => {
            let sender = match recover_sender(&tx) {
                Ok(addr) => {
                    info!("   📧 Sender: {}", addr);
                    addr
                }
                Err(e) => {
                    error!("   ❌ Failed to recover sender: {}", e);
                    return None;
                }
            };
            Some((tx, sender))
        }
        Err(_) => {
            error!(
                "   ❌ Failed to decode tx envelope: {}",
                hex::encode(tx_data)
            );
            None
        }
    }
}

/// Extract sender address from transaction signature using alloy's built-in recovery
pub fn recover_sender(tx: &TxEnvelope) -> anyhow::Result<Address> {
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
        TxEnvelope::Eip4844(signed_tx) => match signed_tx.recover_signer() {
            Ok(address) => Ok(address),
            Err(e) => Err(anyhow!(
                "Failed to recover signer from EIP-4844 tx: {:?}",
                e
            )),
        },
        _ => Err(anyhow!("Unsupported transaction type for sender recovery")),
    }
}
