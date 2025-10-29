use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, U256};
use alloy_rlp::Decodable;
use anyhow::anyhow;
use ciborium::{from_reader, into_writer, Value};
use tracing::{error, info};

#[derive(Debug, Clone)]
pub struct CoreLaneBundle {
    pub valid_for_block: u64,
    #[allow(dead_code)]
    pub flash_loan_amount: U256,
    #[allow(dead_code)]
    pub flash_loaner_address: Address,
    pub sequencer_payment_recipient: Address,
    pub transactions: Vec<(TxEnvelope, Address, Vec<u8>)>,
}

impl CoreLaneBundle {
    pub fn new(transaction: TxEnvelope, sender: Address, raw_tx: Vec<u8>) -> Self {
        Self {
            valid_for_block: u64::MAX,
            flash_loan_amount: U256::ZERO,
            flash_loaner_address: Address::ZERO,
            sequencer_payment_recipient: Address::ZERO,
            transactions: vec![(transaction, sender, raw_tx)],
        }
    }
}

/// CoreLaneBundle in CBOR format for CORE_BNDL prefix
/// This represents a bundle with raw transaction data as Vec<Vec<u8>>
/// Uses manual CBOR encoding for maximum efficiency (no field names)
#[derive(Debug, Clone)]
pub struct CoreLaneBundleCbor {
    pub valid_for_block: u64,
    #[allow(dead_code)]
    pub flash_loan_amount: U256,
    #[allow(dead_code)]
    pub flash_loaner_address: Address,
    pub sequencer_payment_recipient: Address,
    pub transactions: Vec<Vec<u8>>,
}

impl CoreLaneBundleCbor {
    pub fn new(transactions: Vec<Vec<u8>>) -> Self {
        Self {
            valid_for_block: u64::MAX,
            flash_loan_amount: U256::ZERO,
            flash_loaner_address: Address::ZERO,
            sequencer_payment_recipient: Address::ZERO,
            transactions,
        }
    }

    pub fn new_with_sequencer(
        transactions: Vec<Vec<u8>>,
        sequencer_payment_recipient: Address,
    ) -> Self {
        Self {
            valid_for_block: u64::MAX,
            flash_loan_amount: U256::ZERO,
            flash_loaner_address: Address::ZERO,
            sequencer_payment_recipient,
            transactions,
        }
    }

    /// Parse CBOR data into CoreLaneBundleCbor using manual decoding
    /// Schema: [valid_for_block, flash_loan_amount, flash_loaner_address, sequencer_payment_recipient, transactions]
    pub fn from_cbor(data: &[u8]) -> anyhow::Result<Self> {
        let value: Value =
            from_reader(data).map_err(|e| anyhow!("Failed to parse CBOR data: {}", e))?;

        // Expect array of 5 elements
        let array = match value {
            Value::Array(arr) => arr,
            _ => return Err(anyhow!("Expected CBOR array, got {:?}", value)),
        };

        if array.len() != 5 {
            return Err(anyhow!(
                "Invalid array length, expected 5, got {}",
                array.len()
            ));
        }

        // Decode valid_for_block (u64)
        let valid_for_block = match &array[0] {
            Value::Integer(i) => {
                // Convert ciborium::value::Integer to u64
                // Check if it's negative
                if *i < ciborium::value::Integer::from(0) {
                    return Err(anyhow!("Expected positive integer for valid_for_block"));
                }

                // Convert to u64
                if let Ok(val) = u64::try_from(*i) {
                    val
                } else {
                    return Err(anyhow!("Integer too large for u64: {:?}", i));
                }
            }
            _ => return Err(anyhow!("Expected integer for valid_for_block")),
        };

        // Decode flash_loan_amount (32 bytes for U256)
        let flash_loan_amount_bytes = match &array[1] {
            Value::Bytes(bytes) => bytes,
            _ => return Err(anyhow!("Expected bytes for flash_loan_amount")),
        };
        if flash_loan_amount_bytes.len() != 32 {
            return Err(anyhow!(
                "Invalid flash_loan_amount length, expected 32, got {}",
                flash_loan_amount_bytes.len()
            ));
        }
        let flash_loan_amount = U256::from_be_bytes(
            TryInto::<[u8; 32]>::try_into(flash_loan_amount_bytes.as_slice())
                .map_err(|_| anyhow!("Failed to convert flash_loan_amount bytes"))?,
        );

        // Decode flash_loaner_address (20 bytes for Address)
        let flash_loaner_address_bytes = match &array[2] {
            Value::Bytes(bytes) => bytes,
            _ => return Err(anyhow!("Expected bytes for flash_loaner_address")),
        };
        if flash_loaner_address_bytes.len() != 20 {
            return Err(anyhow!(
                "Invalid flash_loaner_address length, expected 20, got {}",
                flash_loaner_address_bytes.len()
            ));
        }
        let flash_loaner_address = Address::from_slice(flash_loaner_address_bytes.as_slice());

        // Decode sequencer_payment_recipient (20 bytes for Address)
        let sequencer_payment_recipient_bytes = match &array[3] {
            Value::Bytes(bytes) => bytes,
            _ => return Err(anyhow!("Expected bytes for sequencer_payment_recipient")),
        };
        if sequencer_payment_recipient_bytes.len() != 20 {
            return Err(anyhow!(
                "Invalid sequencer_payment_recipient length, expected 20, got {}",
                sequencer_payment_recipient_bytes.len()
            ));
        }
        let sequencer_payment_recipient =
            Address::from_slice(sequencer_payment_recipient_bytes.as_slice());

        // Decode transactions array
        let transactions = match &array[4] {
            Value::Array(tx_array) => {
                let mut transactions = Vec::new();
                for tx_value in tx_array {
                    match tx_value {
                        Value::Bytes(tx_bytes) => transactions.push(tx_bytes.clone()),
                        _ => return Err(anyhow!("Expected bytes for transaction")),
                    }
                }
                transactions
            }
            _ => return Err(anyhow!("Expected array for transactions")),
        };

        Ok(Self {
            valid_for_block,
            flash_loan_amount,
            flash_loaner_address,
            sequencer_payment_recipient,
            transactions,
        })
    }

    /// Serialize CoreLaneBundleCbor to CBOR using manual encoding
    /// Schema: [valid_for_block, flash_loan_amount, flash_loaner_address, sequencer_payment_recipient, transactions]
    pub fn to_cbor(&self) -> anyhow::Result<Vec<u8>> {
        // Create CBOR array with 5 elements
        let transactions: Vec<Value> = self
            .transactions
            .iter()
            .map(|tx| Value::Bytes(tx.clone()))
            .collect();

        let value = Value::Array(vec![
            Value::Integer(self.valid_for_block.into()),
            Value::Bytes(self.flash_loan_amount.to_be_bytes_vec()),
            Value::Bytes(self.flash_loaner_address.as_slice().to_vec()),
            Value::Bytes(self.sequencer_payment_recipient.as_slice().to_vec()),
            Value::Array(transactions),
        ]);

        let mut buffer = Vec::new();
        into_writer(&value, &mut buffer)
            .map_err(|e| anyhow!("Failed to serialize to CBOR: {}", e))?;
        Ok(buffer)
    }

    /// Convert to regular CoreLaneBundle by decoding all transactions
    pub fn to_core_lane_bundle(&self) -> anyhow::Result<CoreLaneBundle> {
        let mut decoded_transactions = Vec::new();

        for raw_tx in &self.transactions {
            if let Some((tx, sender)) = decode_tx_envelope(raw_tx) {
                decoded_transactions.push((tx, sender, raw_tx.clone()));
            } else {
                return Err(anyhow!("Failed to decode transaction in bundle"));
            }
        }

        Ok(CoreLaneBundle {
            valid_for_block: self.valid_for_block,
            flash_loan_amount: self.flash_loan_amount,
            flash_loaner_address: self.flash_loaner_address,
            sequencer_payment_recipient: self.sequencer_payment_recipient,
            transactions: decoded_transactions,
        })
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

    pub fn add_bundle_from_cbor(&mut self, cbor_bundle: CoreLaneBundleCbor) -> anyhow::Result<()> {
        let bundle = cbor_bundle.to_core_lane_bundle()?;
        self.bundles.push(bundle);
        Ok(())
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
