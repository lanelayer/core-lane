use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, U256};
use alloy_rlp::Decodable;
use anyhow::anyhow;
use ciborium::{from_reader, into_writer, Value};
use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};
use tracing::{error, info};

/// Maximum size for decompressed bundle data (128 MB)
/// This prevents decompression bombs from consuming excessive memory
const MAX_DECOMPRESSED_SIZE: u32 = 128 * 1024 * 1024;

/// Bundle position marker for processing order
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleMarker {
    /// Head bundle: processed in Phase 1 (sequencer only, before burns)
    Head,
    /// Standard bundle: default behavior (processed in Phase 3 with non-sequencer bundles)
    Standard,
}

impl BundleMarker {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => BundleMarker::Standard,
            1 => BundleMarker::Head,
            _ => BundleMarker::Standard, // Default to Standard for unknown values
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            BundleMarker::Standard => 0,
            BundleMarker::Head => 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreLaneBundle {
    pub valid_for_block: u64,
    #[allow(dead_code)]
    pub flash_loan_amount: U256,
    #[allow(dead_code)]
    pub flash_loaner_address: Address,
    pub sequencer_payment_recipient: Address,
    pub transactions: Vec<(TxEnvelope, Address, Vec<u8>)>,
    /// Recoverable secp256k1 signature over the bundle data (with signature field zeroed out)
    /// Format: 65 bytes [r (32 bytes) || s (32 bytes) || recovery_id (1 byte)]
    pub signature: Option<[u8; 65]>,
    /// Bundle position marker (Head, or None)
    pub marker: BundleMarker,
}

impl CoreLaneBundle {
    pub fn new(transaction: TxEnvelope, sender: Address, raw_tx: Vec<u8>) -> Self {
        Self {
            valid_for_block: u64::MAX,
            flash_loan_amount: U256::ZERO,
            flash_loaner_address: Address::ZERO,
            sequencer_payment_recipient: Address::ZERO,
            transactions: vec![(transaction, sender, raw_tx)],
            signature: None,
            marker: BundleMarker::Standard,
        }
    }

    /// Convert to CoreLaneBundleCbor format for serialization and signing
    pub fn to_cbor_bundle(&self) -> CoreLaneBundleCbor {
        let transactions: Vec<Vec<u8>> = self
            .transactions
            .iter()
            .map(|(_, _, raw_tx)| raw_tx.clone())
            .collect();

        CoreLaneBundleCbor {
            valid_for_block: self.valid_for_block,
            flash_loan_amount: self.flash_loan_amount,
            flash_loaner_address: self.flash_loaner_address,
            sequencer_payment_recipient: self.sequencer_payment_recipient,
            transactions,
            signature: self.signature,
            marker: self.marker,
        }
    }

    /// Get the hash that should be signed (via CBOR format)
    pub fn get_signing_hash(&self) -> anyhow::Result<[u8; 32]> {
        let cbor_bundle = self.to_cbor_bundle();
        cbor_bundle.get_signing_hash()
    }

    /// Sign the bundle with a secp256k1 private key
    pub fn sign(&mut self, secret_key: &SecretKey) -> anyhow::Result<[u8; 65]> {
        let mut cbor_bundle = self.to_cbor_bundle();
        let signature = cbor_bundle.sign(secret_key)?;
        self.signature = Some(signature);
        Ok(signature)
    }

    /// Verify the signature on the bundle
    pub fn verify_signature(&self) -> anyhow::Result<()> {
        let cbor_bundle = self.to_cbor_bundle();
        cbor_bundle.verify_signature()
    }

    /// Recover the Ethereum address from the signature
    pub fn recover_signer_address(&self) -> anyhow::Result<Address> {
        let cbor_bundle = self.to_cbor_bundle();
        cbor_bundle.recover_signer_address()
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
    /// Recoverable secp256k1 signature over the bundle data (with signature field zeroed out)
    /// Format: 65 bytes [r (32 bytes) || s (32 bytes) || recovery_id (1 byte)]
    pub signature: Option<[u8; 65]>,
    /// Bundle position marker (Head, or None)
    pub marker: BundleMarker,
}

impl CoreLaneBundleCbor {
    pub fn new(transactions: Vec<Vec<u8>>) -> Self {
        Self {
            valid_for_block: u64::MAX,
            flash_loan_amount: U256::ZERO,
            flash_loaner_address: Address::ZERO,
            sequencer_payment_recipient: Address::ZERO,
            transactions,
            signature: None,
            marker: BundleMarker::Standard,
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
            signature: None,
            marker: BundleMarker::Standard,
        }
    }

    /// Parse CBOR data into CoreLaneBundleCbor using manual decoding
    /// Schema: [type, decompressed_length, valid_for_block, flash_loan_amount, flash_loaner_address, sequencer_payment_recipient, compressed_transactions, signature, marker]
    /// type: u8 (0 = no compression, 1 = brotli)
    /// decompressed_length: u32 (size of decompressed data)
    /// compressed_transactions: bytes (brotli-compressed CBOR array of transactions)
    /// signature: optional bytes (65 bytes recoverable secp256k1 signature)
    /// marker: optional u8 (0 = None, 1 = Head)
    pub fn from_cbor(data: &[u8]) -> anyhow::Result<Self> {
        let value: Value =
            from_reader(data).map_err(|e| anyhow!("Failed to parse CBOR data: {}", e))?;

        // Expect array of 7, 8, or 9 elements (8 if signature is present, 9 if marker is also present)
        let array = match value {
            Value::Array(arr) => arr,
            _ => return Err(anyhow!("Expected CBOR array, got {:?}", value)),
        };

        if array.len() < 7 || array.len() > 9 {
            return Err(anyhow!(
                "Invalid array length, expected 7-9, got {}",
                array.len()
            ));
        }

        // Decode type (u8)
        let compression_type = match &array[0] {
            Value::Integer(i) => {
                if *i < ciborium::value::Integer::from(0) {
                    return Err(anyhow!("Expected positive integer for type"));
                }
                if let Ok(val) = u8::try_from(*i) {
                    val
                } else {
                    return Err(anyhow!("Integer too large for u8: {:?}", i));
                }
            }
            _ => return Err(anyhow!("Expected integer for type")),
        };

        // Decode decompressed_length (u32)
        let decompressed_length = match &array[1] {
            Value::Integer(i) => {
                if *i < ciborium::value::Integer::from(0) {
                    return Err(anyhow!("Expected positive integer for decompressed_length"));
                }
                if let Ok(val) = u32::try_from(*i) {
                    val
                } else {
                    return Err(anyhow!("Integer too large for u32: {:?}", i));
                }
            }
            _ => return Err(anyhow!("Expected integer for decompressed_length")),
        };

        // Enforce max decompression limit
        if decompressed_length > MAX_DECOMPRESSED_SIZE {
            return Err(anyhow!(
                "Decompressed length {} exceeds maximum of {} bytes (128MB)",
                decompressed_length,
                MAX_DECOMPRESSED_SIZE
            ));
        }

        // Decode valid_for_block (u64)
        let valid_for_block = match &array[2] {
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
        let flash_loan_amount_bytes = match &array[3] {
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
        let flash_loaner_address_bytes = match &array[4] {
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
        let sequencer_payment_recipient_bytes = match &array[5] {
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

        // Decode compressed_transactions bytes
        let compressed_transactions_bytes = match &array[6] {
            Value::Bytes(bytes) => bytes,
            _ => return Err(anyhow!("Expected bytes for compressed_transactions")),
        };

        // Decompress based on type
        let transactions = match compression_type {
            0 => {
                // No compression - parse as CBOR array directly
                let value: Value =
                    from_reader(compressed_transactions_bytes.as_slice()).map_err(|e| {
                        anyhow!("Failed to parse uncompressed transactions CBOR: {}", e)
                    })?;
                match value {
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
                }
            }
            1 => {
                // Brotli compression
                use std::io::Read;

                let decompressor = brotli::Decompressor::new(
                    compressed_transactions_bytes.as_slice(),
                    4096, // buffer size
                );

                // Limit decompression to max of decompressed_length bytes
                // This prevents decompression bombs by capping how much we'll read
                let mut limited_reader = decompressor.take(decompressed_length as u64);
                let mut decompressed = Vec::with_capacity(decompressed_length as usize);

                limited_reader
                    .read_to_end(&mut decompressed)
                    .map_err(|e| anyhow!("Failed to decompress brotli data: {}", e))?;

                // Parse decompressed CBOR array
                let value: Value = from_reader(decompressed.as_slice()).map_err(|e| {
                    anyhow!("Failed to parse decompressed transactions CBOR: {}", e)
                })?;
                match value {
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
                }
            }
            _ => {
                return Err(anyhow!("Unknown compression type: {}", compression_type));
            }
        };

        // Decode signature if present (element 7, optional)
        let signature = if array.len() >= 8 {
            match &array[7] {
                Value::Bytes(sig_bytes) => {
                    if sig_bytes.len() != 65 {
                        return Err(anyhow!(
                            "Invalid signature length, expected 65, got {}",
                            sig_bytes.len()
                        ));
                    }
                    let mut sig_array = [0u8; 65];
                    sig_array.copy_from_slice(sig_bytes);
                    Some(sig_array)
                }
                Value::Null => None,
                _ => return Err(anyhow!("Expected bytes or null for signature")),
            }
        } else {
            None
        };

        // Decode marker if present (element 8, optional)
        let marker = if array.len() >= 9 {
            match &array[8] {
                Value::Integer(i) => {
                    if *i < ciborium::value::Integer::from(0) {
                        return Err(anyhow!("Expected non-negative integer for marker"));
                    }
                    if let Ok(val) = u8::try_from(*i) {
                        BundleMarker::from_u8(val)
                    } else {
                        return Err(anyhow!("Marker value too large for u8: {:?}", i));
                    }
                }
                Value::Null => BundleMarker::Standard,
                _ => return Err(anyhow!("Expected integer or null for marker")),
            }
        } else {
            BundleMarker::Standard
        };

        Ok(Self {
            valid_for_block,
            flash_loan_amount,
            flash_loaner_address,
            sequencer_payment_recipient,
            transactions,
            signature,
            marker,
        })
    }

    /// Serialize CoreLaneBundleCbor to CBOR using manual encoding
    /// Schema: [type, decompressed_length, valid_for_block, flash_loan_amount, flash_loaner_address, sequencer_payment_recipient, compressed_transactions, signature, marker]
    pub fn to_cbor(&self) -> anyhow::Result<Vec<u8>> {
        // First, serialize transactions to CBOR
        let transactions: Vec<Value> = self
            .transactions
            .iter()
            .map(|tx| Value::Bytes(tx.clone()))
            .collect();

        let transactions_value = Value::Array(transactions);
        let mut uncompressed_transactions = Vec::new();
        into_writer(&transactions_value, &mut uncompressed_transactions)
            .map_err(|e| anyhow!("Failed to serialize transactions to CBOR: {}", e))?;

        let decompressed_length = uncompressed_transactions.len() as u32;

        // Compress with brotli (quality 6, window size 22)
        let mut compressed_transactions = Vec::new();
        let params = brotli::enc::BrotliEncoderParams {
            quality: 6,
            lgwin: 22,
            ..Default::default()
        };
        brotli::BrotliCompress(
            &mut uncompressed_transactions.as_slice(),
            &mut compressed_transactions,
            &params,
        )
        .map_err(|e| anyhow!("Failed to compress transactions with brotli: {}", e))?;

        // Create CBOR array with 9 elements (7 + signature + marker)
        let mut array_elements = vec![
            Value::Integer(1.into()),                   // type: 1 = brotli
            Value::Integer(decompressed_length.into()), // decompressed_length
            Value::Integer(self.valid_for_block.into()),
            Value::Bytes(self.flash_loan_amount.to_be_bytes_vec()),
            Value::Bytes(self.flash_loaner_address.as_slice().to_vec()),
            Value::Bytes(self.sequencer_payment_recipient.as_slice().to_vec()),
            Value::Bytes(compressed_transactions), // compressed transactions
        ];

        // Add signature if present
        array_elements.push(match self.signature {
            Some(sig) => Value::Bytes(sig.to_vec()),
            None => Value::Null,
        });

        // Add marker
        array_elements.push(Value::Integer(self.marker.to_u8().into()));

        let value = Value::Array(array_elements);

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
            signature: self.signature,
            marker: self.marker,
        })
    }

    /// Get the hash that should be signed (Keccak256 of CBOR data with signature zeroed out)
    /// This is the message digest that gets signed with secp256k1
    pub fn get_signing_hash(&self) -> anyhow::Result<[u8; 32]> {
        // Create a copy with signature set to None
        let mut bundle_for_signing = self.clone();
        bundle_for_signing.signature = None;

        // Serialize to CBOR
        let cbor_data = bundle_for_signing.to_cbor()?;

        // Hash with Keccak256
        let mut hasher = Keccak256::new();
        hasher.update(&cbor_data);
        let hash = hasher.finalize();

        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash);
        Ok(hash_array)
    }

    /// Sign the bundle with a secp256k1 private key
    /// Returns the 65-byte recoverable signature [r (32) || s (32) || recovery_id (1)]
    pub fn sign(&mut self, secret_key: &SecretKey) -> anyhow::Result<[u8; 65]> {
        let secp = Secp256k1::new();

        // Get the hash to sign
        let hash = self.get_signing_hash()?;
        let message = Message::from_digest(hash);

        // Sign with recovery
        let signature = secp.sign_ecdsa_recoverable(&message, secret_key);

        // Serialize to 65 bytes [r || s || recovery_id]
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let mut sig_array = [0u8; 65];
        sig_array[..64].copy_from_slice(&signature_bytes);
        sig_array[64] = recovery_id.to_i32() as u8;

        // Store the signature
        self.signature = Some(sig_array);

        Ok(sig_array)
    }

    /// Verify the signature on the bundle
    /// Returns Ok(()) if signature is valid, Err otherwise
    pub fn verify_signature(&self) -> anyhow::Result<()> {
        let signature = self
            .signature
            .ok_or_else(|| anyhow!("No signature present"))?;

        let secp = Secp256k1::new();

        // Get the hash that was signed
        let hash = self.get_signing_hash()?;
        let message = Message::from_digest(hash);

        // Parse recoverable signature
        let recovery_id = secp256k1::ecdsa::RecoveryId::from_i32(signature[64] as i32)
            .map_err(|e| anyhow!("Invalid recovery ID: {}", e))?;
        let sig = RecoverableSignature::from_compact(&signature[..64], recovery_id)
            .map_err(|e| anyhow!("Invalid signature format: {}", e))?;

        // Recover public key and verify
        let public_key = secp
            .recover_ecdsa(&message, &sig)
            .map_err(|e| anyhow!("Failed to recover public key: {}", e))?;

        // Verify the signature
        let normal_sig = sig.to_standard();
        secp.verify_ecdsa(&message, &normal_sig, &public_key)
            .map_err(|e| anyhow!("Signature verification failed: {}", e))?;

        Ok(())
    }

    /// Recover the public key from the signature
    /// Returns the 33-byte compressed public key
    pub fn recover_public_key(&self) -> anyhow::Result<[u8; 33]> {
        let signature = self
            .signature
            .ok_or_else(|| anyhow!("No signature present"))?;

        let secp = Secp256k1::new();

        // Get the hash that was signed
        let hash = self.get_signing_hash()?;
        let message = Message::from_digest(hash);

        // Parse recoverable signature
        let recovery_id = secp256k1::ecdsa::RecoveryId::from_i32(signature[64] as i32)
            .map_err(|e| anyhow!("Invalid recovery ID: {}", e))?;
        let sig = RecoverableSignature::from_compact(&signature[..64], recovery_id)
            .map_err(|e| anyhow!("Invalid signature format: {}", e))?;

        // Recover public key
        let public_key = secp
            .recover_ecdsa(&message, &sig)
            .map_err(|e| anyhow!("Failed to recover public key: {}", e))?;

        Ok(public_key.serialize())
    }

    /// Recover the Ethereum address from the signature
    /// Returns the 20-byte Ethereum address
    pub fn recover_signer_address(&self) -> anyhow::Result<Address> {
        let signature = self
            .signature
            .ok_or_else(|| anyhow!("No signature present"))?;

        let secp = Secp256k1::new();

        // Get the hash that was signed
        let hash = self.get_signing_hash()?;
        let message = Message::from_digest(hash);

        // Parse recoverable signature
        let recovery_id = secp256k1::ecdsa::RecoveryId::from_i32(signature[64] as i32)
            .map_err(|e| anyhow!("Invalid recovery ID: {}", e))?;
        let sig = RecoverableSignature::from_compact(&signature[..64], recovery_id)
            .map_err(|e| anyhow!("Invalid signature format: {}", e))?;

        // Recover public key
        let public_key = secp
            .recover_ecdsa(&message, &sig)
            .map_err(|e| anyhow!("Failed to recover public key: {}", e))?;

        // Get uncompressed public key (65 bytes: 0x04 || x || y)
        let public_key_uncompressed = public_key.serialize_uncompressed();

        // Take the last 64 bytes (x || y, skip the 0x04 prefix)
        let public_key_bytes = &public_key_uncompressed[1..];

        // Hash with Keccak256 and take last 20 bytes for Ethereum address
        let mut hasher = Keccak256::new();
        hasher.update(public_key_bytes);
        let hash = hasher.finalize();

        // Ethereum address is the last 20 bytes of the hash
        let address = Address::from_slice(&hash[12..]);

        Ok(address)
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
