use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolCall};
use anyhow::Result;
use ciborium::de::from_reader;
use ciborium::into_writer;
use serde::{Deserialize, Serialize};

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
    pub fn parse_anchor_bitcoin_fill(&self) -> anyhow::Result<AnchorBitcoinFill> {
        use anyhow::anyhow;
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

    pub fn parse_bitcoin_address(&self) -> anyhow::Result<String> {
        use anyhow::anyhow;
        use bitcoin::Address as BitcoinAddress;
        use std::str::FromStr;
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

pub fn parse_bitcoin_address_from_cbor_intent(cbor_intent: &IntentData) -> anyhow::Result<String> {
    match cbor_intent.intent_type {
        IntentType::AnchorBitcoinFill => {
            let fill_data = cbor_intent.parse_anchor_bitcoin_fill().unwrap();
            let address_str = fill_data.parse_bitcoin_address().unwrap();
            Ok(address_str)
        }
    }
}

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
    use alloy_sol_types::SolCall as _;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentStatus {
    Submitted,
    Locked(Address),
    Solved,
}

#[derive(Debug, Clone)]
pub struct Intent {
    pub data: Bytes,
    pub value: u64,
    pub status: IntentStatus,
}
