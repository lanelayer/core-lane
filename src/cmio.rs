use crate::intents::IntentCommandType;
use crate::state::StateManager;
use crate::IntentData;
use crate::IntentType;
use alloy_primitives::B256;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::warn;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CmioMessage {
    QueryCommandType {},
    CommandTypeResponse {
        command_type: IntentCommandType,
        success: bool,
    },
    ReadIntentData {
        intent_id: String,
    },
    IntentDataResponse {
        data_hex: String,
        success: bool,
    },
    ReadBlobInfo {
        blob_hash_hex: String,
    },
    BlobInfoResponse {
        length: u64,
        success: bool,
    },
    ReadBlob {
        blob_hash_hex: String,
    },
    BlobResponse {
        data_hex: String,
        success: bool,
    },
    Log {
        message: String,
    },
    ReadExtraData {},
    ExtraDataResponse {
        extra_data: Vec<u8>,
    },
    Exit {
        code: u32,
    },
}

impl CmioMessage {
    pub fn to_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, anyhow::Error> {
        Ok(serde_json::from_slice(data)?)
    }
}

/// Helper function to parse a B256 from a hex string
fn parse_b256(hex_input: &str) -> Option<B256> {
    use std::str::FromStr;
    B256::from_str(hex_input).ok()
}

/// Common CMIO query handler that both the main node and library can use
///
/// This handles queries from RISC-V programs running in the Cartesi machine.
/// It queries the StateManager to provide intent data, blob data, etc.
pub fn handle_cmio_query(
    message: CmioMessage,
    state_manager: &StateManager,
    current_intent_id: Option<B256>,
) -> Option<CmioMessage> {
    match message {
        CmioMessage::QueryCommandType {} => {
            let Some(intent_id) = current_intent_id else {
                warn!("QueryCommandType called without current intent context");
                return None;
            };
            state_manager
                .get_intent(&intent_id)
                .map(|intent| CmioMessage::CommandTypeResponse {
                    command_type: intent.last_command,
                    success: true,
                })
        }
        CmioMessage::ReadIntentData { intent_id } => {
            let intent_id_b256 = parse_b256(&intent_id)?;
            if let Some(intent) = state_manager.get_intent(&intent_id_b256) {
                Some(CmioMessage::IntentDataResponse {
                    data_hex: format!("0x{}", hex::encode(&intent.data)),
                    success: true,
                })
            } else {
                Some(CmioMessage::IntentDataResponse {
                    data_hex: "0x".to_string(),
                    success: false,
                })
            }
        }
        CmioMessage::ReadBlobInfo { blob_hash_hex } => {
            let blob_hash = parse_b256(&blob_hash_hex)?;
            if let Some(data) = state_manager.get_blob(&blob_hash) {
                Some(CmioMessage::BlobInfoResponse {
                    length: data.len() as u64,
                    success: true,
                })
            } else {
                Some(CmioMessage::BlobInfoResponse {
                    length: 0,
                    success: false,
                })
            }
        }
        CmioMessage::ReadBlob { blob_hash_hex } => {
            let blob_hash = parse_b256(&blob_hash_hex)?;
            if let Some(data) = state_manager.get_blob(&blob_hash) {
                Some(CmioMessage::BlobResponse {
                    data_hex: format!("0x{}", hex::encode(data)),
                    success: true,
                })
            } else {
                Some(CmioMessage::BlobResponse {
                    data_hex: "0x".to_string(),
                    success: false,
                })
            }
        }
        CmioMessage::Log { message } => {
            tracing::info!(target = "cmio", "CM LOG: {}", message);
            None
        }
        CmioMessage::ReadExtraData {} => {
            if let Some(intent_id) = current_intent_id {
                if let Some(intent) = state_manager.get_intent(&intent_id) {
                    let intent_data = match IntentData::from_cbor(&intent.data) {
                        Ok(data) => data,
                        Err(_) => {
                            return Some(CmioMessage::ExtraDataResponse { extra_data: vec![] });
                        }
                    };

                    if intent_data.intent_type == IntentType::RiscVProgram {
                        let riscv_intent = match intent_data.parse_riscv_program() {
                            Ok(prog) => prog,
                            Err(_) => {
                                return Some(CmioMessage::ExtraDataResponse { extra_data: vec![] });
                            }
                        };

                        Some(CmioMessage::ExtraDataResponse {
                            extra_data: riscv_intent.extra_data,
                        })
                    } else {
                        Some(CmioMessage::ExtraDataResponse { extra_data: vec![] })
                    }
                } else {
                    Some(CmioMessage::ExtraDataResponse { extra_data: vec![] })
                }
            } else {
                warn!("ReadExtraData called but no current intent context available");
                Some(CmioMessage::ExtraDataResponse { extra_data: vec![] })
            }
        }
        CmioMessage::Exit { code } => Some(CmioMessage::Exit { code }),
        _ => None,
    }
}
