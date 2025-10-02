use crate::intents::IntentCommandType;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CmioMessage {
    QueryCommandType {
        intent_id: String,
    },
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
