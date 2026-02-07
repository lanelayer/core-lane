//! Abstraction for Bitcoin RPC read client. Uses corepc-client for both HTTP and HTTPS.

use anyhow::Result;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::Transaction;
use bitcoin::Txid;
use corepc_client::client_sync::v28;
use corepc_client::client_sync::Auth as CorepcAuth;
use corepc_types::model::GetRawTransactionVerbose;
use serde_json::Value;
use std::str::FromStr;
use std::sync::Arc;

/// Result of getrawtransaction (verbose).
#[derive(Debug, Clone)]
pub struct RawTransactionInfo {
    pub block_hash: Option<BlockHash>,
    pub transaction: Transaction,
}

/// Read-only Bitcoin RPC interface used by the block scanner and verification.
/// Implemented by corepc-client and HttpBitcoinRpcClient.
pub trait BitcoinRpcReadClient: Send + Sync {
    fn get_block_count(&self) -> Result<u64>;
    fn get_block_hash(&self, height: u64) -> Result<BlockHash>;
    /// Returns the raw hash hex string from getblockhash - use this for getblock to avoid
    /// BlockHash roundtrip byte-order issues with some RPC backends.
    fn get_block_hash_hex(&self, height: u64) -> Result<String>;
    fn get_block(&self, hash: &BlockHash) -> Result<Block>;
    /// Fetch block by raw hash hex (from getblockhash) - avoids BlockHash conversion issues.
    fn get_block_by_hash_hex(&self, hash_hex: &str) -> Result<Block>;
    /// Optional: for initial bootstrap to get chain (main/test/regtest). Fallback when not implemented.
    fn getblockchaininfo(&self) -> Result<Value> {
        let _ = self;
        Err(anyhow::anyhow!("getblockchaininfo not implemented"))
    }
    fn get_raw_transaction_info(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<RawTransactionInfo>;
}

/// HTTP/HTTPS Bitcoin RPC client using reqwest (blocking). Kept as fallback; create_bitcoin_read_client uses corepc.
pub struct HttpBitcoinRpcClient {
    url: String,
    client: reqwest::blocking::Client,
    auth: Option<(String, String)>,
}

impl HttpBitcoinRpcClient {
    pub fn new(url: String, user: Option<String>, password: Option<String>) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))?;
        let auth = user
            .zip(password)
            .filter(|(u, p)| !u.is_empty() || !p.is_empty());
        Ok(Self { url, client, auth })
    }

    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });
        let mut req = self.client.post(&self.url).json(&body);
        if let Some((ref u, ref p)) = self.auth {
            req = req.basic_auth(u, Some(p));
        }
        let response = req
            .send()
            .map_err(|e| anyhow::anyhow!("HTTP request failed: {}", e))?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Bitcoin RPC HTTP {}: {}",
                response.status(),
                response.text().unwrap_or_default()
            ));
        }
        let json: Value = response
            .json()
            .map_err(|e| anyhow::anyhow!("Invalid JSON response: {}", e))?;
        if let Some(err) = json.get("error") {
            if !err.is_null() {
                return Err(anyhow::anyhow!("RPC error: {}", err));
            }
        }
        json.get("result")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No result in RPC response"))
    }
}

impl BitcoinRpcReadClient for HttpBitcoinRpcClient {
    fn get_block_count(&self) -> Result<u64> {
        let result = self.call("getblockcount", vec![])?;
        result
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Invalid getblockcount response"))
    }

    fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        let hex = self.get_block_hash_hex(height)?;
        let hex_trimmed = hex.trim_start_matches("0x").trim();
        BlockHash::from_str(hex_trimmed).map_err(|e| anyhow::anyhow!("Invalid block hash: {}", e))
    }

    fn get_block_hash_hex(&self, height: u64) -> Result<String> {
        let result = self.call("getblockhash", vec![Value::from(height)])?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("getblockhash did not return string"))
    }

    fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        self.get_block_by_hash_hex(&hash.to_string())
    }

    fn get_block_by_hash_hex(&self, hash_hex: &str) -> Result<Block> {
        let result = self.call("getblock", vec![Value::from(hash_hex), Value::from(0)])?;
        let hex_block = result
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("getblock did not return string"))?;
        let bytes = hex::decode(hex_block.trim_start_matches("0x").trim())
            .or_else(|_| hex::decode(hex_block))
            .map_err(|e| anyhow::anyhow!("Invalid block hex: {}", e))?;
        bitcoin::consensus::Decodable::consensus_decode(&mut bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("Failed to decode block: {}", e))
    }

    fn getblockchaininfo(&self) -> Result<Value> {
        self.call("getblockchaininfo", vec![])
    }

    fn get_raw_transaction_info(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<RawTransactionInfo> {
        let mut params = vec![Value::from(txid.to_string()), Value::from(true)];
        if let Some(h) = block_hash {
            params.push(Value::from(h.to_string()));
        }
        let result = self.call("getrawtransaction", params)?;
        let r: GetRawTransactionVerbose = serde_json::from_value(result)
            .map_err(|e| anyhow::anyhow!("Failed to parse getrawtransaction result: {}", e))?;
        Ok(RawTransactionInfo {
            block_hash: r.block_hash,
            transaction: r.transaction,
        })
    }
}

/// corepc-client (bitreq transport, HTTP and HTTPS).
impl BitcoinRpcReadClient for v28::Client {
    fn get_block_count(&self) -> Result<u64> {
        let result: Value = self
            .call("getblockcount", &[])
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        result
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Invalid getblockcount response"))
    }

    fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        let hex = self.get_block_hash_hex(height)?;
        let hex_trimmed = hex.trim_start_matches("0x").trim();
        BlockHash::from_str(hex_trimmed).map_err(|e| anyhow::anyhow!("Invalid block hash: {}", e))
    }

    fn get_block_hash_hex(&self, height: u64) -> Result<String> {
        let result: Value = self
            .call("getblockhash", &[Value::from(height)])
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("getblockhash did not return string"))
    }

    fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        self.get_block_by_hash_hex(&hash.to_string())
    }

    fn get_block_by_hash_hex(&self, hash_hex: &str) -> Result<Block> {
        let result: Value = self
            .call("getblock", &[Value::from(hash_hex), Value::from(0)])
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let hex_block = result
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("getblock did not return string"))?;
        let bytes = hex::decode(hex_block.trim_start_matches("0x").trim())
            .or_else(|_| hex::decode(hex_block))
            .map_err(|e| anyhow::anyhow!("Invalid block hex: {}", e))?;
        bitcoin::consensus::Decodable::consensus_decode(&mut bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("Failed to decode block: {}", e))
    }

    fn getblockchaininfo(&self) -> Result<Value> {
        self.call("getblockchaininfo", &[])
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    fn get_raw_transaction_info(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<RawTransactionInfo> {
        let mut args: Vec<Value> = vec![Value::from(txid.to_string()), Value::from(true)];
        if let Some(h) = block_hash {
            args.push(Value::from(h.to_string()));
        }
        let result: Value = self
            .call("getrawtransaction", &args)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let r: GetRawTransactionVerbose = serde_json::from_value(result)
            .map_err(|e| anyhow::anyhow!("Failed to parse getrawtransaction result: {}", e))?;
        Ok(RawTransactionInfo {
            block_hash: r.block_hash,
            transaction: r.transaction,
        })
    }
}

/// Corepc client type - used for both read and write Bitcoin RPC.
pub type BitcoinRpcClient = v28::Client;

/// Build a Bitcoin RPC client (corepc). Use for both read and write operations.
pub fn create_bitcoin_rpc_client(
    url: &str,
    user: &str,
    password: &str,
) -> Result<Arc<BitcoinRpcClient>> {
    let auth = CorepcAuth::UserPass(user.to_string(), password.to_string());
    let client = v28::Client::new_with_auth(url, auth)?;
    Ok(Arc::new(client))
}

/// Build the read client (convenience; same underlying client).
pub fn create_bitcoin_read_client(
    url: &str,
    user: &str,
    password: &str,
) -> Result<Arc<dyn BitcoinRpcReadClient>> {
    let client = create_bitcoin_rpc_client(url, user, password)?;
    Ok(client as Arc<dyn BitcoinRpcReadClient>)
}
