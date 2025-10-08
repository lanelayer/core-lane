use anyhow::{anyhow, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use bitcoincore_rpc::{Client, RpcApi};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Timeout for establishing HTTP connection to upstream Bitcoin RPC
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for complete HTTP request/response cycle to upstream Bitcoin RPC
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Simple HTTP-based Bitcoin RPC client for public RPCs
#[derive(Clone)]
struct HttpRpcClient {
    url: String,
    client: reqwest::Client,
}

impl HttpRpcClient {
    fn new(url: String) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()
            .expect("Failed to build HTTP client");

        Self { url, client }
    }

    async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        let response = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP error: {}", response.status()));
        }

        let json: Value = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse JSON response: {}", e))?;

        if let Some(error) = json.get("error") {
            if !error.is_null() {
                return Err(anyhow!("RPC error: {}", error));
            }
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("No result in response"))
    }

    async fn get_block_count(&self) -> Result<u64> {
        let result = self.call("getblockcount", vec![]).await?;
        result
            .as_u64()
            .ok_or_else(|| anyhow!("Invalid block count response"))
    }

    async fn get_block_hash(&self, height: u64) -> Result<String> {
        let result = self.call("getblockhash", vec![json!(height)]).await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Invalid block hash response"))
    }

    async fn get_block_hex(&self, hash: &str) -> Result<String> {
        let result = self.call("getblock", vec![json!(hash), json!(0)]).await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Invalid block hex response"))
    }
}

/// Bitcoin RPC client that can use either bitcoincore-rpc or HTTP
#[derive(Clone)]
enum BitcoinRpcClient {
    BitcoinCore(Arc<Client>),
    Http(HttpRpcClient),
}

/// Bitcoin Cache RPC Server
/// Exposes a minimal set of Bitcoin RPC methods for caching purposes
#[derive(Clone)]
pub struct BitcoinCacheRpcServer {
    state: Arc<BitcoinCacheState>,
}

#[derive(Clone)]
struct BitcoinCacheState {
    cache_dir: PathBuf,
    bitcoin_client: BitcoinRpcClient,
}

impl BitcoinCacheRpcServer {
    pub fn new(cache_dir: &str, bitcoin_client: Client) -> Result<Self> {
        let cache_path = PathBuf::from(cache_dir);

        // Create cache directory structure if it doesn't exist
        if !cache_path.exists() {
            std::fs::create_dir_all(&cache_path)?;
            info!("📁 Created cache directory: {}", cache_path.display());
        }

        let blocks_dir = cache_path.join("blocks");
        if !blocks_dir.exists() {
            std::fs::create_dir_all(&blocks_dir)?;
            info!("📁 Created blocks directory: {}", blocks_dir.display());
        }

        info!("📁 Using cache directory: {}", cache_path.display());

        Ok(Self {
            state: Arc::new(BitcoinCacheState {
                cache_dir: cache_path,
                bitcoin_client: BitcoinRpcClient::BitcoinCore(Arc::new(bitcoin_client)),
            }),
        })
    }

    pub fn new_with_http(cache_dir: &str, rpc_url: String) -> Result<Self> {
        let cache_path = PathBuf::from(cache_dir);

        // Create cache directory structure if it doesn't exist
        if !cache_path.exists() {
            std::fs::create_dir_all(&cache_path)?;
            info!("📁 Created cache directory: {}", cache_path.display());
        }

        let blocks_dir = cache_path.join("blocks");
        if !blocks_dir.exists() {
            std::fs::create_dir_all(&blocks_dir)?;
            info!("📁 Created blocks directory: {}", blocks_dir.display());
        }

        info!("📁 Using cache directory: {}", cache_path.display());

        Ok(Self {
            state: Arc::new(BitcoinCacheState {
                cache_dir: cache_path,
                bitcoin_client: BitcoinRpcClient::Http(HttpRpcClient::new(rpc_url)),
            }),
        })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/", post(handle_rpc))
            .with_state(self.clone())
    }

    async fn handle_getblockcount(&self) -> Result<Value> {
        info!("📊 Bitcoin Cache: getblockcount called");

        // Forward to Bitcoin RPC (no lock needed - state is immutable)
        let count = match &self.state.bitcoin_client {
            BitcoinRpcClient::BitcoinCore(client) => client
                .get_block_count()
                .map_err(|e| anyhow!("Failed to get block count from Bitcoin RPC: {}", e))?,
            BitcoinRpcClient::Http(client) => client.get_block_count().await?,
        };

        debug!("✅ Forwarded getblockcount: {}", count);
        Ok(json!(count))
    }

    async fn handle_getblockhash(&self, block_height: u64) -> Result<Value> {
        info!(
            "🔗 Bitcoin Cache: getblockhash called for block {}",
            block_height
        );

        // Forward to Bitcoin RPC (no lock needed - state is immutable)
        let hash = match &self.state.bitcoin_client {
            BitcoinRpcClient::BitcoinCore(client) => client
                .get_block_hash(block_height)
                .map_err(|e| anyhow!("Failed to get block hash from Bitcoin RPC: {}", e))?
                .to_string(),
            BitcoinRpcClient::Http(client) => client.get_block_hash(block_height).await?,
        };

        debug!("✅ Forwarded getblockhash: {}", hash);
        Ok(json!(hash))
    }

    async fn handle_getblock(&self, block_hash: String, verbosity: Option<u64>) -> Result<Value> {
        info!("📦 Bitcoin Cache: getblock called for hash {}", block_hash);

        // Only support verbosity=0 (raw block hex)
        let verbosity = verbosity.unwrap_or(0);
        if verbosity != 0 {
            return Err(anyhow!("Only verbosity=0 is supported (raw block hex)"));
        }

        // Validate block hash format
        let block_hash = Self::validate_block_hash(&block_hash)?;

        let block_hex = self.get_or_fetch_block(&block_hash).await?;

        info!(
            "✅ Served block {} ({} bytes)",
            block_hash,
            block_hex.len() / 2
        );

        Ok(json!(block_hex))
    }

    /// Get block from cache or fetch from Bitcoin RPC if not cached
    /// Uses file-based locking to prevent concurrent fetches of the same block
    async fn get_or_fetch_block(&self, block_hash: &str) -> Result<String> {
        // Access immutable state directly (no lock needed)
        let blocks_dir = self.state.cache_dir.join("blocks");
        let bitcoin_client = &self.state.bitcoin_client;

        let block_file = blocks_dir.join(format!("{}.bin", block_hash));
        let lock_file = blocks_dir.join(format!("{}.lock", block_hash));

        // Check if block is already cached
        if block_file.exists() {
            debug!("📂 Block found in cache: {}", block_hash);
            let block_data = tokio::fs::read(&block_file)
                .await
                .map_err(|e| anyhow!("Failed to read cached block: {}", e))?;
            return Ok(hex::encode(block_data));
        }

        debug!(
            "⚠️  Block not in cache, attempting to acquire lock: {}",
            block_hash
        );

        // Atomically try to create lock file in a loop
        let max_wait = Duration::from_secs(60);
        let check_interval = Duration::from_millis(100);
        let start = std::time::Instant::now();

        loop {
            // Try to atomically create the lock file
            match tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_file)
                .await
            {
                Ok(_) => {
                    // Successfully created lock file, we now hold the lock
                    info!("🔒 Acquired lock for block {}", block_hash);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Someone else holds the lock, wait and retry
                    debug!("🔒 Lock held by another request, waiting...");

                    if start.elapsed() > max_wait {
                        warn!("⏱️  Timeout waiting for lock on block {}", block_hash);
                        // Try to remove stale lock
                        let _ = tokio::fs::remove_file(&lock_file).await;
                        return Err(anyhow!("Timeout waiting for block fetch"));
                    }

                    sleep(check_interval).await;

                    // Check if block appeared while we were waiting
                    if block_file.exists() {
                        info!("✅ Block became available while waiting");
                        let block_data = tokio::fs::read(&block_file)
                            .await
                            .map_err(|e| anyhow!("Failed to read cached block: {}", e))?;
                        return Ok(hex::encode(block_data));
                    }

                    // Continue loop to retry lock acquisition
                }
                Err(e) => {
                    // Some other error occurred (permissions, disk full, etc.)
                    return Err(anyhow!("Failed to create lock file: {}", e));
                }
            }
        }

        let result = self
            .fetch_and_cache_block(block_hash, bitcoin_client.clone(), &block_file, &lock_file)
            .await;

        // Always try to remove lock file when done
        let _ = tokio::fs::remove_file(&lock_file).await;

        result
    }

    /// Fetch block from Bitcoin RPC and save to cache with exponential backoff retry
    async fn fetch_and_cache_block(
        &self,
        block_hash: &str,
        bitcoin_client: BitcoinRpcClient,
        block_file: &PathBuf,
        lock_file: &PathBuf,
    ) -> Result<String> {
        info!("📡 Fetching block {} from Bitcoin RPC...", block_hash);

        // Exponential backoff configuration
        let max_retries = 5;
        let initial_delay = Duration::from_millis(100);
        let max_delay = Duration::from_secs(10);

        let mut last_error = None;

        for attempt in 0..max_retries {
            if attempt > 0 {
                // Calculate exponential backoff delay: 100ms, 200ms, 400ms, 800ms, etc.
                let delay = initial_delay * 2u32.pow(attempt as u32);
                let delay = delay.min(max_delay);
                warn!("🔄 Retry attempt {} after {:?}", attempt + 1, delay);
                sleep(delay).await;
            }

            // Fetch raw block hex from Bitcoin RPC
            let fetch_result = match &bitcoin_client {
                BitcoinRpcClient::BitcoinCore(client) => {
                    // Parse block hash
                    let hash = match bitcoin::BlockHash::from_str(block_hash) {
                        Ok(h) => h,
                        Err(e) => return Err(anyhow!("Invalid block hash: {}", e)),
                    };

                    let client = client.clone();
                    match tokio::task::spawn_blocking(move || client.get_block_hex(&hash)).await {
                        Ok(Ok(hex)) => Some(hex),
                        Ok(Err(e)) => {
                            warn!("⚠️  Attempt {} failed: {}", attempt + 1, e);
                            last_error = Some(anyhow!("{}", e));
                            None
                        }
                        Err(e) => {
                            warn!("⚠️  Attempt {} failed (task error): {}", attempt + 1, e);
                            last_error = Some(anyhow!("Task join error: {}", e));
                            None
                        }
                    }
                }
                BitcoinRpcClient::Http(client) => match client.get_block_hex(block_hash).await {
                    Ok(hex) => Some(hex),
                    Err(e) => {
                        warn!("⚠️  Attempt {} failed: {}", attempt + 1, e);
                        last_error = Some(e);
                        None
                    }
                },
            };

            // Check if fetch was successful
            let block_hex_result = match fetch_result {
                Some(hex) => hex,
                None => continue, // Retry
            };

            // Successfully fetched, now decode and verify
            let block_data = hex::decode(&block_hex_result)
                .map_err(|e| anyhow!("Failed to decode block hex: {}", e))?;

            // Parse block and verify hash matches
            let block: bitcoin::Block = bitcoin::consensus::deserialize(&block_data)
                .map_err(|e| anyhow!("Failed to deserialize block: {}", e))?;

            let actual_hash = block.block_hash();
            let expected_hash = bitcoin::BlockHash::from_str(block_hash)
                .map_err(|e| anyhow!("Invalid expected block hash: {}", e))?;

            if actual_hash != expected_hash {
                let error_msg = format!(
                    "Block hash mismatch! Expected: {}, got: {}",
                    expected_hash, actual_hash
                );
                warn!("⚠️  {}", error_msg);
                last_error = Some(anyhow!(error_msg));
                continue; // Retry - upstream might have sent wrong data
            }

            debug!("✅ Block hash verified: {}", actual_hash);

            // Save to cache
            tokio::fs::write(&block_file, &block_data)
                .await
                .map_err(|e| {
                    warn!("❌ Failed to save block to cache: {}", e);
                    // Remove lock on failure
                    let lock_file = lock_file.clone();
                    tokio::spawn(async move {
                        let _ = tokio::fs::remove_file(&lock_file).await;
                    });
                    anyhow!("Failed to save block to cache: {}", e)
                })?;

            info!(
                "💾 Cached block {} ({} bytes)",
                block_hash,
                block_data.len()
            );

            return Ok(block_hex_result);
        }

        // All retries failed
        Err(last_error
            .unwrap_or_else(|| anyhow!("Failed to fetch block after {} retries", max_retries)))
    }

    /// Validate and normalize block hash format
    /// Accepts with or without 0x prefix, validates hex format and length
    fn validate_block_hash(hash: &str) -> Result<String> {
        // Remove 0x prefix if present
        let hash = hash.strip_prefix("0x").unwrap_or(hash);

        // Validate length (Bitcoin block hash is 32 bytes = 64 hex characters)
        if hash.len() != 64 {
            return Err(anyhow!(
                "Invalid block hash length: expected 64 characters, got {}",
                hash.len()
            ));
        }

        // Validate hex format
        if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!("Invalid block hash format: must be hexadecimal"));
        }

        // Return lowercase normalized hash
        Ok(hash.to_lowercase())
    }
}

async fn handle_rpc(
    State(server): State<BitcoinCacheRpcServer>,
    Json(payload): Json<Value>,
) -> Response {
    debug!("Received RPC request: {}", payload);

    let method = match payload.get("method").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": "Invalid Request: missing method"
                    },
                    "id": payload.get("id")
                })),
            )
                .into_response();
        }
    };

    let params = payload.get("params").and_then(|v| v.as_array());
    let id = payload.get("id").cloned().unwrap_or(Value::Null);

    let result = match method {
        "getblockcount" => server.handle_getblockcount().await,
        "getblockhash" => {
            let block_height = match params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()) {
                Some(h) => h,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32602,
                                "message": "Invalid params: block height required"
                            },
                            "id": id
                        })),
                    )
                        .into_response();
                }
            };
            server.handle_getblockhash(block_height).await
        }
        "getblock" => {
            let block_hash = match params.and_then(|p| p.get(0)).and_then(|v| v.as_str()) {
                Some(h) => h.to_string(),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32602,
                                "message": "Invalid params: block hash required"
                            },
                            "id": id
                        })),
                    )
                        .into_response();
                }
            };
            let verbosity = params.and_then(|p| p.get(1)).and_then(|v| v.as_u64());
            server.handle_getblock(block_hash, verbosity).await
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32601,
                        "message": format!("Method not found: {}", method)
                    },
                    "id": id
                })),
            )
                .into_response();
        }
    };

    match result {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({
                "jsonrpc": "2.0",
                "result": result,
                "id": id
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": format!("Internal error: {}", e)
                },
                "id": id
            })),
        )
            .into_response(),
    }
}
