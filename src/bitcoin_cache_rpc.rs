use anyhow::{anyhow, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use bitcoin::Block;
use bitcoincore_rpc::{Client, RpcApi};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
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
            .pool_max_idle_per_host(10) // Keep connections alive
            .pool_idle_timeout(Duration::from_secs(90)) // Keep idle connections for 90s
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

    async fn get_block_hash_many(&self, heights: &[u64]) -> Result<Vec<(u64, String)>> {
        // Build a batch JSON-RPC request with multiple IDs
        let requests: Vec<Value> = heights
            .iter()
            .map(|height| {
                json!({
                    "jsonrpc": "2.0",
                    "id": height,
                    "method": "getblockhash",
                    "params": [height]
                })
            })
            .collect();

        let response = self
            .client
            .post(&self.url)
            .json(&requests)
            .send()
            .await
            .map_err(|e| anyhow!("HTTP batch request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP error: {}", response.status()));
        }

        let results: Vec<Value> = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse batch JSON response: {}", e))?;

        let mut hashes = Vec::new();
        for result in results {
            if let Some(error) = result.get("error") {
                if !error.is_null() {
                    warn!("RPC error in batch response: {}", error);
                    continue;
                }
            }

            if let (Some(id), Some(hash)) = (
                result.get("id").and_then(|v| v.as_u64()),
                result.get("result").and_then(|v| v.as_str()),
            ) {
                hashes.push((id, hash.to_string()));
            }
        }

        Ok(hashes)
    }

    async fn get_block_hex(&self, hash: &str) -> Result<String> {
        let result = self.call("getblock", vec![json!(hash), json!(0)]).await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Invalid block hex response"))
    }

    async fn get_blockchain_info(&self) -> Result<Value> {
        self.call("getblockchaininfo", vec![]).await
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
    block_archive_url: String,
    archive_http_client: reqwest::Client,
}

impl BitcoinCacheRpcServer {
    pub fn new(
        cache_dir: &str,
        bitcoin_client: Client,
        block_archive_url: String,
        _starting_block_count: Option<u64>,
    ) -> Result<Self> {
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

        // Create a shared HTTP client for archive requests with connection pooling
        let archive_http_client = reqwest::Client::builder()
            .pool_max_idle_per_host(10) // Keep connections alive
            .pool_idle_timeout(Duration::from_secs(90)) // Keep idle connections for 90s
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| anyhow!("Failed to create archive HTTP client: {}", e))?;

        Ok(Self {
            state: Arc::new(BitcoinCacheState {
                cache_dir: cache_path,
                bitcoin_client: BitcoinRpcClient::BitcoinCore(Arc::new(bitcoin_client)),
                block_archive_url,
                archive_http_client,
            }),
        })
    }

    pub fn new_with_http(
        cache_dir: &str,
        rpc_url: String,
        block_archive_url: String,
        starting_block_count: Option<u64>,
    ) -> Result<Self> {
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

        let http_client = HttpRpcClient::new(rpc_url);

        // Create a shared HTTP client for archive requests with connection pooling
        let archive_http_client = reqwest::Client::builder()
            .pool_max_idle_per_host(10) // Keep connections alive
            .pool_idle_timeout(Duration::from_secs(90)) // Keep idle connections for 90s
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| anyhow!("Failed to create archive HTTP client: {}", e))?;

        let server = Self {
            state: Arc::new(BitcoinCacheState {
                cache_dir: cache_path.clone(),
                bitcoin_client: BitcoinRpcClient::Http(http_client.clone()),
                block_archive_url: block_archive_url.clone(),
                archive_http_client,
            }),
        };

        // Check for .inited file and start prefetching if needed
        let inited_file = cache_path.join(".inited");
        if !inited_file.exists() {
            if let Some(start_block) = starting_block_count {
                info!("🔄 First startup detected, initiating block prefetch...");

                // Spawn background task for prefetching
                let server_clone = server.clone();

                tokio::spawn(async move {
                    if let Err(e) = server_clone.prefetch_blocks(start_block).await {
                        warn!("⚠️  Block prefetch failed: {}", e);
                    }
                });

                // Create .inited file immediately to prevent multiple prefetch attempts
                if let Err(e) = std::fs::write(&inited_file, "") {
                    warn!("⚠️  Failed to create .inited file: {}", e);
                }
            }
        } else {
            info!("✅ Cache already initialized");
        }

        Ok(server)
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/", post(handle_rpc))
            .with_state(self.clone())
    }

    /// Prefetch blocks from starting block to current block count
    async fn prefetch_blocks(&self, start_block: u64) -> Result<()> {
        info!("🚀 Starting block prefetch from block {}", start_block);

        // Get current block count
        let current_block = match &self.state.bitcoin_client {
            BitcoinRpcClient::Http(client) => match client.get_block_count().await {
                Ok(count) => count,
                Err(e) => {
                    warn!("⚠️  Failed to get block count for prefetch: {}", e);
                    return Err(anyhow!("Failed to get block count: {}", e));
                }
            },
            _ => {
                info!("ℹ️  Prefetch only works with HTTP client, skipping");
                return Ok(());
            }
        };

        let total_blocks = current_block.saturating_sub(start_block);
        info!(
            "📊 Will prefetch {} blocks (from {} to {})",
            total_blocks, start_block, current_block
        );

        // Fetch block hashes in batches of 500
        const BATCH_SIZE: u64 = 500;
        let mut current = start_block;
        let mut total_fetched = 0u64;

        while current <= current_block {
            let end = (current + BATCH_SIZE).min(current_block + 1);

            info!(
                "🔍 Fetching hashes for blocks {} to {} ({}/{} blocks)",
                current,
                end - 1,
                total_fetched,
                total_blocks
            );

            // Fetch hashes for this batch using batch JSON-RPC request
            let heights: Vec<u64> = (current..end).collect();
            let block_hashes = match &self.state.bitcoin_client {
                BitcoinRpcClient::Http(client) => {
                    match client.get_block_hash_many(&heights).await {
                        Ok(hashes) => hashes,
                        Err(e) => {
                            warn!(
                                "⚠️  Failed to get hashes for batch {}-{}: {}",
                                current,
                                end - 1,
                                e
                            );
                            Vec::new()
                        }
                    }
                }
                _ => {
                    // Shouldn't reach here as we check earlier, but fallback to individual calls
                    let mut hashes = Vec::new();
                    for height in heights {
                        match self.handle_getblockhash(height).await {
                            Ok(hash_value) => {
                                if let Some(hash_str) = hash_value.as_str() {
                                    hashes.push((height, hash_str.to_string()));
                                }
                            }
                            Err(e) => {
                                warn!("⚠️  Failed to get hash for block {}: {}", height, e);
                            }
                        }
                    }
                    hashes
                }
            };

            // Fetch blocks for this batch
            for (height, hash) in block_hashes {
                let blocks_dir = self.state.cache_dir.join("blocks");
                let block_file = blocks_dir.join(format!("{}.bin", hash));

                // Skip if already cached
                if block_file.exists() {
                    debug!("⏭️  Block {} ({}) already cached", height, hash);
                    total_fetched += 1;
                    continue;
                }

                // Fetch and cache the block
                match self.get_or_fetch_block(&hash).await {
                    Ok(_) => {
                        total_fetched += 1;
                        if total_fetched.is_multiple_of(10) {
                            info!("✅ Prefetched {}/{} blocks", total_fetched, total_blocks);
                        }
                    }
                    Err(e) => {
                        warn!("⚠️  Failed to prefetch block {} ({}): {}", height, hash, e);
                    }
                }
            }

            current = end;
        }

        info!(
            "🎉 Block prefetch complete! Fetched {} blocks",
            total_fetched
        );
        Ok(())
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

    async fn handle_getblockchaininfo(&self) -> Result<Value> {
        info!("ℹ️  Bitcoin Cache: getblockchaininfo called");

        // Forward to Bitcoin RPC (no lock needed - state is immutable)
        let info = match &self.state.bitcoin_client {
            BitcoinRpcClient::BitcoinCore(client) => {
                let blockchain_info = client.get_blockchain_info().map_err(|e| {
                    anyhow!("Failed to get blockchain info from Bitcoin RPC: {}", e)
                })?;

                // Convert to JSON value
                json!({
                    "chain": blockchain_info.chain.to_string(),
                    "blocks": blockchain_info.blocks,
                    "headers": blockchain_info.headers,
                    "bestblockhash": blockchain_info.best_block_hash.to_string(),
                    "difficulty": blockchain_info.difficulty,
                    "mediantime": blockchain_info.median_time,
                    "verificationprogress": blockchain_info.verification_progress,
                    "initialblockdownload": blockchain_info.initial_block_download,
                    "chainwork": hex::encode(&blockchain_info.chain_work),
                    "size_on_disk": blockchain_info.size_on_disk,
                    "pruned": blockchain_info.pruned,
                })
            }
            BitcoinRpcClient::Http(client) => client.get_blockchain_info().await?,
        };

        debug!("✅ Forwarded getblockchaininfo");
        Ok(info)
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
            match tokio::fs::read(&block_file).await {
                Ok(block_data) if !block_data.is_empty() => {
                    // Verify the cached block is valid
                    if let Err(e) = bitcoin::consensus::deserialize::<Block>(&block_data) {
                        warn!(
                            "⚠️  Cached block {} is corrupted, removing: {}",
                            block_hash, e
                        );
                        let _ = tokio::fs::remove_file(&block_file).await;
                        // Fall through to fetch the block again
                    } else {
                        return Ok(hex::encode(block_data));
                    }
                }
                Ok(_) => {
                    warn!("⚠️  Cached block {} is empty, removing", block_hash);
                    let _ = tokio::fs::remove_file(&block_file).await;
                    // Fall through to fetch the block again
                }
                Err(e) => {
                    warn!("⚠️  Failed to read cached block {}: {}", block_hash, e);
                    // Fall through to fetch the block again
                }
            }
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
                        match tokio::fs::read(&block_file).await {
                            Ok(block_data) if !block_data.is_empty() => {
                                // Verify the block is valid
                                if bitcoin::consensus::deserialize::<Block>(&block_data).is_ok() {
                                    return Ok(hex::encode(block_data));
                                }
                                debug!("⚠️  Block not yet fully written, continuing to wait...");
                            }
                            _ => {
                                debug!("⚠️  Block file exists but not readable yet, continuing to wait...");
                            }
                        }
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

    /// Verify block hash and save to cache
    async fn verify_and_cache_block(
        &self,
        block_data: &[u8],
        expected_hash: &str,
        block_file: &Path,
    ) -> Result<String> {
        // Parse and verify the block hash
        let block: Block = bitcoin::consensus::deserialize(block_data)
            .map_err(|e| anyhow!("Failed to deserialize block: {}", e))?;

        let actual_hash = block.block_hash().to_string();

        if actual_hash.to_lowercase() != expected_hash.to_lowercase() {
            return Err(anyhow!(
                "Block hash mismatch! Expected: {}, got: {}",
                expected_hash,
                actual_hash
            ));
        }

        info!("✅ Block hash verified: {}", actual_hash);

        // Save binary data to cache with explicit sync to ensure data is flushed
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::File::create(block_file)
            .await
            .map_err(|e| anyhow!("Failed to create block file: {}", e))?;

        file.write_all(block_data)
            .await
            .map_err(|e| anyhow!("Failed to write block data: {}", e))?;

        // Ensure all data is written to disk before releasing lock
        file.sync_all()
            .await
            .map_err(|e| anyhow!("Failed to sync block data to disk: {}", e))?;

        info!("💾 Saved block to cache ({} bytes)", block_data.len());

        // Return hex-encoded block
        Ok(hex::encode(block_data))
    }

    /// Fetch block from Bitcoin RPC and save to cache with exponential backoff retry
    async fn fetch_and_cache_block(
        &self,
        block_hash: &str,
        bitcoin_client: BitcoinRpcClient,
        block_file: &Path,
        _lock_file: &Path,
    ) -> Result<String> {
        // First, try to fetch from the block archive server using the shared HTTP client
        let archive_url = format!("{}/{}.bin", self.state.block_archive_url, block_hash);
        info!("📦 Trying block archive: {}", archive_url);

        if let Ok(response) = self
            .state
            .archive_http_client
            .get(&archive_url)
            .send()
            .await
        {
            if response.status().is_success() {
                if let Ok(block_data) = response.bytes().await {
                    info!("✅ Found block in archive ({} bytes)", block_data.len());
                    match self
                        .verify_and_cache_block(&block_data, block_hash, block_file)
                        .await
                    {
                        Ok(hex) => return Ok(hex),
                        Err(e) => warn!("⚠️  Archive block verification failed: {}", e),
                    }
                }
            }
        }

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
            let block_hex = match fetch_result {
                Some(hex) => hex,
                None => continue, // Retry
            };

            // Successfully fetched, now decode and verify
            let block_data = match hex::decode(&block_hex) {
                Ok(data) => data,
                Err(e) => {
                    warn!("⚠️  Failed to decode block hex: {}", e);
                    last_error = Some(anyhow!("Failed to decode block hex: {}", e));
                    continue; // Retry
                }
            };

            // Verify and cache the block
            match self
                .verify_and_cache_block(&block_data, block_hash, block_file)
                .await
            {
                Ok(hex) => return Ok(hex),
                Err(e) => {
                    warn!("⚠️  Verification/caching failed: {}", e);
                    last_error = Some(e);
                    continue; // Retry - upstream might have sent wrong data
                }
            }
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

    /// Handle submitpackage RPC call - forward to upstream Bitcoin RPC
    async fn handle_submitpackage(&self, package_txs: Value) -> Result<Value> {
        let tx_count = package_txs.as_array().map(|arr| arr.len()).unwrap_or(0);
        info!(
            "📦 Bitcoin Cache: submitpackage called with {} transactions",
            tx_count
        );

        // Print transaction hex for debugging
        if let Some(tx_array) = package_txs.as_array() {
            for (i, tx) in tx_array.iter().enumerate() {
                if let Some(tx_hex) = tx.as_str() {
                    info!("📝 Transaction {} hex: {}", i + 1, tx_hex);
                }
            }
        }

        // Forward to upstream Bitcoin RPC using HTTP client
        let result = self
            .forward_rpc_call("submitpackage", vec![package_txs])
            .await?;

        // Verify the submission was successful
        if let Some(tx_results) = result.get("tx-results").and_then(|v| v.as_object()) {
            let mut success_count = 0;
            let mut error_count = 0;

            for (wtxid, tx_result) in tx_results {
                if let Some(result_obj) = tx_result.as_object() {
                    // Check if there's an error field that's not null
                    let has_error = result_obj
                        .get("error")
                        .map(|e| !e.is_null())
                        .unwrap_or(false);

                    if has_error {
                        error_count += 1;
                        if let Some(error) = result_obj.get("error") {
                            warn!("❌ Transaction wtxid {} failed: {}", wtxid, error);
                        }
                    } else {
                        success_count += 1;
                        // Extract actual txid if available, otherwise use wtxid
                        let display_id = result_obj
                            .get("txid")
                            .and_then(|t| t.as_str())
                            .unwrap_or(wtxid);
                        info!(
                            "✅ Transaction {} submitted successfully (wtxid: {})",
                            display_id, wtxid
                        );
                    }
                }
            }

            info!(
                "📊 Package submission result: {} successful, {} failed",
                success_count, error_count
            );

            if error_count > 0 {
                warn!("⚠️  Some transactions in package failed to submit");
            }
        } else {
            warn!("⚠️  Could not parse tx-results from submitpackage response");
        }

        info!("✅ Forwarded submitpackage to upstream Bitcoin RPC");
        Ok(result)
    }

    /// Handle sendrawtransaction RPC call - forward to upstream Bitcoin RPC
    async fn handle_sendrawtransaction(&self, raw_tx_hex: String) -> Result<Value> {
        info!(
            "📤 Bitcoin Cache: sendrawtransaction called with tx: {}...",
            &raw_tx_hex[..32.min(raw_tx_hex.len())]
        );

        // Print full transaction hex for debugging
        info!("📝 Transaction hex: {}", raw_tx_hex);

        // Forward to upstream Bitcoin RPC using HTTP client
        let result = self
            .forward_rpc_call("sendrawtransaction", vec![json!(raw_tx_hex)])
            .await?;

        // Verify the submission was successful
        if let Some(tx_id) = result.as_str() {
            info!("✅ Transaction {} submitted successfully", tx_id);
        } else {
            warn!("⚠️  Could not parse transaction ID from sendrawtransaction response");
        }

        info!("✅ Forwarded sendrawtransaction to upstream Bitcoin RPC");
        Ok(result)
    }

    /// Handle getnetworkinfo RPC call - forward to upstream Bitcoin RPC
    async fn handle_getnetworkinfo(&self) -> Result<Value> {
        info!("🌐 Bitcoin Cache: getnetworkinfo called");

        // Forward to upstream Bitcoin RPC using HTTP client
        let result = self.forward_rpc_call("getnetworkinfo", vec![]).await?;

        debug!("✅ Forwarded getnetworkinfo to upstream Bitcoin RPC");
        Ok(result)
    }

    /// Handle estimatesmartfee RPC call - forward to upstream Bitcoin RPC
    async fn handle_estimatesmartfee(
        &self,
        conf_target: u64,
        estimate_mode: &str,
    ) -> Result<Value> {
        info!(
            "💰 Bitcoin Cache: estimatesmartfee called (target: {}, mode: {})",
            conf_target, estimate_mode
        );

        // Forward to upstream Bitcoin RPC using HTTP client
        let result = self
            .forward_rpc_call(
                "estimatesmartfee",
                vec![json!(conf_target), json!(estimate_mode)],
            )
            .await?;

        debug!("✅ Forwarded estimatesmartfee to upstream Bitcoin RPC");
        Ok(result)
    }

    /// Handle getrawtransaction RPC call - forward to upstream Bitcoin RPC
    async fn handle_getrawtransaction(
        &self,
        txid: String,
        verbose: bool,
        blockhash: Option<String>,
    ) -> Result<Value> {
        info!(
            "🔍 Bitcoin Cache: getrawtransaction called for txid={}, verbose={}, blockhash={:?}",
            txid, verbose, blockhash
        );

        // Build params array based on what was provided
        let mut params = vec![json!(txid), json!(verbose)];
        if let Some(hash) = blockhash {
            params.push(json!(hash));
        }

        // Forward to upstream Bitcoin RPC using HTTP client
        let result = self.forward_rpc_call("getrawtransaction", params).await?;

        debug!("✅ Forwarded getrawtransaction to upstream Bitcoin RPC");
        Ok(result)
    }

    /// Forward RPC call to upstream Bitcoin RPC server
    async fn forward_rpc_call(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        match &self.state.bitcoin_client {
            BitcoinRpcClient::BitcoinCore(client) => {
                // Use the existing call method for Bitcoin Core client
                let result = client
                    .call(method, &params)
                    .map_err(|e| anyhow!("Bitcoin Core RPC call failed: {}", e))?;
                Ok(result)
            }
            BitcoinRpcClient::Http(client) => {
                // Use the existing call method for HTTP client
                let result = client
                    .call(method, params)
                    .await
                    .map_err(|e| anyhow!("HTTP RPC call failed: {}", e))?;
                Ok(result)
            }
        }
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
        "getblockchaininfo" => server.handle_getblockchaininfo().await,
        "getblockhash" => {
            let block_height = match params.and_then(|p| p.first()).and_then(|v| v.as_u64()) {
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
            let block_hash = match params.and_then(|p| p.first()).and_then(|v| v.as_str()) {
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
        // Write operations - forward to upstream Bitcoin RPC
        "submitpackage" => {
            let package_txs = match params.and_then(|p| p.first()).cloned() {
                Some(p) => p,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32602,
                                "message": "Invalid params: package transactions required"
                            },
                            "id": id
                        })),
                    )
                        .into_response();
                }
            };
            server.handle_submitpackage(package_txs).await
        }
        "sendrawtransaction" => {
            let raw_tx_hex = match params.and_then(|p| p.first()).and_then(|v| v.as_str()) {
                Some(hex) => hex.to_string(),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32602,
                                "message": "Invalid params: raw transaction hex required"
                            },
                            "id": id
                        })),
                    )
                        .into_response();
                }
            };
            server.handle_sendrawtransaction(raw_tx_hex).await
        }
        // Additional read operations needed by TaprootDA
        "getnetworkinfo" => server.handle_getnetworkinfo().await,
        "estimatesmartfee" => {
            let conf_target = match params.and_then(|p| p.first()).and_then(|v| v.as_u64()) {
                Some(target) => target,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32602,
                                "message": "Invalid params: confirmation target required"
                            },
                            "id": id
                        })),
                    )
                        .into_response();
                }
            };
            let estimate_mode = params
                .and_then(|p| p.get(1))
                .and_then(|v| v.as_str())
                .unwrap_or("ECONOMICAL");
            server
                .handle_estimatesmartfee(conf_target, estimate_mode)
                .await
        }
        "getrawtransaction" => {
            let txid = match params.and_then(|p| p.first()).and_then(|v| v.as_str()) {
                Some(t) => t.to_string(),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32602,
                                "message": "Invalid params: transaction ID required"
                            },
                            "id": id
                        })),
                    )
                        .into_response();
                }
            };
            let verbose = params
                .and_then(|p| p.get(1))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let blockhash = params
                .and_then(|p| p.get(2))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            server
                .handle_getrawtransaction(txid, verbose, blockhash)
                .await
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
