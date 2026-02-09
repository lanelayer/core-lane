use crate::intents::{decode_intent_calldata, IntentCall, IntentStatus};
use crate::CoreLaneState;
use alloy_consensus::transaction::SignerRecoverable;
use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use axum::body::to_bytes;
use axum::{
    extract::{Json, Request},
    http::StatusCode,
    response::Json as JsonResponse,
    routing::{get, post},
    Router,
};
use core_lane::{run_cartesi_query, state::StateManager, QueryMethod};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    #[allow(dead_code)]
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Vec<Value>,
    pub id: Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

/// Configuration for RPC server when using Bitcoin client
pub struct BitcoinClientConfig {
    pub wallet: Option<String>,
    pub mnemonic: Option<String>,
    pub electrum_url: Option<String>,
    pub data_dir: String,
    pub sequencer_rpc_url: Option<String>,
}

impl BitcoinClientConfig {
    /// Validate that either bitcoin config (mnemonic) or sequencer_rpc_url is present
    pub fn validate(&self) -> Result<(), String> {
        let has_bitcoin_config = self.mnemonic.is_some();
        let has_sequencer = self.sequencer_rpc_url.is_some();

        if !has_bitcoin_config && !has_sequencer {
            return Err(
                "Either mnemonic (for Bitcoin DA) or sequencer_rpc_url must be provided"
                    .to_string(),
            );
        }

        Ok(())
    }
}

/// Wallet balance data structure
struct WalletBalanceData {
    network_str: String,
    total_sats: u64,
    confirmed_sats: u64,
    unconfirmed_sats: u64,
    total_btc: String,
    confirmed_btc: String,
    unconfirmed_btc: String,
}

/// Wallet balance error types
enum WalletBalanceError {
    /// Wallet database file not found
    WalletNotFound(String),
    /// Invalid mnemonic or key derivation failure
    InvalidMnemonic(String),
    /// Failed to open or load wallet database
    DatabaseError(String),
    /// Wallet not found in database
    WalletNotInDatabase,
    /// Missing required configuration (e.g., electrum URL or bitcoin RPC client)
    ConfigError(String),
}

impl WalletBalanceError {
    /// Convert error to HTTP status code
    fn to_status_code(&self) -> StatusCode {
        match self {
            WalletBalanceError::WalletNotFound(_) => StatusCode::NOT_FOUND,
            WalletBalanceError::InvalidMnemonic(_) => StatusCode::BAD_REQUEST,
            WalletBalanceError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WalletBalanceError::WalletNotInDatabase => StatusCode::NOT_FOUND,
            WalletBalanceError::ConfigError(_) => StatusCode::BAD_REQUEST,
        }
    }

    /// Get error message
    fn message(&self) -> String {
        match self {
            WalletBalanceError::WalletNotFound(msg) => msg.clone(),
            WalletBalanceError::InvalidMnemonic(msg) => msg.clone(),
            WalletBalanceError::DatabaseError(msg) => msg.clone(),
            WalletBalanceError::WalletNotInDatabase => "Wallet not found in database".to_string(),
            WalletBalanceError::ConfigError(msg) => msg.clone(),
        }
    }
}

/// Parameters for sending a transaction to Bitcoin DA
struct SendToBitcoinDaParams<'a> {
    bitcoin_client: &'a Arc<core_lane::BitcoinRpcClient>,
    bdk_bitcoind_client: Option<Arc<bdk_bitcoind_rpc::bitcoincore_rpc::Client>>,
    network: bitcoin::Network,
    network_str: &'a str,
    electrum_url: Option<&'a str>,
    data_dir: &'a str,
}

pub struct RpcServer {
    state: Arc<Mutex<CoreLaneState>>,
    bitcoin_client: Option<Arc<core_lane::BitcoinRpcClient>>,
    /// For regtest wallet sync only - BDK Emitter requires bitcoincore_rpc::Client
    bdk_bitcoind_client: Option<Arc<bdk_bitcoind_rpc::bitcoincore_rpc::Client>>,
    network: Option<bitcoin::Network>,
    #[allow(dead_code)]
    wallet: Option<String>,
    mnemonic: Option<String>,
    electrum_url: Option<String>,
    data_dir: String,
    core_rpc_url: Option<String>,
    da_feed_address: Option<Address>,
    sequencer_rpc_url: Option<String>,
}

impl RpcServer {
    pub fn with_bitcoin_client(
        state: Arc<Mutex<CoreLaneState>>,
        bitcoin_client: Option<Arc<core_lane::BitcoinRpcClient>>,
        bdk_bitcoind_client: Option<Arc<bdk_bitcoind_rpc::bitcoincore_rpc::Client>>,
        network: Option<bitcoin::Network>,
        config: BitcoinClientConfig,
    ) -> Result<Self, String> {
        // Validate configuration
        config.validate()?;

        // If sequencer is configured, bitcoin client is optional
        // If bitcoin config is provided, bitcoin_client and network should be present
        if config.mnemonic.is_some() && (bitcoin_client.is_none() || network.is_none()) {
            return Err(
                "Bitcoin client and network are required when mnemonic is provided".to_string(),
            );
        }

        Ok(Self {
            state,
            bitcoin_client,
            bdk_bitcoind_client,
            network,
            wallet: config.wallet,
            mnemonic: config.mnemonic,
            electrum_url: config.electrum_url,
            data_dir: config.data_dir,
            core_rpc_url: None,
            da_feed_address: None,
            sequencer_rpc_url: config.sequencer_rpc_url,
        })
    }

    pub fn with_derived(
        state: Arc<Mutex<CoreLaneState>>,
        core_rpc_url: String,
        da_feed_address: Address,
        data_dir: String,
        sequencer_rpc_url: Option<String>,
    ) -> Self {
        Self {
            state,
            bitcoin_client: None,
            bdk_bitcoind_client: None,
            network: None,
            wallet: None,
            mnemonic: None,
            electrum_url: None,
            data_dir,
            core_rpc_url: Some(core_rpc_url),
            da_feed_address: Some(da_feed_address),
            sequencer_rpc_url,
        }
    }

    pub fn router(self) -> Router {
        Router::new()
            // JSON-RPC endpoint (POST)
            .route("/", post(Self::handle_request))
            // Custom REST endpoints for raw data access (GET)
            .route(
                "/get_raw_block/:block_number",
                axum::routing::get(Self::handle_get_raw_block),
            )
            .route(
                "/get_raw_block_delta/:block_number",
                axum::routing::get(Self::handle_get_raw_block_delta),
            )
            .route(
                "/get_latest_block",
                axum::routing::get(Self::handle_get_latest_block),
            )
            .route("/kv/:key", axum::routing::get(Self::handle_kv_get))
            .route("/health", axum::routing::get(Self::handle_health))
            .route(
                "/bitcoin/wallet/balance",
                axum::routing::get(Self::handle_bitcoin_wallet_balance),
            )
            .route("/query", get(Self::handle_query).post(Self::handle_query))
            .route(
                "/query/*path",
                get(Self::handle_query).post(Self::handle_query),
            )
            .with_state(Arc::new(self))
    }

    async fn handle_request(
        axum::extract::State(state): axum::extract::State<Arc<Self>>,
        Json(request): Json<JsonRpcRequest>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        let response = match request.method.as_str() {
            // Account and balance methods
            "eth_getBalance" => Self::handle_get_balance(request, &state).await,
            "eth_getTransactionCount" => Self::handle_get_transaction_count(request, &state).await,
            "eth_getCode" => Self::handle_get_code(request, &state).await,

            // Transaction methods
            "eth_sendTransaction" => Self::handle_send_transaction(request, &state).await,
            "eth_sendRawTransaction" => Self::handle_send_raw_transaction(request, &state).await,
            "eth_getTransactionByHash" => {
                Self::handle_get_transaction_by_hash(request, &state).await
            }
            "eth_getTransactionByBlockHashAndIndex" => {
                Self::handle_get_transaction_by_block_hash_and_index(request, &state).await
            }
            "eth_getTransactionByBlockNumberAndIndex" => {
                Self::handle_get_transaction_by_block_number_and_index(request, &state).await
            }
            "eth_getTransactionReceipt" => {
                Self::handle_get_transaction_receipt(request, &state).await
            }

            // Block methods
            "eth_blockNumber" => Self::handle_block_number(request, &state).await,
            "eth_getBlockByNumber" => Self::handle_get_block_by_number(request, &state).await,
            "eth_getBlockByHash" => Self::handle_get_block_by_hash(request, &state).await,
            "eth_getBlockTransactionCountByNumber" => {
                Self::handle_get_block_transaction_count_by_number(request, &state).await
            }

            // Network and chain methods
            "eth_chainId" => Self::handle_chain_id(request).await,
            "eth_syncing" => Self::handle_syncing(request, &state).await,
            "net_version" => Self::handle_net_version(request).await,
            "net_listening" => Self::handle_net_listening(request).await,
            "net_peerCount" => Self::handle_net_peer_count(request).await,

            // Gas and fee methods
            "eth_gasPrice" => Self::handle_gas_price(request).await,
            "eth_estimateGas" => Self::handle_estimate_gas(request, &state).await,
            "eth_maxPriorityFeePerGas" => {
                Self::handle_max_priority_fee_per_gas(&state, request).await
            }
            "eth_feeHistory" => Self::handle_fee_history(&state, request).await,
            "eth_baseFeePerGas" => Self::handle_base_fee_per_gas(&state, request).await,
            "corelane_sequencerBalance" => Self::handle_sequencer_balance(&state, request).await,
            "corelane_totalBurned" => Self::handle_total_burned(&state, request).await,
            "bitcoin_getWalletBalance" => {
                Self::handle_bitcoin_wallet_balance_rpc(request, &state).await
            }

            // Storage and state methods
            "eth_getStorageAt" => Self::handle_get_storage_at(request, &state).await,
            // KV read via JSON-RPC for applications
            "corelane_getKV" => Self::handle_get_kv_rpc(request, &state).await,
            // Call and execution methods
            "eth_call" => Self::handle_call(request, &state).await,

            // Unsupported methods
            _ => Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("Method not found: {}", request.method),
                }),
                id: request.id,
            })),
        };

        response
    }

    // Account and balance methods
    async fn handle_get_balance(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 2 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let address_str = request.params[0].as_str().ok_or(StatusCode::BAD_REQUEST)?;

        // Parse address (address_from_str handles "0x" prefix)
        let address = address_from_str(address_str).map_err(|_| StatusCode::BAD_REQUEST)?;

        // Get balance from account manager
        let state = state.state.lock().await;
        let balance = state.account_manager.get_balance(address);

        // Convert to hex string (0x-prefixed)
        let balance_hex = format!("0x{:x}", balance);

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(balance_hex)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_get_transaction_count(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 2 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let address_str = request.params[0].as_str().ok_or(StatusCode::BAD_REQUEST)?;

        // Parse address (address_from_str handles "0x" prefix)
        let address = address_from_str(address_str).map_err(|_| StatusCode::BAD_REQUEST)?;

        // Get nonce from account manager
        let state = state.state.lock().await;
        let nonce = state.account_manager.get_nonce(address);

        // Convert to hex string (0x-prefixed)
        let nonce_hex = format!("0x{:x}", nonce);

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(nonce_hex)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_get_code(
        request: JsonRpcRequest,
        _state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 2 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let _address_str = request.params[0].as_str().ok_or(StatusCode::BAD_REQUEST)?;

        // Return code as hex string (0x-prefixed)
        let code_hex = "0x";

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(code_hex)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_get_kv_rpc(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 1 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let key = request.params[0].as_str().ok_or(StatusCode::BAD_REQUEST)?;

        let state_guard = state.state.lock().await;

        // Check applied state
        if let Some(value) = state_guard.account_manager.get_kv(key) {
            let hex_str = format!("0x{}", hex::encode(value));
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(json!(hex_str)),
                error: None,
                id: request.id,
            }));
        }

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(Value::Null),
            error: None,
            id: request.id,
        }))
    }

    // Transaction methods
    async fn handle_send_transaction(
        request: JsonRpcRequest,
        _state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 1 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        // For now, return an error indicating this method is not fully implemented
        // In a full implementation, this would:
        // 1. Parse the transaction request
        // 2. Validate the transaction
        // 3. Execute the transaction
        // 4. Return the transaction hash

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: "eth_sendTransaction not yet implemented".to_string(),
            }),
            id: request.id,
        }))
    }

    async fn handle_send_raw_transaction(
        request: JsonRpcRequest,
        server: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 1 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let raw_tx_hex = match request.params[0].as_str() {
            Some(hex_str) => hex_str.trim_start_matches("0x"),
            None => {
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: "Invalid raw transaction format".to_string(),
                    }),
                    id: request.id,
                }));
            }
        };

        // Validate the hex format
        if hex::decode(raw_tx_hex).is_err() {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid hex format".to_string(),
                }),
                id: request.id,
            }));
        }

        // Check if sequencer RPC URL is configured - forward transaction to sequencer
        if let Some(sequencer_rpc_url) = &server.sequencer_rpc_url {
            match Self::forward_to_sequencer_rpc(raw_tx_hex, sequencer_rpc_url).await {
                Ok(tx_hash_hex) => {
                    info!(
                        sequencer_tx_hash = %tx_hash_hex,
                        "Transaction forwarded to sequencer RPC"
                    );

                    return Ok(JsonResponse::from(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: Some(json!(tx_hash_hex)),
                        error: None,
                        id: request.id,
                    }));
                }
                Err(e) => {
                    return Ok(JsonResponse::from(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32603,
                            message: format!(
                                "Failed to forward transaction to sequencer RPC: {}",
                                e
                            ),
                        }),
                        id: request.id,
                    }));
                }
            }
        }

        if let (Some(core_rpc_url), Some(da_feed_address)) =
            (&server.core_rpc_url, &server.da_feed_address)
        {
            match Self::send_to_core_lane_da(raw_tx_hex, core_rpc_url, *da_feed_address).await {
                Ok(tx_hash_hex) => {
                    info!(
                        core_tx_hash = %tx_hash_hex,
                        "Transaction forwarded to upstream Core Lane RPC"
                    );

                    return Ok(JsonResponse::from(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: Some(json!(tx_hash_hex)),
                        error: None,
                        id: request.id,
                    }));
                }
                Err(e) => {
                    return Ok(JsonResponse::from(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32603,
                            message: format!(
                                "Failed to forward transaction to upstream Core Lane RPC: {}",
                                e
                            ),
                        }),
                        id: request.id,
                    }));
                }
            }
        }

        // Check if Bitcoin client is available (only needed if sequencer is not configured)
        // If sequencer is configured, we've already handled it above, so this should not be reached
        // But we check anyway for safety
        let bitcoin_client = match &server.bitcoin_client {
            Some(client) => client,
            None => {
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32601,
                        message: "Bitcoin client not configured and no sequencer RPC URL provided - cannot send transaction".to_string(),
                    }),
                    id: request.id,
                }));
            }
        };

        // Send transaction to Bitcoin DA
        let mnemonic = server.mnemonic.clone().ok_or_else(|| {
            tracing::error!("Mnemonic not configured for RPC server");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        // Validate network is configured
        let network = server.network.ok_or_else(|| {
            tracing::error!("Network not configured for RPC server");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let network_str = match network {
            bitcoin::Network::Bitcoin => "bitcoin",
            bitcoin::Network::Testnet => "testnet",
            bitcoin::Network::Testnet4 => "testnet4",
            bitcoin::Network::Signet => "signet",
            bitcoin::Network::Regtest => "regtest",
        };
        let electrum_url = server.electrum_url.as_deref();

        let da_params = SendToBitcoinDaParams {
            bitcoin_client,
            bdk_bitcoind_client: server.bdk_bitcoind_client.clone(),
            network,
            network_str,
            electrum_url,
            data_dir: &server.data_dir,
        };
        match Self::send_to_bitcoin_da(raw_tx_hex, &da_params, &mnemonic).await {
            Ok(bitcoin_txid) => {
                // Calculate the Core Lane transaction hash for the response
                use alloy_primitives::keccak256;
                let tx_bytes = hex::decode(raw_tx_hex).unwrap(); // Already validated above
                let tx_hash = keccak256(&tx_bytes);
                let tx_hash_hex = format!("0x{}", hex::encode(tx_hash));

                info!(
                    bitcoin_txid = %bitcoin_txid,
                    core_tx_hash = %tx_hash_hex,
                    "Transaction sent to Bitcoin DA"
                );

                Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: Some(json!(tx_hash_hex)),
                    error: None,
                    id: request.id,
                }))
            }
            Err(e) => Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32603,
                    message: format!("Failed to send to Bitcoin DA: {}", e),
                }),
                id: request.id,
            })),
        }
    }

    async fn send_to_bitcoin_da(
        raw_tx_hex: &str,
        params: &SendToBitcoinDaParams<'_>,
        mnemonic: &str,
    ) -> Result<String, anyhow::Error> {
        let taproot_da = crate::taproot_da::TaprootDA::new(
            params.bitcoin_client.clone(),
            params.bdk_bitcoind_client.clone(),
        );

        taproot_da
            .send_transaction_to_da(
                raw_tx_hex,
                mnemonic,
                params.network,
                params.network_str,
                params.electrum_url,
                params.data_dir,
            )
            .await
    }

    async fn forward_to_sequencer_rpc(
        raw_tx_hex: &str,
        sequencer_rpc_url: &str,
    ) -> Result<String, anyhow::Error> {
        // Create HTTP client
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))?;

        // Prepare the raw transaction hex with 0x prefix
        let tx_hex_with_prefix = if raw_tx_hex.starts_with("0x") {
            raw_tx_hex.to_string()
        } else {
            format!("0x{}", raw_tx_hex)
        };

        // Forward the transaction via JSON-RPC
        let request_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendRawTransaction",
            "params": [tx_hex_with_prefix]
        });

        let response = client
            .post(sequencer_rpc_url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send request to sequencer RPC: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Sequencer RPC returned error status: {}",
                response.status()
            ));
        }

        let json_response: Value = response
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to parse JSON response: {}", e))?;

        // Check for RPC error
        if let Some(error) = json_response.get("error") {
            if !error.is_null() {
                let error_msg = error
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown error");
                return Err(anyhow::anyhow!("Sequencer RPC error: {}", error_msg));
            }
        }

        // Extract transaction hash from result
        let tx_hash = json_response
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or_else(|| anyhow::anyhow!("No result in sequencer RPC response"))?;

        info!(
            sequencer_rpc_url = sequencer_rpc_url,
            tx_hash = tx_hash,
            "Transaction forwarded to sequencer RPC"
        );

        Ok(tx_hash.to_string())
    }

    async fn send_to_core_lane_da(
        raw_tx_hex: &str,
        core_rpc_url: &str,
        da_feed_address: Address,
    ) -> Result<String, anyhow::Error> {
        let tx_bytes =
            hex::decode(raw_tx_hex).map_err(|e| anyhow::anyhow!("Failed to decode hex: {}", e))?;

        let tx_request = TransactionRequest::default()
            .to(da_feed_address)
            .input(Bytes::from(tx_bytes.clone()).into());

        let url = core_rpc_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid core_rpc_url '{}': {}", core_rpc_url, e))?;

        let privkey_hex = std::env::var("CORE_LANE_DA_PRIVATE_KEY")
            .map_err(|e| anyhow::anyhow!("CORE_LANE_DA_PRIVATE_KEY env var not set: {}", e))?;
        let signer = PrivateKeySigner::from_str(&privkey_hex)
            .map_err(|e| anyhow::anyhow!("Invalid CORE_LANE_DA_PRIVATE_KEY: {}", e))?;
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);

        let upstream_hash = provider
            .send_transaction(tx_request)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send to upstream Core Lane RPC: {}", e))?;

        let original_tx_hash = alloy_primitives::keccak256(&tx_bytes);
        let tx_hash_hex = format!("0x{}", hex::encode(original_tx_hash));

        info!(
            upstream_tx = ?upstream_hash,
            original_tx_hash = %tx_hash_hex,
            "Transaction forwarded to upstream Core Lane RPC"
        );

        Ok(tx_hash_hex)
    }

    async fn handle_get_transaction_by_hash(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 1 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let tx_hash = request.params[0].as_str().ok_or(StatusCode::BAD_REQUEST)?;

        // Ensure we have the "0x" prefix for comparison
        let tx_hash = if tx_hash.starts_with("0x") {
            tx_hash.to_string()
        } else {
            format!("0x{}", tx_hash)
        };

        let state = state.state.lock().await;

        // Look for the transaction by calculating hash from raw data
        for (index, stored_tx) in state.account_manager.get_transactions().iter().enumerate() {
            let current_tx_hash = format!(
                "0x{}",
                hex::encode(alloy_primitives::keccak256(&stored_tx.raw_data))
            );

            if current_tx_hash == tx_hash {
                // Found the transaction, extract actual data from TxEnvelope
                let mut result = serde_json::Map::new();
                result.insert("hash".to_string(), json!(current_tx_hash));

                // Extract transaction data based on envelope type
                match &stored_tx.envelope {
                    alloy_consensus::TxEnvelope::Legacy(tx) => {
                        result.insert("type".to_string(), json!("0x0"));
                        result.insert("nonce".to_string(), json!(format!("0x{:x}", tx.tx().nonce)));
                        result.insert(
                            "gasPrice".to_string(),
                            json!(format!("0x{:x}", tx.tx().gas_price)),
                        );
                        result.insert(
                            "gas".to_string(),
                            json!(format!("0x{:x}", tx.tx().gas_limit)),
                        );
                        // Add chainId for EIP-155 transactions
                        if let Some(chain_id) = tx.tx().chain_id {
                            result
                                .insert("chainId".to_string(), json!(format!("0x{:x}", chain_id)));
                        }

                        // Handle 'to' field - it's a TxKind enum
                        let to_address = match tx.tx().to {
                            alloy_primitives::TxKind::Call(addr) => format!("0x{:x}", addr),
                            alloy_primitives::TxKind::Create => "null".to_string(),
                        };
                        result.insert("to".to_string(), json!(to_address));

                        result.insert("value".to_string(), json!(format!("0x{:x}", tx.tx().value)));
                        result.insert(
                            "input".to_string(),
                            json!(format!("0x{}", hex::encode(&tx.tx().input))),
                        );
                        // Calculate proper EIP-155 v value: chain_id * 2 + 35 + parity
                        let v_value = if let Some(chain_id) = tx.tx().chain_id {
                            chain_id * 2 + 35 + if tx.signature().v() { 1 } else { 0 }
                        } else {
                            // Pre-EIP-155: 27 + parity
                            27 + if tx.signature().v() { 1 } else { 0 }
                        };
                        result.insert("v".to_string(), json!(format!("0x{:x}", v_value)));
                        result.insert(
                            "r".to_string(),
                            json!(format!("0x{:x}", tx.signature().r())),
                        );
                        result.insert(
                            "s".to_string(),
                            json!(format!("0x{:x}", tx.signature().s())),
                        );

                        // Try to recover sender address
                        if let Ok(sender) = tx.recover_signer() {
                            result.insert("from".to_string(), json!(format!("0x{:x}", sender)));
                        } else {
                            result.insert(
                                "from".to_string(),
                                json!("0x0000000000000000000000000000000000000000"),
                            );
                        }
                    }
                    alloy_consensus::TxEnvelope::Eip1559(tx) => {
                        result.insert("type".to_string(), json!("0x2"));
                        result.insert(
                            "chainId".to_string(),
                            json!(format!("0x{:x}", tx.tx().chain_id)),
                        );
                        result.insert("nonce".to_string(), json!(format!("0x{:x}", tx.tx().nonce)));
                        result.insert(
                            "maxFeePerGas".to_string(),
                            json!(format!("0x{:x}", tx.tx().max_fee_per_gas)),
                        );
                        result.insert(
                            "maxPriorityFeePerGas".to_string(),
                            json!(format!("0x{:x}", tx.tx().max_priority_fee_per_gas)),
                        );
                        result.insert(
                            "gas".to_string(),
                            json!(format!("0x{:x}", tx.tx().gas_limit)),
                        );

                        // Handle 'to' field - it's a TxKind enum
                        let to_address = match tx.tx().to {
                            alloy_primitives::TxKind::Call(addr) => format!("0x{:x}", addr),
                            alloy_primitives::TxKind::Create => "null".to_string(),
                        };
                        result.insert("to".to_string(), json!(to_address));

                        result.insert("value".to_string(), json!(format!("0x{:x}", tx.tx().value)));
                        result.insert(
                            "input".to_string(),
                            json!(format!("0x{}", hex::encode(&tx.tx().input))),
                        );
                        result.insert(
                            "v".to_string(),
                            json!(format!("0x{:x}", if tx.signature().v() { 1 } else { 0 })),
                        );
                        result.insert(
                            "r".to_string(),
                            json!(format!("0x{:x}", tx.signature().r())),
                        );
                        result.insert(
                            "s".to_string(),
                            json!(format!("0x{:x}", tx.signature().s())),
                        );
                        // Serialize the actual access list
                        let access_list: Vec<_> = tx.tx().access_list.0.iter().map(|item| {
                            json!({
                                "address": format!("0x{:x}", item.address),
                                "storageKeys": item.storage_keys.iter().map(|key| format!("0x{:x}", key)).collect::<Vec<_>>()
                            })
                        }).collect();
                        result.insert("accessList".to_string(), json!(access_list));

                        // Try to recover sender address
                        if let Ok(sender) = tx.recover_signer() {
                            result.insert("from".to_string(), json!(format!("0x{:x}", sender)));
                        } else {
                            result.insert(
                                "from".to_string(),
                                json!("0x0000000000000000000000000000000000000000"),
                            );
                        }
                    }
                    alloy_consensus::TxEnvelope::Eip2930(tx) => {
                        result.insert("type".to_string(), json!("0x1"));
                        result.insert(
                            "chainId".to_string(),
                            json!(format!("0x{:x}", tx.tx().chain_id)),
                        );
                        result.insert("nonce".to_string(), json!(format!("0x{:x}", tx.tx().nonce)));
                        result.insert(
                            "gasPrice".to_string(),
                            json!(format!("0x{:x}", tx.tx().gas_price)),
                        );
                        result.insert(
                            "gas".to_string(),
                            json!(format!("0x{:x}", tx.tx().gas_limit)),
                        );

                        // Handle 'to' field - it's a TxKind enum
                        let to_address = match tx.tx().to {
                            alloy_primitives::TxKind::Call(addr) => format!("0x{:x}", addr),
                            alloy_primitives::TxKind::Create => "null".to_string(),
                        };
                        result.insert("to".to_string(), json!(to_address));

                        result.insert("value".to_string(), json!(format!("0x{:x}", tx.tx().value)));
                        result.insert(
                            "input".to_string(),
                            json!(format!("0x{}", hex::encode(&tx.tx().input))),
                        );
                        result.insert(
                            "v".to_string(),
                            json!(format!("0x{:x}", if tx.signature().v() { 1 } else { 0 })),
                        );
                        result.insert(
                            "r".to_string(),
                            json!(format!("0x{:x}", tx.signature().r())),
                        );
                        result.insert(
                            "s".to_string(),
                            json!(format!("0x{:x}", tx.signature().s())),
                        );
                        // Serialize the actual access list
                        let access_list: Vec<_> = tx.tx().access_list.0.iter().map(|item| {
                            json!({
                                "address": format!("0x{:x}", item.address),
                                "storageKeys": item.storage_keys.iter().map(|key| format!("0x{:x}", key)).collect::<Vec<_>>()
                            })
                        }).collect();
                        result.insert("accessList".to_string(), json!(access_list));

                        // Try to recover sender address
                        if let Ok(sender) = tx.recover_signer() {
                            result.insert("from".to_string(), json!(format!("0x{:x}", sender)));
                        } else {
                            result.insert(
                                "from".to_string(),
                                json!("0x0000000000000000000000000000000000000000"),
                            );
                        }
                    }
                    _ => {
                        // Fallback for other transaction types
                        result.insert("nonce".to_string(), json!("0x0"));
                        result.insert("gasPrice".to_string(), json!("0x3b9aca00"));
                        result.insert("gas".to_string(), json!("0x0"));
                        result.insert("to".to_string(), json!(null));
                        result.insert("value".to_string(), json!("0x0"));
                        result.insert("input".to_string(), json!("0x"));
                        result.insert("v".to_string(), json!("0x0"));
                        result.insert("r".to_string(), json!("0x0"));
                        result.insert("s".to_string(), json!("0x0"));
                        result.insert(
                            "from".to_string(),
                            json!("0x0000000000000000000000000000000000000000"),
                        );
                    }
                }
                if let Some(block) = state.blocks.get(&stored_tx.block_number) {
                    // Add block information
                    result.insert(
                        "blockHash".to_string(),
                        json!(format!("0x{:x}", block.hash)),
                    );
                } else {
                    return Ok(JsonResponse::from(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32603,
                            message: format!(
                                "Internal error: block {} not found (blocks={})",
                                stored_tx.block_number,
                                state.blocks.len()
                            ),
                        }),
                        id: request.id,
                    }));
                }
                result.insert(
                    "blockNumber".to_string(),
                    json!(format!("0x{:x}", stored_tx.block_number)),
                );
                result.insert(
                    "transactionIndex".to_string(),
                    json!(format!("0x{:x}", index)),
                );

                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: Some(json!(result)),
                    error: None,
                    id: request.id,
                }));
            }
        }

        // Transaction not found
        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(null)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_get_transaction_receipt(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 1 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let tx_hash = request.params[0].as_str().ok_or(StatusCode::BAD_REQUEST)?;

        // Remove "0x" prefix if present
        let tx_hash = tx_hash.trim_start_matches("0x");

        let state = state.state.lock().await;

        // Look for the transaction receipt
        if let Some(receipt) = state.account_manager.get_receipt(&format!("0x{}", tx_hash)) {
            // Found the receipt, return its details
            let mut result = serde_json::Map::new();
            result.insert(
                "transactionHash".to_string(),
                json!(receipt.transaction_hash),
            );
            result.insert(
                "blockNumber".to_string(),
                json!(format!("0x{:x}", receipt.block_number)),
            );
            result.insert("type".to_string(), json!(receipt.tx_type));

            if let Some(block) = state.blocks.get(&receipt.block_number) {
                let block_hash = block.hash;
                result.insert(
                    "blockHash".to_string(),
                    json!(format!("0x{:x}", block_hash)),
                );
            } else {
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: "Internal error: Block not found".to_string(),
                    }),
                    id: request.id,
                }));
            }
            result.insert(
                "transactionIndex".to_string(),
                json!(format!("0x{:x}", receipt.transaction_index)),
            );
            result.insert("from".to_string(), json!(receipt.from));
            result.insert("to".to_string(), json!(receipt.to));
            result.insert(
                "cumulativeGasUsed".to_string(),
                json!(receipt.cumulative_gas_used),
            );
            result.insert("gasUsed".to_string(), json!(receipt.gas_used));
            result.insert(
                "contractAddress".to_string(),
                json!(receipt.contract_address),
            );
            result.insert("logs".to_string(), json!(receipt.logs));
            result.insert("logsBloom".to_string(), json!(receipt.logs_bloom));
            result.insert("status".to_string(), json!(receipt.status));
            result.insert(
                "effectiveGasPrice".to_string(),
                json!(receipt.effective_gas_price),
            );

            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(json!(result)),
                error: None,
                id: request.id,
            }));
        }

        // Receipt not found
        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(null)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_get_transaction_by_block_hash_and_index(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 2 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let block_hash = request.params[0].as_str().ok_or(StatusCode::BAD_REQUEST)?;
        let index = request.params[1].as_str().ok_or(StatusCode::BAD_REQUEST)?;

        // Parse block hash
        let block_hash = if block_hash.starts_with("0x") {
            block_hash.to_string()
        } else {
            format!("0x{}", block_hash)
        };

        // Parse transaction index
        let index = index.trim_start_matches("0x");
        let tx_index = u64::from_str_radix(index, 16).map_err(|_| StatusCode::BAD_REQUEST)?;

        let state = state.state.lock().await;

        // Find block by hash
        if let Some(&block_number) = state
            .block_hashes
            .get(&B256::from_str(&block_hash).unwrap_or_default())
        {
            if let Some(block) = state.blocks.get(&block_number) {
                // Get transaction hash from block
                if let Some(tx_hash) = block.transactions.get(tx_index as usize) {
                    // Find the actual transaction data
                    for stored_tx in state.account_manager.get_transactions().iter() {
                        let current_tx_hash = format!(
                            "0x{}",
                            hex::encode(alloy_primitives::keccak256(&stored_tx.raw_data))
                        );

                        if &current_tx_hash == tx_hash {
                            // Found the transaction, return its details
                            let mut result = serde_json::Map::new();
                            result.insert("hash".to_string(), json!(current_tx_hash));

                            // Extract transaction data based on envelope type
                            match &stored_tx.envelope {
                                alloy_consensus::TxEnvelope::Legacy(tx) => {
                                    result.insert("type".to_string(), json!("0x0"));
                                    result.insert(
                                        "nonce".to_string(),
                                        json!(format!("0x{:x}", tx.tx().nonce)),
                                    );
                                    result.insert(
                                        "gasPrice".to_string(),
                                        json!(format!("0x{:x}", tx.tx().gas_price)),
                                    );
                                    result.insert(
                                        "gas".to_string(),
                                        json!(format!("0x{:x}", tx.tx().gas_limit)),
                                    );
                                    // Add chainId for EIP-155 transactions
                                    if let Some(chain_id) = tx.tx().chain_id {
                                        result.insert(
                                            "chainId".to_string(),
                                            json!(format!("0x{:x}", chain_id)),
                                        );
                                    }

                                    // Handle 'to' field - it's a TxKind enum
                                    let to_address = match tx.tx().to {
                                        alloy_primitives::TxKind::Call(addr) => {
                                            format!("0x{:x}", addr)
                                        }
                                        alloy_primitives::TxKind::Create => "null".to_string(),
                                    };
                                    result.insert("to".to_string(), json!(to_address));

                                    result.insert(
                                        "value".to_string(),
                                        json!(format!("0x{:x}", tx.tx().value)),
                                    );
                                    result.insert(
                                        "input".to_string(),
                                        json!(format!("0x{}", hex::encode(&tx.tx().input))),
                                    );
                                    // Calculate proper EIP-155 v value: chain_id * 2 + 35 + parity
                                    let v_value = if let Some(chain_id) = tx.tx().chain_id {
                                        chain_id * 2 + 35 + if tx.signature().v() { 1 } else { 0 }
                                    } else {
                                        // Pre-EIP-155: 27 + parity
                                        27 + if tx.signature().v() { 1 } else { 0 }
                                    };
                                    result
                                        .insert("v".to_string(), json!(format!("0x{:x}", v_value)));
                                    result.insert(
                                        "r".to_string(),
                                        json!(format!("0x{:x}", tx.signature().r())),
                                    );
                                    result.insert(
                                        "s".to_string(),
                                        json!(format!("0x{:x}", tx.signature().s())),
                                    );

                                    // Try to recover sender address
                                    if let Ok(sender) = tx.recover_signer() {
                                        result.insert(
                                            "from".to_string(),
                                            json!(format!("0x{:x}", sender)),
                                        );
                                    } else {
                                        result.insert(
                                            "from".to_string(),
                                            json!("0x0000000000000000000000000000000000000000"),
                                        );
                                    }
                                }
                                alloy_consensus::TxEnvelope::Eip1559(tx) => {
                                    result.insert("type".to_string(), json!("0x2"));
                                    result.insert(
                                        "chainId".to_string(),
                                        json!(format!("0x{:x}", tx.tx().chain_id)),
                                    );
                                    result.insert(
                                        "nonce".to_string(),
                                        json!(format!("0x{:x}", tx.tx().nonce)),
                                    );
                                    result.insert(
                                        "maxFeePerGas".to_string(),
                                        json!(format!("0x{:x}", tx.tx().max_fee_per_gas)),
                                    );
                                    result.insert(
                                        "maxPriorityFeePerGas".to_string(),
                                        json!(format!("0x{:x}", tx.tx().max_priority_fee_per_gas)),
                                    );
                                    result.insert(
                                        "gas".to_string(),
                                        json!(format!("0x{:x}", tx.tx().gas_limit)),
                                    );

                                    // Handle 'to' field - it's a TxKind enum
                                    let to_address = match tx.tx().to {
                                        alloy_primitives::TxKind::Call(addr) => {
                                            format!("0x{:x}", addr)
                                        }
                                        alloy_primitives::TxKind::Create => "null".to_string(),
                                    };
                                    result.insert("to".to_string(), json!(to_address));

                                    result.insert(
                                        "value".to_string(),
                                        json!(format!("0x{:x}", tx.tx().value)),
                                    );
                                    result.insert(
                                        "input".to_string(),
                                        json!(format!("0x{}", hex::encode(&tx.tx().input))),
                                    );
                                    result.insert(
                                        "v".to_string(),
                                        json!(format!(
                                            "0x{:x}",
                                            if tx.signature().v() { 1 } else { 0 }
                                        )),
                                    );
                                    result.insert(
                                        "r".to_string(),
                                        json!(format!("0x{:x}", tx.signature().r())),
                                    );
                                    result.insert(
                                        "s".to_string(),
                                        json!(format!("0x{:x}", tx.signature().s())),
                                    );
                                    // Serialize the actual access list
                                    let access_list: Vec<_> = tx.tx().access_list.0.iter().map(|item| {
                                        json!({
                                            "address": format!("0x{:x}", item.address),
                                            "storageKeys": item.storage_keys.iter().map(|key| format!("0x{:x}", key)).collect::<Vec<_>>()
                                        })
                                    }).collect();
                                    result.insert("accessList".to_string(), json!(access_list));

                                    // Try to recover sender address
                                    if let Ok(sender) = tx.recover_signer() {
                                        result.insert(
                                            "from".to_string(),
                                            json!(format!("0x{:x}", sender)),
                                        );
                                    } else {
                                        result.insert(
                                            "from".to_string(),
                                            json!("0x0000000000000000000000000000000000000000"),
                                        );
                                    }
                                }
                                alloy_consensus::TxEnvelope::Eip2930(tx) => {
                                    result.insert("type".to_string(), json!("0x1"));
                                    result.insert(
                                        "chainId".to_string(),
                                        json!(format!("0x{:x}", tx.tx().chain_id)),
                                    );
                                    result.insert(
                                        "nonce".to_string(),
                                        json!(format!("0x{:x}", tx.tx().nonce)),
                                    );
                                    result.insert(
                                        "gasPrice".to_string(),
                                        json!(format!("0x{:x}", tx.tx().gas_price)),
                                    );
                                    result.insert(
                                        "gas".to_string(),
                                        json!(format!("0x{:x}", tx.tx().gas_limit)),
                                    );

                                    // Handle 'to' field - it's a TxKind enum
                                    let to_address = match tx.tx().to {
                                        alloy_primitives::TxKind::Call(addr) => {
                                            format!("0x{:x}", addr)
                                        }
                                        alloy_primitives::TxKind::Create => "null".to_string(),
                                    };
                                    result.insert("to".to_string(), json!(to_address));

                                    result.insert(
                                        "value".to_string(),
                                        json!(format!("0x{:x}", tx.tx().value)),
                                    );
                                    result.insert(
                                        "input".to_string(),
                                        json!(format!("0x{}", hex::encode(&tx.tx().input))),
                                    );
                                    result.insert(
                                        "v".to_string(),
                                        json!(format!(
                                            "0x{:x}",
                                            if tx.signature().v() { 1 } else { 0 }
                                        )),
                                    );
                                    result.insert(
                                        "r".to_string(),
                                        json!(format!("0x{:x}", tx.signature().r())),
                                    );
                                    result.insert(
                                        "s".to_string(),
                                        json!(format!("0x{:x}", tx.signature().s())),
                                    );
                                    // Serialize the actual access list
                                    let access_list: Vec<_> = tx.tx().access_list.0.iter().map(|item| {
                                        json!({
                                            "address": format!("0x{:x}", item.address),
                                            "storageKeys": item.storage_keys.iter().map(|key| format!("0x{:x}", key)).collect::<Vec<_>>()
                                        })
                                    }).collect();
                                    result.insert("accessList".to_string(), json!(access_list));

                                    // Try to recover sender address
                                    if let Ok(sender) = tx.recover_signer() {
                                        result.insert(
                                            "from".to_string(),
                                            json!(format!("0x{:x}", sender)),
                                        );
                                    } else {
                                        result.insert(
                                            "from".to_string(),
                                            json!("0x0000000000000000000000000000000000000000"),
                                        );
                                    }
                                }
                                _ => {
                                    // Fallback for other transaction types
                                    result.insert("nonce".to_string(), json!("0x0"));
                                    result.insert("gasPrice".to_string(), json!("0x3b9aca00"));
                                    result.insert("gas".to_string(), json!("0x0"));
                                    result.insert("to".to_string(), json!(null));
                                    result.insert("value".to_string(), json!("0x0"));
                                    result.insert("input".to_string(), json!("0x"));
                                    result.insert("v".to_string(), json!("0x0"));
                                    result.insert("r".to_string(), json!("0x0"));
                                    result.insert("s".to_string(), json!("0x0"));
                                    result.insert(
                                        "from".to_string(),
                                        json!("0x0000000000000000000000000000000000000000"),
                                    );
                                }
                            }

                            // Add block information
                            result.insert("blockHash".to_string(), json!(block_hash));
                            result.insert(
                                "blockNumber".to_string(),
                                json!(format!("0x{:x}", block.number)),
                            );
                            result.insert(
                                "transactionIndex".to_string(),
                                json!(format!("0x{:x}", tx_index)),
                            );

                            return Ok(JsonResponse::from(JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                result: Some(json!(result)),
                                error: None,
                                id: request.id,
                            }));
                        }
                    }
                }
            }
        }

        // Transaction not found
        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(null)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_get_transaction_by_block_number_and_index(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 2 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let block_id = request.params[0].as_str().ok_or(StatusCode::BAD_REQUEST)?;
        let index = request.params[1].as_str().ok_or(StatusCode::BAD_REQUEST)?;

        // Parse block number
        let block_number = if block_id == "latest" {
            // Get latest block number
            let state_guard = state.state.lock().await;
            state_guard.blocks.keys().max().copied().unwrap_or(0)
        } else if block_id == "earliest" {
            0 // Genesis block
        } else if block_id == "pending" {
            // Return null for pending (no pending blocks in Core Lane)
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(json!(null)),
                error: None,
                id: request.id,
            }));
        } else {
            // Parse hex number
            let block_id = block_id.trim_start_matches("0x");
            u64::from_str_radix(block_id, 16).map_err(|_| StatusCode::BAD_REQUEST)?
        };

        // Parse transaction index
        let index = index.trim_start_matches("0x");
        let tx_index = u64::from_str_radix(index, 16).map_err(|_| StatusCode::BAD_REQUEST)?;

        let state = state.state.lock().await;

        // Get block from state
        if let Some(block) = state.blocks.get(&block_number) {
            // Get transaction hash from block
            if let Some(tx_hash) = block.transactions.get(tx_index as usize) {
                // Find the actual transaction data
                for stored_tx in state.account_manager.get_transactions().iter() {
                    let current_tx_hash = format!(
                        "0x{}",
                        hex::encode(alloy_primitives::keccak256(&stored_tx.raw_data))
                    );

                    if &current_tx_hash == tx_hash {
                        // Found the transaction, return its details
                        let mut result = serde_json::Map::new();
                        result.insert("hash".to_string(), json!(current_tx_hash));

                        // Extract transaction data based on envelope type
                        match &stored_tx.envelope {
                            alloy_consensus::TxEnvelope::Legacy(tx) => {
                                result.insert("type".to_string(), json!("0x0"));
                                result.insert(
                                    "nonce".to_string(),
                                    json!(format!("0x{:x}", tx.tx().nonce)),
                                );
                                result.insert(
                                    "gasPrice".to_string(),
                                    json!(format!("0x{:x}", tx.tx().gas_price)),
                                );
                                result.insert(
                                    "gas".to_string(),
                                    json!(format!("0x{:x}", tx.tx().gas_limit)),
                                );
                                // Add chainId for EIP-155 transactions
                                if let Some(chain_id) = tx.tx().chain_id {
                                    result.insert(
                                        "chainId".to_string(),
                                        json!(format!("0x{:x}", chain_id)),
                                    );
                                }

                                // Handle 'to' field - it's a TxKind enum
                                let to_address = match tx.tx().to {
                                    alloy_primitives::TxKind::Call(addr) => format!("0x{:x}", addr),
                                    alloy_primitives::TxKind::Create => "null".to_string(),
                                };
                                result.insert("to".to_string(), json!(to_address));

                                result.insert(
                                    "value".to_string(),
                                    json!(format!("0x{:x}", tx.tx().value)),
                                );
                                result.insert(
                                    "input".to_string(),
                                    json!(format!("0x{}", hex::encode(&tx.tx().input))),
                                );
                                // Calculate proper EIP-155 v value: chain_id * 2 + 35 + parity
                                let v_value = if let Some(chain_id) = tx.tx().chain_id {
                                    chain_id * 2 + 35 + if tx.signature().v() { 1 } else { 0 }
                                } else {
                                    // Pre-EIP-155: 27 + parity
                                    27 + if tx.signature().v() { 1 } else { 0 }
                                };
                                result.insert("v".to_string(), json!(format!("0x{:x}", v_value)));
                                result.insert(
                                    "r".to_string(),
                                    json!(format!("0x{:x}", tx.signature().r())),
                                );
                                result.insert(
                                    "s".to_string(),
                                    json!(format!("0x{:x}", tx.signature().s())),
                                );

                                // Try to recover sender address
                                if let Ok(sender) = tx.recover_signer() {
                                    result.insert(
                                        "from".to_string(),
                                        json!(format!("0x{:x}", sender)),
                                    );
                                } else {
                                    result.insert(
                                        "from".to_string(),
                                        json!("0x0000000000000000000000000000000000000000"),
                                    );
                                }
                            }
                            alloy_consensus::TxEnvelope::Eip1559(tx) => {
                                result.insert("type".to_string(), json!("0x2"));
                                result.insert(
                                    "chainId".to_string(),
                                    json!(format!("0x{:x}", tx.tx().chain_id)),
                                );
                                result.insert(
                                    "nonce".to_string(),
                                    json!(format!("0x{:x}", tx.tx().nonce)),
                                );
                                result.insert(
                                    "maxFeePerGas".to_string(),
                                    json!(format!("0x{:x}", tx.tx().max_fee_per_gas)),
                                );
                                result.insert(
                                    "maxPriorityFeePerGas".to_string(),
                                    json!(format!("0x{:x}", tx.tx().max_priority_fee_per_gas)),
                                );
                                result.insert(
                                    "gas".to_string(),
                                    json!(format!("0x{:x}", tx.tx().gas_limit)),
                                );

                                // Handle 'to' field - it's a TxKind enum
                                let to_address = match tx.tx().to {
                                    alloy_primitives::TxKind::Call(addr) => format!("0x{:x}", addr),
                                    alloy_primitives::TxKind::Create => "null".to_string(),
                                };
                                result.insert("to".to_string(), json!(to_address));

                                result.insert(
                                    "value".to_string(),
                                    json!(format!("0x{:x}", tx.tx().value)),
                                );
                                result.insert(
                                    "input".to_string(),
                                    json!(format!("0x{}", hex::encode(&tx.tx().input))),
                                );
                                result.insert(
                                    "v".to_string(),
                                    json!(format!(
                                        "0x{:x}",
                                        if tx.signature().v() { 1 } else { 0 }
                                    )),
                                );
                                result.insert(
                                    "r".to_string(),
                                    json!(format!("0x{:x}", tx.signature().r())),
                                );
                                result.insert(
                                    "s".to_string(),
                                    json!(format!("0x{:x}", tx.signature().s())),
                                );
                                // Serialize the actual access list
                                let access_list: Vec<_> = tx.tx().access_list.0.iter().map(|item| {
                                    json!({
                                        "address": format!("0x{:x}", item.address),
                                        "storageKeys": item.storage_keys.iter().map(|key| format!("0x{:x}", key)).collect::<Vec<_>>()
                                    })
                                }).collect();
                                result.insert("accessList".to_string(), json!(access_list));

                                // Try to recover sender address
                                if let Ok(sender) = tx.recover_signer() {
                                    result.insert(
                                        "from".to_string(),
                                        json!(format!("0x{:x}", sender)),
                                    );
                                } else {
                                    result.insert(
                                        "from".to_string(),
                                        json!("0x0000000000000000000000000000000000000000"),
                                    );
                                }
                            }
                            alloy_consensus::TxEnvelope::Eip2930(tx) => {
                                result.insert("type".to_string(), json!("0x1"));
                                result.insert(
                                    "chainId".to_string(),
                                    json!(format!("0x{:x}", tx.tx().chain_id)),
                                );
                                result.insert(
                                    "nonce".to_string(),
                                    json!(format!("0x{:x}", tx.tx().nonce)),
                                );
                                result.insert(
                                    "gasPrice".to_string(),
                                    json!(format!("0x{:x}", tx.tx().gas_price)),
                                );
                                result.insert(
                                    "gas".to_string(),
                                    json!(format!("0x{:x}", tx.tx().gas_limit)),
                                );

                                // Handle 'to' field - it's a TxKind enum
                                let to_address = match tx.tx().to {
                                    alloy_primitives::TxKind::Call(addr) => format!("0x{:x}", addr),
                                    alloy_primitives::TxKind::Create => "null".to_string(),
                                };
                                result.insert("to".to_string(), json!(to_address));

                                result.insert(
                                    "value".to_string(),
                                    json!(format!("0x{:x}", tx.tx().value)),
                                );
                                result.insert(
                                    "input".to_string(),
                                    json!(format!("0x{}", hex::encode(&tx.tx().input))),
                                );
                                result.insert(
                                    "v".to_string(),
                                    json!(format!(
                                        "0x{:x}",
                                        if tx.signature().v() { 1 } else { 0 }
                                    )),
                                );
                                result.insert(
                                    "r".to_string(),
                                    json!(format!("0x{:x}", tx.signature().r())),
                                );
                                result.insert(
                                    "s".to_string(),
                                    json!(format!("0x{:x}", tx.signature().s())),
                                );
                                // Serialize the actual access list
                                let access_list: Vec<_> = tx.tx().access_list.0.iter().map(|item| {
                                    json!({
                                        "address": format!("0x{:x}", item.address),
                                        "storageKeys": item.storage_keys.iter().map(|key| format!("0x{:x}", key)).collect::<Vec<_>>()
                                    })
                                }).collect();
                                result.insert("accessList".to_string(), json!(access_list));

                                // Try to recover sender address
                                if let Ok(sender) = tx.recover_signer() {
                                    result.insert(
                                        "from".to_string(),
                                        json!(format!("0x{:x}", sender)),
                                    );
                                } else {
                                    result.insert(
                                        "from".to_string(),
                                        json!("0x0000000000000000000000000000000000000000"),
                                    );
                                }
                            }
                            _ => {
                                // Unsupported transaction type - return JSON-RPC error
                                return Ok(JsonResponse::from(JsonRpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    result: None,
                                    error: Some(JsonRpcError {
                                        code: -32602,
                                        message: "Unsupported transaction type".to_string(),
                                    }),
                                    id: request.id,
                                }));
                            }
                        }

                        // Add block information
                        result.insert(
                            "blockHash".to_string(),
                            json!(format!("0x{:x}", block.hash)),
                        );
                        result.insert(
                            "blockNumber".to_string(),
                            json!(format!("0x{:x}", block.number)),
                        );
                        result.insert(
                            "transactionIndex".to_string(),
                            json!(format!("0x{:x}", tx_index)),
                        );

                        return Ok(JsonResponse::from(JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: Some(json!(result)),
                            error: None,
                            id: request.id,
                        }));
                    }
                }
            }
        }

        // Transaction not found
        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(null)),
            error: None,
            id: request.id,
        }))
    }

    // Block methods
    async fn handle_block_number(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        // Return the latest Core Lane block number
        let state = state.state.lock().await;
        let block_number = state.blocks.keys().max().copied().unwrap_or(0);
        let block_number_hex = format!("0x{:x}", block_number);

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(block_number_hex)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_get_block_by_number(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 2 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let block_id = request.params[0].as_str().ok_or(StatusCode::BAD_REQUEST)?;
        let full = request.params[1].as_bool().unwrap_or(false);

        // Parse block number
        let block_number = if block_id == "latest" {
            // Get latest block number
            let state_guard = state.state.lock().await;
            state_guard.blocks.keys().max().copied().unwrap_or(0)
        } else if block_id == "earliest" {
            0 // Genesis block
        } else if block_id == "pending" {
            // Return null for pending (no pending blocks in Core Lane)
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(json!(null)),
                error: None,
                id: request.id,
            }));
        } else {
            // Parse hex number
            let block_id = block_id.trim_start_matches("0x");
            u64::from_str_radix(block_id, 16).map_err(|_| StatusCode::BAD_REQUEST)?
        };

        // Get block from state
        let state_guard = state.state.lock().await;
        if let Some(block) = state_guard.blocks.get(&block_number) {
            Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(block.to_json(full)),
                error: None,
                id: request.id,
            }))
        } else {
            // Block not found
            Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(json!(null)),
                error: None,
                id: request.id,
            }))
        }
    }

    async fn handle_get_block_by_hash(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 2 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let block_hash_str = request.params[0].as_str().ok_or(StatusCode::BAD_REQUEST)?;
        let full = request.params[1].as_bool().unwrap_or(false);

        // Parse block hash
        let block_hash_str = block_hash_str.trim_start_matches("0x");
        let block_hash_bytes = hex::decode(block_hash_str).map_err(|_| StatusCode::BAD_REQUEST)?;

        if block_hash_bytes.len() != 32 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid block hash length".to_string(),
                }),
                id: request.id,
            }));
        }

        let block_hash = alloy_primitives::B256::from_slice(&block_hash_bytes);

        // Get block from state
        let state_guard = state.state.lock().await;
        if let Some(&block_number) = state_guard.block_hashes.get(&block_hash) {
            if let Some(block) = state_guard.blocks.get(&block_number) {
                Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: Some(block.to_json(full)),
                    error: None,
                    id: request.id,
                }))
            } else {
                Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: Some(json!(null)),
                    error: None,
                    id: request.id,
                }))
            }
        } else {
            // Block not found
            Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(json!(null)),
                error: None,
                id: request.id,
            }))
        }
    }

    async fn handle_get_block_transaction_count_by_number(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 1 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let block_id = request.params[0].as_str().ok_or(StatusCode::BAD_REQUEST)?;

        // Parse block number
        let block_number = if block_id == "latest" {
            // Get latest block number
            let state_guard = state.state.lock().await;
            state_guard.blocks.keys().max().copied().unwrap_or(0)
        } else if block_id == "earliest" {
            0 // Genesis block
        } else if block_id == "pending" {
            // Return 0 for pending (no pending blocks in Core Lane)
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(json!("0x0")),
                error: None,
                id: request.id,
            }));
        } else {
            // Parse hex number
            let block_id = block_id.trim_start_matches("0x");
            u64::from_str_radix(block_id, 16).map_err(|_| StatusCode::BAD_REQUEST)?
        };

        // Get block from state
        let state_guard = state.state.lock().await;
        if let Some(block) = state_guard.blocks.get(&block_number) {
            Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(json!(format!("0x{:x}", block.transaction_count))),
                error: None,
                id: request.id,
            }))
        } else {
            // Block not found
            Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(json!("0x0")),
                error: None,
                id: request.id,
            }))
        }
    }

    // Network and chain methods
    async fn handle_chain_id(
        request: JsonRpcRequest,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        let chain_id = "0x4c616e42";

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(chain_id)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_syncing(
        request: JsonRpcRequest,
        server: &Arc<RpcServer>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        // Get bitcoin client from server
        let bitcoin_client = match &server.bitcoin_client {
            Some(client) => client.clone(),
            None => {
                // If no bitcoin client, we can't determine syncing status
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: Some(json!(false)),
                    error: None,
                    id: request.id,
                }));
            }
        };

        // Get current Bitcoin tip (use trait to get u64, not corepc's GetBlockCount)
        // Run blocking RPC off the async runtime
        let bitcoin_tip = match tokio::task::spawn_blocking({
            let client = bitcoin_client.clone();
            move || {
                core_lane::bitcoin_rpc_client::BitcoinRpcReadClient::get_block_count(
                    client.as_ref(),
                )
            }
        })
        .await
        {
            Ok(Ok(tip)) => tip,
            Ok(Err(e)) => {
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32603,
                        message: format!("Failed to get Bitcoin block count: {}", e),
                    }),
                    id: request.id,
                }));
            }
            Err(e) => {
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32603,
                        message: format!("Blocking task failed: {}", e),
                    }),
                    id: request.id,
                }));
            }
        };

        // Get last processed Bitcoin height and current Core Lane block number
        let state_guard = server.state.lock().await;
        let last_processed_bitcoin = state_guard.last_processed_bitcoin_height;
        let current_core_lane_block = state_guard.blocks.keys().max().copied().unwrap_or(0);
        drop(state_guard);

        match last_processed_bitcoin {
            None => {
                // Haven't processed any blocks yet - definitely syncing
                Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: Some(json!({
                        "startingBlock": "0x0",
                        "currentBlock": "0x0",
                        "highestBlock": "0x0",
                    })),
                    error: None,
                    id: request.id,
                }))
            }
            Some(current_bitcoin_height) => {
                // Consider synced if we're within 1 block of the Bitcoin tip
                // (allows for network propagation delay)
                if bitcoin_tip <= current_bitcoin_height
                    || bitcoin_tip - current_bitcoin_height <= 1
                {
                    // Synced
                    Ok(JsonResponse::from(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: Some(json!(false)),
                        error: None,
                        id: request.id,
                    }))
                } else {
                    // Still syncing - estimate the highest Core Lane block
                    // We can't know the exact highest block until we sync,
                    // but we can estimate based on the difference
                    let blocks_behind = bitcoin_tip - current_bitcoin_height;
                    let estimated_highest = current_core_lane_block + blocks_behind;

                    Ok(JsonResponse::from(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: Some(json!({
                            "startingBlock": "0x0",
                            "currentBlock": format!("0x{:x}", current_core_lane_block),
                            "highestBlock": format!("0x{:x}", estimated_highest),
                        })),
                        error: None,
                        id: request.id,
                    }))
                }
            }
        }
    }

    async fn handle_net_version(
        request: JsonRpcRequest,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        let net_version = "1281453634";

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(net_version)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_net_listening(
        request: JsonRpcRequest,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        // Always return true for now
        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(true)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_net_peer_count(
        request: JsonRpcRequest,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        // Return 0 peers for now (no P2P networking yet)
        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!("0x0")),
            error: None,
            id: request.id,
        }))
    }

    // Gas and fee methods
    async fn handle_gas_price(
        request: JsonRpcRequest,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        // Return a reasonable gas price (1 Gwei = 1000000000 wei)
        let gas_price = U256::from(214285714u64);
        let gas_price = format!("0x{}", hex::encode(gas_price.to_be_bytes_vec()));

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(gas_price)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_estimate_gas(
        request: JsonRpcRequest,
        _state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.is_empty() || request.params.len() > 2 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        // Validate first param is a call object
        if !request.params[0].is_object() {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params: expected call object".to_string(),
                }),
                id: request.id,
            }));
        }

        // For now, return a default gas estimate
        let gas_estimate = "0x5208"; // 21000 gas (basic transfer)

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(gas_estimate)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_max_priority_fee_per_gas(
        state: &Arc<Self>,
        request: JsonRpcRequest,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        // Get current base fee to suggest a reasonable priority fee
        let state = state.state.lock().await;
        let current_base_fee = state.eip1559_fee_manager.current_base_fee();

        // Suggest priority fee as 10% of current base fee, minimum 0.1 Gwei
        let suggested_priority_fee = std::cmp::max(
            current_base_fee / U256::from(10u64), // 10% of base fee
            U256::from(100_000_000u64),           // 0.1 Gwei minimum
        );

        let priority_fee = format!("0x{:x}", suggested_priority_fee);

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(priority_fee)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_fee_history(
        state: &Arc<Self>,
        request: JsonRpcRequest,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 3 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        // Parse block count from hex string or number, rejecting invalid inputs
        let block_count = match &request.params[0] {
            Value::String(s) => {
                let s = s.trim_start_matches("0x");
                match u64::from_str_radix(s, 16) {
                    Ok(count) => count,
                    Err(_) => {
                        return Ok(JsonResponse::from(JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32602,
                                message: "Invalid params: block count must be a valid hex string"
                                    .to_string(),
                            }),
                            id: request.id,
                        }));
                    }
                }
            }
            Value::Number(n) => match n.as_u64() {
                Some(count) => count,
                None => {
                    return Ok(JsonResponse::from(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32602,
                            message: "Invalid params: block count must be a valid integer"
                                .to_string(),
                        }),
                        id: request.id,
                    }));
                }
            },
            _ => {
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: "Invalid params: block count must be a hex string or number"
                            .to_string(),
                    }),
                    id: request.id,
                }));
            }
        };

        // Validate block count is not zero
        if block_count == 0 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params: block count must be greater than zero".to_string(),
                }),
                id: request.id,
            }));
        };

        // Parse newest block parameter (may be "latest"/"pending", a hex string, or a number)
        // We parse the caller's requested newest block first without holding the main lock,
        // then take a short-lived lock to read the highest available block and clamp to it.
        let parsed_newest: Option<u64> = match &request.params[1] {
            Value::String(s) if s == "latest" || s == "pending" => None,
            Value::String(s) => {
                let s = s.trim_start_matches("0x");
                u64::from_str_radix(s, 16).ok()
            }
            Value::Number(n) => n.as_u64(),
            _ => None,
        };

        // Short lock to determine the highest available block, then clamp the parsed value to it.
        let newest_block = {
            let state_guard = state.state.lock().await;
            // highest block number present in the map (keys are block numbers)
            let highest_block = state_guard.blocks.keys().max().copied().unwrap_or(0);
            match parsed_newest {
                Some(n) => std::cmp::min(n, highest_block),
                None => highest_block,
            }
        };

        // Parse reward percentiles - must be between 0-100, sorted ascending
        let reward_percentiles = match &request.params[2] {
            Value::Array(arr) => {
                let mut percentiles: Vec<f64> = arr
                    .iter()
                    .filter_map(|v| v.as_f64())
                    .filter(|&p| (0.0..=100.0).contains(&p))
                    .collect();
                percentiles.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                percentiles
            }
            _ => vec![], // If not provided or invalid, return empty array
        };

        // Get state to access EIP-1559 fee manager
        let state = state.state.lock().await;

        // Helper function to calculate percentiles from a sorted array
        let calculate_percentile = |sorted_values: &[U256], percentile: f64| -> U256 {
            if sorted_values.is_empty() {
                return U256::ZERO;
            }
            let index = (percentile / 100.0 * (sorted_values.len() - 1) as f64).round() as usize;
            sorted_values[index.min(sorted_values.len() - 1)]
        };

        // Calculate block range using saturating subtraction to handle genesis block and prevent underflow
        let start_block = newest_block.saturating_sub(block_count.saturating_sub(1));
        let end_block = newest_block;

        // Get base fee history from EIP-1559 fee manager
        let _base_fee_history = state
            .eip1559_fee_manager
            .get_base_fee_history(start_block, end_block);

        // Build base fee array
        let mut base_fees = Vec::new();
        let mut gas_used_ratios = Vec::new();
        let mut rewards = Vec::new();

        for block_num in start_block..=end_block {
            if let Some(base_fee) = state.eip1559_fee_manager.get_base_fee_for_block(block_num) {
                base_fees.push(format!("0x{:x}", base_fee));

                // Get gas used ratio for this block
                if let Some(block) = state.blocks.get(&block_num) {
                    let gas_used_ratio =
                        state.eip1559_fee_manager.get_gas_used_ratio(block.gas_used);
                    gas_used_ratios.push(gas_used_ratio);
                } else {
                    gas_used_ratios.push(0.5); // Default ratio
                }

                // Calculate reward percentiles for this block
                if !reward_percentiles.is_empty() {
                    let block_rewards = if let Some(block) = state.blocks.get(&block_num) {
                        // Collect priority fees from all transactions in the block
                        let mut priority_fees: Vec<U256> = Vec::new();
                        for tx_hash in &block.transactions {
                            if let Some(tx) =
                                state.account_manager.get_transactions().iter().find(|tx| {
                                    let hash = format!(
                                        "0x{}",
                                        hex::encode(alloy_primitives::keccak256(&tx.raw_data))
                                    );
                                    &hash == tx_hash
                                })
                            {
                                // Extract priority fee based on transaction type
                                match &tx.envelope {
                                    alloy_consensus::TxEnvelope::Eip1559(tx) => {
                                        // max_priority_fee_per_gas is a primitive (u128) — convert to U256
                                        priority_fees
                                            .push(U256::from(tx.tx().max_priority_fee_per_gas));
                                    }
                                    // For non-1559 transactions, use the excess over base fee as priority fee
                                    alloy_consensus::TxEnvelope::Legacy(tx) => {
                                        if let Some(base_fee) = state
                                            .eip1559_fee_manager
                                            .get_base_fee_for_block(block_num)
                                        {
                                            let tx_gas_price = U256::from(tx.tx().gas_price);
                                            if tx_gas_price > base_fee {
                                                priority_fees.push(tx_gas_price - base_fee);
                                            }
                                        }
                                    }
                                    _ => {} // Skip other transaction types
                                }
                            }
                        }

                        // Sort priority fees for percentile calculation
                        priority_fees.sort();

                        // Calculate requested percentiles
                        reward_percentiles
                            .iter()
                            .map(|&p| format!("0x{:x}", calculate_percentile(&priority_fees, p)))
                            .collect()
                    } else {
                        // If block not found, return zeros for all percentiles
                        reward_percentiles
                            .iter()
                            .map(|_| "0x0".to_string())
                            .collect()
                    };
                    rewards.push(block_rewards);
                } else {
                    // No percentiles requested, return empty array
                    rewards.push(vec![]);
                }
            } else {
                // Fallback to default values when no base fee available
                base_fees.push("0x3b9aca00".to_string()); // 1 gwei
                gas_used_ratios.push(0.5);
                // Return empty or zero rewards based on whether percentiles were requested
                rewards.push(if reward_percentiles.is_empty() {
                    vec![]
                } else {
                    reward_percentiles
                        .iter()
                        .map(|_| "0x0".to_string())
                        .collect()
                });
            }
        }

        // If no history available, return default values
        if base_fees.is_empty() {
            base_fees.push("0x3b9aca00".to_string()); // 1 gwei
            gas_used_ratios.push(0.5);
            // Return empty or zero rewards based on whether percentiles were requested
            rewards.push(if reward_percentiles.is_empty() {
                vec![]
            } else {
                reward_percentiles
                    .iter()
                    .map(|_| "0x0".to_string())
                    .collect()
            });
        }

        let fee_history = json!({
            "oldestBlock": format!("0x{:x}", start_block),
            "baseFeePerGas": base_fees,
            "gasUsedRatio": gas_used_ratios,
            "reward": rewards
        });

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(fee_history),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_base_fee_per_gas(
        state: &Arc<Self>,
        request: JsonRpcRequest,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        // Get current base fee from EIP-1559 fee manager
        let state = state.state.lock().await;
        let current_base_fee = state.eip1559_fee_manager.current_base_fee();

        let base_fee = format!("0x{:x}", current_base_fee);

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(base_fee)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_sequencer_balance(
        state: &Arc<Self>,
        request: JsonRpcRequest,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        // Get sequencer balance from state
        let state = state.state.lock().await;
        let sequencer_balance = state.account_manager.get_balance(state.sequencer_address);

        let balance = format!("0x{:x}", sequencer_balance);

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(balance)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_total_burned(
        state: &Arc<Self>,
        request: JsonRpcRequest,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        // Get total burned amount from state
        let state = state.state.lock().await;
        let total_burned = format!("0x{:x}", state.total_burned_amount);

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(total_burned)),
            error: None,
            id: request.id,
        }))
    }

    // Storage and state methods
    // We don't support storage at the moment
    async fn handle_get_storage_at(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 3 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        let address_str = request.params[0].as_str().ok_or(StatusCode::BAD_REQUEST)?;
        let position_str = request.params[1].as_str().ok_or(StatusCode::BAD_REQUEST)?;

        // Parse address and position (both handle "0x" prefix)
        let _address = address_from_str(address_str).map_err(|_| StatusCode::BAD_REQUEST)?;
        let _position = B256::from_str(position_str).map_err(|_| StatusCode::BAD_REQUEST)?;

        // Get storage value from account manager
        let _state = state.state.lock().await;
        let storage_value = B256::ZERO;

        // Convert to hex string (0x-prefixed, 32 bytes)
        let storage_hex = format!("0x{}", hex::encode(storage_value.as_slice()));

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(storage_hex)),
            error: None,
            id: request.id,
        }))
    }

    // Call and execution methods
    async fn handle_call(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        if request.params.len() != 2 {
            return Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Invalid params".to_string(),
                }),
                id: request.id,
            }));
        }

        // Parse call object
        let call_obj = match &request.params[0] {
            Value::Object(map) => map,
            _ => {
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: "Invalid params: expected call object".to_string(),
                    }),
                    id: request.id,
                }));
            }
        };

        // Support both "data" and "input" fields (both are valid in Ethereum RPC)
        let data_str = call_obj
            .get("data")
            .or_else(|| call_obj.get("input"))
            .and_then(|v| v.as_str())
            .unwrap_or("0x");

        let calldata_hex = data_str.trim_start_matches("0x");
        let calldata = match hex::decode(calldata_hex) {
            Ok(b) => b,
            Err(_) => {
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: "Invalid data hex".to_string(),
                    }),
                    id: request.id,
                }));
            }
        };

        let maybe_call = decode_intent_calldata(&calldata);
        let mut ret_bytes: Vec<u8> = Vec::new();

        match maybe_call {
            Some(IntentCall::IsIntentSolved { intent_id }) => {
                info!("IsIntentSolved: intent_id = {}", intent_id);
                let state_guard = state.state.lock().await;
                match state_guard.account_manager.get_intent(&intent_id) {
                    Some(intent) if matches!(intent.status, IntentStatus::Solved) => {
                        ret_bytes.extend_from_slice(&{
                            let mut res = [0u8; 32];
                            res[31] = 1;
                            res
                        });
                    }
                    _ => {
                        ret_bytes.extend_from_slice(&[0u8; 32]);
                    }
                }
            }
            Some(IntentCall::ValueStoredInIntent { intent_id }) => {
                info!("ValueStoredInIntent: intent_id = {}", intent_id);
                let state_guard = state.state.lock().await;
                let value_u256: U256 = match state_guard.account_manager.get_intent(&intent_id) {
                    Some(intent) => U256::from(intent.value),
                    None => U256::ZERO,
                };
                let be: [u8; 32] = value_u256.to_be_bytes();
                ret_bytes.extend_from_slice(&be);
            }
            Some(IntentCall::IntentLocker { intent_id }) => {
                info!("IntentLocker: intent_id = {}", intent_id);
                let state_guard = state.state.lock().await;
                let mut buf = [0u8; 32];
                if let Some(intent) = state_guard.account_manager.get_intent(&intent_id) {
                    if let IntentStatus::Locked(addr) = intent.status {
                        let addr_bytes = addr.as_slice();
                        buf[12..].copy_from_slice(addr_bytes);
                    }
                }
                ret_bytes.extend_from_slice(&buf);
            }
            _ => {
                // Unsupported/unknown function; return empty bytes per eth_call conventions
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: Some(json!("0x")),
                    error: None,
                    id: request.id,
                }));
            }
        }

        let result_hex = format!("0x{}", hex::encode(ret_bytes));
        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(result_hex)),
            error: None,
            id: request.id,
        }))
    }

    /// GET /get_raw_block/:block_number
    /// Returns the raw Borsh-serialized StateManager for the specified block
    async fn handle_get_raw_block(
        axum::extract::State(rpc_state): axum::extract::State<Arc<Self>>,
        axum::extract::Path(block_number): axum::extract::Path<u64>,
    ) -> Result<axum::response::Response, StatusCode> {
        use std::fs;
        use std::path::Path;

        let blocks_dir = Path::new(&rpc_state.data_dir).join("blocks");
        let block_file = blocks_dir.join(format!("{}", block_number));

        if !block_file.exists() {
            return Err(StatusCode::NOT_FOUND);
        }

        let bytes = fs::read(&block_file).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .header("X-Block-Number", block_number.to_string())
            .body(axum::body::Body::from(bytes))
            .unwrap())
    }

    /// GET /get_raw_block_delta/:block_number
    /// Returns the raw Borsh-serialized BundleStateManager (delta) for the specified block
    async fn handle_get_raw_block_delta(
        axum::extract::State(rpc_state): axum::extract::State<Arc<Self>>,
        axum::extract::Path(block_number): axum::extract::Path<u64>,
    ) -> Result<axum::response::Response, StatusCode> {
        use std::fs;
        use std::path::Path;

        let deltas_dir = Path::new(&rpc_state.data_dir).join("deltas");
        let delta_file = deltas_dir.join(format!("{}", block_number));

        if !delta_file.exists() {
            return Err(StatusCode::NOT_FOUND);
        }

        let bytes = fs::read(&delta_file).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .header("X-Block-Number", block_number.to_string())
            .body(axum::body::Body::from(bytes))
            .unwrap())
    }

    /// GET /get_latest_block
    /// Returns the raw Borsh-serialized StateManager for the latest block
    async fn handle_get_latest_block(
        axum::extract::State(rpc_state): axum::extract::State<Arc<Self>>,
    ) -> Result<axum::response::Response, StatusCode> {
        use std::fs;
        use std::path::Path;

        let state = rpc_state.state.lock().await;
        let latest_block = state.blocks.keys().max().copied().unwrap_or(0);
        drop(state);

        let blocks_dir = Path::new(&rpc_state.data_dir).join("blocks");
        let block_file = blocks_dir.join(format!("{}", latest_block));

        if !block_file.exists() {
            return Err(StatusCode::NOT_FOUND);
        }

        let bytes = fs::read(&block_file).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .header("X-Block-Number", latest_block.to_string())
            .body(axum::body::Body::from(bytes))
            .unwrap())
    }

    async fn handle_kv_get(
        axum::extract::State(rpc_state): axum::extract::State<Arc<Self>>,
        axum::extract::Path(key): axum::extract::Path<String>,
    ) -> Result<axum::response::Response, StatusCode> {
        let state = rpc_state.state.lock().await;

        if let Some(value) = state.account_manager.get_kv(&key) {
            return Ok(axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/octet-stream")
                .body(axum::body::Body::from(value.clone()))
                .unwrap());
        }
        Err(StatusCode::NOT_FOUND)
    }

    /// GET or POST /query[/path]
    /// Runs a read-only Cartesi machine execution at a given revision.
    /// Headers: X-Revision-Hash (hash or hex prefix; preferred) and/or X-Revision-Height (block number).
    /// Omit both for latest block. Response includes X-Revision-Height and X-Revision-Hash.
    /// The path after /query is the endpoint to call inside the machine (e.g. /query/api/foo -> guest /api/foo).
    async fn handle_query(
        axum::extract::State(rpc_state): axum::extract::State<Arc<Self>>,
        request: Request,
    ) -> Result<axum::response::Response, StatusCode> {
        use std::path::Path;

        let path = request
            .uri()
            .path()
            .strip_prefix("/query")
            .unwrap_or("")
            .trim_start_matches('/')
            .to_string();
        if path.is_empty() {
            return Ok(axum::response::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "error": "sub_path_required",
                        "message": "Use /query/<endpoint> to call a guest endpoint (e.g. /query/health)."
                    })
                    .to_string(),
                ))
                .unwrap());
        }

        let revision_height = request
            .headers()
            .get("X-Revision-Height")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let revision_hash = request
            .headers()
            .get("X-Revision-Hash")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let method = if request.method() == axum::http::Method::GET {
            QueryMethod::Get
        } else {
            QueryMethod::Post
        };

        let body = match to_bytes(request.into_body(), usize::MAX).await {
            Ok(b) => Bytes::from(b.to_vec()),
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        };

        let (block_number, block_timestamp, block_hash) = {
            let state = rpc_state.state.lock().await;
            let block_number = state
                .query_resolve_revision(revision_height.as_deref(), revision_hash.as_deref())
                .map_err(|e| {
                    if e.contains("not found") || e.contains("No block") {
                        StatusCode::NOT_FOUND
                    } else {
                        StatusCode::BAD_REQUEST
                    }
                })?;
            let block = state.blocks.get(&block_number);
            let block_timestamp = block.map(|b| b.timestamp).unwrap_or(0);
            let block_hash = block.map(|b| b.hash);
            (block_number, block_timestamp, block_hash)
        };

        let blocks_dir = Path::new(&rpc_state.data_dir).join("blocks");
        let block_file = blocks_dir.join(format!("{}", block_number));
        let serialized = tokio::fs::read(&block_file).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;
        let state_manager = StateManager::borsh_deserialize(&serialized)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let bundle_state = state_manager.to_bundle_state_snapshot();

        // run_cartesi_query is !Send (Cartesi Machine), so we use spawn_blocking to avoid
        // tying up a tokio worker; the blocking pool runs the future via block_on.
        let response_bytes = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(run_cartesi_query(
                path,
                method,
                body,
                bundle_state,
                block_timestamp,
            ))
        })
        .await
        .map_err(|_| {
            info!("Query task join failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map_err(|e| {
            info!("Query execution failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let mut response = axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .header("X-Revision-Height", block_number.to_string());
        if let Some(h) = block_hash {
            response = response.header("X-Revision-Hash", format!("0x{:x}", h));
        }
        Ok(response
            .body(axum::body::Body::from(response_bytes))
            .unwrap())
    }

    /// GET /health
    /// Simple health check endpoint
    async fn handle_health(
        axum::extract::State(rpc_state): axum::extract::State<Arc<Self>>,
    ) -> Result<JsonResponse<serde_json::Value>, StatusCode> {
        let state = rpc_state.state.lock().await;
        let block_count = state.blocks.len();
        let latest_block = state.blocks.keys().max().copied().unwrap_or(0);

        // Calculate the 4 metrics
        let total_accounts = state.account_manager.accounts_count();
        let total_transactions = state.account_manager.get_transactions().len();
        let current_base_fee = state.eip1559_fee_manager.current_base_fee();
        let total_burned_amount = state.total_burned_amount;

        // Get the 3 tracked metrics
        let reorgs_detected = state.reorgs_detected;
        let total_sequencer_payments = state.total_sequencer_payments;
        let last_block_processing_time_ms = state.last_block_processing_time_ms;

        // Convert U256 to u128/u64 for JSON serialization
        let current_base_fee_u128 = current_base_fee.to::<u128>();
        let current_base_fee_gwei = (current_base_fee / U256::from(1_000_000_000u64)).to::<u64>();
        let total_burned_u128 = total_burned_amount.to::<u128>();
        let total_sequencer_payments_u128 = total_sequencer_payments.to::<u128>();

        Ok(JsonResponse(json!({
            "status": "ok",
            "block_count": block_count,
            "latest_block": latest_block,
            "last_processed_bitcoin_height": state.last_processed_bitcoin_height,
            // State metrics
            "total_accounts": total_accounts,
            "total_transactions": total_transactions,
            // Base fee (provide both wei and gwei for flexibility)
            "current_base_fee_wei": current_base_fee_u128,
            "current_base_fee_gwei": current_base_fee_gwei,
            // Total burned (provide both wei and ETH for flexibility)
            "total_burned_wei": total_burned_u128,
            "total_burned_eth": format!("{:.9}", total_burned_u128 as f64 / 1e18),
            // Performance and stability metrics
            "reorgs_detected": reorgs_detected,
            "total_sequencer_payments_wei": total_sequencer_payments_u128,
            "total_sequencer_payments_eth": format!("{:.9}", total_sequencer_payments_u128 as f64 / 1e18),
            "last_block_processing_time_ms": last_block_processing_time_ms,
        })))
    }

    /// Helper function to load, sync (Electrum/RPC), and get wallet balance
    /// Returns the balance data or an error
    fn get_wallet_balance(
        mnemonic: &str,
        network: bitcoin::Network,
        data_dir: &str,
        electrum_url: Option<&str>,
        bdk_bitcoind_client: Option<Arc<bdk_bitcoind_rpc::bitcoincore_rpc::Client>>,
    ) -> Result<WalletBalanceData, WalletBalanceError> {
        use bdk_wallet::keys::bip39::Mnemonic;
        use bdk_wallet::keys::DerivableKey;
        use bdk_wallet::keys::ExtendedKey;
        use bdk_wallet::rusqlite::Connection;
        use bdk_wallet::{KeychainKind, Wallet};

        let network_str = match network {
            bitcoin::Network::Bitcoin => "bitcoin",
            bitcoin::Network::Testnet => "testnet",
            bitcoin::Network::Testnet4 => "testnet4",
            bitcoin::Network::Signet => "signet",
            bitcoin::Network::Regtest => "regtest",
        };

        let wallet_path =
            std::path::Path::new(data_dir).join(format!("wallet_{}.sqlite3", network_str));

        if !wallet_path.exists() {
            return Err(WalletBalanceError::WalletNotFound(format!(
                "Wallet database not found at: {}",
                wallet_path.display()
            )));
        }

        let mut conn = Connection::open(&wallet_path).map_err(|e| {
            WalletBalanceError::DatabaseError(format!("Failed to open wallet database: {}", e))
        })?;

        // Parse mnemonic and derive descriptors
        let mnemonic = Mnemonic::parse(mnemonic)
            .map_err(|_| WalletBalanceError::InvalidMnemonic("Invalid mnemonic".to_string()))?;

        let xkey: ExtendedKey = mnemonic.into_extended_key().map_err(|_| {
            WalletBalanceError::InvalidMnemonic(
                "Failed to derive extended key from mnemonic".to_string(),
            )
        })?;

        let xprv = xkey.into_xprv(network).ok_or_else(|| {
            WalletBalanceError::InvalidMnemonic("Failed to get extended private key".to_string())
        })?;

        let external_descriptor = format!("wpkh({}/0/*)", xprv);
        let internal_descriptor = format!("wpkh({}/1/*)", xprv);

        // Load wallet
        let wallet_opt = Wallet::load()
            .descriptor(KeychainKind::External, Some(external_descriptor.clone()))
            .descriptor(KeychainKind::Internal, Some(internal_descriptor.clone()))
            .extract_keys()
            .check_network(network)
            .load_wallet(&mut conn)
            .map_err(|e| {
                WalletBalanceError::DatabaseError(format!(
                    "Failed to load wallet from database: {}",
                    e
                ))
            })?;

        let wallet = wallet_opt.ok_or(WalletBalanceError::WalletNotInDatabase)?;

        // Sync wallet before reading balance
        match network {
            bitcoin::Network::Regtest => {
                // Use bitcoind RPC for regtest
                use bdk_bitcoind_rpc::Emitter;
                let rpc = bdk_bitcoind_client.as_ref().ok_or_else(|| {
                    WalletBalanceError::ConfigError(
                        "Bitcoin RPC client not configured for regtest sync".to_string(),
                    )
                })?;

                let mut emitter = Emitter::new(
                    rpc.as_ref(),
                    wallet.latest_checkpoint().clone(),
                    0,
                    std::iter::empty::<Arc<bitcoin::Transaction>>(),
                );

                let mut wallet = wallet;
                while let Some(block_emission) = emitter.next_block().map_err(|e| {
                    WalletBalanceError::DatabaseError(format!(
                        "Failed to fetch blocks from Bitcoin RPC: {}",
                        e
                    ))
                })? {
                    wallet
                        .apply_block(&block_emission.block, block_emission.block_height())
                        .map_err(|e| {
                            WalletBalanceError::DatabaseError(format!(
                                "Failed to apply block: {}",
                                e
                            ))
                        })?;
                }

                wallet
                    .persist(&mut conn)
                    .map_err(|e| WalletBalanceError::DatabaseError(format!("{}", e)))?;

                // Proceed with the synced wallet
                let balance = wallet.balance();
                Ok(WalletBalanceData {
                    network_str: network_str.to_string(),
                    total_sats: balance.total().to_sat(),
                    confirmed_sats: balance.confirmed.to_sat(),
                    unconfirmed_sats: balance.untrusted_pending.to_sat(),
                    total_btc: format!("{:.8}", balance.total().to_sat() as f64 / 100_000_000.0),
                    confirmed_btc: format!(
                        "{:.8}",
                        balance.confirmed.to_sat() as f64 / 100_000_000.0
                    ),
                    unconfirmed_btc: format!(
                        "{:.8}",
                        balance.untrusted_pending.to_sat() as f64 / 100_000_000.0
                    ),
                })
            }
            _ => {
                // Use Electrum for non-regtest networks
                use bdk_electrum::{electrum_client, BdkElectrumClient};

                let url = electrum_url.ok_or_else(|| {
                    WalletBalanceError::ConfigError(format!(
                        "Electrum URL required for network: {}",
                        network_str
                    ))
                })?;

                let electrum_client = electrum_client::Client::new(url).map_err(|e| {
                    WalletBalanceError::DatabaseError(format!(
                        "Failed to connect to Electrum: {}",
                        e
                    ))
                })?;
                let electrum = BdkElectrumClient::new(electrum_client);

                let request = wallet.start_sync_with_revealed_spks().build();
                let response = electrum.sync(request, 5, false).map_err(|e| {
                    WalletBalanceError::DatabaseError(format!(
                        "Failed to sync with Electrum: {}",
                        e
                    ))
                })?;

                let mut wallet = wallet;
                wallet.apply_update(response).map_err(|e| {
                    WalletBalanceError::DatabaseError(format!("Sync apply failed: {}", e))
                })?;
                wallet
                    .persist(&mut conn)
                    .map_err(|e| WalletBalanceError::DatabaseError(format!("{}", e)))?;

                let balance = wallet.balance();
                Ok(WalletBalanceData {
                    network_str: network_str.to_string(),
                    total_sats: balance.total().to_sat(),
                    confirmed_sats: balance.confirmed.to_sat(),
                    unconfirmed_sats: balance.untrusted_pending.to_sat(),
                    total_btc: format!("{:.8}", balance.total().to_sat() as f64 / 100_000_000.0),
                    confirmed_btc: format!(
                        "{:.8}",
                        balance.confirmed.to_sat() as f64 / 100_000_000.0
                    ),
                    unconfirmed_btc: format!(
                        "{:.8}",
                        balance.untrusted_pending.to_sat() as f64 / 100_000_000.0
                    ),
                })
            }
        }
    }

    /// GET /bitcoin/wallet/balance
    /// Returns the Bitcoin wallet balance from BDK wallet
    async fn handle_bitcoin_wallet_balance(
        axum::extract::State(rpc_state): axum::extract::State<Arc<Self>>,
    ) -> Result<JsonResponse<serde_json::Value>, StatusCode> {
        // Check if wallet is configured
        let mnemonic_str = match &rpc_state.mnemonic {
            Some(m) => m,
            None => {
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        let network = match rpc_state.network {
            Some(n) => n,
            None => {
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        // Get wallet balance using shared helper (wrapped in spawn_blocking for blocking I/O)
        let mnemonic_str = mnemonic_str.to_string();
        let data_dir = rpc_state.data_dir.clone();
        let electrum_url = rpc_state.electrum_url.clone();
        let bdk_bitcoind_client = rpc_state.bdk_bitcoind_client.clone();

        match tokio::task::spawn_blocking(move || {
            Self::get_wallet_balance(
                &mnemonic_str,
                network,
                &data_dir,
                electrum_url.as_deref(),
                bdk_bitcoind_client,
            )
        })
        .await
        {
            Ok(Ok(balance_data)) => Ok(JsonResponse(json!({
                "network": balance_data.network_str,
                "total_sats": balance_data.total_sats,
                "confirmed_sats": balance_data.confirmed_sats,
                "unconfirmed_sats": balance_data.unconfirmed_sats,
                "total_btc": balance_data.total_btc,
                "confirmed_btc": balance_data.confirmed_btc,
                "unconfirmed_btc": balance_data.unconfirmed_btc,
            }))),
            Ok(Err(err)) => Err(err.to_status_code()),
            Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }

    /// JSON-RPC method: bitcoin_getWalletBalance
    /// Returns the Bitcoin wallet balance from BDK wallet
    async fn handle_bitcoin_wallet_balance_rpc(
        request: JsonRpcRequest,
        state: &Arc<Self>,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        // Check if wallet is configured
        let mnemonic_str = match &state.mnemonic {
            Some(m) => m,
            None => {
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32000,
                        message:
                            "Wallet not configured: Mnemonic is required for wallet operations"
                                .to_string(),
                    }),
                    id: request.id,
                }));
            }
        };

        let network = match state.network {
            Some(n) => n,
            None => {
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32000,
                        message: "Network not configured: Bitcoin network is required for wallet operations".to_string(),
                    }),
                    id: request.id,
                }));
            }
        };

        // Get wallet balance using shared helper (wrapped in spawn_blocking for blocking I/O)
        let mnemonic_str = mnemonic_str.to_string();
        let data_dir = state.data_dir.clone();
        let electrum_url = state.electrum_url.clone();
        let bdk_bitcoind_client = state.bdk_bitcoind_client.clone();
        let request_id = request.id.clone();

        match tokio::task::spawn_blocking(move || {
            Self::get_wallet_balance(
                &mnemonic_str,
                network,
                &data_dir,
                electrum_url.as_deref(),
                bdk_bitcoind_client,
            )
        })
        .await
        {
            Ok(Ok(balance_data)) => {
                let result = json!({
                    "network": balance_data.network_str,
                    "total_sats": balance_data.total_sats,
                    "confirmed_sats": balance_data.confirmed_sats,
                    "unconfirmed_sats": balance_data.unconfirmed_sats,
                    "total_btc": balance_data.total_btc,
                    "confirmed_btc": balance_data.confirmed_btc,
                    "unconfirmed_btc": balance_data.unconfirmed_btc,
                });

                Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: Some(result),
                    error: None,
                    id: request_id,
                }))
            }
            Ok(Err(err)) => Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32000,
                    message: err.message(),
                }),
                id: request_id,
            })),
            Err(_) => Ok(JsonResponse::from(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32603,
                    message: "Internal error: task execution failed".to_string(),
                }),
                id: request_id,
            })),
        }
    }
}

// Helper function to parse Address from string
pub fn parse_address(s: &str) -> Result<Address, String> {
    // Handle both with and without 0x prefix
    let s = s.trim_start_matches("0x");

    // Ensure the string is exactly 40 characters (20 bytes)
    if s.len() != 40 {
        return Err("Invalid address length".to_string());
    }

    // Parse hex string
    let bytes = hex::decode(s).map_err(|_| "Invalid hex string".to_string())?;

    if bytes.len() != 20 {
        return Err("Invalid address length".to_string());
    }

    Ok(Address::from_slice(&bytes))
}

// Re-export for use in main.rs
pub use parse_address as address_from_str;
