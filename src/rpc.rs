use crate::CoreMELState;
use alloy_consensus::transaction::SignerRecoverable;
use alloy_primitives::{Address, B256};
use anyhow;
use axum::{
    extract::Json, http::StatusCode, response::Json as JsonResponse, routing::post, Router,
};
use bitcoincore_rpc;
use hex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
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

#[derive(Debug, Deserialize)]
pub struct TransactionRequest {
    #[serde(rename = "from")]
    pub from: Option<String>,
    #[serde(rename = "to")]
    pub to: Option<String>,
    #[serde(rename = "gas")]
    pub gas: Option<String>,
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<String>,
    #[serde(rename = "maxFeePerGas")]
    pub max_fee_per_gas: Option<String>,
    #[serde(rename = "maxPriorityFeePerGas")]
    pub max_priority_fee_per_gas: Option<String>,
    #[serde(rename = "value")]
    pub value: Option<String>,
    #[serde(rename = "data")]
    pub data: Option<String>,
    #[serde(rename = "nonce")]
    pub nonce: Option<String>,
}

pub struct RpcServer {
    state: Arc<Mutex<CoreMELState>>,
    bitcoin_client: Option<Arc<bitcoincore_rpc::Client>>,
}

impl RpcServer {
    pub fn new(state: Arc<Mutex<CoreMELState>>) -> Self {
        Self {
            state,
            bitcoin_client: None,
        }
    }

    pub fn with_bitcoin_client(
        state: Arc<Mutex<CoreMELState>>,
        bitcoin_client: Arc<bitcoincore_rpc::Client>,
    ) -> Self {
        Self {
            state,
            bitcoin_client: Some(bitcoin_client),
        }
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/", post(Self::handle_request))
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
            "net_version" => Self::handle_net_version(request).await,
            "net_listening" => Self::handle_net_listening(request).await,
            "net_peerCount" => Self::handle_net_peer_count(request).await,

            // Gas and fee methods
            "eth_gasPrice" => Self::handle_gas_price(request).await,
            "eth_estimateGas" => Self::handle_estimate_gas(request, &state).await,
            "eth_maxPriorityFeePerGas" => Self::handle_max_priority_fee_per_gas(request).await,
            "eth_feeHistory" => Self::handle_fee_history(request).await,

            // Storage and state methods
            "eth_getStorageAt" => Self::handle_get_storage_at(request, &state).await,

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

        // Remove "0x" prefix if present
        let address_str = address_str.trim_start_matches("0x");

        // Parse address
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

        // Parse address
        let address = address_from_str(address_str.trim_start_matches("0x"))
            .map_err(|_| StatusCode::BAD_REQUEST)?;

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

        // Parse address
        let address = address_from_str(address_str.trim_start_matches("0x"))
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        // Get account from account manager
        let state = state.state.lock().await;
        let account = state.account_manager.get_account(address);

        // Return code as hex string (0x-prefixed)
        let code_hex = format!("0x{}", hex::encode(&account.unwrap().code));

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(code_hex)),
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

        // Check if Bitcoin client is available
        let bitcoin_client = match &server.bitcoin_client {
            Some(client) => client,
            None => {
                return Ok(JsonResponse::from(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32601,
                        message: "Bitcoin client not configured - cannot send to DA".to_string(),
                    }),
                    id: request.id,
                }));
            }
        };

        // Send transaction to Bitcoin DA
        match Self::send_to_bitcoin_da(raw_tx_hex, bitcoin_client).await {
            Ok(bitcoin_txid) => {
                // Calculate the Core Lane transaction hash for the response
                use alloy_primitives::keccak256;
                let tx_bytes = hex::decode(raw_tx_hex).unwrap(); // Already validated above
                let tx_hash = keccak256(&tx_bytes);
                let tx_hash_hex = format!("0x{}", hex::encode(tx_hash));

                println!("✅ Transaction sent to Bitcoin DA");
                println!("   Bitcoin TXID: {}", bitcoin_txid);
                println!("   Core Lane TX Hash: {}", tx_hash_hex);

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
        bitcoin_client: &Arc<bitcoincore_rpc::Client>,
    ) -> Result<String, anyhow::Error> {
        // Use the shared TaprootDA module with proper Taproot envelope method
        let taproot_da = crate::taproot_da::TaprootDA::new(bitcoin_client.clone());

        // Default fee for DA transactions (this could be made configurable)
        let fee_sats = 10000u64;
        let wallet = "mine";
        let network = "regtest";

        taproot_da
            .send_transaction_to_da(raw_tx_hex, fee_sats, wallet, network)
            .await
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
        for (index, stored_tx) in state.transactions.iter().enumerate() {
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
        if let Some(receipt) = state.transaction_receipts.get(&format!("0x{}", tx_hash)) {
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
                    for (stored_index, stored_tx) in state.transactions.iter().enumerate() {
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
                for (stored_index, stored_tx) in state.transactions.iter().enumerate() {
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
        // Core Lane chain ID = 1 (for testing)
        let chain_id = "0x1";

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(chain_id)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_net_version(
        request: JsonRpcRequest,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        // Network version same as chain ID
        let net_version = "1";

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
        let gas_price = "0x3b9aca00"; // 1 Gwei in hex

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
        request: JsonRpcRequest,
    ) -> Result<JsonResponse<JsonRpcResponse>, StatusCode> {
        // Return a reasonable priority fee (0.1 Gwei)
        let priority_fee = "0x5f5e100"; // 0.1 Gwei in hex

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!(priority_fee)),
            error: None,
            id: request.id,
        }))
    }

    async fn handle_fee_history(
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

        // Return a simple fee history structure
        let fee_history = json!({
            "oldestBlock": "0x1",
            "baseFeePerGas": ["0x3b9aca00"],
            "gasUsedRatio": [0.5],
            "reward": [["0x5f5e100"]]
        });

        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(fee_history),
            error: None,
            id: request.id,
        }))
    }

    // Storage and state methods
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

        // Parse address and position
        let address = address_from_str(address_str.trim_start_matches("0x"))
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let position = B256::from_str(position_str.trim_start_matches("0x"))
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        // Get storage value from account manager
        let state = state.state.lock().await;
        let account = state.account_manager.get_account(address);
        let storage_value = account
            .unwrap()
            .storage
            .get(&position)
            .unwrap_or(&B256::ZERO);

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

        // For now, return an error indicating this method is not fully implemented
        Ok(JsonResponse::from(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: "eth_call not yet implemented".to_string(),
            }),
            id: request.id,
        }))
    }
}

// Helper function to parse Address from string
pub fn from_str(s: &str) -> Result<Address, String> {
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
pub use from_str as address_from_str;
