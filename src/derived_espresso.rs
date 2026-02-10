use crate::block::decode_tx_envelope;
use crate::block::CoreLaneBlockParsed;
use anyhow::{anyhow, Result};
use espresso_types::v0::Header;
use espresso_types::NamespaceProofQueryData;
use hotshot_types::traits::block_contents::BlockHeader;
use reqwest::Url;
use std::time::Duration;
use surf_disco::{Client, StatusCode};
use tide_disco::error::ServerError;
use tokio::time::sleep;
use tracing::{info, warn};
use vbs::version::StaticVersion;

const MAX_RETRY_COUNT: u32 = 5;

fn height_to_hash(height: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    bytes[24..].copy_from_slice(&height.to_be_bytes());
    bytes
}

pub async fn fetch_espresso_block_number(base_url: &str) -> Result<u64> {
    let client: Client<ServerError, StaticVersion<0, 1>> = Client::new(Url::parse(base_url)?);

    let height_plus_one: u64 = client.get::<u64>("node/block-height").send().await?;

    Ok(height_plus_one.saturating_sub(1))
}

pub async fn process_espresso_block(
    base_url: &str,
    header: Header,
    namespace: u64,
) -> Result<CoreLaneBlockParsed> {
    let height = header.height();
    let anchor_block_hash = height_to_hash(height);

    let parent_hash = if height > 0 {
        height_to_hash(height.saturating_sub(1))
    } else {
        vec![0u8; 32]
    };

    let mut parsed_block =
        CoreLaneBlockParsed::new(anchor_block_hash, header.timestamp(), height, parent_hash);

    let mut attempt: u32 = 0;
    let transactions = loop {
        match fetch_namespace_transactions(base_url, height, namespace).await {
            Ok(txs) => break txs,
            Err(err) => {
                if let Some(server_err) = err.downcast_ref::<ServerError>() {
                    if server_err.status == StatusCode::NOT_FOUND {
                        if attempt >= MAX_RETRY_COUNT {
                            return Err(anyhow!(
                                "DA data for Espresso block {} namespace {} still unavailable after {} attempts",
                                height,
                                namespace,
                                attempt + 1,
                            ));
                        }

                        attempt += 1;

                        warn!(
                            "No DA data for Espresso block {} namespace {} yet (attempt {}/{}). Retrying in 1s...",
                            height,
                            namespace,
                            attempt,
                            MAX_RETRY_COUNT + 1,
                        );
                        sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }

                warn!("Error in process espresso block {:?}", err);
                return Err(err);
            }
        }
    };

    info!(
        "Espresso block {} has {} transactions in namespace {}",
        height,
        transactions.len(),
        namespace
    );

    for tx_data in transactions {
        if let Some((tx_envelope, sender)) = decode_tx_envelope(&tx_data) {
            info!(
                "Espresso: decoded transaction in block {} (sender: {})",
                height, sender
            );
            parsed_block.add_bundle_from_single_tx(tx_envelope, sender, tx_data);
        } else {
            warn!(
                "Espresso: failed to decode transaction in block {} ({} bytes)",
                height,
                tx_data.len()
            );
        }
    }

    Ok(parsed_block)
}

pub async fn fetch_namespace_transactions(
    base_url: &str,
    height: u64,
    namespace: u64,
) -> Result<Vec<Vec<u8>>> {
    let client: Client<ServerError, StaticVersion<0, 1>> = Client::new(Url::parse(base_url)?);

    let transactions: NamespaceProofQueryData = client
        .get(&format!(
            "availability/block/{height}/namespace/{namespace}"
        ))
        .send()
        .await?;

    let transactions: Vec<Vec<u8>> = transactions
        .transactions
        .iter()
        .map(|tx| tx.payload().to_vec())
        .collect();

    Ok(transactions)
}
