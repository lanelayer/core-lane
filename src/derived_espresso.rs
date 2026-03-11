use crate::block::{
    decode_tx_envelope, extract_burn, CoreLaneBlockParsed, CoreLaneBundleCbor, CoreLaneBurn,
};
use alloy_primitives::B256;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::{BlockId, BlockNumberOrTag, BlockTransactions};
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

pub struct CoreLaneTip {
    pub height: u64,
    pub hash: [u8; 32],
    pub parent_hash: Vec<u8>,
}

const CORE_LANE_ANCHOR_PREFIX_LEN: usize = 32;

fn parse_core_lane_anchor_prefix(tx_data: &[u8]) -> (Option<[u8; 32]>, &[u8]) {
    // If length is less than the anchor prefix length + 1, return no prefix.
    if tx_data.len() < CORE_LANE_ANCHOR_PREFIX_LEN + 1 {
        return (None, tx_data);
    }

    let mut prefix_hash = [0u8; 32];
    prefix_hash.copy_from_slice(&tx_data[..32]);
    let remaining = &tx_data[32..];

    let is_valid_payload =
        CoreLaneBundleCbor::from_cbor(remaining).is_ok() || decode_tx_envelope(remaining).is_some();

    if is_valid_payload {
        info!(
            "Espresso: found Core Lane anchor tip hash in first transaction of block {}",
            hex::encode(prefix_hash)
        );
        (Some(prefix_hash), remaining)
    } else {
        (None, tx_data)
    }
}
const MAX_RETRY_COUNT: u32 = 5;

async fn fetch_core_lane_block_metadata(
    core_rpc_url: &str,
    hash: [u8; 32],
) -> Option<(u64, Vec<u8>)> {
    let url = match core_rpc_url.parse() {
        Ok(url) => url,
        Err(e) => {
            warn!("Invalid core_rpc_url '{}': {}", core_rpc_url, e);
            return None;
        }
    };
    let provider = ProviderBuilder::new().connect_http(url);
    let block_hash = B256::from(hash);
    match provider.get_block(BlockId::from(block_hash)).await {
        Ok(Some(block)) => {
            let height = block.header.number;
            let parent_hash = block.header.inner.parent_hash.as_slice().to_vec();
            Some((height, parent_hash))
        }
        Ok(None) => None,
        Err(e) => {
            warn!(
                "Failed to fetch Core Lane block metadata for {}: {}",
                hex::encode(hash),
                e
            );
            None
        }
    }
}

async fn scan_block_for_burns(
    provider: &impl Provider,
    height: u64,
    chain_id: u32,
) -> Result<Vec<CoreLaneBurn>> {
    let block = match provider
        .get_block(BlockId::Number(BlockNumberOrTag::Number(height)))
        .await
    {
        Ok(Some(b)) => b,
        Ok(None) => {
            warn!("scan_block_for_burns: block {} not found", height);
            return Err(anyhow!("scan_block_for_burns: block {} not found", height));
        }
        Err(e) => {
            warn!(
                "scan_block_for_burns: failed to fetch block {}: {}",
                height, e
            );
            return Err(e.into());
        }
    };

    let tx_hashes = match block.transactions {
        BlockTransactions::Full(txs) => {
            return Ok(txs
                .iter()
                .filter_map(|tx| extract_burn(tx, chain_id))
                .collect());
        }
        BlockTransactions::Hashes(hashes) => hashes,
        _ => return Ok(Vec::new()),
    };

    let mut burns = Vec::new();
    for hash in tx_hashes {
        let tx = match provider.get_transaction_by_hash(hash).await {
            Ok(Some(tx)) => tx,
            Ok(None) => {
                warn!("scan_block_for_burns: tx {} not found", hash);
                return Err(anyhow!("scan_block_for_burns: tx {} not found", hash));
            }
            Err(e) => {
                warn!("scan_block_for_burns: failed to fetch tx {}: {}", hash, e);
                return Err(e.into());
            }
        };
        if let Some(burn) = extract_burn(&tx, chain_id) {
            burns.push(burn);
        }
    }
    Ok(burns)
}

async fn fetch_core_lane_burns(
    core_rpc_url: &str,
    from_height: u64,
    to_height: u64,
    chain_id: u32,
) -> Result<Vec<CoreLaneBurn>> {
    if from_height > to_height {
        info!("fetch_core_lane_burns: range is empty (from > to), skipping");
        return Ok(Vec::new());
    }

    let url = match core_rpc_url.parse() {
        Ok(url) => url,
        Err(e) => {
            warn!(
                "fetch_core_lane_burns: invalid core_rpc_url '{}': {}",
                core_rpc_url, e
            );
            return Err(anyhow!(
                "fetch_core_lane_burns: invalid core_rpc_url '{}': {}",
                core_rpc_url,
                e
            ));
        }
    };
    let provider = ProviderBuilder::new().connect_http(url);
    let mut burns = Vec::new();

    for height in from_height..=to_height {
        let block_burns = scan_block_for_burns(&provider, height, chain_id).await?;
        for burn in &block_burns {
            info!(
                "🔥 Core Lane burn for Espresso Lane detected in block {} → {} (value: {})",
                height, burn.address, burn.amount
            );
        }
        burns.extend(block_burns);
    }

    Ok(burns)
}

pub async fn fetch_core_lane_tip(rpc_url: &str) -> Result<CoreLaneTip> {
    let url = rpc_url.parse()?;
    let provider = ProviderBuilder::new().connect_http(url);
    let height = provider.get_block_number().await?;
    let block = provider
        .get_block(BlockId::Number(BlockNumberOrTag::Number(height)))
        .await?
        .ok_or_else(|| anyhow!("Core Lane tip block {} not found", height))?;
    Ok(CoreLaneTip {
        height,
        hash: block.header.hash.into(),
        parent_hash: block.header.inner.parent_hash.as_slice().to_vec(),
    })
}

pub async fn fetch_espresso_block_number(base_url: &str) -> Result<u64> {
    let client: Client<ServerError, StaticVersion<0, 1>> = Client::new(Url::parse(base_url)?);

    let height_plus_one: u64 = client.get::<u64>("node/block-height").send().await?;

    Ok(height_plus_one.saturating_sub(1))
}

#[allow(clippy::too_many_arguments)]
pub async fn process_espresso_block(
    base_url: &str,
    core_rpc_url: &str,
    header: Header,
    namespace: u64,
    chain_id: u32,
    previous_core_lane_tip: [u8; 32],
    previous_anchor_height: u64,
    previous_anchor_parent_hash: Vec<u8>,
) -> Result<CoreLaneBlockParsed> {
    let height = header.height();
    let mut core_lane_block = CoreLaneBlockParsed::new(
        previous_core_lane_tip,
        header.timestamp(),
        previous_anchor_height,
        previous_anchor_parent_hash,
    );

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

    let mut first_tx_processed = false;

    for tx_data in transactions {
        let (derived_core_lane_tip, tx_without_prefix) = if !first_tx_processed {
            parse_core_lane_anchor_prefix(&tx_data)
        } else {
            (None, tx_data.as_slice())
        };

        let pending_anchor = if !first_tx_processed {
            if let Some(core_lane_tip_hash) = derived_core_lane_tip {
                match fetch_core_lane_block_metadata(core_rpc_url, core_lane_tip_hash).await {
                    Some((tip_height, tip_parent_hash)) => {
                        info!(
                            "Espresso: found Core Lane anchor tip hash in first transaction of block {}: {} (height {})",
                            height,
                            hex::encode(core_lane_tip_hash),
                            tip_height,
                        );
                        Some((core_lane_tip_hash, tip_height, tip_parent_hash))
                    }
                    None => {
                        warn!(
                            "Espresso: Core Lane tip hash {} claimed in block {} prefix not found in Core Lane; ignoring",
                            hex::encode(core_lane_tip_hash),
                            height
                        );
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };
        first_tx_processed = true;

        match CoreLaneBundleCbor::from_cbor(tx_without_prefix) {
            Ok(cbor_bundle) => {
                info!(
                    "Espresso: decoded CBOR bundle in block {} ({} transactions)",
                    height,
                    cbor_bundle.transactions.len()
                );
                if let Err(e) = core_lane_block.add_bundle_from_cbor(cbor_bundle) {
                    warn!(
                        "Espresso: failed to process CBOR bundle in block {}: {}",
                        height, e
                    );
                } else if let Some((tip_hash, tip_height, tip_parent_hash)) = pending_anchor {
                    core_lane_block.anchor_block_hash = tip_hash;
                    core_lane_block.anchor_block_height = tip_height;
                    core_lane_block.parent_hash = tip_parent_hash;
                }
            }
            Err(_) => {
                // Fall back to raw transaction envelope
                if let Some((tx_envelope, sender)) = decode_tx_envelope(tx_without_prefix) {
                    info!(
                        "Espresso: decoded legacy RLP transaction in block {} (sender: {})",
                        height, sender
                    );
                    core_lane_block.add_bundle_from_single_tx(
                        tx_envelope,
                        sender,
                        tx_without_prefix.to_vec(),
                    );
                    if let Some((tip_hash, tip_height, tip_parent_hash)) = pending_anchor {
                        core_lane_block.anchor_block_hash = tip_hash;
                        core_lane_block.anchor_block_height = tip_height;
                        core_lane_block.parent_hash = tip_parent_hash;
                    }
                } else {
                    warn!(
                        "Espresso: failed to decode transaction in block {} ({} bytes)",
                        height,
                        tx_without_prefix.len()
                    );
                }
            }
        }
    }

    let burns = fetch_core_lane_burns(
        core_rpc_url,
        previous_anchor_height.saturating_add(1),
        core_lane_block.anchor_block_height,
        chain_id,
    )
    .await?;
    for burn in burns {
        core_lane_block.add_burn(burn);
    }

    Ok(core_lane_block)
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
