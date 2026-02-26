use alloy_consensus::Transaction;
use alloy_primitives::Address;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::{BlockId, BlockNumberOrTag};
use anyhow::{anyhow, Result};
use tracing::{info, warn};

use crate::block::{decode_tx_envelope, extract_burn, CoreLaneBlockParsed};

pub async fn fetch_core_block_number(rpc_url: &str) -> Result<u64> {
    let url = rpc_url.parse()?;
    let provider = ProviderBuilder::new().connect_http(url);
    let block_number = provider.get_block_number().await?;
    Ok(block_number)
}

pub async fn process_core_lane_block(
    rpc_url: &str,
    height: u64,
    chain_id: u32,
    da_feed_address: Address,
) -> Result<CoreLaneBlockParsed> {
    let url = rpc_url.parse()?;
    let provider = ProviderBuilder::new().connect_http(url);
    let block = provider
        .get_block(BlockId::Number(BlockNumberOrTag::Number(height)))
        .await?
        .ok_or_else(|| anyhow!("Derived block {} not found", height))?;

    let anchor_block_hash: [u8; 32] = block.header.hash.into();
    let parent_hash = block.header.inner.parent_hash.as_slice().to_vec();
    let anchor_block_timestamp = block.header.inner.timestamp;

    let mut parsed_block = CoreLaneBlockParsed::new(
        anchor_block_hash,
        anchor_block_timestamp,
        height,
        parent_hash,
    );

    let txs: Vec<alloy_rpc_types::Transaction> = match &block.transactions {
        alloy_rpc_types::BlockTransactions::Full(txs) => txs.to_vec(),
        alloy_rpc_types::BlockTransactions::Hashes(hashes) => {
            info!(
                "Derived: block {} has {} transaction hashes, fetching full transactions...",
                height,
                hashes.len()
            );
            let mut full_txs = Vec::new();
            for hash in hashes {
                if let Ok(Some(tx)) = provider.get_transaction_by_hash(*hash).await {
                    full_txs.push(tx);
                } else {
                    warn!(
                        "Derived: failed to fetch transaction {:?} from block {}",
                        hash, height
                    );
                }
            }
            full_txs
        }
        alloy_rpc_types::BlockTransactions::Uncle => {
            warn!(
                "Derived: block {} is an uncle block, skipping transaction processing",
                height
            );
            Vec::new()
        }
    };

    info!(
        "Derived: processing core block {} for burns and DA ({} transactions)",
        height,
        txs.len()
    );

    for tx in &txs {
        if let Some(payload) = extract_da_payload(tx, da_feed_address) {
            if let Some((tx_envelope, sender)) = decode_tx_envelope(&payload) {
                info!("Derived DA bundle in block {} (sender: {})", height, sender);
                parsed_block.add_bundle_from_single_tx(tx_envelope, sender, payload);
            } else {
                warn!(
                    "Failed to decode derived DA payload in block {} ({} bytes)",
                    height,
                    payload.len()
                );
            }
        }

        if let Some(burn) = extract_burn(tx, chain_id) {
            info!(
                "🔥 Derived burn in block {} → {} (value: {})",
                height, burn.address, burn.amount
            );
            parsed_block.add_burn(burn);
        }
    }

    Ok(parsed_block)
}

fn extract_da_payload(
    tx: &alloy_rpc_types::Transaction,
    da_feed_address: Address,
) -> Option<Vec<u8>> {
    let to = tx.to()?;
    if to != da_feed_address {
        return None;
    }

    let payload = tx.input();
    if payload.is_empty() {
        return None;
    }
    Some(payload.to_vec())
}
