use std::str::FromStr;

use alloy_consensus::Transaction;
use alloy_primitives::{Address, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::{BlockId, BlockNumberOrTag};
use anyhow::{anyhow, Result};
use tracing::{info, warn};

use crate::block::{decode_tx_envelope, CoreLaneBlockParsed, CoreLaneBurn};

const DERIVED_BURN_ADDRESS_HEX: &str = "0x0000000000000000000000000000000000000666";

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

    let anchor_block_hash = block.header.hash.as_slice().to_vec();
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

        if let Some(burn) = extract_burn(tx, chain_id)? {
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

fn extract_burn(
    tx: &alloy_rpc_types::Transaction,
    expected_chain_id: u32,
) -> Result<Option<CoreLaneBurn>> {
    let burn_address = Address::from_str(DERIVED_BURN_ADDRESS_HEX)
        .map_err(|_| anyhow!("Invalid burn address constant"))?;

    let Some(to) = tx.to() else {
        return Ok(None);
    };
    if to != burn_address {
        return Ok(None);
    }

    let input = tx.input();
    if input.len() < 24 {
        // Candidate burn (to the burn address) but calldata is too short
        info!(
            "Derived: tx to burn address but input too short (len={})",
            input.len()
        );
        return Ok(None);
    }

    let chain_id = u32::from_be_bytes(input[0..4].try_into().unwrap());
    if chain_id != expected_chain_id {
        return Ok(None);
    }

    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&input[4..24]);
    let recipient = Address::from(addr_bytes);

    let amount: U256 = tx.value();

    info!(
        "Derived: candidate burn tx, chain_id={}, expected_chain_id={}, recipient={}, amount={}",
        chain_id, expected_chain_id, recipient, amount
    );

    if chain_id != expected_chain_id {
        info!(
            "Derived: rejecting burn tx due to chain_id mismatch (got {}, expected {})",
            chain_id, expected_chain_id
        );
        return Ok(None);
    }

    if amount.is_zero() {
        info!("Derived: rejecting burn tx due to zero amount");
        return Ok(None);
    }

    info!(
        "🔥 Derived burn in block (from extract_burn) → {} (value: {})",
        recipient, amount
    );

    Ok(Some(CoreLaneBurn::new(amount, recipient)))
}

/// Fetch only burns from a Core Lane block (for Espresso mode)
pub async fn fetch_burns_from_core_lane_block(
    rpc_url: &str,
    height: u64,
    chain_id: u32,
) -> Result<Vec<CoreLaneBurn>> {
    let url = rpc_url.parse()?;
    let provider = ProviderBuilder::new().connect_http(url);
    let block = provider
        .get_block(BlockId::Number(BlockNumberOrTag::Number(height)))
        .await?
        .ok_or_else(|| anyhow!("Core Lane block {} not found", height))?;

    let txs: Vec<alloy_rpc_types::Transaction> = match &block.transactions {
        alloy_rpc_types::BlockTransactions::Full(txs) => txs.to_vec(),
        alloy_rpc_types::BlockTransactions::Hashes(hashes) => {
            let mut full_txs = Vec::new();
            for hash in hashes {
                if let Ok(Some(tx)) = provider.get_transaction_by_hash(*hash).await {
                    full_txs.push(tx);
                }
            }
            full_txs
        }
        alloy_rpc_types::BlockTransactions::Uncle => Vec::new(),
    };

    let mut burns = Vec::new();
    for tx in &txs {
        if let Some(burn) = extract_burn(tx, chain_id)? {
            burns.push(burn);
        }
    }

    Ok(burns)
}

/// Fetch Core Lane block hash at a specific height
pub async fn fetch_core_block_hash(rpc_url: &str, height: u64) -> Result<alloy_primitives::B256> {
    let url = rpc_url.parse()?;
    let provider = ProviderBuilder::new().connect_http(url);
    let block = provider
        .get_block(BlockId::Number(BlockNumberOrTag::Number(height)))
        .await?
        .ok_or_else(|| anyhow!("Core Lane block {} not found", height))?;
    Ok(block.header.hash)
}
