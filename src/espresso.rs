use crate::block::{decode_tx_envelope, CoreLaneBlockParsed};
use alloy_primitives::B256;
use anyhow::Result;
use espresso_types::v0::Header;
use espresso_types::NamespaceProofQueryData;
use hotshot_types::traits::block_contents::BlockHeader;
use reqwest::Url;
use surf_disco::Client;
use tide_disco::error::ServerError;
use tracing::{info, warn};
use vbs::version::StaticVersion;

pub const DECAF_QUERY_URL: &str = "https://query.decaf.testnet.espresso.network/v1";

pub fn block_id_from_height(height: u64) -> B256 {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&height.to_be_bytes());
    B256::from(bytes)
}

pub async fn fetch_namespace_transactions(
    height: u64,
    namespace: u64,
) -> Result<Vec<Vec<u8>>> {
    let client: Client<ServerError, StaticVersion<0, 1>> =
        Client::new(Url::parse(DECAF_QUERY_URL).unwrap());

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

pub async fn fetch_block_header(height: u64) -> Result<Header> {
    let client: Client<ServerError, StaticVersion<0, 1>> =
        Client::new(Url::parse(DECAF_QUERY_URL).unwrap());

    let block_header = client
        .get::<Header>(&format!("availability/header/{height}"))
        .send()
        .await?;

    Ok(block_header)
}

pub async fn process_espresso_block(
    height: u64,
    namespace: u64,
) -> Result<CoreLaneBlockParsed> {
    let header = fetch_block_header(height).await?;

    let anchor_block_hash = block_id_from_height(height).to_vec();

    let parent_hash = if height > 0 {
        block_id_from_height(height - 1).to_vec()
    } else {
        vec![0u8; 32]
    };

    let mut parsed_block =
        CoreLaneBlockParsed::new(anchor_block_hash, header.timestamp(), height, parent_hash);

    let transactions = fetch_namespace_transactions(height, namespace).await?;

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
