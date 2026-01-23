use crate::block::{decode_tx_envelope, CoreLaneBlockParsed};
use alloy_primitives::B256;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::BlockNumberOrTag;
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

pub struct CoreLaneReorgTracker {
    core_rpc_url: String,
    anchors: Vec<(u64, u64, B256)>,
}

impl CoreLaneReorgTracker {
    pub fn new(core_rpc_url: String) -> Self {
        Self {
            core_rpc_url,
            anchors: Vec::new(),
        }
    }

    pub fn record(&mut self, espresso_block: u64, core_height: u64, core_hash: B256) {
        info!(
            "📌 Anchor: Espresso {} -> Core Lane {} ({})",
            espresso_block, core_height, core_hash
        );
        self.anchors.push((espresso_block, core_height, core_hash));
    }

    pub async fn check_reorg(&mut self) -> Result<Option<u64>> {
        let provider = ProviderBuilder::new().connect_http(self.core_rpc_url.parse()?);
        info!(
            "🔎 CoreLaneReorgTracker: {} anchor(s) recorded",
            self.anchors.len(),
        );

        if self.anchors.is_empty() {
            return Ok(None);
        }

        let mut anchors = self.anchors.clone();
        anchors.reverse();

        let mut fork_point: Option<u64> = None;

        for (_espresso_block, core_height, stored_hash) in anchors.into_iter() {
            match provider
                .get_block_by_number(BlockNumberOrTag::Number(core_height))
                .await?
            {
                Some(block) => {
                    if block.header.hash != stored_hash {
                        if fork_point.is_none() {
                            warn!(
                                "🚨 Core Lane reorg at block {}! Hash changed: {} → {}",
                                core_height, stored_hash, block.header.hash
                            );
                        }
                        fork_point = Some(core_height);
                    } else {
                        if fork_point.is_some() {
                            return Ok(fork_point);
                        }
                    }
                }
                None => {
                    warn!(
                        "🚨 Core Lane block {} not found, reorg detected",
                        core_height
                    );
                    fork_point = Some(core_height);
                }
            }
        }

        Ok(fork_point)
    }

    pub fn remove_anchors_after_core_height(&mut self, rollback_core_height: u64) {
        for (espresso_height, core_height, core_hash) in self.anchors.iter() {
            if *core_height >= rollback_core_height {
                info!(
                    "🧹 Removing anchor due to reorg: Espresso {} -> Core Lane {} ({})",
                    espresso_height, core_height, core_hash
                );
            }
        }

        self.anchors
            .retain(|(_, core_height, _)| *core_height < rollback_core_height);
    }

    pub fn remove_anchors_for_finalized_blocks(&mut self, finalized_tip: u64) {
        let before = self.anchors.len();
        self.anchors.retain(|(_, h, _)| *h > finalized_tip);
        let removed = before - self.anchors.len();
        if removed > 0 {
            info!(
                "🧹 Removed {} anchor(s) for finalized Core Lane blocks (height ≤ {})",
                removed, finalized_tip
            );
        }
    }
}

pub fn block_id_from_height(height: u64) -> B256 {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&height.to_be_bytes());
    B256::from(bytes)
}

pub async fn fetch_namespace_transactions(height: u64, namespace: u64) -> Result<Vec<Vec<u8>>> {
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

pub async fn process_espresso_block(height: u64, namespace: u64) -> Result<CoreLaneBlockParsed> {
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
