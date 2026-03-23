//! Polls a Core Lane / JSON-RPC lane for `eth_blockNumber`; when it increases,
//! POSTs to each configured sprite's `/do_poll` (on-demand derived nodes).

use alloy_provider::Provider;
use alloy_provider::ProviderBuilder;
use anyhow::{Context, Result};
use clap::Parser;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "espresso-watcher")]
struct Cli {
    /// JSON-RPC HTTP URL for the lane (same as Core Lane RPC, e.g. https://lane.example/ or host:8545).
    #[arg(long, env = "LANE_RPC_URL")]
    lane_rpc_url: String,

    /// Seconds between polls (default 2).
    #[arg(long, default_value_t = 2, env = "WATCHER_POLL_INTERVAL_SECS")]
    poll_interval_secs: u64,

    /// Comma-separated sprite bases (e.g. `https://a.fly.dev,https://b.fly.dev`) or full `.../do_poll` URLs.
    #[arg(long, env = "SPRITE_URLS")]
    sprite_urls: String,
}

fn normalize_do_poll_url(base: &str) -> Option<String> {
    let t = base.trim();
    if t.is_empty() {
        return None;
    }
    let t = t.trim_end_matches('/');
    Some(if t.ends_with("/do_poll") {
        t.to_string()
    } else {
        format!("{}/do_poll", t)
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let sprites: Vec<String> = cli
        .sprite_urls
        .split(',')
        .filter_map(|s| normalize_do_poll_url(s))
        .collect();

    anyhow::ensure!(
        !sprites.is_empty(),
        "SPRITE_URLS must contain at least one non-empty URL"
    );

    let parsed = cli
        .lane_rpc_url
        .parse()
        .context("invalid LANE_RPC_URL")?;
    let provider = ProviderBuilder::new().connect_http(parsed);

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;

    let interval = Duration::from_secs(cli.poll_interval_secs.max(1));

    tracing::info!(
        lane = %cli.lane_rpc_url,
        poll_secs = cli.poll_interval_secs,
        sprites = ?sprites,
        "espresso-watcher started"
    );

    let mut last_seen: Option<u64> = None;

    loop {
        tokio::time::sleep(interval).await;

        let height = match provider.get_block_number().await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "eth_blockNumber failed");
                continue;
            }
        };

        match last_seen {
            None => {
                tracing::info!(height, "initial lane block number (no /do_poll yet)");
                last_seen = Some(height);
            }
            Some(prev) if height > prev => {
                tracing::info!(from = prev, to = height, "lane advanced; notifying sprites");
                for url in &sprites {
                    match http.post(url).send().await {
                        Ok(resp) => {
                            let status = resp.status();
                            let body = resp.text().await.unwrap_or_default();
                            if status.is_success() {
                                tracing::info!(%url, %status, "do_poll ok");
                            } else {
                                tracing::warn!(%url, %status, body = %body, "do_poll non-success");
                            }
                        }
                        Err(e) => tracing::warn!(%url, error = %e, "do_poll request failed"),
                    }
                }
                last_seen = Some(height);
            }
            Some(_) => {}
        }
    }
}
