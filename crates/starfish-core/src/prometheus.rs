// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, time::Duration};

use axum::{Extension, Router, http::StatusCode, routing::get};
use prometheus::{Registry, TextEncoder};
use tokio::net::TcpListener;
use tower_http::compression::CompressionLayer;

use crate::runtime::{Handle, JoinHandle};

pub const METRICS_ROUTE: &str = "/metrics";

/// Minimum metrics scrape/push interval in seconds.
pub const MIN_METRICS_INTERVAL_SECS: u64 = 5;

/// Compute a metrics interval that scales with the number of nodes, keeping the
/// aggregate request rate roughly constant (~10 req/s). Both the orchestrator
/// scrape config and the per-validator push task should use this function.
pub fn scaled_metrics_interval(node_count: usize) -> Duration {
    Duration::from_secs((node_count as u64 / 10).max(MIN_METRICS_INTERVAL_SECS))
}

pub fn start_prometheus_server(
    address: SocketAddr,
    registry: &Registry,
) -> JoinHandle<Result<(), std::io::Error>> {
    let app = Router::new()
        .route(METRICS_ROUTE, get(metrics))
        .layer(CompressionLayer::new())
        .layer(Extension(registry.clone()));

    tracing::info!("Prometheus server booted on {address}");
    Handle::current().spawn(async move {
        let listener = TcpListener::bind(&address).await?;
        axum::serve(listener, app).await
    })
}

async fn metrics(registry: Extension<Registry>) -> (StatusCode, String) {
    let metrics_families = registry.gather();
    match TextEncoder.encode_to_string(&metrics_families) {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to encode metrics: {error}"),
        ),
    }
}

/// Spawn a background task that periodically pushes metrics to a Prometheus
/// Pushgateway. The push interval scales with committee size to keep the
/// request rate on the gateway roughly constant.
pub fn start_metrics_push_task(
    pushgateway_url: String,
    instance_label: String,
    registry: &Registry,
    committee_size: usize,
) -> JoinHandle<()> {
    let registry = registry.clone();
    let push_interval = scaled_metrics_interval(committee_size);

    Handle::current().spawn(async move {
        let url = format!(
            "{}/metrics/job/starfish/instance/{instance_label}",
            pushgateway_url.trim_end_matches('/')
        );
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client for metrics push");

        let mut interval = tokio::time::interval(push_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            let metrics_families = registry.gather();
            let body = match TextEncoder.encode_to_string(&metrics_families) {
                Ok(text) => text,
                Err(e) => {
                    tracing::warn!("Failed to encode metrics for push: {e}");
                    continue;
                }
            };

            if let Err(e) = client
                .put(&url)
                .header("content-type", "text/plain; version=0.0.4")
                .body(body)
                .send()
                .await
            {
                tracing::warn!("Metrics push to Pushgateway failed: {e}");
            }
        }
    })
}
