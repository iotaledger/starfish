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
/// aggregate scrape rate roughly constant (~10 req/s).
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
