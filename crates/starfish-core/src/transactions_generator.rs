// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{cmp::min, sync::Arc, time::Duration};
use rand::RngCore;
use rand::SeedableRng;
use tokio::sync::mpsc;

use crate::crypto::AsBytes;
use crate::{
    config::{ClientParameters, NodePublicConfig},
    metrics::Metrics,
    runtime::{self, timestamp_utc},
    types::{Transaction},
};

pub struct TransactionGenerator {
    sender: mpsc::Sender<Vec<Transaction>>,
    client_parameters: ClientParameters,
    node_public_config: NodePublicConfig,
    metrics: Arc<Metrics>,
}

impl TransactionGenerator {
    const BATCHES_IN_SECOND: usize = 20;
    const TARGET_BLOCK_INTERVAL: Duration =
        Duration::from_millis((1000 / Self::BATCHES_IN_SECOND) as u64);

    pub fn start(
        sender: mpsc::Sender<Vec<Transaction>>,
        client_parameters: ClientParameters,
        node_public_config: NodePublicConfig,
        metrics: Arc<Metrics>,
    ) {
        assert!(client_parameters.transaction_size > 8 + 8); // 8 bytes timestamp + 8 bytes random
        runtime::Handle::current().spawn(
            Self {
                sender,
                client_parameters,
                node_public_config,
                metrics,
            }
            .run(),
        );
    }

    pub async fn run(self) {
        let load = self.client_parameters.load;

        let transactions_per_block_interval =
            (load + Self::BATCHES_IN_SECOND - 1) / Self::BATCHES_IN_SECOND;
        // For every 10 validators, add 2 seconds to the initial default delay
        // used for establishing connections between validators
        let initial_delay_plus_extra_delay = self.client_parameters.initial_delay
            + Duration::from_millis(
                (self.node_public_config.identifiers.len() as f64 / 100.0 * 20000.0) as u64,
            );
        tracing::info!(
            "Starting tx generator. After {} sec, generating {transactions_per_block_interval} transactions every {} ms",
            initial_delay_plus_extra_delay.as_secs(), Self::TARGET_BLOCK_INTERVAL.as_millis()
        );
        let max_block_size = self.node_public_config.parameters.max_block_size;
        let target_block_size = min(max_block_size, transactions_per_block_interval);

        let mut counter = 0;
        let mut tx_to_report = 0;

        let mut interval = runtime::TimeInterval::new(Self::TARGET_BLOCK_INTERVAL);
        runtime::sleep(initial_delay_plus_extra_delay).await;
        let mut rng = rand::rngs::SmallRng::from_entropy(); // faster than thread_rng

        loop {
            interval.tick().await;
            let timestamp = (timestamp_utc().as_millis() as u64).to_le_bytes();

            let mut block = Vec::with_capacity(target_block_size);
            let mut block_size = 0;
            for _ in 0..transactions_per_block_interval {
                let mut payload = vec![0u8; self.client_parameters.transaction_size - 8];
                rng.fill_bytes(&mut payload);

                let mut transaction = Vec::with_capacity(self.client_parameters.transaction_size);
                transaction.extend_from_slice(&timestamp); // 8 bytes
                transaction.extend_from_slice(&payload);

                block.push(Transaction::new(transaction));
                block_size += self.client_parameters.transaction_size;
                counter += 1;
                tx_to_report += 1;

                if block_size >= max_block_size {
                    if self.sender.send(block.clone()).await.is_err() {
                        return;
                    }
                    block.clear();
                    block_size = 0;
                }
            }
            tracing::debug!("Generator send {} transactions", block.len());
            if !block.is_empty() && self.sender.send(block).await.is_err() {
                return;
            }

            if counter % 10_000 == 0 {
                self.metrics.submitted_transactions.inc_by(tx_to_report);
                tx_to_report = 0
            }
        }
    }

    pub fn extract_timestamp(transaction: &Transaction) -> Duration {
        let bytes = transaction.as_bytes()[0..8]
            .try_into()
            .expect("Transactions should be at least 8 bytes");
        Duration::from_millis(u64::from_le_bytes(bytes))
    }
}
