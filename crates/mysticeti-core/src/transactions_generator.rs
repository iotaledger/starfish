// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{cmp::min, sync::Arc, time::Duration};

use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::sync::mpsc;

use crate::{
    config::{ClientParameters, NodePublicConfig},
    metrics::Metrics,
    runtime::{self, timestamp_utc},
    types::{AuthorityIndex, Transaction},
};
use crate::crypto::AsBytes;

pub struct TransactionGenerator {
    sender: mpsc::Sender<Vec<Transaction>>,
    rng: StdRng,
    client_parameters: ClientParameters,
    node_public_config: NodePublicConfig,
    metrics: Arc<Metrics>,
}

impl TransactionGenerator {
    const TARGET_BLOCK_INTERVAL: Duration = Duration::from_millis(100);

    pub fn start(
        sender: mpsc::Sender<Vec<Transaction>>,
        seed: AuthorityIndex,
        client_parameters: ClientParameters,
        node_public_config: NodePublicConfig,
        metrics: Arc<Metrics>,
    ) {
        assert!(client_parameters.transaction_size > 8 + 8); // 8 bytes timestamp + 8 bytes random
        tracing::info!(
            "Starting generator with {} transactions per second, initial delay {:?}",
            client_parameters.load,
            client_parameters.initial_delay
        );
        runtime::Handle::current().spawn(
            Self {
                sender,
                rng: StdRng::seed_from_u64(seed),
                client_parameters,
                node_public_config,
                metrics,
            }
            .run(),
        );
    }

    pub async fn run(mut self) {
        let load = self.client_parameters.load;
        let transactions_per_block_interval = (load + 9) / 10;
        tracing::info!(
            "Generating {transactions_per_block_interval} transactions per {} ms",
            Self::TARGET_BLOCK_INTERVAL.as_millis()
        );
        let max_block_size = self.node_public_config.parameters.max_block_size;
        let target_block_size = min(max_block_size, transactions_per_block_interval);

        let mut counter = 0;
        let mut tx_to_report = 0;
        let mut random: u64 = self.rng.gen(); // 8 bytes
        let zeros = vec![0u8; self.client_parameters.transaction_size - 8 - 8]; // 8 bytes timestamp + 8 bytes random

        let mut interval = runtime::TimeInterval::new(Self::TARGET_BLOCK_INTERVAL);
        runtime::sleep(self.client_parameters.initial_delay).await;
        loop {
            interval.tick().await;
            let timestamp = (timestamp_utc().as_millis() as u64).to_le_bytes();

            let mut block = Vec::with_capacity(target_block_size);
            let mut block_size = 0;
            for _ in 0..transactions_per_block_interval {
                random += counter;

                let mut transaction = Vec::with_capacity(self.client_parameters.transaction_size);
                transaction.extend_from_slice(&timestamp); // 8 bytes
                transaction.extend_from_slice(&random.to_le_bytes()); // 8 bytes
                transaction.extend_from_slice(&zeros[..]);

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
