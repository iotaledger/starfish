// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{cmp::min, sync::Arc, time::Duration};

use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use tokio::sync::mpsc;

use crate::{
    config::{NodePublicConfig, Parameters, TransactionMode},
    crypto::AsBytes,
    metrics::Metrics,
    runtime::{self, timestamp_utc},
    types::{AuthorityIndex, Transaction},
};

pub struct TransactionGenerator {
    sender: mpsc::Sender<Vec<Transaction>>,
    rng: StdRng,
    parameters: Parameters,
    node_public_config: NodePublicConfig,
    metrics: Arc<Metrics>,
}

impl TransactionGenerator {
    const BATCHES_IN_SECOND: usize = 20;
    const TARGET_BLOCK_INTERVAL: Duration =
        Duration::from_millis((1000 / Self::BATCHES_IN_SECOND) as u64);

    pub fn start(
        sender: mpsc::Sender<Vec<Transaction>>,
        seed: AuthorityIndex,
        parameters: Parameters,
        node_public_config: NodePublicConfig,
        metrics: Arc<Metrics>,
    ) {
        assert!(parameters.transaction_size > 8 + 8); // 8 bytes timestamp + 8 bytes random
        runtime::Handle::current().spawn(
            Self {
                sender,
                rng: StdRng::seed_from_u64(seed),
                parameters,
                node_public_config,
                metrics,
            }
            .run(),
        );
    }

    pub async fn run(mut self) {
        let load = self.parameters.load;

        let transactions_per_block_interval = load.div_ceil(Self::BATCHES_IN_SECOND);
        // For every 10 validators, add 2 seconds to the initial default delay
        // used for establishing connections between validators
        let initial_delay_plus_extra_delay = self.parameters.initial_delay
            + Duration::from_millis(
                (self.node_public_config.identifiers.len() as f64 / 100.0 * 20000.0) as u64,
            );
        tracing::info!(
            "Starting tx generator. After {} sec, \
            generating {transactions_per_block_interval} \
            transactions every {} ms",
            initial_delay_plus_extra_delay.as_secs(),
            Self::TARGET_BLOCK_INTERVAL.as_millis()
        );
        let max_block_size = self.node_public_config.parameters.max_block_size;
        let target_block_size = min(max_block_size, transactions_per_block_interval);

        let tx_size = self.parameters.transaction_size;
        let mode = &self.parameters.transaction_mode;

        let mut counter: u64 = 0;
        let mut tx_to_report = 0;
        let mut random: u64 = self.rng.gen();
        // Pre-allocated payload buffer reused in AllZero mode.
        let zeros = vec![0u8; tx_size - 8 - 8];

        let mut interval = runtime::TimeInterval::new(Self::TARGET_BLOCK_INTERVAL);
        runtime::sleep(initial_delay_plus_extra_delay).await;

        loop {
            interval.tick().await;
            let timestamp = (timestamp_utc().as_millis() as u64).to_le_bytes();

            let mut block = Vec::with_capacity(target_block_size);
            let mut block_size = 0;
            for _ in 0..transactions_per_block_interval {
                let mut transaction = Vec::with_capacity(tx_size);
                transaction.extend_from_slice(&timestamp); // 8 bytes

                match mode {
                    TransactionMode::AllZero => {
                        random += counter;
                        transaction.extend_from_slice(&random.to_le_bytes()); // 8 bytes
                        transaction.extend_from_slice(&zeros);
                    }
                    TransactionMode::Random => {
                        // Fill remaining bytes with RNG.
                        transaction.resize(tx_size, 0);
                        self.rng.fill_bytes(&mut transaction[8..]);
                    }
                }

                block.push(Transaction::new(transaction));
                block_size += tx_size;
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

            if counter.is_multiple_of(10_000) {
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
