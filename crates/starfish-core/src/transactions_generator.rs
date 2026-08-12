// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    cmp::min,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use tokio::{
    sync::{mpsc, watch},
    time::{Instant, MissedTickBehavior, interval_at, sleep_until},
};

use crate::{
    config::{NodePublicConfig, Parameters, TransactionMode},
    crypto::AsBytes,
    metrics::{BenchmarkGeneratorState, BenchmarkTransactionWindow, Metrics},
    runtime::{self, timestamp_utc},
    types::{AuthorityIndex, Transaction},
};

pub struct TransactionGenerator {
    sender: mpsc::Sender<Vec<Transaction>>,
    rng: StdRng,
    parameters: Parameters,
    node_public_config: NodePublicConfig,
    metrics: Arc<Metrics>,
    start_gate: Option<watch::Receiver<Option<BenchmarkTransactionWindow>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubmissionOutcome {
    Submitted,
    Cutoff,
    Closed,
}

impl TransactionGenerator {
    const BATCHES_IN_SECOND: usize = 20;
    const TARGET_BLOCK_INTERVAL: Duration =
        Duration::from_millis((1000 / Self::BATCHES_IN_SECOND) as u64);

    fn transactions_for_interval(load: usize, carry: &mut usize) -> usize {
        *carry += load;
        let transactions = *carry / Self::BATCHES_IN_SECOND;
        *carry %= Self::BATCHES_IN_SECOND;
        transactions
    }

    async fn submit_before_end(
        &self,
        block: Vec<Transaction>,
        generation_end: Option<Instant>,
    ) -> SubmissionOutcome {
        let Some(end) = generation_end else {
            return if self.sender.send(block).await.is_ok() {
                SubmissionOutcome::Submitted
            } else {
                SubmissionOutcome::Closed
            };
        };
        if Instant::now() >= end {
            return SubmissionOutcome::Cutoff;
        }
        // Deadline first makes t == end exclusive even when channel capacity
        // and the cutoff become ready in the same scheduler turn. A pending
        // send is cancelled without publishing its block, so it cannot become
        // post-window offered work or drain debt.
        tokio::select! {
            biased;
            _ = sleep_until(end) => SubmissionOutcome::Cutoff,
            result = self.sender.send(block) => {
                if result.is_ok() {
                    SubmissionOutcome::Submitted
                } else {
                    SubmissionOutcome::Closed
                }
            }
        }
    }

    #[cfg(test)]
    pub fn start(
        sender: mpsc::Sender<Vec<Transaction>>,
        seed: AuthorityIndex,
        parameters: Parameters,
        node_public_config: NodePublicConfig,
        metrics: Arc<Metrics>,
    ) {
        Self::start_with_gate(sender, seed, parameters, node_public_config, metrics, None);
    }

    pub fn start_with_gate(
        sender: mpsc::Sender<Vec<Transaction>>,
        seed: AuthorityIndex,
        parameters: Parameters,
        node_public_config: NodePublicConfig,
        metrics: Arc<Metrics>,
        start_gate: Option<watch::Receiver<Option<BenchmarkTransactionWindow>>>,
    ) {
        assert!(parameters.transaction_size > 8 + 8); // 8 bytes timestamp + 8 bytes random
        // Publish the finite-window warmup state synchronously. The spawned
        // task may not be polled until after the benchmark harness inspects
        // readiness, so setting this only inside `run` creates a false active
        // window and can baseline before the topology is complete.
        if parameters.benchmark_duration.is_some() {
            metrics.metrics_active.store(false, Ordering::Relaxed);
            metrics
                .transaction_metrics_active
                .store(false, Ordering::Relaxed);
        }
        if start_gate.is_some() {
            metrics
                .benchmark_generator_state
                .store(BenchmarkGeneratorState::Waiting as u8, Ordering::Release);
        }
        runtime::Handle::current().spawn(
            Self {
                sender,
                rng: StdRng::seed_from_u64(seed as u64),
                parameters,
                node_public_config,
                metrics,
                start_gate,
            }
            .run(),
        );
    }

    pub async fn run(mut self) {
        let load = self.parameters.load;
        let max_transactions_per_block_interval = load.div_ceil(Self::BATCHES_IN_SECOND);
        let coordinated_start = self.start_gate.is_some();
        // Add a small extra delay proportional to committee size to give
        // connections time to come up in normal production/ungated runs.
        // Calibrated so n=100 lands at ~15s total when initial_delay is the
        // 10s default. A coordinated benchmark gate is released only after
        // topology and clock activation, so it deliberately skips this
        // second warmup and starts the shared finite window immediately.
        let initial_delay_plus_extra_delay = self.parameters.initial_delay
            + Duration::from_millis(
                (self.node_public_config.identifiers.len() as f64 / 100.0 * 5000.0) as u64,
            );
        let benchmark_duration = self.parameters.benchmark_duration;

        // When the orchestrator sets a finite benchmark window, gate metrics
        // off while awaiting either the coordinated release or the normal
        // warmup so `benchmark_duration` counts only active submissions.
        let finite_window_description = match benchmark_duration {
            Some(d) => format!(", stopping after {} sec of generation", d.as_secs()),
            None => String::new(),
        };
        if coordinated_start {
            tracing::info!(
                "Starting tx generator behind the coordinated release gate; \
                targeting {load} tx/s immediately after release \
                (up to {max_transactions_per_block_interval} transactions every {} ms){}",
                Self::TARGET_BLOCK_INTERVAL.as_millis(),
                finite_window_description,
            );
        } else {
            tracing::info!(
                "Starting tx generator. After {} sec, \
                targeting {load} tx/s \
                (up to {max_transactions_per_block_interval} transactions every {} ms){}",
                initial_delay_plus_extra_delay.as_secs(),
                Self::TARGET_BLOCK_INTERVAL.as_millis(),
                finite_window_description,
            );
        }
        let max_block_size = self.node_public_config.parameters.max_block_size;
        let target_block_size = min(max_block_size, max_transactions_per_block_interval);

        let tx_size = self.parameters.transaction_size;
        let mode = &self.parameters.transaction_mode;
        self.metrics.transaction_mode_info.set(match mode {
            TransactionMode::AllZero => 0,
            TransactionMode::Random => 1,
        });

        let mut counter: u64 = 0;
        let mut random: u64 = self.rng.gen();
        let mut load_carry = 0;
        // Pre-allocated payload buffer reused in AllZero mode.
        let zeros = vec![0u8; tx_size - 8 - 8];

        let coordinated_window = if let Some(mut start_gate) = self.start_gate.take() {
            match start_gate.wait_for(Option::is_some).await {
                Ok(window) => *window,
                Err(_) => {
                    self.fail_coordinated_window();
                    return;
                }
            }
        } else {
            None
        };

        if !coordinated_start {
            runtime::sleep(initial_delay_plus_extra_delay).await;
        }

        let generation_start = coordinated_window
            .map(|window| window.start)
            .unwrap_or_else(Instant::now);
        let generation_end = coordinated_window.map(|window| window.end).or_else(|| {
            benchmark_duration.and_then(|duration| generation_start.checked_add(duration))
        });
        if Instant::now() < generation_start {
            sleep_until(generation_start).await;
        }

        // Anchor every coordinated generator to the same absolute tick grid.
        // MissedTickBehavior::Skip prevents a delayed task from bursting old
        // batches, and comparing the scheduled tick strictly with `end`
        // excludes the historical extra batch at t == duration.
        let mut interval = interval_at(generation_start, Self::TARGET_BLOCK_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Open the active metrics window: anchor `benchmark_duration`'s
        // clock to this instant so the TPS denominator only counts seconds
        // during which transactions are actually being submitted.
        let active_start_micros = generation_start
            .saturating_duration_since(self.metrics.validator_start)
            .as_micros()
            .min(u64::MAX as u128) as u64;
        self.metrics
            .active_start_micros
            .store(active_start_micros, Ordering::Relaxed);
        self.metrics.metrics_active.store(true, Ordering::Relaxed);
        self.metrics
            .transaction_metrics_active
            .store(true, Ordering::Relaxed);
        if coordinated_start {
            self.metrics
                .benchmark_generator_state
                .store(BenchmarkGeneratorState::Active as u8, Ordering::Release);
        }

        'generation: loop {
            let scheduled_tick = interval.tick().await;
            if generation_end.is_some_and(|end| scheduled_tick >= end) {
                break;
            }
            let timestamp = (timestamp_utc().as_millis() as u64).to_le_bytes();
            let transactions_per_block_interval =
                Self::transactions_for_interval(load, &mut load_carry);

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

                if block_size >= max_block_size {
                    let submitted = block.len() as u64;
                    match self.submit_before_end(block.clone(), generation_end).await {
                        SubmissionOutcome::Submitted => {}
                        SubmissionOutcome::Cutoff => break 'generation,
                        SubmissionOutcome::Closed => {
                            self.fail_coordinated_window();
                            return;
                        }
                    }
                    self.metrics.submitted_transactions.inc_by(submitted);
                    self.metrics
                        .submitted_transactions_bytes
                        .inc_by(submitted.saturating_mul(tx_size as u64));
                    block.clear();
                    block_size = 0;
                }
            }
            tracing::debug!("Generator send {} transactions", block.len());
            if !block.is_empty() {
                let submitted = block.len() as u64;
                match self.submit_before_end(block, generation_end).await {
                    SubmissionOutcome::Submitted => {}
                    SubmissionOutcome::Cutoff => break 'generation,
                    SubmissionOutcome::Closed => {
                        self.fail_coordinated_window();
                        return;
                    }
                }
                self.metrics.submitted_transactions.inc_by(submitted);
                self.metrics
                    .submitted_transactions_bytes
                    .inc_by(submitted.saturating_mul(tx_size as u64));
            }
        }

        self.metrics.metrics_active.store(false, Ordering::Release);
        if coordinated_start {
            // The local benchmark keeps transaction observation open during
            // its bounded drain and closes it after every offered transaction
            // is observed (or reports an explicit incomplete drain).
            self.metrics
                .benchmark_generator_state
                .store(BenchmarkGeneratorState::Finished as u8, Ordering::Release);
        } else {
            self.metrics
                .transaction_metrics_active
                .store(false, Ordering::Release);
        }
    }

    fn fail_coordinated_window(&self) {
        self.metrics.metrics_active.store(false, Ordering::Release);
        self.metrics
            .transaction_metrics_active
            .store(false, Ordering::Release);
        if self.start_gate.is_some()
            || BenchmarkGeneratorState::from_u8(
                self.metrics
                    .benchmark_generator_state
                    .load(Ordering::Acquire),
            ) != BenchmarkGeneratorState::Disabled
        {
            self.metrics
                .benchmark_generator_state
                .store(BenchmarkGeneratorState::Failed as u8, Ordering::Release);
        }
    }

    pub fn extract_timestamp(transaction: &Transaction) -> Duration {
        let bytes = transaction.as_bytes()[0..8]
            .try_into()
            .expect("Transactions should be at least 8 bytes");
        Duration::from_millis(u64::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::atomic::Ordering,
        time::Duration,
    };

    use prometheus::Registry;
    use tokio::{
        sync::{mpsc, watch},
        time::{Instant, timeout},
    };

    use super::TransactionGenerator;
    use crate::{
        config::{NodePublicConfig, Parameters},
        metrics::{BenchmarkGeneratorState, BenchmarkTransactionWindow, Metrics},
    };

    #[test]
    fn transactions_for_interval_matches_target_rate() {
        for load in [0, 1, 7, 19, 20, 21, 25, 99, 100, 101] {
            let mut carry = 0;
            let mut generated = 0;
            for _ in 0..TransactionGenerator::BATCHES_IN_SECOND {
                generated += TransactionGenerator::transactions_for_interval(load, &mut carry);
            }
            assert_eq!(generated, load, "load={load}");
            assert_eq!(carry, 0, "load={load}");
        }
    }

    #[tokio::test]
    async fn ungated_finite_generator_keeps_metrics_closed_during_warmup() {
        let (metrics, _reporter) = Metrics::new(&Registry::new(), None, None, None);
        metrics.metrics_active.store(true, Ordering::Relaxed);
        let (sender, mut receiver) = mpsc::channel(1);
        let mut parameters = Parameters::almost_default(1);
        parameters.benchmark_duration = Some(Duration::from_secs(1));
        parameters.initial_delay = Duration::from_secs(60);
        let public_config =
            NodePublicConfig::new_for_benchmarks(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], None);

        TransactionGenerator::start(sender, 0, parameters, public_config, metrics.clone());

        assert!(!metrics.metrics_active.load(Ordering::Relaxed));
        assert!(
            timeout(Duration::from_millis(100), receiver.recv())
                .await
                .is_err(),
            "ungated generator skipped its configured warmup"
        );
        assert!(!metrics.metrics_active.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn coordinated_generator_starts_immediately_after_release() {
        let (metrics, _reporter) = Metrics::new(&Registry::new(), None, None, None);
        let (sender, mut receiver) = mpsc::channel(1);
        let mut parameters = Parameters::almost_default(20);
        parameters.benchmark_duration = Some(Duration::from_secs(1));
        parameters.initial_delay = Duration::from_secs(60);
        let public_config =
            NodePublicConfig::new_for_benchmarks(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], None);
        let (release, gate) = watch::channel(None);

        TransactionGenerator::start_with_gate(
            sender,
            0,
            parameters,
            public_config,
            metrics.clone(),
            Some(gate),
        );
        assert!(
            timeout(Duration::from_millis(100), receiver.recv())
                .await
                .is_err(),
            "generator submitted before the coordinated release"
        );
        assert!(!metrics.metrics_active.load(Ordering::Relaxed));

        let start = Instant::now() + Duration::from_millis(10);
        release.send_replace(BenchmarkTransactionWindow::new(
            start,
            start + Duration::from_secs(1),
        ));
        timeout(Duration::from_millis(500), receiver.recv())
            .await
            .expect("released generator waited for the configured initial delay")
            .expect("released generator channel closed");
        assert!(metrics.metrics_active.load(Ordering::Relaxed));

        assert!(
            timeout(Duration::from_millis(20), receiver.recv())
                .await
                .is_err(),
            "released generator emitted a stale-interval catch-up burst"
        );
        timeout(Duration::from_millis(250), receiver.recv())
            .await
            .expect("released generator did not establish a fresh cadence")
            .expect("released generator channel closed");
    }

    #[tokio::test]
    async fn coordinated_window_counts_every_send_and_excludes_end_tick() {
        let (metrics, _reporter) = Metrics::new(&Registry::new(), None, None, None);
        let (sender, mut receiver) = mpsc::channel(16);
        let mut parameters = Parameters::almost_default(20);
        parameters.benchmark_duration = Some(Duration::from_secs(60));
        parameters.initial_delay = Duration::from_secs(60);
        let public_config =
            NodePublicConfig::new_for_benchmarks(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], None);
        let (release, gate) = watch::channel(None);

        TransactionGenerator::start_with_gate(
            sender,
            0,
            parameters,
            public_config,
            metrics.clone(),
            Some(gate),
        );
        assert_eq!(
            BenchmarkGeneratorState::from_u8(
                metrics.benchmark_generator_state.load(Ordering::Acquire)
            ),
            BenchmarkGeneratorState::Waiting
        );
        assert_eq!(metrics.submitted_transactions.get(), 0);

        let start = Instant::now() + Duration::from_millis(20);
        let end = start + Duration::from_millis(200);
        release.send_replace(BenchmarkTransactionWindow::new(start, end));
        timeout(Duration::from_secs(1), async {
            loop {
                if BenchmarkGeneratorState::from_u8(
                    metrics.benchmark_generator_state.load(Ordering::Acquire),
                ) == BenchmarkGeneratorState::Finished
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("coordinated generator did not finish its absolute window");

        let mut received = 0usize;
        while let Ok(block) = receiver.try_recv() {
            received += block.len();
        }
        assert_eq!(received, 4, "ticks must be start, +50, +100, +150 ms");
        assert_eq!(metrics.submitted_transactions.get(), 4);
        assert_eq!(metrics.submitted_transactions_bytes.get(), 4 * 512);
        assert!(!metrics.metrics_active.load(Ordering::Acquire));
        assert!(metrics.transaction_metrics_active.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn coordinated_window_cancels_a_backpressured_send_at_cutoff() {
        let (metrics, _reporter) = Metrics::new(&Registry::new(), None, None, None);
        // The first tick fills this channel. The next scheduled pre-end send
        // must remain pending until the common cutoff and then be cancelled,
        // not counted as offered work after the window.
        let (sender, mut receiver) = mpsc::channel(1);
        let mut parameters = Parameters::almost_default(20);
        parameters.benchmark_duration = Some(Duration::from_secs(60));
        let public_config =
            NodePublicConfig::new_for_benchmarks(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], None);
        let (release, gate) = watch::channel(None);
        TransactionGenerator::start_with_gate(
            sender,
            0,
            parameters,
            public_config,
            metrics.clone(),
            Some(gate),
        );

        let start = Instant::now() + Duration::from_millis(20);
        let end = start + Duration::from_millis(120);
        release.send_replace(BenchmarkTransactionWindow::new(start, end));
        timeout(Duration::from_secs(1), async {
            loop {
                if BenchmarkGeneratorState::from_u8(
                    metrics.benchmark_generator_state.load(Ordering::Acquire),
                ) == BenchmarkGeneratorState::Finished
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("backpressured generator did not finish at the common cutoff");

        assert_eq!(metrics.submitted_transactions.get(), 1);
        assert_eq!(receiver.recv().await.unwrap().len(), 1);
        assert!(receiver.try_recv().is_err());
    }
}
