// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use ahash::AHashSet;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use tokio::{
    sync::{
        Mutex, mpsc,
        mpsc::{Receiver, Sender},
    },
    task::JoinHandle,
    time::{Instant, sleep_until},
};

use crate::{
    committee::Committee,
    crypto::TransactionsCommitment,
    decoder,
    metrics::Metrics,
    types::{AuthorityIndex, BlockReference, ReconstructedTransactionData, RoundNumber, Shard},
};

const EVICTION_TIMEOUT: Duration = Duration::from_secs(1);
const SEND_TO_CORE_TIMEOUT: Duration = Duration::from_millis(20);
const NUMBER_OF_RECONSTRUCTION_WORKERS: usize = 5;

type ReconstructionJob = (BlockReference, TransactionsCommitment, Vec<Option<Shard>>);

/// Message sent from connection handlers to the shard reconstructor.
#[derive(Clone, Debug)]
pub enum ShardMessage {
    /// A shard arrived for a block.
    Shard {
        block_reference: BlockReference,
        shard: Shard,
        shard_index: usize,
        /// Merkle root (transactions commitment) for verification after
        /// reconstruction.
        transactions_commitment: TransactionsCommitment,
    },
    /// Full block with transactions arrived — stop collecting shards.
    FullBlock(BlockReference),
}

/// Collects shards for a single block until reconstruction threshold is met.
struct ShardAccumulator {
    transactions_commitment: TransactionsCommitment,
    shards: Vec<Option<Shard>>,
    shard_count: usize,
}

impl ShardAccumulator {
    fn new(
        transactions_commitment: TransactionsCommitment,
        committee_size: usize,
        initial_shard: Option<(Shard, usize)>,
    ) -> Self {
        let mut shards = vec![None; committee_size];
        let mut shard_count = 0;
        if let Some((shard, index)) = initial_shard {
            shards[index] = Some(shard);
            shard_count = 1;
        }
        Self {
            transactions_commitment,
            shards,
            shard_count,
        }
    }

    fn update_with_shard(&mut self, shard: Shard, shard_index: usize) {
        if self.shards[shard_index].is_none() {
            self.shards[shard_index] = Some(shard);
            self.shard_count += 1;
        }
    }

    fn is_ready(&self, info_length: usize) -> bool {
        self.shard_count >= info_length
    }
}

/// Result from a reconstruction worker (success or failure).
struct ReconstructionResult {
    block_reference: BlockReference,
    data: Option<ReconstructedTransactionData>,
}

/// Type alias for reconstructed transaction data sent to core.
pub type DecodedBlocks = Vec<ReconstructedTransactionData>;

/// Public handle for the running shard reconstructor.
pub struct ShardReconstructorHandle {
    shard_message_sender: Sender<Vec<ShardMessage>>,
    join_handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl ShardReconstructorHandle {
    pub fn shard_message_sender(&self) -> Sender<Vec<ShardMessage>> {
        self.shard_message_sender.clone()
    }

    pub async fn stop(&self) {
        let mut guard = self.join_handle.lock().await;
        if let Some(handle) = guard.take() {
            handle.abort();
            match handle.await {
                Ok(()) | Err(_) => {}
            }
        }
    }
}

/// Dedicated component that collects shards and decodes blocks off the
/// consensus critical path. Runs as a separate tokio task with a worker pool.
///
/// Decoded blocks are sent via `decoded_tx` channel. A bridge task in
/// `net_sync.rs` reads from the corresponding receiver and forwards to Core.
struct ShardReconstructor {
    info_length: usize,
    committee_size: usize,
    own_id: AuthorityIndex,
    committee: Arc<Committee>,
    metrics: Arc<Metrics>,
    // Shard collection state
    shard_accumulators: BTreeMap<BlockReference, ShardAccumulator>,
    processed_blocks: BTreeSet<BlockReference>,
    reconstruction_queue: AHashSet<BlockReference>,
    // Incoming shard messages (batched)
    shard_rx: Receiver<Vec<ShardMessage>>,
    // Worker pool channels
    ready_tx: Sender<ReconstructionJob>,
    ready_rx: Arc<Mutex<Receiver<ReconstructionJob>>>,
    result_tx: Sender<ReconstructionResult>,
    result_rx: Receiver<ReconstructionResult>,
    // Decoded blocks waiting to be flushed to core
    pending_decoded: DecodedBlocks,
    // Output channel to core bridge
    decoded_tx: Sender<DecodedBlocks>,
    // Eviction
    gc_round: Arc<AtomicU32>,
    // Highest round seen from incoming shard messages (for lag metric)
    highest_seen_round: RoundNumber,
}

/// Start a shard reconstructor and return the public handle.
///
/// `decoded_tx` is used to send batches of decoded blocks to a bridge task
/// that integrates them into the core thread.
pub fn start_shard_reconstructor(
    committee: Arc<Committee>,
    own_id: AuthorityIndex,
    metrics: Arc<Metrics>,
    decoded_tx: Sender<DecodedBlocks>,
    gc_round: Arc<AtomicU32>,
) -> Arc<ShardReconstructorHandle> {
    ShardReconstructor::start(committee, own_id, metrics, decoded_tx, gc_round)
}

impl ShardReconstructor {
    fn start(
        committee: Arc<Committee>,
        own_id: AuthorityIndex,
        metrics: Arc<Metrics>,
        decoded_tx: Sender<DecodedBlocks>,
        gc_round: Arc<AtomicU32>,
    ) -> Arc<ShardReconstructorHandle> {
        let info_length = committee.info_length();
        let committee_size = committee.len();

        let (shard_tx, shard_rx) = mpsc::channel(100_000);
        let (ready_tx, ready_rx) = mpsc::channel(1000);
        let (result_tx, result_rx) = mpsc::channel(1000);

        let mut reconstructor = Self {
            info_length,
            committee_size,
            own_id,
            committee,
            metrics,
            shard_accumulators: BTreeMap::new(),
            processed_blocks: BTreeSet::new(),
            reconstruction_queue: AHashSet::new(),
            shard_rx,
            ready_tx,
            ready_rx: Arc::new(Mutex::new(ready_rx)),
            result_tx,
            result_rx,
            pending_decoded: Vec::new(),
            decoded_tx,
            gc_round,
            highest_seen_round: 0,
        };

        let join_handle = tokio::spawn(async move {
            reconstructor.run().await;
        });

        Arc::new(ShardReconstructorHandle {
            shard_message_sender: shard_tx,
            join_handle: tokio::sync::Mutex::new(Some(join_handle)),
        })
    }

    fn start_workers(&self) {
        for _ in 0..NUMBER_OF_RECONSTRUCTION_WORKERS {
            let ready_rx = Arc::clone(&self.ready_rx);
            let result_tx = self.result_tx.clone();
            let committee = self.committee.clone();
            let own_id = self.own_id;
            let metrics = self.metrics.clone();

            tokio::spawn(async move {
                let mut encoder =
                    ReedSolomonEncoder::new(2, 4, 2).expect("Encoder should be created");
                let mut rs_decoder =
                    ReedSolomonDecoder::new(2, 4, 2).expect("Decoder should be created");

                loop {
                    let job = {
                        let mut rx = ready_rx.lock().await;
                        rx.recv().await
                    };

                    match job {
                        Some((block_reference, transactions_commitment, shards)) => {
                            let decoded = decoder::decode_shards(
                                &mut rs_decoder,
                                &committee,
                                &mut encoder,
                                transactions_commitment,
                                &shards,
                                own_id,
                            );

                            let data = if let Some((mut transaction_data, mut shard_data)) = decoded
                            {
                                metrics.shard_reconstruction_success_total.inc();
                                tracing::debug!("Worker reconstructed block {:?}", block_reference);
                                // Pre-serialize off the core thread.
                                transaction_data.preserialize();
                                shard_data.preserialize();
                                Some(ReconstructedTransactionData {
                                    block_reference,
                                    transaction_data,
                                    shard_data,
                                })
                            } else {
                                metrics.shard_reconstruction_failed_total.inc();
                                tracing::warn!(
                                    "Worker failed to reconstruct block {:?}",
                                    block_reference
                                );
                                None
                            };

                            if result_tx
                                .send(ReconstructionResult {
                                    block_reference,
                                    data,
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            });
        }
    }

    async fn run(&mut self) {
        self.start_workers();
        self.update_backlog_metrics();

        let flush_timeout = sleep_until(Instant::now() + SEND_TO_CORE_TIMEOUT);
        tokio::pin!(flush_timeout);

        let eviction_timeout = sleep_until(Instant::now() + EVICTION_TIMEOUT);
        tokio::pin!(eviction_timeout);

        loop {
            tokio::select! {
                msgs = self.shard_rx.recv() => {
                    match msgs {
                        Some(msgs) => {
                            for msg in msgs {
                                self.handle_message(msg).await;
                            }
                        }
                        None => {
                            tracing::debug!("Shard channel closed, shutting down reconstructor");
                            break;
                        }
                    }
                }

                Some(result) = self.result_rx.recv() => {
                    self.handle_reconstruction_result(result);
                }

                () = &mut flush_timeout => {
                    self.flush_to_core().await;
                    flush_timeout.as_mut().reset(Instant::now() + SEND_TO_CORE_TIMEOUT);
                }

                () = &mut eviction_timeout => {
                    self.evict_memory();
                    eviction_timeout.as_mut().reset(Instant::now() + EVICTION_TIMEOUT);
                }
            }
        }

        // Final flush on shutdown
        self.flush_to_core().await;
    }

    async fn handle_message(&mut self, msg: ShardMessage) {
        match msg {
            ShardMessage::Shard {
                block_reference,
                shard,
                shard_index,
                transactions_commitment,
            } => {
                if transactions_commitment == TransactionsCommitment::default() {
                    return;
                }
                if block_reference.round > self.highest_seen_round {
                    self.highest_seen_round = block_reference.round;
                }
                if self.processed_blocks.contains(&block_reference)
                    || self.reconstruction_queue.contains(&block_reference)
                {
                    return;
                }
                let gc = self.gc_round.load(Ordering::Relaxed);
                if block_reference.round < gc as RoundNumber {
                    return;
                }

                let acc = self
                    .shard_accumulators
                    .entry(block_reference)
                    .or_insert_with(|| {
                        ShardAccumulator::new(transactions_commitment, self.committee_size, None)
                    });
                acc.update_with_shard(shard, shard_index);

                if acc.is_ready(self.info_length) {
                    let acc = self
                        .shard_accumulators
                        .remove(&block_reference)
                        .expect("just checked");
                    self.reconstruction_queue.insert(block_reference);
                    if self
                        .ready_tx
                        .send((block_reference, acc.transactions_commitment, acc.shards))
                        .await
                        .is_err()
                    {
                        tracing::warn!("Worker channel closed");
                    } else {
                        self.metrics.shard_reconstruction_jobs_total.inc();
                    }
                }
            }
            ShardMessage::FullBlock(block_reference) => {
                self.processed_blocks.insert(block_reference);
                let cancelled = self.shard_accumulators.remove(&block_reference).is_some()
                    || self.reconstruction_queue.remove(&block_reference);
                if cancelled {
                    self.metrics.shard_reconstruction_cancelled_total.inc();
                }
            }
        }
        self.update_backlog_metrics();
    }

    fn handle_reconstruction_result(&mut self, result: ReconstructionResult) {
        let block_reference = result.block_reference;
        if !self.reconstruction_queue.remove(&block_reference) {
            return;
        }

        if let Some(data) = result.data {
            self.processed_blocks.insert(block_reference);
            self.pending_decoded.push(data);
        }
        // On failure (block == None): the entry is removed from
        // reconstruction_queue so future shards can retry accumulation.
        self.update_backlog_metrics();
    }

    async fn flush_to_core(&mut self) {
        if self.pending_decoded.is_empty() {
            return;
        }
        let blocks = std::mem::take(&mut self.pending_decoded);
        self.metrics
            .reconstructed_blocks_total
            .inc_by(blocks.len() as u64);
        for block in &blocks {
            let lag = self
                .highest_seen_round
                .saturating_sub(block.block_reference.round);
            self.metrics.shard_reconstruction_lag.observe(lag as f64);
        }
        if self.decoded_tx.send(blocks).await.is_err() {
            tracing::warn!("Decoded blocks channel closed");
        }
        self.update_backlog_metrics();
    }

    fn evict_memory(&mut self) {
        let gc = self.gc_round.load(Ordering::Relaxed) as RoundNumber;
        if gc == 0 {
            return;
        }
        let threshold = BlockReference {
            round: gc,
            authority: 0,
            digest: Default::default(),
        };
        self.shard_accumulators = self.shard_accumulators.split_off(&threshold);
        self.processed_blocks = self.processed_blocks.split_off(&threshold);
        self.reconstruction_queue.retain(|r| r.round >= gc);
        self.update_backlog_metrics();
    }

    fn update_backlog_metrics(&self) {
        self.metrics
            .shard_reconstruction_pending_accumulators
            .set(self.shard_accumulators.len() as i64);
        self.metrics
            .shard_reconstruction_queued_jobs
            .set(self.reconstruction_queue.len() as i64);
        self.metrics
            .shard_reconstruction_pending_decoded_blocks
            .set(self.pending_decoded.len() as i64);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use prometheus::Registry;
    use reed_solomon_simd::ReedSolomonEncoder;

    use super::*;
    use crate::{
        crypto::Signer,
        dag_state::ConsensusProtocol,
        encoder::ShardEncoder,
        types::{BaseTransaction, Transaction, VerifiedBlock},
    };

    fn make_test_block_and_shards(
        transactions: Vec<BaseTransaction>,
        authority: AuthorityIndex,
        committee: &Committee,
        encoder: &mut ReedSolomonEncoder,
        signer: &Signer,
    ) -> (VerifiedBlock, Vec<Shard>) {
        let info_length = committee.info_length();
        let parity_length = committee.len() - info_length;
        let encoded = encoder.encode_transactions(&transactions, info_length, parity_length);
        let block = VerifiedBlock::new_with_signer(
            authority,
            1,
            vec![],
            None,
            vec![],
            0,
            signer,
            None,
            None,
            vec![],
            transactions,
            Some(encoded.clone()),
            ConsensusProtocol::Starfish,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        (block, encoded)
    }

    // --- Synchronous ShardAccumulator tests ---

    #[test]
    fn accumulator_threshold() {
        let committee_size = 4;
        let signers = Signer::new_for_test(committee_size);
        let committee = Committee::new_for_benchmarks(committee_size);
        let info_length = committee.info_length();

        let mut encoder = ReedSolomonEncoder::new(2, 4, 2).unwrap();
        let transactions = vec![BaseTransaction::Share(Transaction::new(vec![1; 50]))];
        let (block, shards) =
            make_test_block_and_shards(transactions, 0, &committee, &mut encoder, &signers[0]);

        let mut acc = ShardAccumulator::new(block.merkle_root(), committee_size, None);
        assert!(!acc.is_ready(info_length));

        acc.update_with_shard(shards[1].clone(), 1);
        assert!(!acc.is_ready(info_length));

        acc.update_with_shard(shards[2].clone(), 2);
        assert!(acc.is_ready(info_length));
    }

    #[test]
    fn accumulator_duplicate_shard_ignored() {
        let committee_size = 4;
        let signers = Signer::new_for_test(committee_size);
        let committee = Committee::new_for_benchmarks(committee_size);
        let info_length = committee.info_length();

        let mut encoder = ReedSolomonEncoder::new(2, 4, 2).unwrap();
        let transactions = vec![BaseTransaction::Share(Transaction::new(vec![7; 30]))];
        let (block, shards) =
            make_test_block_and_shards(transactions, 0, &committee, &mut encoder, &signers[0]);

        let mut acc = ShardAccumulator::new(block.merkle_root(), committee_size, None);
        acc.update_with_shard(shards[0].clone(), 0);
        acc.update_with_shard(shards[0].clone(), 0); // duplicate
        assert!(!acc.is_ready(info_length));
    }

    // --- Async ShardReconstructor tests ---

    #[tokio::test]
    async fn reconstruction_end_to_end() {
        let committee_size = 4;
        let signers = Signer::new_for_test(committee_size);
        let committee = Committee::new_for_benchmarks(committee_size);
        let info_length = committee.info_length();
        let own_id: AuthorityIndex = 0;

        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(&registry, Some(&committee), None, None);

        let (decoded_tx, mut decoded_rx) = mpsc::channel(100);
        let gc_round = Arc::new(AtomicU32::new(0));

        let handle =
            start_shard_reconstructor(committee.clone(), own_id, metrics, decoded_tx, gc_round);

        let mut encoder = ReedSolomonEncoder::new(2, 4, 2).unwrap();
        let transactions = vec![BaseTransaction::Share(Transaction::new(vec![7; 200]))];
        let (block, shards) = make_test_block_and_shards(
            transactions.clone(),
            1,
            &committee,
            &mut encoder,
            &signers[1],
        );

        let block_ref = *block.reference();
        let sender = handle.shard_message_sender();

        let batch: Vec<_> = shards[..info_length]
            .iter()
            .enumerate()
            .map(|(i, shard)| ShardMessage::Shard {
                block_reference: block_ref,
                shard: shard.clone(),
                shard_index: i,
                transactions_commitment: block.merkle_root(),
            })
            .collect();
        sender.send(batch).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(5), decoded_rx.recv()).await;
        assert!(
            result.is_ok(),
            "should receive decoded blocks within timeout"
        );
        let decoded_items = result.unwrap().unwrap();
        assert!(!decoded_items.is_empty());

        let item = &decoded_items[0];
        assert_eq!(
            item.block_reference, block_ref,
            "block reference should match"
        );
        assert_eq!(
            item.shard_data.transactions_commitment(),
            block.merkle_root(),
            "merkle root should match"
        );
        assert_eq!(
            item.transaction_data.transactions(),
            &transactions,
            "transactions should match"
        );

        handle.stop().await;
    }

    #[tokio::test]
    async fn full_block_cancels_shard_collection() {
        let committee_size = 4;
        let signers = Signer::new_for_test(committee_size);
        let committee = Committee::new_for_benchmarks(committee_size);
        let own_id: AuthorityIndex = 0;

        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(&registry, Some(&committee), None, None);

        let (decoded_tx, mut decoded_rx) = mpsc::channel(100);
        let gc_round = Arc::new(AtomicU32::new(0));

        let handle =
            start_shard_reconstructor(committee.clone(), own_id, metrics, decoded_tx, gc_round);

        let mut encoder = ReedSolomonEncoder::new(2, 4, 2).unwrap();
        let transactions = vec![BaseTransaction::Share(Transaction::new(vec![9; 50]))];
        let (block, shards) =
            make_test_block_and_shards(transactions, 1, &committee, &mut encoder, &signers[1]);

        let block_ref = *block.reference();
        let sender = handle.shard_message_sender();

        sender
            .send(vec![ShardMessage::Shard {
                block_reference: block_ref,
                shard: shards[0].clone(),
                shard_index: 0,
                transactions_commitment: block.merkle_root(),
            }])
            .await
            .unwrap();

        sender
            .send(vec![ShardMessage::FullBlock(block_ref)])
            .await
            .unwrap();

        let remaining: Vec<_> = shards
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, shard)| ShardMessage::Shard {
                block_reference: block_ref,
                shard: shard.clone(),
                shard_index: i,
                transactions_commitment: block.merkle_root(),
            })
            .collect();
        sender.send(remaining).await.unwrap();

        let result = tokio::time::timeout(Duration::from_millis(200), decoded_rx.recv()).await;
        assert!(
            result.is_err(),
            "should NOT receive decoded blocks after FullBlock cancellation"
        );

        handle.stop().await;
    }
}
