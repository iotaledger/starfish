// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use ahash::AHashSet;

use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use tokio::{
    sync::{
        mpsc,
        mpsc::{Receiver, Sender},
        Mutex,
    },
    task::JoinHandle,
    time::{sleep_until, Instant},
};

use crate::{
    committee::Committee,
    data::Data,
    decoder::CachedStatementBlockDecoder,
    metrics::Metrics,
    types::{
        AuthorityIndex, BlockReference, CachedStatementBlock, RoundNumber, Shard,
        VerifiedStatementBlock,
    },
};

const EVICTION_TIMEOUT: Duration = Duration::from_secs(1);
const SEND_TO_CORE_TIMEOUT: Duration = Duration::from_millis(20);
const NUMBER_OF_RECONSTRUCTION_WORKERS: usize = 5;

/// Message sent from connection handlers to the shard reconstructor.
#[derive(Clone, Debug)]
pub enum ShardMessage {
    /// A shard arrived for a block.
    Shard {
        block_reference: BlockReference,
        shard: Shard,
        shard_index: usize,
        /// Block metadata needed to initialize the accumulator.
        block_template: VerifiedStatementBlock,
    },
    /// Full block with statements arrived — stop collecting shards.
    FullBlock(BlockReference),
}

/// Collects shards for a single block until reconstruction threshold is met.
struct ShardAccumulator {
    cached_block: CachedStatementBlock,
    shard_count: usize,
}

impl ShardAccumulator {
    fn new(block_template: &VerifiedStatementBlock, committee_size: usize) -> Self {
        Self {
            cached_block: block_template.to_cached_block(committee_size),
            shard_count: if block_template.encoded_shard().is_some() {
                1
            } else {
                0
            },
        }
    }

    fn update_with_shard(&mut self, shard: Shard, shard_index: usize) {
        if self.cached_block.encoded_statements()[shard_index].is_none() {
            self.cached_block.add_encoded_shard(shard_index, shard);
            self.shard_count += 1;
        }
    }

    fn is_ready(&self, info_length: usize) -> bool {
        self.shard_count >= info_length
    }
}

/// Result of a successful reconstruction worker.
struct ReconstructedBlock {
    block_reference: BlockReference,
    storage_block: VerifiedStatementBlock,
}

/// Type alias for decoded blocks sent to core.
pub type DecodedBlocks = Vec<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>;

/// Public handle for the running shard reconstructor.
pub struct ShardReconstructorHandle {
    shard_message_sender: Sender<ShardMessage>,
    join_handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl ShardReconstructorHandle {
    pub fn shard_message_sender(&self) -> Sender<ShardMessage> {
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
    // Incoming shard messages
    shard_rx: Receiver<ShardMessage>,
    // Worker pool channels
    ready_tx: Sender<(BlockReference, CachedStatementBlock)>,
    ready_rx: Arc<Mutex<Receiver<(BlockReference, CachedStatementBlock)>>>,
    result_tx: Sender<ReconstructedBlock>,
    result_rx: Receiver<ReconstructedBlock>,
    // Decoded blocks waiting to be flushed to core
    pending_decoded: DecodedBlocks,
    // Output channel to core bridge
    decoded_tx: Sender<DecodedBlocks>,
    // Eviction
    gc_round: Arc<AtomicU64>,
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
    gc_round: Arc<AtomicU64>,
) -> Arc<ShardReconstructorHandle> {
    ShardReconstructor::start(committee, own_id, metrics, decoded_tx, gc_round)
}

impl ShardReconstructor {
    fn start(
        committee: Arc<Committee>,
        own_id: AuthorityIndex,
        metrics: Arc<Metrics>,
        decoded_tx: Sender<DecodedBlocks>,
        gc_round: Arc<AtomicU64>,
    ) -> Arc<ShardReconstructorHandle> {
        let info_length = committee.info_length();
        let committee_size = committee.len();

        let (shard_tx, shard_rx) = mpsc::channel(4096);
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
                let mut decoder =
                    ReedSolomonDecoder::new(2, 4, 2).expect("Decoder should be created");

                loop {
                    let job = {
                        let mut rx = ready_rx.lock().await;
                        rx.recv().await
                    };

                    match job {
                        Some((block_reference, cached_block)) => {
                            let result = decoder.decode_shards(
                                &committee,
                                &mut encoder,
                                cached_block,
                                own_id,
                            );

                            if let Some(storage_block) = result {
                                metrics.reconstructed_blocks_total.inc();
                                metrics.shard_reconstruction_success_total.inc();
                                tracing::debug!("Worker reconstructed block {:?}", block_reference);
                                if result_tx
                                    .send(ReconstructedBlock {
                                        block_reference,
                                        storage_block,
                                    })
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            } else {
                                metrics.shard_reconstruction_failed_total.inc();
                                tracing::warn!(
                                    "Worker failed to reconstruct block {:?}",
                                    block_reference
                                );
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
                msg = self.shard_rx.recv() => {
                    match msg {
                        Some(msg) => self.handle_message(msg).await,
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
                block_template,
            } => {
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
                    .or_insert_with(|| ShardAccumulator::new(&block_template, self.committee_size));
                acc.update_with_shard(shard, shard_index);

                if acc.is_ready(self.info_length) {
                    let acc = self
                        .shard_accumulators
                        .remove(&block_reference)
                        .expect("just checked");
                    self.reconstruction_queue.insert(block_reference);
                    if self
                        .ready_tx
                        .send((block_reference, acc.cached_block))
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

    fn handle_reconstruction_result(&mut self, result: ReconstructedBlock) {
        let block_reference = result.block_reference;
        if !self.reconstruction_queue.remove(&block_reference) {
            return;
        }
        self.processed_blocks.insert(block_reference);

        let storage_block = result.storage_block;
        let transmission_block = storage_block.from_storage_to_transmission(self.own_id);
        self.pending_decoded
            .push((Data::new(storage_block), Data::new(transmission_block)));
        self.update_backlog_metrics();
    }

    async fn flush_to_core(&mut self) {
        if self.pending_decoded.is_empty() {
            return;
        }
        let blocks = std::mem::take(&mut self.pending_decoded);
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
        // split_off at the minimum BlockReference for gc round — O(log n)
        let threshold = BlockReference {
            round: gc,
            authority: 0,
            digest: Default::default(),
        };
        self.shard_accumulators = self.shard_accumulators.split_off(&threshold);
        self.processed_blocks = self.processed_blocks.split_off(&threshold);
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
    use super::*;
    use crate::block_store::ConsensusProtocol;
    use crate::crypto::Signer;
    use crate::encoder::ShardEncoder;
    use crate::types::{BaseStatement, Transaction};
    use prometheus::Registry;
    use reed_solomon_simd::ReedSolomonEncoder;
    use std::time::Duration;

    fn make_test_block_and_shards(
        statements: Vec<BaseStatement>,
        authority: AuthorityIndex,
        committee: &Committee,
        encoder: &mut ReedSolomonEncoder,
        signer: &Signer,
    ) -> (VerifiedStatementBlock, Vec<Shard>) {
        let info_length = committee.info_length();
        let parity_length = committee.len() - info_length;
        let encoded = encoder.encode_statements(statements.clone(), info_length, parity_length);
        let block = VerifiedStatementBlock::new_with_signer(
            authority,
            1,
            vec![],
            vec![],
            0,
            false,
            signer,
            statements,
            Some(encoded.clone()),
            ConsensusProtocol::Starfish,
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
        let info_length = committee.info_length(); // 2

        let mut encoder = ReedSolomonEncoder::new(2, 4, 2).unwrap();
        let statements = vec![BaseStatement::Share(Transaction::new(vec![1; 50]))];
        let (block, shards) =
            make_test_block_and_shards(statements, 0, &committee, &mut encoder, &signers[0]);

        // new_with_signer sets encoded_shard to None, so initial shard_count = 0
        let mut acc = ShardAccumulator::new(&block, committee_size);
        assert!(!acc.is_ready(info_length));

        acc.update_with_shard(shards[1].clone(), 1);
        assert!(!acc.is_ready(info_length)); // 1 < info_length=2

        acc.update_with_shard(shards[2].clone(), 2);
        assert!(acc.is_ready(info_length)); // 2 == info_length
    }

    #[test]
    fn accumulator_duplicate_shard_ignored() {
        let committee_size = 4;
        let signers = Signer::new_for_test(committee_size);
        let committee = Committee::new_for_benchmarks(committee_size);
        let info_length = committee.info_length();

        let mut encoder = ReedSolomonEncoder::new(2, 4, 2).unwrap();
        let statements = vec![BaseStatement::Share(Transaction::new(vec![7; 30]))];
        let (block, shards) =
            make_test_block_and_shards(statements, 0, &committee, &mut encoder, &signers[0]);

        let mut acc = ShardAccumulator::new(&block, committee_size);
        acc.update_with_shard(shards[0].clone(), 0);
        acc.update_with_shard(shards[0].clone(), 0); // duplicate — should not increment
        assert!(!acc.is_ready(info_length)); // still only 1 unique shard
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
        let (metrics, _reporter) = Metrics::new(&registry, Some(&committee), None);

        let (decoded_tx, mut decoded_rx) = mpsc::channel(100);
        let gc_round = Arc::new(AtomicU64::new(0));

        let handle =
            start_shard_reconstructor(committee.clone(), own_id, metrics, decoded_tx, gc_round);

        let mut encoder = ReedSolomonEncoder::new(2, 4, 2).unwrap();
        let statements = vec![BaseStatement::Share(Transaction::new(vec![7; 200]))];
        let (block, shards) = make_test_block_and_shards(
            statements.clone(),
            1,
            &committee,
            &mut encoder,
            &signers[1],
        );

        let block_ref = *block.reference();
        let sender = handle.shard_message_sender();

        // Send exactly info_length shards to trigger reconstruction
        for i in 0..info_length {
            sender
                .send(ShardMessage::Shard {
                    block_reference: block_ref,
                    shard: shards[i].clone(),
                    shard_index: i,
                    block_template: block.clone(),
                })
                .await
                .unwrap();
        }

        // Wait for decoded block (20ms flush + reconstruction time)
        let result = tokio::time::timeout(Duration::from_secs(5), decoded_rx.recv()).await;
        assert!(
            result.is_ok(),
            "should receive decoded blocks within timeout"
        );
        let decoded_blocks = result.unwrap().unwrap();
        assert!(!decoded_blocks.is_empty());

        let (storage_block, _transmission_block) = &decoded_blocks[0];
        assert!(
            storage_block.merkle_root() == block.merkle_root(),
            "merkle root should match"
        );
        assert!(
            storage_block.statements().as_ref().unwrap() == &statements,
            "statements should match"
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
        let (metrics, _reporter) = Metrics::new(&registry, Some(&committee), None);

        let (decoded_tx, mut decoded_rx) = mpsc::channel(100);
        let gc_round = Arc::new(AtomicU64::new(0));

        let handle =
            start_shard_reconstructor(committee.clone(), own_id, metrics, decoded_tx, gc_round);

        let mut encoder = ReedSolomonEncoder::new(2, 4, 2).unwrap();
        let statements = vec![BaseStatement::Share(Transaction::new(vec![9; 50]))];
        let (block, shards) =
            make_test_block_and_shards(statements, 1, &committee, &mut encoder, &signers[1]);

        let block_ref = *block.reference();
        let sender = handle.shard_message_sender();

        // Send 1 shard (not enough to reconstruct)
        sender
            .send(ShardMessage::Shard {
                block_reference: block_ref,
                shard: shards[0].clone(),
                shard_index: 0,
                block_template: block.clone(),
            })
            .await
            .unwrap();

        // Send FullBlock to cancel collection
        sender
            .send(ShardMessage::FullBlock(block_ref))
            .await
            .unwrap();

        // Send remaining shards — should be ignored
        for i in 1..committee_size {
            sender
                .send(ShardMessage::Shard {
                    block_reference: block_ref,
                    shard: shards[i].clone(),
                    shard_index: i,
                    block_template: block.clone(),
                })
                .await
                .unwrap();
        }

        // Wait briefly — no decoded block should arrive
        let result = tokio::time::timeout(Duration::from_millis(200), decoded_rx.recv()).await;
        assert!(
            result.is_err(),
            "should NOT receive decoded blocks after FullBlock cancellation"
        );

        handle.stop().await;
    }
}
