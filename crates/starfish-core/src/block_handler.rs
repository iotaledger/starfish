// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use ahash::AHashSet;
use tokio::sync::mpsc;

use crate::{
    committee::Committee,
    consensus::{
        CommitMetastate,
        linearizer::{CommittedSubDag, Linearizer},
    },
    crypto::AsBytes,
    dag_state::{DacCertificateVerificationState, DagState, PendingSubDag},
    data::Data,
    metrics::Metrics,
    runtime::{self, TimeInstant},
    syncer::CommitObserver,
    transactions_generator::TransactionGenerator,
    types::{BaseTransaction, BlockReference, RoundNumber, Transaction, VerifiedBlock},
};

pub trait BlockHandler: Send + Sync {
    fn handle_proposal(&mut self, number_transactions: usize);
    fn handle_blocks(&mut self, require_response: bool) -> Vec<BaseTransaction>;
}

const REAL_BLOCK_HANDLER_TXN_SIZE: usize = 512;
const REAL_BLOCK_HANDLER_TXN_GEN_STEP: usize = 32;
const _: () = assert_constants();

#[allow(dead_code)]
const fn assert_constants() {
    if !REAL_BLOCK_HANDLER_TXN_SIZE.is_multiple_of(REAL_BLOCK_HANDLER_TXN_GEN_STEP) {
        panic!("REAL_BLOCK_HANDLER_TXN_SIZE % REAL_BLOCK_HANDLER_TXN_GEN_STEP != 0")
    }
}

pub struct RealBlockHandler {
    receiver: mpsc::Receiver<Vec<Transaction>>,
    pending_transactions: usize,
    // Max number of transactions in block. Depends on committee size.
    max_transactions_per_block: usize,
}

impl RealBlockHandler {
    pub fn new(committee: &Committee) -> (Self, mpsc::Sender<Vec<Transaction>>) {
        let (sender, receiver) = mpsc::channel(1024);
        // Assuming max TPS to be 600.000 and 4 blocks per second
        // (for this TPS), we limit the max number of transactions
        // per block to ensure fast processing
        let max_transactions_per_block = 150 * 1024 / committee.len();
        let this = Self {
            max_transactions_per_block,
            receiver,
            pending_transactions: 0, // todo - need to initialize correctly when loaded from disk
        };
        (this, sender)
    }
}

impl RealBlockHandler {
    fn receive_with_limit(&mut self) -> Option<Vec<Transaction>> {
        if self.pending_transactions >= self.max_transactions_per_block {
            return None;
        }
        let received = self.receiver.try_recv().ok()?;
        let num_transactions = received.len();
        self.pending_transactions += num_transactions;
        tracing::debug!("Received {num_transactions} transactions from generator");
        Some(received)
    }
}

impl BlockHandler for RealBlockHandler {
    fn handle_proposal(&mut self, number_transactions: usize) {
        self.pending_transactions -= number_transactions;
    }

    fn handle_blocks(&mut self, require_response: bool) -> Vec<BaseTransaction> {
        let mut response = vec![];
        if require_response {
            while let Some(data) = self.receive_with_limit() {
                for tx in data {
                    response.push(BaseTransaction::Share(tx));
                }
            }
        }
        response
    }
}

pub struct RealCommitHandler {
    commit_interpreter: Linearizer,
    committed_leaders: Vec<BlockReference>,
    committed_count: usize,
    sequenced_commit_count: usize,
    commit_digest: [u8; 32],
    start_time: TimeInstant,
    metrics: Arc<Metrics>,
}

impl RealCommitHandler {
    pub fn new(committee: Arc<Committee>, metrics: Arc<Metrics>) -> Self {
        Self::new_with_handler(committee, metrics)
    }
}

impl RealCommitHandler {
    pub fn new_with_handler(committee: Arc<Committee>, metrics: Arc<Metrics>) -> Self {
        Self {
            commit_interpreter: Linearizer::new((*committee).clone()),
            committed_leaders: vec![],
            committed_count: 0,
            sequenced_commit_count: 0,
            commit_digest: [0u8; 32],
            start_time: TimeInstant::now(),
            metrics,
        }
    }

    fn transaction_observer(&self, block: Data<VerifiedBlock>) {
        let current_timestamp = runtime::timestamp_utc();
        if let Some(vec) = block.transactions() {
            for transaction in vec {
                let BaseTransaction::Share(transaction) = transaction;
                let tx_submission_timestamp = TransactionGenerator::extract_timestamp(transaction);
                let latency = current_timestamp.saturating_sub(tx_submission_timestamp);

                self.metrics.transaction_committed_latency.observe(latency);
                self.metrics
                    .transaction_committed_latency_squared_micros
                    .inc_by(latency.as_micros().pow(2) as u64);

                self.metrics.sequenced_transactions_total.inc();
                self.metrics
                    .sequenced_transactions_bytes
                    .inc_by(transaction.as_bytes().len() as u64);
            }
        } else {
            tracing::debug!(
                "Transactions from block {:?} are committed, but not available",
                block
            );
        }
    }
    pub fn committed_leaders(&self) -> &Vec<BlockReference> {
        &self.committed_leaders
    }

    fn filter_certified_commit(
        &self,
        dag_state: &DagState,
        commit: &PendingSubDag,
    ) -> Option<PendingSubDag> {
        debug_assert_eq!(commit.0.blocks.len(), commit.1.len());

        let mut certified_blocks = Vec::with_capacity(commit.0.blocks.len());
        let mut acknowledgement_authorities = Vec::with_capacity(commit.1.len());
        for (block, holders) in commit.0.blocks.iter().zip(commit.1.iter()) {
            if block.round() == 0 {
                certified_blocks.push(block.clone());
                acknowledgement_authorities.push(holders.clone());
                continue;
            }

            match dag_state.dac_certificate_state(block.reference()) {
                DacCertificateVerificationState::Verified => {
                    certified_blocks.push(block.clone());
                    acknowledgement_authorities.push(holders.clone());
                }
                DacCertificateVerificationState::Rejected => {
                    tracing::debug!(
                        "Skipping {} from pending certified commit {} after DAC rejection",
                        block.reference(),
                        commit.0.anchor
                    );
                }
                DacCertificateVerificationState::Unchecked => {
                    tracing::debug!(
                        "Waiting for DAC certification of {} before sequencing anchor {}",
                        block.reference(),
                        commit.0.anchor
                    );
                    return None;
                }
            }
        }

        Some((
            CommittedSubDag::new(commit.0.anchor, certified_blocks),
            acknowledgement_authorities,
        ))
    }

    fn drain_certified_commits(
        &self,
        dag_state: &DagState,
        committed: Vec<PendingSubDag>,
    ) -> (Vec<PendingSubDag>, Vec<PendingSubDag>) {
        let mut certified = Vec::new();
        let mut resolved_count = 0;
        for commit in &committed {
            let Some(filtered) = self.filter_certified_commit(dag_state, commit) else {
                break;
            };
            certified.push(filtered);
            resolved_count += 1;
        }
        let pending = committed.into_iter().skip(resolved_count).collect();
        (certified, pending)
    }

    fn drain_available_commits(
        &self,
        dag_state: &DagState,
        committed: Vec<PendingSubDag>,
    ) -> (Vec<CommittedSubDag>, Vec<PendingSubDag>) {
        let mut ready_count = 0;
        let mut resulted_committed = Vec::new();
        for commit in &committed {
            let mut check_availability = true;
            for block in &commit.0.blocks {
                if block.round() > 0 && !dag_state.is_data_available(block.reference()) {
                    tracing::debug!("Block {} is not available", block.reference());
                    check_availability = false;
                    break;
                }
            }
            if check_availability {
                for block in &commit.0.blocks {
                    let updated_block = dag_state
                        .get_storage_block(*block.reference())
                        .expect("We should have the whole sub-dag by now");
                    if updated_block.round() > 0 {
                        self.transaction_observer(updated_block);

                        tracing::debug!(
                            "Latency of transactions from block {} is computed",
                            block.reference()
                        );
                    }
                }
            } else {
                break;
            }
            resulted_committed.push(commit.0.clone());
            ready_count += 1;
        }
        let pending = committed.into_iter().skip(ready_count).collect();
        (resulted_committed, pending)
    }
}

impl CommitObserver for RealCommitHandler {
    fn handle_commit(
        &mut self,
        dag_state: &DagState,
        committed_leaders: Vec<(Data<VerifiedBlock>, Option<CommitMetastate>)>,
    ) -> Vec<CommittedSubDag> {
        let mut committed = self
            .commit_interpreter
            .handle_commit(dag_state, committed_leaders);
        let current_timestamp = runtime::timestamp_utc();
        for commit in &committed {
            self.committed_leaders.push(commit.0.anchor);
            self.committed_count += 1;

            // Chain rolling commit digest: hash(prev_digest || anchor.digest)
            let mut hasher = blake3::Hasher::new();
            hasher.update(&self.commit_digest);
            hasher.update(commit.0.anchor.digest.as_ref());
            self.commit_digest = *hasher.finalize().as_bytes();

            let commit_index = self.committed_count;
            self.metrics.commit_index.set(commit_index as i64);
            let digest_short =
                u16::from_le_bytes([self.commit_digest[0], self.commit_digest[1]]) & 0x3FF;
            self.metrics.commit_digest_latest.set(digest_short as i64);
            if commit_index.is_multiple_of(100) {
                self.metrics.commit_digest.set(digest_short as i64);
            }

            for block in &commit.0.blocks {
                let gap = commit.0.anchor.round.saturating_sub(block.round());
                self.metrics.commit_gap.observe(gap as f64);

                let block_creation_time = block.meta_creation_time();
                let block_latency = current_timestamp.saturating_sub(block_creation_time);

                if block_creation_time.is_zero() || block_latency.as_secs() > 60 {
                    tracing::debug!(
                        "Latency of block {} is too large, \
                        skip updating metrics - \
                        (latency: {:?}; block creation time: {:?})",
                        block.reference(),
                        block_latency,
                        block_creation_time
                    );
                    continue;
                }

                self.metrics.block_committed_latency.observe(block_latency);
                self.metrics
                    .committed_blocks
                    .with_label_values(&[&block.authority().to_string()])
                    .inc();

                self.metrics
                    .block_committed_latency_squared_micros
                    .inc_by(block_latency.as_micros().pow(2) as u64);

                tracing::debug!("Latency of block {} is computed", block.reference());
            }

            // Record benchmark start time.
            let time_from_start = self.start_time.elapsed();
            let benchmark_duration = self.metrics.benchmark_duration.get();
            if let Some(delta) = time_from_start.as_secs().checked_sub(benchmark_duration) {
                self.metrics.benchmark_duration.inc_by(delta);
            }
        }
        if dag_state.consensus_protocol == crate::dag_state::ConsensusProtocol::StarfishBls {
            let mut pending = dag_state.read_pending_not_certified();
            pending.append(&mut committed);
            let (certified, unresolved) = self.drain_certified_commits(dag_state, pending);
            dag_state.update_pending_not_certified(unresolved);
            committed = certified;
        }

        // Compute transaction end-to-end latency after certification is
        // resolved and the data itself is locally available.
        let mut pending = dag_state.read_pending_unavailable();
        pending.append(&mut committed);
        let (resulted_committed, unavailable) = self.drain_available_commits(dag_state, pending);
        dag_state.update_pending_unavailable(unavailable);
        self.sequenced_commit_count += resulted_committed.len();
        self.metrics
            .commit_availability_gap
            .set((self.committed_count - self.sequenced_commit_count) as i64);
        resulted_committed
    }

    fn recover_committed(
        &mut self,
        committed: AHashSet<BlockReference>,
        committed_leaders_count: usize,
    ) {
        assert!(self.commit_interpreter.committed.is_empty());
        self.committed_count = committed_leaders_count;
        self.sequenced_commit_count = committed_leaders_count;
        self.metrics.commit_index.set(self.committed_count as i64);
        self.commit_interpreter.committed_slots =
            committed.iter().map(|r| (r.round, r.authority)).collect();
        self.commit_interpreter.committed = committed.into_iter().collect();
    }

    fn cleanup(&mut self, threshold_round: RoundNumber) {
        self.commit_interpreter.cleanup(threshold_round);
    }
}
