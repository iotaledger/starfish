// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, sync::Arc};

use crate::data::Data;
use crate::transactions_generator::TransactionGenerator;
use crate::types::{BaseStatement, VerifiedStatementBlock};
use crate::{
    block_store::BlockStore,
    committee::Committee,
    consensus::{
        linearizer::{CommittedSubDag, Linearizer},
        CommitMetastate,
    },
    metrics::Metrics,
    runtime::{self, TimeInstant},
    syncer::CommitObserver,
    types::{AuthorityIndex, BlockReference, Transaction},
};
use tokio::sync::mpsc;

pub trait BlockHandler: Send + Sync {
    fn handle_proposal(&mut self, number_transactions: usize);
    fn handle_blocks(&mut self, require_response: bool) -> Vec<BaseStatement>;
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
    max_transactions_per_block: usize, // max number of transaction in block. Depends on the committee size
}

impl RealBlockHandler {
    pub fn new(committee: &Committee) -> (Self, mpsc::Sender<Vec<Transaction>>) {
        let (sender, receiver) = mpsc::channel(1024);
        // Assuming max TPS to be 600.000 and 4 blocks per second (for this TPS), we limit the max number of
        // transactions per block to ensure fast processing
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

    fn handle_blocks(&mut self, require_response: bool) -> Vec<BaseStatement> {
        let mut response = vec![];
        if require_response {
            while let Some(data) = self.receive_with_limit() {
                for tx in data {
                    response.push(BaseStatement::Share(tx));
                }
            }
        }
        response
    }
}

/// The max number of transactions per block for TestBlockHandler
pub const SOFT_MAX_PROPOSED_PER_BLOCK: usize = 4 * 1000;

// Immediately votes and generates new transactions
#[allow(dead_code)]
pub struct TestBlockHandler {
    last_transaction: u64,
    pending_transactions: usize,
    committee: Arc<Committee>,
    authority: AuthorityIndex,
    receiver: mpsc::Receiver<Vec<Transaction>>,
    metrics: Arc<Metrics>,
}

impl TestBlockHandler {
    pub fn new(
        last_transaction: u64,
        committee: Arc<Committee>,
        authority: AuthorityIndex,
        metrics: Arc<Metrics>,
    ) -> (Self, mpsc::Sender<Vec<Transaction>>) {
        let (sender, receiver) = mpsc::channel(1024);
        let this = Self {
            last_transaction,
            committee,
            authority,
            metrics,
            pending_transactions: 0,
            receiver,
        };
        (this, sender)
    }

    fn receive_with_limit(&mut self) -> Option<Vec<Transaction>> {
        if self.pending_transactions >= SOFT_MAX_PROPOSED_PER_BLOCK {
            return None;
        }
        let received = self.receiver.try_recv().ok()?;
        self.pending_transactions += received.len();
        Some(received)
    }

    pub fn make_transaction(i: u64) -> Transaction {
        Transaction::new(i.to_le_bytes().to_vec())
    }
}

impl BlockHandler for TestBlockHandler {
    fn handle_proposal(&mut self, number_transactions: usize) {
        self.pending_transactions -= number_transactions;
    }

    fn handle_blocks(&mut self, require_response: bool) -> Vec<BaseStatement> {
        // todo - this is ugly, but right now we need a way to recover self.last_transaction
        let mut response = vec![];
        if require_response {
            while let Some(data) = self.receive_with_limit() {
                for tx in data {
                    response.push(BaseStatement::Share(tx));
                }
            }
        }
        response
    }
}

pub struct RealCommitHandler {
    commit_interpreter: Linearizer,
    committed_leaders: Vec<BlockReference>,
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
            start_time: TimeInstant::now(),
            metrics,
        }
    }

    fn transaction_observer(&self, block: Data<VerifiedStatementBlock>) {
        let current_timestamp = runtime::timestamp_utc();
        if let Some(vec) = block.statements().as_ref() {
            for statement in vec {
                let BaseStatement::Share(transaction) = statement;
                let tx_submission_timestamp = TransactionGenerator::extract_timestamp(transaction);
                let latency = current_timestamp.saturating_sub(tx_submission_timestamp);

                self.metrics.transaction_committed_latency.observe(latency);
                self.metrics
                    .transaction_committed_latency_squared_micros
                    .inc_by(latency.as_micros().pow(2) as u64);

                self.metrics.sequenced_transactions_total.inc();
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
}

impl CommitObserver for RealCommitHandler {
    fn handle_commit(
        &mut self,
        block_store: &BlockStore,
        committed_leaders: Vec<(Data<VerifiedStatementBlock>, Option<CommitMetastate>)>,
    ) -> Vec<CommittedSubDag> {
        let mut committed = self
            .commit_interpreter
            .handle_commit(block_store, committed_leaders);
        let current_timestamp = runtime::timestamp_utc();
        for commit in &committed {
            self.committed_leaders.push(commit.0.anchor);
            for block in &commit.0.blocks {
                let block_creation_time = block.meta_creation_time();
                let block_latency = current_timestamp.saturating_sub(block_creation_time);

                if block_creation_time.is_zero() || block_latency.as_secs() > 60 {
                    tracing::debug!("Latency of block {} is too large, skip updating metrics - (latency: {:?}; block creation time: {:?})", block.reference(), block_latency, block_creation_time);
                    continue;
                }

                self.metrics.block_committed_latency.observe(block_latency);
                self.metrics
                    .committed_blocks
                    .with_label_values(&[&block.author().to_string()])
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
        // Compute transaction end-to-end latency
        // First read for which subdags there is not enough transaction data
        let mut pending = block_store.read_pending_unavailable();
        pending.append(&mut committed);
        let committed = pending;
        let mut slice_index = 0;
        let mut resulted_committed = Vec::new();
        for commit in committed.iter() {
            let mut check_availability = true;
            for block in &commit.0.blocks {
                if block.round() > 0 && !block_store.is_data_available(block.reference()) {
                    tracing::debug!("Block {} is not available", block.reference());
                    check_availability = false;
                    break;
                }
            }
            if check_availability {
                for block in &commit.0.blocks {
                    let updated_block = block_store
                        .get_storage_block(*block.reference())
                        .expect("We should have the whole sub-dag by now");
                    if updated_block.round() > 0 {
                        // Block is supposed to have uncoded transactions
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
            // todo: need to change the committed subdag again, but it is ok for now as the storage
            // is not used.
            resulted_committed.push(commit.0.clone());
            // self.committed_dags.push(commit);
            slice_index += 1;
        }
        block_store.update_pending_unavailable(committed[slice_index..].to_vec());
        resulted_committed
    }

    fn recover_committed(&mut self, committed: HashSet<BlockReference>) {
        assert!(self.commit_interpreter.committed.is_empty());
        self.commit_interpreter.committed_slots =
            committed.iter().map(|r| (r.round, r.authority)).collect();
        self.commit_interpreter.committed = committed;
    }
}
