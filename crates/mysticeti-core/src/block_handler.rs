// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::Duration,
};

use minibytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use crate::{
    block_store::BlockStore,
    committee::{Committee, ProcessedTransactionHandler, QuorumThreshold, TransactionAggregator},
    consensus::linearizer::{CommittedSubDag, Linearizer},
    log::TransactionLog,
    metrics::{Metrics, UtilizationTimerExt},
    runtime::{self, TimeInstant},
    syncer::CommitObserver,
    types::{
        AuthorityIndex, BlockReference, Transaction,
        TransactionLocator,
    },
};
use crate::data::Data;
use crate::transactions_generator::TransactionGenerator;
use crate::types::{BaseStatement, VerifiedStatementBlock};

pub trait BlockHandler: Send + Sync {

    fn handle_proposal(&mut self, number_transactions: usize);
    fn handle_blocks(
        &mut self,
        require_response: bool,
    ) -> Vec<BaseStatement>;
    fn state(&self) -> Bytes;

    fn recover_state(&mut self, _state: &Bytes);

    fn cleanup(&self) {}
}

const REAL_BLOCK_HANDLER_TXN_SIZE: usize = 512;
const REAL_BLOCK_HANDLER_TXN_GEN_STEP: usize = 32;
const _: () = assert_constants();

#[allow(dead_code)]
const fn assert_constants() {
    if REAL_BLOCK_HANDLER_TXN_SIZE % REAL_BLOCK_HANDLER_TXN_GEN_STEP != 0 {
        panic!("REAL_BLOCK_HANDLER_TXN_SIZE % REAL_BLOCK_HANDLER_TXN_GEN_STEP != 0")
    }
}

pub struct RealBlockHandler {
    transaction_votes: TransactionAggregator<QuorumThreshold, TransactionLog>,
    pub transaction_time: Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>>,
    committee: Arc<Committee>,
    authority: AuthorityIndex,
    block_store: BlockStore,
    metrics: Arc<Metrics>,
    receiver: mpsc::Receiver<Vec<Transaction>>,
    pending_transactions: usize,
    consensus_only: bool,
}

/// The max number of transactions per block.
// todo - This value should be in bytes because it is capped by the wal entry size.
pub const SOFT_MAX_PROPOSED_PER_BLOCK: usize = 4 * 1000;

impl RealBlockHandler {


    pub fn new(
        committee: Arc<Committee>,
        authority: AuthorityIndex,
        certified_transactions_log_path: &Path,
        block_store: BlockStore,
        metrics: Arc<Metrics>,
        consensus_only: bool,
    ) -> (Self, mpsc::Sender<Vec<Transaction>>) {
        let (sender, receiver) = mpsc::channel(1024);
        let transaction_log = TransactionLog::start(certified_transactions_log_path)
            .expect("Failed to open certified transaction log for write");

        let this = Self {
            transaction_votes: TransactionAggregator::with_handler(transaction_log),
            transaction_time: Default::default(),
            committee,
            authority,
            block_store,
            metrics,
            receiver,
            pending_transactions: 0, // todo - need to initialize correctly when loaded from disk
            consensus_only,
        };
        (this, sender)
    }
}

impl RealBlockHandler {
    fn receive_with_limit(&mut self) -> Option<Vec<Transaction>> {
        if self.pending_transactions >= SOFT_MAX_PROPOSED_PER_BLOCK {
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
    fn state(&self) -> Bytes {
        self.transaction_votes.state()
    }

    fn handle_proposal(&mut self, number_transactions: usize) {
        self.pending_transactions -= number_transactions;
    }

    fn recover_state(&mut self, state: &Bytes) {
        self.transaction_votes.with_state(state);
    }


    fn cleanup(&self) {
        let _timer = self.metrics.block_handler_cleanup_util.utilization_timer();
        // todo - all of this should go away and we should measure tx latency differently
        let mut l = self.transaction_time.lock();
        l.retain(|_k, v| v.elapsed() < Duration::from_secs(10));
    }

    fn handle_blocks(
        &mut self,
        require_response: bool,
    ) -> Vec<BaseStatement> {
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

// Immediately votes and generates new transactions
#[allow(dead_code)]
pub struct TestBlockHandler {
    last_transaction: u64,
    pending_transactions: usize,
    transaction_votes: TransactionAggregator<QuorumThreshold>,
    pub transaction_time: Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>>,
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
    ) -> (Self, mpsc::Sender<Vec<Transaction>>)  {
        let (sender, receiver) = mpsc::channel(1024);
        let this = Self {
            last_transaction,
            transaction_votes: Default::default(),
            transaction_time: Default::default(),
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

    pub fn is_certified(&self, locator: &TransactionLocator) -> bool {
        self.transaction_votes.is_processed(locator)
    }

    pub fn make_transaction(i: u64) -> Transaction {
        Transaction::new(i.to_le_bytes().to_vec())
    }
}

impl BlockHandler for TestBlockHandler {


    fn handle_proposal(&mut self, number_transactions: usize) {
        self.pending_transactions -= number_transactions;
    }
    fn state(&self) -> Bytes {
        let state = (&self.transaction_votes.state(), &self.last_transaction);
        let bytes =
            bincode::serialize(&state).expect("Failed to serialize transaction aggregator state");
        bytes.into()
    }

    fn recover_state(&mut self, state: &Bytes) {
        let (transaction_votes, last_transaction) = bincode::deserialize(state)
            .expect("Failed to deserialize transaction aggregator state");
        self.transaction_votes.with_state(&transaction_votes);
        self.last_transaction = last_transaction;
    }

    fn handle_blocks(
        &mut self,
        require_response: bool,
    ) -> Vec<BaseStatement> {
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

pub struct TestCommitHandler<H = HashSet<TransactionLocator>> {
    commit_interpreter: Linearizer,
    transaction_votes: TransactionAggregator<QuorumThreshold, H>,
    committed_leaders: Vec<BlockReference>,
    metrics: Arc<Metrics>,
}

impl<H: ProcessedTransactionHandler<TransactionLocator> + Default> TestCommitHandler<H> {
    pub fn new(
        committee: Arc<Committee>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self::new_with_handler(
            committee,
            metrics,
            Default::default(),
        )
    }
}



impl<H: ProcessedTransactionHandler<TransactionLocator>> TestCommitHandler<H> {
    pub fn new_with_handler(
        committee: Arc<Committee>,
        metrics: Arc<Metrics>,
        handler: H,
    ) -> Self {
        Self {
            commit_interpreter: Linearizer::new((*committee).clone()),
            transaction_votes: TransactionAggregator::with_handler(handler),
            committed_leaders: vec![],
            metrics,
        }
    }



    fn transaction_observer(&self, block: Data<VerifiedStatementBlock>) {
        let current_timestamp = runtime::timestamp_utc();
        if let Some(vec) = block.statements().as_ref() {
            for statement in vec {
                if let BaseStatement::Share(transaction) = statement {
                    let tx_submission_timestamp = TransactionGenerator::extract_timestamp(transaction);
                    let latency = current_timestamp.saturating_sub(tx_submission_timestamp);

                    self.metrics.transaction_committed_latency.observe(latency);
                    self.metrics.sequenced_transactions_total.inc();
                }
            }
        } else {
            tracing::debug!("Transactions from block {:?} are committed, but not available", block);
        }
    }
    pub fn committed_leaders(&self) -> &Vec<BlockReference> {
        &self.committed_leaders
    }
}

impl<H: ProcessedTransactionHandler<TransactionLocator> + Send + Sync> CommitObserver
    for TestCommitHandler<H>
{
    fn handle_commit(
        &mut self,
        block_store: &BlockStore,
        committed_leaders: Vec<Data<VerifiedStatementBlock>>,
    ) -> Vec<CommittedSubDag> {
        let mut committed = self
            .commit_interpreter
            .handle_commit(block_store, committed_leaders);
        for commit in &committed {
            self.committed_leaders.push(commit.0.anchor);
            for block in &commit.0.blocks {
                let block_creation_time = block.meta_creation_time();
                let block_timestamp = runtime::timestamp_utc() - block_creation_time;

                self.metrics.block_committed_latency.observe(block_timestamp);
                tracing::debug!("Latency of block {} is computed", block.reference());
            }
        }
        let mut pending = block_store.read_pending_unavailable();
        pending.append(&mut committed);
        let committed = pending;
        let mut slice_index = 0;
        let mut resulted_committed = Vec::new();
        for (_i, commit) in committed.iter().enumerate() {
            let mut check_availability = true;
            for block in &commit.0.blocks {
                if block.round() > 0 {
                    if !block_store.is_data_available(block.reference()) {
                        tracing::debug!("Block {} is not available", block.reference());
                        check_availability = false;
                        break;
                    }
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

                        tracing::debug!("Latency of transactions from block {} is computed", block.reference());
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



    fn aggregator_state(&self) -> Bytes {
        self.transaction_votes.state()
    }

    fn recover_committed(&mut self, committed: HashSet<BlockReference>, state: Option<Bytes>) {
        assert!(self.commit_interpreter.committed.is_empty());
        if let Some(state) = state {
            self.transaction_votes.with_state(&state);
        } else {
            assert!(committed.is_empty());
        }
        self.commit_interpreter.committed = committed;
    }
}
