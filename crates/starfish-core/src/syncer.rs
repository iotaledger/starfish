// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Instant};

use ahash::AHashSet;

use tokio::sync::mpsc;

use crate::{
    block_handler::BlockHandler,
    bls_certificate_aggregator::{CertificateEvent, apply_certificate_events},
    bls_service::BlsServiceMessage,
    consensus::{CommitMetastate, linearizer::CommittedSubDag},
    core::Core,
    dag_state::DagState,
    data::Data,
    metrics::{Metrics, UtilizationTimerVecExt},
    runtime::timestamp_utc,
    types::{
        AuthorityIndex, BlockReference, ReconstructedTransactionData, RoundNumber, VerifiedBlock,
    },
};

pub struct Syncer<H: BlockHandler, S: SyncerSignals, C: CommitObserver> {
    core: Core<H>,
    force_new_block: bool,
    proposal_wait_started_at: Option<Instant>,
    signals: S,
    commit_observer: C,
    pub(crate) connected_authorities: AHashSet<AuthorityIndex>,
    pub(crate) subscribed_by_authorities: AHashSet<AuthorityIndex>,
    pub(crate) metrics: Arc<Metrics>,
    bls_tx: Option<mpsc::Sender<BlsServiceMessage>>,
}

pub trait SyncerSignals: Send + Sync {
    fn new_block_ready(&mut self);
    fn threshold_clock_round_advanced(&mut self, round: RoundNumber);
}

pub trait CommitObserver: Send + Sync {
    fn handle_commit(
        &mut self,
        dag_state: &DagState,
        committed_leaders: Vec<(Data<VerifiedBlock>, Option<CommitMetastate>)>,
    ) -> Vec<CommittedSubDag>;

    fn recover_committed(
        &mut self,
        committed: AHashSet<BlockReference>,
        committed_leaders_count: usize,
    );

    fn cleanup(&mut self, threshold_round: RoundNumber);
}

impl<H: BlockHandler, S: SyncerSignals, C: CommitObserver> Syncer<H, S, C> {
    pub fn new(
        core: Core<H>,
        signals: S,
        commit_observer: C,
        metrics: Arc<Metrics>,
        bls_tx: Option<mpsc::Sender<BlsServiceMessage>>,
    ) -> Self {
        let committee_size = core.committee().len();
        Self {
            core,
            force_new_block: false,
            proposal_wait_started_at: None,
            signals,
            commit_observer,
            connected_authorities: AHashSet::with_capacity(committee_size),
            subscribed_by_authorities: AHashSet::with_capacity(committee_size),
            metrics,
            bls_tx,
        }
    }

    pub fn add_blocks(
        &mut self,
        blocks: Vec<Data<VerifiedBlock>>,
    ) -> (
        Vec<BlockReference>,
        AHashSet<BlockReference>,
        Vec<BlockReference>,
    ) {
        let previous_threshold_round = self.core.dag_state().threshold_clock_round();
        // todo: when block is updated we might return false here and it can make
        // committing longer
        let (
            success,
            pending_blocks_with_transactions,
            missing_parents,
            used_additional_blocks,
            _processed_blocks,
        ) = self.core.add_blocks(blocks);
        self.maybe_start_proposal_wait();
        self.maybe_signal_threshold_round_advance(previous_threshold_round);
        if success {
            tracing::debug!("Attempt to create block from syncer after adding block");
            self.try_new_block();
        }
        (
            pending_blocks_with_transactions,
            missing_parents,
            used_additional_blocks,
        )
    }

    /// Add header-only blocks and attempt block creation.
    pub fn add_headers(
        &mut self,
        headers: Vec<Data<VerifiedBlock>>,
    ) -> (AHashSet<BlockReference>, Vec<BlockReference>) {
        let previous_threshold_round = self.core.dag_state().threshold_clock_round();
        let (success, missing_parents, processed_refs, _processed_blocks) =
            self.core.add_headers(headers);
        self.maybe_start_proposal_wait();
        self.maybe_signal_threshold_round_advance(previous_threshold_round);
        if success {
            tracing::debug!("Attempt to create block from syncer after adding headers");
            self.try_new_block();
        }
        (missing_parents, processed_refs)
    }

    /// Attach recovered transaction data to existing blocks and attempt block
    /// creation.
    pub fn add_transaction_data(&mut self, items: Vec<ReconstructedTransactionData>) {
        self.core.add_transaction_data(items);
        self.maybe_start_proposal_wait();
        self.try_new_block();
    }

    /// Apply BLS certificate events from the BLS verification service.
    /// Fresh certificates can unblock both block production and sequencing, so
    /// retry both paths immediately when DAG state changed.
    pub fn apply_certificate_events(&mut self, events: Vec<CertificateEvent>) {
        if apply_certificate_events(self.core.dag_state(), events) {
            self.maybe_start_proposal_wait();
            self.try_new_block();
            self.try_new_commit();
        }
    }

    pub fn force_new_block(&mut self, round: RoundNumber) -> bool {
        if self.core.last_proposed() == round {
            self.metrics.leader_timeout_total.inc();
            self.force_new_block = true;
            tracing::debug!("Attempt to force new block after timeout");
            self.maybe_start_proposal_wait();
            self.try_new_block();
            true
        } else {
            false
        }
    }

    fn try_new_block(&mut self) -> bool {
        self.maybe_start_proposal_wait();
        let committee = self.core.committee();
        let own_authority = self.core.authority();
        let mut subscriber_stake = committee.get_total_stake(&self.subscribed_by_authorities);
        if !self.subscribed_by_authorities.contains(&own_authority) {
            subscriber_stake += committee
                .get_stake(own_authority)
                .expect("Own authority should exist in committee");
        }
        if !committee.is_quorum(subscriber_stake) {
            return false;
        }
        if self.force_new_block || self.core.ready_new_block(&self.connected_authorities) {
            tracing::debug!("Attempt to create new block in syncer after one trigger");
            if let Some(ref block) = self.core.try_new_block() {
                if let Some(started_at) = self.proposal_wait_started_at.take() {
                    self.metrics
                        .proposal_wait_time_total_us
                        .inc_by(started_at.elapsed().as_micros() as u64);
                }
                // Send own block and DAC partial sig to BLS service.
                if let Some(ref bls_tx) = self.bls_tx {
                    let _ = bls_tx.try_send(BlsServiceMessage::ProcessBlocks(vec![block.clone()]));
                    if let Some((block_ref, auth, sig)) =
                        self.core.generate_own_dac_partial_sig(block)
                    {
                        let _ =
                            bls_tx.try_send(BlsServiceMessage::DacPartialSig(block_ref, auth, sig));
                    }
                }
                self.signals.new_block_ready();
                self.force_new_block = false;
                return true;
            }
        }
        false
    }

    fn maybe_start_proposal_wait(&mut self) {
        if self.proposal_wait_started_at.is_some() {
            return;
        }
        if self.core.dag_state().threshold_clock_round() > self.core.last_proposed() {
            self.proposal_wait_started_at = Some(Instant::now());
        }
    }

    fn maybe_signal_threshold_round_advance(&mut self, previous_threshold_round: RoundNumber) {
        let current_threshold_round = self.core.dag_state().threshold_clock_round();
        if current_threshold_round > previous_threshold_round {
            self.signals
                .threshold_clock_round_advanced(current_threshold_round);
        }
    }

    pub fn try_new_commit(&mut self) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Syncer::try_new_commit");
        let timer_core_commit = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::try_new_commit");
        let (newly_committed, any_decided) = self.core.try_commit();
        drop(timer_core_commit);
        let utc_now = timestamp_utc();
        if !newly_committed.is_empty() {
            let committed_refs: Vec<_> = newly_committed
                .iter()
                .map(|(block, _meta)| {
                    let age = utc_now
                        .checked_sub(block.meta_creation_time())
                        .unwrap_or_default();
                    format!("{}({}ms)", block.reference(), age.as_millis())
                })
                .collect();
            tracing::debug!("Committed {:?}", committed_refs);
        }
        let committed_subdag = self
            .commit_observer
            .handle_commit(self.core.dag_state(), newly_committed);

        self.core
            .handle_committed_subdag(committed_subdag, any_decided);
        self.try_new_block();
    }

    pub fn cleanup(&mut self) {
        let threshold = self.core.cleanup();
        self.commit_observer.cleanup(threshold);
    }

    pub fn commit_observer(&self) -> &C {
        &self.commit_observer
    }

    pub fn core(&self) -> &Core<H> {
        &self.core
    }

    #[cfg(test)]
    pub fn scheduler_state_id(&self) -> usize {
        self.core.authority() as usize
    }
}

impl SyncerSignals for bool {
    fn new_block_ready(&mut self) {
        *self = true;
    }

    fn threshold_clock_round_advanced(&mut self, _round: RoundNumber) {
        *self = true;
    }
}
