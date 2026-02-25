// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::types::VerifiedStatementBlock;
use crate::{
    block_handler::BlockHandler,
    block_store::BlockStore,
    consensus::{CommitMetastate, linearizer::CommittedSubDag},
    core::Core,
    data::Data,
    metrics::{Metrics, UtilizationTimerVecExt},
    runtime::timestamp_utc,
    types::{AuthorityIndex, BlockReference, RoundNumber},
};
use ahash::AHashSet;
use std::sync::Arc;

pub struct Syncer<H: BlockHandler, S: SyncerSignals, C: CommitObserver> {
    core: Core<H>,
    force_new_block: bool,
    signals: S,
    commit_observer: C,
    pub(crate) connected_authorities: AHashSet<AuthorityIndex>,
    metrics: Arc<Metrics>,
}

pub trait SyncerSignals: Send + Sync {
    fn new_block_ready(&mut self);
}

pub trait CommitObserver: Send + Sync {
    fn handle_commit(
        &mut self,
        block_store: &BlockStore,
        committed_leaders: Vec<(Data<VerifiedStatementBlock>, Option<CommitMetastate>)>,
    ) -> Vec<CommittedSubDag>;

    fn recover_committed(&mut self, committed: AHashSet<BlockReference>);

    fn cleanup(&mut self, threshold_round: RoundNumber);
}

impl<H: BlockHandler, S: SyncerSignals, C: CommitObserver> Syncer<H, S, C> {
    pub fn new(core: Core<H>, signals: S, commit_observer: C, metrics: Arc<Metrics>) -> Self {
        let committee_size = core.committee().len();
        Self {
            core,
            force_new_block: false,
            signals,
            commit_observer,
            connected_authorities: AHashSet::with_capacity(committee_size),
            metrics,
        }
    }

    pub fn add_blocks(
        &mut self,
        blocks: Vec<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>,
    ) -> (
        Vec<BlockReference>,
        AHashSet<BlockReference>,
        Vec<BlockReference>,
    ) {
        // todo: when block is updated we might return false here and it can make
        // committing longer
        let (success, pending_blocks_with_statements, missing_parents, used_additional_blocks) =
            self.core.add_blocks(blocks);
        if success {
            tracing::debug!("Attempt to create block from syncer after adding block");
            self.try_new_block();
        }
        (
            pending_blocks_with_statements,
            missing_parents,
            used_additional_blocks,
        )
    }

    pub fn force_new_block(&mut self, round: RoundNumber) -> bool {
        if self.core.last_proposed() == round {
            self.metrics.leader_timeout_total.inc();
            self.force_new_block = true;
            tracing::debug!("Attempt to force new block after timeout");
            self.try_new_block();
            true
        } else {
            false
        }
    }

    fn try_new_block(&mut self) -> bool {
        if self.force_new_block || self.core.ready_new_block(&self.connected_authorities) {
            tracing::debug!("Attempt to create new block in syncer after one trigger");
            if self.core.try_new_block().is_some() {
                self.signals.new_block_ready();
                self.force_new_block = false;
                return true;
            }
        }
        false
    }
    pub fn try_new_commit(&mut self) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Syncer::try_new_commit");
        // No need to commit after epoch is safe to close
        if self.core.epoch_closed() {
            return;
        };
        let timer_core_commit = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::try_new_commit");
        let newly_committed = self.core.try_commit();
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
            .handle_commit(self.core.block_store(), newly_committed);

        self.core.handle_committed_subdag(committed_subdag);
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
}
