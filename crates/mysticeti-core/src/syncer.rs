// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, sync::Arc};

use minibytes::Bytes;

use crate::{
    block_handler::BlockHandler,
    block_store::BlockStore,
    consensus::linearizer::CommittedSubDag,
    core::Core,
    data::Data,
    metrics::{Metrics, UtilizationTimerVecExt},
    runtime::timestamp_utc,
    types::{AuthorityIndex, BlockReference, RoundNumber, StatementBlock},
};
use crate::types::VerifiedStatementBlock;

pub struct Syncer<H: BlockHandler, S: SyncerSignals, C: CommitObserver> {
    core: Core<H>,
    force_new_block: bool,
    commit_period: u64,
    signals: S,
    commit_observer: C,
    pub(crate) connected_authorities: HashSet<AuthorityIndex>,
    metrics: Arc<Metrics>,
}

pub trait SyncerSignals: Send + Sync {
    fn new_block_ready(&mut self);
}

pub trait CommitObserver: Send + Sync {
    fn handle_commit(
        &mut self,
        block_store: &BlockStore,
        committed_leaders: Vec<Arc<StatementBlock>>,
    ) -> Vec<CommittedSubDag>;

    fn aggregator_state(&self) -> Bytes;

    fn recover_committed(&mut self, committed: HashSet<BlockReference>, state: Option<Bytes>);
}

impl<H: BlockHandler, S: SyncerSignals, C: CommitObserver> Syncer<H, S, C> {
    pub fn new(
        core: Core<H>,
        commit_period: u64,
        signals: S,
        commit_observer: C,
        metrics: Arc<Metrics>,
    ) -> Self {
        let committee_size = core.committee().len();
        Self {
            core,
            force_new_block: false,
            commit_period,
            signals,
            commit_observer,
            connected_authorities: HashSet::with_capacity(committee_size),
            metrics,
        }
    }

    pub fn add_blocks(&mut self, blocks: Vec<Data<VerifiedStatementBlock>>) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Syncer::add_blocks");
        self.core.add_blocks(blocks);
        self.try_new_block();
        self.try_new_commit();
    }

    pub fn force_new_block(&mut self, round: RoundNumber) -> bool {
        if self.core.last_proposed() == round {
            self.metrics.leader_timeout_total.inc();
            self.force_new_block = true;
            if self.try_new_block() {
                self.try_new_commit();
            }
            true
        } else {
            false
        }
    }

    fn try_new_block(&mut self) -> bool {
        if self.force_new_block
            || self
            .core
            .ready_new_block(self.commit_period, &self.connected_authorities)
        {
            if self.core.try_new_block().is_some() {
                self.signals.new_block_ready();
                self.force_new_block = false;
                return true;
            }
        }
        return false;
    }
    fn try_new_commit(&mut self) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Syncer::try_new_commit");
    // No need to commit after epoch is safe to close
        if self.core.epoch_closed() {
            return;
        };

        let newly_committed = self.core.try_commit();
        let utc_now = timestamp_utc();
        if !newly_committed.is_empty() {
            let committed_refs: Vec<_> = newly_committed
                .iter()
                .map(|block| {
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
        self.core.handle_committed_subdag(
            committed_subdag,
            &self.commit_observer.aggregator_state(),
        );

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

#[cfg(test)]
mod tests {
    use std::{ops::Range, time::Duration};

    use rand::Rng;

    use super::*;
    use crate::{
        block_handler::{TestBlockHandler, TestCommitHandler},
        data::Data,
        simulator::{Scheduler, SimulatorState},
    };

    const ROUND_TIMEOUT: Duration = Duration::from_millis(1000);
    const LATENCY_RANGE: Range<Duration> = Duration::from_millis(100)..Duration::from_millis(1800);

    pub enum SyncerEvent {
        ForceNewBlock(RoundNumber),
        DeliverBlock(Data<StatementBlock>),
    }

    impl SimulatorState for Syncer<TestBlockHandler, bool, TestCommitHandler> {
        type Event = SyncerEvent;

        fn handle_event(&mut self, event: Self::Event) {
            match event {
                SyncerEvent::ForceNewBlock(round) => {
                    if self.force_new_block(round) {
                        // eprintln!("[{:06} {}] Proposal timeout for {round}", scheduler.time_ms(), self.core.authority());
                    }
                }
                SyncerEvent::DeliverBlock(block) => {
                    // eprintln!("[{:06} {}] Deliver {block}", scheduler.time_ms(), self.core.authority());
                    self.add_blocks(vec![block]);
                }
            }

            // New block was created
            if self.signals {
                self.signals = false;
                let last_block = self.core.last_own_block().clone();
                Scheduler::schedule_event(
                    ROUND_TIMEOUT,
                    self.scheduler_state_id(),
                    SyncerEvent::ForceNewBlock(last_block.round()),
                );
                for authority in self.core.committee().authorities() {
                    if authority == self.core.authority() {
                        continue;
                    }
                    let latency =
                        Scheduler::<SyncerEvent>::with_rng(|rng| rng.gen_range(LATENCY_RANGE));
                    Scheduler::schedule_event(
                        latency,
                        authority as usize,
                        SyncerEvent::DeliverBlock(last_block.clone()),
                    );
                }
            }
        }
    }
}
