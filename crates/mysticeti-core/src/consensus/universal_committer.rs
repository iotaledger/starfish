// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{base_committer::BaseCommitter, LeaderStatus, WAVE_LENGTH};
use crate::{
    block_store::BlockStore,
    committee::Committee,
    consensus::base_committer::BaseCommitterOptions,
    metrics::Metrics,
    types::{format_authority_round, AuthorityIndex, BlockReference, RoundNumber},
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::{collections::VecDeque, sync::Arc};
use crate::metrics::UtilizationTimerVecExt;

/// A universal committer uses a collection of committers to commit a sequence of leaders.
/// It can be configured to use a combination of different commit strategies, including
/// multi-leaders, backup leaders, and pipelines.
#[derive(Clone)]
pub struct UniversalCommitter {
    block_store: BlockStore,
    committers: Vec<BaseCommitter>,
    metrics: Arc<Metrics>,
    /// Keep track of all committed blocks to avoid computing the metrics for the same block twice.
    committed: HashSet<(AuthorityIndex, RoundNumber)>,
}

impl UniversalCommitter {
    /// Try to commit part of the dag. This function is idempotent and returns a list of
    /// ordered decided leaders.
    #[tracing::instrument(skip_all, fields(last_decided = %last_decided))]
    pub fn try_commit(&mut self, last_decided: BlockReference) -> Vec<LeaderStatus> {
        // Auxiliary structures
        let universal_committer_timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Committer: Direct and indirect commit");

        let highest_known_round = self.block_store.highest_round();
        let last_decided_round = last_decided.round();
        let last_decided_round_authority = (last_decided.round(), last_decided.authority);
        let highest_possible_leader_to_decide_round = highest_known_round.saturating_sub(1);


        let dag = self.block_store.get_dag_between_rounds(last_decided_round, highest_known_round);
        let directly_committed_leaders
            = self.block_store.get_directly_committed_leaders();
        // Auxiliary structures

        // Try to decide as many leaders as possible, starting with the highest round.
        let mut leaders = VecDeque::new();

        for round in (last_decided_round..=highest_possible_leader_to_decide_round).rev() {
            for committer in self.committers.iter().rev() {
                // Skip committers that don't have a leader for this round.
                let Some(leader) = committer.elect_leader(round) else {
                    continue;
                };

                tracing::debug!(
                    "Trying to decide {} with {committer}",
                    format_authority_round(leader, round)
                );





                // Try to directly decide the leader.
                let timer_direct_decide = self
                    .metrics
                    .utilization_timer
                    .utilization_timer("Committer::direct_decide");

                let mut voters_for_leaders: BTreeSet<(BlockReference, BlockReference)> = BTreeSet::new();
                let voting_round = round + 1;
                let potential_voting_blocks = self.block_store.get_blocks_by_round(voting_round);
                for potential_block in potential_voting_blocks {
                    if let Some((_parents, _authorities, vote_for_leader, _cert, _stake)) =
                        dag.get(&voting_round)
                            .and_then(|round_map| round_map.get(&(potential_block.author(), potential_block.digest()))) {
                        if let Some(leader) = vote_for_leader {
                            voters_for_leaders.insert((leader.clone(), potential_block.reference().clone()));
                        }
                    }
                }

                let mut status = committer.try_direct_decide(leader, round, &voters_for_leaders, &directly_committed_leaders);
                if !self.committed.contains(&(leader, round)) {
                    self.update_metrics(&status, true);
                }
                drop(timer_direct_decide);
                tracing::debug!("Outcome of direct rule: {status}");

                // If we can't directly decide the leader, try to indirectly decide it.
                let timer_indirect_decide = self
                    .metrics
                    .utilization_timer
                    .utilization_timer("Committer::indirect_decide");
                if !status.is_decided() {
                    status = committer.try_indirect_decide(leader, round, leaders.iter(), &voters_for_leaders);
                    if !self.committed.contains(&(leader, round)) {
                        self.update_metrics(&status, false);
                    }
                    tracing::debug!("Outcome of indirect rule: {status}");
                }
                drop(timer_indirect_decide);

                if status.is_decided() {
                    self.committed.insert((leader, round));
                }

                leaders.push_front(status);
            }
        }
        drop(universal_committer_timer);

        // The decided sequence is the longest prefix of decided leaders.
        leaders
            .into_iter()
            // Skip all leaders before the last decided round.
            .skip_while(|x| (x.round(), x.authority()) != last_decided_round_authority)
            // Skip the last decided leader.
            .skip(1)
            // Filter out all the genesis.
            .filter(|x| x.round() > 0)
            // Stop the sequence upon encountering an undecided leader.
            .take_while(|x| x.is_decided())
            .inspect(|x| tracing::debug!("Decided {x}"))
            .collect()
    }

    /// Return list of leaders for the round. Syncer may give those leaders some extra time.
    /// To preserve (theoretical) liveness, we should wait `Delta` time for at least the first leader.
    /// Can return empty vec if round does not have a designated leader.
    pub fn get_leaders(&self, round: RoundNumber) -> Vec<AuthorityIndex> {
        self.committers
            .iter()
            .filter_map(|committer| committer.elect_leader(round))
            .collect()
    }

    /// Update metrics.
    fn update_metrics(&self, leader: &LeaderStatus, direct_decide: bool) {
        let authority = leader.authority().to_string();
        let direct_or_indirect = if direct_decide { "direct" } else { "indirect" };
        let status = match leader {
            LeaderStatus::Commit(..) => format!("{direct_or_indirect}-commit"),
            LeaderStatus::Skip(..) => format!("{direct_or_indirect}-skip"),
            LeaderStatus::Undecided(..) => return,
        };
        self.metrics
            .committed_leaders_total
            .with_label_values(&[&authority, &status])
            .inc();
    }
}

/// A builder for a universal committer. By default, the builder creates a single base committer,
/// that is, a single leader and no pipeline.
pub struct UniversalCommitterBuilder {
    committee: Arc<Committee>,
    block_store: BlockStore,
    metrics: Arc<Metrics>,
    wave_length: RoundNumber,
    pipeline: bool,
}

impl UniversalCommitterBuilder {
    pub fn new(committee: Arc<Committee>, block_store: BlockStore, metrics: Arc<Metrics>) -> Self {
        Self {
            committee,
            block_store,
            metrics,
            wave_length: WAVE_LENGTH,
            pipeline: true,
        }
    }

    pub fn build(self) -> UniversalCommitter {
        let mut committers = Vec::new();
        let pipeline_stages = if self.pipeline { self.wave_length } else { 1 };
        for round_offset in 0..pipeline_stages {
            let options = BaseCommitterOptions {
                wave_length: self.wave_length,
                round_offset,
            };
            let committer =
                BaseCommitter::new(self.committee.clone(), self.block_store.clone())
                    .with_options(options);
            committers.push(committer);
        }

        UniversalCommitter {
            block_store: self.block_store,
            committers,
            metrics: self.metrics,
            committed: Default::default(),
        }
    }
}
