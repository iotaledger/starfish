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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::{collections::VecDeque, sync::Arc};
use digest::Digest;
use crate::block_store::{leader_in_round, CertificateForLeader, CertifiedStake, VoteForLeader};
use crate::committee::{QuorumThreshold, StakeAggregator};
use crate::consensus::LeaderStatus::Commit;
use crate::data::Data;
use crate::metrics::UtilizationTimerVecExt;
use crate::types::{BlockDigest, VerifiedStatementBlock};

/// A universal committer uses a collection of committers to commit a sequence of leaders.
/// It can be configured to use a combination of different commit strategies, including
/// multi-leaders, backup leaders, and pipelines.
#[derive(Clone)]
pub struct UniversalCommitter {
    block_store: BlockStore,
    committers: Vec<BaseCommitter>,
    metrics: Arc<Metrics>,
    committee: Committee,
    /// Keep track of all committed blocks to avoid computing the metrics for the same block twice.
    committed: HashSet<(AuthorityIndex, RoundNumber)>,
    last_committed_round: RoundNumber,
    sequence_leaders_with_decision: Vec<LeaderDecision>,
    dag: BTreeMap<(RoundNumber, AuthorityIndex), HashMap<BlockDigest, (Vec<BlockReference>, VoteForLeader, CertificateForLeader, CertifiedStake)>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum LeaderDecision {
    Commit(BlockReference),
    Skip(),
    Undecided(),
}

impl UniversalCommitter {

    pub fn contains_block_reference(&self, block_ref: &BlockReference) -> bool {
        self.dag.get(&(block_ref.round, block_ref.authority))
            .map_or(false, |hashmap|
                hashmap.contains_key(&block_ref.digest)
            )
    }

    pub fn update_sequence_leaders(&mut self, round: RoundNumber, leader_decision: LeaderDecision) {
        if self.sequence_leaders_with_decision.len() < round as usize + 1 {
            self.sequence_leaders_with_decision.resize(round as usize + 1, LeaderDecision::Undecided());
        }
        self.sequence_leaders_with_decision[round as usize] = leader_decision;
    }




    pub fn update_dag(&mut self, newly_processed_blocks: Vec<Data<VerifiedStatementBlock>>) {
        let committee = self.committee.clone();
        for new_block in newly_processed_blocks {
            let new_block_reference = new_block.reference().clone();
            if self.contains_block_reference(&new_block_reference) {
                continue;
            }
            let parents = new_block.includes().clone();
            let stake_aggregator: Option<StakeAggregator<QuorumThreshold>> = if leader_in_round(new_block_reference.round, committee.len()) == new_block_reference.authority  {
                Some(StakeAggregator::new())
            } else {
                None
            };
            let new_vote_for_leader: VoteForLeader = if new_block_reference.round >= 1 {
                let previous_round = new_block_reference.round - 1 as RoundNumber;
                let leader_previous_round = leader_in_round(previous_round, committee.len()) as RoundNumber;
                parents.iter().find_map(|parent| {
                    if parent.round == previous_round && parent.authority == leader_previous_round {
                        Some(parent.clone())
                    } else {
                        None
                    }
                })
            } else {
                None
            };

            let mut leader_votes: HashMap<BlockReference, StakeAggregator<QuorumThreshold>> = HashMap::new();
            let mut new_certificate_for_leader = None;

            for parent in &parents {
                let previous_round = new_block_reference.round - 1 as RoundNumber;
                // Safely fetch and clone the value from the DAG
                if parent.round == previous_round {
                    if let Some((_, _, vote_for_leader, _,_)) = self.read_block_reference(parent) {
                        if let Some(leader) = vote_for_leader {
                            // Get or initialize the StakeAggregator for this leader
                            let votes_for_leader = leader_votes.entry(leader).or_insert_with(|| StakeAggregator::new());


                            // Add the parent's authority and check if the leader is certified
                            if votes_for_leader.add(parent.authority, &committee) {
                                new_certificate_for_leader = Some(leader);
                                break;
                            }
                        }
                    }
                }
            }
            tracing::debug!("Added {:?}, Vote {:?}, Stake  {:?}", new_block_reference, new_vote_for_leader, stake_aggregator);
            if let Some(leader) = new_certificate_for_leader.clone() {
                let mut leader_committed = false;
                // Safely get the leader's DAG entry
                if let Some((_, _, _, _,ref mut stake_aggregator)) = self.get_mut_block_reference(&leader) {
                    if let Some(aggregator) = stake_aggregator {
                        // Add the block reference's authority to the leader's StakeAggregator
                        if aggregator.add(new_block_reference.authority, &committee) {
                            self.update_sequence_leaders(leader.round, Commit(leader));
                            tracing::debug!("Leader {:?} is directly committed, Stake  {:?}", leader, aggregator);
                        }
                    }
                } else {
                    panic!("The DAG must contain the certified leader");
                }
            }
            // update information about block_reference
            self.dag.entry((new_block_reference.round, new_block_reference.authority))
                .or_insert_with(HashMap::new)
                .insert(
                    (new_block_reference.digest),
                    (
                        parents,
                        new_vote_for_leader,
                        new_certificate_for_leader,
                        stake_aggregator,
                    )
                );
        }
    }
    /// Try to commit part of the dag. This function is idempotent and returns a list of
    /// ordered decided leaders.
    ///
    ///
    #[tracing::instrument(skip_all, fields(last_decided = %last_decided))]
    pub fn try_commit(&mut self, last_decided: BlockReference, newly_processed_blocks: Vec<Data<VerifiedStatementBlock>>) -> Vec<LeaderStatus> {
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
