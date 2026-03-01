// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::VecDeque, sync::Arc};

use ahash::{AHashMap, AHashSet};

use super::{CommitMetastate, LeaderStatus, VoterInfo, WAVE_LENGTH, base_committer::BaseCommitter};
use crate::{
    committee::Committee,
    consensus::base_committer::BaseCommitterOptions,
    dag_state::{ConsensusProtocol, DagState},
    metrics::{Metrics, UtilizationTimerVecExt},
    types::{AuthorityIndex, BlockReference, RoundNumber, format_authority_round},
};

/// A universal committer uses a collection of committers to commit a sequence
/// of leaders. It can be configured to use a combination of different commit
/// strategies, including multi-leaders, backup leaders, and pipelines.
#[derive(Clone)]
pub struct UniversalCommitter {
    dag_state: DagState,
    committers: Vec<BaseCommitter>,
    metrics: Arc<Metrics>,
    /// Cache of already-final leaders to avoid redundant recomputation.
    decided: AHashMap<(AuthorityIndex, RoundNumber), LeaderStatus>,
    /// Version-gated cache of voter info per (leader, leader_round).
    /// Key: (leader, leader_round), Value: (voting_round_version, VoterInfo).
    voters_cache: AHashMap<(AuthorityIndex, RoundNumber), (u64, VoterInfo)>,
}

impl UniversalCommitter {
    /// Try to commit part of the dag. This function is idempotent and returns a
    /// list of ordered decided leaders.
    #[tracing::instrument(skip_all, fields(last_decided = %last_decided))]
    pub fn try_commit(&mut self, last_decided: BlockReference) -> Vec<LeaderStatus> {
        let highest_known_round = self.dag_state.highest_round();
        let last_decided_round = last_decided.round();
        let last_decided_round_authority = (last_decided.round(), last_decided.authority);

        let highest_possible_leader_to_decide_round = highest_known_round.saturating_sub(1);

        // Try to decide as many leaders as possible, starting with the highest round.
        let mut leaders = VecDeque::new();
        // Track which leaders were resolved via indirect rule (for metrics).
        let mut indirect_decided: AHashSet<(AuthorityIndex, RoundNumber)> = AHashSet::new();

        for round in (last_decided_round..=highest_possible_leader_to_decide_round).rev() {
            for committer in self.committers.iter().rev() {
                // Skip committers that don't have a leader for this round.
                let Some(leader) = committer.elect_leader(round) else {
                    continue;
                };

                // Use cached finalized decision if available.
                if let Some(cached) = self.decided.get(&(leader, round)).cloned() {
                    if cached.is_final() {
                        leaders.push_front(cached);
                        continue;
                    }
                    self.decided.remove(&(leader, round));
                }

                tracing::debug!(
                    "Trying to decide {} with {committer}",
                    format_authority_round(leader, round)
                );
                // Build or retrieve cached voter info for this (leader, round).
                let voting_round = round + 1 as RoundNumber;
                let voting_round_version = self.dag_state.round_version(voting_round);
                let needs_rebuild = !matches!(
                    self.voters_cache.get(&(leader, round)),
                    Some((ver, _)) if *ver == voting_round_version
                );
                if needs_rebuild {
                    let potential_voting_blocks =
                        self.dag_state.get_blocks_by_round_cached(voting_round);
                    let mut voters = AHashSet::new();
                    let mut voter_strong_votes = AHashMap::new();
                    for vb in potential_voting_blocks.iter() {
                        let vb_ref = *vb.reference();
                        for reference in vb.block_references() {
                            if reference.round == round && reference.authority == leader {
                                voters.insert((*reference, vb_ref));
                                voter_strong_votes.insert(vb_ref, vb.strong_vote());
                                break;
                            }
                        }
                    }
                    self.voters_cache.insert(
                        (leader, round),
                        (
                            voting_round_version,
                            VoterInfo {
                                voters,
                                voter_strong_votes,
                            },
                        ),
                    );
                }
                let voter_info = &self.voters_cache[&(leader, round)].1;

                // Try to directly decide the leader.
                let timer_direct_decide = self
                    .metrics
                    .utilization_timer
                    .utilization_timer("Committer::direct_decide");
                let mut status = committer.try_direct_decide(leader, round, voter_info);
                drop(timer_direct_decide);
                tracing::debug!("Outcome of direct rule: {status}");

                // If the leader is not final (undecided, or Commit(Pending) for StarfishS),
                // try to resolve via indirect rule.
                let timer_indirect_decide = self
                    .metrics
                    .utilization_timer
                    .utilization_timer("Committer::indirect_decide");
                if !status.is_final() {
                    status =
                        committer.try_indirect_decide(leader, round, leaders.iter(), voter_info);
                    if status.is_decided() {
                        indirect_decided.insert((leader, round));
                    }
                    tracing::debug!("Outcome of indirect rule: {status}");
                }
                drop(timer_indirect_decide);

                if status.is_final() {
                    self.decided.insert((leader, round), status.clone());
                } else {
                    self.decided.remove(&(leader, round));
                }

                leaders.push_front(status);
            }
        }

        // The decided sequence is the longest prefix of decided leaders.
        leaders
            .into_iter()
            // Skip all leaders before the last decided round.
            .skip_while(|x| (x.round(), x.authority()) != last_decided_round_authority)
            // Skip the last decided leader.
            .skip(1)
            // Filter out all the genesis.
            .filter(|x| x.round() > 0)
            // Stop the sequence upon encountering a non-final leader.
            // For StarfishS, Commit(Pending) blocks sequencing; for others is_final == is_decided.
            .take_while(|x| x.is_final())
            .inspect(|x| {
                tracing::debug!("Decided {x}");
                let direct_decide = !indirect_decided.contains(&(x.authority(), x.round()));
                self.update_metrics(x, direct_decide);
            })
            .collect()
    }

    /// Return list of leaders for the round. Syncer may give those leaders some
    /// extra time. To preserve (theoretical) liveness, we should wait
    /// `Delta` time for at least the first leader.
    /// Can return empty vec if round does not have a designated leader.
    pub fn get_leaders(&self, round: RoundNumber) -> Vec<AuthorityIndex> {
        self.committers
            .iter()
            .filter_map(|committer| committer.elect_leader(round))
            .collect()
    }

    /// Evict cached decisions below the given threshold round.
    pub fn cleanup(&mut self, threshold_round: RoundNumber) {
        self.decided
            .retain(|&(_, round), _| round >= threshold_round);
        self.voters_cache
            .retain(|&(_, round), _| round >= threshold_round);
    }

    /// Update metrics.
    fn update_metrics(&self, leader: &LeaderStatus, direct_decide: bool) {
        let authority = leader.authority().to_string();
        let direct_or_indirect = if direct_decide { "direct" } else { "indirect" };
        let status = match leader {
            LeaderStatus::Commit(.., Some(CommitMetastate::Opt)) => {
                format!("{direct_or_indirect}-commit-opt")
            }
            LeaderStatus::Commit(.., Some(CommitMetastate::Std)) => {
                format!("{direct_or_indirect}-commit-std")
            }
            LeaderStatus::Commit(.., Some(CommitMetastate::Pending)) => return,
            LeaderStatus::Commit(.., None) => format!("{direct_or_indirect}-commit"),
            LeaderStatus::Skip(..) => format!("{direct_or_indirect}-skip"),
            LeaderStatus::Undecided(..) => return,
        };
        self.metrics
            .committed_leaders_total
            .with_label_values(&[&authority, &status])
            .inc();
    }
}

/// A builder for a universal committer. By default, the builder creates a
/// single base committer, that is, a single leader and no pipeline.
pub struct UniversalCommitterBuilder {
    committee: Arc<Committee>,
    dag_state: DagState,
    metrics: Arc<Metrics>,
    wave_length: RoundNumber,
    pipeline: bool,
}

impl UniversalCommitterBuilder {
    pub fn new(committee: Arc<Committee>, dag_state: DagState, metrics: Arc<Metrics>) -> Self {
        match dag_state.consensus_protocol {
            ConsensusProtocol::StarfishPull
            | ConsensusProtocol::Mysticeti
            | ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishS => Self {
                committee,
                dag_state,
                metrics,
                wave_length: WAVE_LENGTH,
                pipeline: true,
            },
            ConsensusProtocol::CordialMiners => Self {
                committee,
                dag_state,
                metrics,
                wave_length: WAVE_LENGTH,
                pipeline: false,
            },
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
            let committer = BaseCommitter::new(self.committee.clone(), self.dag_state.clone())
                .with_options(options);
            committers.push(committer);
        }

        UniversalCommitter {
            dag_state: self.dag_state,
            committers,
            metrics: self.metrics,
            decided: AHashMap::new(),
            voters_cache: AHashMap::new(),
        }
    }
}
