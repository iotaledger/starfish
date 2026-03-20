// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::VecDeque, sync::Arc};

use ahash::{AHashMap, AHashSet};

use super::{CommitMetastate, LeaderStatus, VoterInfo, WAVE_LENGTH, base_committer::BaseCommitter};
use crate::{
    committee::{Committee, QuorumThreshold, StakeAggregator},
    consensus::base_committer::BaseCommitterOptions,
    dag_state::{ConsensusProtocol, DagState},
    metrics::Metrics,
    types::{AuthorityIndex, BlockReference, RoundNumber, Stake, format_authority_round},
};

/// A universal committer uses a collection of committers to commit a sequence
/// of leaders. It can be configured to use a combination of different commit
/// strategies, including multi-leaders, backup leaders, and pipelines.
#[derive(Clone)]
pub struct UniversalCommitter {
    dag_state: DagState,
    committee: Arc<Committee>,
    committers: Vec<BaseCommitter>,
    metrics: Arc<Metrics>,
    /// Cache of already-final leaders to avoid redundant recomputation.
    decided: AHashMap<(AuthorityIndex, RoundNumber), LeaderStatus>,
    /// Version-gated cache of voter info per (leader, leader_round).
    /// Key: (leader, leader_round), Value: (voting_round_version, VoterInfo).
    voters_cache: AHashMap<(AuthorityIndex, RoundNumber), (u64, VoterInfo)>,
    /// Leaders whose metrics have already been reported (to avoid overcounting
    /// when the same decided leader is re-emitted across multiple `try_commit`
    /// calls).
    metrics_emitted: AHashSet<(AuthorityIndex, RoundNumber)>,
}

impl UniversalCommitter {
    /// Try to commit part of the dag. This function is idempotent and returns a
    /// list of ordered decided leaders.
    #[tracing::instrument(skip_all, fields(last_decided = %last_decided))]
    pub fn try_commit(&mut self, last_decided: BlockReference) -> Vec<LeaderStatus> {
        if self.dag_state.consensus_protocol == ConsensusProtocol::SailfishPlusPlus {
            return self.try_commit_sailfish(last_decided);
        }
        if self.dag_state.consensus_protocol == ConsensusProtocol::Bluestreak {
            return self.try_commit_bluestreak(last_decided);
        }

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
                        if self.dag_state.consensus_protocol == ConsensusProtocol::StarfishBls {
                            if let Some(leader_ref) =
                                vb.header().starfish_bls_voted_leader(&self.committee)
                            {
                                if leader_ref.round == round && leader_ref.authority == leader {
                                    voters.insert((*leader_ref, vb_ref));
                                    voter_strong_votes.insert(vb_ref, vb.strong_vote());
                                }
                            }
                        } else {
                            for reference in vb.block_references() {
                                if reference.round == round && reference.authority == leader {
                                    voters.insert((*reference, vb_ref));
                                    voter_strong_votes.insert(vb_ref, vb.strong_vote());
                                    break;
                                }
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
                let mut status = committer.try_direct_decide(leader, round, voter_info);
                tracing::debug!("Outcome of direct rule: {status}");

                // If the leader is not final (undecided, or Commit(Pending) for StarfishSpeed),
                // try to resolve via indirect rule.
                if !status.is_final() {
                    status =
                        committer.try_indirect_decide(leader, round, leaders.iter(), voter_info);
                    if status.is_decided() {
                        indirect_decided.insert((leader, round));
                    }
                    tracing::debug!("Outcome of indirect rule: {status}");
                }

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
            // For StarfishSpeed, Commit(Pending) blocks sequencing; for others is_final ==
            // is_decided.
            .take_while(|x| x.is_final())
            .inspect(|x| {
                let key = (x.authority(), x.round());
                if self.metrics_emitted.insert(key) {
                    tracing::debug!("Decided {x}");
                    let direct_decide = !indirect_decided.contains(&key);
                    self.update_metrics(x, direct_decide);
                }
            })
            .collect()
    }

    fn try_commit_bluestreak(&mut self, last_decided: BlockReference) -> Vec<LeaderStatus> {
        let highest_known_round = self.dag_state.highest_round();
        let last_decided_round = last_decided.round();
        let highest_anchor = highest_known_round.saturating_sub(2);
        let mut committed = Vec::new();
        let mut newly_committed = AHashSet::new();

        for round in last_decided_round + 1..=highest_anchor {
            let leader = self.committee.elect_leader(round);

            // Fast path: reuse finalized decisions from previous calls.
            let key = (leader, round);
            if let Some(cached) = self.decided.get(&key) {
                if cached.is_final() {
                    committed.push(cached.clone());
                    if matches!(cached, LeaderStatus::Commit(..)) {
                        newly_committed.insert(key);
                    }
                    continue;
                }
            }

            if self.check_direct_skip_bluestreak(leader, round) {
                if !self.decided.contains_key(&key) {
                    let status = LeaderStatus::Skip(leader, round);
                    self.decided.insert(key, status.clone());
                    if self.metrics_emitted.insert(key) {
                        tracing::debug!("Decided {status}");
                        self.update_metrics(&status, true);
                    }
                    committed.push(status);
                }
                continue;
            }

            let Some(anchor) = self.try_direct_commit_bluestreak(leader, round) else {
                continue;
            };

            let mut chain = vec![anchor.clone()];
            let mut current = anchor;
            for prev_round in (last_decided_round + 1..current.round()).rev() {
                let prev_leader = self.committee.elect_leader(prev_round);
                let prev_key = (prev_leader, prev_round);
                if newly_committed.contains(&prev_key) {
                    continue;
                }

                let mut linked_leaders: Vec<_> = self
                    .dag_state
                    .get_blocks_at_authority_round(prev_leader, prev_round)
                    .into_iter()
                    .filter(|block| self.dag_state.has_vertex_certificate(block.reference()))
                    .filter(|block| self.dag_state.linked(&current, block))
                    .collect();

                if linked_leaders.len() > 1 {
                    panic!(
                        "[Bluestreak] More than one linked leader for {}",
                        format_authority_round(prev_leader, prev_round)
                    );
                }

                if let Some(prev) = linked_leaders.pop() {
                    current = prev.clone();
                    chain.push(prev);
                }
            }

            chain.reverse();
            for leader_block in chain {
                let key = (leader_block.authority(), leader_block.round());
                if !newly_committed.insert(key) {
                    continue;
                }
                let direct_decide = key.1 == round;
                let status = LeaderStatus::Commit(leader_block, None);
                self.decided.insert(key, status.clone());
                if self.metrics_emitted.insert(key) {
                    tracing::debug!("Decided {status}");
                    self.update_metrics(&status, direct_decide);
                }
                committed.push(status);
            }
        }

        committed.sort();
        committed
    }

    fn try_direct_commit_bluestreak(
        &self,
        leader: AuthorityIndex,
        leader_round: RoundNumber,
    ) -> Option<crate::data::Data<crate::types::VerifiedBlock>> {
        let cert_round = leader_round + 2;
        let leader_blocks = self
            .dag_state
            .get_blocks_at_authority_round(leader, leader_round);

        for leader_block in leader_blocks {
            if !self
                .dag_state
                .has_vertex_certificate(leader_block.reference())
            {
                continue;
            }
            let leader_ref = *leader_block.reference();
            let cert_blocks = self.dag_state.get_blocks_by_round_cached(cert_round);
            let mut supporters = StakeAggregator::<QuorumThreshold>::new();
            for block in cert_blocks.iter() {
                if block.unprovable_certificate() == Some(&leader_ref)
                    && supporters.add(block.authority(), &self.committee)
                {
                    return Some(leader_block);
                }
            }
        }

        None
    }

    fn check_direct_skip_bluestreak(&self, leader: AuthorityIndex, round: RoundNumber) -> bool {
        let vote_round = round + 1;
        let vote_blocks = self.dag_state.get_blocks_by_round_cached(vote_round);
        let mut non_voters = StakeAggregator::<QuorumThreshold>::new();
        for block in vote_blocks.iter() {
            let votes_for = block
                .block_references()
                .iter()
                .any(|r| r.round == round && r.authority == leader);
            if !votes_for && non_voters.add(block.authority(), &self.committee) {
                return true;
            }
        }
        false
    }

    fn try_commit_sailfish(&mut self, last_decided: BlockReference) -> Vec<LeaderStatus> {
        let highest_known_round = self.dag_state.highest_round();
        let last_decided_round = last_decided.round();
        let highest_possible_leader_to_decide_round = highest_known_round.saturating_sub(1);
        let mut committed = Vec::new();
        let mut newly_committed = AHashSet::new();
        let mut skipped = AHashSet::new();

        for round in last_decided_round + 1..=highest_possible_leader_to_decide_round {
            let leader = self.committee.elect_leader(round);

            // Direct skip: if a no-vote certificate exists for this slot,
            // the leader provably cannot be committed.
            if self.dag_state.has_novote_cert(round, leader) {
                skipped.insert((leader, round));
                let key = (leader, round);
                if !self.decided.contains_key(&key) {
                    let status = LeaderStatus::Skip(leader, round);
                    self.decided.insert(key, status.clone());
                    if self.metrics_emitted.insert(key) {
                        tracing::debug!("Decided {status}");
                        self.update_metrics(&status, true);
                    }
                    committed.push(status);
                }
                continue;
            }

            let Some(anchor) = self.try_direct_commit_block_sailfish(leader, round) else {
                continue;
            };

            // Backward walk: resolve older slots between last_decided and
            // this anchor. If anchor has a causal path to a certified leader
            // at slot s, commit it. If an NVC exists for slot s, skip it.
            let mut chain = vec![anchor.clone()];
            let mut current = anchor;
            for prev_round in (last_decided_round + 1..current.round()).rev() {
                let prev_leader = self.committee.elect_leader(prev_round);
                let prev_key = (prev_leader, prev_round);
                if newly_committed.contains(&prev_key) || skipped.contains(&prev_key) {
                    continue;
                }

                // Check for NVC-based skip.
                if self.dag_state.has_novote_cert(prev_round, prev_leader) {
                    skipped.insert(prev_key);
                    let status = LeaderStatus::Skip(prev_leader, prev_round);
                    self.decided.insert(prev_key, status.clone());
                    if self.metrics_emitted.insert(prev_key) {
                        tracing::debug!("Decided {status}");
                        self.update_metrics(&status, false);
                    }
                    committed.push(status);
                    continue;
                }

                let mut linked_leaders: Vec<_> = self
                    .dag_state
                    .get_blocks_at_authority_round(prev_leader, prev_round)
                    .into_iter()
                    .filter(|block| self.dag_state.has_vertex_certificate(block.reference()))
                    .filter(|block| self.dag_state.linked(&current, block))
                    .collect();

                if linked_leaders.len() > 1 {
                    panic!(
                        "[Sailfish] More than one linked leader for {}",
                        format_authority_round(prev_leader, prev_round)
                    );
                }

                if let Some(prev) = linked_leaders.pop() {
                    current = prev.clone();
                    chain.push(prev);
                }
            }

            chain.reverse();
            for leader_block in chain {
                let key = (leader_block.authority(), leader_block.round());
                if !newly_committed.insert(key) {
                    continue;
                }
                let direct_decide = leader_block.round() == round;
                let status = LeaderStatus::Commit(leader_block, None);
                self.decided.insert(key, status.clone());
                if self.metrics_emitted.insert(key) {
                    tracing::debug!("Decided {status}");
                    self.update_metrics(&status, direct_decide);
                }
                committed.push(status);
            }
        }

        committed.sort();
        committed
    }

    fn try_direct_commit_block_sailfish(
        &self,
        leader: AuthorityIndex,
        leader_round: RoundNumber,
    ) -> Option<crate::data::Data<crate::types::VerifiedBlock>> {
        let support_round = leader_round + 1;
        let leader_blocks = self
            .dag_state
            .get_blocks_at_authority_round(leader, leader_round);

        let mut committed_leaders: Vec<_> = leader_blocks
            .into_iter()
            .filter(|leader_block| {
                self.dag_state
                    .has_vertex_certificate(leader_block.reference())
            })
            .filter(|leader_block| {
                let support =
                    self.supporting_stake_for_sailfish(leader_block.reference(), support_round);
                let delivered_support = self.delivered_supporting_stake_for_sailfish(
                    leader_block.reference(),
                    support_round,
                );
                support >= self.committee.quorum_threshold()
                    || delivered_support >= self.committee.validity_threshold()
            })
            .collect();

        if committed_leaders.len() > 1 {
            panic!(
                "[Sailfish] More than one certified block for {}",
                format_authority_round(leader, leader_round)
            )
        }

        committed_leaders.pop()
    }

    fn supporting_stake_for_sailfish(
        &self,
        leader_ref: &BlockReference,
        support_round: RoundNumber,
    ) -> Stake {
        let supporting_blocks = self.dag_state.get_blocks_by_round_cached(support_round);
        let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
        for block in supporting_blocks.iter() {
            if block
                .block_references()
                .iter()
                .any(|reference| reference == leader_ref)
            {
                aggregator.add(block.authority(), &self.committee);
            }
        }
        aggregator.get_stake()
    }

    fn delivered_supporting_stake_for_sailfish(
        &self,
        leader_ref: &BlockReference,
        support_round: RoundNumber,
    ) -> Stake {
        let supporting_blocks = self.dag_state.get_blocks_by_round_cached(support_round);
        let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
        for block in supporting_blocks.iter() {
            if !self.dag_state.has_vertex_certificate(block.reference()) {
                continue;
            }
            if block
                .block_references()
                .iter()
                .any(|reference| reference == leader_ref)
            {
                aggregator.add(block.authority(), &self.committee);
            }
        }
        aggregator.get_stake()
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
        self.metrics_emitted
            .retain(|&(_, round)| round >= threshold_round);
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
            ConsensusProtocol::Mysticeti
            | ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishSpeed
            | ConsensusProtocol::StarfishBls => Self {
                committee,
                dag_state,
                metrics,
                wave_length: WAVE_LENGTH,
                pipeline: true,
            },
            ConsensusProtocol::SailfishPlusPlus => Self {
                committee,
                dag_state,
                metrics,
                wave_length: WAVE_LENGTH,
                pipeline: false,
            },
            ConsensusProtocol::Bluestreak => Self {
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
            committee: self.committee,
            committers,
            metrics: self.metrics,
            decided: AHashMap::new(),
            voters_cache: AHashMap::new(),
            metrics_emitted: AHashSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    use crate::{
        config::StorageBackend,
        crypto::{SignatureBytes, TransactionsCommitment},
        dag_state::DataSource,
        data::Data,
    };
    use prometheus::Registry;

    fn open_test_dag_state_for(consensus: &str, authority: AuthorityIndex) -> DagState {
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) =
            Metrics::new(&registry, Some(committee.as_ref()), Some(consensus), None);
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        std::mem::forget(dir);
        DagState::open(
            authority,
            path,
            metrics,
            committee,
            "honest".to_string(),
            consensus.to_string(),
            &StorageBackend::Rocksdb,
            false,
        )
        .dag_state
    }

    fn make_full_block(
        authority: AuthorityIndex,
        round: RoundNumber,
        parents: Vec<BlockReference>,
    ) -> Data<crate::types::VerifiedBlock> {
        let empty_transactions = Vec::new();
        let merkle_root = TransactionsCommitment::new_from_transactions(&empty_transactions);
        let mut block = crate::types::VerifiedBlock::new(
            authority,
            round,
            parents,
            Vec::new(),
            0,
            SignatureBytes::default(),
            empty_transactions,
            merkle_root,
            None,
            None,
            None,
        );
        block.preserialize();
        Data::new(block)
    }

    #[test]
    fn sailfish_direct_commit_accepts_f_plus_1_delivered_supporters() {
        let dag_state = open_test_dag_state_for("sailfish-pp", 0);
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("sailfish-pp"),
            None,
        );

        let leader = make_full_block(1, 1, vec![BlockReference::new_test(1, 0)]);
        let leader_ref = *leader.reference();
        let supporter_a = make_full_block(0, 2, vec![leader_ref]);
        let supporter_b = make_full_block(2, 2, vec![leader_ref]);

        dag_state.insert_general_block(leader, DataSource::BlockBundleStreaming);
        dag_state.insert_general_block(supporter_a.clone(), DataSource::BlockBundleStreaming);
        dag_state.insert_general_block(supporter_b.clone(), DataSource::BlockBundleStreaming);

        dag_state.mark_vertices_certified(&[
            leader_ref,
            *supporter_a.reference(),
            *supporter_b.reference(),
        ]);

        let mut committer = UniversalCommitterBuilder::new(committee, dag_state, metrics).build();

        let decided = committer.try_commit(BlockReference::new_test(0, 0));
        assert!(
            decided.iter().any(|status| {
                matches!(
                    status,
                    LeaderStatus::Commit(block, None)
                        if block.authority() == 1 && block.round() == 1
                )
            }),
            "expected round-1 leader to commit with f+1 certified supporters in round 2"
        );
    }

    #[test]
    fn bluestreak_direct_commit_uses_unprovable_certificates() {
        let dag_state = open_test_dag_state_for("bluestreak", 0);
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("bluestreak"),
            None,
        );

        let leader = make_full_block(1, 1, vec![BlockReference::new_test(1, 0)]);
        let leader_ref = *leader.reference();
        let vote_a = make_full_block(0, 2, vec![leader_ref]);
        let vote_b = make_full_block(2, 2, vec![leader_ref]);
        let vote_c = make_full_block(3, 2, vec![leader_ref]);

        let empty_transactions = Vec::new();
        let commitment = TransactionsCommitment::new_from_transactions(&empty_transactions);

        let mut cert_a = crate::types::VerifiedBlock::new_with_unprovable(
            0,
            3,
            vec![*vote_a.reference()],
            Vec::new(),
            0,
            SignatureBytes::default(),
            empty_transactions.clone(),
            commitment,
            None,
            None,
            None,
            Some(leader_ref),
        );
        cert_a.preserialize();
        let cert_a = Data::new(cert_a);

        let mut cert_b = crate::types::VerifiedBlock::new_with_unprovable(
            2,
            3,
            vec![*vote_b.reference()],
            Vec::new(),
            0,
            SignatureBytes::default(),
            empty_transactions.clone(),
            commitment,
            None,
            None,
            None,
            Some(leader_ref),
        );
        cert_b.preserialize();
        let cert_b = Data::new(cert_b);

        let mut cert_c = crate::types::VerifiedBlock::new_with_unprovable(
            3,
            3,
            vec![*vote_c.reference()],
            Vec::new(),
            0,
            SignatureBytes::default(),
            empty_transactions,
            commitment,
            None,
            None,
            None,
            Some(leader_ref),
        );
        cert_c.preserialize();
        let cert_c = Data::new(cert_c);

        dag_state.insert_general_block(leader, DataSource::BlockBundleStreaming);
        dag_state.insert_general_block(vote_a, DataSource::BlockBundleStreaming);
        dag_state.insert_general_block(vote_b, DataSource::BlockBundleStreaming);
        dag_state.insert_general_block(vote_c, DataSource::BlockBundleStreaming);
        dag_state.insert_general_block(cert_a, DataSource::BlockBundleStreaming);
        dag_state.insert_general_block(cert_b, DataSource::BlockBundleStreaming);
        dag_state.insert_general_block(cert_c, DataSource::BlockBundleStreaming);

        let mut committer = UniversalCommitterBuilder::new(committee, dag_state, metrics).build();
        let decided = committer.try_commit(BlockReference::new_test(0, 0));

        assert!(
            decided.iter().any(|status| {
                matches!(
                    status,
                    LeaderStatus::Commit(block, None)
                        if block.authority() == 1 && block.round() == 1
                )
            }),
            "expected round-1 leader to commit from round-3 unprovable certificates"
        );
    }
}
