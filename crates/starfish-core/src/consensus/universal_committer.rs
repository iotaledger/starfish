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
        if self.dag_state.consensus_protocol.is_sailfish_pp() {
            return self.try_commit_sailfish(last_decided);
        }
        if self.dag_state.consensus_protocol.is_bluestreak()
            || self.dag_state.consensus_protocol == ConsensusProtocol::SparseStarfishSpeed
        {
            return self.try_commit_compressed_refs(last_decided);
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
                        if self.dag_state.consensus_protocol.uses_bls() {
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

    /// Commit path shared by Bluestreak and SparseStarfishSpeed (both use
    /// compressed references and an on-wire `unprovable_certificate` for
    /// direct commit). The two protocols differ only in two narrow points
    /// handled inline: (a) Bluestreak filters the chain walk-back by
    /// `has_clean_vertex` (which it tracks via dual-DAG support);
    /// SparseStarfishSpeed has no such tracking. (b) SparseStarfishSpeed
    /// also derives a `CommitMetastate` from the cert flavors at the
    /// certifying round; Bluestreak always reports `None`.
    fn try_commit_compressed_refs(&mut self, last_decided: BlockReference) -> Vec<LeaderStatus> {
        let protocol = self.dag_state.consensus_protocol;
        let is_bluestreak = protocol.is_bluestreak();
        let protocol_name = if is_bluestreak {
            "Bluestreak"
        } else {
            "SparseStarfishSpeed"
        };

        let highest_known_round = self.dag_state.highest_round();
        let last_decided_round = last_decided.round();
        let highest_anchor = highest_known_round.saturating_sub(2);
        let mut committed = Vec::new();
        let mut newly_committed = AHashSet::new();

        for round in last_decided_round + 1..=highest_anchor {
            let leader = self.committee.elect_leader(round);

            // Fast path: reuse finalized decisions from previous calls.
            // Only re-emit Commits; cached Skips still short-circuit evaluation
            // but are not pushed to `committed` (matching the original guard
            // behavior that never re-emitted Skips).
            let key = (leader, round);
            if let Some(cached) = self.decided.get(&key) {
                if cached.is_final() {
                    if let LeaderStatus::Commit(..) = cached {
                        committed.push(cached.clone());
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

            let direct = if is_bluestreak {
                self.try_direct_commit_bluestreak(leader, round)
                    .map(|b| (b, None))
            } else {
                self.try_direct_commit_sparse_starfish_speed(leader, round)
            };
            let Some((anchor, anchor_metastate)) = direct else {
                continue;
            };

            // Walk back through prior rounds. Bluestreak additionally
            // filters by `has_clean_vertex` to skip leaders that the
            // dual-DAG machinery has not certified.
            let mut chain = vec![(anchor.clone(), anchor_metastate)];
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
                    .filter(|block| {
                        !is_bluestreak || self.dag_state.has_clean_vertex(block.reference())
                    })
                    .filter(|block| self.dag_state.linked(&current, block))
                    .collect();

                if linked_leaders.len() > 1 {
                    panic!(
                        "[{protocol_name}] More than one linked leader for {}",
                        format_authority_round(prev_leader, prev_round)
                    );
                }

                if let Some(prev) = linked_leaders.pop() {
                    current = prev.clone();
                    // SparseStarfishSpeed: re-derive the metastate for
                    // every chain-walked leader from its OWN certifying-
                    // round certs + voting-round strong-blame quorum.
                    // If sufficient certs exist for the older leader,
                    // promote its ack list via Opt; if a mixed-cert
                    // quorum sits alongside a strong-blame quorum at the
                    // voting round, Std; otherwise leave metastate as
                    // None (treated as no ack derivation by the
                    // linearizer). Bluestreak always uses None.
                    let prev_metastate = if is_bluestreak {
                        None
                    } else {
                        self.try_direct_commit_sparse_starfish_speed(prev.authority(), prev.round())
                            .and_then(|(_, ms)| ms)
                    };
                    chain.push((prev, prev_metastate));
                }
            }

            chain.reverse();
            for (leader_block, metastate) in chain {
                let key = (leader_block.authority(), leader_block.round());
                if !newly_committed.insert(key) {
                    continue;
                }
                let direct_decide = key.1 == round;
                let status = LeaderStatus::Commit(leader_block, metastate);
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
            if !self.dag_state.has_clean_vertex(leader_block.reference()) {
                continue;
            }
            let leader_ref = *leader_block.reference();
            let cert_blocks = self.dag_state.get_blocks_by_round_cached(cert_round);
            let mut supporters = StakeAggregator::<QuorumThreshold>::new();
            for block in cert_blocks.iter() {
                if block.unprovable_certificate().map(|(r, _)| r) == Some(leader_ref)
                    && supporters.add(block.authority(), &self.committee)
                {
                    return Some(leader_block);
                }
            }
        }

        None
    }

    /// SparseStarfishSpeed direct-commit: a leader at round r is committed
    /// when 2f+1 round-(r+2) blocks each carry an `unprovable_certificate`
    /// pointing to that leader. Returns the (leader_block, metastate) pair.
    /// Metastate:
    ///   - Opt    iff 2f+1 of those certs carry `strong = true`
    ///   - Std    iff 2f+1 mixed AND 2f+1 round-(r+1) voters of the leader are
    ///     `is_strong_blame()`
    ///   - Pending otherwise (sequencing blocks until indirect rule resolves)
    fn try_direct_commit_sparse_starfish_speed(
        &self,
        leader: AuthorityIndex,
        leader_round: RoundNumber,
    ) -> Option<(
        crate::data::Data<crate::types::VerifiedBlock>,
        Option<CommitMetastate>,
    )> {
        let cert_round = leader_round + 2;
        let voting_round = leader_round + 1;
        let leader_blocks = self
            .dag_state
            .get_blocks_at_authority_round(leader, leader_round);

        let cert_blocks = self.dag_state.get_blocks_by_round_cached(cert_round);

        for leader_block in leader_blocks {
            let leader_ref = *leader_block.reference();
            let mut all_supporters = StakeAggregator::<QuorumThreshold>::new();
            let mut strong_supporters = StakeAggregator::<QuorumThreshold>::new();
            for block in cert_blocks.iter() {
                let Some((cref, strong)) = block.unprovable_certificate() else {
                    continue;
                };
                if cref != leader_ref {
                    continue;
                }
                all_supporters.add(block.authority(), &self.committee);
                if strong {
                    strong_supporters.add(block.authority(), &self.committee);
                }
            }
            if !all_supporters.is_quorum(&self.committee) {
                continue;
            }

            let metastate = if strong_supporters.is_quorum(&self.committee) {
                Some(CommitMetastate::Opt)
            } else {
                // Mixed certs reached quorum. Check strong-blame at r+1.
                let voting_blocks = self.dag_state.get_blocks_by_round_cached(voting_round);
                let mut strong_blamers = StakeAggregator::<QuorumThreshold>::new();
                for vb in voting_blocks.iter() {
                    let votes_for_leader = vb.block_references().contains(&leader_ref);
                    if votes_for_leader && vb.is_strong_blame() {
                        strong_blamers.add(vb.authority(), &self.committee);
                    }
                }
                if strong_blamers.is_quorum(&self.committee) {
                    Some(CommitMetastate::Std)
                } else {
                    Some(CommitMetastate::Pending)
                }
            };
            return Some((leader_block, metastate));
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
                    .filter(|block| self.dag_state.has_clean_vertex(block.reference()))
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
            .filter(|leader_block| self.dag_state.has_clean_vertex(leader_block.reference()))
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
            if !self.dag_state.has_clean_vertex(block.reference()) {
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
            | ConsensusProtocol::StarfishBls
            | ConsensusProtocol::MysticetiBls
            | ConsensusProtocol::SparseStarfishSpeed => Self {
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
        config::{DisseminationMode, StorageBackend},
        consensus::linearizer::Linearizer,
        crypto::SignatureBytes,
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
            DisseminationMode::ProtocolDefault,
        )
        .dag_state
    }

    fn make_full_block(
        authority: AuthorityIndex,
        round: RoundNumber,
        parents: Vec<BlockReference>,
    ) -> Data<crate::types::VerifiedBlock> {
        let mut block = crate::types::VerifiedBlock::new(
            authority,
            round,
            parents,
            Vec::new(),
            0,
            SignatureBytes::default(),
            Vec::new(),
            None,
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

        dag_state.mark_vertices_clean(&[
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

        let mut cert_a = crate::types::VerifiedBlock::new_with_unprovable(
            0,
            3,
            vec![*vote_a.reference()],
            Vec::new(),
            0,
            SignatureBytes::default(),
            Vec::new(),
            None,
            None,
            None,
            None,
            Some((leader_ref, false)),
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
            Vec::new(),
            None,
            None,
            None,
            None,
            Some((leader_ref, false)),
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
            Vec::new(),
            None,
            None,
            None,
            None,
            Some((leader_ref, false)),
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

    // ────────────────────────────────────────────────────────────────────
    //  SparseStarfishSpeed commit-decision truth table (4-validator DAG)
    // ────────────────────────────────────────────────────────────────────
    //
    // n=4 → f=1 → quorum = 3. For a candidate leader L at round r, the
    // commit decision at round r+2 is one of:
    //
    //   Opt     iff 2f+1 round-(r+2) blocks carry Some((L.ref, true))
    //   Std     iff 2f+1 mixed certs at r+2 AND 2f+1 round-(r+1)
    //               voters of L are `is_strong_blame()`
    //   Pending iff 2f+1 mixed certs at r+2 but no strong-blame quorum
    //   Skip    iff 2f+1 round-(r+1) blocks fail to reference L
    //   None    iff < 2f+1 certs of any flavor at r+2
    //
    // We exercise each branch by fabricating round-r+1 voters and
    // round-r+2 certifiers directly (the `insert_general_block` path does
    // not validate, so blocks need only be structurally well-formed).

    fn ssfs_setup() -> (Arc<Committee>, DagState, Arc<crate::metrics::Metrics>) {
        let dag_state = open_test_dag_state_for("sparse-starfish-speed", 0);
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("sparse-starfish-speed"),
            None,
        );
        (committee, dag_state, metrics)
    }

    fn ssfs_block(
        authority: AuthorityIndex,
        round: RoundNumber,
        parents: Vec<BlockReference>,
        acks: Vec<BlockReference>,
        strong_vote: Option<crate::types::AuthoritySet>,
        unprovable_cert: Option<(BlockReference, bool)>,
    ) -> Data<crate::types::VerifiedBlock> {
        let mut block = crate::types::VerifiedBlock::new_with_unprovable(
            authority,
            round,
            parents,
            acks,
            0,
            SignatureBytes::default(),
            Vec::new(),
            None,
            strong_vote,
            None,
            None,
            unprovable_cert,
        );
        block.preserialize();
        Data::new(block)
    }

    /// Convenience: a strong vote with a single blame bit set.
    fn blame_mask(blamed: AuthorityIndex) -> crate::types::AuthoritySet {
        let mut m = crate::types::AuthoritySet::default();
        m.insert(blamed);
        m
    }

    /// Fabricate L at round `leader_round` with no parents/acks. The
    /// caller picks `leader_round` so that `committee.elect_leader` lands
    /// on the desired authority. The block is inserted into DagState.
    fn insert_leader(
        dag_state: &DagState,
        committee: &Committee,
        leader_round: RoundNumber,
    ) -> (AuthorityIndex, BlockReference) {
        let leader_authority = committee.elect_leader(leader_round);
        let leader = ssfs_block(leader_authority, leader_round, vec![], vec![], None, None);
        let leader_ref = *leader.reference();
        dag_state.insert_general_block(leader, DataSource::BlockBundleStreaming);
        (leader_authority, leader_ref)
    }

    /// Insert one cert at the certifying round with the given flavor.
    fn insert_cert(
        dag_state: &DagState,
        authority: AuthorityIndex,
        cert_round: RoundNumber,
        leader_ref: BlockReference,
        strong: bool,
    ) {
        let cert = ssfs_block(
            authority,
            cert_round,
            vec![],
            vec![],
            None,
            Some((leader_ref, strong)),
        );
        dag_state.insert_general_block(cert, DataSource::BlockBundleStreaming);
    }

    /// Insert one voter at the voting round, referencing the leader,
    /// with the chosen strong_vote mask.
    fn insert_voter(
        dag_state: &DagState,
        authority: AuthorityIndex,
        voting_round: RoundNumber,
        leader_ref: BlockReference,
        strong_vote: Option<crate::types::AuthoritySet>,
    ) {
        let voter = ssfs_block(
            authority,
            voting_round,
            vec![leader_ref],
            vec![],
            strong_vote,
            None,
        );
        dag_state.insert_general_block(voter, DataSource::BlockBundleStreaming);
    }

    /// Build a UniversalCommitter wired to the given DagState (committee
    /// is cloned for the builder; tests own the `Arc<Committee>` for any
    /// extra calls).
    fn build_committer(
        committee: Arc<Committee>,
        dag_state: DagState,
        metrics: Arc<crate::metrics::Metrics>,
    ) -> UniversalCommitter {
        UniversalCommitterBuilder::new(committee, dag_state, metrics).build()
    }

    // ── 1. Opt ────────────────────────────────────────────────────────
    #[test]
    fn ssfs_direct_commit_opt_with_strong_cert_quorum() {
        let (committee, dag_state, metrics) = ssfs_setup();
        let (leader_auth, leader_ref) = insert_leader(&dag_state, &committee, 3);

        // 3 strong certs at the certifying round (cert.round + 2 == 5).
        for auth in [0u16, 1, 2] {
            insert_cert(&dag_state, auth, 5, leader_ref, true);
        }

        let committer = build_committer(committee, dag_state, metrics);
        let result = committer.try_direct_commit_sparse_starfish_speed(leader_auth, 3);

        let (anchor, metastate) =
            result.expect("3 strong certs constitute a quorum — leader must commit");
        assert_eq!(*anchor.reference(), leader_ref);
        assert_eq!(
            metastate,
            Some(CommitMetastate::Opt),
            "strong-cert quorum must yield Opt"
        );
    }

    // ── 2. Std (mixed certs + strong-blame quorum at the voting round) ─
    #[test]
    fn ssfs_direct_commit_std_with_mixed_certs_and_strong_blame_quorum() {
        let (committee, dag_state, metrics) = ssfs_setup();
        let (leader_auth, leader_ref) = insert_leader(&dag_state, &committee, 3);

        // Mixed cert quorum: 1 strong + 2 standard at round 5.
        insert_cert(&dag_state, 0, 5, leader_ref, true);
        insert_cert(&dag_state, 1, 5, leader_ref, false);
        insert_cert(&dag_state, 2, 5, leader_ref, false);

        // 3 strong-blame voters at the voting round 4 (they reference L
        // but emit a non-empty mask — the `is_strong_blame()` quorum).
        let mask = blame_mask(leader_auth);
        for auth in [0u16, 1, 2] {
            insert_voter(&dag_state, auth, 4, leader_ref, Some(mask));
        }

        let committer = build_committer(committee, dag_state, metrics);
        let result = committer.try_direct_commit_sparse_starfish_speed(leader_auth, 3);

        let (_anchor, metastate) =
            result.expect("3 mixed certs constitute a cert quorum — leader must commit");
        assert_eq!(
            metastate,
            Some(CommitMetastate::Std),
            "mixed cert quorum + 2f+1 strong-blames must yield Std"
        );
    }

    // ── 3. Pending (mixed certs but no strong-blame quorum) ───────────
    #[test]
    fn ssfs_direct_commit_pending_without_strong_blame_quorum() {
        let (committee, dag_state, metrics) = ssfs_setup();
        let (leader_auth, leader_ref) = insert_leader(&dag_state, &committee, 3);

        // Same mixed cert quorum as the Std test.
        insert_cert(&dag_state, 0, 5, leader_ref, true);
        insert_cert(&dag_state, 1, 5, leader_ref, false);
        insert_cert(&dag_state, 2, 5, leader_ref, false);

        // Only ONE strong-blame voter at the voting round (below quorum).
        // Two clean voters keep the strong-blame count under 2f+1.
        let mask = blame_mask(leader_auth);
        insert_voter(&dag_state, 0, 4, leader_ref, Some(mask));
        insert_voter(
            &dag_state,
            1,
            4,
            leader_ref,
            Some(crate::types::AuthoritySet::default()),
        );
        insert_voter(
            &dag_state,
            2,
            4,
            leader_ref,
            Some(crate::types::AuthoritySet::default()),
        );

        let committer = build_committer(committee, dag_state, metrics);
        let result = committer.try_direct_commit_sparse_starfish_speed(leader_auth, 3);

        let (_anchor, metastate) =
            result.expect("3 mixed certs still commit the leader (kind pending)");
        assert_eq!(
            metastate,
            Some(CommitMetastate::Pending),
            "mixed quorum without 2f+1 strong-blames must defer to indirect rule"
        );
    }

    // ── 4. No direct commit when cert quorum is missing ───────────────
    #[test]
    fn ssfs_direct_commit_none_below_cert_quorum() {
        let (committee, dag_state, metrics) = ssfs_setup();
        let (leader_auth, leader_ref) = insert_leader(&dag_state, &committee, 3);

        // Only 2 certs (any flavor) — short of the 2f+1 = 3 quorum.
        insert_cert(&dag_state, 0, 5, leader_ref, true);
        insert_cert(&dag_state, 1, 5, leader_ref, false);

        let committer = build_committer(committee, dag_state, metrics);
        let result = committer.try_direct_commit_sparse_starfish_speed(leader_auth, 3);

        assert!(
            result.is_none(),
            "< 2f+1 certs of any flavor must NOT trigger direct commit"
        );
    }

    // ────────────────────────────────────────────────────────────────────
    //  Per-c ack derivation (post-Opt commit, in the linearizer)
    // ────────────────────────────────────────────────────────────────────
    //
    // When the committer reports `CommitMetastate::Opt`, the linearizer
    // promotes `c ∈ L.acknowledgments()` to the sub-dag iff 2f+1 distinct
    // round-(L.round+1) voters of L have `!v.strong_vote.contains(c.authority)`.
    // For these tests we fabricate L so that its `block_references` do NOT
    // transitively reach its `acknowledgments` — otherwise the structural
    // BFS in `collect_subdag_ancestors` would commit the acks regardless
    // of the derivation filter, masking the effect we want to observe.

    /// Build a fully-formed SSFS DAG with three ack candidates (a0/a1/a3
    /// at round 1, authorities 0/1/3) disjoint from the leader's
    /// structural parents (p0/p1/p3 at round 2, with refs only to
    /// genesis). The leader L sits at round 3, references the fillers,
    /// and acknowledges the three round-1 ack candidates. Returns
    /// `(committee, dag_state, leader, ack_refs)`.
    #[allow(clippy::type_complexity)]
    fn build_derivation_dag() -> (
        Arc<Committee>,
        DagState,
        Data<crate::types::VerifiedBlock>,
        [BlockReference; 3],
    ) {
        let (committee, dag_state, _metrics) = ssfs_setup();
        let genesis: Vec<_> = (0u16..4)
            .map(|auth| {
                *dag_state
                    .get_blocks_at_authority_round(auth, 0)
                    .first()
                    .expect("genesis block")
                    .reference()
            })
            .collect();

        // Three ack candidates at round 1, each rooted at its own
        // authority's genesis block.
        let mut ack_refs = [
            BlockReference::new_test(0, 0),
            BlockReference::new_test(0, 0),
            BlockReference::new_test(0, 0),
        ];
        for (idx, auth) in [0u16, 1, 3].into_iter().enumerate() {
            let a = ssfs_block(auth, 1, vec![genesis[auth as usize]], vec![], None, None);
            ack_refs[idx] = *a.reference();
            dag_state.insert_general_block(a, DataSource::BlockBundleStreaming);
        }

        // Three filler parents at round 2. Refs point at genesis only,
        // NOT at the ack candidates — so the structural BFS from L does
        // not encounter a0/a1/a3 by accident.
        let mut filler_refs = Vec::new();
        for auth in [0u16, 1, 3] {
            let p = ssfs_block(auth, 2, vec![genesis[auth as usize]], vec![], None, None);
            filler_refs.push(*p.reference());
            dag_state.insert_general_block(p, DataSource::BlockBundleStreaming);
        }

        // Leader at round 3 (committee.elect_leader(3) == 3). Refs are
        // the three fillers; acks are the three ack candidates.
        let leader = ssfs_block(3, 3, filler_refs, ack_refs.to_vec(), None, None);
        let leader_clone = leader.clone();
        dag_state.insert_general_block(leader, DataSource::BlockBundleStreaming);

        (committee, dag_state, leader_clone, ack_refs)
    }

    // ── 6. Opt → all acks promoted when every voter is clean ──────────
    #[test]
    fn ssfs_linearizer_promotes_all_acks_with_clean_voters() {
        let (committee, dag_state, leader, ack_refs) = build_derivation_dag();
        let leader_ref = *leader.reference();

        // Three round-4 voters of L, each with an empty strong_vote.
        for auth in [0u16, 1, 3] {
            insert_voter(
                &dag_state,
                auth,
                4,
                leader_ref,
                Some(crate::types::AuthoritySet::default()),
            );
        }

        let mut linearizer = Linearizer::new((*committee).clone());
        let committed =
            linearizer.handle_commit(&dag_state, vec![(leader, Some(CommitMetastate::Opt))]);

        assert_eq!(committed.len(), 1);
        let (sub_dag, _) = &committed[0];
        let committed_refs: std::collections::BTreeSet<_> =
            sub_dag.blocks.iter().map(|b| *b.reference()).collect();
        for ack in &ack_refs {
            assert!(
                committed_refs.contains(ack),
                "ack {ack:?} should be promoted to subdag — all voters clean"
            );
        }
    }

    // ── 7. Opt → filtered ack when one voter blames its author ─────────
    #[test]
    fn ssfs_linearizer_filters_ack_when_author_blamed() {
        let (committee, dag_state, leader, ack_refs) = build_derivation_dag();
        let leader_ref = *leader.reference();
        let blamed_author = ack_refs[1].authority; // a1 — authored by 1

        // Voter at authority 0 blames authority 1; the other two are clean.
        insert_voter(
            &dag_state,
            0,
            4,
            leader_ref,
            Some(blame_mask(blamed_author)),
        );
        for auth in [1u16, 3] {
            insert_voter(
                &dag_state,
                auth,
                4,
                leader_ref,
                Some(crate::types::AuthoritySet::default()),
            );
        }

        let mut linearizer = Linearizer::new((*committee).clone());
        let committed =
            linearizer.handle_commit(&dag_state, vec![(leader, Some(CommitMetastate::Opt))]);

        let (sub_dag, _) = &committed[0];
        let committed_refs: std::collections::BTreeSet<_> =
            sub_dag.blocks.iter().map(|b| *b.reference()).collect();

        // a0 and a3 still reach 2f+1=3 votes (all three voters).
        assert!(
            committed_refs.contains(&ack_refs[0]),
            "a0 should be promoted"
        );
        assert!(
            committed_refs.contains(&ack_refs[2]),
            "a3 should be promoted"
        );
        // a1 only collects 2 votes (the two clean voters), below quorum.
        assert!(
            !committed_refs.contains(&ack_refs[1]),
            "a1 should NOT be promoted — its author is blamed by one voter, \
             leaving only 2 of 3 derived votes (below 2f+1 quorum)"
        );
    }

    // ── 8. Std → derivation skipped, only structural ancestors commit ─
    #[test]
    fn ssfs_linearizer_skips_ack_derivation_on_std_metastate() {
        let (committee, dag_state, leader, ack_refs) = build_derivation_dag();
        let leader_ref = *leader.reference();

        // Three clean voters — would promote all acks in Opt mode.
        for auth in [0u16, 1, 3] {
            insert_voter(
                &dag_state,
                auth,
                4,
                leader_ref,
                Some(crate::types::AuthoritySet::default()),
            );
        }

        let mut linearizer = Linearizer::new((*committee).clone());
        let committed =
            linearizer.handle_commit(&dag_state, vec![(leader, Some(CommitMetastate::Std))]);

        let (sub_dag, _) = &committed[0];
        let committed_refs: std::collections::BTreeSet<_> =
            sub_dag.blocks.iter().map(|b| *b.reference()).collect();
        for ack in &ack_refs {
            assert!(
                !committed_refs.contains(ack),
                "Std metastate must NOT trigger per-c ack derivation"
            );
        }
    }

    // ── 9 & 10. Indirect (chain-walk-back) metastate derivation ───────
    //
    // In `try_commit_compressed_refs`, when a newer leader `L_anchor`
    // direct-commits and the chain walk-back discovers an older leader
    // `L_old` that has not yet been decided, the chain walk pushes
    // `L_old` to the committed sequence with a metastate derived from
    // `L_old`'s OWN certifying-round certs — not `None`. This means an
    // older leader can pick up `Opt` (or `Std`) from the indirect path
    // and the linearizer will run the per-`c` ack derivation for it.
    //
    // Direct iteration order is ascending, so in a fresh `try_commit`
    // call `L_old`'s round is processed before `L_anchor`'s and would
    // normally direct-commit if certs exist. To exercise the chain-walk
    // derivation in isolation, we pre-populate `self.decided` with a
    // `Skip` for `L_old` — the cache check at the top of the loop
    // short-circuits the direct path, then `L_anchor`'s chain walk
    // discovers `L_old` (still linked, not yet in `newly_committed`)
    // and overrides the cached `Skip` with `Commit(L_old, derived)`.

    /// Build a 2-leader chain: L_old at round 1 + L_anchor at round 3,
    /// each with its own cert quorum at its certifying_round, plus a
    /// causal linkage from L_anchor to L_old via a round-2 block. Used
    /// for both indirect-Opt and indirect-Std tests.
    fn build_indirect_chain_dag() -> (
        Arc<Committee>,
        DagState,
        Arc<crate::metrics::Metrics>,
        BlockReference, // L_old.ref
        BlockReference, // L_anchor.ref
    ) {
        let (committee, dag_state, metrics) = ssfs_setup();
        let genesis: Vec<_> = (0u16..4)
            .map(|auth| {
                *dag_state
                    .get_blocks_at_authority_round(auth, 0)
                    .first()
                    .expect("genesis block")
                    .reference()
            })
            .collect();

        // L_old at round 1 — authority 1 (= elect_leader(1)).
        let l_old = ssfs_block(1, 1, vec![genesis[1]], vec![], None, None);
        let l_old_ref = *l_old.reference();
        dag_state.insert_general_block(l_old, DataSource::BlockBundleStreaming);

        // Round-2 bridge block (auth 0) that references L_old. This
        // creates a causal path so L_anchor (at round 3, with this
        // round-2 block among its parents) reaches L_old via `linked`.
        let bridge = ssfs_block(0, 2, vec![l_old_ref], vec![], None, None);
        let bridge_ref = *bridge.reference();
        dag_state.insert_general_block(bridge, DataSource::BlockBundleStreaming);

        // L_anchor at round 3 — authority 3 (= elect_leader(3)). Refs
        // include the bridge so linkage to L_old is provable.
        let l_anchor = ssfs_block(3, 3, vec![bridge_ref], vec![], None, None);
        let l_anchor_ref = *l_anchor.reference();
        dag_state.insert_general_block(l_anchor, DataSource::BlockBundleStreaming);

        (committee, dag_state, metrics, l_old_ref, l_anchor_ref)
    }

    // ── 9. Indirect Opt: chain walk-back derives Opt for L_old ────────
    #[test]
    fn ssfs_indirect_chain_walk_derives_opt_for_older_leader() {
        let (committee, dag_state, metrics, l_old_ref, l_anchor_ref) = build_indirect_chain_dag();

        // L_old (round 1) gets a strong-cert quorum at its certifying
        // round (cert.round + 2 == 3) — so try_direct_commit returns Opt.
        for auth in [0u16, 1, 2] {
            insert_cert(&dag_state, auth, 3, l_old_ref, true);
        }

        // L_anchor (round 3) gets its own strong-cert quorum at round 5.
        for auth in [0u16, 1, 2] {
            insert_cert(&dag_state, auth, 5, l_anchor_ref, true);
        }

        let mut committer = build_committer(committee, dag_state, metrics);

        // Pre-poison the decided cache: mark L_old as Skip so the
        // direct-iteration short-circuits at round 1; only the chain
        // walk from L_anchor will reach it.
        committer.decided.insert((1, 1), LeaderStatus::Skip(1, 1));

        let committed = committer.try_commit(BlockReference::new_test(0, 0));

        let l_old_status = committed
            .iter()
            .find(|s| s.round() == 1 && s.authority() == 1)
            .expect("L_old must appear in committed sequence via chain walk");
        match l_old_status {
            LeaderStatus::Commit(_, metastate) => {
                assert_eq!(
                    *metastate,
                    Some(CommitMetastate::Opt),
                    "indirect chain walk should derive Opt from L_old's own \
                     strong-cert quorum at its certifying round"
                );
            }
            other => panic!("expected Commit, got {other:?}"),
        }
    }

    // ── 10. Indirect Std: chain walk-back derives Std for L_old ───────
    #[test]
    fn ssfs_indirect_chain_walk_derives_std_for_older_leader() {
        let (committee, dag_state, metrics, l_old_ref, l_anchor_ref) = build_indirect_chain_dag();

        // L_old certs at its certifying round 3: 1 strong + 2 standard
        // (cert quorum exists but no STRONG quorum) AND 3 strong-blame
        // voters at the voting round 2 — recipe for Std.
        insert_cert(&dag_state, 0, 3, l_old_ref, true);
        insert_cert(&dag_state, 1, 3, l_old_ref, false);
        insert_cert(&dag_state, 2, 3, l_old_ref, false);
        // Strong-blame voters at L_old's voting_round = 2.
        // The bridge block at (auth 0, round 2) already references
        // L_old, but it has strong_vote = None. We add three voter
        // blocks at distinct authorities (1, 2, 3) with non-empty
        // masks to satisfy the strong-blame quorum.
        let blame = blame_mask(1);
        insert_voter(&dag_state, 1, 2, l_old_ref, Some(blame));
        insert_voter(&dag_state, 2, 2, l_old_ref, Some(blame));
        insert_voter(&dag_state, 3, 2, l_old_ref, Some(blame));

        // L_anchor strong-cert quorum at round 5 — direct Opt.
        for auth in [0u16, 1, 2] {
            insert_cert(&dag_state, auth, 5, l_anchor_ref, true);
        }

        let mut committer = build_committer(committee, dag_state, metrics);
        committer.decided.insert((1, 1), LeaderStatus::Skip(1, 1));

        let committed = committer.try_commit(BlockReference::new_test(0, 0));

        let l_old_status = committed
            .iter()
            .find(|s| s.round() == 1 && s.authority() == 1)
            .expect("L_old must appear in committed sequence via chain walk");
        match l_old_status {
            LeaderStatus::Commit(_, metastate) => {
                assert_eq!(
                    *metastate,
                    Some(CommitMetastate::Std),
                    "indirect chain walk should derive Std when L_old has \
                     mixed certs + strong-blame quorum at the voting round"
                );
            }
            other => panic!("expected Commit, got {other:?}"),
        }
    }

    // ── 5. Skip when 2f+1 round-(r+1) blocks fail to reference L ──────
    #[test]
    fn ssfs_skip_when_quorum_of_non_voters_at_voting_round() {
        let (committee, dag_state, _metrics) = ssfs_setup();
        let (leader_auth, _leader_ref) = insert_leader(&dag_state, &committee, 3);

        // 3 round-4 blocks whose refs do NOT include leader_ref. We use
        // a dummy ref so they parse as non-voters of L.
        let dummy = BlockReference::new_test(0, 0);
        for auth in [0u16, 1, 2] {
            let b = ssfs_block(auth, 4, vec![dummy], vec![], None, None);
            dag_state.insert_general_block(b, DataSource::BlockBundleStreaming);
        }

        let committer = UniversalCommitterBuilder::new(
            committee.clone(),
            dag_state,
            // metrics not needed for this assertion path
            {
                let registry = Registry::new();
                let (m, _r) = Metrics::new(
                    &registry,
                    Some(committee.as_ref()),
                    Some("sparse-starfish-speed"),
                    None,
                );
                m
            },
        )
        .build();
        assert!(
            committer.check_direct_skip_bluestreak(leader_auth, 3),
            "2f+1 non-voters at voting round must trigger skip"
        );
    }
}
