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
    use prometheus::Registry;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        config::{DisseminationMode, StorageBackend},
        crypto::SignatureBytes,
        dag_state::DataSource,
        data::Data,
    };

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
    //   Opt     iff 2f+1 round-(r+2) clean blocks carry Some((L.ref, true))
    //   Std     iff 2f+1 certs at r+2, no strong-cert quorum, AND 2f+1
    //               round-(r+1) voters of L are `is_strong_blame()`
    //   Pending iff 2f+1 certs at r+2 without strong-cert or strong-blame quorum
    //   Skip    iff 2f+1 round-(r+1) blocks fail to reference L
    //   None    iff no direct/indirect rule can finalize the slot yet
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
        insert_leader_with_parents(dag_state, committee, leader_round, vec![])
    }

    fn insert_leader_with_parents(
        dag_state: &DagState,
        committee: &Committee,
        leader_round: RoundNumber,
        parents: Vec<BlockReference>,
    ) -> (AuthorityIndex, BlockReference) {
        let leader_authority = committee.elect_leader(leader_round);
        let leader = ssfs_block(leader_authority, leader_round, parents, vec![], None, None);
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
    ) -> BlockReference {
        let cert = ssfs_block(
            authority,
            cert_round,
            vec![],
            vec![],
            None,
            Some((leader_ref, strong)),
        );
        let cert_ref = *cert.reference();
        dag_state.insert_general_block(cert, DataSource::BlockBundleStreaming);
        cert_ref
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
        let (leader_auth, leader_ref) = insert_leader(&dag_state, &committee, 1);

        for auth in [0u16, 1, 2] {
            insert_voter(
                &dag_state,
                auth,
                2,
                leader_ref,
                Some(crate::types::AuthoritySet::default()),
            );
        }

        for auth in [0u16, 1, 2] {
            insert_cert(&dag_state, auth, 3, leader_ref, true);
        }

        let mut committer = build_committer(committee, dag_state, metrics);
        let committed = committer.try_commit(BlockReference::new_test(0, 0));

        let status = committed
            .iter()
            .find(|status| status.authority() == leader_auth && status.round() == 1)
            .expect("leader must commit with a strong-cert quorum");
        match status {
            LeaderStatus::Commit(block, metastate) => {
                assert_eq!(*block.reference(), leader_ref);
                assert_eq!(*metastate, Some(CommitMetastate::Opt));
            }
            other => panic!("expected Commit(Opt), got {other:?}"),
        }
    }

    // ── 2. Std (standard certs + strong-blame quorum) ────────────────
    #[test]
    fn ssfs_direct_commit_std_with_standard_certs_and_strong_blame_quorum() {
        let (committee, dag_state, metrics) = ssfs_setup();
        let (leader_auth, leader_ref) = insert_leader(&dag_state, &committee, 1);

        let mask = blame_mask(leader_auth);
        for auth in [0u16, 1, 2] {
            insert_voter(&dag_state, auth, 2, leader_ref, Some(mask));
        }

        for auth in [0u16, 1, 2] {
            insert_cert(&dag_state, auth, 3, leader_ref, false);
        }

        let mut committer = build_committer(committee, dag_state, metrics);
        let committed = committer.try_commit(BlockReference::new_test(0, 0));

        let status = committed
            .iter()
            .find(|status| status.authority() == leader_auth && status.round() == 1)
            .expect("leader must commit with standard certs and strong blame");
        match status {
            LeaderStatus::Commit(_, metastate) => {
                assert_eq!(*metastate, Some(CommitMetastate::Std));
            }
            other => panic!("expected Commit(Std), got {other:?}"),
        }
    }

    // ── 3. Std (standard certs without strong-blame quorum) ──────────
    #[test]
    fn ssfs_direct_commit_std_without_strong_blame_quorum() {
        let (committee, dag_state, metrics) = ssfs_setup();
        let (leader_auth, leader_ref) = insert_leader(&dag_state, &committee, 1);

        let mask = blame_mask(leader_auth);
        insert_voter(&dag_state, 0, 2, leader_ref, Some(mask));
        insert_voter(
            &dag_state,
            1,
            2,
            leader_ref,
            Some(crate::types::AuthoritySet::default()),
        );
        insert_voter(
            &dag_state,
            2,
            2,
            leader_ref,
            Some(crate::types::AuthoritySet::default()),
        );

        for auth in [0u16, 1, 2] {
            insert_cert(&dag_state, auth, 3, leader_ref, false);
        }

        let mut committer = build_committer(committee, dag_state, metrics);
        let committed = committer.try_commit(BlockReference::new_test(0, 0));
        let status = committed
            .iter()
            .find(|status| status.authority() == leader_auth && status.round() == 1)
            .expect("leader must commit standard once a standard-cert quorum exists");
        match status {
            LeaderStatus::Commit(_, metastate) => {
                assert_eq!(*metastate, Some(CommitMetastate::Std));
            }
            other => panic!("expected Commit(Std), got {other:?}"),
        }
    }

    #[test]
    fn ssfs_indirect_commit_opt_keeps_metastate() {
        let (committee, dag_state, metrics) = ssfs_setup();
        let (old_auth, old_ref) = insert_leader(&dag_state, &committee, 1);

        for auth in [0u16, 1, 2] {
            insert_voter(
                &dag_state,
                auth,
                2,
                old_ref,
                Some(crate::types::AuthoritySet::default()),
            );
        }

        let cert_refs = vec![insert_cert(&dag_state, 0, 3, old_ref, true)];

        let (_anchor_auth, anchor_ref) =
            insert_leader_with_parents(&dag_state, &committee, 4, cert_refs);
        for auth in [0u16, 1, 2] {
            insert_voter(
                &dag_state,
                auth,
                5,
                anchor_ref,
                Some(crate::types::AuthoritySet::default()),
            );
            insert_cert(&dag_state, auth, 6, anchor_ref, true);
        }

        let mut committer = build_committer(committee, dag_state, metrics);
        let committed = committer.try_commit(BlockReference::new_test(0, 0));

        let old_status = committed
            .iter()
            .find(|status| status.authority() == old_auth && status.round() == 1)
            .expect("old leader should commit indirectly through anchor");
        assert!(
            committed
                .iter()
                .all(|status| !matches!(status, LeaderStatus::Commit(_, None))),
            "SSFS commits must always carry Opt/Std metastate"
        );
        match old_status {
            LeaderStatus::Commit(_, metastate) => {
                assert_eq!(*metastate, Some(CommitMetastate::Opt));
            }
            other => panic!("expected indirect Commit(Opt), got {other:?}"),
        }
    }

    #[test]
    fn ssfs_indirect_commit_std_keeps_metastate() {
        let (committee, dag_state, metrics) = ssfs_setup();
        let (old_auth, old_ref) = insert_leader(&dag_state, &committee, 1);

        for auth in [0u16, 1, 2] {
            insert_voter(
                &dag_state,
                auth,
                2,
                old_ref,
                Some(crate::types::AuthoritySet::default()),
            );
        }

        let cert_refs = vec![insert_cert(&dag_state, 0, 3, old_ref, false)];

        let (_anchor_auth, anchor_ref) =
            insert_leader_with_parents(&dag_state, &committee, 4, cert_refs);
        for auth in [0u16, 1, 2] {
            insert_voter(
                &dag_state,
                auth,
                5,
                anchor_ref,
                Some(crate::types::AuthoritySet::default()),
            );
            insert_cert(&dag_state, auth, 6, anchor_ref, true);
        }

        let mut committer = build_committer(committee, dag_state, metrics);
        let committed = committer.try_commit(BlockReference::new_test(0, 0));

        let old_status = committed
            .iter()
            .find(|status| status.authority() == old_auth && status.round() == 1)
            .expect("old leader should commit indirectly through anchor");
        assert!(
            committed
                .iter()
                .all(|status| !matches!(status, LeaderStatus::Commit(_, None))),
            "SSFS commits must always carry Opt/Std metastate"
        );
        match old_status {
            LeaderStatus::Commit(_, metastate) => {
                assert_eq!(*metastate, Some(CommitMetastate::Std));
            }
            other => panic!("expected indirect Commit(Std), got {other:?}"),
        }
    }

    // ── 4. No direct commit when cert quorum is missing ───────────────
    #[test]
    fn ssfs_direct_commit_none_below_cert_quorum() {
        let (committee, dag_state, metrics) = ssfs_setup();
        let (leader_auth, leader_ref) = insert_leader(&dag_state, &committee, 1);

        for auth in [0u16, 1, 2] {
            insert_voter(
                &dag_state,
                auth,
                2,
                leader_ref,
                Some(crate::types::AuthoritySet::default()),
            );
        }
        insert_cert(&dag_state, 0, 3, leader_ref, true);
        insert_cert(&dag_state, 1, 3, leader_ref, true);

        let mut committer = build_committer(committee, dag_state, metrics);
        let committed = committer.try_commit(BlockReference::new_test(0, 0));
        assert!(
            committed
                .iter()
                .all(|status| status.authority() != leader_auth || status.round() != 1),
            "< 2f+1 certs of any flavor must NOT trigger direct commit"
        );
    }

    // ── 5. Skip when 2f+1 round-(r+1) blocks fail to reference L ──────
    #[test]
    fn ssfs_skip_when_quorum_of_non_voters_at_voting_round() {
        let (committee, dag_state, metrics) = ssfs_setup();
        let (leader_auth, _leader_ref) = insert_leader(&dag_state, &committee, 1);

        // 3 round-2 blocks whose refs do NOT include leader_ref. We use
        // a dummy ref so they parse as non-voters of L.
        let dummy = BlockReference::new_test(0, 0);
        for auth in [0u16, 1, 2] {
            let b = ssfs_block(auth, 2, vec![dummy], vec![], None, None);
            dag_state.insert_general_block(b, DataSource::BlockBundleStreaming);
        }

        let mut committer = build_committer(committee, dag_state, metrics);
        let committed = committer.try_commit(BlockReference::new_test(0, 0));
        assert!(
            committed.iter().any(|status| matches!(
                status,
                LeaderStatus::Skip(authority, 1) if *authority == leader_auth
            )),
            "2f+1 non-voters at voting round must trigger skip"
        );
    }
}
