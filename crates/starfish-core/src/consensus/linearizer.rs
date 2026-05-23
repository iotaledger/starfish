// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};

use super::CommitMetastate;
use crate::{
    committee::{Committee, QuorumThreshold, StakeAggregator},
    dag_state::{ConsensusProtocol, DagState},
    data::Data,
    types::{AuthorityIndex, BlockDigest, BlockReference, RoundNumber, VerifiedBlock},
};

pub const MAX_TRAVERSAL_DEPTH: RoundNumber = 50;

/// The output of consensus is an ordered list of
/// [`CommittedSubDag`]. The application can arbitrarily sort
/// the blocks within each sub-dag (but using a deterministic
/// algorithm).
#[derive(Clone, Serialize, Deserialize)]
pub struct CommittedSubDag {
    /// A reference to the anchor of the sub-dag
    pub anchor: BlockReference,
    /// All the committed blocks that are part of this sub-dag
    pub blocks: Vec<Data<VerifiedBlock>>,
}

impl CommittedSubDag {
    /// Create new (empty) sub-dag.
    pub fn new(anchor: BlockReference, blocks: Vec<Data<VerifiedBlock>>) -> Self {
        Self { anchor, blocks }
    }

    /// Sort the blocks of the sub-dag by round number. Any deterministic
    /// algorithm works.
    pub fn sort(&mut self) {
        self.blocks.sort_by_key(|x| x.round());
    }
}

/// Expand a committed sequence of leader into a sequence of sub-dags.
pub struct Linearizer {
    /// Keep track of all committed blocks to avoid committing the same block
    /// twice.
    pub committed: BTreeSet<BlockReference>,
    /// Keep track of committed slots (round, author) to avoid sequencing the
    /// same transaction data twice — e.g. via both the optimistic and
    /// standard paths.
    pub committed_slots: BTreeSet<(RoundNumber, AuthorityIndex)>,
    pub traversed_blocks: BTreeSet<BlockReference>,
    pub votes: BTreeMap<BlockReference, StakeAggregator<QuorumThreshold>>,
    pub committee: Committee,
}

impl Linearizer {
    pub fn new(committee: Committee) -> Self {
        Self {
            committed: BTreeSet::new(),
            committed_slots: BTreeSet::new(),
            traversed_blocks: BTreeSet::new(),
            votes: BTreeMap::new(),
            committee,
        }
    }

    pub fn cleanup(&mut self, threshold_round: RoundNumber) {
        let split_ref = BlockReference {
            authority: 0,
            round: threshold_round,
            digest: BlockDigest::default(),
        };
        self.committed = self.committed.split_off(&split_ref);
        self.traversed_blocks = self.traversed_blocks.split_off(&split_ref);
        self.votes = self.votes.split_off(&split_ref);
        self.committed_slots = self.committed_slots.split_off(&(threshold_round, 0));
    }

    fn potential_data_holders(&self) -> StakeAggregator<QuorumThreshold> {
        let mut holders = StakeAggregator::<QuorumThreshold>::new();
        for authority in self.committee.authorities() {
            holders.add(authority, &self.committee);
        }
        holders
    }

    /// Effective acknowledgment set carried by `block` for sub-dag derivation.
    ///
    /// For protocols other than SparseStarfishSpeed this is simply
    /// `block.acknowledgments()` (explicit list on the wire), preserving
    /// existing Starfish/StarfishSpeed/StarfishBls semantics.
    ///
    /// For SparseStarfishSpeed the per-block ack set is derived from the
    /// `strong_vote` mask plus a *source* set:
    /// - **Leader blocks**: source = `block.acknowledgments()` (the explicit
    ///   ack list the leader drained from `pending_acknowledgment`).
    /// - **Non-leader blocks** at round `k`: source =
    ///   `L_{k-1}.acknowledgments() ∪ {L_{k-1}.ref}` — what the previous-round
    ///   leader acknowledged, plus the leader block itself (its own
    ///   transactions).
    ///
    /// In both cases we then filter the source by `block.strong_vote()`,
    /// dropping any ref whose author the block flagged as unavailable.
    ///
    /// Returns an empty list when:
    /// - `strong_vote` is `None` (non-SSFS block in mixed test setups).
    /// - Non-leader's `block_references` doesn't contain `L_{k-1}` (e.g.
    ///   own-prev-only fallback under chain-bomb scenarios).
    /// - `L_{k-1}` is missing from storage.
    fn effective_acknowledgments(
        &self,
        dag_state: &DagState,
        block: &VerifiedBlock,
    ) -> Vec<BlockReference> {
        let explicit = block.acknowledgments();
        if dag_state.consensus_protocol != ConsensusProtocol::SparseStarfishSpeed {
            return explicit;
        }
        let Some(mask) = block.strong_vote() else {
            return explicit;
        };
        let round = block.round();
        if round == 0 {
            return explicit;
        }
        let is_leader = self.committee.elect_leader(round) == block.authority();
        let source: Vec<BlockReference> = if is_leader {
            explicit
        } else {
            let prev_round = round - 1;
            let prev_leader_auth = self.committee.elect_leader(prev_round);
            let Some(prev_leader_ref) = block
                .block_references()
                .iter()
                .find(|r| r.round == prev_round && r.authority == prev_leader_auth)
                .copied()
            else {
                return Vec::new();
            };
            let Some(prev_leader) = dag_state.get_storage_block(prev_leader_ref) else {
                return Vec::new();
            };
            let mut v = prev_leader.acknowledgments();
            v.push(prev_leader_ref);
            v
        };
        source
            .into_iter()
            .filter(|r| !mask.contains(r.authority))
            .collect()
    }

    /// Collect the sub-dag from a specific anchor excluding any duplicates or
    /// blocks that have already been committed (within previous sub-dags).
    /// Uses BFS with per-level batch fetching to minimize lock acquisitions.
    fn collect_subdag_ancestors(
        &mut self,
        dag_state: &DagState,
        leader_block: Data<VerifiedBlock>,
    ) -> CommittedSubDag {
        let mut to_commit = Vec::new();
        let leader_block_ref = *leader_block.reference();
        let min_round = leader_block_ref.round.saturating_sub(MAX_TRAVERSAL_DEPTH);
        let follow_unprovable = dag_state.consensus_protocol.is_bluestreak();

        assert!(self.committed.insert(leader_block_ref));
        let mut current_level = vec![leader_block];

        while !current_level.is_empty() {
            let mut next_refs = Vec::new();
            for x in &current_level {
                to_commit.push(x.clone());
                let s = self.votes.entry(*x.reference()).or_default();
                s.add(leader_block_ref.authority, &self.committee);
                for reference in x.block_references() {
                    if reference.round >= min_round && self.committed.insert(*reference) {
                        next_refs.push(*reference);
                    }
                }
                if follow_unprovable {
                    if let Some((cert_ref, _strong)) = x.unprovable_certificate() {
                        if cert_ref.round >= min_round && self.committed.insert(cert_ref) {
                            next_refs.push(cert_ref);
                        }
                    }
                }
            }
            if next_refs.is_empty() {
                break;
            }
            current_level = dag_state
                .get_storage_blocks(&next_refs)
                .into_iter()
                .map(|b| b.expect("We should have the whole sub-dag by now"))
                .collect();
        }

        CommittedSubDag::new(leader_block_ref, to_commit)
    }

    /// Collect all blocks in the history of committed leader that have
    /// acknowledgment support. Uses BFS with per-level batch fetching.
    ///
    /// When `direct_ack` is false (Starfish/StarfishSpeed): accumulate
    /// votes per ack_ref, commit when quorum is reached.
    /// When `direct_ack` is true (StarfishBls): only self-acks count — the DAC
    /// certificate provides the availability guarantee directly.
    fn collect_subdag_acknowledgments(
        &mut self,
        dag_state: &DagState,
        leader_block: Data<VerifiedBlock>,
        direct_ack: bool,
    ) -> CommittedSubDag {
        tracing::debug!("Starting collection with leader {:?}", leader_block);
        let leader_block_ref = *leader_block.reference();
        let min_round = leader_block_ref.round.saturating_sub(MAX_TRAVERSAL_DEPTH);

        let mut committed_ack_refs = BTreeSet::new();
        let mut current_level = vec![leader_block];

        // Phase 1: BFS traversal — process acknowledgments and collect
        // block_references per level, batch-fetching each level.
        while !current_level.is_empty() {
            let mut next_refs = Vec::new();
            for x in &current_level {
                let who_votes = x.authority();
                for ack_ref in self.effective_acknowledgments(dag_state, x) {
                    if ack_ref.round < min_round {
                        continue;
                    }
                    if direct_ack {
                        if ack_ref.authority != x.authority() {
                            continue;
                        }
                        committed_ack_refs.insert(ack_ref);
                    } else {
                        let s = self.votes.entry(ack_ref).or_default();
                        if !s.is_quorum(&self.committee) && s.add(who_votes, &self.committee) {
                            committed_ack_refs.insert(ack_ref);
                        }
                    }
                }
                self.traversed_blocks.insert(*x.reference());
                for reference in x.block_references() {
                    if reference.round >= min_round && self.traversed_blocks.insert(*reference) {
                        next_refs.push(*reference);
                    }
                }
            }
            if next_refs.is_empty() {
                break;
            }
            current_level = dag_state
                .get_storage_blocks(&next_refs)
                .into_iter()
                .map(|b| b.expect("We should have the whole sub-dag by now"))
                .collect();
        }

        // Phase 2: batch-fetch the newly committed ack refs.
        let new_ack_refs: Vec<_> = committed_ack_refs
            .into_iter()
            .filter(|r| self.committed.insert(*r))
            .collect();

        let mut to_commit: Vec<_> = dag_state
            .get_storage_blocks(&new_ack_refs)
            .into_iter()
            .map(|b| b.expect("We should have the whole sub-dag by now"))
            .map(|block| {
                let round = block.round();
                let author = block.authority();
                let digest = block.digest();
                (round, author, digest, block)
            })
            .collect();

        // Sort by (round, author, digest) for deterministic slot selection.
        to_commit.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));

        // Select at most one block per (round, author), persisting across subdags.
        let to_commit: Vec<_> = to_commit
            .into_iter()
            .filter_map(|(round, author, _, block)| {
                if self.committed_slots.insert((round, author)) {
                    Some(block)
                } else {
                    None
                }
            })
            .collect();

        CommittedSubDag::new(leader_block_ref, to_commit)
    }

    fn collect_strong_vote_holders(
        &self,
        dag_state: &DagState,
        round: RoundNumber,
    ) -> StakeAggregator<QuorumThreshold> {
        let mut holders = StakeAggregator::<QuorumThreshold>::new();
        for block in dag_state.get_blocks_by_round(round) {
            if block.is_strong_vote() {
                holders.add(block.authority(), &self.committee);
            }
        }
        holders
    }

    fn add_optimistic_acknowledgments(
        &mut self,
        dag_state: &DagState,
        sub_dag: &mut CommittedSubDag,
        ack_refs: Vec<BlockReference>,
        data_holders: &StakeAggregator<QuorumThreshold>,
    ) {
        let data_holder_votes: Vec<_> = data_holders.voters().collect();
        let mut refs_to_fetch = Vec::new();
        for ack_ref in ack_refs {
            let votes = self.votes.entry(ack_ref).or_default();
            for authority in &data_holder_votes {
                votes.add(*authority, &self.committee);
            }
            if self.committed.insert(ack_ref) {
                refs_to_fetch.push(ack_ref);
            }
        }

        let mut blocks_to_add: Vec<_> = dag_state
            .get_storage_blocks(&refs_to_fetch)
            .into_iter()
            .flatten()
            .map(|block| {
                let round = block.round();
                let author = block.authority();
                let digest = block.digest();
                (round, author, digest, block)
            })
            .collect();

        blocks_to_add.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));

        for (round, author, _, block) in blocks_to_add {
            if self.committed_slots.insert((round, author)) {
                sub_dag.blocks.push(block);
            }
        }
    }

    pub fn handle_commit(
        &mut self,
        dag_state: &DagState,
        committed_leaders: Vec<(Data<VerifiedBlock>, Option<CommitMetastate>)>,
    ) -> Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)> {
        let consensus_protocol = dag_state.consensus_protocol;
        let mut committed = vec![];
        for (leader_block, metastate) in committed_leaders {
            // Collect the sub-dag generated using each of these leaders as anchor.
            let leader_ref = *leader_block.reference();
            let leader_acks = leader_block.acknowledgments();
            let optimistic_data_holders = (metastate == Some(CommitMetastate::Opt))
                .then(|| self.collect_strong_vote_holders(dag_state, leader_block.round() + 1));
            let mut sub_dag = match consensus_protocol {
                ConsensusProtocol::StarfishBls => {
                    self.collect_subdag_acknowledgments(dag_state, leader_block, true)
                }
                ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::SparseStarfishSpeed => {
                    self.collect_subdag_acknowledgments(dag_state, leader_block, false)
                }
                ConsensusProtocol::Mysticeti
                | ConsensusProtocol::CordialMiners
                | ConsensusProtocol::SailfishPlusPlus
                | ConsensusProtocol::Bluestreak
                | ConsensusProtocol::MysticetiBls => {
                    self.collect_subdag_ancestors(dag_state, leader_block)
                }
            };

            // Optimistic Starfish-family commits can immediately sequence
            // data covered by the strong-vote quorum. StarfishSpeed directly
            // sequences the leader's explicit acks; SparseStarfishSpeed also
            // sequences the committed leader itself so the leader's own
            // transactions have gap 0.
            if let Some(data_holders) = optimistic_data_holders.as_ref() {
                match consensus_protocol {
                    ConsensusProtocol::StarfishSpeed => {
                        self.add_optimistic_acknowledgments(
                            dag_state,
                            &mut sub_dag,
                            leader_acks,
                            data_holders,
                        );
                    }
                    ConsensusProtocol::SparseStarfishSpeed => {
                        let mut optimistic_refs = Vec::with_capacity(1 + leader_acks.len());
                        optimistic_refs.push(leader_ref);
                        optimistic_refs.extend(leader_acks);
                        self.add_optimistic_acknowledgments(
                            dag_state,
                            &mut sub_dag,
                            optimistic_refs,
                            data_holders,
                        );
                    }
                    _ => {}
                }
            }
            // [Optional] sort the sub-dag using a deterministic algorithm.
            sub_dag.sort();
            let acknowledgement_authorities: Vec<_> = sub_dag
                .blocks
                .iter()
                .map(|x| {
                    if consensus_protocol.uses_bls() {
                        self.potential_data_holders()
                    } else {
                        self.votes.get(x.reference()).cloned().unwrap_or_default()
                    }
                })
                .collect();
            tracing::debug!("Committed sub DAG {:?}", sub_dag);
            committed.push((sub_dag, acknowledgement_authorities));
        }
        committed
    }
}

impl fmt::Debug for CommittedSubDag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.anchor)?;
        for block in &self.blocks {
            write!(f, "{}, ", block.reference())?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{DisseminationMode, StorageBackend},
        crypto::SignatureBytes,
        dag_state::DataSource,
        metrics::Metrics,
        types::AuthoritySet,
    };
    use prometheus::Registry;
    use tempfile::TempDir;

    fn open_test_dag_state_for(consensus: &str) -> (Committee, DagState) {
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) =
            Metrics::new(&registry, Some(committee.as_ref()), Some(consensus), None);
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        std::mem::forget(dir);
        let dag_state = DagState::open(
            0,
            path,
            metrics,
            committee.clone(),
            "honest".to_string(),
            consensus.to_string(),
            &StorageBackend::Rocksdb,
            false,
            DisseminationMode::ProtocolDefault,
        )
        .dag_state;
        ((*committee).clone(), dag_state)
    }

    fn make_block(
        authority: AuthorityIndex,
        round: RoundNumber,
        parents: Vec<BlockReference>,
        acks: Vec<BlockReference>,
        strong_vote: Option<AuthoritySet>,
    ) -> Data<VerifiedBlock> {
        let mut block = VerifiedBlock::new(
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
        );
        block.preserialize();
        Data::new(block)
    }

    #[test]
    fn ssfs_opt_sequences_leader_and_leader_acknowledgments() {
        let (committee, dag_state) = open_test_dag_state_for("sparse-starfish-speed");
        let acknowledged = make_block(0, 1, vec![], vec![], None);
        let acknowledged_ref = *acknowledged.reference();
        dag_state.insert_general_block(acknowledged, DataSource::BlockBundleStreaming);

        let leader_round = 3;
        let leader_authority = committee.elect_leader(leader_round);
        let leader = make_block(
            leader_authority,
            leader_round,
            vec![],
            vec![acknowledged_ref],
            None,
        );
        let leader_ref = *leader.reference();
        dag_state.insert_general_block(leader.clone(), DataSource::BlockBundleStreaming);

        for authority in [0u16, 1, 2] {
            let voter = make_block(
                authority,
                leader_round + 1,
                vec![leader_ref],
                vec![],
                Some(AuthoritySet::default()),
            );
            dag_state.insert_general_block(voter, DataSource::BlockBundleStreaming);
        }

        let mut linearizer = Linearizer::new(committee);
        let committed =
            linearizer.handle_commit(&dag_state, vec![(leader, Some(CommitMetastate::Opt))]);

        let blocks: BTreeSet<_> = committed[0]
            .0
            .blocks
            .iter()
            .map(|block| *block.reference())
            .collect();
        assert!(blocks.contains(&leader_ref), "Opt must sequence leader");
        assert!(
            blocks.contains(&acknowledged_ref),
            "Opt must sequence leader acknowledgments"
        );
    }

    #[test]
    fn ssfs_std_does_not_directly_sequence_leader_acknowledgments() {
        let (committee, dag_state) = open_test_dag_state_for("sparse-starfish-speed");
        let acknowledged = make_block(0, 1, vec![], vec![], None);
        let acknowledged_ref = *acknowledged.reference();
        dag_state.insert_general_block(acknowledged, DataSource::BlockBundleStreaming);

        let leader_round = 3;
        let leader_authority = committee.elect_leader(leader_round);
        let leader = make_block(
            leader_authority,
            leader_round,
            vec![],
            vec![acknowledged_ref],
            None,
        );
        let leader_ref = *leader.reference();
        dag_state.insert_general_block(leader.clone(), DataSource::BlockBundleStreaming);

        let mut linearizer = Linearizer::new(committee);
        let committed =
            linearizer.handle_commit(&dag_state, vec![(leader, Some(CommitMetastate::Std))]);

        let blocks: BTreeSet<_> = committed[0]
            .0
            .blocks
            .iter()
            .map(|block| *block.reference())
            .collect();
        assert!(
            !blocks.contains(&leader_ref),
            "Std uses only the quorum-acknowledgment mechanism"
        );
        assert!(
            !blocks.contains(&acknowledged_ref),
            "Std must not directly sequence leader acknowledgments"
        );
    }
}
