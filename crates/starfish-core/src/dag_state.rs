// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    cmp::max,
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
    sync::Arc,
    time::Instant,
};

use ahash::{AHashMap, AHashSet};
use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{
    committee::{Committee, QuorumThreshold, StakeAggregator},
    consensus::linearizer::{CommittedSubDag, MAX_TRAVERSAL_DEPTH},
    data::Data,
    metrics::{Metrics, UtilizationTimerExt},
    rocks_store::RocksStore,
    state::{RecoveredState, RecoveredStateBuilder},
    types::{AuthorityIndex, BlockDigest, BlockReference, RoundNumber, VerifiedStatementBlock},
};

/// Bitmask tracking which authorities know about a block. Supports up to 128
/// authorities.
type AuthorityBitmask = u128;

#[derive(Clone, Debug, Copy, PartialEq)]
pub enum ConsensusProtocol {
    Mysticeti,
    StarfishPull,
    CordialMiners,
    Starfish,
    StarfishS,
}

impl ConsensusProtocol {
    pub fn from_str(s: &str) -> Self {
        match s {
            "mysticeti" => ConsensusProtocol::Mysticeti,
            "starfish-pull" => ConsensusProtocol::StarfishPull,
            "cordial-miners" => ConsensusProtocol::CordialMiners,
            "starfish" => ConsensusProtocol::Starfish,
            "starfish-s" => ConsensusProtocol::StarfishS,
            _ => ConsensusProtocol::StarfishPull, // Default to Starfish
        }
    }
}

#[allow(unused)]
#[derive(Clone, Debug, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ByzantineStrategy {
    TimeoutLeader,          // Adversary waits timeout before sending their leader blocks
    EquivocatingChains,     // Equivocation attack: N-1 equivocations per round
    EquivocatingTwoChains,  // Skipping rule equivocation: 2 equivocations split across validators
    RandomDrop,             // Drop messages randomly
    LeaderWithholding,      // Withholding leader blocks (sent to f+1+c validators)
    ChainBomb,              // Fork bomb: withhold a chain of blocks and release it all at once
    EquivocatingChainsBomb, // Equivocation fork bomb: send different chains to each validator
}
#[derive(Clone)]
pub struct DagState {
    inner: Arc<RwLock<DagStateInner>>,
    rocks_store: Arc<RocksStore>,
    metrics: Arc<Metrics>,
    pub(crate) consensus_protocol: ConsensusProtocol,
    pub(crate) committee_size: usize,
    pub(crate) byzantine_strategy: Option<ByzantineStrategy>,
    /// Version-gated cache of round block snapshots (outside the RwLock).
    round_block_cache: Arc<parking_lot::Mutex<RoundBlockCache>>,
}

type RoundBlockCache = AHashMap<RoundNumber, (u64, Arc<[Data<VerifiedStatementBlock>]>)>;

struct DagStateInner {
    rocks_store: Arc<RocksStore>,
    index: BTreeMap<RoundNumber, HashMap<(AuthorityIndex, BlockDigest), IndexEntry>>,
    // Store the blocks for which we have transaction data
    data_availability: BTreeSet<BlockReference>,
    // Blocks for which has available transactions data and didn't yet acknowledge.
    pending_acknowledgment: Vec<BlockReference>,
    // Byzantine nodes will create different blocks intended for the different validators
    own_blocks: BTreeMap<(RoundNumber, AuthorityIndex), BlockDigest>,
    highest_round: RoundNumber,
    authority: AuthorityIndex,
    committee_size: usize,
    last_seen_by_authority: Vec<RoundNumber>,
    last_own_block: Option<BlockReference>,
    // this dag structure store for each block its predecessors and who knows the block
    dag: BTreeMap<RoundNumber, DagRoundEntries>,
    // Round of the latest committed leader whose sub-dag was fully sequenced
    // (all data available). Used as the single eviction threshold source.
    last_available_commit: RoundNumber,
    // per-round version counter, incremented on each add_block to that round
    round_version: AHashMap<RoundNumber, u64>,
    // committed subdag which contains blocks with at least one unavailable transaction data
    pending_not_available: Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)>,
}

type IndexEntry = (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>);
type DagRoundEntries =
    HashMap<(AuthorityIndex, BlockDigest), (Vec<BlockReference>, AuthorityBitmask)>;

impl DagState {
    pub fn open(
        authority: AuthorityIndex,
        path: impl AsRef<Path>,
        metrics: Arc<Metrics>,
        committee: &Committee,
        byzantine_strategy: String,
        consensus: String,
    ) -> RecoveredState {
        assert!(
            committee.len() <= 128,
            "Committee size {} exceeds AuthorityBitmask capacity (128)",
            committee.len()
        );
        let rocks_store = Arc::new(RocksStore::open(path).expect("Failed to open RocksDB"));
        let last_seen_by_authority = committee.authorities().map(|_| 0).collect();
        let mut inner = DagStateInner {
            rocks_store: rocks_store.clone(),
            authority,
            last_seen_by_authority,
            last_available_commit: 0,
            committee_size: committee.len(),
            index: BTreeMap::new(),
            data_availability: BTreeSet::new(),
            pending_acknowledgment: Vec::new(),
            own_blocks: BTreeMap::new(),
            highest_round: 0,
            last_own_block: None,
            dag: BTreeMap::new(),
            pending_not_available: Vec::new(),
            round_version: AHashMap::new(),
        };
        let mut builder = RecoveredStateBuilder::new();
        let replay_started = Instant::now();
        let mut block_count = 0u64;
        let mut recovered_commit_leaders = AHashSet::new();
        // Recover blocks from RocksDB
        let mut current_round = 0;
        loop {
            let blocks = rocks_store
                .get_blocks_by_round(current_round)
                .expect("Failed to read blocks from RocksDB");

            if blocks.is_empty() {
                break;
            }

            for block in blocks {
                let block_ref = *block.reference();
                let transmission_block = block.from_storage_to_transmission(authority);
                let data_transmission_block = Data::new(transmission_block);
                let data_storage_transmission_blocks = (block.clone(), data_transmission_block);

                builder.block(current_round, data_storage_transmission_blocks.clone());
                block_count += 1;
                inner.add_block(
                    data_storage_transmission_blocks,
                    0,
                    committee.len() as AuthorityIndex,
                );
                if recovered_commit_leaders.insert(block_ref) {
                    if let Some(commit_data) = rocks_store
                        .get_commit(&block_ref)
                        .expect("Failed to read commit data from RocksDB")
                    {
                        builder.commit(commit_data);
                    }
                }
            }

            current_round += 1;
        }

        metrics.dag_state_entries.inc_by(block_count);
        tracing::debug!(
            "authority={} RocksDB replay: {} blocks in {:?}, highest_round={}",
            authority,
            block_count,
            replay_started.elapsed(),
            inner.highest_round
        );
        let byzantine_strategy = match byzantine_strategy.as_str() {
            "timeout-leader" => Some(ByzantineStrategy::TimeoutLeader),
            "leader-withholding" => Some(ByzantineStrategy::LeaderWithholding),
            "equivocating-chains" => Some(ByzantineStrategy::EquivocatingChains),
            "equivocating-two-chains" => Some(ByzantineStrategy::EquivocatingTwoChains),
            "chain-bomb" => Some(ByzantineStrategy::ChainBomb),
            "equivocating-chains-bomb" => Some(ByzantineStrategy::EquivocatingChainsBomb),
            "random-drop" => Some(ByzantineStrategy::RandomDrop),
            _ => None, // Default to honest behavior
        };
        let consensus_protocol = ConsensusProtocol::from_str(&consensus);

        match &consensus_protocol {
            ConsensusProtocol::Mysticeti => tracing::info!("Starting Mysticeti protocol"),
            ConsensusProtocol::StarfishPull => {
                tracing::info!("Starting Starfish-Pull protocol")
            }
            ConsensusProtocol::Starfish => tracing::info!("Starting Starfish protocol"),
            ConsensusProtocol::StarfishS => tracing::info!("Starting Starfish-S protocol"),
            ConsensusProtocol::CordialMiners => tracing::info!("Starting Cordial Miners protocol"),
        }
        let dag_state = Self {
            rocks_store: rocks_store.clone(),
            byzantine_strategy,
            inner: Arc::new(RwLock::new(inner)),
            metrics,
            consensus_protocol,
            committee_size: committee.len(),
            round_block_cache: Arc::new(parking_lot::Mutex::new(AHashMap::new())),
        };
        builder.build(rocks_store, dag_state)
    }

    pub fn get_dag_sorted(&self) -> Vec<(BlockReference, Vec<BlockReference>, AuthorityBitmask)> {
        let inner = self.inner.read();
        // BTreeMap is already sorted by round
        inner
            .dag
            .iter()
            .flat_map(|(round, map)| {
                map.iter()
                    .map(move |((authority, digest), (parents, known_by))| {
                        (
                            BlockReference {
                                authority: *authority,
                                round: *round,
                                digest: *digest,
                            },
                            parents.clone(),
                            *known_by,
                        )
                    })
            })
            .collect()
    }

    pub fn get_own_authority_index(&self) -> AuthorityIndex {
        self.inner.read().authority
    }

    pub fn read_pending_unavailable(
        &self,
    ) -> Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)> {
        self.inner.read().read_pending_unavailable()
    }

    pub fn update_pending_unavailable(
        &self,
        pending: Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)>,
    ) {
        self.inner.write().update_pending_unavailable(pending);
    }

    pub fn insert_block_bounds(
        &self,
        storage_and_transmission_blocks: (
            Data<VerifiedStatementBlock>,
            Data<VerifiedStatementBlock>,
        ),
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        self.metrics.dag_state_entries.inc();

        // Store in RocksDB
        self.rocks_store
            .store_block(storage_and_transmission_blocks.0.clone())
            .expect("Failed to store block in RocksDB");

        self.inner.write().add_block(
            storage_and_transmission_blocks,
            authority_index_start,
            authority_index_end,
        );
    }

    pub fn insert_general_block(
        &self,
        storage_and_transmission_blocks: (
            Data<VerifiedStatementBlock>,
            Data<VerifiedStatementBlock>,
        ),
    ) {
        let authority_index_start = 0;
        let authority_index_end = self.committee_size as AuthorityIndex;
        self.insert_block_bounds(
            storage_and_transmission_blocks,
            authority_index_start,
            authority_index_end,
        );
    }

    // Insert own blocks is primarily needed to capture Byzantine behavior with
    // equivocating blocks
    pub fn insert_own_block(&self, own_block: OwnBlockData) {
        self.insert_block_bounds(
            own_block.storage_transmission_blocks,
            own_block.authority_index_start,
            own_block.authority_index_end,
        );
    }

    pub fn get_storage_block(
        &self,
        reference: BlockReference,
    ) -> Option<Data<VerifiedStatementBlock>> {
        if let Some((storage, _)) = self.inner.read().get_block(reference) {
            return Some(storage);
        }
        self.rocks_store
            .get_block(&reference)
            .expect("RocksDB read failed")
    }

    pub fn get_transmission_block(
        &self,
        reference: BlockReference,
    ) -> Option<Data<VerifiedStatementBlock>> {
        if let Some((_, transmission)) = self.inner.read().get_block(reference) {
            return Some(transmission);
        }
        let own_id = self.inner.read().authority;
        self.rocks_store
            .get_block(&reference)
            .expect("RocksDB read failed")
            .map(|storage| Data::new(storage.from_storage_to_transmission(own_id)))
    }

    pub fn get_pending_acknowledgment(&self, round_number: RoundNumber) -> Vec<BlockReference> {
        self.inner.write().get_pending_acknowledgment(round_number)
    }

    pub fn get_blocks_by_round(&self, round: RoundNumber) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self.inner.read().get_blocks_by_round(round);
        Self::extract_storage_blocks(entries)
    }

    /// Version-gated cached variant of `get_blocks_by_round`.
    /// Returns `Arc<[T]>` to avoid repeated Vec allocations for the same round.
    pub fn get_blocks_by_round_cached(
        &self,
        round: RoundNumber,
    ) -> Arc<[Data<VerifiedStatementBlock>]> {
        let inner = self.inner.read();
        let version = inner.round_version.get(&round).copied().unwrap_or(0);
        {
            let cache = self.round_block_cache.lock();
            if let Some((ver, blocks)) = cache.get(&round) {
                if *ver == version {
                    return blocks.clone();
                }
            }
        }
        let blocks: Arc<[_]> =
            Self::extract_storage_blocks(inner.get_blocks_by_round(round)).into();
        self.round_block_cache
            .lock()
            .insert(round, (version, blocks.clone()));
        blocks
    }

    pub fn get_blocks_at_authority_round(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self
            .inner
            .read()
            .get_blocks_at_authority_round(authority, round);
        Self::extract_storage_blocks(entries)
    }

    pub fn block_exists_at_authority_round(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> bool {
        !self
            .inner
            .read()
            .get_blocks_at_authority_round(authority, round)
            .is_empty()
    }

    pub fn all_blocks_exists_at_authority_round(
        &self,
        authorities: &[AuthorityIndex],
        round: RoundNumber,
    ) -> bool {
        let inner = self.inner.read();
        let blocks = inner.get_blocks_by_round(round);
        if blocks.is_empty() {
            return false;
        }
        authorities
            .iter()
            .all(|auth| blocks.iter().any(|(sb, _)| sb.author() == *auth))
    }

    /// Check if a quorum of blocks at `round` include the leader
    /// from `leader_round` in their references.
    pub fn has_votes_quorum_at_round(
        &self,
        round: RoundNumber,
        leader: AuthorityIndex,
        leader_round: RoundNumber,
        committee: &Committee,
    ) -> bool {
        let inner = self.inner.read();
        let blocks = inner.get_blocks_by_round(round);
        let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
        for (storage_block, _) in &blocks {
            let votes_for_leader = storage_block
                .block_references()
                .iter()
                .any(|r| r.authority == leader && r.round == leader_round);
            if votes_for_leader && aggregator.add(storage_block.author(), committee) {
                return true;
            }
        }
        false
    }

    /// Check if a quorum of blocks at `round` have `strong_vote == Some(true)`.
    pub fn has_strong_votes_quorum_at_round(
        &self,
        round: RoundNumber,
        committee: &Committee,
    ) -> bool {
        let inner = self.inner.read();
        let blocks = inner.get_blocks_by_round(round);
        let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
        for (storage_block, _) in &blocks {
            if storage_block.strong_vote() == Some(true)
                && aggregator.add(storage_block.author(), committee)
            {
                return true;
            }
        }
        false
    }

    pub fn block_exists(&self, reference: BlockReference) -> bool {
        self.inner.read().block_exists(reference)
    }

    /// A peer reports it has only synced up to `round`.
    /// Clear its known-by bit for newer blocks so they become eligible for
    /// re-dissemination.
    pub fn reset_peer_known_by_after_round(&self, peer: AuthorityIndex, round: RoundNumber) {
        self.inner
            .write()
            .reset_peer_known_by_after_round(peer, round);
    }

    pub fn is_data_available(&self, reference: &BlockReference) -> bool {
        self.inner.read().is_data_available(reference)
    }

    pub fn shard_count(&self, block_reference: &BlockReference) -> usize {
        self.inner.read().shard_count(block_reference)
    }

    pub fn contains_new_statements(&self, block: &VerifiedStatementBlock) -> bool {
        self.inner.read().contains_new_statements(block)
    }

    pub fn len_expensive(&self) -> usize {
        let inner = self.inner.read();
        inner.index.values().map(HashMap::len).sum()
    }

    pub fn highest_round(&self) -> RoundNumber {
        self.inner.read().highest_round
    }

    /// Version counter for a round, incremented each time a block is added at
    /// that round. Used as cache invalidation key.
    pub fn round_version(&self, round: RoundNumber) -> u64 {
        self.inner
            .read()
            .round_version
            .get(&round)
            .copied()
            .unwrap_or(0)
    }

    pub fn lowest_round(&self) -> RoundNumber {
        self.inner.read().dag.keys().next().copied().unwrap_or(0)
    }

    pub fn update_last_available_commit(&self, round: RoundNumber) {
        let mut inner = self.inner.write();
        inner.last_available_commit = inner.last_available_commit.max(round);
    }

    pub fn last_available_commit(&self) -> RoundNumber {
        self.inner.read().last_available_commit
    }

    pub fn cleanup(&self) {
        let threshold_round = self
            .inner
            .read()
            .last_available_commit
            .saturating_sub(2 * MAX_TRAVERSAL_DEPTH);
        if threshold_round == 0 {
            return;
        }
        let _timer = self.metrics.dag_state_cleanup_util.utilization_timer();

        self.inner.write().evict_below_round();
        self.round_block_cache
            .lock()
            .retain(|&r, _| r >= threshold_round);

        let inner = self.inner.read();
        self.metrics
            .dag_highest_round
            .set(inner.highest_round as i64);
        self.metrics
            .dag_lowest_round
            .set(inner.dag.keys().next().copied().unwrap_or(0) as i64);
        self.metrics
            .dag_blocks_in_memory
            .set(inner.index.values().map(|m| m.len() as i64).sum::<i64>());
    }

    pub fn get_own_transmission_blocks(
        &self,
        to_whom_authority_index: AuthorityIndex,
        from_excluded: RoundNumber,
        limit: usize,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let references = self.inner.read().get_own_block_references(
            to_whom_authority_index,
            from_excluded,
            limit,
        );
        references
            .into_iter()
            .filter_map(|reference| self.get_transmission_block(reference))
            .collect()
    }

    pub fn get_unsent_own_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_own_block_size: usize,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self
            .inner
            .read()
            .get_unsent_own_blocks(sent, peer, batch_own_block_size);

        Self::extract_transmission_blocks(entries)
    }

    pub fn get_unsent_other_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_other_block_size: usize,
        max_round_own_blocks: Option<RoundNumber>,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self.inner.read().get_unsent_other_blocks(
            sent,
            peer,
            batch_other_block_size,
            max_round_own_blocks,
        );

        Self::extract_transmission_blocks(entries)
    }

    pub fn get_unsent_causal_history(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
        authorities_with_missing_blocks: AHashSet<AuthorityIndex>,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self.inner.read().get_unsent_causal_history(
            sent,
            peer,
            batch_own_block_size,
            batch_other_block_size,
            authorities_with_missing_blocks,
        );

        Self::extract_transmission_blocks(entries)
    }

    pub fn get_unsent_past_cone(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        block_reference: BlockReference,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self.inner.read().get_unsent_past_cone(
            sent,
            peer,
            block_reference,
            batch_own_block_size,
            batch_other_block_size,
        );

        Self::extract_transmission_blocks(entries)
    }

    pub fn last_seen_by_authority(&self, authority: AuthorityIndex) -> RoundNumber {
        self.inner.read().last_seen_by_authority(authority)
    }

    pub fn min_last_seen_round(&self) -> RoundNumber {
        self.inner.read().min_last_seen_round()
    }

    pub fn last_own_block_ref(&self) -> Option<BlockReference> {
        self.inner.read().last_own_block()
    }

    fn extract_storage_blocks(entries: Vec<IndexEntry>) -> Vec<Data<VerifiedStatementBlock>> {
        entries.into_iter().map(|(s, _)| s).collect()
    }

    fn extract_transmission_blocks(entries: Vec<IndexEntry>) -> Vec<Data<VerifiedStatementBlock>> {
        entries.into_iter().map(|(_, t)| t).collect()
    }

    /// Check whether `earlier_block` is an ancestor of `later_block`.
    pub fn linked(
        &self,
        later_block: &Data<VerifiedStatementBlock>,
        earlier_block: &Data<VerifiedStatementBlock>,
    ) -> bool {
        let mut parents = AHashSet::from([later_block.clone()]);
        for _round_number in (earlier_block.round()..later_block.round()).rev() {
            // Collect parents from the current set of blocks.
            parents = parents
                .iter()
                .flat_map(|block| block.block_references()) // Get included blocks.
                .map(|block_reference| {
                    self.get_storage_block(*block_reference)
                        .expect("Block should be in DagState")
                })
                // Filter by round.
                .filter(|included_block| included_block.round() >= earlier_block.round())
                .collect();
        }
        parents.contains(earlier_block)
    }

    /// Compute all block references reachable from `later_block` at
    /// `target_round`. Single BFS traversal replaces N separate `linked()`
    /// calls for the same anchor.
    pub fn reachable_at_round(
        &self,
        later_block: &Data<VerifiedStatementBlock>,
        target_round: RoundNumber,
    ) -> AHashSet<BlockReference> {
        let mut frontier = AHashSet::from([later_block.clone()]);
        for _ in (target_round..later_block.round()).rev() {
            frontier = frontier
                .iter()
                .flat_map(|block| block.block_references())
                .filter_map(|r| self.get_storage_block(*r))
                .filter(|b| b.round() >= target_round)
                .collect();
        }
        frontier.iter().map(|b| *b.reference()).collect()
    }
}

impl DagStateInner {
    pub fn block_exists(&self, reference: BlockReference) -> bool {
        if let Some(blocks) = self.index.get(&reference.round) {
            if blocks.contains_key(&(reference.authority, reference.digest)) {
                return true;
            }
        }
        // RocksDB fallback for evicted blocks
        self.rocks_store
            .get_block(&reference)
            .expect("RocksDB read failed")
            .is_some()
    }

    pub fn is_data_available(&self, reference: &BlockReference) -> bool {
        self.data_availability.contains(reference)
    }

    pub fn shard_count(&self, block_reference: &BlockReference) -> usize {
        if self.data_availability.contains(block_reference) {
            return self.committee_size;
        }
        0
    }

    pub fn read_pending_unavailable(
        &self,
    ) -> Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)> {
        self.pending_not_available.clone()
    }

    pub fn update_pending_unavailable(
        &mut self,
        pending: Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)>,
    ) {
        self.pending_not_available = pending;
    }

    /// Check if the block has new statement data we don't already have.
    pub fn contains_new_statements(&self, block: &VerifiedStatementBlock) -> bool {
        let block_reference = block.reference();
        if self.data_availability.contains(block_reference) {
            return false;
        }
        block.statements().is_some()
    }

    pub fn get_blocks_at_authority_round(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Vec<IndexEntry> {
        let Some(blocks) = self.index.get(&round) else {
            return vec![];
        };
        blocks
            .iter()
            .filter_map(|((a, _), entry)| {
                if *a == authority {
                    Some(entry.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn get_blocks_by_round(&self, round: RoundNumber) -> Vec<IndexEntry> {
        let Some(blocks) = self.index.get(&round) else {
            return vec![];
        };
        blocks.values().cloned().collect()
    }

    pub fn get_block(&self, reference: BlockReference) -> Option<IndexEntry> {
        let round_entries = self.index.get(&reference.round)?;
        round_entries
            .get(&(reference.authority, reference.digest))
            .cloned()
    }

    pub fn evict_below_round(&mut self) {
        let dag_threshold = self
            .last_available_commit
            .saturating_sub(2 * MAX_TRAVERSAL_DEPTH);
        if dag_threshold > 0 {
            self.dag = self.dag.split_off(&dag_threshold);
            self.index = self.index.split_off(&dag_threshold);

            let split_ref = BlockReference {
                authority: 0,
                round: dag_threshold,
                digest: BlockDigest::default(),
            };
            self.data_availability = self.data_availability.split_off(&split_ref);
            self.round_version.retain(|&r, _| r >= dag_threshold);
        }
    }

    pub fn add_block(
        &mut self,
        blocks: (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>),
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        let reference = blocks.0.reference();
        self.highest_round = max(self.highest_round, reference.round());

        self.add_own_index(reference, authority_index_start, authority_index_end);
        self.update_last_seen_by_authority(reference);

        let map = self.index.entry(reference.round()).or_default();
        map.insert(reference.author_digest(), blocks.clone());

        *self.round_version.entry(reference.round()).or_insert(0) += 1;
        self.update_dag(*reference, blocks.0.block_references().clone());
        self.update_data_availability(&blocks.0);
    }

    fn dag_get(&self, r: &BlockReference) -> Option<&(Vec<BlockReference>, AuthorityBitmask)> {
        self.dag.get(&r.round)?.get(&(r.authority, r.digest))
    }

    fn dag_get_mut(
        &mut self,
        r: &BlockReference,
    ) -> Option<&mut (Vec<BlockReference>, AuthorityBitmask)> {
        self.dag
            .get_mut(&r.round)?
            .get_mut(&(r.authority, r.digest))
    }

    fn dag_contains(&self, r: &BlockReference) -> bool {
        self.dag_get(r).is_some()
    }

    fn dag_insert(&mut self, r: BlockReference, val: (Vec<BlockReference>, AuthorityBitmask)) {
        self.dag
            .entry(r.round)
            .or_default()
            .insert((r.authority, r.digest), val);
    }

    fn reset_peer_known_by_after_round(&mut self, peer: AuthorityIndex, round: RoundNumber) {
        let bit = !(1u128 << peer);
        for (_, entries) in self.dag.range_mut((round.saturating_add(1))..) {
            for (_, (_, known_by)) in entries.iter_mut() {
                *known_by &= bit;
            }
        }
    }

    /// Insert a block into the DAG and propagate "known-by" bits along the
    /// causal history.
    pub fn update_dag(&mut self, block_reference: BlockReference, parents: Vec<BlockReference>) {
        if block_reference.round == 0 {
            return;
        }
        if self.dag_contains(&block_reference) {
            return;
        }
        let known_by = (1u128 << block_reference.authority) | (1u128 << self.authority);
        self.dag_insert(block_reference, (parents, known_by));
        // Traverse the DAG from block_reference and update the
        // blocks known by block_reference.authority
        let authority = block_reference.authority;
        let mut buffer = vec![block_reference];

        while let Some(block_reference) = buffer.pop() {
            let Some((parents, _)) = self.dag_get(&block_reference).cloned() else {
                continue; // evicted
            };
            for parent in parents {
                if parent.round == 0 {
                    continue;
                }
                let Some((_, known_by)) = self.dag_get_mut(&parent) else {
                    continue; // evicted
                };
                let bit = 1u128 << authority;
                if *known_by & bit == 0 {
                    *known_by |= bit;
                    buffer.push(parent);
                }
            }
        }
    }

    pub fn update_data_availability(&mut self, block: &VerifiedStatementBlock) {
        if block.statements().is_some() && !self.data_availability.contains(block.reference()) {
            self.data_availability.insert(*block.reference());
            self.pending_acknowledgment.push(*block.reference());
        }
    }

    pub fn get_pending_acknowledgment(&mut self, round_number: RoundNumber) -> Vec<BlockReference> {
        let (to_return, to_keep): (Vec<_>, Vec<_>) = self
            .pending_acknowledgment
            .drain(..)
            .partition(|x| x.round <= round_number);
        self.pending_acknowledgment = to_keep;
        to_return
    }

    pub fn last_seen_by_authority(&self, authority: AuthorityIndex) -> RoundNumber {
        *self
            .last_seen_by_authority
            .get(authority as usize)
            .expect("last_seen_by_authority not found")
    }

    pub fn min_last_seen_round(&self) -> RoundNumber {
        self.last_seen_by_authority
            .iter()
            .copied()
            .min()
            .unwrap_or(0)
    }

    fn update_last_seen_by_authority(&mut self, reference: &BlockReference) {
        let last_seen = self
            .last_seen_by_authority
            .get_mut(reference.authority as usize)
            .expect("last_seen_by_authority not found");
        *last_seen = (*last_seen).max(reference.round());
    }

    pub fn get_own_block_references(
        &self,
        to_whom_index: AuthorityIndex,
        from_excluded: RoundNumber,
        limit: usize,
    ) -> Vec<BlockReference> {
        self.own_blocks
            .range((from_excluded + 1, 0)..)
            .filter(|((_round, authority_index), _digest)| *authority_index == to_whom_index)
            .take(limit)
            .map(|((round, _authority_index), digest)| BlockReference {
                authority: self.authority,
                round: *round,
                digest: *digest,
            })
            .collect()
    }

    /// Collect unsent blocks for a peer by iterating the DAG, skipping those in
    /// `sent`.
    fn collect_unsent_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        filter: impl Fn(&BlockReference) -> bool,
        limit: usize,
    ) -> Vec<(IndexEntry, RoundNumber)> {
        let peer_bit = 1u128 << peer;
        self.dag
            .iter()
            .flat_map(|(round, entries)| {
                entries
                    .iter()
                    .map(move |((authority, digest), (_, known_by))| {
                        (
                            BlockReference {
                                authority: *authority,
                                round: *round,
                                digest: *digest,
                            },
                            *known_by,
                        )
                    })
            })
            .filter(|(r, known_by)| known_by & peer_bit == 0 && !sent.contains(r) && filter(r))
            .take(limit)
            .map(|(r, _)| r)
            .map(|r| {
                let entry = self
                    .get_block(r)
                    .unwrap_or_else(|| panic!("Block index corrupted, not found: {r}"));
                (entry, r.round())
            })
            .collect()
    }

    fn into_sorted_entries(mut blocks: Vec<(IndexEntry, RoundNumber)>) -> Vec<IndexEntry> {
        blocks.sort_by_key(|x| x.1);
        blocks.into_iter().map(|x| x.0).collect()
    }

    pub fn get_unsent_own_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_own_block_size: usize,
    ) -> Vec<IndexEntry> {
        let auth = self.authority;
        Self::into_sorted_entries(self.collect_unsent_blocks(
            sent,
            peer,
            |r| r.authority == auth,
            batch_own_block_size,
        ))
    }

    pub fn get_unsent_other_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_other_block_size: usize,
        max_round: Option<RoundNumber>,
    ) -> Vec<IndexEntry> {
        let auth = self.authority;
        let max = max_round.unwrap_or(RoundNumber::MAX);
        Self::into_sorted_entries(self.collect_unsent_blocks(
            sent,
            peer,
            |r| r.authority != auth && r.round < max,
            batch_other_block_size,
        ))
    }

    pub fn get_unsent_causal_history(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
        authorities_with_missing_blocks: AHashSet<AuthorityIndex>,
    ) -> Vec<IndexEntry> {
        let auth = self.authority;
        let own =
            self.collect_unsent_blocks(sent, peer, |r| r.authority == auth, batch_own_block_size);
        let max = own.iter().map(|x| x.1).max().unwrap_or(RoundNumber::MAX);
        let other = self.collect_unsent_blocks(
            sent,
            peer,
            |r| authorities_with_missing_blocks.contains(&r.authority) && r.round < max,
            batch_other_block_size,
        );
        Self::into_sorted_entries(own.into_iter().chain(other).collect())
    }

    pub fn get_unsent_past_cone(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        block_reference: BlockReference,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
    ) -> Vec<IndexEntry> {
        let auth = self.authority;
        let max = block_reference.round;
        let own = self.collect_unsent_blocks(
            sent,
            peer,
            |r| r.authority == auth && r.round < max,
            batch_own_block_size,
        );
        let other = self.collect_unsent_blocks(
            sent,
            peer,
            |r| r.authority != auth && r.round < max,
            batch_other_block_size,
        );
        Self::into_sorted_entries(own.into_iter().chain(other).collect())
    }

    fn add_own_index(
        &mut self,
        reference: &BlockReference,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        if reference.authority != self.authority {
            return;
        }
        if reference.round > self.last_own_block.map(|r| r.round).unwrap_or_default() {
            self.last_own_block = Some(*reference);
        }
        for authority_index in authority_index_start..authority_index_end {
            // own_blocks is never evicted, so duplicates are expected when blocks
            // arrive again from the network.
            self.own_blocks
                .entry((reference.round, authority_index))
                .or_insert(reference.digest);
        }
    }

    pub fn last_own_block(&self) -> Option<BlockReference> {
        self.last_own_block
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OwnBlockData {
    pub storage_transmission_blocks: (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>),
    pub authority_index_start: AuthorityIndex,
    pub authority_index_end: AuthorityIndex,
}

impl OwnBlockData {
    pub fn new(
        storage_transmission_blocks: (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>),
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) -> Self {
        Self {
            storage_transmission_blocks,
            authority_index_start,
            authority_index_end,
        }
    }

    pub fn from_bytes(bytes: Bytes) -> bincode::Result<Self> {
        bincode::deserialize(&bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization failed")
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommitData {
    pub leader: BlockReference,
    // All committed blocks, including the leader
    pub sub_dag: Vec<BlockReference>,
}

impl From<&CommittedSubDag> for CommitData {
    fn from(value: &CommittedSubDag) -> Self {
        let sub_dag = value.blocks.iter().map(|b| *b.reference()).collect();
        Self {
            leader: value.anchor,
            sub_dag,
        }
    }
}
