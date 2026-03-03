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
    config::StorageBackend,
    consensus::linearizer::{CommittedSubDag, MAX_TRAVERSAL_DEPTH},
    data::Data,
    metrics::{Metrics, UtilizationTimerExt},
    network::ShardPayload,
    rocks_store::RocksStore,
    state::{RecoveredState, RecoveredStateBuilder},
    store::Store,
    types::{
        AuthorityIndex, BlockDigest, BlockReference, ProvableShard, RoundNumber, TransactionData,
        VerifiedBlock,
    },
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

    pub fn supports_acknowledgments(self) -> bool {
        matches!(
            self,
            ConsensusProtocol::StarfishPull
                | ConsensusProtocol::CordialMiners
                | ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishS
        )
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
    dag_state_inner: Arc<RwLock<DagStateInner>>,
    store: Arc<dyn Store>,
    metrics: Arc<Metrics>,
    pub(crate) consensus_protocol: ConsensusProtocol,
    pub(crate) committee_size: usize,
    pub(crate) byzantine_strategy: Option<ByzantineStrategy>,
    /// Version-gated cache of round block snapshots (outside the RwLock).
    round_block_cache: Arc<parking_lot::Mutex<RoundBlockCache>>,
}

type RoundBlockCache = AHashMap<RoundNumber, (u64, Arc<[Data<VerifiedBlock>]>)>;

/// Number of rounds to keep in memory per authority beyond the evicted
/// frontier. Must be >= 2 * MAX_TRAVERSAL_DEPTH to guarantee consensus
/// traversals can complete without storage fallback.
const CACHED_ROUNDS: RoundNumber = 2 * MAX_TRAVERSAL_DEPTH;

/// Per-authority DAG: round → (digest → (parents, known_by_bitmask)).
type DagAuthorityMap =
    BTreeMap<RoundNumber, HashMap<BlockDigest, (Vec<BlockReference>, AuthorityBitmask)>>;

struct DagStateInner {
    store: Arc<dyn Store>,
    /// Per-authority block storage. Vec index = authority.
    index: Vec<BTreeMap<RoundNumber, HashMap<BlockDigest, Data<VerifiedBlock>>>>,
    /// Per-authority data availability tracking. Vec index = authority.
    data_availability: Vec<BTreeSet<BlockReference>>,
    // Blocks for which we have transaction data and still need to acknowledge.
    // Unsupported protocols leave this disabled entirely.
    pending_acknowledgment: Option<Vec<BlockReference>>,
    // Byzantine nodes will create different blocks intended for the different validators
    own_blocks: BTreeMap<(RoundNumber, AuthorityIndex), BlockDigest>,
    highest_round: RoundNumber,
    authority: AuthorityIndex,
    committee_size: usize,
    consensus_protocol: ConsensusProtocol,
    last_seen_by_authority: Vec<RoundNumber>,
    last_own_block: Option<BlockReference>,
    /// Per-authority DAG metadata. Vec index = authority.
    dag: Vec<DagAuthorityMap>,
    /// Per-authority eviction frontier: highest round evicted for each
    /// authority.
    evicted_rounds: Vec<RoundNumber>,
    // Round of the latest committed leader whose sub-dag was fully sequenced
    // (all data available).
    last_available_commit: RoundNumber,
    // per-round version counter, incremented on each add_block to that round
    round_version: AHashMap<RoundNumber, u64>,
    // committed subdag which contains blocks with at least one unavailable transaction data
    pending_not_available: Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)>,
}

impl DagState {
    pub fn open(
        authority: AuthorityIndex,
        path: impl AsRef<Path>,
        metrics: Arc<Metrics>,
        committee: &Committee,
        byzantine_strategy: String,
        consensus: String,
        storage_backend: &StorageBackend,
    ) -> RecoveredState {
        assert!(
            committee.len() <= 128,
            "Committee size {} exceeds AuthorityBitmask capacity (128)",
            committee.len()
        );
        let store: Arc<dyn Store> = match storage_backend {
            #[cfg(feature = "tidehunter")]
            StorageBackend::Tidehunter => {
                tracing::info!("Using TideHunter storage backend");
                metrics.storage_backend_info.set(1);
                Arc::new(
                    crate::tidehunter_store::TideHunterStore::open(&path)
                        .expect("Failed to open TideHunter"),
                )
            }
            #[cfg(not(feature = "tidehunter"))]
            StorageBackend::Tidehunter => {
                panic!("TideHunter storage requested but the `tidehunter` feature is not enabled");
            }
            StorageBackend::Rocksdb => {
                metrics.storage_backend_info.set(0);
                Arc::new(RocksStore::open(&path).expect("Failed to open RocksDB"))
            }
        };
        let consensus_protocol = ConsensusProtocol::from_str(&consensus);
        let last_seen_by_authority = committee.authorities().map(|_| 0).collect();
        let n = committee.len();
        let mut inner = DagStateInner {
            store: store.clone(),
            authority,
            last_seen_by_authority,
            last_available_commit: 0,
            committee_size: n,
            consensus_protocol,
            index: (0..n).map(|_| BTreeMap::new()).collect(),
            data_availability: (0..n).map(|_| BTreeSet::new()).collect(),
            pending_acknowledgment: consensus_protocol.supports_acknowledgments().then(Vec::new),
            own_blocks: BTreeMap::new(),
            highest_round: 0,
            last_own_block: None,
            dag: (0..n).map(|_| BTreeMap::new()).collect(),
            evicted_rounds: vec![0; n],
            pending_not_available: Vec::new(),
            round_version: AHashMap::new(),
        };
        let mut builder = RecoveredStateBuilder::new();
        let replay_started = Instant::now();
        let mut block_count = 0u64;
        let mut recovered_commit_leaders = AHashSet::new();
        // Recover blocks from storage
        let mut current_round = 0;
        loop {
            let blocks = store
                .get_blocks_by_round(current_round)
                .expect("Failed to read blocks from storage");

            if blocks.is_empty() {
                break;
            }

            for block in blocks {
                let block_ref = *block.reference();

                builder.block(current_round, block.clone());
                block_count += 1;
                inner.add_block(block, 0, committee.len() as AuthorityIndex);
                if recovered_commit_leaders.insert(block_ref) {
                    if let Some(commit_data) = store
                        .get_commit(&block_ref)
                        .expect("Failed to read commit data from storage")
                    {
                        builder.commit(commit_data);
                    }
                }
            }

            current_round += 1;
        }

        metrics.dag_state_entries.inc_by(block_count);
        metrics.dag_highest_round.set(inner.highest_round as i64);
        metrics
            .dag_lowest_round
            .set(inner.global_lowest_round() as i64);
        tracing::debug!(
            "authority={} storage replay: {} blocks in {:?}, highest_round={}",
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
            store: store.clone(),
            byzantine_strategy,
            dag_state_inner: Arc::new(RwLock::new(inner)),
            metrics,
            consensus_protocol,
            committee_size: committee.len(),
            round_block_cache: Arc::new(parking_lot::Mutex::new(AHashMap::new())),
        };
        builder.build(store, dag_state)
    }

    pub fn get_dag_sorted(&self) -> Vec<(BlockReference, Vec<BlockReference>, AuthorityBitmask)> {
        let inner = self.dag_state_inner.read();
        let mut result: Vec<_> = inner
            .dag
            .iter()
            .enumerate()
            .flat_map(|(auth_idx, auth_dag)| {
                auth_dag.iter().flat_map(move |(round, entries)| {
                    entries.iter().map(move |(digest, (parents, known_by))| {
                        (
                            BlockReference {
                                authority: auth_idx as AuthorityIndex,
                                round: *round,
                                digest: *digest,
                            },
                            parents.clone(),
                            *known_by,
                        )
                    })
                })
            })
            .collect();
        result.sort_by_key(|(r, _, _)| r.round);
        result
    }

    pub fn get_own_authority_index(&self) -> AuthorityIndex {
        self.dag_state_inner.read().authority
    }

    pub fn read_pending_unavailable(
        &self,
    ) -> Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)> {
        self.dag_state_inner.read().read_pending_unavailable()
    }

    pub fn update_pending_unavailable(
        &self,
        pending: Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)>,
    ) {
        self.dag_state_inner
            .write()
            .update_pending_unavailable(pending);
    }

    pub fn insert_block_bounds(
        &self,
        block: Data<VerifiedBlock>,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        self.metrics.dag_state_entries.inc();

        // Persist to storage — use component stores for header-only blocks
        // to avoid writing empty payloads, and store_block for full blocks.
        // Pre-serialized bytes (from preserialize()) are used when available.
        let store_start = std::time::Instant::now();
        if block.has_transaction_data() {
            self.store
                .store_block(block.clone())
                .expect("Failed to store block");
        } else {
            let header_bytes = block
                .serialized_header_bytes()
                .expect("header should be preserialized before entering core thread");
            self.store
                .store_header_bytes(block.reference(), header_bytes)
                .expect("Failed to store header");
        }
        self.metrics
            .store_block_latency_us
            .inc_by(store_start.elapsed().as_micros() as u64);
        self.metrics.store_block_count.inc();

        let (highest_round, lowest_round) = {
            let mut inner = self.dag_state_inner.write();
            inner.add_block(block, authority_index_start, authority_index_end);
            (inner.highest_round, inner.global_lowest_round())
        };
        self.metrics.dag_highest_round.set(highest_round as i64);
        self.metrics.dag_lowest_round.set(lowest_round as i64);
    }

    pub fn insert_general_block(&self, block: Data<VerifiedBlock>) {
        let authority_index_start = 0;
        let authority_index_end = self.committee_size as AuthorityIndex;
        self.insert_block_bounds(block, authority_index_start, authority_index_end);
    }

    // Insert own blocks is primarily needed to capture Byzantine behavior with
    // equivocating blocks
    pub fn insert_own_block(&self, own_block: OwnBlockData) {
        self.insert_block_bounds(
            own_block.block,
            own_block.authority_index_start,
            own_block.authority_index_end,
        );
    }

    pub fn get_storage_block(&self, reference: BlockReference) -> Option<Data<VerifiedBlock>> {
        self.dag_state_inner.read().get_storage_block(reference)
    }

    pub fn get_transmission_block(&self, reference: BlockReference) -> Option<Data<VerifiedBlock>> {
        self.dag_state_inner
            .read()
            .get_transmission_block(reference)
    }

    pub fn get_pending_acknowledgment(&self, round_number: RoundNumber) -> Vec<BlockReference> {
        self.dag_state_inner
            .write()
            .get_pending_acknowledgment(round_number)
    }

    pub fn get_blocks_by_round(&self, round: RoundNumber) -> Vec<Data<VerifiedBlock>> {
        self.dag_state_inner.read().get_blocks_by_round(round)
    }

    /// Version-gated cached variant of `get_blocks_by_round`.
    /// Returns `Arc<[T]>` to avoid repeated Vec allocations for the same round.
    pub fn get_blocks_by_round_cached(&self, round: RoundNumber) -> Arc<[Data<VerifiedBlock>]> {
        let inner = self.dag_state_inner.read();
        let version = inner.round_version.get(&round).copied().unwrap_or(0);
        {
            let cache = self.round_block_cache.lock();
            if let Some((ver, blocks)) = cache.get(&round) {
                if *ver == version {
                    return blocks.clone();
                }
            }
        }
        let blocks: Arc<[_]> = inner.get_blocks_by_round(round).into();
        self.round_block_cache
            .lock()
            .insert(round, (version, blocks.clone()));
        blocks
    }

    pub fn get_blocks_at_authority_round(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Vec<Data<VerifiedBlock>> {
        self.dag_state_inner
            .read()
            .get_blocks_at_authority_round(authority, round)
    }

    pub fn block_exists_at_authority_round(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> bool {
        !self
            .dag_state_inner
            .read()
            .get_blocks_at_authority_round(authority, round)
            .is_empty()
    }

    pub fn all_blocks_exists_at_authority_round(
        &self,
        authorities: &[AuthorityIndex],
        round: RoundNumber,
    ) -> bool {
        let inner = self.dag_state_inner.read();
        let blocks = inner.get_blocks_by_round(round);
        if blocks.is_empty() {
            return false;
        }
        authorities
            .iter()
            .all(|auth| blocks.iter().any(|b| b.author() == *auth))
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
        let inner = self.dag_state_inner.read();
        let blocks = inner.get_blocks_by_round(round);
        let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
        for block in &blocks {
            let votes_for_leader = block
                .block_references()
                .iter()
                .any(|r| r.authority == leader && r.round == leader_round);
            if votes_for_leader && aggregator.add(block.author(), committee) {
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
        let inner = self.dag_state_inner.read();
        let blocks = inner.get_blocks_by_round(round);
        let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
        for block in &blocks {
            if block.strong_vote() == Some(true) && aggregator.add(block.author(), committee) {
                return true;
            }
        }
        false
    }

    pub fn block_exists(&self, reference: BlockReference) -> bool {
        self.dag_state_inner.read().block_exists(reference)
    }

    /// A peer reports it has only synced up to `round`.
    /// Clear its known-by bit for newer blocks so they become eligible for
    /// re-dissemination.
    pub fn reset_peer_known_by_after_round(&self, peer: AuthorityIndex, round: RoundNumber) {
        self.dag_state_inner
            .write()
            .reset_peer_known_by_after_round(peer, round);
    }

    pub fn is_data_available(&self, reference: &BlockReference) -> bool {
        self.dag_state_inner.read().is_data_available(reference)
    }

    pub fn shard_count(&self, block_reference: &BlockReference) -> usize {
        self.dag_state_inner.read().shard_count(block_reference)
    }

    /// Batch variant of `get_storage_block` — single read lock for N lookups.
    pub fn get_storage_blocks(&self, refs: &[BlockReference]) -> Vec<Option<Data<VerifiedBlock>>> {
        let inner = self.dag_state_inner.read();
        refs.iter().map(|r| inner.get_storage_block(*r)).collect()
    }

    /// Batch variant of `get_transmission_block` — single read lock for N
    /// lookups.
    pub fn get_transmission_blocks(
        &self,
        refs: &[BlockReference],
    ) -> Vec<Option<Data<VerifiedBlock>>> {
        let inner = self.dag_state_inner.read();
        refs.iter()
            .map(|r| inner.get_transmission_block(*r))
            .collect()
    }

    /// Fetch blocks as header-only for the given references.
    pub fn get_header_only_blocks(&self, refs: &[BlockReference]) -> Vec<Data<VerifiedBlock>> {
        let inner = self.dag_state_inner.read();
        refs.iter()
            .filter_map(|r| {
                inner
                    .get_storage_block(*r)
                    .map(|block| Data::new(block.as_header_only()))
            })
            .collect()
    }

    /// Fetch shard payloads for the given references.
    pub fn get_shard_payloads(&self, refs: &[BlockReference]) -> Vec<ShardPayload> {
        let inner = self.dag_state_inner.read();
        refs.iter()
            .filter_map(|r| {
                let block = inner.get_storage_block(*r)?;
                let shard = block.shard_data()?.clone();
                Some(ShardPayload {
                    block_reference: *r,
                    shard,
                })
            })
            .collect()
    }

    /// Batch variant of `is_data_available` — single read lock for N lookups.
    pub fn are_data_available(&self, refs: &[BlockReference]) -> Vec<bool> {
        let inner = self.dag_state_inner.read();
        refs.iter().map(|r| inner.is_data_available(r)).collect()
    }

    pub fn contains_new_transactions(&self, block: &VerifiedBlock) -> bool {
        self.dag_state_inner.read().contains_new_transactions(block)
    }

    /// Attach recovered transaction data to an existing header-only block.
    /// Bypasses the block manager — the header is already accepted and
    /// connected.
    pub fn attach_transaction_data(
        &self,
        block_ref: BlockReference,
        transaction_data: &TransactionData,
        shard_data: &ProvableShard,
        serialized_tx_data: &[u8],
        serialized_shard_data: &[u8],
    ) -> bool {
        let mut inner = self.dag_state_inner.write();
        let auth = block_ref.authority as usize;

        // Clone the header from the existing block (immutable borrow, dropped at block
        // end).
        let header = {
            let existing = inner.index[auth]
                .get(&block_ref.round)
                .and_then(|m| m.get(&block_ref.digest));
            match existing {
                Some(b) if b.has_transaction_data() => return true,
                Some(b) => b.header().clone(),
                None => return false,
            }
        };

        // Persist only the new components — the header is already stored.
        // Bytes are pre-serialized off the core thread.
        self.store
            .store_tx_data_bytes(&block_ref, serialized_tx_data)
            .expect("Failed to store transaction data");
        self.store
            .store_shard_data_bytes(&block_ref, serialized_shard_data)
            .expect("Failed to store shard data");

        // Rebuild the in-memory composite block (consumers expect Data<VerifiedBlock>).
        let updated = Data::new(VerifiedBlock::from_parts(
            header,
            Some(transaction_data.clone()),
            Some(shard_data.clone()),
        ));

        // Replace in index (short-lived mutable borrow).
        inner.index[auth]
            .get_mut(&block_ref.round)
            .unwrap()
            .insert(block_ref.digest, updated);

        // Mark data-available + queue acknowledgment.
        if !inner.data_availability[auth].contains(&block_ref) {
            inner.data_availability[auth].insert(block_ref);
            if let Some(pending_acknowledgment) = inner.pending_acknowledgment.as_mut() {
                pending_acknowledgment.push(block_ref);
            }
        }
        *inner.round_version.entry(block_ref.round).or_insert(0) += 1;
        true
    }

    pub fn len_expensive(&self) -> usize {
        let inner = self.dag_state_inner.read();
        inner
            .index
            .iter()
            .flat_map(|auth_map| auth_map.values())
            .map(HashMap::len)
            .sum()
    }

    pub fn highest_round(&self) -> RoundNumber {
        self.dag_state_inner.read().highest_round
    }

    /// Version counter for a round, incremented each time a block is added at
    /// that round. Used as cache invalidation key.
    pub fn round_version(&self, round: RoundNumber) -> u64 {
        self.dag_state_inner
            .read()
            .round_version
            .get(&round)
            .copied()
            .unwrap_or(0)
    }

    pub fn lowest_round(&self) -> RoundNumber {
        self.dag_state_inner.read().global_lowest_round()
    }

    pub fn update_last_available_commit(&self, round: RoundNumber) {
        let mut inner = self.dag_state_inner.write();
        inner.last_available_commit = inner.last_available_commit.max(round);
    }

    pub fn last_available_commit(&self) -> RoundNumber {
        self.dag_state_inner.read().last_available_commit
    }

    pub fn cleanup(&self) {
        let _timer = self.metrics.dag_state_cleanup_util.utilization_timer();

        let (highest_round, lowest_round, block_count, max_evicted) = {
            let mut inner = self.dag_state_inner.write();
            inner.evict_per_authority();
            (
                inner.highest_round,
                inner.global_lowest_round(),
                inner
                    .index
                    .iter()
                    .flat_map(|m| m.values())
                    .map(|h| h.len() as i64)
                    .sum::<i64>(),
                inner.evicted_rounds.iter().copied().max().unwrap_or(0),
            )
        };

        // Invalidate cache below max evicted round (any partially-evicted round
        // is stale).
        self.round_block_cache
            .lock()
            .retain(|&r, _| r >= max_evicted);
        self.metrics.dag_highest_round.set(highest_round as i64);
        self.metrics.dag_lowest_round.set(lowest_round as i64);
        self.metrics.dag_blocks_in_memory.set(block_count);
    }

    pub fn get_own_transmission_blocks(
        &self,
        to_whom_authority_index: AuthorityIndex,
        from_excluded: RoundNumber,
        limit: usize,
    ) -> Vec<Data<VerifiedBlock>> {
        let inner = self.dag_state_inner.read();
        let references =
            inner.get_own_block_references(to_whom_authority_index, from_excluded, limit);
        references
            .into_iter()
            .filter_map(|reference| inner.get_transmission_block(reference))
            .collect()
    }

    pub fn get_unsent_own_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_own_block_size: usize,
    ) -> Vec<Data<VerifiedBlock>> {
        self.dag_state_inner
            .read()
            .get_unsent_own_blocks(sent, peer, batch_own_block_size)
    }

    pub fn get_unsent_other_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_other_block_size: usize,
        max_round_own_blocks: Option<RoundNumber>,
    ) -> Vec<Data<VerifiedBlock>> {
        self.dag_state_inner.read().get_unsent_other_blocks(
            sent,
            peer,
            batch_other_block_size,
            max_round_own_blocks,
        )
    }

    pub fn get_unsent_causal_history(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
        authorities_with_missing_blocks: AHashSet<AuthorityIndex>,
    ) -> Vec<Data<VerifiedBlock>> {
        self.dag_state_inner.read().get_unsent_causal_history(
            sent,
            peer,
            batch_own_block_size,
            batch_other_block_size,
            authorities_with_missing_blocks,
        )
    }

    pub fn get_unsent_past_cone(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        block_reference: BlockReference,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
    ) -> Vec<Data<VerifiedBlock>> {
        self.dag_state_inner.read().get_unsent_past_cone(
            sent,
            peer,
            block_reference,
            batch_own_block_size,
            batch_other_block_size,
        )
    }

    pub fn last_seen_by_authority(&self, authority: AuthorityIndex) -> RoundNumber {
        self.dag_state_inner
            .read()
            .last_seen_by_authority(authority)
    }

    pub fn min_last_seen_round(&self) -> RoundNumber {
        self.dag_state_inner.read().min_last_seen_round()
    }

    /// Conservative global GC round (minimum across all authorities).
    /// Used by external callers that need a single safe threshold.
    pub fn gc_round(&self) -> RoundNumber {
        self.dag_state_inner.read().min_evicted_round()
    }

    /// Per-authority eviction rounds for fine-grained cleanup.
    pub fn evicted_rounds(&self) -> Vec<RoundNumber> {
        self.dag_state_inner.read().evicted_rounds.clone()
    }

    pub fn last_own_block_ref(&self) -> Option<BlockReference> {
        self.dag_state_inner.read().last_own_block()
    }

    /// Check whether `earlier_block` is an ancestor of `later_block`.
    pub fn linked(
        &self,
        later_block: &Data<VerifiedBlock>,
        earlier_block: &Data<VerifiedBlock>,
    ) -> bool {
        self.dag_state_inner
            .read()
            .linked(later_block, earlier_block)
    }

    /// Compute all block references reachable from `later_block` at
    /// `target_round`. Single BFS traversal replaces N separate `linked()`
    /// calls for the same anchor.
    pub fn reachable_at_round(
        &self,
        later_block: &Data<VerifiedBlock>,
        target_round: RoundNumber,
    ) -> AHashSet<BlockReference> {
        self.dag_state_inner
            .read()
            .reachable_at_round(later_block, target_round)
    }
}

impl DagStateInner {
    fn global_lowest_round(&self) -> RoundNumber {
        self.dag
            .iter()
            .filter_map(|m| m.keys().next().copied())
            .min()
            .unwrap_or(0)
    }

    fn min_evicted_round(&self) -> RoundNumber {
        self.evicted_rounds.iter().copied().min().unwrap_or(0)
    }

    pub fn block_exists(&self, reference: BlockReference) -> bool {
        let auth = reference.authority as usize;
        if let Some(blocks) = self.index[auth].get(&reference.round) {
            if blocks.contains_key(&reference.digest) {
                return true;
            }
        }
        // Storage fallback for evicted blocks
        self.store
            .get_block(&reference)
            .expect("Storage read failed")
            .is_some()
    }

    pub fn is_data_available(&self, reference: &BlockReference) -> bool {
        self.data_availability[reference.authority as usize].contains(reference)
    }

    pub fn shard_count(&self, block_reference: &BlockReference) -> usize {
        if self.data_availability[block_reference.authority as usize].contains(block_reference) {
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

    /// Check if the block has new transaction data we don't already have.
    pub fn contains_new_transactions(&self, block: &VerifiedBlock) -> bool {
        let block_reference = block.reference();
        if self.data_availability[block_reference.authority as usize].contains(block_reference) {
            return false;
        }
        block.transactions().is_some()
    }

    pub fn get_blocks_at_authority_round(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Vec<Data<VerifiedBlock>> {
        self.index[authority as usize]
            .get(&round)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_blocks_by_round(&self, round: RoundNumber) -> Vec<Data<VerifiedBlock>> {
        self.index
            .iter()
            .flat_map(|auth_map| {
                auth_map
                    .get(&round)
                    .into_iter()
                    .flat_map(|m| m.values().cloned())
            })
            .collect()
    }

    pub fn get_block(&self, reference: BlockReference) -> Option<Data<VerifiedBlock>> {
        let auth = reference.authority as usize;
        self.index[auth]
            .get(&reference.round)?
            .get(&reference.digest)
            .cloned()
    }

    /// Get a block, with persistent store fallback for evicted blocks.
    fn get_storage_block(&self, reference: BlockReference) -> Option<Data<VerifiedBlock>> {
        if let Some(block) = self.get_block(reference) {
            return Some(block);
        }
        self.store
            .get_block(&reference)
            .expect("Storage read failed")
    }

    /// Get a block suitable for transmission to peers. Same as storage block
    /// since transmission views are now constructed at send time.
    fn get_transmission_block(&self, reference: BlockReference) -> Option<Data<VerifiedBlock>> {
        self.get_storage_block(reference)
    }

    /// Check whether `earlier_block` is an ancestor of `later_block`.
    fn linked(
        &self,
        later_block: &Data<VerifiedBlock>,
        earlier_block: &Data<VerifiedBlock>,
    ) -> bool {
        let mut parents = AHashSet::from([later_block.clone()]);
        for _round_number in (earlier_block.round()..later_block.round()).rev() {
            parents = parents
                .iter()
                .flat_map(|block| block.block_references())
                .map(|block_reference| {
                    self.get_storage_block(*block_reference)
                        .expect("Block should be in DagState")
                })
                .filter(|included_block| included_block.round() >= earlier_block.round())
                .collect();
        }
        parents.contains(earlier_block)
    }

    /// Compute all block references reachable from `later_block` at
    /// `target_round`. Single BFS traversal replaces N separate `linked()`
    /// calls for the same anchor.
    fn reachable_at_round(
        &self,
        later_block: &Data<VerifiedBlock>,
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

    /// Per-authority eviction using BTreeMap::split_off.
    fn evict_per_authority(&mut self) {
        for auth in 0..self.committee_size {
            let last_seen = self.last_seen_by_authority[auth];
            let threshold = last_seen.saturating_sub(CACHED_ROUNDS);
            if threshold == 0 || threshold <= self.evicted_rounds[auth] {
                continue;
            }
            self.evicted_rounds[auth] = threshold;

            self.index[auth] = self.index[auth].split_off(&threshold);
            self.dag[auth] = self.dag[auth].split_off(&threshold);

            let split_ref = BlockReference {
                authority: auth as AuthorityIndex,
                round: threshold,
                digest: BlockDigest::default(),
            };
            self.data_availability[auth] = self.data_availability[auth].split_off(&split_ref);
        }
        let min_evicted = self.min_evicted_round();
        self.round_version.retain(|&r, _| r >= min_evicted);
    }

    pub fn add_block(
        &mut self,
        block: Data<VerifiedBlock>,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        let reference = block.reference();
        let auth = reference.authority as usize;
        self.highest_round = max(self.highest_round, reference.round());

        self.add_own_index(reference, authority_index_start, authority_index_end);
        self.update_last_seen_by_authority(reference);

        let map = self.index[auth].entry(reference.round()).or_default();
        map.insert(reference.digest, block.clone());

        *self.round_version.entry(reference.round()).or_insert(0) += 1;
        self.update_dag(
            *reference,
            block.block_references().clone(),
            block.acknowledgments(),
        );
        self.update_data_availability(&block);
    }

    fn dag_get(&self, r: &BlockReference) -> Option<&(Vec<BlockReference>, AuthorityBitmask)> {
        self.dag[r.authority as usize].get(&r.round)?.get(&r.digest)
    }

    fn dag_get_mut(
        &mut self,
        r: &BlockReference,
    ) -> Option<&mut (Vec<BlockReference>, AuthorityBitmask)> {
        self.dag[r.authority as usize]
            .get_mut(&r.round)?
            .get_mut(&r.digest)
    }

    fn dag_contains(&self, r: &BlockReference) -> bool {
        self.dag_get(r).is_some()
    }

    fn dag_insert(&mut self, r: BlockReference, val: (Vec<BlockReference>, AuthorityBitmask)) {
        self.dag[r.authority as usize]
            .entry(r.round)
            .or_default()
            .insert(r.digest, val);
    }

    fn reset_peer_known_by_after_round(&mut self, peer: AuthorityIndex, round: RoundNumber) {
        let bit = !(1u128 << peer);
        for auth_dag in self.dag.iter_mut() {
            for (_, entries) in auth_dag.range_mut((round.saturating_add(1))..) {
                for (_, (_, known_by)) in entries.iter_mut() {
                    *known_by &= bit;
                }
            }
        }
    }

    /// Insert a block into the DAG and propagate "known-by" bits along the
    /// causal history.
    ///
    /// For StarfishS, `known_by` is propagated starting from `ack_refs`
    /// (acknowledgment references) rather than `block_reference` itself.
    /// Acknowledgment references prove data availability, whereas block
    /// references only prove header knowledge.
    pub fn update_dag(
        &mut self,
        block_reference: BlockReference,
        parents: Vec<BlockReference>,
        ack_refs: Vec<BlockReference>,
    ) {
        if block_reference.round == 0 {
            return;
        }
        if self.dag_contains(&block_reference) {
            return;
        }
        let known_by = (1u128 << block_reference.authority) | (1u128 << self.authority);
        self.dag_insert(block_reference, (parents, known_by));

        let authority = block_reference.authority;

        // For StarfishS: propagate known_by starting from acknowledged blocks
        // (which prove data availability), not from the block itself (which
        // only proves header knowledge via block_references).
        let seeds = match self.consensus_protocol {
            ConsensusProtocol::StarfishS => ack_refs,
            _ => vec![block_reference],
        };

        for seed in seeds {
            let mut buffer = vec![seed];
            while let Some(r) = buffer.pop() {
                let Some((parents, _)) = self.dag_get(&r).cloned() else {
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
    }

    pub fn update_data_availability(&mut self, block: &VerifiedBlock) {
        let r = block.reference();
        let auth = r.authority as usize;
        if block.transactions().is_some() && !self.data_availability[auth].contains(r) {
            self.data_availability[auth].insert(*r);
            if let Some(pending_acknowledgment) = self.pending_acknowledgment.as_mut() {
                pending_acknowledgment.push(*r);
            }
        }
    }

    pub fn get_pending_acknowledgment(&mut self, round_number: RoundNumber) -> Vec<BlockReference> {
        let Some(pending_acknowledgment) = self.pending_acknowledgment.as_mut() else {
            return Vec::new();
        };
        let (to_return, to_keep): (Vec<_>, Vec<_>) = pending_acknowledgment
            .drain(..)
            .partition(|x| x.round <= round_number);
        *pending_acknowledgment = to_keep;
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
    ) -> Vec<(Data<VerifiedBlock>, RoundNumber)> {
        let peer_bit = 1u128 << peer;
        let mut candidates: Vec<(BlockReference, RoundNumber)> = self
            .dag
            .iter()
            .enumerate()
            .flat_map(|(auth_idx, auth_dag)| {
                auth_dag.iter().flat_map(move |(round, entries)| {
                    entries.iter().map(move |(digest, (_, known_by))| {
                        (
                            BlockReference {
                                authority: auth_idx as AuthorityIndex,
                                round: *round,
                                digest: *digest,
                            },
                            *known_by,
                        )
                    })
                })
            })
            .filter(|(r, known_by)| known_by & peer_bit == 0 && !sent.contains(r) && filter(r))
            .map(|(r, _)| (r, r.round))
            .collect();
        candidates.sort_by_key(|(_, round)| *round);
        candidates.truncate(limit);
        candidates
            .into_iter()
            .map(|(r, round)| {
                let block = self
                    .get_block(r)
                    .unwrap_or_else(|| panic!("Block index corrupted, not found: {r}"));
                (block, round)
            })
            .collect()
    }

    fn into_sorted_blocks(
        mut blocks: Vec<(Data<VerifiedBlock>, RoundNumber)>,
    ) -> Vec<Data<VerifiedBlock>> {
        blocks.sort_by_key(|x| x.1);
        blocks.into_iter().map(|x| x.0).collect()
    }

    pub fn get_unsent_own_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_own_block_size: usize,
    ) -> Vec<Data<VerifiedBlock>> {
        let auth = self.authority;
        Self::into_sorted_blocks(self.collect_unsent_blocks(
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
    ) -> Vec<Data<VerifiedBlock>> {
        let auth = self.authority;
        let max = max_round.unwrap_or(RoundNumber::MAX);
        Self::into_sorted_blocks(self.collect_unsent_blocks(
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
    ) -> Vec<Data<VerifiedBlock>> {
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
        Self::into_sorted_blocks(own.into_iter().chain(other).collect())
    }

    pub fn get_unsent_past_cone(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        block_reference: BlockReference,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
    ) -> Vec<Data<VerifiedBlock>> {
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
        Self::into_sorted_blocks(own.into_iter().chain(other).collect())
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
    pub block: Data<VerifiedBlock>,
    pub authority_index_start: AuthorityIndex,
    pub authority_index_end: AuthorityIndex,
}

impl OwnBlockData {
    pub fn new(
        block: Data<VerifiedBlock>,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) -> Self {
        Self {
            block,
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

#[cfg(test)]
mod tests {
    use super::ConsensusProtocol;

    #[test]
    fn acknowledgments_are_only_enabled_for_starfish_variants() {
        assert!(!ConsensusProtocol::Mysticeti.supports_acknowledgments());
        assert!(ConsensusProtocol::CordialMiners.supports_acknowledgments());
        assert!(ConsensusProtocol::StarfishPull.supports_acknowledgments());
        assert!(ConsensusProtocol::Starfish.supports_acknowledgments());
        assert!(ConsensusProtocol::StarfishS.supports_acknowledgments());
    }
}
