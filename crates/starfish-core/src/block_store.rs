// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    cmp::max,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::Instant,
};

use minibytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::committee::{QuorumThreshold, StakeAggregator};
use crate::rocks_store::RocksStore;
use crate::types::{CachedStatementBlock, VerifiedStatementBlock};
use crate::{
    committee::Committee,
    consensus::linearizer::{CommittedSubDag, MAX_TRAVERSAL_DEPTH},
    data::Data,
    metrics::{Metrics, UtilizationTimerExt},
    state::{RecoveredState, RecoveredStateBuilder},
    types::{AuthorityIndex, BlockDigest, BlockReference, RoundNumber},
};

/// Bitmask tracking which authorities know about a block. Supports up to 128 authorities.
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
pub struct BlockStore {
    inner: Arc<RwLock<BlockStoreInner>>,
    rocks_store: Arc<RocksStore>,
    metrics: Arc<Metrics>,
    pub(crate) consensus_protocol: ConsensusProtocol,
    pub(crate) committee_size: usize,
    pub(crate) byzantine_strategy: Option<ByzantineStrategy>,
}

#[derive(Default)]
struct BlockStoreInner {
    index: BTreeMap<RoundNumber, HashMap<(AuthorityIndex, BlockDigest), IndexEntry>>,
    // Store the blocks for which we have transaction data
    data_availability: BTreeSet<BlockReference>,
    // Blocks for which has available transactions data and didn't yet acknowledge.
    pending_acknowledgment: Vec<BlockReference>,
    // Store the blocks until the transaction data gets recoverable
    cached_blocks: HashMap<BlockReference, (CachedStatementBlock, usize)>,
    // Byzantine nodes will create different blocks intended for the different validators
    own_blocks: BTreeMap<(RoundNumber, AuthorityIndex), BlockDigest>,
    highest_round: RoundNumber,
    authority: AuthorityIndex,
    info_length: usize,
    committee_size: usize,
    last_seen_by_authority: Vec<RoundNumber>,
    last_own_block: Option<BlockReference>,
    // for each authority, the set of blocks they don't know about
    not_known_by_authority: Vec<BTreeSet<BlockReference>>,
    // this dag structure store for each block its predecessors and who knows the block
    dag: BTreeMap<RoundNumber, HashMap<(AuthorityIndex, BlockDigest), (Vec<BlockReference>, AuthorityBitmask)>>,
    // per-authority highest committed round, used as dag eviction threshold
    last_committed_round: Vec<RoundNumber>,
    // committed subdag which contains blocks with at least one unavailable transaction data
    pending_not_available: Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)>,
}

type IndexEntry = (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>);

impl BlockStore {
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
        let not_known_by_authority = committee.authorities().map(|_| BTreeSet::new()).collect();
        let last_committed_round = committee.authorities().map(|_| 0).collect();
        let mut inner = BlockStoreInner {
            authority,
            last_seen_by_authority,
            not_known_by_authority,
            last_committed_round,
            info_length: committee.info_length(),
            committee_size: committee.len(),
            ..Default::default()
        };
        let mut builder = RecoveredStateBuilder::new();
        let replay_started = Instant::now();
        let mut block_count = 0u64;
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
            }

            current_round += 1;
        }

        metrics.block_store_entries.inc_by(block_count);
        tracing::info!(
            "RocksDB replay completed in {:?}, recovered {} blocks",
            replay_started.elapsed(),
            block_count
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
        let block_store = Self {
            rocks_store: rocks_store.clone(),
            byzantine_strategy,
            inner: Arc::new(RwLock::new(inner)),
            metrics,
            consensus_protocol,
            committee_size: committee.len(),
        };
        builder.build(rocks_store, block_store)
    }

    pub fn get_dag_sorted(
        &self,
    ) -> Vec<(BlockReference, Vec<BlockReference>, AuthorityBitmask)> {
        let inner = self.inner.read();
        // BTreeMap is already sorted by round
        inner
            .dag
            .iter()
            .flat_map(|(round, map)| {
                map.iter().map(move |((authority, digest), (parents, known_by))| {
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

    pub fn get_unknown_by_authority(
        &self,
        authority_index: AuthorityIndex,
    ) -> BTreeSet<BlockReference> {
        self.inner.read().not_known_by_authority[authority_index as usize].clone()
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
        self.metrics.block_store_entries.inc();

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

    // Insert own blocks is primarily needed to capture Byzantine behavior with equivocating blocks
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
        if let Some(blocks) = self.inner.read().get_block(reference) {
            return Some(blocks.0);
        }
        // Not in memory — fall back to RocksDB
        self.rocks_store
            .get_block(&reference)
            .expect("Failed to read from RocksDB")
    }

    pub fn get_transmission_block(
        &self,
        reference: BlockReference,
    ) -> Option<Data<VerifiedStatementBlock>> {
        if let Some(blocks) = self.inner.read().get_block(reference) {
            return Some(blocks.1);
        }
        // Not in memory — fall back to RocksDB
        let own_id = self.inner.read().authority;
        self.rocks_store
            .get_block(&reference)
            .expect("Failed to read from RocksDB")
            .map(|storage_block| {
                let transmission_block = storage_block.from_storage_to_transmission(own_id);
                Data::new(transmission_block)
            })
    }

    pub fn updated_unknown_by_others(&self, block_reference: BlockReference) {
        self.inner
            .write()
            .updated_unknown_by_others(block_reference);
    }

    pub fn get_pending_acknowledgment(&self, round_number: RoundNumber) -> Vec<BlockReference> {
        self.inner.write().get_pending_acknowledgment(round_number)
    }

    // This function should be called when we send a block to a certain authority
    pub fn update_known_by_authority(
        &self,
        block_reference: BlockReference,
        authority: AuthorityIndex,
    ) {
        self.inner
            .write()
            .update_known_by_authority(block_reference, authority);
    }

    pub fn get_blocks_by_round(&self, round: RoundNumber) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self.inner.read().get_blocks_by_round(round);
        Self::extract_storage_blocks(entries)
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
        let inner = self.inner.read();
        let Some(blocks) = inner.index.get(&round) else {
            return false;
        };
        blocks
            .keys()
            .any(|(block_authority, _)| *block_authority == authority)
    }

    pub fn all_blocks_exists_at_authority_round(
        &self,
        authorities: &[AuthorityIndex],
        round: RoundNumber,
    ) -> bool {
        let inner = self.inner.read();
        let Some(blocks) = inner.index.get(&round) else {
            return false;
        };
        authorities.iter().all(|authority| {
            blocks
                .keys()
                .any(|(block_authority, _)| block_authority == authority)
        })
    }

    /// Check if a quorum of blocks at `round` include the leader from `leader_round` in their references.
    /// Only checks cached (in-memory) blocks for performance; unloaded blocks are skipped.
    pub fn has_votes_quorum_at_round(
        &self,
        round: RoundNumber,
        leader: AuthorityIndex,
        leader_round: RoundNumber,
        committee: &Committee,
    ) -> bool {
        let inner = self.inner.read();
        let Some(blocks) = inner.index.get(&round) else {
            return false;
        };
        let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
        for ((authority, _), (storage_block, _)) in blocks {
            let votes_for_leader = storage_block
                .includes()
                .iter()
                .any(|r| r.authority == leader && r.round == leader_round);
            if votes_for_leader && aggregator.add(*authority, committee) {
                return true;
            }
        }
        false
    }

    /// Check if a quorum of blocks at `round` have `strong_vote == Some(true)`.
    /// Only checks cached (in-memory) blocks for performance; unloaded blocks are skipped.
    pub fn has_strong_votes_quorum_at_round(
        &self,
        round: RoundNumber,
        committee: &Committee,
    ) -> bool {
        let inner = self.inner.read();
        let Some(blocks) = inner.index.get(&round) else {
            return false;
        };
        let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
        for ((authority, _), (storage_block, _)) in blocks {
            if storage_block.strong_vote() == Some(true)
                && aggregator.add(*authority, committee)
            {
                return true;
            }
        }
        false
    }

    pub fn block_exists(&self, reference: BlockReference) -> bool {
        self.inner.read().block_exists(reference)
    }

    pub fn is_data_available(&self, reference: &BlockReference) -> bool {
        self.inner.read().is_data_available(reference)
    }

    pub fn shard_count(&self, block_reference: &BlockReference) -> usize {
        self.inner.read().shard_count(block_reference)
    }

    pub fn contains_new_shard_or_header(&self, block: &VerifiedStatementBlock) -> bool {
        self.inner.read().contains_new_shard_or_header(block)
    }

    pub fn ready_to_reconstruct(
        &self,
        block: &VerifiedStatementBlock,
    ) -> (bool, Option<CachedStatementBlock>) {
        self.inner.read().ready_to_reconstruct(block)
    }

    pub fn update_with_new_shard(&self, block: &VerifiedStatementBlock) {
        self.inner.write().update_with_new_shard(block);
    }

    pub fn is_sufficient_shards(&self, block_reference: &BlockReference) -> bool {
        self.inner.read().is_sufficient_shards(block_reference)
    }

    pub fn get_cached_block(&self, block_reference: &BlockReference) -> CachedStatementBlock {
        self.inner.read().get_cached_block(block_reference)
    }
    pub fn len_expensive(&self) -> usize {
        let inner = self.inner.read();
        inner.index.values().map(HashMap::len).sum()
    }

    pub fn highest_round(&self) -> RoundNumber {
        self.inner.read().highest_round
    }

    pub fn update_committed_rounds(&self, committed_blocks: &[Data<VerifiedStatementBlock>]) {
        let mut inner = self.inner.write();
        for block in committed_blocks {
            let authority = block.author() as usize;
            if let Some(slot) = inner.last_committed_round.get_mut(authority) {
                *slot = (*slot).max(block.round());
            }
        }
    }

    pub fn cleanup(&self, threshold_round: RoundNumber) {
        if threshold_round == 0 {
            return;
        }
        let _timer = self.metrics.block_store_cleanup_util.utilization_timer();

        self.inner.write().evict_below_round();
    }

    pub fn get_own_transmission_blocks(
        &self,
        to_whom_authority_index: AuthorityIndex,
        from_excluded: RoundNumber,
        limit: usize,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries =
            self.inner
                .read()
                .get_own_blocks(to_whom_authority_index, from_excluded, limit);
        Self::extract_transmission_blocks(entries)
    }

    pub fn get_unknown_own_blocks(
        &self,
        to_whom_authority_index: AuthorityIndex,
        batch_own_block_size: usize,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self
            .inner
            .read()
            .get_unknown_own_blocks(to_whom_authority_index, batch_own_block_size);

        Self::extract_transmission_blocks(entries)
    }

    pub fn get_unknown_other_blocks(
        &self,
        to_whom_authority_index: AuthorityIndex,
        batch_other_block_size: usize,
        max_round_own_blocks: Option<RoundNumber>,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self.inner.read().get_unknown_other_blocks(
            to_whom_authority_index,
            batch_other_block_size,
            max_round_own_blocks,
        );

        Self::extract_transmission_blocks(entries)
    }

    pub fn get_unknown_causal_history(
        &self,
        to_whom_authority_index: AuthorityIndex,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
        authorities_with_missing_blocks: HashSet<AuthorityIndex>,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self.inner.read().get_unknown_causal_history(
            to_whom_authority_index,
            batch_own_block_size,
            batch_other_block_size,
            authorities_with_missing_blocks,
        );

        Self::extract_transmission_blocks(entries)
    }

    pub fn get_unknown_past_cone(
        &self,
        to_whom_authority_index: AuthorityIndex,
        block_reference: BlockReference,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self.inner.read().get_unknown_past_cone(
            to_whom_authority_index,
            block_reference,
            batch_own_block_size,
            batch_other_block_size,
        );

        Self::extract_transmission_blocks(entries)
    }

    pub fn last_seen_by_authority(&self, authority: AuthorityIndex) -> RoundNumber {
        self.inner.read().last_seen_by_authority(authority)
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
        let mut parents = HashSet::from([later_block.clone()]);
        for _round_number in (earlier_block.round()..later_block.round()).rev() {
            // Collect parents from the current set of blocks.
            parents = parents
                .iter()
                .flat_map(|block| block.includes()) // Get included blocks.
                .map(|block_reference| {
                    self.get_storage_block(*block_reference)
                        .expect("Block should be in Block Store")
                })
                .filter(|included_block| included_block.round() >= earlier_block.round()) // Filter by round.
                .collect();
        }
        parents.contains(earlier_block)
    }
}

impl BlockStoreInner {
    pub fn block_exists(&self, reference: BlockReference) -> bool {
        let Some(blocks) = self.index.get(&reference.round) else {
            return false;
        };
        blocks.contains_key(&(reference.authority, reference.digest))
    }

    pub fn is_data_available(&self, reference: &BlockReference) -> bool {
        self.data_availability.contains(reference)
    }

    pub fn shard_count(&self, block_reference: &BlockReference) -> usize {
        if self.data_availability.contains(block_reference) {
            return self.committee_size;
        }
        self.cached_blocks.get(block_reference).map_or(0, |x| x.1)
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

    pub fn contains_new_shard_or_header(&self, block: &VerifiedStatementBlock) -> bool {
        let block_reference = block.reference();
        if self.data_availability.contains(block_reference) {
            return false;
        }
        if block.statements().is_some() {
            return true;
        }
        let Some(cached) = self.cached_blocks.get(block_reference) else {
            // Block is not in the cache yet
            return true;
        };
        // The header is already cached; we need a new shard to make progress
        let Some((_, shard_index)) = block.encoded_shard().as_ref() else {
            return false;
        };
        cached.0.encoded_statements()[*shard_index].is_none()
    }

    // Check whether the block can be reconstructed with a new shard
    pub fn ready_to_reconstruct(
        &self,
        block: &VerifiedStatementBlock,
    ) -> (bool, Option<CachedStatementBlock>) {
        let Some((_, shard_index)) = block.encoded_shard().as_ref() else {
            return (false, None);
        };
        let Some((cached_block, _)) = self.cached_blocks.get(block.reference()) else {
            return (false, None);
        };
        if cached_block.encoded_statements()[*shard_index].is_none() {
            let shard_count =
                1 + cached_block.encoded_statements().iter().filter(|s| s.is_some()).count();
            if shard_count >= self.info_length {
                return (true, Some(cached_block.clone()));
            }
        }
        (false, None)
    }

    pub fn update_with_new_shard(&mut self, block: &VerifiedStatementBlock) {
        if let Some(entry) = self.cached_blocks.get_mut(block.reference()) {
            let (cached_block, count) = entry;
            if let Some((encoded_shard, position)) = block.encoded_shard().clone() {
                if cached_block.encoded_statements()[position].is_none() {
                    cached_block.add_encoded_shard(position, encoded_shard);
                    *count += 1;
                    tracing::debug!("Updated cached block {:?}. Now shards {:?}", block, count);
                } else {
                    tracing::debug!(
                        "Not updated cached block {:?}. Still shards {:?}. Position {:?}",
                        block,
                        count,
                        position
                    );
                }
            }
        } else {
            tracing::debug!("Block {:?} is not cached", block);
        }
    }

    pub fn is_sufficient_shards(&self, block_reference: &BlockReference) -> bool {
        self.shard_count(block_reference) >= self.info_length
    }

    pub fn get_cached_block(&self, block_reference: &BlockReference) -> CachedStatementBlock {
        self.cached_blocks
            .get(block_reference)
            .expect("Cached block missing")
            .0
            .clone()
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
        self.index
            .get(&reference.round)?
            .get(&(reference.authority, reference.digest))
            .cloned()
    }

    pub fn evict_below_round(&mut self) {
        // Evict metadata below the min committed round across all authorities,
        // with a safety margin of 2 * MAX_TRAVERSAL_DEPTH
        let dag_threshold = self
            .last_committed_round
            .iter()
            .copied()
            .min()
            .unwrap_or(0)
            .saturating_sub(2 * MAX_TRAVERSAL_DEPTH);
        if dag_threshold > 0 {
            self.dag = self.dag.split_off(&dag_threshold);
            self.index = self.index.split_off(&dag_threshold);

            let split_ref = BlockReference {
                authority: 0,
                round: dag_threshold,
                digest: BlockDigest::default(),
            };
            for set in self.not_known_by_authority.iter_mut() {
                *set = set.split_off(&split_ref);
            }
            self.data_availability = self.data_availability.split_off(&split_ref);
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

        self.update_dag(*reference, blocks.0.includes().clone());
        self.update_data_availability_and_cached_blocks(&blocks.0);
    }

    pub fn updated_unknown_by_others(&mut self, block_reference: BlockReference) {
        for authority in 0..self.not_known_by_authority.len() {
            if authority == self.authority as usize
                || authority == block_reference.authority as usize
            {
                continue;
            }
            self.not_known_by_authority[authority].insert(block_reference);
        }
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

    /// Insert a block into the DAG and propagate "known-by" bits along the causal history.
    pub fn update_dag(&mut self, block_reference: BlockReference, parents: Vec<BlockReference>) {
        if block_reference.round == 0 {
            return;
        }
        if self.dag_contains(&block_reference) {
            return;
        }
        let known_by = (1u128 << block_reference.authority) | (1u128 << self.authority);
        self.dag_insert(block_reference, (parents, known_by));
        for authority in 0..self.not_known_by_authority.len() {
            if authority == self.authority as usize
                || authority == block_reference.authority as usize
            {
                continue;
            }
            self.not_known_by_authority[authority].insert(block_reference);
        }
        // traverse the DAG from block_reference and update the blocks known by block_reference.authority
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
                    self.not_known_by_authority[authority as usize].remove(&parent);
                    buffer.push(parent);
                }
            }
        }
    }

    pub fn update_data_availability_and_cached_blocks(&mut self, block: &VerifiedStatementBlock) {
        let count = usize::from(block.encoded_shard().is_some());

        if block.statements().is_some() {
            if !self.data_availability.contains(block.reference()) {
                self.data_availability.insert(*block.reference());
                self.pending_acknowledgment.push(*block.reference());
            }
            tracing::debug!("Remove cached block {:?}", block.reference());
            self.cached_blocks.remove(block.reference());
        } else if !self.data_availability.contains(block.reference()) {
            let cached_block = block.to_cached_block(self.committee_size);
            self.cached_blocks
                .insert(*block.reference(), (cached_block, count));
            tracing::debug!("Insert cached block {:?}", block.reference());
        } else {
            tracing::debug!("Block is already available {:?}", block.reference());
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

    pub fn update_known_by_authority(
        &mut self,
        block_reference: BlockReference,
        authority: AuthorityIndex,
    ) {
        self.not_known_by_authority[authority as usize].remove(&block_reference);
        if let Some((_, known_by)) = self.dag_get_mut(&block_reference) {
            *known_by |= 1u128 << authority;
        }
    }

    pub fn last_seen_by_authority(&self, authority: AuthorityIndex) -> RoundNumber {
        *self
            .last_seen_by_authority
            .get(authority as usize)
            .expect("last_seen_by_authority not found")
    }

    fn update_last_seen_by_authority(&mut self, reference: &BlockReference) {
        let last_seen = self
            .last_seen_by_authority
            .get_mut(reference.authority as usize)
            .expect("last_seen_by_authority not found");
        *last_seen = (*last_seen).max(reference.round());
    }

    pub fn get_own_blocks(
        &self,
        to_whom_index: AuthorityIndex,
        from_excluded: RoundNumber,
        limit: usize,
    ) -> Vec<IndexEntry> {
        self.own_blocks
            .range((from_excluded + 1, 0)..)

            .filter(|((_round, authority_index), _digest)| *authority_index == to_whom_index)
            .take(limit)
            .map(|((round, _authority_index), digest)| {
                let reference = BlockReference {
                    authority: self.authority,
                    round: *round,
                    digest: *digest,
                };
                self.get_block(reference)
                    .unwrap_or_else(|| panic!("Own block index corrupted, not found: {reference}"))
            })
            .collect()
    }

    /// Collect unknown blocks for a peer, filtered by predicate and limited in count.
    fn collect_unknown_blocks(
        &self,
        to_whom: AuthorityIndex,
        filter: impl Fn(&BlockReference) -> bool,
        limit: usize,
    ) -> Vec<(IndexEntry, RoundNumber)> {
        self.not_known_by_authority[to_whom as usize]
            .iter()
            .filter(|r| filter(r))
            .take(limit)
            .map(|r| {
                let entry = self
                    .get_block(*r)
                    .unwrap_or_else(|| panic!("Block index corrupted, not found: {r}"));
                (entry, r.round())
            })
            .collect()
    }

    fn into_sorted_entries(mut blocks: Vec<(IndexEntry, RoundNumber)>) -> Vec<IndexEntry> {
        blocks.sort_by_key(|x| x.1);
        blocks.into_iter().map(|x| x.0).collect()
    }

    pub fn get_unknown_own_blocks(
        &self,
        to_whom: AuthorityIndex,
        batch_own_block_size: usize,
    ) -> Vec<IndexEntry> {
        let auth = self.authority;
        Self::into_sorted_entries(self.collect_unknown_blocks(
            to_whom,
            |r| r.authority == auth,
            batch_own_block_size,
        ))
    }

    pub fn get_unknown_other_blocks(
        &self,
        to_whom: AuthorityIndex,
        batch_other_block_size: usize,
        max_round: Option<RoundNumber>,
    ) -> Vec<IndexEntry> {
        let auth = self.authority;
        let max = max_round.unwrap_or(RoundNumber::MAX);
        Self::into_sorted_entries(self.collect_unknown_blocks(
            to_whom,
            |r| r.authority != auth && r.round < max,
            batch_other_block_size,
        ))
    }

    pub fn get_unknown_causal_history(
        &self,
        to_whom: AuthorityIndex,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
        authorities_with_missing_blocks: HashSet<AuthorityIndex>,
    ) -> Vec<IndexEntry> {
        let auth = self.authority;
        let own =
            self.collect_unknown_blocks(to_whom, |r| r.authority == auth, batch_own_block_size);
        let max = own.iter().map(|x| x.1).max().unwrap_or(RoundNumber::MAX);
        let other = self.collect_unknown_blocks(
            to_whom,
            |r| authorities_with_missing_blocks.contains(&r.authority) && r.round < max,
            batch_other_block_size,
        );
        Self::into_sorted_entries(own.into_iter().chain(other).collect())
    }

    pub fn get_unknown_past_cone(
        &self,
        to_whom: AuthorityIndex,
        block_reference: BlockReference,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
    ) -> Vec<IndexEntry> {
        let auth = self.authority;
        let max = block_reference.round;
        let own = self.collect_unknown_blocks(
            to_whom,
            |r| r.authority == auth && r.round < max,
            batch_own_block_size,
        );
        let other = self.collect_unknown_blocks(
            to_whom,
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
            assert!(
                self.own_blocks
                    .insert((reference.round, authority_index), reference.digest)
                    .is_none(),
                "Duplicate own block at round {} for authority {}",
                reference.round,
                authority_index,
            );
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
