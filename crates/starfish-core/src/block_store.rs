// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use minibytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Instant,
};

use crate::committee::{QuorumThreshold, StakeAggregator};
use crate::rocks_store::RocksStore;
use crate::types::{CachedStatementBlock, VerifiedStatementBlock};
use crate::{
    committee::Committee,
    consensus::linearizer::CommittedSubDag,
    data::Data,
    metrics::{Metrics, UtilizationTimerExt},
    state::{RecoveredState, RecoveredStateBuilder},
    types::{AuthorityIndex, BlockDigest, BlockReference, RoundNumber},
};

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
    data_availability: HashSet<BlockReference>,
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
    // for each authority, the set of unknown blocks
    not_known_by_authority: Vec<HashSet<BlockReference>>,
    // this dag structure store for each block its predecessors and who knows the block
    dag: HashMap<BlockReference, (Vec<BlockReference>, HashSet<AuthorityIndex>)>,
    // committed subdag which contains blocks with at least one unavailable transaction data
    pending_not_available: Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)>,
}

#[derive(Clone, Debug)]
enum IndexEntry {
    // Block needs to be loaded from RocksDB
    Unloaded(BlockReference),
    // Block is currently in memory
    Loaded((Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)),
}

impl BlockStore {
    pub fn open(
        authority: AuthorityIndex,
        path: impl AsRef<Path>,
        metrics: Arc<Metrics>,
        committee: &Committee,
        byzantine_strategy: String,
        consensus: String,
    ) -> RecoveredState {
        let rocks_store = Arc::new(RocksStore::open(path).expect("Failed to open RocksDB"));
        let last_seen_by_authority = committee.authorities().map(|_| 0).collect();
        let not_known_by_authority = committee.authorities().map(|_| HashSet::new()).collect();
        let mut inner = BlockStoreInner {
            authority,
            last_seen_by_authority,
            not_known_by_authority,
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
                inner.add_unloaded(
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

    pub fn get_dag(
        &self,
    ) -> HashMap<BlockReference, (Vec<BlockReference>, HashSet<AuthorityIndex>)> {
        self.inner.read().dag.clone()
    }

    pub fn get_dag_sorted(
        &self,
    ) -> Vec<(BlockReference, Vec<BlockReference>, HashSet<AuthorityIndex>)> {
        let mut dag: Vec<(BlockReference, Vec<BlockReference>, HashSet<AuthorityIndex>)> = self
            .get_dag()
            .iter()
            .map(|(block_reference, refs_and_indices)| {
                (
                    *block_reference,
                    refs_and_indices.0.clone(),
                    refs_and_indices.1.clone(),
                )
            })
            .collect();

        dag.sort_by_key(|(block_reference, _, _)| block_reference.round());
        dag
    }

    pub fn get_own_authority_index(&self) -> AuthorityIndex {
        self.inner.read().authority
    }

    pub fn get_unknown_by_authority(
        &self,
        authority_index: AuthorityIndex,
    ) -> HashSet<BlockReference> {
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

        self.inner.write().add_loaded(
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
        let authority_index_start = 0 as AuthorityIndex;
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
        // First try to get from memory
        let entry = self.inner.read().get_block(reference);
        match entry {
            Some(IndexEntry::Loaded(blocks)) => Some(blocks.0),
            Some(IndexEntry::Unloaded(block_ref)) => {
                // If not in memory, get from RocksDB
                self.rocks_store
                    .get_block(&block_ref)
                    .expect("Failed to read from RocksDB")
            }
            None => None,
        }
    }

    pub fn get_transmission_block(
        &self,
        reference: BlockReference,
    ) -> Option<Data<VerifiedStatementBlock>> {
        // First try to get from memory
        let entry = self.inner.read().get_block(reference);
        match entry {
            Some(IndexEntry::Loaded(blocks)) => Some(blocks.1),
            Some(IndexEntry::Unloaded(block_ref)) => {
                // If not in memory, get from RocksDB and create transmission block
                let own_id = self.inner.read().authority;
                self.rocks_store
                    .get_block(&block_ref)
                    .expect("Failed to read from RocksDB")
                    .map(|storage_block| {
                        let transmission_block = storage_block.from_storage_to_transmission(own_id);
                        Data::new(transmission_block)
                    })
            }
            None => None,
        }
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
        self.read_index_storage_vec(entries)
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
        self.read_index_storage_vec(entries)
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
        for ((authority, _), entry) in blocks {
            if let IndexEntry::Loaded((storage_block, _)) = entry {
                if storage_block
                    .includes()
                    .iter()
                    .any(|r| r.authority == leader && r.round == leader_round)
                {
                    if aggregator.add(*authority, committee) {
                        return true;
                    }
                }
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
        for ((authority, _), entry) in blocks {
            if let IndexEntry::Loaded((storage_block, _)) = entry {
                if storage_block.strong_vote() == Some(true) {
                    if aggregator.add(*authority, committee) {
                        return true;
                    }
                }
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

    pub fn cleanup(&self, threshold_round: RoundNumber) {
        if threshold_round == 0 {
            return;
        }
        let _timer = self.metrics.block_store_cleanup_util.utilization_timer();

        // Only unload from RAM, keep everything in RocksDB
        let unloaded = self.inner.write().unload_below_round(threshold_round);
        self.metrics
            .block_store_unloaded_blocks
            .inc_by(unloaded as u64);
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
        self.read_index_transmission_vec(entries)
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

        self.read_index_transmission_vec(entries)
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

        self.read_index_transmission_vec(entries)
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

        self.read_index_transmission_vec(entries)
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

        self.read_index_transmission_vec(entries)
    }

    pub fn last_seen_by_authority(&self, authority: AuthorityIndex) -> RoundNumber {
        self.inner.read().last_seen_by_authority(authority)
    }

    pub fn last_own_block_ref(&self) -> Option<BlockReference> {
        self.inner.read().last_own_block()
    }

    fn read_index(
        &self,
        entry: IndexEntry,
    ) -> (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>) {
        let own_id = self.inner.read().authority;
        match entry {
            IndexEntry::Loaded(blocks) => blocks,
            IndexEntry::Unloaded(reference) => {
                self.metrics.block_store_loaded_blocks.inc();

                // Get from RocksDB
                let data_storage_block = self
                    .rocks_store
                    .get_block(&reference)
                    .expect("Failed to read from RocksDB")
                    .expect("Block not found in RocksDB");

                // Create transmission block
                let transmission_block = data_storage_block.from_storage_to_transmission(own_id);
                let data_transmission_block = Data::new(transmission_block);

                (data_storage_block, data_transmission_block)
            }
        }
    }

    fn read_index_storage_vec(
        &self,
        entries: Vec<IndexEntry>,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        entries
            .into_iter()
            .map(|pos| self.read_index(pos).0)
            .collect()
    }

    fn read_index_transmission_vec(
        &self,
        entries: Vec<IndexEntry>,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        entries
            .into_iter()
            .map(|pos| self.read_index(pos).1)
            .collect()
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
        // If the block is not in the cache
        if !self.cached_blocks.contains_key(block_reference) {
            return true;
        }
        // the header is in the cached block in this place
        // we need at least a shard to update
        if block.encoded_shard().is_none() {
            return false;
        }
        let (_, shard_index) = block
            .encoded_shard()
            .as_ref()
            .expect("It should be some because of the above check");
        let cached_block = &self
            .cached_blocks
            .get(block_reference)
            .expect("Cached block missing")
            .0;
        if cached_block.encoded_statements()[*shard_index].is_none() {
            return true;
        }
        false
    }

    // Chech whether the block can be reconstructed with a new shard
    pub fn ready_to_reconstruct(
        &self,
        block: &VerifiedStatementBlock,
    ) -> (bool, Option<CachedStatementBlock>) {
        if block.encoded_shard().is_none() || !self.cached_blocks.contains_key(block.reference()) {
            return (false, None);
        }
        let (_, shard_index) = block
            .encoded_shard()
            .as_ref()
            .expect("It should be some because of the above check");
        let cached_block = &self
            .cached_blocks
            .get(block.reference())
            .expect("Cached block missing")
            .0;
        if cached_block.encoded_statements()[*shard_index].is_none() {
            let shard_count = 1 + cached_block
                .encoded_statements()
                .iter()
                .filter(|s| s.is_some())
                .count();
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
        let count_shards = self.shard_count(block_reference);
        if count_shards >= self.info_length {
            return true;
        }
        false
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

    pub fn unload_below_round(&mut self, threshold_round: RoundNumber) -> usize {
        let mut unloaded = 0usize;

        // Keep the index entries but unload the actual block data from RAM
        for (round, map) in self.index.iter_mut() {
            if *round > threshold_round {
                continue;
            }

            // Only remove blocks from cache, keeping the references
            for ((authority, digest), entry) in map.iter_mut() {
                if let IndexEntry::Loaded(_block) = entry {
                    unloaded += 1;
                    // Convert to unloaded state with reference
                    *entry = IndexEntry::Unloaded(BlockReference {
                        round: *round,
                        authority: *authority,
                        digest: *digest,
                    });
                }
            }
        }

        tracing::debug!("Unloaded {unloaded} entries from block store cache");
        unloaded
    }

    pub fn add_unloaded(
        &mut self,
        data_storage_transmission_blocks: (
            Data<VerifiedStatementBlock>,
            Data<VerifiedStatementBlock>,
        ),
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        let reference = data_storage_transmission_blocks.0.reference();
        self.highest_round = max(self.highest_round, reference.round());

        let map = self.index.entry(reference.round()).or_default();
        map.insert(reference.author_digest(), IndexEntry::Unloaded(*reference));

        self.add_own_index(reference, authority_index_start, authority_index_end);
        self.update_last_seen_by_authority(reference);
        self.update_dag(
            *reference,
            data_storage_transmission_blocks.0.includes().clone(),
        );
        self.update_data_availability_and_cached_blocks(&data_storage_transmission_blocks.0);
    }

    pub fn add_loaded(
        &mut self,
        storage_and_transmission_blocks: (
            Data<VerifiedStatementBlock>,
            Data<VerifiedStatementBlock>,
        ),
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        let reference = storage_and_transmission_blocks.0.reference();
        self.highest_round = max(self.highest_round, reference.round());

        self.add_own_index(reference, authority_index_start, authority_index_end);
        self.update_last_seen_by_authority(reference);

        let map = self.index.entry(reference.round()).or_default();
        map.insert(
            reference.author_digest(),
            IndexEntry::Loaded(storage_and_transmission_blocks.clone()),
        );

        tracing::debug!(
            "Current index map in round {} is : {:?}",
            reference.round(),
            map
        );

        self.update_dag(
            *reference,
            storage_and_transmission_blocks.0.includes().clone(),
        );
        self.update_data_availability_and_cached_blocks(&storage_and_transmission_blocks.0);
    }
    // Update not known by authorities when the block gets recoverable after decoding
    // This will send the block to others
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

    // Upon updating the local DAG with a block, we know that the authority created this block is aware of the causal history
    // of the block, and we assume that others are not aware of this block
    pub fn update_dag(&mut self, block_reference: BlockReference, parents: Vec<BlockReference>) {
        if block_reference.round == 0 {
            return;
        }
        // don't update if it is already there
        if self.dag.contains_key(&block_reference) {
            return;
        }
        // update information about block_reference
        self.dag.insert(
            block_reference,
            (
                parents,
                vec![block_reference.authority, self.authority]
                    .into_iter()
                    .collect::<HashSet<_>>(),
            ),
        );
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
            let (parents, _) = self.dag.get(&block_reference).unwrap().clone();
            for parent in parents {
                if parent.round == 0 {
                    continue;
                }
                let (_, known_by) = self.dag.get_mut(&parent).unwrap();
                if known_by.insert(authority) {
                    self.not_known_by_authority[authority as usize].remove(&parent);
                    buffer.push(parent);
                }
            }
        }
    }

    pub fn update_data_availability_and_cached_blocks(&mut self, block: &VerifiedStatementBlock) {
        let count = if block.encoded_shard().is_some() {
            1
        } else {
            0
        };

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
        // Partition the vector into two parts: one to keep, and one to return
        let (to_return, to_keep): (Vec<_>, Vec<_>) = self
            .pending_acknowledgment
            .drain(..)
            .partition(|x| x.round <= round_number);

        // Replace the original vector with the elements to keep
        self.pending_acknowledgment = to_keep;

        // Return the filtered elements
        to_return
    }

    pub fn update_known_by_authority(
        &mut self,
        block_reference: BlockReference,
        authority: AuthorityIndex,
    ) {
        self.not_known_by_authority[authority as usize].remove(&block_reference);
        let (_, known_by) = self.dag.get_mut(&block_reference).unwrap();
        known_by.insert(authority);
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
        if reference.round() > *last_seen {
            *last_seen = reference.round();
        }
    }

    // Function returns which own blocks are intended to which authority
    pub fn get_own_blocks(
        &self,
        to_whom_index: AuthorityIndex,
        from_excluded: RoundNumber,
        limit: usize,
    ) -> Vec<IndexEntry> {
        self.own_blocks
            .range((from_excluded + 1, 0 as AuthorityIndex)..)
            .filter(|((_round, authority_index), _digest)| *authority_index == to_whom_index)
            .take(limit)
            .map(|((round, _authority_index), digest)| {
                let reference = BlockReference {
                    authority: self.authority,
                    round: *round,
                    digest: *digest,
                };
                if let Some(block) = self.get_block(reference) {
                    block
                } else {
                    panic!("Own block index corrupted, not found: {reference}");
                }
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
            assert!(self
                .own_blocks
                .insert(
                    (reference.round, authority_index as AuthorityIndex),
                    reference.digest
                )
                .is_none());
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
