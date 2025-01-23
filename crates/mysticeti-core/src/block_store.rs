// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashSet};
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
    io::IoSlice,
    sync::Arc,
    time::Instant,
};

use minibytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{
    committee::Committee,
    consensus::linearizer::CommittedSubDag,
    data::Data,
    metrics::{Metrics, UtilizationTimerExt},
    state::{RecoveredState, RecoveredStateBuilder},
    types::{
        AuthorityIndex, BlockDigest, BlockReference, RoundNumber,
    },
    wal::{Tag, WalPosition, WalReader, WalWriter},
};
use crate::committee::{QuorumThreshold, StakeAggregator};
use crate::consensus::WAVE_LENGTH;
use crate::types::{CachedStatementBlock, VerifiedStatementBlock};

#[allow(unused)]
#[derive(Clone, Debug)]
pub enum ByzantineStrategy {
    TimeoutLeader,                 // Adversary waits timeout before sending their leader blocks
    EquivocatingChains,                  // Equivocation attack: N-1 equivocations per round
    EquivocatingTwoChains,          // Skipping rule equivocation: 2 equivocations split across validators
    LeaderWithholding,             // Withholding leader blocks (sent to f+1+c validators)
    ChainBomb,                       // Fork bomb: withhold a chain of blocks and release it all at once
    EquivocatingChainsBomb,          // Equivocation fork bomb: send different chains to each validator
}
#[derive(Clone)]
pub struct BlockStore {
    inner: Arc<RwLock<BlockStoreInner>>,
    block_wal_reader: Arc<WalReader>,
    metrics: Arc<Metrics>,
    pub(crate) starfish: usize,
    pub(crate) committee_size: usize,
    pub(crate) byzantine_strategy: Option<ByzantineStrategy>,
}

// VoteForLeader says whether a block is voting for a leader in previous round. It is Some when voting.
pub(crate) type VoteForLeader = Option<BlockReference>;

// CertificateForLeader says whether a block is certificate for a leader in two rounds before. It is Some when certificate.
pub(crate) type CertificateForLeader = Option<BlockReference>;

// CertifiedStake collects stake of certificate if a given block is a leader
pub(crate) type CertifiedStake = Option<StakeAggregator<QuorumThreshold>>;

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
    committee: Committee,
    last_seen_by_authority: Vec<RoundNumber>,
    last_own_block: Option<BlockReference>,
    // for each authority, the set of unknown blocks
    not_known_by_authority: Vec<HashSet<BlockReference>>,
    // this dag structure store for each block (a,b,c,d) a: its predecessors, b: who knows the block
    // c: is a vote for the leader in the previous round, d: if a leader, StakeAggregator for certificates
    dag: BTreeMap<RoundNumber, HashMap<(AuthorityIndex, BlockDigest), (Vec<BlockReference>, HashSet<AuthorityIndex>, VoteForLeader, CertificateForLeader, CertifiedStake)>>,
    // committed subdag which contains blocks with at least one unavailable transaction data
    pending_not_available: Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)>,
    directly_committed_leaders: HashSet<BlockReference>,
}

pub trait BlockWriter {
    fn insert_block(&mut self, block: (Data<VerifiedStatementBlock>,Data<VerifiedStatementBlock>)) -> WalPosition;

    fn insert_own_block(
        &mut self,
        block: &OwnBlockData,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    );
}

#[derive(Clone)]
enum IndexEntry {
    WalPosition(WalPosition),
    //the first entry in the pair in the block for storage (may contain statements)
    //the second entry is the block for transmission (no statements and possibly encoded shard)
    Loaded(WalPosition, (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)),
}

impl BlockStore {
    pub fn open(
        authority: AuthorityIndex,
        block_wal_reader: Arc<WalReader>,
        wal_writer: &WalWriter,
        metrics: Arc<Metrics>,
        committee: &Committee,
        byzantine_strategy: String,
        starfish: usize,
    ) -> RecoveredState {
        let last_seen_by_authority = committee.authorities().map(|_| 0).collect();
        let not_known_by_authority = committee.authorities().map(|_| HashSet::new()).collect();
        let mut inner = BlockStoreInner {
            authority,
            last_seen_by_authority,
            not_known_by_authority,
            info_length: committee.info_length(),
            committee_size: committee.len(),
            committee: committee.clone(),
            ..Default::default()
        };
        let mut builder = RecoveredStateBuilder::new();
        let mut replay_started: Option<Instant> = None;
        let mut block_count = 0u64;
        for (pos, (tag, data)) in block_wal_reader.iter_until(wal_writer) {
            if replay_started.is_none() {
                replay_started = Some(Instant::now());
                tracing::info!("Wal is not empty, starting replay");
            }
            let block = match tag {
                WAL_ENTRY_BLOCK => {
                    let data_storage_block: Data<VerifiedStatementBlock> = Data::from_bytes(data)
                        .expect("Failed to deserialize data from wal");
                    let transmission_block = data_storage_block.from_storage_to_transmission(authority);
                    let data_transmission_block = Data::new(transmission_block);
                    let data_storage_transmission_blocks = (data_storage_block,data_transmission_block);
                    builder.block(pos, data_storage_transmission_blocks.clone());
                    data_storage_transmission_blocks
                }
                WAL_ENTRY_PAYLOAD => {
                    builder.payload(pos, data);
                    continue;
                }
                WAL_ENTRY_OWN_BLOCK => {
                    let (own_block_data, own_storage_transmission_blocks) = OwnBlockData::from_bytes(data)
                        .expect("Failed to deserialized own block data from wal");
                    builder.own_block(own_block_data);
                    own_storage_transmission_blocks
                }
                WAL_ENTRY_STATE => {
                    builder.state(data);
                    continue;
                }
                WAL_ENTRY_COMMIT => {
                    let (commit_data, state) = bincode::deserialize(&data)
                        .expect("Failed to deserialized commit data from wal");
                    builder.commit_data(commit_data, state);
                    continue;
                }
                _ => panic!("Unknown wal tag {tag} at position {pos}"),
            };
            // todo - we want to keep some last blocks in the cache
            block_count += 1;
            inner.add_unloaded(block, pos, 0, committee.len() as AuthorityIndex);
        }
        metrics.block_store_entries.inc_by(block_count);
        if let Some(replay_started) = replay_started {
            tracing::info!("Wal replay completed in {:?}", replay_started.elapsed());
        } else {
            tracing::info!("Wal is empty, will start from genesis");
        }
        let byzantine_strategy = match byzantine_strategy.as_str() {
            "timeout-leader" => Some(ByzantineStrategy::TimeoutLeader),
            "leader-withholding" => Some(ByzantineStrategy::LeaderWithholding),
            "equivocating-chains" => Some(ByzantineStrategy::EquivocatingChains),
            "equivocating-two-chains" => Some(ByzantineStrategy::EquivocatingTwoChains),
            "chain-bomb" => Some(ByzantineStrategy::ChainBomb),
            "equivocating-chains-bomb" => Some(ByzantineStrategy::EquivocatingChainsBomb),
            _ => None, // Default to honest behavior
        };
        if starfish == 1 {
            tracing::info!("Starting Starfish mixed push-pull protocol");
        } else if starfish == 2 {
            tracing::info!("Starting Starfish push protocol");
        } else {
            tracing::info!("Starting Mysticeti protocol");
        }
        let this = Self {
            block_wal_reader,
            byzantine_strategy,
            inner: Arc::new(RwLock::new(inner)),
            metrics,
            starfish,
            committee_size: committee.len(),
        };
        builder.build(this)
    }

    pub fn get_dag(
        &self,
    ) -> BTreeMap<RoundNumber, HashMap<(AuthorityIndex, BlockDigest), (Vec<BlockReference>, HashSet<AuthorityIndex>, VoteForLeader, CertificateForLeader, CertifiedStake)>> {
        self.inner.read().dag.clone()
    }

    pub fn get_dag_between_rounds(
        &self,
        lower_round: RoundNumber,
        upper_round: RoundNumber,
    ) -> BTreeMap<RoundNumber, HashMap<(AuthorityIndex, BlockDigest), (Vec<BlockReference>, HashSet<AuthorityIndex>, VoteForLeader, CertificateForLeader, CertifiedStake)>> {
        self.inner.read().dag
            .range(lower_round..=upper_round)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn get_directly_committed_leaders(&self) -> HashSet<BlockReference> {
        self.inner.read().directly_committed_leaders.clone()
    }

    pub fn get_dag_sorted(&self) -> Vec<(BlockReference, Vec<BlockReference>, HashSet<AuthorityIndex>)> {
        self.get_dag()
            .iter()
            .flat_map(|(round, hashmap)| {
                hashmap.iter().map(|((authority, digest), value)| {
                    (
                        BlockReference {
                            authority: authority.clone(),
                            round: round.clone(),
                            digest: digest.clone(),
                        },
                        value.0.clone(),
                        value.1.clone()
                    )
                }).collect::<Vec<_>>()
            })
            .collect()
    }

    pub fn get_own_authority_index(&self) -> AuthorityIndex {
        self.inner.read().authority
    }

    pub fn get_unknown_by_authority(&self, authority_index: AuthorityIndex) -> HashSet<BlockReference> {
        self.inner.read().not_known_by_authority[authority_index as usize].clone()
    }

    pub fn read_pending_unavailable(&self) -> Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)>{
        self.inner.read().read_pending_unavailable()
    }

    pub fn update_pending_unavailable(&self, pending: Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)>) {
        self.inner.write().update_pending_unavailable(pending);
    }

    pub fn insert_block(
        &self,
        storage_and_transmission_blocks: (Data<VerifiedStatementBlock>,Data<VerifiedStatementBlock>),
        position: WalPosition,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        self.metrics.block_store_entries.inc();
        self.inner
            .write()
            .add_loaded(position, storage_and_transmission_blocks, authority_index_start, authority_index_end);
    }

    pub fn get_storage_block(&self, reference: BlockReference) -> Option<Data<VerifiedStatementBlock>> {
        let entry = self.inner.read().get_block(reference);
        // todo - consider adding loaded entries back to cache
        entry.map(|pos| self.read_index(pos).0)
    }

    pub fn get_transmission_block(&self, reference: BlockReference) -> Option<Data<VerifiedStatementBlock>> {
        let entry = self.inner.read().get_block(reference);
        // todo - consider adding loaded entries back to cache
        entry.map(|pos| self.read_index(pos).1)
    }


    pub fn updated_unknown_by_others(&self, block_reference: BlockReference) {
        self.inner.write().updated_unknown_by_others(block_reference);
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

    pub fn ready_to_reconstruct(&self, block: &VerifiedStatementBlock) -> (bool, Option<CachedStatementBlock>) {
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
        let unloaded = self.inner.write().unload_below_round(threshold_round);
        self.metrics
            .block_store_unloaded_blocks
            .inc_by(unloaded as u64);
        let retained_maps = self.block_wal_reader.cleanup();
        self.metrics.wal_mappings.set(retained_maps as i64);
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
            .get_unknown_own_blocks(to_whom_authority_index, batch_own_block_size,
            );
        let data_transmission_blocks = self.read_index_transmission_vec(entries);
        data_transmission_blocks
    }

    pub fn get_unknown_other_blocks(
        &self,
        to_whom_authority_index: AuthorityIndex,
        batch_other_block_size: usize,
        max_round_own_blocks: Option<RoundNumber>,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self
            .inner
            .read()
            .get_unknown_other_blocks(to_whom_authority_index, batch_other_block_size, max_round_own_blocks
            );
        let data_transmission_blocks = self.read_index_transmission_vec(entries);
        data_transmission_blocks
    }

    pub fn get_unknown_causal_history(
        &self,
        to_whom_authority_index: AuthorityIndex,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self
            .inner
            .read()
            .get_unknown_causal_history(to_whom_authority_index, batch_own_block_size,batch_other_block_size
        );
        let data_transmission_blocks = self.read_index_transmission_vec(entries);
        data_transmission_blocks
    }


    pub fn get_unknown_past_cone(
        &self,
        to_whom_authority_index: AuthorityIndex,
        block_reference: BlockReference,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
    ) -> Vec<Data<VerifiedStatementBlock>> {
        let entries = self
            .inner
            .read()
            .get_unknown_past_cone(to_whom_authority_index, block_reference, batch_own_block_size,batch_other_block_size
            );
        let data_transmission_blocks = self.read_index_transmission_vec(entries);
        data_transmission_blocks
    }

    pub fn last_seen_by_authority(&self, authority: AuthorityIndex) -> RoundNumber {
        self.inner.read().last_seen_by_authority(authority)
    }

    pub fn last_own_block_ref(&self) -> Option<BlockReference> {
        self.inner.read().last_own_block()
    }

    fn read_index(&self, entry: IndexEntry) -> (Data<VerifiedStatementBlock>,Data<VerifiedStatementBlock>) {
        let own_id = self.inner.read().authority;
        match entry {
            IndexEntry::WalPosition(position) => {
                self.metrics.block_store_loaded_blocks.inc();
                let (tag, data) = self
                    .block_wal_reader
                    .read(position)
                    .expect("Failed to read wal");
                match tag {
                    WAL_ENTRY_BLOCK => {

                        let data_storage_block: Data<VerifiedStatementBlock> = Data::from_bytes(data).expect("Failed to deserialize data from wal");
                        let transmission_block = data_storage_block.from_storage_to_transmission(own_id);
                        let data_transmission_block = Data::new(transmission_block);
                        (data_storage_block, data_transmission_block)
                    }
                    WAL_ENTRY_OWN_BLOCK => {
                        OwnBlockData::from_bytes(data)
                            .expect("Failed to deserialized own block from wal").1
                    }
                    _ => {
                        panic!("Trying to load index entry at position {position}, found tag {tag}")
                    }
                }
            }
            IndexEntry::Loaded(_, block) => block,
        }
    }

    fn read_index_storage_vec(&self, entries: Vec<IndexEntry>) -> Vec<Data<VerifiedStatementBlock>> {
        entries
            .into_iter()
            .map(|pos| self.read_index(pos).0)
            .collect()
    }

    fn read_index_transmission_vec(&self, entries: Vec<IndexEntry>) -> Vec<Data<VerifiedStatementBlock>> {
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
                .map(|block_reference| self.get_storage_block(*block_reference).expect("Block should be in Block Store"))
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
        self.cached_blocks.get(block_reference).map_or(0, |x| x.1.clone())
    }

    pub fn read_pending_unavailable(&self) -> Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)>{
        self.pending_not_available.clone()
    }

    pub fn update_pending_unavailable(&mut self, pending: Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)>) {
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
        let (_, shard_index) = block.encoded_shard().as_ref().expect("It should be some because of the above check");
        let cached_block = &self.cached_blocks.get(&block_reference).expect("Cached block missing").0;
        if cached_block.encoded_statements()[*shard_index].is_none() {
            return true;
        }
        false
    }

    // Chech whether the block can be reconstructed with a new shard
    pub fn ready_to_reconstruct(&self, block: &VerifiedStatementBlock) -> (bool, Option<CachedStatementBlock>) {
        if block.encoded_shard().is_none() || !self.cached_blocks.contains_key(block.reference())  {
            return (false, None);
        }
        let (_, shard_index) = block.encoded_shard().as_ref().expect("It should be some because of the above check");
        let cached_block = &self.cached_blocks.get(block.reference()).expect("Cached block missing").0;
        if cached_block.encoded_statements()[*shard_index].is_none() {
            let shard_count = 1 + cached_block.encoded_statements().iter().filter(|s| s.is_some()).count();
            if shard_count >= self.info_length {
                return (true, Some(cached_block.clone()));
            }
        }
        return (false, None);
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
                        tracing::debug!("Not updated cached block {:?}. Still shards {:?}. Position {:?}", block, count, position);
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
        self.cached_blocks.get(&block_reference).expect("Cached block missing").0.clone()
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

    // todo - also specify LRU criteria
    /// Unload all entries from below or equal threshold_round
    pub fn unload_below_round(&mut self, threshold_round: RoundNumber) -> usize {
        let mut unloaded = 0usize;
        for (round, map) in self.index.iter_mut() {
            // todo - try BTreeMap for self.index?
            if *round > threshold_round {
                continue;
            }
            for entry in map.values_mut() {
                match entry {
                    IndexEntry::WalPosition(_) => {}
                    // Unload entry
                    IndexEntry::Loaded(position, _) => {
                        unloaded += 1;
                        *entry = IndexEntry::WalPosition(*position);
                    }
                }
            }
        }
        if unloaded > 0 {
            tracing::debug!("Unloaded {unloaded} entries from block store cache");
        }
        unloaded
    }

    pub fn add_unloaded(
        &mut self,
        data_storage_transmission_blocks: (Data<VerifiedStatementBlock>,Data<VerifiedStatementBlock>) ,
        position: WalPosition,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        let reference = data_storage_transmission_blocks.0.reference();
        self.highest_round = max(self.highest_round, reference.round());
        let map = self.index.entry(reference.round()).or_default();
        map.insert(reference.author_digest(), IndexEntry::WalPosition(position));
        self.add_own_index(reference, authority_index_start, authority_index_end);
        self.update_last_seen_by_authority(reference);
        self.update_dag(data_storage_transmission_blocks.0.reference().clone(), data_storage_transmission_blocks.0.includes().clone());
        self.update_data_availability_and_cached_blocks(&data_storage_transmission_blocks.0);
    }

    pub fn add_loaded(
        &mut self,
        position: WalPosition,
        storage_and_transmission_blocks: (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>),
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        self.highest_round = max(self.highest_round, storage_and_transmission_blocks.0.round());
        self.add_own_index(
            storage_and_transmission_blocks.0.reference(),
            authority_index_start,
            authority_index_end,
        );
        self.update_last_seen_by_authority(storage_and_transmission_blocks.0.reference());
        let map = self.index.entry(storage_and_transmission_blocks.0.round()).or_default();
        map.insert(
            (storage_and_transmission_blocks.0.author(), storage_and_transmission_blocks.0.digest()),
            IndexEntry::Loaded(position, storage_and_transmission_blocks.clone()),
        );
        self.update_dag(storage_and_transmission_blocks.0.reference().clone(), storage_and_transmission_blocks.0.includes().clone());
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

    pub fn contains_block_reference(&self, block_ref: &BlockReference) -> bool {
        self.dag.get(&block_ref.round)
            .map_or(false, |hashmap|
                hashmap.contains_key(&(block_ref.authority, block_ref.digest))
            )
    }

    pub fn read_block_reference(&self, block_ref: &BlockReference) -> Option<(Vec<BlockReference>, HashSet<AuthorityIndex>, VoteForLeader, CertificateForLeader, CertifiedStake)> {
        self.dag.get(&block_ref.round)
            .and_then(|hashmap|
                hashmap.get(&(block_ref.authority, block_ref.digest)).cloned()
            )
    }

    pub fn get_mut_block_reference(&mut self, block_ref: &BlockReference) -> Option<&mut (Vec<BlockReference>, HashSet<AuthorityIndex>, VoteForLeader, CertificateForLeader, CertifiedStake)> {
        self.dag.get_mut(&block_ref.round)
            .and_then(|hashmap|
                hashmap.get_mut(&(block_ref.authority, block_ref.digest))
            )
    }
    // Upon updating the local DAG with a block, we know that the authority created this block is aware of the causal history
    // of the block, and we assume that others are not aware of this block
    pub fn update_dag(&mut self, new_block_reference: BlockReference, parents: Vec<BlockReference>) {
        let committee = self.committee.clone();
        // don't update if it is already there
        if self.contains_block_reference(&new_block_reference) {
            return;
        }
        // TODO: this is manual logic to not have recursive dependency with UniversalCommitter
        let stake_aggregator: Option<StakeAggregator<QuorumThreshold>> = if leader_in_round(new_block_reference.round, committee.len()) == new_block_reference.authority  {
            Some(StakeAggregator::new())
        } else {
            None
        };

        // TODO: this is manual logic for updating whether a block is a voter
        // for a past leader, assuming one leader in every round
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


        // TODO: this is manual logic for updating whether a block is a certificate
        // for a leader two rounds before, assuming one leader in every round
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
                        leader_committed = true;
                        tracing::debug!("Leader {:?} is directly committed, Stake  {:?}", leader, aggregator);
                    }
                }
            } else {
                panic!("The DAG must contain the certified leader");
            }
            if leader_committed {
                self.directly_committed_leaders.insert(leader);
            }
        }
        // update information about block_reference
        self.dag.entry(new_block_reference.round)
            .or_insert_with(HashMap::new)
            .insert(
                (new_block_reference.authority, new_block_reference.digest),
                (
                    parents,
                    vec![new_block_reference.authority, self.authority]
                        .into_iter()
                        .collect::<HashSet<_>>(),
                    new_vote_for_leader,
                    new_certificate_for_leader,
                    stake_aggregator,
                )
            );

        for authority in 0..self.not_known_by_authority.len() {
            if authority == self.authority as usize
                || authority == new_block_reference.authority as usize
            {
                continue;
            }
            self.not_known_by_authority[authority].insert(new_block_reference);
        }
        // traverse the DAG from block_reference and update the blocks known by block_reference.authority
        let authority = new_block_reference.authority;
        let mut buffer = vec![new_block_reference];

        while !buffer.is_empty() {
            let block_reference = buffer.pop().unwrap();
            let (parents, _,_,_,_) = self.read_block_reference(&block_reference).unwrap();
            for parent in parents {
                if parent.round == 0 {
                    continue;
                }
                let (_, known_by,_,_,_) = self.get_mut_block_reference(&parent).unwrap();
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
                self.data_availability.insert(block.reference().clone());
                self.pending_acknowledgment.push(block.reference().clone());
            }
            tracing::debug!("Remove cached block {:?}", block.reference());
            self.cached_blocks.remove(block.reference());
        } else  {
            if !self.data_availability.contains(&block.reference()) {
                let cached_block = block.to_cached_block(self.committee_size);
                self.cached_blocks.insert(block.reference().clone(), (cached_block, count));
                tracing::debug!("Insert cached block {:?}", block.reference());
            } else {
                tracing::debug!("Block is already available {:?}", block.reference());
            }
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
        let (_, known_by,_,_,_) = self.get_mut_block_reference(&block_reference).unwrap();
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

    pub fn get_unknown_own_blocks(
        &self,
        to_whom: AuthorityIndex,
        batch_own_block_size: usize,
    ) -> Vec<IndexEntry> {
        let mut own_blocks: Vec<(IndexEntry, RoundNumber)> = self.not_known_by_authority[to_whom as usize]
            .iter()
            .filter(|block_reference| block_reference.authority == self.authority)
            .take(batch_own_block_size)
            .map(|block_reference| {
                if let Some(index_entry) = self.get_block(*block_reference) {
                    (index_entry, block_reference.round())
                } else {
                    panic!("Block index corrupted, not found: {block_reference}");
                }
            })
            .collect();

        own_blocks.sort_by_key(|x| x.1 as u64);
        own_blocks.iter().map(|x|x.0.clone()).collect()
    }

    pub fn get_unknown_other_blocks(
        &self,
        to_whom: AuthorityIndex,
        batch_other_block_size: usize,
        max_round: Option<RoundNumber>,
    ) -> Vec<IndexEntry> {
        let max_round_own_blocks = max_round.unwrap_or(RoundNumber::MAX);
        let mut other_blocks: Vec<(IndexEntry, RoundNumber)> = self.not_known_by_authority[to_whom as usize]
            .iter()
            .filter(|block_reference| (block_reference.authority != self.authority) && (block_reference.round < max_round_own_blocks))
            .take(batch_other_block_size)
            .map(|block_reference| {
                if let Some(index_entry) = self.get_block(*block_reference) {
                    (index_entry, block_reference.round())
                } else {
                    panic!("Block index corrupted, not found: {block_reference}");
                }
            })
            .collect();
        other_blocks.sort_by_key(|x| x.1 as u64);
        other_blocks.iter().map(|x|x.0.clone()).collect()

    }

    pub fn get_unknown_causal_history(
        &self,
        to_whom: AuthorityIndex,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
    ) -> Vec<IndexEntry> {
        let own_blocks: Vec<(IndexEntry, RoundNumber)> = self.not_known_by_authority[to_whom as usize]
            .iter()
            .filter(|block_reference| block_reference.authority == self.authority)
            .take(batch_own_block_size)
            .map(|block_reference| {
                if let Some(index_entry) = self.get_block(*block_reference) {
                    (index_entry, block_reference.round())
                } else {
                    panic!("Block index corrupted, not found: {block_reference}");
                }
            })
            .collect();
        let max_round_own_blocks = own_blocks.iter().map(|own_block|own_block.1).max();
        let max_round_own_blocks = max_round_own_blocks.unwrap_or(RoundNumber::MAX);
        let other_blocks: Vec<(IndexEntry, RoundNumber)> = self.not_known_by_authority[to_whom as usize]
            .iter()
            .filter(|block_reference| (block_reference.authority != self.authority) && (block_reference.round < max_round_own_blocks))
            .take(batch_other_block_size)
            .map(|block_reference| {
                if let Some(index_entry) = self.get_block(*block_reference) {
                    (index_entry, block_reference.round())
                } else {
                    panic!("Block index corrupted, not found: {block_reference}");
                }
            })
            .collect();

        let mut blocks_to_send: Vec<(IndexEntry, RoundNumber)> = own_blocks.into_iter().chain(other_blocks).collect();
        blocks_to_send.sort_by_key(|x| x.1 as u64);
        blocks_to_send.iter().map(|x|x.0.clone()).collect()

    }


    pub fn get_unknown_past_cone(
        &self,
        to_whom: AuthorityIndex,
        block_reference: BlockReference,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
    ) -> Vec<IndexEntry> {
        let max_round = block_reference.round;
        let own_blocks: Vec<(IndexEntry, RoundNumber)> = self.not_known_by_authority[to_whom as usize]
            .iter()
            .filter(|block_reference| block_reference.authority == self.authority && block_reference.round < max_round)
            .take(batch_own_block_size)
            .map(|block_reference| {
                if let Some(index_entry) = self.get_block(*block_reference) {
                    (index_entry, block_reference.round())
                } else {
                    panic!("Block index corrupted, not found: {block_reference}");
                }
            })
            .collect();
        let other_blocks: Vec<(IndexEntry, RoundNumber)> = self.not_known_by_authority[to_whom as usize]
            .iter()
            .filter(|block_reference| (block_reference.authority != self.authority) && (block_reference.round < max_round))
            .take(batch_other_block_size)
            .map(|block_reference| {
                if let Some(index_entry) = self.get_block(*block_reference) {
                    (index_entry, block_reference.round())
                } else {
                    panic!("Block index corrupted, not found: {block_reference}");
                }
            })
            .collect();

        let mut blocks_to_send: Vec<(IndexEntry, RoundNumber)> = own_blocks.into_iter().chain(other_blocks).collect();
        blocks_to_send.sort_by_key(|x| x.1 as u64);
        blocks_to_send.iter().map(|x|x.0.clone()).collect()

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

pub fn leader_in_round(round: RoundNumber, committee_size: usize) -> AuthorityIndex {
    (round as u64) % (committee_size as u64) as AuthorityIndex
}

pub const WAL_ENTRY_BLOCK: Tag = 1;
pub const WAL_ENTRY_PAYLOAD: Tag = 2;
pub const WAL_ENTRY_OWN_BLOCK: Tag = 3;
pub const WAL_ENTRY_STATE: Tag = 4;
// Commit entry includes both commit interpreter incremental state and committed transactions aggregator
// todo - They could be separated for better performance, but this will require catching up for committed transactions aggregator state
pub const WAL_ENTRY_COMMIT: Tag = 5;

impl BlockWriter for (&mut WalWriter, &BlockStore) {

    fn insert_block(&mut self, storage_and_transmission_blocks: (Data<VerifiedStatementBlock>,Data<VerifiedStatementBlock>)) -> WalPosition {
        let pos = self
            .0
            .write(WAL_ENTRY_BLOCK, storage_and_transmission_blocks.0.serialized_bytes())
            .expect("Writing to wal failed");
        self.1
            .insert_block(storage_and_transmission_blocks, pos, 0, self.1.committee_size as AuthorityIndex);
        pos
    }

    fn insert_own_block(
        &mut self,
        data: &OwnBlockData,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        let block_pos = data.write_to_wal(self.0);
        self.1.insert_block(
            data.storage_transmission_blocks.clone(),
            block_pos,
            authority_index_start,
            authority_index_end,
        );
    }
}

// This data structure has a special serialization in/from Bytes, see OwnBlockData::from_bytes/write_to_wal
#[derive(Clone)]
pub struct OwnBlockData {
    pub next_entry: WalPosition,
    pub storage_transmission_blocks: (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>),
}

const OWN_BLOCK_HEADER_SIZE: usize = 8;

impl OwnBlockData {
    // A bit of custom serialization to minimize data copy, relies on own_block_serialization_test
    pub fn from_bytes(bytes: Bytes) -> bincode::Result<(OwnBlockData, (Data<VerifiedStatementBlock>,Data<VerifiedStatementBlock>))> {
        let next_entry = &bytes[..OWN_BLOCK_HEADER_SIZE];
        let next_entry: WalPosition = bincode::deserialize(next_entry)?;
        let block = bytes.slice(OWN_BLOCK_HEADER_SIZE..);
        let data_storage_block: Data<VerifiedStatementBlock> = Data::from_bytes(block)?;
        let own_id = data_storage_block.author();
        let transmission_block = data_storage_block.from_storage_to_transmission(own_id);
        let data_transmission_block = Data::new(transmission_block);
        let own_block_data = OwnBlockData {
            next_entry,
            storage_transmission_blocks: (data_storage_block.clone(), data_transmission_block.clone()),
        };
        Ok((own_block_data, (data_storage_block,data_transmission_block)))
    }

    pub fn write_to_wal(&self, writer: &mut WalWriter) -> WalPosition {
        let header = bincode::serialize(&self.next_entry).expect("Serialization failed");
        let header = IoSlice::new(&header);
        let block = IoSlice::new(self.storage_transmission_blocks.0.serialized_bytes());
        writer
            .writev(WAL_ENTRY_OWN_BLOCK, &[header, block])
            .expect("Writing to wal failed")
    }
}

#[derive(Serialize, Deserialize)]
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
mod test {
    use super::*;

    #[test]
    fn own_block_serialization_test() {
        let next_entry = WalPosition::default();
        let serialized = bincode::serialize(&next_entry).unwrap();
        assert_eq!(serialized.len(), OWN_BLOCK_HEADER_SIZE);
    }
}
