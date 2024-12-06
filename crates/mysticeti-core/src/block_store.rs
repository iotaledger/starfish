// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeSet, HashSet};
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
        AuthorityIndex, BlockDigest, BlockReference, RoundNumber, StatementBlock,
    },
    wal::{Tag, WalPosition, WalReader, WalWriter},
};

#[allow(unused)]
#[derive(Clone, Debug)]
pub enum ByzantineStrategy {
    TimeoutLeader,
    EquivocatingBlocks,
    DelayedEquivocatingBlocks,
}
#[derive(Clone)]
pub struct BlockStore {
    inner: Arc<RwLock<BlockStoreInner>>,
    block_wal_reader: Arc<WalReader>,
    metrics: Arc<Metrics>,
    pub(crate) committee_size: usize,
    pub(crate) byzantine_strategy: Option<ByzantineStrategy>,
}

#[derive(Default)]
struct BlockStoreInner {
    index: BTreeMap<RoundNumber, HashMap<(AuthorityIndex, BlockDigest), IndexEntry>>,
    // Store the blocks for which we have transaction data
    data_availability: HashSet<BlockDigest>,
    // Store the blocks until the transaction data gets recoverable
    cached_blocks: BTreeMap<BlockDigest, (StatementBlock, usize)>,
    // Byzantine nodes will create different blocks intended for the different validators
    own_blocks: BTreeMap<(RoundNumber, AuthorityIndex), BlockDigest>,
    highest_round: RoundNumber,
    authority: AuthorityIndex,
    info_length: usize,
    committee_size: usize,
    last_seen_by_authority: Vec<RoundNumber>,
    last_own_block: Option<BlockReference>,
    not_known_by_authority: Vec<BTreeSet<BlockReference>>,
    // this dag structure store for each block its predecessors and who knows the block
    dag: HashMap<BlockReference, (Vec<BlockReference>, HashSet<AuthorityIndex>)>,
}

pub trait BlockWriter {
    fn insert_block(&mut self, block: Data<StatementBlock>) -> WalPosition;

    fn update_dag(&mut self, block_reference: BlockReference, parents: Vec<BlockReference>);

    fn update_data_availability_and_cached_blocks(&mut self, block: &StatementBlock);

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
    Loaded(WalPosition, Data<StatementBlock>),
}

impl BlockStore {
    pub fn open(
        authority: AuthorityIndex,
        block_wal_reader: Arc<WalReader>,
        wal_writer: &WalWriter,
        metrics: Arc<Metrics>,
        committee: &Committee,
        byzantine_strategy: String,
    ) -> RecoveredState {
        let last_seen_by_authority = committee.authorities().map(|_| 0).collect();
        let not_known_by_authority = committee.authorities().map(|_| BTreeSet::new()).collect();
        let mut inner = BlockStoreInner {
            authority,
            last_seen_by_authority,
            not_known_by_authority,
            info_length: committee.info_length(),
            committee_size: committee.len(),
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
                    let block = Data::<StatementBlock>::from_bytes(data)
                        .expect("Failed to deserialize data from wal");
                    builder.block(pos, &block);
                    block
                }
                WAL_ENTRY_PAYLOAD => {
                    builder.payload(pos, data);
                    continue;
                }
                WAL_ENTRY_OWN_BLOCK => {
                    let (own_block_data, own_block) = OwnBlockData::from_bytes(data)
                        .expect("Failed to deserialized own block data from wal");
                    builder.own_block(own_block_data);
                    own_block
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
            inner.add_unloaded(block.reference(), pos, 0, committee.len() as AuthorityIndex);

            // todo - we might need to sort all unprocessed blocks by rounds and run update with a loop
            inner.update_dag(block.reference().clone(), block.includes().clone());
            inner.update_data_availability_and_cached_blocks(&block);
        }
        metrics.block_store_entries.inc_by(block_count);
        if let Some(replay_started) = replay_started {
            tracing::info!("Wal replay completed in {:?}", replay_started.elapsed());
        } else {
            tracing::info!("Wal is empty, will start from genesis");
        }
        let byzantine_strategy = match byzantine_strategy.as_str() {
            "equivocate" => Some(ByzantineStrategy::EquivocatingBlocks),
            "delayed" => Some(ByzantineStrategy::DelayedEquivocatingBlocks),
            "timeout" => Some(ByzantineStrategy::TimeoutLeader),
            _ => None, // honest by default
        };
        let this = Self {
            block_wal_reader,
            byzantine_strategy,
            inner: Arc::new(RwLock::new(inner)),
            metrics,
            committee_size: committee.len(),
        };
        builder.build(this)
    }

    pub fn get_dag(
        &self,
    ) -> HashMap<BlockReference, (Vec<BlockReference>, HashSet<AuthorityIndex>)> {
        self.inner.read().dag.clone()
    }

    pub fn get_dag_sorted(&self) -> Vec<(BlockReference, Vec<BlockReference>, HashSet<AuthorityIndex>)> {
        let mut dag: Vec<(BlockReference, Vec<BlockReference>, HashSet<AuthorityIndex>)> = self
            .get_dag()
            .iter()
            .map(|(block_reference, refs_and_indices)| {
                (block_reference.clone(), refs_and_indices.0.clone(), refs_and_indices.1.clone())
            })
            .collect();

        dag.sort_by_key(|(block_reference, _, _)| block_reference.round());
        dag
    }

    pub fn get_own_authority_index(&self) -> AuthorityIndex {
        self.inner.read().authority
    }

    pub fn get_unknown_by_authority(&self, authority_index: AuthorityIndex) -> BTreeSet<BlockReference> {
        self.inner.read().not_known_by_authority[authority_index as usize].clone()
    }

    pub fn insert_block(
        &self,
        block: Data<StatementBlock>,
        position: WalPosition,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        self.metrics.block_store_entries.inc();
        self.inner
            .write()
            .add_loaded(position, block, authority_index_start, authority_index_end);
    }

    pub fn get_block(&self, reference: BlockReference) -> Option<Data<StatementBlock>> {
        let entry = self.inner.read().get_block(reference);
        // todo - consider adding loaded entries back to cache
        entry.map(|pos| self.read_index(pos))
    }

    // this function should be called when we add a block to the local DAG for the first time
    pub fn update_dag(&self, block_reference: BlockReference, parents: Vec<BlockReference>) {
        self.inner.write().update_dag(block_reference, parents);
    }

    pub fn updated_unknown_by_others(&self, block_reference: BlockReference) {
        self.inner.write().updated_unknown_by_others(block_reference);
    }

    pub fn update_data_availability_and_cached_blocks(&self, block: &StatementBlock) {
        self.inner.write().update_data_availability_and_cached_blocks(block);
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

    pub fn get_blocks_by_round(&self, round: RoundNumber) -> Vec<Data<StatementBlock>> {
        let entries = self.inner.read().get_blocks_by_round(round);
        self.read_index_vec(entries)
    }

    pub fn get_blocks_at_authority_round(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Vec<Data<StatementBlock>> {
        let entries = self
            .inner
            .read()
            .get_blocks_at_authority_round(authority, round);
        self.read_index_vec(entries)
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

    pub fn shard_count(&self, digest: BlockDigest) -> usize {
        self.inner.read().shard_count(digest)
    }

    pub fn get_new_shards_ids(&self, block: &StatementBlock) -> Vec<usize> {
        self.inner.read().get_new_shards_ids(block)
    }

    pub fn update_with_new_shard(&self, block: &StatementBlock) {
        self.inner.write().update_with_new_shard(block);
    }


    pub fn is_sufficient_shards(&self, block: &StatementBlock) -> bool {
        self.inner.write().is_sufficient_shards(block)
    }

    pub fn get_cached_block(&self, digest: BlockDigest) -> StatementBlock {
        self.inner.read().get_cached_block(digest)
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

    pub fn get_own_blocks(
        &self,
        to_whom_authority_index: AuthorityIndex,
        from_excluded: RoundNumber,
        limit: usize,
    ) -> Vec<Data<StatementBlock>> {
        let entries =
            self.inner
                .read()
                .get_own_blocks(to_whom_authority_index, from_excluded, limit);
        self.read_index_vec(entries)
    }

    pub fn get_unknown_causal_history(
        &self,
        to_whom_authority_index: AuthorityIndex,
        limit: usize,
    ) -> Vec<Data<StatementBlock>> {
        let entries = self
            .inner
            .read()
            .get_unknown_causal_history(to_whom_authority_index, limit);
        let data_blocks = self.read_index_vec(entries);
        let mut changed_data_blocks = Vec::new();
        let own_index = self.inner.read().authority;
        let info_length = self.inner.read().info_length;
        for data_block in data_blocks {
            let mut block: StatementBlock = data_block.into();
            if block.author() == own_index {
                block.change_for_own_index(info_length);
            } else {
                block.change_for_not_own_index(own_index);
            }
            let changed_data_block = Data::new(block);
            changed_data_blocks.push(changed_data_block);
        }
        changed_data_blocks
    }


    pub fn get_others_blocks(
        &self,
        from_excluded: RoundNumber,
        authority: AuthorityIndex,
        limit: usize,
    ) -> Vec<Data<StatementBlock>> {
        let entries = self
            .inner
            .read()
            .get_others_blocks(from_excluded, authority, limit);
        self.read_index_vec(entries)
    }

    pub fn last_seen_by_authority(&self, authority: AuthorityIndex) -> RoundNumber {
        self.inner.read().last_seen_by_authority(authority)
    }

    pub fn last_own_block_ref(&self) -> Option<BlockReference> {
        self.inner.read().last_own_block()
    }

    fn read_index(&self, entry: IndexEntry) -> Data<StatementBlock> {
        match entry {
            IndexEntry::WalPosition(position) => {
                self.metrics.block_store_loaded_blocks.inc();
                let (tag, data) = self
                    .block_wal_reader
                    .read(position)
                    .expect("Failed to read wal");
                match tag {
                    WAL_ENTRY_BLOCK => {
                        Data::from_bytes(data).expect("Failed to deserialize data from wal")
                    }
                    WAL_ENTRY_OWN_BLOCK => {
                        OwnBlockData::from_bytes(data)
                            .expect("Failed to deserialized own block from wal")
                            .1
                    }
                    _ => {
                        panic!("Trying to load index entry at position {position}, found tag {tag}")
                    }
                }
            }
            IndexEntry::Loaded(_, block) => block,
        }
    }

    fn read_index_vec(&self, entries: Vec<IndexEntry>) -> Vec<Data<StatementBlock>> {
        entries
            .into_iter()
            .map(|pos| self.read_index(pos))
            .collect()
    }

    /// Check whether `earlier_block` is an ancestor of `later_block`.
    pub fn linked(
        &self,
        later_block: &Data<StatementBlock>,
        earlier_block: &Data<StatementBlock>,
    ) -> bool {
        let mut parents = vec![later_block.clone()];
        for r in (earlier_block.round()..later_block.round()).rev() {
            parents = self
                .get_blocks_by_round(r)
                .into_iter()
                .filter(|block| {
                    parents
                        .iter()
                        .any(|x| x.includes().contains(block.reference()))
                })
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

    pub fn shard_count(&self, digest: BlockDigest) -> usize {
        if self.data_availability.contains(&digest) {
            return self.committee_size;
        }
        self.cached_blocks.get(&digest).map_or(0, |x| x.1)
    }

    pub fn get_new_shards_ids(&self, block: &StatementBlock) -> Vec<usize> {
        let block_digest = block.digest();
        if self.data_availability.contains(&block_digest) {
            return vec![];
        }
        // If the block is not in the cache
        if !self.cached_blocks.contains_key(&block_digest) {
            // Collect indices of `Some` encoded statements
            return block
                .encoded_statements()
                .iter()
                .enumerate()
                .filter_map(|(i, stmt)| if stmt.is_some() { Some(i) } else { None })
                .collect();
        }
        // Get the cached block
        let cached_block = &self.cached_blocks.get(&block_digest).expect("Cached block missing").0;
        let cached_statements = cached_block.encoded_statements();
        let block_statements = block.encoded_statements();

        // Compare the cached and current block to collect new indices
        let mut res = Vec::new();
        for (i, (cached_stmt, block_stmt)) in cached_statements.iter().zip(block_statements).enumerate() {
            if cached_stmt.is_none() && block_stmt.is_some() {
                res.push(i);
            }
        }
        res
    }

    pub fn update_with_new_shard(&mut self, block: &StatementBlock) {
        if let Some(entry) = self.cached_blocks.get_mut(&block.digest()) {
            let (cached_block, count) = entry;
            for (index, encoded_shard) in block.encoded_statements().iter().enumerate() {
                if let Some(encoded_shard) = encoded_shard {
                    if cached_block.encoded_statements()[index].is_none() {
                        cached_block.add_encoded_shard(index, encoded_shard.clone());
                        *count += 1;
                    }
                }
            }
        }
    }

    pub fn is_sufficient_shards(&mut self, block: &StatementBlock) -> bool{
        let count_shards = self.shard_count(block.digest());
        if count_shards >= self.info_length {
            return true;
        }
        return false
    }

    pub fn get_cached_block(&self, digest: BlockDigest) -> StatementBlock {
        self.cached_blocks.get(&digest).expect("Cached block missing").0.clone()
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
        reference: &BlockReference,
        position: WalPosition,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        self.highest_round = max(self.highest_round, reference.round());
        let map = self.index.entry(reference.round()).or_default();
        map.insert(reference.author_digest(), IndexEntry::WalPosition(position));
        self.add_own_index(reference, authority_index_start, authority_index_end);
        self.update_last_seen_by_authority(reference);
    }

    pub fn add_loaded(
        &mut self,
        position: WalPosition,
        block: Data<StatementBlock>,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        self.highest_round = max(self.highest_round, block.round());
        self.add_own_index(
            block.reference(),
            authority_index_start,
            authority_index_end,
        );
        self.update_last_seen_by_authority(block.reference());
        let map = self.index.entry(block.round()).or_default();
        map.insert(
            (block.author(), block.digest()),
            IndexEntry::Loaded(position, block),
        );
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

        while !buffer.is_empty() {
            let block_reference = buffer.pop().unwrap();
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


    pub fn update_data_availability_and_cached_blocks(&mut self, block: &StatementBlock) {
        let committee_size = block.encoded_statements().len();
        let count = block.encoded_statements().iter().filter(|x|x.is_some()).count();
        if count < committee_size {
            if !self.data_availability.contains(&block.digest()) {
                self.cached_blocks.insert(block.digest(), (block.clone(), count));
            }
        } else {
            self.data_availability.insert(block.digest());
            self.cached_blocks.remove(&block.digest());
        }
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

    pub fn get_unknown_causal_history(
        &self,
        to_whom: AuthorityIndex,
        limit: usize,
    ) -> Vec<IndexEntry> {
        let own_blocks: Vec<(IndexEntry, RoundNumber)> = self.not_known_by_authority[to_whom as usize]
            .iter()
            .filter(|block_reference| block_reference.authority == self.authority)
            .take(limit)
            .map(|block_reference| {
                if let Some(index_entry) = self.get_block(*block_reference) {
                    (index_entry, block_reference.round())
                } else {
                    panic!("Block index corrupted, not found: {block_reference}");
                }
            })
            .collect();
        let max_round_own_blocks = own_blocks.iter().map(|own_block|own_block.1).max();
        let max_round_own_blocks = max_round_own_blocks.unwrap_or(0 as RoundNumber);
        let new_limit = limit.saturating_sub(own_blocks.len());
        let other_blocks: Vec<(IndexEntry, RoundNumber)> = self.not_known_by_authority[to_whom as usize]
            .iter()
            .filter(|block_reference| (block_reference.authority != self.authority) && (block_reference.round < max_round_own_blocks))
            .take(new_limit)
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

    pub fn get_others_blocks(
        &self,
        from_excluded: RoundNumber,
        authority: AuthorityIndex,
        limit: usize,
    ) -> Vec<IndexEntry> {
        self.index
            .range((from_excluded + 1)..)
            .take(limit)
            .flat_map(|(round, map)| {
                map.keys()
                    .filter(|(a, _)| *a == authority)
                    .map(|(a, d)| BlockReference {
                        authority: *a,
                        round: *round,
                        digest: *d,
                    })
            })
            .map(|reference| {
                self.get_block(reference)
                    .unwrap_or_else(|| panic!("Block index corrupted, not found: {reference}"))
            })
            .collect()
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

pub const WAL_ENTRY_BLOCK: Tag = 1;
pub const WAL_ENTRY_PAYLOAD: Tag = 2;
pub const WAL_ENTRY_OWN_BLOCK: Tag = 3;
pub const WAL_ENTRY_STATE: Tag = 4;
// Commit entry includes both commit interpreter incremental state and committed transactions aggregator
// todo - They could be separated for better performance, but this will require catching up for committed transactions aggregator state
pub const WAL_ENTRY_COMMIT: Tag = 5;

impl BlockWriter for (&mut WalWriter, &BlockStore) {
    fn update_dag(&mut self, block_reference: BlockReference, parents: Vec<BlockReference>) {
        self.1.update_dag(block_reference, parents);
    }

    fn update_data_availability_and_cached_blocks(&mut self, block: &StatementBlock) {
        self.1.update_data_availability_and_cached_blocks(block);
    }

    fn insert_block(&mut self, block: Data<StatementBlock>) -> WalPosition {
        let pos = self
            .0
            .write(WAL_ENTRY_BLOCK, block.serialized_bytes())
            .expect("Writing to wal failed");
        self.1
            .insert_block(block, pos, 0, self.1.committee_size as AuthorityIndex);
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
            data.block.clone(),
            block_pos,
            authority_index_start,
            authority_index_end,
        );
        self.1.update_dag(
            *data.block.reference(),
            data.block.includes().clone(),
        );
        self.1.update_data_availability_and_cached_blocks(&data.block);
    }
}

// This data structure has a special serialization in/from Bytes, see OwnBlockData::from_bytes/write_to_wal
#[derive(Clone)]
pub struct OwnBlockData {
    pub next_entry: WalPosition,
    pub block: Data<StatementBlock>,
}

const OWN_BLOCK_HEADER_SIZE: usize = 8;

impl OwnBlockData {
    // A bit of custom serialization to minimize data copy, relies on own_block_serialization_test
    pub fn from_bytes(bytes: Bytes) -> bincode::Result<(OwnBlockData, Data<StatementBlock>)> {
        let next_entry = &bytes[..OWN_BLOCK_HEADER_SIZE];
        let next_entry: WalPosition = bincode::deserialize(next_entry)?;
        let block = bytes.slice(OWN_BLOCK_HEADER_SIZE..);
        let block = Data::<StatementBlock>::from_bytes(block)?;
        let own_block_data = OwnBlockData {
            next_entry,
            block: block.clone(),
        };
        Ok((own_block_data, block))
    }

    pub fn write_to_wal(&self, writer: &mut WalWriter) -> WalPosition {
        let header = bincode::serialize(&self.next_entry).expect("Serialization failed");
        let header = IoSlice::new(&header);
        let block = IoSlice::new(self.block.serialized_bytes());
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
