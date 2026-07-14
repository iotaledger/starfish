// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

use ahash::{AHashMap, AHashSet};

use crate::{
    committee::Committee,
    dag_state::{DagState, DataSource},
    data::Data,
    types::{BlockReference, RoundNumber, VerifiedBlock},
};

/// Block manager suspends incoming blocks until they are connected to the
/// existing graph, returning newly connected blocks
pub struct BlockManager {
    /// Keeps all pending blocks.
    blocks_pending: BTreeMap<BlockReference, Data<VerifiedBlock>>,
    /// Keeps all the blocks (`AHashSet<BlockReference>`) waiting
    /// for `BlockReference` to be processed.
    block_references_waiting: BTreeMap<BlockReference, AHashSet<BlockReference>>,
    /// Keeps all blocks that need to be synced in order to unblock the
    /// processing of other pending blocks. The indices of the vector
    /// correspond the authority indices.
    missing: Vec<AHashSet<BlockReference>>,
    dag_state: DagState,
}

impl BlockManager {
    pub fn new(dag_state: DagState, committee: &Arc<Committee>) -> Self {
        Self {
            blocks_pending: Default::default(),
            block_references_waiting: Default::default(),
            missing: (0..committee.len()).map(|_| AHashSet::new()).collect(),
            dag_state,
        }
    }

    pub fn add_blocks(
        &mut self,
        blocks: Vec<Data<VerifiedBlock>>,
        source: DataSource,
    ) -> (
        Vec<Data<VerifiedBlock>>,
        Vec<Data<VerifiedBlock>>,
        AHashSet<BlockReference>,
    ) {
        let dag_state = self.dag_state.clone();
        let mut blocks: VecDeque<Data<VerifiedBlock>> = blocks.into();
        let mut newly_processed: Vec<Data<VerifiedBlock>> = vec![];
        let mut updated_existing_with_transactions: Vec<Data<VerifiedBlock>> = vec![];
        // Blocks to insert into the DAG in a single batched write lock.
        let mut blocks_to_insert: Vec<Data<VerifiedBlock>> = vec![];
        // References first discovered in this batch are not visible through
        // DagState until the final batched insert. Keep their positions so a
        // richer duplicate later in the same batch can upgrade that pending
        // insertion instead of being mistaken for an already stored block.
        let mut new_blocks_in_batch: AHashMap<BlockReference, (usize, usize)> = AHashMap::new();
        let mut updated_blocks_in_batch: AHashMap<BlockReference, (usize, usize)> = AHashMap::new();
        // missing references that we don't currently have
        let mut missing_references = AHashSet::new();
        let mut block_exists_cache: AHashMap<BlockReference, bool> = AHashMap::new();
        while let Some(block) = blocks.pop_front() {
            let block_reference = block.reference();

            if let Some(existing_pending_block) = self.blocks_pending.get_mut(block_reference) {
                if let Some(mut merged) = existing_pending_block.merge_same_block(&block) {
                    merged.preserialize();
                    *existing_pending_block = Data::new(merged);
                }
                continue;
            }

            if let Some((insert_index, updated_index)) =
                updated_blocks_in_batch.get(block_reference).copied()
            {
                if let Some(mut merged) = blocks_to_insert[insert_index].merge_same_block(&block) {
                    merged.preserialize();
                    let merged = Data::new(merged);
                    blocks_to_insert[insert_index] = merged.clone();
                    updated_existing_with_transactions[updated_index] = merged;
                }
                continue;
            }

            if let Some((insert_index, processed_index)) =
                new_blocks_in_batch.get(block_reference).copied()
            {
                if let Some(mut merged) = blocks_to_insert[insert_index].merge_same_block(&block) {
                    merged.preserialize();
                    let merged = Data::new(merged);
                    blocks_to_insert[insert_index] = merged.clone();
                    newly_processed[processed_index] = merged;
                }
                continue;
            }

            let block_exists = *block_exists_cache
                .entry(*block_reference)
                .or_insert_with(|| self.dag_state.block_exists(*block_reference));
            if block_exists {
                // Block already in store — check if this version brings new transaction data
                if self.dag_state.contains_new_transactions(&block) {
                    tracing::debug!("Block has new transactions: {:?}", block_reference);
                    let stored_reference = *block_reference;
                    let mut merged = self
                        .dag_state
                        .get_storage_block(stored_reference)
                        .and_then(|existing| existing.merge_same_block(&block));
                    let block = if let Some(ref mut merged) = merged {
                        merged.preserialize();
                        Data::new(merged.clone())
                    } else {
                        block
                    };
                    let insert_index = blocks_to_insert.len();
                    blocks_to_insert.push(block.clone());
                    let updated_index = updated_existing_with_transactions.len();
                    updated_existing_with_transactions.push(block);
                    updated_blocks_in_batch.insert(stored_reference, (insert_index, updated_index));
                } else {
                    self.dag_state.upgrade_mac_authentication(&block);
                }
                continue;
            }

            let mut processed = true;
            for included_reference in block.block_references() {
                if self.blocks_pending.contains_key(included_reference) {
                    processed = false;
                    self.block_references_waiting
                        .entry(*included_reference)
                        .or_default()
                        .insert(*block_reference);
                    continue;
                }

                // If we are missing a reference then we insert
                // into pending and update the waiting index
                if !*block_exists_cache
                    .entry(*included_reference)
                    .or_insert_with(|| self.dag_state.block_exists(*included_reference))
                {
                    processed = false;

                    self.block_references_waiting
                        .entry(*included_reference)
                        .or_default()
                        .insert(*block_reference);
                    if !self.blocks_pending.contains_key(included_reference) {
                        // add missing references if it is not available
                        // in both pending set and storage
                        missing_references.insert(*included_reference);
                        self.missing[included_reference.authority as usize]
                            .insert(*included_reference);
                    }
                }
            }
            self.missing[block_reference.authority as usize].remove(block_reference);

            if !processed {
                self.blocks_pending.insert(*block_reference, block);
            } else {
                let block_reference = *block_reference;

                // Defer DAG insertion — will be done in batch after the loop.
                let insert_index = blocks_to_insert.len();
                blocks_to_insert.push(block.clone());
                block_exists_cache.insert(block_reference, true);
                let processed_index = newly_processed.len();
                newly_processed.push(block);
                new_blocks_in_batch.insert(block_reference, (insert_index, processed_index));

                // Now unlock any pending blocks, and process them if ready.
                if let Some(waiting_references) =
                    self.block_references_waiting.remove(&block_reference)
                {
                    // For each reference see if it's unblocked.
                    for waiting_block_reference in waiting_references {
                        let block_pointer =
                            self.blocks_pending.get(&waiting_block_reference).expect(
                                "Safe since we ensure the block \
                                waiting reference has a valid \
                                primary key.",
                            );

                        if block_pointer
                            .block_references()
                            .iter()
                            .all(|item_ref| !self.block_references_waiting.contains_key(item_ref))
                        {
                            // No dependencies are left unprocessed,
                            // so remove from unprocessed list, and
                            // add to the blocks we are processing now.
                            let block =
                                self.blocks_pending.remove(&waiting_block_reference).expect(
                                    "Safe since we ensure the block \
                                    waiting reference has a valid \
                                    primary key.",
                                );
                            blocks.push_front(block);
                        }
                    }
                }
            }
        }

        // Batch-insert all collected blocks under a single DAG write lock.
        dag_state.insert_general_blocks(blocks_to_insert, source);

        (
            newly_processed,
            updated_existing_with_transactions,
            missing_references,
        )
    }

    pub fn missing_blocks(&self) -> &[AHashSet<BlockReference>] {
        &self.missing
    }

    pub fn missing_block_references(&self) -> Vec<BlockReference> {
        let mut missing: Vec<_> = self
            .missing
            .iter()
            .flat_map(|missing_set| missing_set.iter().copied())
            .collect();
        missing.sort_unstable();
        missing.dedup();
        missing
    }

    pub fn pending_blocks_count(&self) -> usize {
        self.blocks_pending.len()
    }

    /// Pending cleanup is intentionally disabled. For the current short-lived
    /// testnet/benchmark environment we prefer retaining dependency state over
    /// evicting unresolved chains from the block manager.
    pub fn cleanup(&mut self, _threshold_round: RoundNumber) {}
}

#[cfg(test)]
mod tests {
    use prometheus::Registry;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        config::{DisseminationMode, StorageBackend},
        crypto,
        dag_state::ConsensusProtocol,
        metrics::Metrics,
        types::{AuthorityIndex, BlockAuthorizer},
    };

    fn open_mac_dag_state(committee: Arc<Committee>, path: &std::path::Path) -> DagState {
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("starfish-mac"),
            None,
        );
        DagState::open(
            0,
            path,
            metrics,
            committee,
            "honest".to_string(),
            "starfish-mac".to_string(),
            &StorageBackend::Rocksdb,
            false,
            DisseminationMode::ProtocolDefault,
        )
        .dag_state
    }

    fn make_mac_block(
        keyrings: &[Vec<crypto::MacKey>],
        authority: AuthorityIndex,
        round: RoundNumber,
        parents: Vec<BlockReference>,
    ) -> VerifiedBlock {
        let mut block = VerifiedBlock::new_with_authorizer_and_unprovable(
            authority,
            round,
            parents,
            None,
            Vec::new(),
            0,
            &BlockAuthorizer::MacVector(&keyrings[authority as usize]),
            None,
            None,
            Vec::new(),
            Vec::new(),
            None,
            ConsensusProtocol::Starfish,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        block.preserialize();
        block
    }

    #[test]
    fn block_manager_upgrades_stored_batched_and_pending_mac_copies() {
        let committee = Committee::new_for_benchmarks(4);
        let keyrings = crypto::mac_keyrings_for_test(committee.len());
        let temp_dir = TempDir::new().unwrap();
        let dag_state = open_mac_dag_state(committee.clone(), temp_dir.path());
        let mut manager = BlockManager::new(dag_state.clone(), &committee);
        let genesis: Vec<_> = committee
            .authorities()
            .map(|authority| BlockReference::new_test(authority, 0))
            .collect();

        // A stored tag-only copy is upgraded when the author's full vector
        // arrives later, without reporting another newly processed block.
        let full = make_mac_block(&keyrings, 1, 1, genesis.clone());
        let reference = *full.reference();
        let mut tagged = full.with_recipient_mac(0).unwrap();
        tagged.preserialize();
        assert_eq!(
            manager
                .add_blocks(vec![Data::new(tagged)], DataSource::BlockBundleStreaming,)
                .0
                .len(),
            1
        );
        assert!(
            manager
                .add_blocks(vec![Data::new(full)], DataSource::BlockBundleStreaming,)
                .0
                .is_empty()
        );
        assert!(
            dag_state
                .get_storage_block(reference)
                .unwrap()
                .has_full_mac_vector()
        );

        // The same upgrade also works when both copies share one receive
        // batch and when the block is waiting on a missing parent.
        let parent = make_mac_block(&keyrings, 2, 1, genesis);
        let child = make_mac_block(&keyrings, 2, 2, vec![*parent.reference()]);
        let child_reference = *child.reference();
        let mut tagged_child = child.with_recipient_mac(0).unwrap();
        tagged_child.preserialize();
        manager.add_blocks(
            vec![Data::new(tagged_child), Data::new(child)],
            DataSource::BlockBundleStreaming,
        );
        assert_eq!(manager.pending_blocks_count(), 1);
        manager.add_blocks(vec![Data::new(parent)], DataSource::BlockBundleStreaming);
        assert_eq!(manager.pending_blocks_count(), 0);
        assert!(
            dag_state
                .get_storage_block(child_reference)
                .unwrap()
                .has_full_mac_vector()
        );
    }
}
