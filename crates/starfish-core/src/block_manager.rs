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
    dag_state::DagState,
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
        // missing references that we don't currently have
        let mut missing_references = AHashSet::new();
        let mut block_exists_cache: AHashMap<BlockReference, bool> = AHashMap::new();
        while let Some(block) = blocks.pop_front() {
            let block_reference = block.reference();

            if let Some(existing_pending_block) = self.blocks_pending.get_mut(block_reference) {
                if block.transactions().is_some() {
                    *existing_pending_block = block;
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
                    blocks_to_insert.push(block.clone());
                    updated_existing_with_transactions.push(block);
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
                blocks_to_insert.push(block.clone());
                block_exists_cache.insert(block_reference, true);
                newly_processed.push(block);

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
        dag_state.insert_general_blocks(blocks_to_insert);

        (
            newly_processed,
            updated_existing_with_transactions,
            missing_references,
        )
    }

    pub fn missing_blocks(&self) -> &[AHashSet<BlockReference>] {
        &self.missing
    }

    pub fn pending_blocks_count(&self) -> usize {
        self.blocks_pending.len()
    }

    /// Evict all pending/missing entries below the given threshold to prevent
    /// unbounded growth from permanently-missing blocks (e.g. byzantine
    /// validators referencing parents they never broadcast).
    ///
    /// When a parent entry is evicted from `block_references_waiting`, all
    /// child blocks that depended on it are recursively removed from
    /// `blocks_pending` (cascade removal) — otherwise they would be stuck
    /// forever with no dependency tracking.
    pub fn cleanup(&mut self, threshold_round: RoundNumber) {
        let split_ref = BlockReference {
            round: threshold_round,
            authority: 0,
            digest: Default::default(),
        };

        // `split_off` returns entries >= split_ref, leaving < split_ref in
        // the original. Swap so `evicted_parents` holds the old entries.
        let kept = self.block_references_waiting.split_off(&split_ref);
        let evicted_parents = std::mem::replace(&mut self.block_references_waiting, kept);

        // Cascade: remove children that depended on evicted parents, and
        // recursively remove their dependents too.
        let mut to_remove: Vec<BlockReference> = evicted_parents
            .into_values()
            .flat_map(|children| children.into_iter())
            .collect();

        while let Some(child_ref) = to_remove.pop() {
            self.blocks_pending.remove(&child_ref);
            if let Some(grandchildren) = self.block_references_waiting.remove(&child_ref) {
                to_remove.extend(grandchildren);
            }
        }

        // Evict remaining old pending blocks (roots with no dependents).
        self.blocks_pending = self.blocks_pending.split_off(&split_ref);

        // Clean missing sets.
        for missing_set in &mut self.missing {
            missing_set.retain(|r| r.round >= threshold_round);
        }
    }
}
