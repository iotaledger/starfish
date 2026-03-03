// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use ahash::{AHashMap, AHashSet};

use crate::{
    committee::Committee,
    dag_state::DagState,
    data::Data,
    types::{BlockReference, VerifiedBlock},
};

/// Block manager suspends incoming blocks until they are connected to the
/// existing graph, returning newly connected blocks
pub struct BlockManager {
    /// Keeps all pending blocks.
    blocks_pending: HashMap<BlockReference, Data<VerifiedBlock>>,
    /// Keeps all the blocks (`AHashSet<BlockReference>`) waiting
    /// for `BlockReference` to be processed.
    block_references_waiting: HashMap<BlockReference, AHashSet<BlockReference>>,
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
        let mut updated_existing_with_statements: Vec<Data<VerifiedBlock>> = vec![];
        // missing references that we don't currently have
        let mut missing_references = AHashSet::new();
        let mut block_exists_cache: AHashMap<BlockReference, bool> = AHashMap::new();
        while let Some(block) = blocks.pop_front() {
            let block_reference = block.reference();

            if let Some(existing_pending_block) = self.blocks_pending.get_mut(block_reference) {
                if block.statements().is_some() {
                    *existing_pending_block = block;
                }
                continue;
            }

            let block_exists = *block_exists_cache
                .entry(*block_reference)
                .or_insert_with(|| self.dag_state.block_exists(*block_reference));
            if block_exists {
                // Block already in store — check if this version brings new statement data
                if self.dag_state.contains_new_statements(&block) {
                    tracing::debug!("Block has new statements: {:?}", block_reference);
                    dag_state.insert_general_block(block.clone());
                    updated_existing_with_statements.push(block);
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

                // Block can be processed. So need to update indexes etc
                dag_state.insert_general_block(block.clone());
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

        (
            newly_processed,
            updated_existing_with_statements,
            missing_references,
        )
    }

    pub fn missing_blocks(&self) -> &[AHashSet<BlockReference>] {
        &self.missing
    }
}
