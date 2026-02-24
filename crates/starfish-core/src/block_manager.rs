// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use crate::types::VerifiedStatementBlock;
use crate::{block_store::BlockStore, committee::Committee, data::Data, types::BlockReference};

/// Block manager suspends incoming blocks until they are connected to the existing graph,
/// returning newly connected blocks
pub struct BlockManager {
    /// Keeps all pending blocks.
    blocks_pending:
        HashMap<BlockReference, (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>,
    /// Keeps all the blocks (`HashSet<BlockReference>`) waiting for `BlockReference` to be processed.
    block_references_waiting: HashMap<BlockReference, HashSet<BlockReference>>,
    /// Keeps all blocks that need to be synced in order to unblock the processing of other pending
    /// blocks. The indices of the vector correspond the authority indices.
    missing: Vec<HashSet<BlockReference>>,
    block_store: BlockStore,
}

impl BlockManager {
    pub fn new(block_store: BlockStore, committee: &Arc<Committee>) -> Self {
        Self {
            blocks_pending: Default::default(),
            block_references_waiting: Default::default(),
            missing: (0..committee.len()).map(|_| HashSet::new()).collect(),
            block_store,
        }
    }

    pub fn add_blocks(
        &mut self,
        blocks: Vec<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>,
    ) -> (
        Vec<Data<VerifiedStatementBlock>>,
        bool,
        HashSet<BlockReference>,
    ) {
        let block_store = self.block_store.clone();
        let mut updated_statements = false;
        let mut blocks: VecDeque<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)> =
            blocks.into();
        let mut newly_storage_blocks_processed: Vec<Data<VerifiedStatementBlock>> = vec![];
        // missing references that we don't currently have
        let mut missing_references = HashSet::new();
        while let Some(storage_and_transmission_blocks) = blocks.pop_front() {
            // check whether we have already processed this block and skip it if so.
            let block_reference = storage_and_transmission_blocks.0.reference();

            let block_exists = self.block_store.block_exists(*block_reference);
            if block_exists {
                // Block already in store — check if this version brings new statement data
                if self
                    .block_store
                    .contains_new_statements(&storage_and_transmission_blocks.0)
                {
                    tracing::debug!("Block has new statements: {:?}", block_reference);
                    block_store.insert_general_block(storage_and_transmission_blocks.clone());
                    newly_storage_blocks_processed
                        .push(storage_and_transmission_blocks.0.clone());
                    updated_statements = true;
                }
                continue;
            }

            if self.blocks_pending.contains_key(block_reference) {
                if storage_and_transmission_blocks.0.statements().is_some() {
                    self.blocks_pending
                        .insert(*block_reference, storage_and_transmission_blocks);
                }

                continue;
            }

            let mut processed = true;
            for included_reference in storage_and_transmission_blocks.0.includes() {
                // If we are missing a reference then we insert into pending and update the waiting index
                if !self.block_store.block_exists(*included_reference) {
                    processed = false;

                    self.block_references_waiting
                        .entry(*included_reference)
                        .or_default()
                        .insert(*block_reference);
                    if !self.blocks_pending.contains_key(included_reference) {
                        // add missing references if it is not available in both pending set and storage
                        missing_references.insert(*included_reference);
                        self.missing[included_reference.authority as usize]
                            .insert(*included_reference);
                    }
                }
            }
            self.missing[block_reference.authority as usize].remove(block_reference);

            if !processed {
                self.blocks_pending
                    .insert(*block_reference, storage_and_transmission_blocks);
            } else {
                let block_reference = *block_reference;

                // Block can be processed. So need to update indexes etc
                block_store.insert_general_block(storage_and_transmission_blocks.clone());
                newly_storage_blocks_processed.push(storage_and_transmission_blocks.0.clone());

                // Now unlock any pending blocks, and process them if ready.
                if let Some(waiting_references) =
                    self.block_references_waiting.remove(&block_reference)
                {
                    // For each reference see if it's unblocked.
                    for waiting_block_reference in waiting_references {
                        let block_pointer = self.blocks_pending.get(&waiting_block_reference).expect("Safe since we ensure the block waiting reference has a valid primary key.");

                        if block_pointer
                            .0
                            .includes()
                            .iter()
                            .all(|item_ref| !self.block_references_waiting.contains_key(item_ref))
                        {
                            // No dependencies are left unprocessed, so remove from unprocessed list, and add to the
                            // blocks we are processing now.
                            let block = self.blocks_pending.remove(&waiting_block_reference).expect("Safe since we ensure the block waiting reference has a valid primary key.");
                            blocks.push_front(block);
                        }
                    }
                }
            }
        }

        (
            newly_storage_blocks_processed,
            updated_statements,
            missing_references,
        )
    }

    pub fn missing_blocks(&self) -> &[HashSet<BlockReference>] {
        &self.missing
    }
}
