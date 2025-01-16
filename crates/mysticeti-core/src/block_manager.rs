// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use crate::{
    block_store::{BlockStore, BlockWriter},
    committee::Committee,
    data::Data,
    types::{BlockReference},
    wal::WalPosition,
};
use crate::types::VerifiedStatementBlock;

/// Block manager suspends incoming blocks until they are connected to the existing graph,
/// returning newly connected blocks
pub struct BlockManager {
    /// Keeps all pending blocks.
    blocks_pending: HashMap<BlockReference, (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>,
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
        block_writer: &mut impl BlockWriter,
    ) -> (Vec<(WalPosition, Data<VerifiedStatementBlock>)>, HashSet<BlockReference>, bool) {
        let mut updated_statements = false;
        let mut blocks: VecDeque<(Data<VerifiedStatementBlock>,Data<VerifiedStatementBlock>)> = blocks.into();
        let mut newly_storage_blocks_processed: Vec<(WalPosition, Data<VerifiedStatementBlock>)> = vec![];
        let mut recoverable_blocks: HashSet<BlockReference> = HashSet::new();
        while let Some(storage_and_transmission_blocks) = blocks.pop_front() {
            // check whether we have already processed this block and skip it if so.
            let block_reference = storage_and_transmission_blocks.0.reference();
            if self.blocks_pending.contains_key(block_reference) {
                continue;
            }
            let block_exists = self.block_store.block_exists(*block_reference);
            if block_exists
            {
                let contains_new_shard_or_header =  self.block_store.contains_new_shard_or_header(&storage_and_transmission_blocks.0);
                if contains_new_shard_or_header {
                    if storage_and_transmission_blocks.0.statements().is_some() {
                        // Block can be processed. So need to update indexes etc
                        let position = block_writer.insert_block(storage_and_transmission_blocks.clone());
                        newly_storage_blocks_processed.push((position, storage_and_transmission_blocks.0.clone()));
                        updated_statements = true;
                        self.block_store.updated_unknown_by_others(storage_and_transmission_blocks.0.reference().clone());
                        recoverable_blocks.remove(storage_and_transmission_blocks.0.reference());
                    } else {
                        self.block_store.update_with_new_shard(&storage_and_transmission_blocks.0);
                        if self.block_store.is_sufficient_shards(storage_and_transmission_blocks.0.reference()) {
                            recoverable_blocks.insert(storage_and_transmission_blocks.0.reference().clone());
                        }
                    }
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
                        self.missing[included_reference.authority as usize]
                            .insert(*included_reference);
                    }
                }
            }
            self.missing[block_reference.authority as usize].remove(block_reference);

            if !processed {
                self.blocks_pending.insert(*block_reference, storage_and_transmission_blocks);
            } else {
                let block_reference = *block_reference;

                // Block can be processed. So need to update indexes etc
                let position = block_writer.insert_block(storage_and_transmission_blocks.clone());
                newly_storage_blocks_processed.push((position, storage_and_transmission_blocks.0.clone()));

                // Now unlock any pending blocks, and process them if ready.
                if let Some(waiting_references) =
                    self.block_references_waiting.remove(&block_reference)
                {
                    // For each reference see if it's unblocked.
                    for waiting_block_reference in waiting_references {
                        let block_pointer = self.blocks_pending.get(&waiting_block_reference).expect("Safe since we ensure the block waiting reference has a valid primary key.");

                        if block_pointer.0
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

        (newly_storage_blocks_processed, recoverable_blocks, updated_statements)
    }

    pub fn missing_blocks(&self) -> &[HashSet<BlockReference>] {
        &self.missing
    }
}

#[cfg(test)]
mod tests {
    use rand::{prelude::StdRng, SeedableRng};

    use super::*;
    use crate::{test_util::TestBlockWriter, types::Dag};

    #[test]
    fn test_block_manager_add_block() {
        let dag =
            Dag::draw("A1:[A0, B0]; B1:[A0, B0]; B2:[A0, B1]; A2:[A1, B2]").add_genesis_blocks();
        assert_eq!(dag.len(), 6); // 4 blocks in dag + 2 genesis
        for seed in 0..100u8 {
            let mut block_writer = TestBlockWriter::new(&dag.committee());
            println!("Seed {seed}");
            let iter = dag.random_iter(&mut rng(seed));
            let mut bm = BlockManager::new(block_writer.block_store(), &dag.committee());
            let mut processed_blocks = HashSet::new();
            for block in iter {
                let processed = bm.add_blocks(vec![(block.clone(),block.clone())], &mut block_writer).0;
                print!("Adding {:?}:", block.reference());
                for (_, p) in processed {
                    print!("{:?},", p.reference());
                    if !processed_blocks.insert(p.reference().clone()) {
                        panic!("Block {:?} processed twice", p.reference());
                    }
                }
                println!();
            }
            assert_eq!(bm.block_references_waiting.len(), 0);
            assert_eq!(bm.blocks_pending.len(), 0);
            assert_eq!(processed_blocks.len(), dag.len());
            assert_eq!(bm.block_store.len_expensive(), dag.len());
            println!("======");
        }
    }

    fn rng(s: u8) -> StdRng {
        let mut seed = [0; 32];
        seed[0] = s;
        StdRng::from_seed(seed)
    }
}
