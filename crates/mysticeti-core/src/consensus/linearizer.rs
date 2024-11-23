// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, fmt};
use std::cmp::max;
use std::collections::HashMap;
use crate::{
    block_store::BlockStore,
    data::Data,
    types::{BlockReference, StatementBlock},
};
use crate::committee::{Committee, QuorumThreshold, StakeAggregator};
use crate::types::RoundNumber;

/// The output of consensus is an ordered list of [`CommittedSubDag`]. The application can arbitrarily
/// sort the blocks within each sub-dag (but using a deterministic algorithm).
pub struct CommittedSubDag {
    /// A reference to the anchor of the sub-dag
    pub anchor: BlockReference,
    /// All the committed blocks that are part of this sub-dag
    pub blocks: Vec<Data<StatementBlock>>,
}

impl CommittedSubDag {
    /// Create new (empty) sub-dag.
    pub fn new(anchor: BlockReference, blocks: Vec<Data<StatementBlock>>) -> Self {
        Self { anchor, blocks }
    }

    /// Sort the blocks of the sub-dag by round number. Any deterministic algorithm works.
    pub fn sort(&mut self) {
        self.blocks.sort_by_key(|x| x.round());
    }
}

/// Expand a committed sequence of leader into a sequence of sub-dags.
pub struct Linearizer {
    /// Keep track of all committed blocks to avoid committing the same block twice.
    pub committed: HashSet<BlockReference>,
    pub committee: Committee,
}

impl Linearizer {
    pub fn new(committee: Committee) -> Self {
        Self {
            committed:  HashSet::new(),
            committee,
        }
    }

    /// Collect the sub-dag from a specific anchor excluding any duplicates or blocks that
    /// have already been committed (within previous sub-dags).
    fn collect_sub_dag(
        &mut self,
        block_store: &BlockStore,
        leader_block: Data<StatementBlock>,
    ) -> CommittedSubDag {
        let mut to_commit = Vec::new();

        let leader_block_ref = *leader_block.reference();
        let mut buffer = vec![leader_block];
        assert!(self.committed.insert(leader_block_ref));
        while let Some(x) = buffer.pop() {
            to_commit.push(x.clone());
            for reference in x.includes() {
                // The block manager may have cleaned up blocks passed the latest committed rounds.
                let block = block_store
                    .get_block(*reference)
                    .expect("We should have the whole sub-dag by now");

                // Skip the block if we already committed it (either as part of this sub-dag or
                // a previous one).
                if self.committed.insert(*reference) {
                    buffer.push(block);
                }
            }
        }
        CommittedSubDag::new(leader_block_ref, to_commit)
    }

    // Collect all blocks in the history of committed leader that have a quorum of blocks
    // acknowledging them.
    fn collect_committed_blocks_in_history(
        &mut self,
        block_store: &BlockStore,
        leader_block: Data<StatementBlock>,
    ) -> CommittedSubDag {
        tracing::debug!("Starting collection with leader {:?}", leader_block);
        let maximal_depth_below_leader: u64 = 50;
        let leader_block_ref = *(leader_block.reference());
        let minimal_round_to_collect: RoundNumber =  leader_block.round().saturating_sub(maximal_depth_below_leader);
        let mut buffer = vec![leader_block];
        let mut buffer_track = HashSet::new();
        buffer_track.insert(leader_block_ref);
        let mut votes: HashMap<BlockReference, StakeAggregator<QuorumThreshold>> = HashMap::new();
        while let Some(x) = buffer.pop() {
            tracing::debug!("Buffer popped {}", x.reference());
            let who_votes = x.reference().authority;
            for acknowledgement in x.acknowledgement_statements() {
                if acknowledgement.round < minimal_round_to_collect {
                    continue;
                }
                // Todo the authority creating the block might automatically acknowledge for its block
                votes.entry(*acknowledgement).or_insert_with(StakeAggregator::new).add(who_votes, &self.committee);
            }
            for reference in x.includes() {
                // Skip the block if it is too far back
                if reference.round < minimal_round_to_collect || buffer_track.contains(reference){
                    continue;
                }
                let block = block_store
                    .get_block(*reference)
                    .expect("We should have the whole sub-dag by now");
                buffer_track.insert(*block.reference());
                buffer.push(block);
            }
        }
        let mut to_commit = Vec::new();
        for x in votes {
            if x.1.is_quorum(&self.committee){
                if self.committed.insert(x.0) {
                    let block = block_store
                        .get_block(x.0)
                        .expect("We should have the whole sub-dag by now");
                    to_commit.push(block);
                }

            }
        }
        CommittedSubDag::new(leader_block_ref, to_commit)
    }

    pub fn handle_commit(
        &mut self,
        block_store: &BlockStore,
        committed_leaders: Vec<Data<StatementBlock>>,
    ) -> Vec<CommittedSubDag> {
        let mut committed = vec![];
        for leader_block in committed_leaders {
            // Collect the sub-dag generated using each of these leaders as anchor.
            //let mut sub_dag = self.collect_sub_dag(block_store, leader_block);
            let mut sub_dag = self.collect_committed_blocks_in_history(block_store, leader_block);
            // [Optional] sort the sub-dag using a deterministic algorithm.
            sub_dag.sort();
            tracing::debug!("Committed sub DAG {:?}", sub_dag);
            committed.push(sub_dag);
        }
        committed
    }
}

impl fmt::Debug for CommittedSubDag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.anchor)?;
        for block in &self.blocks {
            write!(f, "{}, ", block.reference())?;
        }
        write!(f, ")")
    }
}
