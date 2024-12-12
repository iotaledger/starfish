// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, fmt};
use std::collections::HashMap;
use std::sync::Arc;
use crate::{
    block_store::BlockStore,
    data::Data,
    types::{BlockReference, StatementBlock},
};
use crate::committee::{Committee, QuorumThreshold, StakeAggregator};
use crate::types::VerifiedStatementBlock;

/// The output of consensus is an ordered list of [`CommittedSubDag`]. The application can arbitrarily
/// sort the blocks within each sub-dag (but using a deterministic algorithm).
pub struct CommittedSubDag {
    /// A reference to the anchor of the sub-dag
    pub anchor: BlockReference,
    /// All the committed blocks that are part of this sub-dag
    pub blocks: Vec<Arc<VerifiedStatementBlock>>,
}

impl CommittedSubDag {
    /// Create new (empty) sub-dag.
    pub fn new(anchor: BlockReference, blocks: Vec<Arc<VerifiedStatementBlock>>) -> Self {
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
    pub traversed_blocks: HashSet<BlockReference>,
    pub votes: HashMap<BlockReference, StakeAggregator<QuorumThreshold>>,
    pub committee: Committee,
}

impl Linearizer {
    pub fn new(committee: Committee) -> Self {
        Self {
            committed:  HashSet::new(),
            traversed_blocks: HashSet::new(),
            votes: HashMap::new(),
            committee,
        }
    }
    // Collect all blocks in the history of committed leader that have a quorum of blocks
    // acknowledging them.
    fn collect_committed_blocks_in_history(
        &mut self,
        block_store: &BlockStore,
        leader_block: Arc<VerifiedStatementBlock>,
    ) -> CommittedSubDag {
        tracing::debug!("Starting collection with leader {:?}", leader_block);
        let leader_block_ref = *(leader_block.reference());
        let mut buffer = vec![leader_block];
        let mut blocks_transaction_data_quorum = vec![];
        while let Some(x) = buffer.pop() {
            tracing::debug!("Buffer popped {}", x.reference());
            let who_votes = x.reference().authority;
            for acknowledgement_statement in x.acknowledgement_statements() {
                // Todo the authority creating the block might automatically acknowledge for its block

                let s = self.votes.entry(*acknowledgement_statement).or_insert_with(StakeAggregator::new);
                if !s.is_quorum(&self.committee) {
                    if s.add(who_votes, &self.committee) {
                        blocks_transaction_data_quorum.push(*acknowledgement_statement);
                    }
                }
            }
            self.traversed_blocks.insert(*x.reference());
            for reference in x.includes() {
                // Skip the block if it is too far back
                if  self.traversed_blocks.contains(reference){
                    continue;
                }
                let block = block_store
                    .get_block(*reference)
                    .expect("We should have the whole sub-dag by now");
                buffer.push(block);
            }
        }
        let mut to_commit = Vec::new();
        for x in blocks_transaction_data_quorum {
            if self.committed.insert(x) {
                let block = block_store
                    .get_block(x)
                    .expect("We should have the whole sub-dag by now");
                to_commit.push(block);
            }
        }

        // Filter the commitment and include only block from each slot (author, round)
        let mut to_commit: Vec<_> = to_commit
            .into_iter()
            .map(|block| {
                // Assuming block has `round`, `author`, and `digest` methods/properties
                let round = block.round();
                let author = block.author(); // Adjust if `author` is not clonable
                let digest = block.digest(); // Adjust if `digest` is not clonable
                (round, author, digest, block) // Store the original block as part of the tuple
            })
            .collect();

        // Sort by (round, author, digest)
        to_commit.sort_by(|a, b| {
            a.0.cmp(&b.0) // Sort by round
                .then(a.1.cmp(&b.1)) // Then by author
                .then(a.2.cmp(&b.2)) // Finally by digest
        });

        // Select at most one block per (round, author)
        let mut seen_round_author = HashSet::new();
        let to_commit: Vec<_> = to_commit
            .into_iter()
            .filter_map(|(round, author, _, block)| {
                // Keep only the first occurrence of each (round, author) pair
                if seen_round_author.insert((round, author.clone())) {
                    Some(block)
                } else {
                    None
                }
            })
            .collect();

        CommittedSubDag::new(leader_block_ref, to_commit)
    }

    pub fn handle_commit(
        &mut self,
        block_store: &BlockStore,
        committed_leaders: Vec<Arc<VerifiedStatementBlock>>,
    ) -> Vec<CommittedSubDag> {
        let mut committed = vec![];
        for leader_block in committed_leaders {
            // Collect the sub-dag generated using each of these leaders as anchor.
           let mut sub_dag = self.collect_committed_blocks_in_history(block_store, leader_block);
           //let mut sub_dag = self.collect_sub_dag(block_store, leader_block);
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
