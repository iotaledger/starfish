// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use crate::{
    block_store::{BlockStore, CommitData},  // Remove OwnBlockData
    data::Data,
    types::{BlockReference},
    // Remove wal import
};
use crate::rocks_store::RocksStore;
use crate::types::VerifiedStatementBlock;

pub struct RecoveredState {
    pub block_store: BlockStore,
    pub rocks_store: Arc<RocksStore>,
    pub unprocessed_blocks: Vec<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>,
    pub last_committed_leader: Option<BlockReference>,
    pub committed_blocks: HashSet<BlockReference>,
}

#[derive(Default)]
pub struct RecoveredStateBuilder {
    pending: BTreeMap<u64, RawMetaStatement>,  // Use sequence number instead of WalPosition
    unprocessed_blocks: Vec<(Data<VerifiedStatementBlock>,Data<VerifiedStatementBlock>)>,
    last_committed_leader: Option<BlockReference>,
    committed_blocks: HashSet<BlockReference>,
}

impl RecoveredStateBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn block(&mut self, sequence: u64, storage_and_transmission_blocks: (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)) {
        self.pending
            .insert(sequence, RawMetaStatement::Include(*storage_and_transmission_blocks.0.reference()));
        self.unprocessed_blocks.push(storage_and_transmission_blocks);
    }


    pub fn commit_data(&mut self, commits: Vec<CommitData>) {
        for commit_data in commits {
            self.last_committed_leader = Some(commit_data.leader);
            self.committed_blocks
                .extend(commit_data.sub_dag.into_iter());
        }
    }

    pub fn build(self, rocks_store: Arc<RocksStore>, block_store: BlockStore) -> RecoveredState {
        RecoveredState {
            block_store,
            rocks_store,
            unprocessed_blocks: self.unprocessed_blocks,
            last_committed_leader: self.last_committed_leader,
            committed_blocks: self.committed_blocks,
        }
    }
}

enum RawMetaStatement {
    Include(BlockReference),
}

