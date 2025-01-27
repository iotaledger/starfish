// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashSet};
use minibytes::Bytes;

use crate::{
    block_store::{BlockStore, CommitData},  // Remove OwnBlockData
    core::MetaStatement,
    data::Data,
    types::{BlockReference},
    // Remove wal import
};
use crate::types::VerifiedStatementBlock;

pub struct RecoveredState {
    pub block_store: BlockStore,
    // Remove last_own_block: Option<OwnBlockData>,
    // Remove pending: Vec<(WalPosition, MetaStatement)>,
    pub state: Option<Bytes>,
    pub unprocessed_blocks: Vec<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>,
    pub last_committed_leader: Option<BlockReference>,
    pub committed_blocks: HashSet<BlockReference>,
    pub committed_state: Option<Bytes>,
}

#[derive(Default)]
pub struct RecoveredStateBuilder {
    pending: BTreeMap<u64, RawMetaStatement>,  // Use sequence number instead of WalPosition
    // Remove last_own_block
    state: Option<Bytes>,
    unprocessed_blocks: Vec<(Data<VerifiedStatementBlock>,Data<VerifiedStatementBlock>)>,
    last_committed_leader: Option<BlockReference>,
    committed_blocks: HashSet<BlockReference>,
    committed_state: Option<Bytes>,
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

    pub fn payload(&mut self, sequence: u64, payload: Bytes) {
        self.pending.insert(sequence, RawMetaStatement::Payload(payload));
    }

    // Remove own_block method as it's RocksDB specific now

    pub fn state(&mut self, state: Bytes) {
        self.state = Some(state);
        self.unprocessed_blocks.clear();
    }

    pub fn commit_data(&mut self, commits: Vec<CommitData>, committed_state: Bytes) {
        for commit_data in commits {
            self.last_committed_leader = Some(commit_data.leader);
            self.committed_blocks
                .extend(commit_data.sub_dag.into_iter());
        }
        self.committed_state = Some(committed_state);
    }

    pub fn build(self, block_store: BlockStore) -> RecoveredState {
        let pending_meta = self
            .pending
            .into_iter()
            .map(|(_, raw)| raw.into_meta_statement())
            .collect();

        RecoveredState {
            block_store,
            state: self.state,
            unprocessed_blocks: self.unprocessed_blocks,
            last_committed_leader: self.last_committed_leader,
            committed_blocks: self.committed_blocks,
            committed_state: self.committed_state,
        }
    }
}

// RawMetaStatement remains the same

enum RawMetaStatement {
    Include(BlockReference),
    Payload(Bytes),
}

impl RawMetaStatement {
    fn into_meta_statement(self) -> MetaStatement {
        match self {
            RawMetaStatement::Include(include) => MetaStatement::Include(include),
            RawMetaStatement::Payload(payload) => MetaStatement::Payload(
                bincode::deserialize(&payload).expect("Failed to deserialize payload"),
            ),
        }
    }
}
