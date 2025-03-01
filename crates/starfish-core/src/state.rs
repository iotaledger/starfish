// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use crate::core::MetaStatement;
use crate::core::MetaStatement::Include;
use crate::rocks_store::RocksStore;
use crate::types::VerifiedStatementBlock;
use crate::{
    block_store::BlockStore, // Remove OwnBlockData
    data::Data,
    types::BlockReference,
};

pub struct RecoveredState {
    pub block_store: BlockStore,
    pub rocks_store: Arc<RocksStore>,
    pub unprocessed_blocks: Vec<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>,
    pub last_committed_leader: Option<BlockReference>,
    pub committed_blocks: HashSet<BlockReference>,
}

#[derive(Default)]
pub struct RecoveredStateBuilder {
    pending: BTreeMap<u64, MetaStatement>, // Use sequence number instead of WalPosition
    unprocessed_blocks: Vec<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>,
    last_committed_leader: Option<BlockReference>,
    committed_blocks: HashSet<BlockReference>,
}

impl RecoveredStateBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn block(
        &mut self,
        sequence: u64,
        storage_and_transmission_blocks: (
            Data<VerifiedStatementBlock>,
            Data<VerifiedStatementBlock>,
        ),
    ) {
        self.pending.insert(
            sequence,
            Include(*storage_and_transmission_blocks.0.reference()),
        );
        self.unprocessed_blocks
            .push(storage_and_transmission_blocks);
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
