// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use ahash::AHashSet;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::core::MetaStatement;
use crate::core::MetaStatement::Include;
use crate::dag_state::CommitData;
use crate::rocks_store::RocksStore;
use crate::types::VerifiedStatementBlock;
use crate::{
    dag_state::DagState, // Remove OwnBlockData
    data::Data,
    types::BlockReference,
};

pub struct RecoveredState {
    pub dag_state: DagState,
    pub rocks_store: Arc<RocksStore>,
    pub unprocessed_blocks: Vec<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>,
    pub last_committed_leader: Option<BlockReference>,
    pub committed_blocks: AHashSet<BlockReference>,
}

#[derive(Default)]
pub struct RecoveredStateBuilder {
    pending: BTreeMap<u64, MetaStatement>, // Use sequence number instead of WalPosition
    unprocessed_blocks: Vec<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>,
    last_committed_leader: Option<BlockReference>,
    committed_blocks: AHashSet<BlockReference>,
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

    pub fn commit(&mut self, commit_data: CommitData) {
        let leader = commit_data.leader;
        if self
            .last_committed_leader
            .map(|current| leader.round > current.round)
            .unwrap_or(true)
        {
            self.last_committed_leader = Some(leader);
        }
        self.committed_blocks.extend(commit_data.sub_dag);
    }

    pub fn build(self, rocks_store: Arc<RocksStore>, dag_state: DagState) -> RecoveredState {
        RecoveredState {
            dag_state,
            rocks_store,
            unprocessed_blocks: self.unprocessed_blocks,
            last_committed_leader: self.last_committed_leader,
            committed_blocks: self.committed_blocks,
        }
    }
}
