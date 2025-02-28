// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use parking_lot::Mutex;

use crate::committee::{QuorumThreshold, StakeAggregator};
use crate::consensus::linearizer::CommittedSubDag;
use crate::types::VerifiedStatementBlock;
use crate::{
    block_handler::BlockHandler,
    data::Data,
    syncer::{CommitObserver, Syncer, SyncerSignals},
    types::{AuthorityIndex, BlockReference, RoundNumber, StatementBlock},
};

pub struct CoreThreadDispatcher<H: BlockHandler, S: SyncerSignals, C: CommitObserver> {
    syncer: Mutex<Syncer<H, S, C>>,
}

impl<H: BlockHandler + 'static, S: SyncerSignals + 'static, C: CommitObserver + 'static>
    CoreThreadDispatcher<H, S, C>
{
    pub fn start(syncer: Syncer<H, S, C>) -> Self {
        Self {
            syncer: Mutex::new(syncer),
        }
    }

    pub fn stop(self) -> Syncer<H, S, C> {
        self.syncer.into_inner()
    }

    pub async fn add_blocks(
        &self,
        blocks: Vec<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>,
    ) -> (Vec<BlockReference>, HashSet<BlockReference>) {
        self.syncer.lock().add_blocks(blocks)
    }

    pub async fn force_new_block(&self, round: RoundNumber) {
        self.syncer.lock().force_new_block(round);
    }

    pub async fn force_commit(&self) {
        self.syncer.lock().try_new_commit();
    }

    pub async fn cleanup(&self) {
        self.syncer.lock().core().cleanup();
    }

    pub async fn get_missing_blocks(&self) -> Vec<HashSet<BlockReference>> {
        self.syncer
            .lock()
            .core()
            .block_manager()
            .missing_blocks()
            .to_vec()
    }

    pub async fn get_pending_blocks(
        &self,
    ) -> Vec<(CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>)> {
        self.syncer.lock().commit_observer().get_pending_blocks()
    }

    pub async fn authority_connection(&self, authority_index: AuthorityIndex, connected: bool) {
        let mut lock = self.syncer.lock();
        if connected {
            lock.connected_authorities.insert(authority_index);
        } else {
            lock.connected_authorities.remove(&authority_index);
        }
    }
}
