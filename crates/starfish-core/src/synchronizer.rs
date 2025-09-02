// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::block_store::{ByzantineStrategy, ConsensusProtocol};
use crate::consensus::universal_committer::UniversalCommitter;
use crate::metrics::UtilizationTimerVecExt;
use crate::types::format_authority_index;
use crate::{
    block_handler::BlockHandler,
    metrics::Metrics,
    net_sync::NetworkSyncerInner,
    network::NetworkMessage,
    runtime::{sleep, Handle},
    syncer::CommitObserver,
    types::{AuthorityIndex, BlockReference, RoundNumber},
};
use futures::future::join_all;
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};
use std::cmp::max;
use std::collections::HashSet;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::select;
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tokio::time::Instant;

#[derive(Clone)]
pub struct SynchronizerParameters {
    /// The number of own blocks to send in a single batch.
    pub batch_own_block_size: usize,
    /// The number of other blocks to send in a single batch.
    pub batch_other_block_size: usize,
    /// The sampling precision with which to re-evaluate the sync strategy.
    pub sample_timeout: Duration,
    /// The maximum age of missing blocks to push the respected block to peers
    pub max_missing_blocks_age: Duration,
}

impl SynchronizerParameters {
    pub fn new(committee_size: usize, consensus_protocol: ConsensusProtocol) -> Self {
        match consensus_protocol {
            ConsensusProtocol::Mysticeti => Self {
                batch_own_block_size: committee_size,
                batch_other_block_size: 3 * committee_size,
                sample_timeout: Duration::from_millis(600),
                max_missing_blocks_age: Duration::from_secs(2),
            },
            ConsensusProtocol::StarfishPull
            | ConsensusProtocol::Starfish
            | ConsensusProtocol::CordialMiners => Self {
                batch_own_block_size: committee_size,
                batch_other_block_size: committee_size * committee_size,
                sample_timeout: Duration::from_millis(600),
                max_missing_blocks_age: Duration::from_secs(2),
            },
        }
    }
}

impl Default for SynchronizerParameters {
    fn default() -> Self {
        Self {
            batch_own_block_size: 8,
            batch_other_block_size: 128,
            sample_timeout: Duration::from_millis(600),
            max_missing_blocks_age: Duration::from_millis(2000),
        }
    }
}

pub struct BlockDisseminator<H: BlockHandler, C: CommitObserver> {
    to_whom_authority_index: AuthorityIndex,
    /// The sender to the network.
    sender: mpsc::Sender<NetworkMessage>,
    /// Universal Committer. This is needed for Byzantine nodes to control when to send the blocks
    universal_committer: UniversalCommitter,
    /// The inner state of the network syncer.
    inner: Arc<NetworkSyncerInner<H, C>>,
    /// The handle of the task disseminating our own blocks.
    own_blocks: Option<JoinHandle<Option<()>>>,
    /// The handle of the task disseminating all unknown blocks.
    push_blocks: Option<JoinHandle<Option<()>>>,
    /// The handle of the task disseminating all unknown blocks.
    response_push_blocks: Option<JoinHandle<Option<()>>>,
    /// The handles of tasks disseminating other nodes' blocks.
    other_blocks: Vec<JoinHandle<Option<()>>>,
    /// The parameters of the synchronizer.
    parameters: SynchronizerParameters,
    /// Metrics.
    metrics: Arc<Metrics>,
    /// List of authorities that have missing blocks when receiving blocks from me,
    authorities_with_missing_blocks_by_peer_from_me: Arc<RwLock<Vec<Instant>>>,
}

pub struct UpdaterMissingAuthorities {
    to_whom_authority_index: AuthorityIndex,
    /// The sender to the network.
    sender: Sender<NetworkMessage>,
    /// The handle of the task disseminating our own blocks.
    updater_handle: Option<JoinHandle<Option<()>>>,
    parameters: SynchronizerParameters,
    authorities_with_missing_blocks: Arc<RwLock<Vec<Instant>>>,
}

impl UpdaterMissingAuthorities {
    pub fn new(
        to_whom_authority_index: AuthorityIndex,
        sender: Sender<NetworkMessage>,
        parameters: SynchronizerParameters,
        authorities_with_missing_blocks: Arc<RwLock<Vec<Instant>>>,
    ) -> Self {
        Self {
            to_whom_authority_index,
            sender,
            updater_handle: None,
            parameters,
            authorities_with_missing_blocks,
        }
    }

    pub async fn shutdown(mut self) {
        let mut waiters = Vec::with_capacity(1);
        if let Some(handle) = self.updater_handle.take() {
            handle.abort();
            waiters.push(handle);
        }
        join_all(waiters).await;
    }

    pub async fn start(&mut self) {
        if let Some(existing) = self.updater_handle.take() {
            existing.abort();
            existing.await.ok();
        }
        let handle = Handle::current().spawn(Self::update_missing_authorities(
            self.to_whom_authority_index,
            self.sender.clone(),
            self.parameters.clone(),
            self.authorities_with_missing_blocks.clone(),
        ));
        self.updater_handle = Some(handle);
    }

    async fn update_missing_authorities(
        peer_id: AuthorityIndex,
        to: Sender<NetworkMessage>,
        parameters: SynchronizerParameters,
        authorities_with_missing_blocks: Arc<RwLock<Vec<Instant>>>,
    ) -> Option<()> {
        let peer = format_authority_index(peer_id);
        let sample_timeout = parameters.sample_timeout;
        loop {
            let now = Instant::now();
            let authorities_with_missing_blocks = authorities_with_missing_blocks.read().await;
            let mut authorities_to_send = Vec::new();
            for (idx, time) in authorities_with_missing_blocks.iter().enumerate() {
                if now.duration_since(*time) > sample_timeout {
                    authorities_to_send.push(idx as AuthorityIndex);
                }
            }
            if !authorities_to_send.is_empty() {
                tracing::debug!(
                    "Authorities with missing block {authorities_to_send:?} are sent to {peer}"
                );
                to.send(NetworkMessage::AuthoritiesWithMissingBlocks(
                    authorities_to_send,
                ))
                .await
                .ok()?;
            }
            let _sleep = sleep(sample_timeout).await;
        }
    }
}

pub struct DataRequestor<H: BlockHandler, C: CommitObserver> {
    to_whom_authority_index: AuthorityIndex,
    /// The sender to the network.
    sender: Sender<NetworkMessage>,
    inner: Arc<NetworkSyncerInner<H, C>>,
    /// The handle of the task disseminating our own blocks.
    data_requestor: Option<JoinHandle<Option<()>>>,
    parameters: SynchronizerParameters,
}

impl<H, C> DataRequestor<H, C>
where
    H: BlockHandler + 'static,
    C: CommitObserver + 'static,
{
    pub fn new(
        to_whom_authority_index: AuthorityIndex,
        sender: Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        parameters: SynchronizerParameters,
    ) -> Self {
        Self {
            to_whom_authority_index,
            sender,
            inner,
            data_requestor: None,
            parameters,
        }
    }

    pub async fn shutdown(mut self) {
        let mut waiters = Vec::with_capacity(1);
        if let Some(handle) = self.data_requestor.take() {
            handle.abort();
            waiters.push(handle);
        }
        join_all(waiters).await;
    }

    pub async fn start(&mut self) {
        if let Some(existing) = self.data_requestor.take() {
            existing.abort();
            existing.await.ok();
        }
        let handle = Handle::current().spawn(Self::request_missing_data_blocks(
            self.to_whom_authority_index,
            self.sender.clone(),
            self.inner.clone(),
            self.parameters.clone(),
        ));
        self.data_requestor = Some(handle);
    }

    async fn request_missing_data_blocks(
        peer_id: AuthorityIndex,
        to: Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        parameters: SynchronizerParameters,
    ) -> Option<()> {
        let peer = format_authority_index(peer_id);
        let own_id = inner.block_store.get_own_authority_index();
        let sample_timeout = parameters.sample_timeout;
        let upper_limit_request_size = parameters.batch_other_block_size;
        loop {
            let committed_dags = inner.block_store.read_pending_unavailable();
            let mut to_request = Vec::new();
            'commit_loop: for commit in &committed_dags {
                for (i, block) in commit.0.blocks.iter().enumerate() {
                    if block.round() > 0 {
                        let mut aggregator = commit.1[i].clone();
                        if aggregator.votes.insert(own_id)
                            && !aggregator.votes.insert(peer_id)
                            && !inner.block_store.is_data_available(block.reference())
                        {
                            tracing::debug!("Data in block {block:?} is missing");
                            to_request.push(*block.reference());
                        }
                    }
                }
                if to_request.len() >= upper_limit_request_size {
                    break 'commit_loop;
                }
            }
            if !to_request.is_empty() {
                tracing::debug!("Data from blocks {to_request:?} is requested from {peer}");
                to.send(NetworkMessage::MissingTxDataRequest(to_request))
                    .await
                    .ok()?;
            }
            let _sleep = sleep(sample_timeout).await;
        }
    }
}

impl<H, C> BlockDisseminator<H, C>
where
    H: BlockHandler + 'static,
    C: CommitObserver + 'static,
{
    pub fn new(
        to_whom_authority_index: AuthorityIndex,
        sender: mpsc::Sender<NetworkMessage>,
        universal_committer: UniversalCommitter,
        inner: Arc<NetworkSyncerInner<H, C>>,
        parameters: SynchronizerParameters,
        metrics: Arc<Metrics>,
        authorities_with_missing_blocks_by_peer_from_me: Arc<RwLock<Vec<Instant>>>,
    ) -> Self {
        Self {
            to_whom_authority_index,
            sender,
            universal_committer,
            inner,
            own_blocks: None,
            push_blocks: None,
            response_push_blocks: None,
            other_blocks: Vec::new(),
            parameters,
            metrics,
            authorities_with_missing_blocks_by_peer_from_me,
        }
    }

    pub async fn shutdown(mut self) {
        let mut waiters = Vec::with_capacity(1 + self.other_blocks.len());
        if let Some(handle) = self.own_blocks.take() {
            handle.abort();
            waiters.push(handle);
        }
        if let Some(handle) = self.push_blocks.take() {
            handle.abort();
            waiters.push(handle);
        }
        if let Some(handle) = self.response_push_blocks.take() {
            handle.abort();
            waiters.push(handle);
        }
        for handle in self.other_blocks {
            handle.abort();
            waiters.push(handle);
        }
        join_all(waiters).await;
    }

    pub async fn push_block_history_with_shards(&mut self, block_reference: BlockReference) {
        if let Some(existing) = self.response_push_blocks.take() {
            existing.abort();
            existing.await.ok();
        }

        let handle = Handle::current().spawn(Self::response_push_blocks(
            block_reference,
            self.inner.clone(),
            self.sender.clone(),
            self.to_whom_authority_index,
            self.parameters.clone(),
        ));
        self.response_push_blocks = Some(handle);
    }

    pub async fn send_transmission_blocks(
        &mut self,
        peer_id: AuthorityIndex,
        block_references: Vec<BlockReference>,
    ) -> Option<()> {
        let peer = format_authority_index(peer_id);
        let own_index = self.inner.block_store.get_own_authority_index();
        let batch_own_block_size = self.parameters.batch_own_block_size;
        let batch_other_block_size = self.parameters.batch_other_block_size;
        let mut blocks = Vec::new();
        let mut own_block_counter = 0;
        let mut other_block_counter = 0;
        for block_reference in block_references {
            let block = self
                .inner
                .block_store
                .get_transmission_block(block_reference);
            if block.is_some() {
                let block = block.expect("Should be some");
                if block.author() == own_index {
                    own_block_counter += 1;
                } else {
                    other_block_counter += 1;
                }
                if own_block_counter >= batch_own_block_size
                    && other_block_counter >= batch_other_block_size
                {
                    break;
                }
                if own_block_counter >= batch_own_block_size {
                    continue;
                }
                if other_block_counter >= batch_other_block_size {
                    continue;
                }
                blocks.push(block);
            }
        }
        tracing::debug!(
            "Requested blocks with missing data {blocks:?} are sent from {own_index:?} to {peer:?}"
        );
        self.sender.send(NetworkMessage::Batch(blocks)).await.ok()?;
        Some(())
    }

    pub async fn send_storage_blocks(
        &mut self,
        peer_id: AuthorityIndex,
        block_references: Vec<BlockReference>,
    ) -> Option<()> {
        let peer = format_authority_index(peer_id);
        let own_index = self.inner.block_store.get_own_authority_index();
        let batch_block_size = self.parameters.batch_own_block_size;
        let mut blocks = Vec::new();
        let mut block_counter = 0;
        let unknown_blocks_by_peer = self.inner.block_store.get_unknown_by_authority(peer_id);
        for block_reference in block_references {
            if unknown_blocks_by_peer.contains(&block_reference) {
                let block = self.inner.block_store.get_storage_block(block_reference);
                if block.is_some() {
                    let block = block.expect("Should be some");
                    block_counter += 1;
                    blocks.push(block);
                    if block_counter >= batch_block_size {
                        break;
                    }
                }
            }
            if block_counter >= batch_block_size {
                break;
            }
        }
        for block in blocks.iter() {
            self.inner
                .block_store
                .update_known_by_authority(*block.reference(), peer_id);
        }
        tracing::debug!(
            "Requested missing blocks {blocks:?} are sent from {own_index:?} to {peer:?}"
        );
        self.sender.send(NetworkMessage::Batch(blocks)).await.ok()?;
        Some(())
    }

    #[allow(dead_code)]
    pub async fn send_parents_storage_blocks(
        &mut self,
        peer_id: AuthorityIndex,
        block_references: Vec<BlockReference>,
    ) -> Option<()> {
        let peer = format_authority_index(peer_id);
        let own_index = self.inner.block_store.get_own_authority_index();
        let batch_block_size = self.parameters.batch_own_block_size;
        let mut blocks = Vec::new();
        let mut block_counter = 0;
        let unknown_blocks_by_peer = self.inner.block_store.get_unknown_by_authority(peer_id);
        for block_reference in block_references {
            let block = self.inner.block_store.get_storage_block(block_reference);
            if block.is_some() {
                let block = block.expect("Should be some");
                for parent_reference in block.includes() {
                    if unknown_blocks_by_peer.contains(parent_reference) {
                        let parent = self.inner.block_store.get_storage_block(*parent_reference);
                        if parent.is_some() {
                            block_counter += 1;
                            if block_counter >= batch_block_size {
                                break;
                            }
                            blocks.push(parent.expect("Should be some"));
                        }
                    }
                }
            }
            if block_counter >= batch_block_size {
                break;
            }
        }
        for block in blocks.iter() {
            self.inner
                .block_store
                .update_known_by_authority(*block.reference(), peer_id);
        }
        tracing::debug!(
            "Requested missing blocks {blocks:?} are sent from {own_index:?} to {peer:?}"
        );
        self.sender.send(NetworkMessage::Batch(blocks)).await.ok()?;
        Some(())
    }

    pub async fn disseminate_own_blocks(&mut self, round: RoundNumber) {
        if let Some(existing) = self.own_blocks.take() {
            existing.abort();
            existing.await.ok();
        }

        let handle = Handle::current().spawn(Self::stream_only_own_blocks(
            self.universal_committer.clone(),
            self.to_whom_authority_index,
            self.sender.clone(),
            self.inner.clone(),
            round,
            self.parameters.clone(),
        ));
        self.own_blocks = Some(handle);
    }

    pub async fn disseminate_all_blocks_push(&mut self) {
        if let Some(existing) = self.push_blocks.take() {
            existing.abort();
            existing.await.ok();
        }

        let handle = Handle::current().spawn(Self::disseminate_own_blocks_and_encoded_past_blocks(
            self.to_whom_authority_index,
            self.sender.clone(),
            self.inner.clone(),
            self.parameters.clone(),
            self.metrics.clone(),
            self.authorities_with_missing_blocks_by_peer_from_me.clone(),
        ));
        self.push_blocks = Some(handle);
    }

    async fn response_push_blocks(
        block_reference: BlockReference,
        inner: Arc<NetworkSyncerInner<H, C>>,
        to: Sender<NetworkMessage>,
        peer_id: AuthorityIndex,
        synchronizer_parameters: SynchronizerParameters,
    ) -> Option<()> {
        let peer = format_authority_index(peer_id);
        let between_push_timeout = Duration::from_millis(100);
        loop {
            let batch_own_block_size = synchronizer_parameters.batch_own_block_size;
            let batch_other_block_size = synchronizer_parameters.batch_other_block_size;
            let blocks = inner.block_store.get_unknown_past_cone(
                peer_id,
                block_reference,
                batch_own_block_size,
                batch_other_block_size,
            );
            for block in &blocks {
                inner
                    .block_store
                    .update_known_by_authority(*block.reference(), peer_id);
            }
            tracing::debug!("Blocks to be sent to {peer} are {blocks:?}");
            if !blocks.is_empty() {
                to.send(NetworkMessage::Batch(blocks)).await.ok()?;
            } else {
                break;
            }
            let _sleep = sleep(between_push_timeout).await;
        }
        Some(())
    }

    async fn stream_only_own_blocks(
        universal_committer: UniversalCommitter,
        to_whom_authority_index: AuthorityIndex,
        to: Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        mut round: RoundNumber,
        synchronizer_parameters: SynchronizerParameters,
    ) -> Option<()> {
        let committee_size = inner.committee.len();
        let mut rng = StdRng::from_entropy();
        let batch_own_block_size = synchronizer_parameters.batch_own_block_size;
        let batch_byzantine_own_block_size = 50 * batch_own_block_size;
        let byzantine_strategy = inner.block_store.byzantine_strategy;
        let own_authority_index = inner.block_store.get_own_authority_index();
        let mut current_round = inner
            .block_store
            .last_own_block_ref()
            .unwrap_or_default()
            .round();
        let sample_timeout = synchronizer_parameters.sample_timeout;
        let withholding_timeout = Duration::from_millis(450);
        loop {
            let notified = inner.notify.notified();
            match byzantine_strategy {
                // Don't send your leader block for at least timeout
                Some(ByzantineStrategy::TimeoutLeader) => {
                    let leaders_current_round = universal_committer.get_leaders(current_round);
                    if leaders_current_round.contains(&own_authority_index) {
                        let _sleep = sleep(sample_timeout).await;
                    }
                    sending_batch_own_blocks(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        batch_byzantine_own_block_size,
                    )
                    .await?;

                    notified.await;
                }
                // Send your leader block (together with all previous non-leader blocks)  to a
                // random set of validators
                // Do not send own blocks if you are not a leader.
                Some(ByzantineStrategy::LeaderWithholding) => {
                    let leaders_current_round = universal_committer.get_leaders(current_round);
                    if leaders_current_round.contains(&own_authority_index) {
                        // Sleep a bit to delay the broadcasting of the leader block
                        let _sleep = sleep(withholding_timeout).await;
                        // Decide probabilistically whether to send blocks to the current authority
                        let send: bool = rng.gen_bool(0.5);
                        if send {
                            // Send blocks to the authority
                            sending_batch_own_blocks(
                                inner.clone(),
                                to.clone(),
                                to_whom_authority_index,
                                &mut round,
                                batch_byzantine_own_block_size,
                            )
                            .await?;
                        }
                    }
                    notified.await;
                }
                // Send a chain of own blocks to the next leader, after having sent no own blocks the last K rounds
                Some(ByzantineStrategy::ChainBomb) => {
                    // send own chain of blocks after becomming the leader and only to the leader in the next round
                    if current_round as usize % committee_size == own_authority_index as usize {
                        let leaders_next_round = universal_committer.get_leaders(current_round + 1);
                        // Only send blocks if the next leader is the intended recipient
                        if leaders_next_round.contains(&to_whom_authority_index) {
                            sending_batch_own_blocks(
                                inner.clone(),
                                to.clone(),
                                to_whom_authority_index,
                                &mut round,
                                batch_byzantine_own_block_size,
                            )
                            .await?;
                        }
                    }
                    notified.await;
                }
                // Send block with a given probability
                Some(ByzantineStrategy::RandomDrop) => {
                    let probability = 1.0 / committee_size as f64;
                    let send: bool = rng.gen_bool(probability);
                    if send {
                        sending_batch_own_blocks(
                            inner.clone(),
                            to.clone(),
                            to_whom_authority_index,
                            &mut round,
                            batch_byzantine_own_block_size,
                        )
                        .await?;
                    }
                    notified.await;
                }
                // Create two equivocating blocks and, send the first one to the first 50% and the
                // second to the other 50% of the validators
                Some(ByzantineStrategy::EquivocatingTwoChains) => {
                    sending_batch_own_blocks(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        batch_byzantine_own_block_size,
                    )
                    .await?;

                    notified.await;
                }
                // Send an equivocating block to the authority whenever it is created
                Some(ByzantineStrategy::EquivocatingChains) => {
                    sending_batch_own_blocks(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        batch_byzantine_own_block_size,
                    )
                    .await?;

                    notified.await;
                }
                // Send a chain of own equivocating blocks to the authority when it is the leader in the next round
                Some(ByzantineStrategy::EquivocatingChainsBomb) => {
                    let leaders_next_round = universal_committer.get_leaders(current_round + 1);
                    if leaders_next_round.contains(&to_whom_authority_index) {
                        sending_batch_own_blocks(
                            inner.clone(),
                            to.clone(),
                            to_whom_authority_index,
                            &mut round,
                            batch_byzantine_own_block_size,
                        )
                        .await?;
                    }
                    notified.await;
                }
                // Send block to the authority whenever a new block is created
                // Additionally try to send blocks after a timeout
                _ => {
                    sending_batch_own_blocks(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        batch_own_block_size,
                    )
                    .await?;
                    select! {
                         _sleep =  sleep(sample_timeout) =>  {}
                        _created_block = notified => {}
                    }
                }
            }
            current_round = inner
                .block_store
                .last_own_block_ref()
                .unwrap_or_default()
                .round();
        }
    }

    async fn disseminate_own_blocks_and_encoded_past_blocks(
        to_whom_authority_index: AuthorityIndex,
        to: Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        synchronizer_parameters: SynchronizerParameters,
        metrics: Arc<Metrics>,
        authorities_with_missing_blocks_by_peer_from_me: Arc<RwLock<Vec<Instant>>>,
    ) -> Option<()> {
        let sample_timeout = synchronizer_parameters.sample_timeout;

        loop {
            let notified = inner.notify.notified();
            select! {
                _sleep =  sleep(sample_timeout) => {
                     let timer = metrics.utilization_timer.utilization_timer("Broadcaster: send blocks");
                    tracing::debug!("Disseminate to {to_whom_authority_index} after timeout");
                    sending_batch_all_blocks(
                inner.clone(),
                to.clone(),
                to_whom_authority_index,
                synchronizer_parameters.clone(),
                        authorities_with_missing_blocks_by_peer_from_me.clone(),
            )
            .await?;
                    drop(timer);
                }
               _created_block = notified => {
                    let timer = metrics.utilization_timer.utilization_timer("Broadcaster: send blocks");
                    tracing::debug!("Disseminate to {to_whom_authority_index} after creating new block");
                    sending_batch_all_blocks(
                inner.clone(),
                to.clone(),
                to_whom_authority_index,
                synchronizer_parameters.clone(),
                        authorities_with_missing_blocks_by_peer_from_me.clone(),
            )
            .await?;
                    drop(timer);
                }
            }
        }
    }
}

async fn sending_batch_own_blocks<H, C>(
    inner: Arc<NetworkSyncerInner<H, C>>,
    to: Sender<NetworkMessage>,
    to_whom_authority_index: AuthorityIndex,
    round: &mut RoundNumber,
    batch_size: usize,
) -> Option<()>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let peer = format_authority_index(to_whom_authority_index);
    let blocks =
        inner
            .block_store
            .get_own_transmission_blocks(to_whom_authority_index, *round, batch_size);
    for block in blocks.iter() {
        inner
            .block_store
            .update_known_by_authority(*block.reference(), to_whom_authority_index);
        *round = max(*round, block.round());
    }
    tracing::debug!("Blocks to be sent to {peer} are {blocks:?}");
    to.send(NetworkMessage::Batch(blocks)).await.ok()?;
    Some(())
}

#[allow(unused)]
async fn sending_batch_all_blocks<H, C>(
    inner: Arc<NetworkSyncerInner<H, C>>,
    to: Sender<NetworkMessage>,
    to_whom_authority_index: AuthorityIndex,
    synchronizer_parameters: SynchronizerParameters,
    authorities_with_missing_blocks_by_peer_from_me: Arc<RwLock<Vec<Instant>>>,
) -> Option<()>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let protocol = inner.block_store.consensus_protocol;
    let committee_size = inner.committee.len();
    let own_index = inner.block_store.get_own_authority_index();
    let max_missing_blocks_age = synchronizer_parameters.max_missing_blocks_age;
    let mut authorities_with_missing_blocks = HashSet::new();
    if protocol == ConsensusProtocol::Starfish {
        let mut authorities_with_missing_blocks_by_peer_from_me =
            authorities_with_missing_blocks_by_peer_from_me.read().await;
        let now = Instant::now();
        for (idx, instant) in authorities_with_missing_blocks_by_peer_from_me
            .iter()
            .enumerate()
        {
            if now.duration_since(*instant) < max_missing_blocks_age {
                authorities_with_missing_blocks.insert(idx as AuthorityIndex);
            }
        }
    }
    if protocol == ConsensusProtocol::CordialMiners {
        authorities_with_missing_blocks.extend(0..committee_size as AuthorityIndex);
    }
    authorities_with_missing_blocks.remove(&own_index);
    let batch_own_block_size = synchronizer_parameters.batch_own_block_size;
    let batch_other_block_size = synchronizer_parameters.batch_other_block_size;
    let peer = format_authority_index(to_whom_authority_index);
    let own_index = inner.block_store.get_own_authority_index();
    let blocks = inner.block_store.get_unknown_causal_history(
        to_whom_authority_index,
        batch_own_block_size,
        batch_other_block_size,
        authorities_with_missing_blocks,
    );
    for block in &blocks {
        inner
            .block_store
            .update_known_by_authority(*block.reference(), to_whom_authority_index);
    }
    tracing::debug!("Blocks to be sent to {peer} are {blocks:?}");
    to.send(NetworkMessage::Batch(blocks)).await.ok()?;
    Some(())
}

#[allow(unused)]
async fn sending_past_cone_block<H, C>(
    inner: Arc<NetworkSyncerInner<H, C>>,
    to: Sender<NetworkMessage>,
    to_whom_authority_index: AuthorityIndex,
    synchronizer_parameters: SynchronizerParameters,
    block_reference: BlockReference,
) -> Option<()>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let batch_own_block_size = synchronizer_parameters.batch_own_block_size;
    let batch_other_block_size = synchronizer_parameters.batch_other_block_size;
    tracing::debug!(
        "Unknown by {to_whom_authority_index}={:?}",
        inner
            .block_store
            .get_unknown_by_authority(to_whom_authority_index)
    );
    let own_index = inner.block_store.get_own_authority_index();
    let blocks = inner.block_store.get_unknown_past_cone(
        to_whom_authority_index,
        block_reference,
        batch_own_block_size,
        batch_other_block_size,
    );
    for block in &blocks {
        inner
            .block_store
            .update_known_by_authority(*block.reference(), to_whom_authority_index);
    }
    tracing::debug!(
        "Blocks to be sent from {own_index} to {to_whom_authority_index} are {blocks:?}"
    );
    to.send(NetworkMessage::Batch(blocks)).await.ok()?;
    Some(())
}

enum BlockFetcherMessage {
    RegisterAuthority(AuthorityIndex, Sender<NetworkMessage>),
    RemoveAuthority(AuthorityIndex),
}

pub struct BlockFetcher {
    sender: Sender<BlockFetcherMessage>,
    handle: JoinHandle<Option<()>>,
}

impl BlockFetcher {
    pub fn start() -> Self {
        let (sender, receiver) = mpsc::channel(100);
        let worker = BlockFetcherWorker::new(receiver);
        let handle = Handle::current().spawn(worker.run());
        Self { sender, handle }
    }

    pub async fn register_authority(
        &self,
        authority: AuthorityIndex,
        sender: Sender<NetworkMessage>,
    ) {
        self.sender
            .send(BlockFetcherMessage::RegisterAuthority(authority, sender))
            .await
            .ok();
    }

    pub async fn remove_authority(&self, authority: AuthorityIndex) {
        self.sender
            .send(BlockFetcherMessage::RemoveAuthority(authority))
            .await
            .ok();
    }

    pub async fn shutdown(self) {
        self.handle.abort();
        self.handle.await.ok();
    }
}

struct BlockFetcherWorker {
    receiver: mpsc::Receiver<BlockFetcherMessage>,
    senders: HashMap<AuthorityIndex, mpsc::Sender<NetworkMessage>>,
    parameters: SynchronizerParameters,
}

impl BlockFetcherWorker {
    pub fn new(receiver: mpsc::Receiver<BlockFetcherMessage>) -> Self {
        Self {
            receiver,
            senders: Default::default(),
            parameters: Default::default(),
        }
    }

    async fn run(mut self) -> Option<()> {
        loop {
            select! {
                _ = sleep(self.parameters.sample_timeout) => {},
                message = self.receiver.recv() => {
                    match message {
                        Some(BlockFetcherMessage::RegisterAuthority(authority, sender)) => {
                            self.senders.insert(authority, sender);
                        },
                        Some(BlockFetcherMessage::RemoveAuthority(authority)) => {
                            self.senders.remove(&authority);
                        },
                        None => return None,
                    }
                }
            }
        }
    }
}
