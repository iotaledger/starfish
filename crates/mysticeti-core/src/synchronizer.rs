// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc, time::Duration};

use futures::future::join_all;
use rand::{seq::SliceRandom, thread_rng};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;

use crate::block_store::ByzantineStrategy;
use crate::consensus::universal_committer::UniversalCommitter;
use crate::{
    block_handler::BlockHandler,
    metrics::Metrics,
    net_sync::{self, NetworkSyncerInner},
    network::NetworkMessage,
    runtime,
    runtime::{sleep, timestamp_utc, Handle, JoinHandle},
    syncer::CommitObserver,
    types::{AuthorityIndex, BlockReference, RoundNumber},
};

// TODO: A central controller will eventually dynamically update these parameters.
pub struct SynchronizerParameters {
    /// The maximum number of helpers (across all nodes).
    pub absolute_maximum_helpers: usize,
    /// The maximum number of helpers per authority.
    pub maximum_helpers_per_authority: usize,
    /// The number of blocks to send in a single batch.
    pub batch_size: usize,
    /// The sampling precision with which to re-evaluate the sync strategy.
    pub sample_precision: Duration,
    /// The grace period with which to eagerly sync missing blocks.
    pub grace_period: Duration,
    /// The interval at which to send stream blocks authored by other nodes.
    pub stream_interval: Duration,
    /// Threshold number of missing block from an authority to open a new stream.
    pub new_stream_threshold: usize,
}

impl Default for SynchronizerParameters {
    fn default() -> Self {
        Self {
            absolute_maximum_helpers: 10,
            maximum_helpers_per_authority: 2,
            batch_size: 30,
            sample_precision: Duration::from_millis(500),
            grace_period: Duration::from_millis(0),
            stream_interval: Duration::from_secs(1),
            new_stream_threshold: 10,
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
    /// The handles of tasks disseminating other nodes' blocks.
    other_blocks: Vec<JoinHandle<Option<()>>>,
    /// The parameters of the synchronizer.
    parameters: SynchronizerParameters,
    /// Metrics.
    metrics: Arc<Metrics>,
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
    ) -> Self {
        Self {
            to_whom_authority_index,
            sender,
            universal_committer,
            inner,
            own_blocks: None,
            push_blocks: None,
            other_blocks: Vec::new(),
            parameters,
            metrics,
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
        for handle in self.other_blocks {
            handle.abort();
            waiters.push(handle);
        }
        join_all(waiters).await;
    }

    pub async fn send_blocks(
        &mut self,
        peer: AuthorityIndex,
        references: Vec<BlockReference>,
    ) -> Option<()> {
        let mut missing = Vec::new();
        for reference in references {
            let stored_block = self.inner.block_store.get_block(reference);
            let found = stored_block.is_some();
            match stored_block {
                // TODO: Should we be able to send more than one block in a single network message?
                Some(block) => self.sender.send(NetworkMessage::Block(block)).await.ok()?,
                None => missing.push(reference),
            }
            self.metrics
                .block_sync_requests_received
                .with_label_values(&[&peer.to_string(), &found.to_string()])
                .inc();
        }
        self.sender
            .send(NetworkMessage::BlockNotFound(missing))
            .await
            .ok()
    }

    pub async fn disseminate_only_own_blocks(&mut self, round: RoundNumber) {
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
            self.parameters.batch_size,
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
            self.parameters.batch_size,
        ));
        self.push_blocks = Some(handle);
    }

    async fn stream_only_own_blocks(
        universal_committer: UniversalCommitter,
        to_whom_authority_index: AuthorityIndex,
        to: mpsc::Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        mut round: RoundNumber,
        batch_size: usize,
    ) -> Option<()> {
        let byzantine_strategy = inner.block_store.byzantine_strategy.clone();
        let own_authority_index = inner.block_store.get_own_authority_index();
        let mut current_round = inner
            .block_store
            .last_own_block_ref()
            .unwrap_or_default()
            .round();
        let leader_timeout = Duration::from_secs(1);
        loop {
            let notified = inner.notify.notified();
            match byzantine_strategy {
                // Don't send your leader block for at least timeout
                Some(ByzantineStrategy::TimeoutLeader) => {
                    let leaders_current_round = universal_committer.get_leaders(current_round);
                    if leaders_current_round.contains(&own_authority_index) {
                        let _sleep = runtime::sleep(leader_timeout).await;
                    }
                    sending_batch_blocks_v1(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        10 * batch_size,
                    )
                    .await?;
                }
                // Send an equivocating block to the authority whenever it is created
                Some(ByzantineStrategy::EquivocatingBlocks) => {
                    sending_batch_blocks_v1(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        10 * batch_size,
                    )
                    .await?;
                }
                // Send a chain of own equivocating blocks to the authority when it is the leader in the next round
                Some(ByzantineStrategy::DelayedEquivocatingBlocks) => {
                    let leaders_next_round = universal_committer.get_leaders(current_round + 1);
                    if leaders_next_round.contains(&to_whom_authority_index) {
                        sending_batch_blocks_v1(
                            inner.clone(),
                            to.clone(),
                            to_whom_authority_index,
                            &mut round,
                            10 * batch_size,
                        )
                        .await?;
                    }
                }
                // Send block to the authority whenever a new block is created
                _ => {
                    sending_batch_blocks_v1(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        batch_size,
                    )
                        .await?;

                }
            }
            notified.await;
            current_round = inner
                .block_store
                .last_own_block_ref()
                .unwrap_or_default()
                .round();
        }
    }

    async fn disseminate_own_blocks_and_encoded_past_blocks(
        to_whom_authority_index: AuthorityIndex,
        to: mpsc::Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        batch_size: usize,
    ) -> Option<()> {
        loop {
            let notified = inner.notify.notified();
            sending_batch_blocks_v2(
                inner.clone(),
                to.clone(),
                to_whom_authority_index,
                batch_size,
            )
            .await?;
            notified.await;
        }
    }
}

async fn sending_batch_blocks_v1<H, C>(
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
    let own_index = inner.block_store.get_own_authority_index();
    let blocks =
        inner
            .block_store
            .get_own_blocks(to_whom_authority_index, round.clone(), batch_size);
    for block in blocks {
        inner
            .block_store
            .update_known_by_authority(block.reference().clone(), to_whom_authority_index);
        *round = block.round();
        tracing::debug!("Blocks to be sent from {own_index:?} to {to_whom_authority_index:?} are {block:?}");
        tracing::debug!("DAG ={:?}", inner.block_store.get_dag_sorted());
        to.send(NetworkMessage::Block(block)).await.ok()?;
    }
    Some(())
}

async fn sending_batch_blocks_v2<H, C>(
    inner: Arc<NetworkSyncerInner<H, C>>,
    to: Sender<NetworkMessage>,
    to_whom_authority_index: AuthorityIndex,
    batch_size: usize,
) -> Option<()>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let own_index = inner.block_store.get_own_authority_index();
    let blocks = inner
        .block_store
        .get_unknown_causal_history(to_whom_authority_index, batch_size);
    for block in &blocks {
        inner
            .block_store
            .update_known_by_authority(block.reference().clone(), to_whom_authority_index);
    }
    tracing::debug!("Blocks to be sent from {own_index:?} to {to_whom_authority_index:?} are {blocks:?}");
    tracing::debug!("DAG ={:?}", inner.block_store.get_dag_sorted());
    to.send(NetworkMessage::Batch(blocks)).await.ok()?;
    Some(())
}

enum BlockFetcherMessage {
    RegisterAuthority(AuthorityIndex, mpsc::Sender<NetworkMessage>),
    RemoveAuthority(AuthorityIndex),
}

pub struct BlockFetcher {
    sender: mpsc::Sender<BlockFetcherMessage>,
    handle: JoinHandle<Option<()>>,
}

impl BlockFetcher {
    pub fn start<B, C>(
        id: AuthorityIndex,
        inner: Arc<NetworkSyncerInner<B, C>>,
        metrics: Arc<Metrics>,
        enable: bool,
    ) -> Self
    where
        B: BlockHandler + 'static,
        C: CommitObserver + 'static,
    {
        let (sender, receiver) = mpsc::channel(100);
        let worker = BlockFetcherWorker::new(id, inner, receiver, metrics, enable);
        let handle = Handle::current().spawn(worker.run());
        Self { sender, handle }
    }

    pub async fn register_authority(
        &self,
        authority: AuthorityIndex,
        sender: mpsc::Sender<NetworkMessage>,
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

struct BlockFetcherWorker<B: BlockHandler, C: CommitObserver> {
    id: AuthorityIndex,
    inner: Arc<NetworkSyncerInner<B, C>>,
    receiver: mpsc::Receiver<BlockFetcherMessage>,
    senders: HashMap<AuthorityIndex, mpsc::Sender<NetworkMessage>>,
    parameters: SynchronizerParameters,
    metrics: Arc<Metrics>,
    /// Hold a timestamp of when blocks were first considered missing.
    missing: HashMap<BlockReference, Duration>,
    enable: bool,
}

impl<B, C> BlockFetcherWorker<B, C>
where
    B: BlockHandler + 'static,
    C: CommitObserver + 'static,
{
    pub fn new(
        id: AuthorityIndex,
        inner: Arc<NetworkSyncerInner<B, C>>,
        receiver: mpsc::Receiver<BlockFetcherMessage>,
        metrics: Arc<Metrics>,
        enable: bool,
    ) -> Self {
        Self {
            id,
            inner,
            receiver,
            senders: Default::default(),
            parameters: Default::default(),
            metrics,
            missing: Default::default(),
            enable,
        }
    }

    async fn run(mut self) -> Option<()> {
        loop {
            tokio::select! {
                _ = sleep(self.parameters.sample_precision) => self.sync_strategy().await,
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

    /// A simple and naive strategy that requests missing blocks from random peers.
    async fn sync_strategy(&mut self) {
        if self.enable {
            return;
        }

        let now = timestamp_utc();
        let mut to_request = vec![];

        let missing_blocks = self.inner.syncer.get_missing_blocks().await;
        for (authority, missing) in missing_blocks.into_iter().enumerate() {
            self.metrics
                .missing_blocks
                .with_label_values(&[&authority.to_string()])
                .set(missing.len() as i64);

            for reference in missing {
                let time = self.missing.entry(reference).or_insert(now);
                if now.checked_sub(*time).unwrap_or_default() >= self.parameters.grace_period {
                    if authority >= to_request.len() {
                        to_request.resize(authority + 1, vec![]);
                    }
                    to_request[authority].push(reference);
                    self.missing.remove(&reference); // todo - ensure we receive the block
                }
            }
        }
        self.missing.retain(|_, time| {
            now.checked_sub(*time).unwrap_or_default() < self.parameters.grace_period
        });
        // TODO: If we are missing many blocks from the same authority
        // (`missing.len() > self.parameters.new_stream_threshold`), it is likely that
        // we have a network partition. We should try to find an other peer from which
        // to (temporarily) sync the blocks from that authority.
        for authority in 0..to_request.len() {
            for chunks in to_request[authority].chunks(net_sync::MAXIMUM_BLOCK_REQUEST) {
                //let Some((peer, permit)) = self.sample_peer(&[self.id]) else {
                //break;
                //};
                //we request the missing block one time from the authority and the second time from a random authority
                let except = [authority as AuthorityIndex, self.id];
                let mut senders = self
                    .senders
                    .iter()
                    .filter(|&(index, _)| !except.contains(index))
                    .collect::<Vec<_>>();

                senders.shuffle(&mut thread_rng());
                let mut up = 1;
                let authority_index = authority as AuthorityIndex;
                if let Some(x) = self.senders.get(&(authority as AuthorityIndex)) {
                    senders.push((&authority_index, x));
                    up += 1;
                    senders.reverse();
                }
                for (peer, sender) in senders {
                    //eprintln!("peer={}", peer);
                    //eprintln!("self.sender = {:?}", self.senders);
                    let Ok(permit) = sender.try_reserve() else {
                        continue;
                    };

                    let message = NetworkMessage::RequestBlocks(chunks.to_vec());
                    permit.send(message);
                    self.metrics
                        .block_sync_requests_sent
                        .with_label_values(&[&peer.to_string()])
                        .inc();
                    up -= 1;
                    if up == 0 {
                        break;
                    }
                }
            }
        }
    }
}
