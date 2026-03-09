// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{cmp::max, collections::HashMap, sync::Arc, time::Duration};

use ahash::AHashSet;
use futures::future::join_all;
use rand::{Rng, SeedableRng, prelude::StdRng};
use tokio::{
    select,
    sync::{mpsc, mpsc::Sender},
    task::JoinHandle,
};

use crate::{
    block_handler::BlockHandler,
    committee::{QuorumThreshold, StakeAggregator},
    config::DisseminationMode,
    consensus::universal_committer::UniversalCommitter,
    dag_state::{ByzantineStrategy, ConsensusProtocol},
    metrics::{Metrics, UtilizationTimerVecExt},
    net_sync::NetworkSyncerInner,
    network::{BlockBatch, NetworkMessage},
    runtime::{Handle, sleep},
    syncer::CommitObserver,
    types::{AuthorityIndex, BlockReference, RoundNumber, format_authority_index},
};

fn peer_can_serve_missing_data(
    consensus_protocol: ConsensusProtocol,
    holders: &StakeAggregator<QuorumThreshold>,
    own_id: AuthorityIndex,
    peer_id: AuthorityIndex,
) -> bool {
    match consensus_protocol {
        ConsensusProtocol::StarfishL => holders.votes.contains(peer_id),
        _ => !holders.votes.contains(own_id) && holders.votes.contains(peer_id),
    }
}

#[derive(Clone)]
pub struct BroadcasterParameters {
    /// The number of own blocks to send in a single batch.
    pub batch_own_block_size: usize,
    /// The number of other blocks to send in a single batch.
    pub batch_other_block_size: usize,
    /// The number of shards to send in a single batch.
    pub batch_shard_size: usize,
    /// The sampling precision with which to re-evaluate the sync strategy.
    pub sample_timeout: Duration,
    /// Whether peers exchange data via pull, push-causal, or push-useful.
    pub dissemination_mode: DisseminationMode,
    /// In push-causal mode, only shard payloads up to this many rounds behind
    /// the current frontier are piggybacked.
    pub causal_push_shard_round_lag: RoundNumber,
}

impl BroadcasterParameters {
    pub fn new(
        committee_size: usize,
        consensus_protocol: ConsensusProtocol,
        dissemination_mode: DisseminationMode,
        causal_push_shard_round_lag: RoundNumber,
    ) -> Self {
        match consensus_protocol {
            ConsensusProtocol::Mysticeti => Self {
                batch_own_block_size: committee_size,
                batch_other_block_size: 3 * committee_size,
                batch_shard_size: 3 * committee_size,
                sample_timeout: Duration::from_millis(600),
                dissemination_mode,
                causal_push_shard_round_lag,
            },
            ConsensusProtocol::StarfishPull
            | ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishS
            | ConsensusProtocol::StarfishL
            | ConsensusProtocol::CordialMiners => Self {
                batch_own_block_size: committee_size,
                batch_other_block_size: committee_size * committee_size,
                batch_shard_size: committee_size * committee_size,
                sample_timeout: Duration::from_millis(600),
                dissemination_mode,
                causal_push_shard_round_lag,
            },
        }
    }
}

impl Default for BroadcasterParameters {
    fn default() -> Self {
        Self {
            batch_own_block_size: 8,
            batch_other_block_size: 128,
            batch_shard_size: 128,
            sample_timeout: Duration::from_millis(600),
            dissemination_mode: DisseminationMode::Pull,
            causal_push_shard_round_lag: 2,
        }
    }
}

pub struct BlockDisseminator<H: BlockHandler, C: CommitObserver> {
    to_whom_authority_index: AuthorityIndex,
    /// The sender to the network.
    sender: mpsc::Sender<NetworkMessage>,
    /// Universal Committer. This is needed for Byzantine nodes to control when
    /// to send the blocks
    universal_committer: UniversalCommitter,
    /// The inner state of the network syncer.
    inner: Arc<NetworkSyncerInner<H, C>>,
    /// The handle of the task disseminating our own blocks.
    own_blocks: Option<JoinHandle<Option<()>>>,
    /// The handle of the task disseminating all unknown blocks.
    push_blocks: Option<JoinHandle<Option<()>>>,
    /// The handles of tasks disseminating other nodes' blocks.
    other_blocks: Vec<JoinHandle<Option<()>>>,
    /// The parameters of the broadcaster.
    parameters: BroadcasterParameters,
    /// Metrics.
    metrics: Arc<Metrics>,
    /// Blocks sent to this peer during this connection.
    /// Starts empty -- all DAG blocks are candidates.
    pub sent_to_peer: Arc<parking_lot::RwLock<AHashSet<BlockReference>>>,
}

pub struct DataRequester<H: BlockHandler, C: CommitObserver> {
    to_whom_authority_index: AuthorityIndex,
    /// The sender to the network.
    sender: Sender<NetworkMessage>,
    inner: Arc<NetworkSyncerInner<H, C>>,
    /// The handle of the task disseminating our own blocks.
    data_requester: Option<JoinHandle<Option<()>>>,
    parameters: BroadcasterParameters,
}

impl<H, C> DataRequester<H, C>
where
    H: BlockHandler + 'static,
    C: CommitObserver + 'static,
{
    pub fn new(
        to_whom_authority_index: AuthorityIndex,
        sender: Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        parameters: BroadcasterParameters,
    ) -> Self {
        Self {
            to_whom_authority_index,
            sender,
            inner,
            data_requester: None,
            parameters,
        }
    }

    pub async fn shutdown(mut self) {
        let mut waiters = Vec::with_capacity(1);
        if let Some(handle) = self.data_requester.take() {
            handle.abort();
            waiters.push(handle);
        }
        join_all(waiters).await;
    }

    pub async fn start(&mut self) {
        if let Some(existing) = self.data_requester.take() {
            existing.abort();
            existing.await.ok();
        }
        let handle = Handle::current().spawn(Self::request_missing_data_blocks(
            self.to_whom_authority_index,
            self.sender.clone(),
            self.inner.clone(),
            self.parameters.clone(),
        ));
        self.data_requester = Some(handle);
    }

    async fn request_missing_data_blocks(
        peer_id: AuthorityIndex,
        to: Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        parameters: BroadcasterParameters,
    ) -> Option<()> {
        let peer = format_authority_index(peer_id);
        let own_id = inner.dag_state.get_own_authority_index();
        let sample_timeout = parameters.sample_timeout;
        let upper_limit_request_size = parameters.batch_other_block_size;
        let consensus_protocol = inner.dag_state.consensus_protocol;
        loop {
            let committed_dags = inner.dag_state.read_pending_unavailable();
            // Collect candidates that pass the aggregator filter.
            let mut candidates = Vec::new();
            'commit_loop: for commit in &committed_dags {
                for (i, block) in commit.0.blocks.iter().enumerate() {
                    if block.round() > 0
                        && peer_can_serve_missing_data(
                            consensus_protocol,
                            &commit.1[i],
                            own_id,
                            peer_id,
                        )
                    {
                        candidates.push(*block.reference());
                    }
                }
                if candidates.len() >= upper_limit_request_size {
                    candidates.truncate(upper_limit_request_size);
                    break 'commit_loop;
                }
            }
            // Batch availability check — single lock for all candidates.
            let availability = inner.dag_state.are_data_available(&candidates);
            let to_request: Vec<_> = candidates
                .into_iter()
                .zip(availability)
                .filter(|(_, available)| !available)
                .map(|(r, _)| {
                    tracing::debug!("Data in block {r:?} is missing");
                    r
                })
                .collect();
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
        parameters: BroadcasterParameters,
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
            sent_to_peer: Arc::new(parking_lot::RwLock::new(AHashSet::new())),
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

    pub async fn send_transmission_blocks(
        &mut self,
        peer_id: AuthorityIndex,
        block_references: Vec<BlockReference>,
    ) -> Option<()> {
        use crate::network::ShardPayload;

        let peer = format_authority_index(peer_id);
        let own_index = self.inner.dag_state.get_own_authority_index();

        let shards: Vec<ShardPayload> = block_references
            .iter()
            .filter_map(|r| {
                let shard = self.inner.dag_state.get_shard(r)?;
                Some(ShardPayload {
                    block_reference: *r,
                    shard,
                })
            })
            .collect();
        tracing::debug!(
            "Sending {} shards for missing tx data from {own_index:?} to {peer:?}",
            shards.len(),
        );
        self.sender
            .send(NetworkMessage::Batch(BlockBatch::shards_only(shards)))
            .await
            .ok()?;
        Some(())
    }

    pub async fn send_storage_blocks(
        &mut self,
        peer_id: AuthorityIndex,
        block_references: Vec<BlockReference>,
    ) -> Option<()> {
        let peer = format_authority_index(peer_id);
        let own_index = self.inner.dag_state.get_own_authority_index();
        let batch_block_size = self.parameters.batch_own_block_size;
        let batch_other_block_size = self.parameters.batch_other_block_size;

        match self.inner.dag_state.consensus_protocol {
            ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishS
            | ConsensusProtocol::StarfishL
            | ConsensusProtocol::StarfishPull => {
                let mut refs_to_send = block_references;
                let remaining_extra_budget =
                    batch_other_block_size.saturating_sub(refs_to_send.len());

                if self.parameters.dissemination_mode == DisseminationMode::PushUseful
                    && remaining_extra_budget > 0
                {
                    if let Some(ck) = self.inner.cordial_knowledge.connection_knowledge(peer_id) {
                        let current_round = self.inner.dag_state.highest_round();
                        let header_candidate_limit =
                            remaining_extra_budget.saturating_mul(HEADER_PRUNE_OVERFETCH_FACTOR);
                        let extra_candidates = {
                            let mut ck = ck.write();
                            let (useful_headers_to_peer, _) =
                                ck.useful_authors_to_peer_bitmasks(current_round);
                            ck.take_unsent_headers_for_authorities(
                                header_candidate_limit,
                                useful_headers_to_peer,
                            )
                        };
                        let extra_refs = self.inner.dag_state.filter_block_refs_unknown_to_peer(
                            &extra_candidates,
                            peer_id,
                            remaining_extra_budget,
                        );
                        if !extra_refs.is_empty() {
                            let mut included = AHashSet::with_capacity(
                                refs_to_send.len().saturating_add(extra_refs.len()),
                            );
                            included.extend(refs_to_send.iter().copied());
                            refs_to_send.reserve(extra_refs.len());
                            for r in extra_refs {
                                if included.insert(r) {
                                    refs_to_send.push(r);
                                }
                            }
                        }
                    }
                }

                let headers = self.inner.dag_state.get_header_only_blocks(&refs_to_send);
                {
                    let mut sent = self.sent_to_peer.write();
                    for block in headers.iter() {
                        sent.insert(*block.reference());
                    }
                }
                tracing::debug!(
                    "Requested missing parent headers (and extra potentially-missing headers) {:?} are sent from {own_index:?} to {peer:?}",
                    headers
                );
                self.sender
                    .send(NetworkMessage::Batch(BlockBatch {
                        full_blocks: Vec::new(),
                        headers,
                        shards: Vec::new(),
                        useful_headers_authors: 0,
                        useful_shards_authors: 0,
                    }))
                    .await
                    .ok()?;
            }
            ConsensusProtocol::Mysticeti | ConsensusProtocol::CordialMiners => {
                let all_blocks = self.inner.dag_state.get_storage_blocks(&block_references);

                let mut blocks = Vec::new();
                for block in all_blocks.into_iter().flatten() {
                    blocks.push(block);
                    if blocks.len() >= batch_block_size {
                        break;
                    }
                }
                {
                    let mut sent = self.sent_to_peer.write();
                    for block in blocks.iter() {
                        sent.insert(*block.reference());
                    }
                }
                tracing::debug!(
                    "Requested missing blocks {blocks:?} are sent from {own_index:?} to {peer:?}"
                );
                self.sender
                    .send(NetworkMessage::Batch(BlockBatch::full_only(blocks)))
                    .await
                    .ok()?;
            }
        }
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
            self.sent_to_peer.clone(),
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
            self.sent_to_peer.clone(),
        ));
        self.push_blocks = Some(handle);
    }

    async fn stream_only_own_blocks(
        universal_committer: UniversalCommitter,
        to_whom_authority_index: AuthorityIndex,
        to: Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        mut round: RoundNumber,
        broadcaster_parameters: BroadcasterParameters,
        sent_to_peer: Arc<parking_lot::RwLock<AHashSet<BlockReference>>>,
    ) -> Option<()> {
        let committee_size = inner.committee.len();
        let mut rng = StdRng::from_entropy();
        let batch_own_block_size = broadcaster_parameters.batch_own_block_size;
        let batch_byzantine_own_block_size = 50 * batch_own_block_size;
        let byzantine_strategy = inner.dag_state.byzantine_strategy;
        let own_authority_index = inner.dag_state.get_own_authority_index();
        let mut current_round = inner
            .dag_state
            .last_own_block_ref()
            .unwrap_or_default()
            .round();
        let sample_timeout = broadcaster_parameters.sample_timeout;
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
                        sent_to_peer.clone(),
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
                                sent_to_peer.clone(),
                            )
                            .await?;
                        }
                    }
                    notified.await;
                }
                // Send a chain of own blocks to the next leader,
                // after having sent no own blocks the last K rounds
                Some(ByzantineStrategy::ChainBomb) => {
                    // Send own chain of blocks after becoming the
                    // leader and only to the leader in the next round
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
                                sent_to_peer.clone(),
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
                            sent_to_peer.clone(),
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
                        sent_to_peer.clone(),
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
                        sent_to_peer.clone(),
                    )
                    .await?;

                    notified.await;
                }
                // Send a chain of own equivocating blocks to the
                // authority when it is the leader in the next round
                Some(ByzantineStrategy::EquivocatingChainsBomb) => {
                    let leaders_next_round = universal_committer.get_leaders(current_round + 1);
                    if leaders_next_round.contains(&to_whom_authority_index) {
                        sending_batch_own_blocks(
                            inner.clone(),
                            to.clone(),
                            to_whom_authority_index,
                            &mut round,
                            batch_byzantine_own_block_size,
                            sent_to_peer.clone(),
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
                        sent_to_peer.clone(),
                    )
                    .await?;
                    select! {
                        _sleep = sleep(sample_timeout) => {}
                        _created_block = notified => {}
                    }
                }
            }
            current_round = inner
                .dag_state
                .last_own_block_ref()
                .unwrap_or_default()
                .round();
        }
    }

    async fn disseminate_own_blocks_and_encoded_past_blocks(
        to_whom_authority_index: AuthorityIndex,
        to: Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        broadcaster_parameters: BroadcasterParameters,
        metrics: Arc<Metrics>,
        sent_to_peer: Arc<parking_lot::RwLock<AHashSet<BlockReference>>>,
    ) -> Option<()> {
        let sample_timeout = broadcaster_parameters.sample_timeout;
        loop {
            let notified = inner.notify.notified();
            let trigger = select! {
                _ = sleep(sample_timeout) => "timeout",
                _ = notified => "new block",
            };
            let timer = metrics
                .utilization_timer
                .utilization_timer("Broadcaster: send blocks");
            tracing::debug!("Disseminate to {to_whom_authority_index} after {trigger}");
            match inner.dag_state.consensus_protocol {
                ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishS
                | ConsensusProtocol::StarfishL
                | ConsensusProtocol::StarfishPull
                | ConsensusProtocol::CordialMiners
                | ConsensusProtocol::Mysticeti => match broadcaster_parameters.dissemination_mode {
                    DisseminationMode::Pull => {
                        sending_batch_all_blocks(
                            inner.clone(),
                            to.clone(),
                            to_whom_authority_index,
                            broadcaster_parameters.clone(),
                            sent_to_peer.clone(),
                            &metrics,
                        )
                        .await?;
                    }
                    DisseminationMode::PushCausal => match inner.dag_state.consensus_protocol {
                        ConsensusProtocol::Starfish
                        | ConsensusProtocol::StarfishS
                        | ConsensusProtocol::StarfishL
                        | ConsensusProtocol::StarfishPull => {
                            sending_batch_causal_starfish_blocks(
                                inner.clone(),
                                to.clone(),
                                to_whom_authority_index,
                                broadcaster_parameters.clone(),
                                sent_to_peer.clone(),
                                &metrics,
                            )
                            .await?;
                        }
                        ConsensusProtocol::CordialMiners | ConsensusProtocol::Mysticeti => {
                            sending_batch_all_blocks(
                                inner.clone(),
                                to.clone(),
                                to_whom_authority_index,
                                broadcaster_parameters.clone(),
                                sent_to_peer.clone(),
                                &metrics,
                            )
                            .await?;
                        }
                    },
                    DisseminationMode::PushUseful => match inner.dag_state.consensus_protocol {
                        ConsensusProtocol::Starfish
                        | ConsensusProtocol::StarfishS
                        | ConsensusProtocol::StarfishL
                        | ConsensusProtocol::StarfishPull => {
                            sending_batch_starfish_blocks(
                                inner.clone(),
                                to.clone(),
                                to_whom_authority_index,
                                broadcaster_parameters.clone(),
                                sent_to_peer.clone(),
                                &metrics,
                            )
                            .await?;
                        }
                        ConsensusProtocol::CordialMiners => {
                            sending_batch_cordial_miners_blocks(
                                inner.clone(),
                                to.clone(),
                                to_whom_authority_index,
                                broadcaster_parameters.clone(),
                                sent_to_peer.clone(),
                                &metrics,
                            )
                            .await?;
                        }
                        ConsensusProtocol::Mysticeti => {
                            sending_batch_all_blocks(
                                inner.clone(),
                                to.clone(),
                                to_whom_authority_index,
                                broadcaster_parameters.clone(),
                                sent_to_peer.clone(),
                                &metrics,
                            )
                            .await?;
                        }
                    },
                    DisseminationMode::ProtocolDefault => {
                        unreachable!("protocol-default dissemination mode must be resolved")
                    }
                },
            }
            drop(timer);
        }
    }
}

async fn sending_batch_own_blocks<H, C>(
    inner: Arc<NetworkSyncerInner<H, C>>,
    to: Sender<NetworkMessage>,
    to_whom_authority_index: AuthorityIndex,
    round: &mut RoundNumber,
    batch_size: usize,
    sent_to_peer: Arc<parking_lot::RwLock<AHashSet<BlockReference>>>,
) -> Option<()>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let peer = format_authority_index(to_whom_authority_index);
    let blocks =
        inner
            .dag_state
            .get_own_transmission_blocks(to_whom_authority_index, *round, batch_size);
    {
        let mut sent = sent_to_peer.write();
        for block in blocks.iter() {
            sent.insert(*block.reference());
            *round = max(*round, block.round());
        }
    }
    tracing::debug!("Blocks to be sent to {peer} are {blocks:?}");
    to.send(NetworkMessage::Batch(BlockBatch::full_only(blocks)))
        .await
        .ok()?;
    Some(())
}

fn report_useful_authorities(
    metrics: &Metrics,
    peer: &str,
    useful_headers: u128,
    useful_shards: u128,
) {
    metrics
        .useful_authorities
        .with_label_values(&[peer, "headers"])
        .set(useful_headers.count_ones() as i64);
    metrics
        .useful_authorities
        .with_label_values(&[peer, "shards"])
        .set(useful_shards.count_ones() as i64);
}

const HEADER_PRUNE_OVERFETCH_FACTOR: usize = 4;

/// Track sent references in `sent_to_peer`, evict stale entries, and send the
/// batch.
async fn send_batch_and_track<H, C>(
    to: &Sender<NetworkMessage>,
    batch: BlockBatch,
    inner: &Arc<NetworkSyncerInner<H, C>>,
    sent_to_peer: &parking_lot::RwLock<AHashSet<BlockReference>>,
    refs: impl Iterator<Item = BlockReference>,
) -> Option<()>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    {
        let mut sent = sent_to_peer.write();
        for r in refs {
            sent.insert(r);
        }
        let lowest_round = inner.dag_state.lowest_round();
        sent.retain(|r| r.round >= lowest_round);
    }
    if !batch.is_empty() {
        to.send(NetworkMessage::Batch(batch)).await.ok()?;
    }
    Some(())
}

async fn sending_batch_all_blocks<H, C>(
    inner: Arc<NetworkSyncerInner<H, C>>,
    to: Sender<NetworkMessage>,
    to_whom_authority_index: AuthorityIndex,
    broadcaster_parameters: BroadcasterParameters,
    sent_to_peer: Arc<parking_lot::RwLock<AHashSet<BlockReference>>>,
    metrics: &Metrics,
) -> Option<()>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let committee_size = inner.committee.len();
    let own_index = inner.dag_state.get_own_authority_index();
    let mut authorities_with_missing_blocks: AHashSet<AuthorityIndex> =
        (0..committee_size as AuthorityIndex).collect();
    authorities_with_missing_blocks.remove(&own_index);
    let batch_own_block_size = broadcaster_parameters.batch_own_block_size;
    let batch_other_block_size = broadcaster_parameters.batch_other_block_size;
    let peer = format_authority_index(to_whom_authority_index);
    let blocks = {
        let sent = sent_to_peer.read();
        inner.dag_state.get_unsent_causal_history(
            &sent,
            to_whom_authority_index,
            batch_own_block_size,
            batch_other_block_size,
            authorities_with_missing_blocks,
        )
    };
    // Full-block protocols do not advertise header/shard usefulness.
    let useful_headers = 0;
    let useful_shards = 0;
    report_useful_authorities(metrics, &peer.to_string(), useful_headers, useful_shards);

    tracing::debug!("Blocks to be sent to {peer} are {blocks:?}");
    let batch = BlockBatch {
        full_blocks: blocks,
        headers: Vec::new(),
        shards: Vec::new(),
        useful_headers_authors: useful_headers,
        useful_shards_authors: useful_shards,
    };
    let sent_refs: Vec<_> = batch.full_blocks.iter().map(|b| *b.reference()).collect();
    send_batch_and_track(&to, batch, &inner, &sent_to_peer, sent_refs.into_iter()).await
}

/// Cordial Miners-specific batch: own blocks as full blocks from the indexed
/// own-block path, plus other full blocks selected from CordialKnowledge's
/// per-peer queue and pruned against the DAG's `known_by` view.
async fn sending_batch_cordial_miners_blocks<H, C>(
    inner: Arc<NetworkSyncerInner<H, C>>,
    to: Sender<NetworkMessage>,
    to_whom_authority_index: AuthorityIndex,
    broadcaster_parameters: BroadcasterParameters,
    sent_to_peer: Arc<parking_lot::RwLock<AHashSet<BlockReference>>>,
    metrics: &Metrics,
) -> Option<()>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let batch_own_block_size = broadcaster_parameters.batch_own_block_size;
    let batch_other_block_size = broadcaster_parameters.batch_other_block_size;
    let peer = format_authority_index(to_whom_authority_index);

    let own_blocks = {
        let sent = sent_to_peer.read();
        inner
            .dag_state
            .get_unsent_own_blocks(&sent, to_whom_authority_index, batch_own_block_size)
    };

    let own_authority = inner.dag_state.get_own_authority_index();
    let ck = inner
        .cordial_knowledge
        .connection_knowledge(to_whom_authority_index)?;
    let candidate_limit = batch_other_block_size.saturating_mul(HEADER_PRUNE_OVERFETCH_FACTOR);
    let other_candidates = {
        let mut ck = ck.write();
        ck.take_unsent_headers_excluding_authority(candidate_limit, own_authority)
    };
    let other_refs = inner.dag_state.filter_block_refs_unknown_to_peer(
        &other_candidates,
        to_whom_authority_index,
        batch_other_block_size,
    );
    let mut full_blocks = own_blocks;
    full_blocks.extend(
        inner
            .dag_state
            .get_transmission_blocks(&other_refs)
            .into_iter()
            .flatten(),
    );

    let useful_headers = 0;
    let useful_shards = 0;
    report_useful_authorities(metrics, &peer.to_string(), useful_headers, useful_shards);

    tracing::debug!("Cordial Miners batch to {peer}: {} full", full_blocks.len());
    let batch = BlockBatch {
        full_blocks,
        headers: Vec::new(),
        shards: Vec::new(),
        useful_headers_authors: useful_headers,
        useful_shards_authors: useful_shards,
    };
    let sent_refs: Vec<_> = batch.full_blocks.iter().map(|b| *b.reference()).collect();
    send_batch_and_track(&to, batch, &inner, &sent_to_peer, sent_refs.into_iter()).await
}

/// Starfish-specific batch: own blocks as full, others' headers from
/// CordialKnowledge, shards from CordialKnowledge, plus useful-authors
/// feedback bitmasks.
async fn sending_batch_starfish_blocks<H, C>(
    inner: Arc<NetworkSyncerInner<H, C>>,
    to: Sender<NetworkMessage>,
    to_whom_authority_index: AuthorityIndex,
    broadcaster_parameters: BroadcasterParameters,
    sent_to_peer: Arc<parking_lot::RwLock<AHashSet<BlockReference>>>,
    metrics: &Metrics,
) -> Option<()>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let batch_own_block_size = broadcaster_parameters.batch_own_block_size;
    let batch_other_block_size = broadcaster_parameters.batch_other_block_size;
    let batch_shard_size = broadcaster_parameters.batch_shard_size;
    let peer = format_authority_index(to_whom_authority_index);

    // 1. Own blocks: send as full blocks
    let own_blocks = {
        let sent = sent_to_peer.read();
        inner
            .dag_state
            .get_unsent_own_blocks(&sent, to_whom_authority_index, batch_own_block_size)
    };

    // 2. Others' headers + shards: consult CordialKnowledge
    let ck = inner
        .cordial_knowledge
        .connection_knowledge(to_whom_authority_index)?;
    let header_candidate_limit =
        batch_other_block_size.saturating_mul(HEADER_PRUNE_OVERFETCH_FACTOR);
    let (header_candidates, shard_refs, useful_headers, useful_shards) = {
        let mut ck = ck.write();
        let current_round = inner.dag_state.highest_round();
        let (useful_headers_to_peer, useful_shards_to_peer) =
            ck.useful_authors_to_peer_bitmasks(current_round);
        let header_refs =
            ck.take_unsent_headers_for_authorities(header_candidate_limit, useful_headers_to_peer);
        let shard_refs =
            ck.take_unsent_shards_for_authorities(batch_shard_size, useful_shards_to_peer);
        let (uh, us) = ck.useful_authors_bitmasks(current_round);
        (header_refs, shard_refs, uh, us)
    };
    let peer_label = peer.to_string();
    report_useful_authorities(metrics, &peer_label, useful_headers, useful_shards);

    let header_refs = inner.dag_state.filter_block_refs_unknown_to_peer(
        &header_candidates,
        to_whom_authority_index,
        batch_other_block_size,
    );
    let header_blocks = inner.dag_state.get_header_only_blocks(&header_refs);
    let shard_payloads = inner.dag_state.get_shard_payloads(&shard_refs);

    // 3. Build structured batch
    let batch = BlockBatch {
        full_blocks: own_blocks,
        headers: header_blocks,
        shards: shard_payloads,
        useful_headers_authors: useful_headers,
        useful_shards_authors: useful_shards,
    };

    if let Ok(size) = bincode::serialized_size(&batch) {
        metrics.block_bundle_size_bytes.observe(size as usize);
    }

    tracing::debug!(
        "Starfish batch to {peer}: {} full, {} headers, {} shards",
        batch.full_blocks.len(),
        batch.headers.len(),
        batch.shards.len()
    );
    let sent_refs: Vec<_> = batch
        .full_blocks
        .iter()
        .map(|b| *b.reference())
        .chain(batch.headers.iter().map(|b| *b.reference()))
        .chain(batch.shards.iter().map(|s| s.block_reference))
        .collect();
    send_batch_and_track(&to, batch, &inner, &sent_to_peer, sent_refs.into_iter()).await
}

async fn sending_batch_causal_starfish_blocks<H, C>(
    inner: Arc<NetworkSyncerInner<H, C>>,
    to: Sender<NetworkMessage>,
    to_whom_authority_index: AuthorityIndex,
    broadcaster_parameters: BroadcasterParameters,
    sent_to_peer: Arc<parking_lot::RwLock<AHashSet<BlockReference>>>,
    metrics: &Metrics,
) -> Option<()>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let committee_size = inner.committee.len();
    let own_index = inner.dag_state.get_own_authority_index();
    let batch_own_block_size = broadcaster_parameters.batch_own_block_size;
    let batch_other_block_size = broadcaster_parameters.batch_other_block_size;
    let batch_shard_size = broadcaster_parameters.batch_shard_size;
    let peer = format_authority_index(to_whom_authority_index);
    let mut authorities_with_missing_blocks: AHashSet<AuthorityIndex> =
        (0..committee_size as AuthorityIndex).collect();
    authorities_with_missing_blocks.remove(&own_index);

    let causal_blocks = {
        let sent = sent_to_peer.read();
        inner.dag_state.get_unsent_causal_history(
            &sent,
            to_whom_authority_index,
            batch_own_block_size,
            batch_other_block_size,
            authorities_with_missing_blocks,
        )
    };

    let own_blocks: Vec<_> = causal_blocks
        .iter()
        .filter(|block| block.authority() == own_index)
        .cloned()
        .collect();
    let header_refs: Vec<_> = causal_blocks
        .iter()
        .filter(|block| block.authority() != own_index)
        .map(|block| *block.reference())
        .collect();
    let header_blocks = inner.dag_state.get_header_only_blocks(&header_refs);

    let current_round = inner.dag_state.highest_round();
    let shard_round_cutoff =
        current_round.saturating_sub(broadcaster_parameters.causal_push_shard_round_lag);
    let shard_refs: Vec<_> = header_refs
        .iter()
        .copied()
        .filter(|block_ref| block_ref.round <= shard_round_cutoff)
        .take(batch_shard_size)
        .collect();
    let shard_payloads = inner.dag_state.get_shard_payloads(&shard_refs);

    let useful_headers = 0;
    let useful_shards = 0;
    report_useful_authorities(metrics, &peer.to_string(), useful_headers, useful_shards);

    let batch = BlockBatch {
        full_blocks: own_blocks,
        headers: header_blocks,
        shards: shard_payloads,
        useful_headers_authors: useful_headers,
        useful_shards_authors: useful_shards,
    };

    if let Ok(size) = bincode::serialized_size(&batch) {
        metrics.block_bundle_size_bytes.observe(size as usize);
    }

    tracing::debug!(
        "Starfish causal batch to {peer}: {} full, {} headers, {} shards",
        batch.full_blocks.len(),
        batch.headers.len(),
        batch.shards.len()
    );
    let sent_refs: Vec<_> = batch
        .full_blocks
        .iter()
        .map(|b| *b.reference())
        .chain(batch.headers.iter().map(|b| *b.reference()))
        .chain(batch.shards.iter().map(|s| s.block_reference))
        .collect();
    send_batch_and_track(&to, batch, &inner, &sent_to_peer, sent_refs.into_iter()).await
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
    parameters: BroadcasterParameters,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::Committee;

    fn holder_set(authorities: &[AuthorityIndex]) -> StakeAggregator<QuorumThreshold> {
        let committee = Committee::new_test(vec![1, 1, 1, 1]);
        let mut holders = StakeAggregator::<QuorumThreshold>::new();
        for authority in authorities {
            holders.add(*authority, committee.as_ref());
        }
        holders
    }

    #[test]
    fn starfish_l_can_request_from_any_peer_even_if_own_is_in_holder_set() {
        let holders = holder_set(&[0, 1, 2, 3]);
        assert!(peer_can_serve_missing_data(
            ConsensusProtocol::StarfishL,
            &holders,
            0,
            1,
        ));
    }

    #[test]
    fn non_starfish_l_only_requests_from_known_remote_holders() {
        let remote_holders = holder_set(&[1, 2, 3]);
        assert!(peer_can_serve_missing_data(
            ConsensusProtocol::Starfish,
            &remote_holders,
            0,
            1,
        ));

        let own_and_remote_holders = holder_set(&[0, 1, 2]);
        assert!(!peer_can_serve_missing_data(
            ConsensusProtocol::Starfish,
            &own_and_remote_holders,
            0,
            1,
        ));
    }
}
