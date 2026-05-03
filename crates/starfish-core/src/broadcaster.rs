// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    cmp::max,
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

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
    dag_state::{ByzantineStrategy, ConsensusProtocol, DataSource},
    data::Data,
    metrics::{Metrics, UtilizationTimerVecExt},
    net_sync::NetworkSyncerInner,
    network::{BlockBatch, NetworkMessage, ShardPayload},
    runtime::{Handle, sleep},
    syncer::CommitObserver,
    types::{
        AuthorityIndex, AuthoritySet, BlockReference, RoundNumber, VerifiedBlock,
        format_authority_index,
    },
};

fn peer_can_serve_missing_data(
    consensus_protocol: ConsensusProtocol,
    holders: &StakeAggregator<QuorumThreshold>,
    own_id: AuthorityIndex,
    peer_id: AuthorityIndex,
) -> bool {
    if consensus_protocol.uses_bls() {
        holders.votes.contains(peer_id)
    } else {
        !holders.votes.contains(own_id) && holders.votes.contains(peer_id)
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
    /// In push-causal mode, shard payloads are piggybacked up to this many
    /// rounds behind the current frontier. A value of `0` means "push as soon
    /// as the shard is ready".
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
            ConsensusProtocol::Mysticeti
            | ConsensusProtocol::SailfishPlusPlus
            | ConsensusProtocol::MysticetiBls => Self {
                batch_own_block_size: committee_size,
                batch_other_block_size: 3 * committee_size,
                batch_shard_size: 3 * committee_size,
                sample_timeout: Duration::from_millis(600),
                dissemination_mode,
                causal_push_shard_round_lag,
            },
            ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishSpeed
            | ConsensusProtocol::StarfishBls
            | ConsensusProtocol::CordialMiners
            | ConsensusProtocol::Bluestreak => Self {
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
            causal_push_shard_round_lag: 0,
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
    metrics: Arc<Metrics>,
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
        metrics: Arc<Metrics>,
        parameters: BroadcasterParameters,
    ) -> Self {
        Self {
            to_whom_authority_index,
            sender,
            inner,
            metrics,
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
        // Ensure the counter time series exists in Prometheus even if no
        // requests are ever sent (avoids "no data" in Grafana).
        self.metrics
            .tx_data_requests_sent
            .with_label_values(&[&self.to_whom_authority_index.to_string()])
            .inc_by(0);
        let handle = Handle::current().spawn(Self::request_missing_data_blocks(
            self.to_whom_authority_index,
            self.sender.clone(),
            self.inner.clone(),
            self.metrics.clone(),
            self.parameters.clone(),
        ));
        self.data_requester = Some(handle);
    }

    async fn request_missing_data_blocks(
        peer_id: AuthorityIndex,
        to: Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        metrics: Arc<Metrics>,
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
                metrics
                    .tx_data_requests_sent
                    .with_label_values(&[&peer_id.to_string()])
                    .inc();
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
            .send(NetworkMessage::Batch(Box::new(BlockBatch::shards_only(
                DataSource::TransactionDataRequest,
                shards,
            ))))
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
            | ConsensusProtocol::StarfishSpeed
            | ConsensusProtocol::StarfishBls => {
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
                        let extra_refs = self
                            .inner
                            .cordial_knowledge
                            .dag_knowledge()
                            .expect("push dissemination requires dag knowledge")
                            .read()
                            .filter_block_refs_unknown_to_peer(
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

                let (headers, shards) = self
                    .inner
                    .dag_state
                    .get_transmission_parts(&refs_to_send, &refs_to_send);
                {
                    let mut sent = self.sent_to_peer.write();
                    for block in headers.iter() {
                        sent.insert(*block.reference());
                    }
                }
                tracing::debug!(
                    "Requested missing parent headers (and extra \
                     potentially-missing headers) {:?} are sent \
                     from {own_index:?} to {peer:?}",
                    headers
                );
                self.sender
                    .send(NetworkMessage::Batch(Box::new(BlockBatch {
                        source: DataSource::BlockHeaderRequest,
                        full_blocks: Vec::new(),
                        headers,
                        shards,
                        useful_headers_authors: AuthoritySet::default(),
                        useful_shards_authors: AuthoritySet::default(),
                    })))
                    .await
                    .ok()?;
            }
            ConsensusProtocol::Mysticeti
            | ConsensusProtocol::CordialMiners
            | ConsensusProtocol::SailfishPlusPlus
            | ConsensusProtocol::Bluestreak
            | ConsensusProtocol::MysticetiBls => {
                let all_blocks: Vec<_> = self
                    .inner
                    .dag_state
                    .get_storage_blocks(&block_references)
                    .into_iter()
                    .flatten()
                    .collect();
                let chunk_size = batch_block_size.max(1);

                // MissingParentsRequest responses must serve the entire requested
                // parent set. Truncating to a single batch can strand late
                // validators permanently behind during catch-up.
                let total_chunks = all_blocks.len().div_ceil(chunk_size);
                for (index, chunk) in all_blocks.chunks(chunk_size).enumerate() {
                    {
                        let mut sent = self.sent_to_peer.write();
                        for block in chunk {
                            sent.insert(*block.reference());
                        }
                    }
                    tracing::debug!(
                        "Requested missing blocks {chunk:?} are sent from {own_index:?} to {peer:?}"
                    );
                    self.sender
                        .send(NetworkMessage::Batch(Box::new(BlockBatch::full_only(
                            DataSource::BlockHeaderRequest,
                            chunk.to_vec(),
                        ))))
                        .await
                        .ok()?;
                    if index + 1 < total_chunks {
                        let _sleep = sleep(MISSING_PARENTS_CHUNK_DELAY).await;
                    }
                }
            }
        }
        Some(())
    }

    pub async fn disseminate_own_blocks(&mut self, round: RoundNumber) {
        if let Some(existing) = self.own_blocks.take() {
            existing.abort();
            existing.await.ok();
        }

        let handle = Handle::current().spawn(Self::stream_own_block_batches(
            self.universal_committer.clone(),
            self.to_whom_authority_index,
            self.sender.clone(),
            self.inner.clone(),
            round,
            self.parameters.clone(),
            self.metrics.clone(),
            self.sent_to_peer.clone(),
        ));
        self.own_blocks = Some(handle);
    }

    pub async fn start_push_batch_stream(&mut self, round: RoundNumber) {
        if let Some(existing) = self.push_blocks.take() {
            existing.abort();
            existing.await.ok();
        }

        let handle = Handle::current().spawn(Self::stream_dissemination_batches(
            self.to_whom_authority_index,
            self.sender.clone(),
            self.inner.clone(),
            round,
            self.parameters.clone(),
            self.metrics.clone(),
            self.sent_to_peer.clone(),
        ));
        self.push_blocks = Some(handle);
    }

    async fn stream_own_block_batches(
        universal_committer: UniversalCommitter,
        to_whom_authority_index: AuthorityIndex,
        to: Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        mut round: RoundNumber,
        broadcaster_parameters: BroadcasterParameters,
        metrics: Arc<Metrics>,
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
            let notified = inner.block_ready_notify.notified();
            match byzantine_strategy {
                // Don't send your leader block for at least timeout
                Some(ByzantineStrategy::TimeoutLeader) => {
                    let leaders_current_round = universal_committer.get_leaders(current_round);
                    if leaders_current_round.contains(&own_authority_index) {
                        let _sleep = sleep(sample_timeout).await;
                    }
                    send_own_block_batch(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        batch_byzantine_own_block_size,
                        &metrics,
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
                            send_own_block_batch(
                                inner.clone(),
                                to.clone(),
                                to_whom_authority_index,
                                &mut round,
                                batch_byzantine_own_block_size,
                                &metrics,
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
                            send_own_block_batch(
                                inner.clone(),
                                to.clone(),
                                to_whom_authority_index,
                                &mut round,
                                batch_byzantine_own_block_size,
                                &metrics,
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
                        send_own_block_batch(
                            inner.clone(),
                            to.clone(),
                            to_whom_authority_index,
                            &mut round,
                            batch_byzantine_own_block_size,
                            &metrics,
                            sent_to_peer.clone(),
                        )
                        .await?;
                    }
                    notified.await;
                }
                // Create two equivocating blocks and, send the first one to the first 50% and the
                // second to the other 50% of the validators
                Some(ByzantineStrategy::EquivocatingTwoChains) => {
                    send_own_block_batch(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        batch_byzantine_own_block_size,
                        &metrics,
                        sent_to_peer.clone(),
                    )
                    .await?;

                    notified.await;
                }
                // Send an equivocating block to the authority whenever it is created
                Some(ByzantineStrategy::EquivocatingChains) => {
                    send_own_block_batch(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        batch_byzantine_own_block_size,
                        &metrics,
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
                        send_own_block_batch(
                            inner.clone(),
                            to.clone(),
                            to_whom_authority_index,
                            &mut round,
                            batch_byzantine_own_block_size,
                            &metrics,
                            sent_to_peer.clone(),
                        )
                        .await?;
                    }
                    notified.await;
                }
                // Send block to the authority whenever a new block is created
                // Additionally try to send blocks after a timeout
                _ => {
                    send_own_block_batch(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        batch_own_block_size,
                        &metrics,
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

    async fn stream_dissemination_batches(
        to_whom_authority_index: AuthorityIndex,
        to: Sender<NetworkMessage>,
        inner: Arc<NetworkSyncerInner<H, C>>,
        mut round: RoundNumber,
        broadcaster_parameters: BroadcasterParameters,
        metrics: Arc<Metrics>,
        sent_to_peer: Arc<parking_lot::RwLock<AHashSet<BlockReference>>>,
    ) -> Option<()> {
        let sample_timeout = broadcaster_parameters.sample_timeout;
        loop {
            let block_notified = inner.block_ready_notify.notified();
            let proposal_round_notified = inner.proposal_round_notify.notified();
            let trigger = select! {
                _ = sleep(sample_timeout) => "timeout",
                _ = block_notified => "new block",
                _ = proposal_round_notified => "proposal round",
            };
            let timer = metrics
                .utilization_timer
                .utilization_timer("Broadcaster: send blocks");
            tracing::debug!("Disseminate to {to_whom_authority_index} after {trigger}");
            match broadcaster_parameters.dissemination_mode {
                DisseminationMode::Pull => {
                    send_full_block_batch(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        broadcaster_parameters.clone(),
                        sent_to_peer.clone(),
                        &metrics,
                    )
                    .await?;
                }
                DisseminationMode::PushCausal => {
                    send_push_batch(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        broadcaster_parameters.clone(),
                        sent_to_peer.clone(),
                        &metrics,
                        PushSelectionMode::Causal,
                    )
                    .await?;
                }
                DisseminationMode::PushUseful => {
                    send_push_batch(
                        inner.clone(),
                        to.clone(),
                        to_whom_authority_index,
                        &mut round,
                        broadcaster_parameters.clone(),
                        sent_to_peer.clone(),
                        &metrics,
                        PushSelectionMode::Useful,
                    )
                    .await?;
                }
                DisseminationMode::ProtocolDefault => {
                    unreachable!("protocol-default dissemination mode must be resolved")
                }
            }
            drop(timer);
        }
    }
}

async fn send_own_block_batch<H, C>(
    inner: Arc<NetworkSyncerInner<H, C>>,
    to: Sender<NetworkMessage>,
    to_whom_authority_index: AuthorityIndex,
    round: &mut RoundNumber,
    batch_size: usize,
    metrics: &Metrics,
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
    let batch = BlockBatch::full_only(DataSource::BlockBundleStreaming, blocks);
    if let Ok(size) = bincode::serialized_size(&batch) {
        metrics.block_bundle_size_bytes.observe(size as usize);
    }
    to.send(NetworkMessage::Batch(Box::new(batch))).await.ok()?;
    Some(())
}

fn report_useful_authorities(
    metrics: &Metrics,
    peer: &str,
    useful_headers: AuthoritySet,
    useful_shards: AuthoritySet,
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
const MISSING_PARENTS_CHUNK_DELAY: Duration = Duration::from_millis(25);

#[derive(Clone, Copy)]
enum PushSelectionMode {
    Causal,
    Useful,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PushOtherBlocksFormat {
    FullBlocks,
    HeadersAndShards,
}

struct PushBatchParts {
    own_blocks: Vec<Data<VerifiedBlock>>,
    other_refs: Vec<BlockReference>,
    shard_refs: Vec<BlockReference>,
    useful_headers: AuthoritySet,
    useful_shards: AuthoritySet,
}

fn push_transport_format(consensus_protocol: ConsensusProtocol) -> PushOtherBlocksFormat {
    match consensus_protocol {
        ConsensusProtocol::Starfish
        | ConsensusProtocol::StarfishSpeed
        | ConsensusProtocol::StarfishBls => PushOtherBlocksFormat::HeadersAndShards,
        ConsensusProtocol::CordialMiners
        | ConsensusProtocol::Mysticeti
        | ConsensusProtocol::SailfishPlusPlus
        | ConsensusProtocol::Bluestreak
        | ConsensusProtocol::MysticetiBls => PushOtherBlocksFormat::FullBlocks,
    }
}

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
        to.send(NetworkMessage::Batch(Box::new(batch))).await.ok()?;
    }
    Some(())
}

fn take_previous_round_header_refs<H, C>(
    inner: &Arc<NetworkSyncerInner<H, C>>,
    peer: AuthorityIndex,
    round: RoundNumber,
    limit: usize,
) -> Vec<BlockReference>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let own_authority = inner.dag_state.get_own_authority_index();
    let Some(ck) = inner.cordial_knowledge.connection_knowledge(peer) else {
        return Vec::new();
    };
    let header_refs =
        ck.write()
            .take_unsent_headers_at_round_excluding_authority(limit, round, own_authority);
    header_refs
}

fn collect_unsent_ancestor_header_refs<H, C>(
    inner: &Arc<NetworkSyncerInner<H, C>>,
    peer: AuthorityIndex,
    own_authority: AuthorityIndex,
    sent_to_peer: &parking_lot::RwLock<AHashSet<BlockReference>>,
    roots: &[BlockReference],
    limit: usize,
) -> Vec<BlockReference>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    if limit == 0 || roots.is_empty() {
        return Vec::new();
    }

    let Some(ck) = inner.cordial_knowledge.connection_knowledge(peer) else {
        return Vec::new();
    };
    let sent = sent_to_peer.read();
    let mut queued = AHashSet::with_capacity(roots.len());
    let mut frontier: VecDeque<_> = roots.iter().copied().collect();
    let mut collected = Vec::with_capacity(limit);

    while !frontier.is_empty() && collected.len() < limit {
        let frontier_refs: Vec<_> = frontier.drain(..).collect();
        let blocks = inner.dag_state.get_storage_blocks(&frontier_refs);
        for block in blocks.into_iter().flatten() {
            for parent in block.block_references() {
                if parent.round == 0
                    || parent.authority == peer
                    || parent.authority == own_authority
                    || sent.contains(parent)
                    || !queued.insert(*parent)
                {
                    continue;
                }
                if ck.read().knows_header(parent) {
                    continue;
                }
                collected.push(*parent);
                frontier.push_back(*parent);
                if collected.len() >= limit {
                    break;
                }
            }
            if collected.len() >= limit {
                break;
            }
        }
    }

    if !collected.is_empty() {
        let mut known = ck.write();
        for block_ref in &collected {
            known.mark_header_known(*block_ref);
        }
    }

    collected
}

fn take_causal_shard_refs<H, C>(
    inner: &Arc<NetworkSyncerInner<H, C>>,
    peer: AuthorityIndex,
    own_authority: AuthorityIndex,
    max_round: RoundNumber,
    limit: usize,
) -> Vec<BlockReference>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    if limit == 0 || max_round == 0 {
        return Vec::new();
    }

    let Some(ck) = inner.cordial_knowledge.connection_knowledge(peer) else {
        return Vec::new();
    };
    let shard_refs = ck
        .write()
        .take_unsent_shards_up_to_round_excluding_authority(limit, max_round, own_authority);
    shard_refs
}

async fn send_full_block_batch<H, C>(
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
    // In pull mode only own blocks are proactively disseminated;
    // peers obtain other blocks via MissingParentsRequest.
    let batch_own_block_size = broadcaster_parameters.batch_own_block_size;
    let peer = format_authority_index(to_whom_authority_index);
    let blocks = {
        let sent = sent_to_peer.read();
        inner.dag_state.get_unsent_own_blocks_pull(
            &sent,
            to_whom_authority_index,
            batch_own_block_size,
        )
    };
    // Full-block protocols do not advertise header/shard usefulness.
    let useful_headers = AuthoritySet::default();
    let useful_shards = AuthoritySet::default();
    report_useful_authorities(metrics, peer.as_str(), useful_headers, useful_shards);

    tracing::debug!("Blocks to be sent to {peer} are {blocks:?}");
    let batch = BlockBatch {
        source: DataSource::BlockBundleStreaming,
        full_blocks: blocks,
        headers: Vec::new(),
        shards: Vec::new(),
        useful_headers_authors: useful_headers,
        useful_shards_authors: useful_shards,
    };
    if let Ok(size) = bincode::serialized_size(&batch) {
        metrics.block_bundle_size_bytes.observe(size as usize);
    }
    let sent_refs: Vec<_> = batch.full_blocks.iter().map(|b| *b.reference()).collect();
    send_batch_and_track(&to, batch, &inner, &sent_to_peer, sent_refs.into_iter()).await
}

fn select_push_batch_parts<H, C>(
    inner: &Arc<NetworkSyncerInner<H, C>>,
    to_whom_authority_index: AuthorityIndex,
    own_round: RoundNumber,
    broadcaster_parameters: &BroadcasterParameters,
    sent_to_peer: &Arc<parking_lot::RwLock<AHashSet<BlockReference>>>,
    selection_mode: PushSelectionMode,
) -> Option<PushBatchParts>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let own_authority = inner.dag_state.get_own_authority_index();
    let other_blocks_format = push_transport_format(inner.dag_state.consensus_protocol);
    let own_blocks = inner.dag_state.get_own_transmission_blocks(
        to_whom_authority_index,
        own_round,
        broadcaster_parameters.batch_own_block_size,
    );
    let own_refs: AHashSet<_> = own_blocks.iter().map(|block| *block.reference()).collect();

    let (mut other_refs, mut shard_refs, useful_headers, useful_shards) = match selection_mode {
        PushSelectionMode::Causal => {
            let newest_own_round = own_blocks.iter().map(|block| block.round()).max();
            let mut other_refs = Vec::new();
            let mut shard_refs = Vec::new();

            if let Some(newest_round) = newest_own_round {
                let previous_round = newest_round.saturating_sub(1);
                if previous_round > 0 {
                    let seed_refs = take_previous_round_header_refs(
                        inner,
                        to_whom_authority_index,
                        previous_round,
                        broadcaster_parameters.batch_other_block_size,
                    );
                    let ancestor_refs = collect_unsent_ancestor_header_refs(
                        inner,
                        to_whom_authority_index,
                        own_authority,
                        sent_to_peer,
                        &seed_refs,
                        broadcaster_parameters
                            .batch_other_block_size
                            .saturating_sub(seed_refs.len()),
                    );
                    other_refs.extend(seed_refs);
                    other_refs.extend(ancestor_refs);
                }

                if other_blocks_format == PushOtherBlocksFormat::HeadersAndShards {
                    let shard_round_cutoff = newest_round
                        .saturating_sub(broadcaster_parameters.causal_push_shard_round_lag);
                    shard_refs = take_causal_shard_refs(
                        inner,
                        to_whom_authority_index,
                        own_authority,
                        shard_round_cutoff,
                        broadcaster_parameters.batch_shard_size,
                    );
                }
            }

            (
                other_refs,
                shard_refs,
                AuthoritySet::default(),
                AuthoritySet::default(),
            )
        }
        PushSelectionMode::Useful => {
            let ck = inner
                .cordial_knowledge
                .connection_knowledge(to_whom_authority_index)?;
            let header_candidate_limit = broadcaster_parameters
                .batch_other_block_size
                .saturating_mul(HEADER_PRUNE_OVERFETCH_FACTOR);
            let (other_candidates, shard_refs, useful_headers, useful_shards) = {
                let mut ck = ck.write();
                let current_round = inner.dag_state.highest_round();
                let (useful_headers_to_peer, useful_shards_to_peer) =
                    ck.useful_authors_to_peer_bitmasks(current_round);
                let other_candidates = ck.take_unsent_headers_for_authorities(
                    header_candidate_limit,
                    useful_headers_to_peer,
                );
                let shard_refs = if other_blocks_format == PushOtherBlocksFormat::HeadersAndShards {
                    ck.take_unsent_shards_for_authorities(
                        broadcaster_parameters.batch_shard_size,
                        useful_shards_to_peer,
                    )
                } else {
                    Vec::new()
                };
                let (useful_headers, useful_shards) = ck.useful_authors_bitmasks(current_round);
                (
                    other_candidates,
                    shard_refs,
                    useful_headers,
                    if other_blocks_format == PushOtherBlocksFormat::HeadersAndShards {
                        useful_shards
                    } else {
                        AuthoritySet::default()
                    },
                )
            };
            let other_refs = inner
                .cordial_knowledge
                .dag_knowledge()
                .expect("push dissemination requires dag knowledge")
                .read()
                .filter_block_refs_unknown_to_peer(
                    &other_candidates,
                    to_whom_authority_index,
                    broadcaster_parameters.batch_other_block_size,
                );
            (other_refs, shard_refs, useful_headers, useful_shards)
        }
    };

    other_refs.retain(|block_ref| !own_refs.contains(block_ref));
    shard_refs.retain(|block_ref| !own_refs.contains(block_ref));

    Some(PushBatchParts {
        own_blocks,
        other_refs,
        shard_refs,
        useful_headers,
        useful_shards,
    })
}

fn materialize_push_batch<H, C>(
    inner: &Arc<NetworkSyncerInner<H, C>>,
    plan: PushBatchParts,
) -> BlockBatch
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    match push_transport_format(inner.dag_state.consensus_protocol) {
        PushOtherBlocksFormat::FullBlocks => {
            let mut full_blocks = plan.own_blocks;
            full_blocks.extend(
                inner
                    .dag_state
                    .get_transmission_blocks(&plan.other_refs)
                    .into_iter()
                    .flatten(),
            );
            BlockBatch {
                source: DataSource::BlockBundleStreaming,
                full_blocks,
                headers: Vec::new(),
                shards: Vec::new(),
                useful_headers_authors: plan.useful_headers,
                useful_shards_authors: AuthoritySet::default(),
            }
        }
        PushOtherBlocksFormat::HeadersAndShards => {
            let (headers, shards) = inner
                .dag_state
                .get_transmission_parts(&plan.other_refs, &plan.shard_refs);
            BlockBatch {
                source: DataSource::BlockBundleStreaming,
                full_blocks: plan.own_blocks,
                headers,
                shards,
                useful_headers_authors: plan.useful_headers,
                useful_shards_authors: plan.useful_shards,
            }
        }
    }
}

async fn send_push_batch<H, C>(
    inner: Arc<NetworkSyncerInner<H, C>>,
    to: Sender<NetworkMessage>,
    to_whom_authority_index: AuthorityIndex,
    round: &mut RoundNumber,
    broadcaster_parameters: BroadcasterParameters,
    sent_to_peer: Arc<parking_lot::RwLock<AHashSet<BlockReference>>>,
    metrics: &Metrics,
    selection_mode: PushSelectionMode,
) -> Option<()>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let peer = format_authority_index(to_whom_authority_index);
    let plan = select_push_batch_parts(
        &inner,
        to_whom_authority_index,
        *round,
        &broadcaster_parameters,
        &sent_to_peer,
        selection_mode,
    );
    report_useful_authorities(
        metrics,
        peer.as_str(),
        plan.as_ref()
            .map_or(AuthoritySet::default(), |p| p.useful_headers),
        plan.as_ref()
            .map_or(AuthoritySet::default(), |p| p.useful_shards),
    );
    let plan = plan?;
    if let Some(max_round) = plan.own_blocks.iter().map(|block| block.round()).max() {
        *round = max_round;
    }

    let batch = materialize_push_batch(&inner, plan);
    if let Ok(size) = bincode::serialized_size(&batch) {
        metrics.block_bundle_size_bytes.observe(size as usize);
    }

    tracing::debug!(
        "Push batch to {peer}: {} full, {} headers, {} shards",
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
    fn starfish_bls_can_request_from_any_peer_even_if_own_is_in_holder_set() {
        let holders = holder_set(&[0, 1, 2, 3]);
        assert!(peer_can_serve_missing_data(
            ConsensusProtocol::StarfishBls,
            &holders,
            0,
            1,
        ));
    }

    #[test]
    fn non_starfish_bls_only_requests_from_known_remote_holders() {
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
