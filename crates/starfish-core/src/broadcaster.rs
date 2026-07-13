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
    dag_state::{ByzantineStrategy, ConsensusProtocol, DataSource},
    data::Data,
    metrics::{Metrics, UtilizationTimerVecExt},
    net_sync::{NetworkSyncerInner, prepare_forwarded_blocks_for_peer},
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

const RAMP_UP_CHAIN_BOMB_SECS: f64 = 180.0;

fn ramp_up_chain_bomb_release_probability(elapsed_secs: f64) -> f64 {
    (elapsed_secs / RAMP_UP_CHAIN_BOMB_SECS).clamp(0.0, 1.0)
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
            | ConsensusProtocol::Bluestreak
            | ConsensusProtocol::SparseStarfishSpeed => Self {
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
        // Per-block 2f+1 quorum used to *advertise* shard demand:
        // for each missing block, only the 2f+1 authorities starting
        // at the block's author (wrapping) are told via the next
        // outgoing block bundle that we need shards for that author —
        // they then proactively include those shards in their batches
        // back to us. The MissingTxDataRequest itself still goes to
        // every peer since we don't know which one will respond first.
        let committee_size = inner.committee.len();
        let quorum_count = 2 * committee_size / 3 + 1;
        let peer_idx = peer_id as usize;
        let in_block_quorum = |block_ref: &BlockReference| -> bool {
            let author = block_ref.authority as usize;
            let dist = (peer_idx + committee_size - author) % committee_size;
            dist < quorum_count
        };
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
                // Of the requested refs, advertise demand only on this
                // peer's ConnectionKnowledge if this peer falls in the
                // block's per-block 2f+1 quorum. The marker is read by
                // `useful_authors_bitmasks` when we build the next
                // outgoing bundle to this peer, so the peer learns it
                // should proactively send shards from those authors.
                let advertise: Vec<_> =
                    to_request.iter().copied().filter(in_block_quorum).collect();
                if !advertise.is_empty() {
                    if let Some(ck) = inner.cordial_knowledge.connection_knowledge(peer_id) {
                        ck.write().mark_shards_useful_from_peer(&advertise);
                    }
                }
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
            | ConsensusProtocol::StarfishBls
            | ConsensusProtocol::SparseStarfishSpeed => {
                let mut refs_to_send = block_references;
                let remaining_extra_budget =
                    batch_other_block_size.saturating_sub(refs_to_send.len());

                if self.parameters.dissemination_mode == DisseminationMode::PushUseful
                    && remaining_extra_budget > 0
                {
                    if let Some(ck) = self.inner.cordial_knowledge.connection_knowledge(peer_id) {
                        let current_round = self.inner.dag_state.highest_round();
                        let extra_candidates = {
                            let mut ck = ck.write();
                            let (useful_headers_to_peer, _) =
                                ck.useful_authors_to_peer_bitmasks(current_round);
                            ck.take_unsent_headers_for_authorities(
                                remaining_extra_budget,
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
                let headers = prepare_forwarded_blocks_for_peer(
                    self.inner.dag_state.block_authentication_scheme,
                    peer_id,
                    headers,
                );
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
                // Send a chain of own blocks to a 2f+1 quorum of peers
                // (the next 2f+1 indices after self, wrapping). Same
                // trigger as ChainBomb but a wider blast radius —
                // enough to influence the next commit decision.
                Some(ByzantineStrategy::ChainBombQuorum) => {
                    if current_round as usize % committee_size == own_authority_index as usize {
                        let quorum_count = 2 * committee_size / 3 + 1;
                        let dist = (to_whom_authority_index as usize + committee_size
                            - own_authority_index as usize
                            - 1)
                            % committee_size;
                        if dist < quorum_count {
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
                // ChainBomb shape with a time ramp: initially withhold, then
                // probabilistically release to the next leader until it fully
                // matches ChainBomb after 3 minutes.
                Some(ByzantineStrategy::RampUpWithholding) => {
                    if current_round as usize % committee_size == own_authority_index as usize {
                        let leaders_next_round = universal_committer.get_leaders(current_round + 1);
                        if leaders_next_round.contains(&to_whom_authority_index) {
                            let release_probability = ramp_up_chain_bomb_release_probability(
                                inner.start_time.elapsed().as_secs_f64(),
                            );
                            if rng.gen_bool(release_probability) {
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
        | ConsensusProtocol::StarfishBls
        | ConsensusProtocol::SparseStarfishSpeed => PushOtherBlocksFormat::HeadersAndShards,
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

fn take_unknown_causal_history_header_refs<H, C>(
    inner: &Arc<NetworkSyncerInner<H, C>>,
    peer: AuthorityIndex,
    own_authority: AuthorityIndex,
    own_blocks: &[Data<VerifiedBlock>],
    sent_to_peer: &AHashSet<BlockReference>,
    limit: usize,
) -> Vec<BlockReference>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    if limit == 0 {
        return Vec::new();
    }

    let Some(dag) = inner.cordial_knowledge.dag_knowledge() else {
        return Vec::new();
    };

    // Fast path: include direct parents of newly pushed own blocks that we
    // believe the peer is missing, even if the CordialKnowledge actor hasn't
    // yet processed the new block's `BlockAdded` event.
    let dag = dag.read();
    let mut direct_unknown: Vec<BlockReference> = Vec::new();
    let mut seen = AHashSet::new();
    for block in own_blocks {
        for parent in block.block_references().iter().copied() {
            if direct_unknown.len() >= limit {
                return direct_unknown;
            }
            if parent.round == 0
                || parent.authority == peer
                || parent.authority == own_authority
                || sent_to_peer.contains(&parent)
                || !seen.insert(parent)
            {
                continue;
            }
            if dag.peer_knows(&parent, peer).unwrap_or(false) {
                continue;
            }
            direct_unknown.push(parent);
        }
    }

    // Fill remaining budget by walking further ancestors using the in-memory
    // parent graph in CordialKnowledge (no DagState traversal).
    let remaining = limit.saturating_sub(direct_unknown.len());
    if remaining > 0 && !direct_unknown.is_empty() {
        let more = dag.collect_unsent_ancestor_refs(
            &direct_unknown,
            peer,
            own_authority,
            sent_to_peer,
            remaining,
        );
        direct_unknown.extend(more);
    }

    direct_unknown
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
    own_blocks: Vec<Data<VerifiedBlock>>,
    broadcaster_parameters: &BroadcasterParameters,
    selection_mode: PushSelectionMode,
    sent_to_peer: &parking_lot::RwLock<AHashSet<BlockReference>>,
) -> Option<PushBatchParts>
where
    C: 'static + CommitObserver,
    H: 'static + BlockHandler,
{
    let own_authority = inner.dag_state.get_own_authority_index();
    let other_blocks_format = push_transport_format(inner.dag_state.consensus_protocol);
    let own_refs: AHashSet<_> = own_blocks.iter().map(|block| *block.reference()).collect();
    // When pushing in `PushUseful` mode we may select a block that references
    // direct ancestors whose authors are *not* currently considered "useful"
    // to the peer. Proactively prioritizing those ancestors avoids a
    // MissingParentsRequest round-trip for freshly created blocks.
    let own_direct_ancestor_refs: Vec<BlockReference> = own_blocks
        .iter()
        .flat_map(|block| block.block_references().iter().copied())
        .filter(|r| {
            r.round > 0
                && r.authority != to_whom_authority_index
                // Avoid sending our own history as header-only in Starfish
                // variants; own blocks are disseminated as full blocks via
                // `own_blocks`.
                && r.authority != own_authority
        })
        .collect();

    let (mut other_refs, mut shard_refs, useful_headers, useful_shards) = match selection_mode {
        PushSelectionMode::Causal => {
            let newest_own_round = own_blocks.iter().map(|block| block.round()).max();
            let other_refs = {
                let sent = sent_to_peer.read();
                take_unknown_causal_history_header_refs(
                    inner,
                    to_whom_authority_index,
                    own_authority,
                    &own_blocks,
                    &sent,
                    broadcaster_parameters.batch_other_block_size,
                )
            };
            let mut shard_refs = Vec::new();

            if let Some(newest_round) = newest_own_round {
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
            // In `PushUseful` we normally only piggyback headers from authors
            // currently deemed useful to the peer. However, a freshly created
            // own block may reference direct ancestors from other authors that
            // are not (yet) useful. If we omit them, the peer will be forced to
            // issue a MissingParentsRequest round-trip for those parents.
            //
            // Important: `ConnectionKnowledge::take_*` advances cursors / marks
            // returned refs as known (sent). Therefore we must reserve budget
            // for these direct ancestors first, and only *then* take the
            // remaining capacity from `ConnectionKnowledge`, otherwise we can
            // "burn" refs that never make it into the final batch.

            // Dedup direct ancestors, keep only those whose author is currently
            // considered "useful" to the peer per CordialKnowledge, and filter
            // out ones we already believe the peer knows. Authors that are not
            // useful are intentionally omitted — `PushUseful` only piggybacks
            // headers from the useful set; non-useful ancestors are recovered
            // by the peer via `MissingParentsRequest` if and when needed.
            let mut direct_candidates: Vec<BlockReference> = Vec::new();
            if !own_direct_ancestor_refs.is_empty() {
                let mut seen = AHashSet::with_capacity(own_direct_ancestor_refs.len());
                let ck_read = ck.read();
                let current_round = inner.dag_state.highest_round();
                let (useful_headers_to_peer, _) =
                    ck_read.useful_authors_to_peer_bitmasks(current_round);
                for r in own_direct_ancestor_refs.iter().copied() {
                    if seen.insert(r)
                        && useful_headers_to_peer.contains(r.authority)
                        && !ck_read.knows_header(&r)
                    {
                        direct_candidates.push(r);
                    }
                }
            }

            // Further filter using transitive known-by inference (if tracked).
            // If the ref is not in dag_knowledge (e.g. evicted), keep it to
            // match prior behavior.
            let mut direct_unknown: Vec<BlockReference> = if direct_candidates.is_empty() {
                Vec::new()
            } else {
                inner
                    .cordial_knowledge
                    .dag_knowledge()
                    .expect("push dissemination requires dag knowledge")
                    .read()
                    .filter_block_refs_unknown_to_peer(
                        &direct_candidates,
                        to_whom_authority_index,
                        direct_candidates.len(),
                    )
            };

            // Don't mark/send more direct ancestors than we can fit in the
            // batch. Any overflow must remain eligible for later batches.
            direct_unknown.truncate(broadcaster_parameters.batch_other_block_size);

            let remaining_other_budget = broadcaster_parameters
                .batch_other_block_size
                .saturating_sub(direct_unknown.len());

            let current_round = inner.dag_state.highest_round();
            let (other_candidates, shard_refs, useful_headers, useful_shards) = {
                let mut ck = ck.write();

                let (useful_headers_to_peer, useful_shards_to_peer) =
                    ck.useful_authors_to_peer_bitmasks(current_round);
                let other_candidates = ck.take_unsent_headers_for_authorities(
                    remaining_other_budget,
                    useful_headers_to_peer,
                );
                // Record direct ancestors as known so we don't repeatedly
                // re-send them on subsequent batches.
                for r in direct_unknown.iter().copied() {
                    ck.mark_header_known(r);
                }
                let shard_refs = if other_blocks_format == PushOtherBlocksFormat::HeadersAndShards {
                    ck.take_unsent_shards_for_authorities(
                        broadcaster_parameters.batch_shard_size,
                        useful_shards_to_peer,
                    )
                } else {
                    Vec::new()
                };
                let (useful_headers, useful_shards) = ck.useful_authors_bitmasks(current_round);
                (other_candidates, shard_refs, useful_headers, useful_shards)
            };

            // Shard demand is now explicit-only: `mark_shards_useful_from_peer`
            // fires solely from `request_missing_data_blocks` when this node
            // sends a `MissingTxDataRequest` (broadcaster.rs:282). Header
            // arrivals must NOT leak into the shard side — that was the bug
            // making `useful_shards_authors` saturate to the full committee
            // even with zero `tx_data_requests_sent`.
            let useful_shards = if other_blocks_format == PushOtherBlocksFormat::HeadersAndShards {
                useful_shards
            } else {
                AuthoritySet::default()
            };

            // Combine direct ancestors first, then the normal useful candidates,
            // and filter out any refs already known by the peer according to the
            // transitive DAG knowledge.
            let mut combined_candidates: Vec<BlockReference> =
                Vec::with_capacity(direct_unknown.len().saturating_add(other_candidates.len()));
            combined_candidates.extend(direct_unknown.iter().copied());
            combined_candidates.extend(other_candidates);
            if combined_candidates.len() > 1 {
                // Dedup while keeping earlier entries (direct ancestors) first.
                let mut seen = AHashSet::with_capacity(combined_candidates.len());
                combined_candidates.retain(|r| seen.insert(*r));
            }

            let other_refs = if combined_candidates.is_empty() {
                Vec::new()
            } else {
                inner
                    .cordial_knowledge
                    .dag_knowledge()
                    .expect("push dissemination requires dag knowledge")
                    .read()
                    .filter_block_refs_unknown_to_peer(
                        &combined_candidates,
                        to_whom_authority_index,
                        broadcaster_parameters.batch_other_block_size,
                    )
            };

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
    to_whom_authority_index: AuthorityIndex,
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
            let headers = prepare_forwarded_blocks_for_peer(
                inner.dag_state.block_authentication_scheme,
                to_whom_authority_index,
                headers,
            );
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

    // Phase 1 — fast batch: ship the freshly produced own blocks BEFORE
    // acquiring any CordialKnowledge locks in `select_push_batch_parts`.
    // The own block is the latency-critical payload (everyone needs it to
    // advance their threshold-clock); the heavier headers + shards
    // selection lives on the wire in a follow-up message so it never gates
    // the receiver's next round.
    let own_blocks = inner.dag_state.get_own_transmission_blocks(
        to_whom_authority_index,
        *round,
        broadcaster_parameters.batch_own_block_size,
    );
    if let Some(max_round) = own_blocks.iter().map(|b| b.round()).max() {
        *round = max_round;
    }
    if !own_blocks.is_empty() {
        let fast_batch =
            BlockBatch::full_only(DataSource::BlockBundleStreaming, own_blocks.clone());
        if let Ok(size) = bincode::serialized_size(&fast_batch) {
            metrics.block_bundle_size_bytes.observe(size as usize);
        }
        let own_refs: Vec<_> = own_blocks.iter().map(|b| *b.reference()).collect();
        tracing::debug!(
            "Push fast batch to {peer}: {} full own blocks",
            fast_batch.full_blocks.len()
        );
        send_batch_and_track(&to, fast_batch, &inner, &sent_to_peer, own_refs.into_iter()).await?;
    }

    // Phase 2 — slow batch: heavy selection (CK reads/writes) for headers
    // + shards. Own blocks are already on the wire from Phase 1, so we
    // pass them in only to let the selection logic skip them.
    let plan = select_push_batch_parts(
        &inner,
        to_whom_authority_index,
        own_blocks,
        &broadcaster_parameters,
        selection_mode,
        sent_to_peer.as_ref(),
    );
    report_useful_authorities(
        metrics,
        peer.as_str(),
        plan.as_ref()
            .map_or(AuthoritySet::default(), |p| p.useful_headers),
        plan.as_ref()
            .map_or(AuthoritySet::default(), |p| p.useful_shards),
    );
    let mut plan = plan?;

    // Drop own blocks from the plan — already shipped in the fast batch.
    plan.own_blocks = Vec::new();

    let slow_batch = materialize_push_batch(&inner, to_whom_authority_index, plan);
    if slow_batch.is_empty() {
        return Some(());
    }
    if let Ok(size) = bincode::serialized_size(&slow_batch) {
        metrics.block_bundle_size_bytes.observe(size as usize);
    }

    tracing::debug!(
        "Push slow batch to {peer}: {} headers, {} shards",
        slow_batch.headers.len(),
        slow_batch.shards.len()
    );
    let slow_refs: Vec<_> = slow_batch
        .headers
        .iter()
        .map(|b| *b.reference())
        .chain(slow_batch.shards.iter().map(|s| s.block_reference))
        .collect();
    send_batch_and_track(
        &to,
        slow_batch,
        &inner,
        &sent_to_peer,
        slow_refs.into_iter(),
    )
    .await
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
    use crate::{
        committee::Committee,
        crypto::{SignatureBytes, mac_keyrings_for_test},
        types::{BaseTransaction, BlockAuthentication, BlockAuthenticationScheme},
    };

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

    #[test]
    fn ramp_up_chain_bomb_probability_reaches_full_release_at_three_minutes() {
        assert_eq!(ramp_up_chain_bomb_release_probability(0.0), 0.0);
        assert_eq!(ramp_up_chain_bomb_release_probability(90.0), 0.5);
        assert_eq!(ramp_up_chain_bomb_release_probability(180.0), 1.0);
        assert_eq!(ramp_up_chain_bomb_release_probability(240.0), 1.0);
    }

    #[test]
    fn relay_preparation_selects_recipient_tag_and_stops_after_one_hop() {
        let committee = Committee::new_for_benchmarks(4);
        let keyrings = mac_keyrings_for_test(committee.len());
        let mut block = VerifiedBlock::new(
            0,
            1,
            Vec::new(),
            Vec::new(),
            0,
            SignatureBytes::default(),
            Vec::<BaseTransaction>::new(),
            None,
            None,
            None,
            None,
        );
        let tags: Vec<_> = keyrings[0]
            .iter()
            .enumerate()
            .map(|(recipient, key)| {
                key.compute_tag(0, recipient as AuthorityIndex, &block.digest())
            })
            .collect();
        let expected = tags[2];
        block.header.authentication = BlockAuthentication::MacVector(tags);

        let relayed = prepare_forwarded_blocks_for_peer(
            BlockAuthenticationScheme::MacVector,
            2,
            vec![Data::new(block)],
        );
        assert_eq!(relayed.len(), 1);
        assert!(matches!(
            relayed[0].authentication(),
            BlockAuthentication::MacTag(tag) if *tag == expected
        ));

        let second_hop =
            prepare_forwarded_blocks_for_peer(BlockAuthenticationScheme::MacVector, 3, relayed);
        assert!(second_hop.is_empty());
    }
}
