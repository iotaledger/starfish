// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use ahash::{AHashMap, AHashSet};
use futures::future::join_all;
use reed_solomon_simd::ReedSolomonEncoder;
use tokio::{
    select,
    sync::{Notify, mpsc},
};

use crate::{
    block_handler::BlockHandler,
    bls_certificate_aggregator::{BlsCertificateAggregator, CertificateEvent},
    bls_service::{BlsServiceHandle, BlsServiceMessage, start_bls_service},
    broadcaster::{BlockDisseminator, BlockFetcher, BroadcasterParameters, DataRequester},
    committee::Committee,
    config::{DisseminationMode, NodeParameters},
    consensus::universal_committer::UniversalCommitter,
    cordial_knowledge::{ConnectionKnowledge, CordialKnowledgeHandle, CordialKnowledgeMessage},
    core::Core,
    core_thread::CoreThreadDispatcher,
    crypto::BlsSigner,
    dag_state::{ConsensusProtocol, DagState, DataSource},
    data::Data,
    metrics::{Metrics, UtilizationTimerVecExt},
    network::{BlockBatch, Connection, Network, NetworkMessage, ShardPayload},
    runtime::{Handle, JoinError, JoinHandle, sleep},
    sailfish_service::{
        SailfishCertEvent, SailfishServiceHandle, SailfishServiceMessage, start_sailfish_service,
    },
    shard_reconstructor::{DecodedBlocks, ShardMessage, start_shard_reconstructor},
    syncer::{CommitObserver, Syncer, SyncerSignals},
    types::{
        AuthorityIndex, BlockDigest, BlockReference, PartialSig, PartialSigKind, ProvableShard,
        RoundNumber, VerifiedBlock, format_authority_index,
    },
};

const MAX_FILTER_SIZE: usize = 100_000;

async fn send_network_message_reliably(
    sender: &mpsc::Sender<NetworkMessage>,
    message: NetworkMessage,
) {
    match sender.try_send(message) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(message)) => {
            let _ = sender.send(message).await;
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
}

struct FilterForBlocks {
    digests: parking_lot::RwLock<AHashSet<BlockDigest>>,
    queue: parking_lot::RwLock<VecDeque<BlockDigest>>,
}

impl FilterForBlocks {
    fn new() -> Self {
        Self {
            digests: parking_lot::RwLock::new(AHashSet::new()),
            queue: parking_lot::RwLock::new(VecDeque::new()),
        }
    }

    fn contains_batch(&self, digests: &[BlockDigest]) -> Vec<bool> {
        let set = self.digests.read();
        digests.iter().map(|d| set.contains(d)).collect()
    }

    fn insert_batch(&self, new_digests: &[BlockDigest]) {
        let mut digests = self.digests.write();
        let mut queue = self.queue.write();

        for digest in new_digests {
            if digests.insert(*digest) {
                queue.push_back(*digest);
            }
        }

        while queue.len() > MAX_FILTER_SIZE {
            if let Some(removed) = queue.pop_front() {
                digests.remove(&removed);
            }
        }
    }

    /// Inserts all digests and returns `true` for each that was genuinely new
    /// (not already in the filter and not duplicated earlier in the batch).
    fn insert_and_report_new(&self, digests: &[BlockDigest]) -> Vec<bool> {
        let mut set = self.digests.write();
        let mut queue = self.queue.write();

        let is_new: Vec<bool> = digests
            .iter()
            .map(|d| {
                if set.insert(*d) {
                    queue.push_back(*d);
                    true
                } else {
                    false
                }
            })
            .collect();

        while queue.len() > MAX_FILTER_SIZE {
            if let Some(removed) = queue.pop_front() {
                set.remove(&removed);
            }
        }
        is_new
    }

    /// For each header digest, returns `true` if the digest has not been seen
    /// before (neither in the filter nor earlier in this batch).
    fn needed_headers(&self, batch: &[BlockDigest]) -> Vec<bool> {
        let digests = self.digests.read();
        let mut seen_in_batch = AHashSet::with_capacity(batch.len());

        batch
            .iter()
            .map(|digest| !digests.contains(digest) && seen_in_batch.insert(*digest))
            .collect()
    }
}

#[derive(Clone, Copy)]
struct ShardStatus {
    count: usize,
    bitmap: u128,
    full_block_received: bool,
}

struct FilterForShards {
    info_length: usize,
    digests: parking_lot::RwLock<AHashMap<BlockDigest, ShardStatus>>,
    queue: parking_lot::RwLock<VecDeque<BlockDigest>>,
}

impl FilterForShards {
    fn new(info_length: usize) -> Self {
        Self {
            info_length,
            digests: parking_lot::RwLock::new(AHashMap::new()),
            queue: parking_lot::RwLock::new(VecDeque::new()),
        }
    }

    /// Returns `true` if this shard is still needed for reconstruction.
    fn needed(&self, digest: &BlockDigest, shard_index: usize) -> bool {
        let digests = self.digests.read();
        match digests.get(digest) {
            Some(status) => {
                !status.full_block_received
                    && status.count < self.info_length
                    && (status.bitmap & (1u128 << shard_index)) == 0
            }
            None => true,
        }
    }

    fn add_batch(&self, entries: &[(BlockDigest, usize)]) {
        let mut digests = self.digests.write();
        let mut queue = self.queue.write();
        for &(digest, shard_index) in entries {
            let entry = digests.entry(digest).or_insert_with(|| {
                queue.push_back(digest);
                ShardStatus {
                    count: 0,
                    bitmap: 0,
                    full_block_received: false,
                }
            });
            let mask = 1u128 << shard_index;
            if entry.bitmap & mask == 0 {
                entry.bitmap |= mask;
                entry.count += 1;
            }
        }
        while queue.len() > MAX_FILTER_SIZE {
            if let Some(removed) = queue.pop_front() {
                digests.remove(&removed);
            }
        }
    }

    fn has_full_batch(&self, digests: &[BlockDigest]) -> Vec<bool> {
        let map = self.digests.read();
        digests
            .iter()
            .map(|d| map.get(d).is_some_and(|s| s.full_block_received))
            .collect()
    }

    fn mark_full_batch(&self, batch: &[BlockDigest]) {
        let mut digests = self.digests.write();
        let mut queue = self.queue.write();
        for &digest in batch {
            let entry = digests.entry(digest).or_insert_with(|| {
                queue.push_back(digest);
                ShardStatus {
                    count: 0,
                    bitmap: 0,
                    full_block_received: false,
                }
            });
            entry.count = self.info_length;
            entry.full_block_received = true;
        }
    }
}

fn infer_peer_knowledge_from_received_batch(
    ck: &mut ConnectionKnowledge,
    full_blocks: &[Data<VerifiedBlock>],
    headers: &[Data<VerifiedBlock>],
    shards: &[ShardPayload],
) {
    for block in full_blocks.iter().chain(headers.iter()) {
        // Peer knows this block's header because they sent it.
        ck.mark_header_known(*block.reference());
        // Peer knows the header of every parent in the causal history.
        for parent_ref in block.block_references() {
            ck.mark_header_known(*parent_ref);
        }
        // Acknowledging a block implies the peer already has that block's data.
        for ack_ref in block.acknowledgments() {
            ck.mark_header_known(ack_ref);
            ck.mark_shard_known(ack_ref);
        }
    }
    for shard in shards {
        ck.mark_header_known(shard.block_reference);
        ck.mark_shard_known(shard.block_reference);
    }
}

/// Per-connection state for `connection_task`. Groups the 15+ shared locals
/// into a struct so the 400-line match body can be split into focused handlers.
struct ConnectionHandler<H: BlockHandler + 'static, C: CommitObserver + 'static> {
    consensus_protocol: ConsensusProtocol,
    inner: Arc<NetworkSyncerInner<H, C>>,
    metrics: Arc<Metrics>,
    filter_for_blocks: Arc<FilterForBlocks>,
    filter_for_shards: Arc<FilterForShards>,
    disseminator: BlockDisseminator<H, C>,
    data_requester: DataRequester<H, C>,
    encoder: ReedSolomonEncoder,
    peer_id: AuthorityIndex,
    peer: char,
    own_id: AuthorityIndex,
    sender: mpsc::Sender<NetworkMessage>,
    bls_service: Option<BlsServiceHandle>,
    sailfish_service: Option<SailfishServiceHandle>,
}

impl<H: BlockHandler + 'static, C: CommitObserver + 'static> ConnectionHandler<H, C> {
    fn new(
        connection: &Connection,
        universal_committer: UniversalCommitter,
        inner: Arc<NetworkSyncerInner<H, C>>,
        metrics: Arc<Metrics>,
        filter_for_blocks: Arc<FilterForBlocks>,
        filter_for_shards: Arc<FilterForShards>,
        bls_service: Option<BlsServiceHandle>,
        sailfish_service: Option<SailfishServiceHandle>,
    ) -> Self {
        let consensus_protocol = inner.dag_state.consensus_protocol;
        let committee_size = inner.dag_state.committee_size;
        let broadcaster_parameters = BroadcasterParameters::new(
            committee_size,
            consensus_protocol,
            inner.dissemination_mode,
            inner.causal_push_shard_round_lag,
        );
        let peer_id = connection.peer_id as AuthorityIndex;

        let disseminator = BlockDisseminator::new(
            peer_id,
            connection.sender.clone(),
            universal_committer,
            inner.clone(),
            broadcaster_parameters.clone(),
            metrics.clone(),
        );
        let data_requester = DataRequester::new(
            peer_id,
            connection.sender.clone(),
            inner.clone(),
            metrics.clone(),
            broadcaster_parameters,
        );

        let encoder = ReedSolomonEncoder::new(2, 4, 2).expect("Encoder should be created");
        let own_id = inner.dag_state.get_own_authority_index();
        let peer = format_authority_index(peer_id);

        Self {
            consensus_protocol,
            inner,
            metrics,
            filter_for_blocks,
            filter_for_shards,
            disseminator,
            data_requester,
            encoder,
            peer_id,
            peer,
            own_id,
            sender: connection.sender.clone(),
            bls_service,
            sailfish_service,
        }
    }

    async fn start(&mut self) {
        // Pre-create received-request time series per peer so Grafana can show
        // zero-valued lines before the first request arrives.
        self.metrics
            .block_sync_requests_received
            .with_label_values(&[&self.peer_id.to_string()])
            .inc_by(0);

        // Data requester is needed for Starfish protocols because of the practical
        // way we update the DAG known by other validators
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
        ) {
            self.metrics
                .tx_data_requests_received
                .with_label_values(&[&self.peer_id.to_string()])
                .inc_by(0);
            self.data_requester.start().await;
        }
    }

    /// Dispatch a single message. Returns `true` to continue, `false` to break
    /// the loop.
    async fn handle_message(&mut self, message: NetworkMessage) -> bool {
        match message {
            NetworkMessage::SubscribeBroadcastRequest(round) => {
                self.handle_subscribe(round).await;
            }
            NetworkMessage::Batch(blocks) => {
                self.handle_batch(blocks).await;
            }
            NetworkMessage::MissingParentsRequest(refs) => {
                return self.handle_missing_parents_request(refs).await;
            }
            NetworkMessage::MissingTxDataRequest(refs) => {
                return self.handle_missing_tx_data_request(refs).await;
            }
            NetworkMessage::PartialSig(sig) => {
                // DAC sigs are addressed: accept only if block author is us.
                // Round/Leader sigs are broadcast: always accept.
                let dominated = match sig.kind {
                    PartialSigKind::Dac(block_ref) => block_ref.authority != self.own_id,
                    _ => false,
                };
                if !dominated {
                    if let Some(ref bls) = self.bls_service {
                        bls.send(BlsServiceMessage::PartialSig(sig));
                    }
                }
            }
            NetworkMessage::CertMessage(message) => {
                if message.sender != self.peer_id {
                    tracing::debug!(
                        "Rejected CertMessage: sender {} != peer {}",
                        message.sender,
                        self.peer_id,
                    );
                    return true;
                }
                tracing::debug!(
                    "Received {:?} from peer {} for {:?}",
                    message.kind,
                    message.sender,
                    message.block_ref,
                );
                if let Some(ref sf) = self.sailfish_service {
                    sf.send(SailfishServiceMessage::CertMessage(message));
                }
            }
            NetworkMessage::SailfishTimeout(msg) => {
                if msg.sender != self.peer_id {
                    return true;
                }
                if let Some(ref sf) = self.sailfish_service {
                    sf.send(SailfishServiceMessage::TimeoutMsg(msg));
                }
            }
            NetworkMessage::SailfishNoVote(msg) => {
                if msg.sender != self.peer_id {
                    return true;
                }
                if let Some(ref sf) = self.sailfish_service {
                    sf.send(SailfishServiceMessage::NoVoteMsg(msg));
                }
            }
        }
        true
    }

    async fn handle_subscribe(&mut self, round: RoundNumber) {
        self.inner.syncer.peer_subscribed(self.peer_id).await;
        self.inner
            .dag_state
            .reset_peer_known_by_after_round(self.peer_id, round);
        if self.inner.dag_state.byzantine_strategy.is_some() {
            let round = 0;
            self.disseminator.disseminate_own_blocks(round).await;
        } else {
            match self.inner.dissemination_mode {
                DisseminationMode::Pull => {
                    self.disseminator.disseminate_own_blocks(round).await;
                }
                DisseminationMode::PushCausal | DisseminationMode::PushUseful => {
                    self.disseminator.start_push_batch_stream(round).await;
                }
                DisseminationMode::ProtocolDefault => {
                    unreachable!("protocol-default dissemination mode must be resolved")
                }
            }
        }
    }

    async fn handle_batch(&mut self, batch: BlockBatch) {
        let timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Network: verify blocks");

        let BlockBatch {
            source,
            full_blocks,
            headers,
            shards,
            useful_headers_authors,
            useful_shards_authors,
        } = batch;

        // Mark received full blocks as "sent" so we don't re-send them.
        {
            let mut sent = self.disseminator.sent_to_peer.write();
            for block in &full_blocks {
                sent.insert(*block.reference());
            }
            for block in &headers {
                sent.insert(*block.reference());
            }
        }

        // Forward useful-authors feedback to CordialKnowledge
        if useful_headers_authors != 0 || useful_shards_authors != 0 {
            let max_round = full_blocks
                .iter()
                .chain(headers.iter())
                .map(|b| b.round())
                .chain(shards.iter().map(|payload| payload.block_reference.round))
                .max()
                .unwrap_or(0);
            self.inner
                .cordial_knowledge
                .send(CordialKnowledgeMessage::UsefulAuthors {
                    peer: self.peer_id,
                    headers: useful_headers_authors,
                    shards: useful_shards_authors,
                    round: max_round,
                });
        }

        // Update ConnectionKnowledge directly — infer what the peer knows
        // from the blocks they sent us and their causal references.
        if let Some(ck) = self
            .inner
            .cordial_knowledge
            .connection_knowledge(self.peer_id)
        {
            let mut ck = ck.write();
            infer_peer_knowledge_from_received_batch(&mut ck, &full_blocks, &headers, &shards);
        }

        let mut blocks_with_transactions = Vec::new();
        let mut blocks_without_transactions = Vec::new();
        for block in full_blocks {
            match self.consensus_protocol {
                // In full-block protocols, an empty payload is still a complete
                // block and must follow the normal add_blocks path.
                ConsensusProtocol::Mysticeti
                | ConsensusProtocol::CordialMiners
                | ConsensusProtocol::SailfishPlusPlus => {
                    blocks_with_transactions.push(block);
                }
                ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls => {
                    if block.transactions().is_some() {
                        blocks_with_transactions.push(block);
                    } else {
                        blocks_without_transactions.push(block);
                    }
                }
            }
        }

        // Header-only blocks are only valid for Starfish erasure-coding
        // variants. SailfishPlusPlus and Mysticeti require full blocks;
        // reject any headers a peer may have sent.
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
        ) {
            blocks_without_transactions.extend(headers);
            let header_source = match source {
                DataSource::BlockBundleStreaming => DataSource::BlockBundleStreamingHeader,
                other => other,
            };
            self.process_block_headers(blocks_without_transactions, header_source)
                .await;
        } else if !headers.is_empty() {
            tracing::warn!(
                "Rejecting {} header-only blocks from peer {} \
                 (not supported by {:?})",
                headers.len(),
                self.peer_id,
                self.consensus_protocol,
            );
        }

        // Process standalone shards — route directly to shard reconstructor
        if !shards.is_empty() {
            self.process_standalone_shards(shards).await;
        }

        // Then process blocks with transactions
        self.process_full_blocks(blocks_with_transactions, source)
            .await;

        drop(timer);
    }

    async fn process_standalone_shards(&mut self, shards: Vec<ShardPayload>) {
        let maybe_tx = self.inner.shard_tx.lock().clone();
        let Some(shard_tx) = maybe_tx else { return };
        let connection_knowledge = self
            .inner
            .cordial_knowledge
            .connection_knowledge(self.peer_id);
        let committee_size = self.inner.committee.len();

        // --- verify loop (only read locks on filter_for_shards) ---
        let mut verified: Vec<(BlockReference, ShardMessage, usize)> = Vec::new();
        for payload in shards {
            let shard_index = payload.shard.shard_index();
            if !self
                .filter_for_shards
                .needed(&payload.block_reference.digest, shard_index)
            {
                self.metrics.filtered_shards_total.inc();
                continue;
            }

            // Verify the Merkle proof against the embedded transactions commitment.
            if !payload.shard.verify(committee_size) {
                tracing::warn!(
                    "Standalone shard for {:?} from {} failed Merkle proof — dropped",
                    payload.block_reference,
                    self.peer
                );
                continue;
            }

            verified.push((
                payload.block_reference,
                ShardMessage::Shard {
                    block_reference: payload.block_reference,
                    transactions_commitment: payload.shard.transactions_commitment(),
                    shard: payload.shard.shard().clone(),
                    shard_index,
                },
                shard_index,
            ));
        }

        // --- batch CK update (one write lock) ---
        let useful_shard_refs: Vec<_> = verified.iter().map(|(r, _, _)| *r).collect();
        if let Some(ck) = connection_knowledge.as_ref() {
            ck.write().mark_shards_useful_from_peer(&useful_shard_refs);
        }
        if !useful_shard_refs.is_empty() {
            self.inner
                .cordial_knowledge
                .send(CordialKnowledgeMessage::UsefulShardsFromPeers(
                    useful_shard_refs.clone(),
                ));
        }

        // --- batch filter update (one write lock) ---
        let filter_entries: Vec<_> = verified
            .iter()
            .map(|(r, _, idx)| (r.digest, *idx))
            .collect();
        self.filter_for_shards.add_batch(&filter_entries);

        // --- send batch ---
        let batch: Vec<_> = verified.into_iter().map(|(_, msg, _)| msg).collect();
        if !batch.is_empty() {
            let _ = shard_tx.send(batch).await;
        }
    }

    async fn process_block_headers(
        &mut self,
        blocks: Vec<Data<VerifiedBlock>>,
        source: DataSource,
    ) {
        let connection_knowledge = self
            .inner
            .cordial_knowledge
            .connection_knowledge(self.peer_id);
        let incoming_digests: Vec<_> = blocks.iter().map(|block| block.digest()).collect();
        let needed_before_verify = self.filter_for_blocks.needed_headers(&incoming_digests);
        let mut verified_blocks: Vec<VerifiedBlock> = Vec::new();

        // --- verify loop (no per-block lock acquisition) ---
        for (data_block, is_needed) in blocks.into_iter().zip(needed_before_verify) {
            if !is_needed {
                self.metrics.filtered_blocks_total.inc();
                continue;
            }
            let mut block: VerifiedBlock = (*data_block).clone();
            tracing::debug!("Received {} from {}", block, self.peer);
            // All blocks here have transaction_data == None, so verify()
            // always returns Ok(None) for the shard.
            match block.verify(
                &self.inner.committee,
                self.own_id as usize,
                self.peer_id as usize,
                &mut self.encoder,
                self.consensus_protocol,
            ) {
                Ok(shard) => {
                    debug_assert!(shard.is_none(), "shard must be None for header-only blocks")
                }
                Err(e) => {
                    tracing::warn!(
                        "Rejected incorrect block {} from {}: {:?}",
                        block.reference(),
                        self.peer,
                        e
                    );
                    break;
                }
            };
            verified_blocks.push(block);
        }

        // --- batch connection knowledge update (one lock acquisition) ---
        if let Some(ck) = connection_knowledge.as_ref() {
            let refs: Vec<_> = verified_blocks.iter().map(|b| *b.reference()).collect();
            let mut ck = ck.write();
            ck.mark_headers_useful_from_peer(&refs);
        }

        // --- batch filter insert + new-detection (one lock acquisition) ---
        let digests: Vec<_> = verified_blocks.iter().map(|b| b.digest()).collect();
        let is_new = self.filter_for_blocks.insert_and_report_new(&digests);
        let mut new_data_blocks = Vec::new();
        for (storage_block, is_new) in verified_blocks.into_iter().zip(is_new) {
            if is_new {
                let mut storage_block = storage_block;
                storage_block.preserialize();
                debug_assert!(
                    storage_block.serialized_header_bytes().is_some(),
                    "header must be preserialized before entering core"
                );
                new_data_blocks.push(Data::new(storage_block));
            }
        }

        tracing::debug!(
            "To be processed after verification from {:?}, {} new blocks without transactions {:?}",
            self.peer,
            new_data_blocks.len(),
            new_data_blocks
        );
        if !new_data_blocks.is_empty() {
            // Send block copies to BLS service for signature verification.
            if let Some(ref bls) = self.bls_service {
                bls.send(BlsServiceMessage::ProcessBlocks(new_data_blocks.clone()));
            }
            // Send block references to Sailfish service for RBC certification.
            if let Some(ref sf) = self.sailfish_service {
                let block_refs: Vec<_> = new_data_blocks.iter().map(|b| *b.reference()).collect();
                sf.send(SailfishServiceMessage::ProcessBlocks(block_refs));
            }
            // Notify CordialKnowledge about all new headers in one batch.
            let header_refs = new_data_blocks
                .iter()
                .map(|block| *block.reference())
                .collect();
            self.inner
                .cordial_knowledge
                .send(CordialKnowledgeMessage::DagParts {
                    headers: header_refs,
                    shards: Vec::new(),
                });
            let useful_shard_refs: Vec<_> = new_data_blocks
                .iter()
                .filter(|block| !block.has_empty_payload())
                .map(|block| *block.reference())
                .collect();
            if !useful_shard_refs.is_empty() {
                self.inner
                    .cordial_knowledge
                    .send(CordialKnowledgeMessage::UsefulShardsFromPeers(
                        useful_shard_refs,
                    ));
            }
            let (missing_parents, processed_additional_refs) =
                self.inner.syncer.add_headers(new_data_blocks, source).await;
            if !missing_parents.is_empty() {
                let missing_parents = missing_parents.iter().copied().collect::<Vec<_>>();
                tracing::debug!(
                    "Make request missing parents of header/shard blocks {:?} from peer {:?}",
                    missing_parents,
                    self.peer
                );
                self.metrics
                    .block_sync_requests_sent
                    .with_label_values(&[&self.peer_id.to_string()])
                    .inc();
                self.sender
                    .send(NetworkMessage::MissingParentsRequest(missing_parents))
                    .await
                    .ok();
            }
            self.metrics
                .used_additional_blocks_total
                .inc_by(processed_additional_refs.len() as u64);
        }
    }

    async fn process_full_blocks(&mut self, blocks: Vec<Data<VerifiedBlock>>, source: DataSource) {
        let connection_knowledge = self
            .inner
            .cordial_knowledge
            .connection_knowledge(self.peer_id);
        let incoming_digests: Vec<_> = blocks.iter().map(|block| block.digest()).collect();
        let shard_tx = self.inner.shard_tx.lock().clone();

        // --- batch pre-filter (one read lock each) ---
        let block_known = self.filter_for_blocks.contains_batch(&incoming_digests);
        let shard_full = self.filter_for_shards.has_full_batch(&incoming_digests);

        // --- verify loop (no lock acquisitions) ---
        let mut verified: Vec<(VerifiedBlock, Option<ProvableShard>)> = Vec::new();
        for ((data_block, _digest), (bk, sf)) in blocks
            .into_iter()
            .zip(incoming_digests)
            .zip(block_known.into_iter().zip(shard_full))
        {
            if bk && sf {
                self.metrics.filtered_blocks_total.inc();
                continue;
            }
            let mut block: VerifiedBlock = (*data_block).clone();
            tracing::debug!("Received {} from {}", block, self.peer);
            let shard = match block.verify(
                &self.inner.committee,
                self.own_id as usize,
                self.peer_id as usize,
                &mut self.encoder,
                self.consensus_protocol,
            ) {
                Ok(shard) => shard,
                Err(e) => {
                    tracing::warn!(
                        "Rejected incorrect block {} from {}: {:?}",
                        block.reference(),
                        self.peer,
                        e
                    );
                    // todo: Terminate connection upon receiving incorrect block.
                    break;
                }
            };
            verified.push((block, shard));
        }

        // --- batch CK update (one write lock) ---
        if let Some(ck) = connection_knowledge.as_ref() {
            let header_refs: Vec<_> = verified.iter().map(|(b, _)| *b.reference()).collect();
            let mut ck = ck.write();
            // Full blocks carry useful header/causal information, but the
            // derived shard sidecar is local bookkeeping rather than a shard
            // the peer pushed to us.
            ck.mark_headers_useful_from_peer(&header_refs);
        }

        // --- batch filter updates (one write lock each) ---
        let verified_digests: Vec<_> = verified.iter().map(|(b, _)| b.digest()).collect();
        self.filter_for_blocks.insert_batch(&verified_digests);
        self.filter_for_shards.mark_full_batch(&verified_digests);

        // --- preserialize + collect ---
        let mut verified_data_blocks = Vec::new();
        let mut verified_has_shard = Vec::new();
        let mut verified_block_shards = Vec::new();
        for (mut block, shard) in verified {
            let has_shard = shard.is_some();
            block.preserialize();
            debug_assert!(
                block.serialized_header_bytes().is_some(),
                "header must be preserialized before entering core"
            );
            let block = Data::new(block);
            verified_data_blocks.push(block.clone());
            verified_has_shard.push(has_shard);
            verified_block_shards.push((block, shard));
        }

        // Notify reconstructor to stop collecting shards for these blocks (batched).
        if let Some(shard_tx) = shard_tx.as_ref() {
            let full_block_msgs: Vec<_> = verified_data_blocks
                .iter()
                .map(|b| ShardMessage::FullBlock(*b.reference()))
                .collect();
            if !full_block_msgs.is_empty() {
                let _ = shard_tx.send(full_block_msgs).await;
            }
        }

        tracing::debug!(
            "To be processed after verification from {:?}, {} blocks with transactions {:?}",
            self.peer,
            verified_data_blocks.len(),
            verified_data_blocks
        );
        if !verified_data_blocks.is_empty() {
            // Send block copies to BLS service for signature verification.
            if let Some(ref bls) = self.bls_service {
                bls.send(BlsServiceMessage::ProcessBlocks(
                    verified_data_blocks.clone(),
                ));
            }
            // Send block references to Sailfish service for RBC certification.
            if let Some(ref sf) = self.sailfish_service {
                let block_refs: Vec<_> = verified_data_blocks
                    .iter()
                    .map(|b| *b.reference())
                    .collect();
                sf.send(SailfishServiceMessage::ProcessBlocks(block_refs));
            }
            // Notify CordialKnowledge about all new headers and shards in one batch.
            let header_refs: Vec<_> = verified_data_blocks
                .iter()
                .map(|block| *block.reference())
                .collect();
            let shard_refs: Vec<_> = verified_data_blocks
                .iter()
                .zip(verified_has_shard.iter())
                .filter_map(|(block, &has_shard)| has_shard.then_some(*block.reference()))
                .collect();
            self.inner
                .cordial_knowledge
                .send(CordialKnowledgeMessage::DagParts {
                    headers: header_refs,
                    shards: shard_refs,
                });
            let (_pending_block_references, missing_parents, _processed_additional_blocks) = self
                .inner
                .syncer
                .add_blocks(verified_block_shards, source)
                .await;
            if !missing_parents.is_empty() {
                tracing::debug!(
                    "Missing parents when processing block from peer {:?}: {:?}",
                    self.peer,
                    missing_parents
                );
            }
            if !missing_parents.is_empty() {
                let missing_parents = missing_parents.iter().copied().collect::<Vec<_>>();
                tracing::debug!(
                    "Make request missing parents of blocks {:?} from peer {:?}",
                    missing_parents,
                    self.peer
                );
                self.metrics
                    .block_sync_requests_sent
                    .with_label_values(&[&self.peer_id.to_string()])
                    .inc();
                self.sender
                    .send(NetworkMessage::MissingParentsRequest(missing_parents))
                    .await
                    .ok();
            }
        }
    }

    /// Returns `true` to continue, `false` to break the connection loop.
    async fn handle_missing_parents_request(
        &mut self,
        block_references: Vec<BlockReference>,
    ) -> bool {
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::Mysticeti
                | ConsensusProtocol::CordialMiners
                | ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
                | ConsensusProtocol::SailfishPlusPlus
        ) {
            self.metrics
                .block_sync_requests_received
                .with_label_values(&[&self.peer_id.to_string()])
                .inc();
            tracing::debug!(
                "Received request missing data {:?} from peer {:?}",
                block_references,
                self.peer
            );
            if self.inner.dissemination_mode == DisseminationMode::PushUseful {
                if let Some(ck) = self
                    .inner
                    .cordial_knowledge
                    .connection_knowledge(self.peer_id)
                {
                    let mut ck = ck.write();
                    let mut useful_headers_mask = 0u128;
                    for block_ref in &block_references {
                        useful_headers_mask |= 1u128 << block_ref.authority;
                    }
                    if useful_headers_mask != 0 {
                        let current_round = self.inner.dag_state.highest_round();
                        ck.update_useful_authors_to_peer(useful_headers_mask, 0, current_round);
                    }
                }
            }
            if self.inner.dag_state.byzantine_strategy.is_none()
                && self
                    .disseminator
                    .send_storage_blocks(self.peer_id, block_references)
                    .await
                    .is_none()
            {
                return false;
            }
        }
        true
    }

    /// Returns `true` to continue, `false` to break the connection loop.
    async fn handle_missing_tx_data_request(
        &mut self,
        block_references: Vec<BlockReference>,
    ) -> bool {
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
        ) {
            self.metrics
                .tx_data_requests_received
                .with_label_values(&[&self.peer_id.to_string()])
                .inc();
            tracing::debug!(
                "Received request missing data {:?} from peer {:?}",
                block_references,
                self.peer
            );
            if self.inner.dissemination_mode == DisseminationMode::PushUseful {
                if let Some(ck) = self
                    .inner
                    .cordial_knowledge
                    .connection_knowledge(self.peer_id)
                {
                    let mut ck = ck.write();
                    for block_ref in &block_references {
                        ck.mark_shard_useful_to_peer(*block_ref);
                    }
                }
            }
            if self.inner.dag_state.byzantine_strategy.is_none()
                && self
                    .disseminator
                    .send_transmission_blocks(self.peer_id, block_references)
                    .await
                    .is_none()
            {
                return false;
            }
        }
        true
    }

    async fn shutdown(self) {
        self.disseminator.shutdown().await;
        self.data_requester.shutdown().await;
    }
}

pub struct NetworkSyncer<H: BlockHandler, C: CommitObserver> {
    inner: Arc<NetworkSyncerInner<H, C>>,
    main_task: JoinHandle<()>,
    stop: mpsc::Receiver<()>,
    bridge_task: Option<JoinHandle<()>>,
    partial_sig_routing_task: Option<JoinHandle<()>>,
    bls_event_task: Option<JoinHandle<()>>,
    bls_broadcast_task: Option<JoinHandle<()>>,
    sf_event_task: Option<JoinHandle<()>>,
    cordial_knowledge_task: JoinHandle<()>,
}

pub(crate) struct NetworkSyncSignals {
    block_ready_notify: Arc<Notify>,
    threshold_clock_notify: Arc<Notify>,
}

pub struct NetworkSyncerInner<H: BlockHandler, C: CommitObserver> {
    syncer: CoreThreadDispatcher<H, NetworkSyncSignals, C>,
    pub dag_state: DagState,
    pub block_ready_notify: Arc<Notify>,
    pub threshold_clock_notify: Arc<Notify>,
    pub committee: Arc<Committee>,
    pub dissemination_mode: DisseminationMode,
    pub causal_push_shard_round_lag: RoundNumber,
    stop: mpsc::Sender<()>,
    pub gc_round: Arc<AtomicU32>,
    pub shard_tx:
        parking_lot::Mutex<Option<mpsc::Sender<Vec<crate::shard_reconstructor::ShardMessage>>>>,
    pub cordial_knowledge: CordialKnowledgeHandle,
    /// Per-peer message senders for direct unicast (e.g. DAC partial sigs).
    pub peer_senders: parking_lot::RwLock<AHashMap<AuthorityIndex, mpsc::Sender<NetworkMessage>>>,
    pub leader_timeout: Duration,
    pub soft_block_timeout: Duration,
    /// Sailfish++ service handle for sending control messages
    /// (timeout/no-vote). None for non-SailfishPlusPlus protocols.
    pub sailfish_handle: Option<SailfishServiceHandle>,
}

impl<H: BlockHandler + 'static, C: CommitObserver + 'static> NetworkSyncer<H, C> {
    pub fn start(
        network: Network,
        mut core: Core<H>,
        mut commit_observer: C,
        metrics: Arc<Metrics>,
        node_parameters: NodeParameters,
        partial_sig_outbox_rx: Option<mpsc::UnboundedReceiver<PartialSig>>,
        bls_cert_aggregator: Option<BlsCertificateAggregator>,
        bls_signer: Option<BlsSigner>,
    ) -> Self {
        let handle = Handle::current();
        let block_ready_notify = Arc::new(Notify::new());
        let threshold_clock_notify = Arc::new(Notify::new());
        let (committed, committed_leaders_count) = core.take_recovered_committed();
        commit_observer.recover_committed(committed, committed_leaders_count);
        let committee = core.committee().clone();
        let dag_state = core.dag_state().clone();
        let dissemination_mode = dag_state
            .consensus_protocol
            .resolve_dissemination_mode(node_parameters.dissemination_mode);
        let _store = core.store();
        let universal_committer = core.get_universal_committer();
        // Create BLS service channel — sender clones go to Syncer (Core thread)
        // and network connection handlers, receiver goes to the BLS service task.
        let (bls_msg_tx, bls_msg_rx) = if bls_cert_aggregator.is_some() {
            let (tx, rx) = mpsc::unbounded_channel::<BlsServiceMessage>();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        // Create Sailfish service channel for SailfishPlusPlus protocol.
        let is_sailfish_pp = dag_state.consensus_protocol == ConsensusProtocol::SailfishPlusPlus;
        let sailfish_signer = if is_sailfish_pp {
            Some(core.get_signer().clone())
        } else {
            None
        };
        let (sf_msg_tx, sf_msg_rx) = if is_sailfish_pp {
            let (tx, rx) = mpsc::unbounded_channel::<SailfishServiceMessage>();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let sf_handle_for_inner = sf_msg_tx
            .as_ref()
            .map(|tx| SailfishServiceHandle::new(tx.clone()));
        let mut syncer = Syncer::new(
            core,
            NetworkSyncSignals {
                block_ready_notify: block_ready_notify.clone(),
                threshold_clock_notify: threshold_clock_notify.clone(),
            },
            commit_observer,
            metrics.clone(),
            bls_msg_tx.clone(),
            sf_msg_tx.clone(),
        );
        syncer.force_new_block(0);
        let syncer = CoreThreadDispatcher::start(syncer);
        let (stop_sender, stop_receiver) = mpsc::channel(1);
        // Occupy the only available permit, so that all other
        // calls to send() will block.
        stop_sender.try_send(()).unwrap();
        // Conditionally prepare shard reconstructor channels for Starfish protocols
        let is_starfish = matches!(
            dag_state.consensus_protocol,
            ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
        );
        let gc_round = Arc::new(AtomicU32::new(dag_state.gc_round()));
        let (shard_tx, decoded_rx) = if is_starfish {
            let (decoded_tx, decoded_rx) = mpsc::channel::<DecodedBlocks>(1000);
            let reconstructor_handle = start_shard_reconstructor(
                committee.clone(),
                dag_state.get_own_authority_index(),
                metrics.clone(),
                decoded_tx,
                gc_round.clone(),
            );
            (
                Some(reconstructor_handle.shard_message_sender()),
                Some(decoded_rx),
            )
        } else {
            (None, None)
        };

        // Create CordialKnowledge actor for per-peer header/shard tracking
        let (cordial_knowledge_handle, cordial_knowledge_actor) =
            CordialKnowledgeHandle::new(committee.len(), metrics.clone());
        let cordial_knowledge_task = handle.spawn(cordial_knowledge_actor.run());

        let inner = Arc::new(NetworkSyncerInner {
            block_ready_notify,
            dag_state: dag_state.clone(),
            syncer,
            threshold_clock_notify,
            committee,
            dissemination_mode,
            causal_push_shard_round_lag: node_parameters.causal_push_shard_round_lag,
            stop: stop_sender.clone(),
            gc_round,
            shard_tx: parking_lot::Mutex::new(shard_tx),
            cordial_knowledge: cordial_knowledge_handle,
            peer_senders: parking_lot::RwLock::new(AHashMap::new()),
            leader_timeout: node_parameters.leader_timeout,
            soft_block_timeout: node_parameters.soft_block_timeout,
            sailfish_handle: sf_handle_for_inner,
        });

        // Start bridge task that forwards reconstructed transaction data to core
        let bridge_task = decoded_rx.map(|mut decoded_rx| {
            let bridge_inner = inner.clone();
            handle.spawn(async move {
                while let Some(items) = decoded_rx.recv().await {
                    // Reconstruction proves we now have the shard data for the
                    // entire batch.
                    let shard_refs = items.iter().map(|item| item.block_reference).collect();
                    bridge_inner
                        .cordial_knowledge
                        .send(CordialKnowledgeMessage::DagParts {
                            headers: Vec::new(),
                            shards: shard_refs,
                        });
                    bridge_inner
                        .syncer
                        .add_transaction_data(items, DataSource::ShardReconstructor)
                        .await;
                }
            })
        });
        // Spawn partial-sig routing task: drains Core's outbox and routes
        // partial sigs by kind — DAC to block author, round/leader to all.
        let partial_sig_routing_task = partial_sig_outbox_rx.map(|mut rx| {
            let routing_inner = inner.clone();
            handle.spawn(async move {
                while let Some(partial_sig) = rx.recv().await {
                    match partial_sig.kind {
                        PartialSigKind::Dac(block_ref) => {
                            let target = block_ref.authority;
                            let sender = routing_inner.peer_senders.read().get(&target).cloned();
                            if let Some(sender) = sender {
                                send_network_message_reliably(
                                    &sender,
                                    NetworkMessage::PartialSig(partial_sig),
                                )
                                .await;
                            }
                        }
                        PartialSigKind::Round(_) | PartialSigKind::Leader(_) => {
                            let senders: Vec<_> = routing_inner
                                .peer_senders
                                .read()
                                .values()
                                .cloned()
                                .collect();
                            for sender in senders {
                                send_network_message_reliably(
                                    &sender,
                                    NetworkMessage::PartialSig(partial_sig.clone()),
                                )
                                .await;
                            }
                        }
                    }
                }
            })
        });
        // Start BLS verification service and event bridge task.
        // The BLS service gets a broadcast sender for pre-computed partial sigs.
        let (bls_broadcast_tx, bls_broadcast_task) = if bls_signer.is_some() {
            let (tx, mut rx) = mpsc::unbounded_channel::<PartialSig>();
            let routing_inner = inner.clone();
            let task = handle.spawn(async move {
                while let Some(partial_sig) = rx.recv().await {
                    // Pre-computed sigs are always round/leader, broadcast to all.
                    let senders: Vec<_> = routing_inner
                        .peer_senders
                        .read()
                        .values()
                        .cloned()
                        .collect();
                    for sender in senders {
                        send_network_message_reliably(
                            &sender,
                            NetworkMessage::PartialSig(partial_sig.clone()),
                        )
                        .await;
                    }
                }
            });
            (Some(tx), Some(task))
        } else {
            (None, None)
        };

        let own_authority = dag_state.get_own_authority_index();
        let bls_committee = inner.committee.clone();
        let (bls_service, bls_event_task) = if let (Some(aggregator), Some(bls_rx), Some(bls_tx)) =
            (bls_cert_aggregator, bls_msg_rx, bls_msg_tx)
        {
            let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Vec<CertificateEvent>>();
            start_bls_service(
                aggregator,
                bls_tx.clone(),
                bls_rx,
                event_tx,
                metrics.clone(),
                bls_signer,
                own_authority,
                bls_committee,
                bls_broadcast_tx,
                dag_state.clone(),
                inner.block_ready_notify.clone(),
                inner.threshold_clock_notify.clone(),
            );
            let bls_handle = BlsServiceHandle::new(bls_tx);
            let event_inner = inner.clone();
            let task = handle.spawn(async move {
                while let Some(events) = event_rx.recv().await {
                    event_inner.syncer.apply_certificate_events(events).await;
                }
            });
            (Some(bls_handle), Some(task))
        } else {
            (None, None)
        };

        // Start Sailfish++ RBC certification service.
        let (sf_service, sf_event_task) = if let (Some(sf_tx), Some(sf_rx), Some(sf_signer)) =
            (sf_msg_tx, sf_msg_rx, sailfish_signer)
        {
            let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Vec<SailfishCertEvent>>();
            start_sailfish_service(
                inner.committee.clone(),
                own_authority,
                sf_signer,
                sf_rx,
                event_tx,
                metrics.clone(),
            );
            let sf_handle = SailfishServiceHandle::new(sf_tx);
            // Event bridge: certification events -> core thread + network broadcast
            let event_inner = inner.clone();
            let event_task = handle.spawn(async move {
                while let Some(events) = event_rx.recv().await {
                    tracing::debug!("Sailfish event bridge: {} events", events.len(),);
                    let certified_refs: Vec<_> = events
                        .iter()
                        .filter_map(|event| match event {
                            SailfishCertEvent::Certified(block_ref) => Some(*block_ref),
                            _ => None,
                        })
                        .collect();
                    if !certified_refs.is_empty() {
                        tracing::info!(
                            "Applying {} Sailfish certificates: {:?}",
                            certified_refs.len(),
                            certified_refs,
                        );
                        event_inner
                            .syncer
                            .apply_sailfish_certificates(certified_refs)
                            .await;
                    }
                    // Apply timeout/novote certs to dag state
                    for event in &events {
                        match event {
                            SailfishCertEvent::TimeoutReady(cert) => {
                                event_inner.syncer.apply_timeout_cert(cert.clone()).await;
                            }
                            SailfishCertEvent::NoVoteReady(cert) => {
                                event_inner.syncer.apply_novote_cert(cert.clone()).await;
                            }
                            _ => {}
                        }
                    }
                    // Broadcast Vote/Ready/Timeout/NoVote messages
                    {
                        let senders: Vec<_> =
                            event_inner.peer_senders.read().values().cloned().collect();
                        tracing::debug!(
                            "Sailfish broadcast: {} peers, {} events",
                            senders.len(),
                            events.len(),
                        );
                        for event in &events {
                            match event {
                                SailfishCertEvent::Broadcast(message) => {
                                    for sender in &senders {
                                        send_network_message_reliably(
                                            sender,
                                            NetworkMessage::CertMessage(message.clone()),
                                        )
                                        .await;
                                    }
                                }
                                SailfishCertEvent::BroadcastTimeout(msg) => {
                                    for sender in &senders {
                                        send_network_message_reliably(
                                            sender,
                                            NetworkMessage::SailfishTimeout(msg.clone()),
                                        )
                                        .await;
                                    }
                                }
                                SailfishCertEvent::SendNoVote(msg) => {
                                    // Route no-vote only to the next-round leader.
                                    let next_leader =
                                        event_inner.committee.elect_leader(msg.round + 1);
                                    let leader_tx =
                                        event_inner.peer_senders.read().get(&next_leader).cloned();
                                    if let Some(sender) = leader_tx {
                                        send_network_message_reliably(
                                            &sender,
                                            NetworkMessage::SailfishNoVote(msg.clone()),
                                        )
                                        .await;
                                    }
                                }
                                SailfishCertEvent::Certified(_)
                                | SailfishCertEvent::TimeoutReady(_)
                                | SailfishCertEvent::NoVoteReady(_) => {}
                            }
                        }
                    }
                }
            });
            (Some(sf_handle), Some(event_task))
        } else {
            (None, None)
        };

        let block_fetcher = Arc::new(BlockFetcher::start());
        let main_task = handle.spawn(Self::run(
            network,
            universal_committer,
            inner.clone(),
            block_fetcher,
            metrics.clone(),
            bls_service.clone(),
            sf_service.clone(),
        ));
        Self {
            inner,
            main_task,
            stop: stop_receiver,
            bridge_task,
            partial_sig_routing_task,
            bls_event_task,
            bls_broadcast_task,
            sf_event_task,
            cordial_knowledge_task,
        }
    }

    pub(crate) async fn shutdown(self) -> Syncer<H, NetworkSyncSignals, C> {
        drop(self.stop);
        // todo - wait for network shutdown as well
        self.main_task.await.ok();
        // Close the shard reconstructor channel so the bridge task can exit
        // and release its Arc reference.
        self.inner.shard_tx.lock().take();
        // Wait for the bridge task to observe channel closure and exit.
        if let Some(bridge_task) = self.bridge_task {
            bridge_task.await.ok();
        }
        // The partial-sig routing task holds an `Arc` to `inner` and waits on
        // a receiver whose sender lives inside the core thread. Abort it here
        // to break that shutdown cycle before unwrapping `inner`.
        if let Some(sig_task) = self.partial_sig_routing_task {
            sig_task.abort();
            sig_task.await.ok();
        }
        // The BLS event bridge task holds an `Arc` to `inner`. Abort it to
        // allow `Arc::try_unwrap` below.
        if let Some(bls_task) = self.bls_event_task {
            bls_task.abort();
            bls_task.await.ok();
        }
        if let Some(bls_broadcast) = self.bls_broadcast_task {
            bls_broadcast.abort();
            bls_broadcast.await.ok();
        }
        // Abort Sailfish event bridge task.
        if let Some(sf_task) = self.sf_event_task {
            sf_task.abort();
            sf_task.await.ok();
        }
        // Stop the cordial knowledge actor.
        self.cordial_knowledge_task.abort();
        self.cordial_knowledge_task.await.ok();
        let Ok(inner) = Arc::try_unwrap(self.inner) else {
            panic!("Shutdown failed - not all resources are freed after main task is completed");
        };
        inner.syncer.stop()
    }

    async fn run(
        mut network: Network,
        universal_committer: UniversalCommitter,
        inner: Arc<NetworkSyncerInner<H, C>>,
        block_fetcher: Arc<BlockFetcher>,
        metrics: Arc<Metrics>,
        bls_service: Option<BlsServiceHandle>,
        sf_service: Option<SailfishServiceHandle>,
    ) {
        let mut connections: HashMap<usize, JoinHandle<Option<()>>> = HashMap::new();
        let handle = Handle::current();
        let leader_timeout_task = handle.spawn(Self::leader_timeout_task(inner.clone()));
        let soft_block_timeout_task =
            if inner.dag_state.consensus_protocol == ConsensusProtocol::StarfishSpeed {
                Some(handle.spawn(Self::soft_block_timeout_task(inner.clone())))
            } else {
                None
            };

        let commit_timeout_task = handle.spawn(Self::commit_timeout_task(inner.clone()));
        let cleanup_task = handle.spawn(Self::cleanup_task(
            inner.clone(),
            bls_service.clone(),
            sf_service.clone(),
        ));
        let filter_for_blocks = Arc::new(FilterForBlocks::new());
        let filter_for_shards = Arc::new(FilterForShards::new(inner.committee.info_length()));
        while let Some(connection) = inner.recv_or_stopped(network.connection_receiver()).await {
            let peer_id = connection.peer_id;
            if let Some(task) = connections.remove(&peer_id) {
                // wait until previous sync task completes
                task.await.ok();
            }

            let sender = connection.sender.clone();
            let authority = peer_id as AuthorityIndex;
            block_fetcher.register_authority(authority, sender).await;

            let task = handle.spawn(Self::connection_task(
                connection,
                universal_committer.clone(),
                inner.clone(),
                block_fetcher.clone(),
                metrics.clone(),
                filter_for_blocks.clone(),
                filter_for_shards.clone(),
                bls_service.clone(),
                sf_service.clone(),
            ));
            connections.insert(peer_id, task);
        }
        join_all(
            connections
                .into_values()
                .chain([leader_timeout_task, commit_timeout_task, cleanup_task].into_iter())
                .chain(soft_block_timeout_task),
        )
        .await;
        Arc::try_unwrap(block_fetcher)
            .unwrap_or_else(|_| panic!("Failed to drop all connections"))
            .shutdown()
            .await;
        // Abort the TCP server so the listening port is released.
        network.abort_server();
    }

    async fn connection_task(
        mut connection: Connection,
        universal_committer: UniversalCommitter,
        inner: Arc<NetworkSyncerInner<H, C>>,
        block_fetcher: Arc<BlockFetcher>,
        metrics: Arc<Metrics>,
        filter_for_blocks: Arc<FilterForBlocks>,
        filter_for_shards: Arc<FilterForShards>,
        bls_service: Option<BlsServiceHandle>,
        sf_service: Option<SailfishServiceHandle>,
    ) -> Option<()> {
        let gc_round = inner.dag_state.gc_round();
        connection
            .sender
            .send(NetworkMessage::SubscribeBroadcastRequest(gc_round))
            .await
            .ok()?;

        let mut handler = ConnectionHandler::new(
            &connection,
            universal_committer,
            inner.clone(),
            metrics,
            filter_for_blocks,
            filter_for_shards,
            bls_service,
            sf_service,
        );
        handler.start().await;

        let peer_id = handler.peer_id;
        let own_id = handler.own_id;

        // Register peer sender for direct unicast messages (DAC partial sigs).
        inner
            .peer_senders
            .write()
            .insert(peer_id, connection.sender.clone());

        if inner.dag_state.consensus_protocol == ConsensusProtocol::StarfishBls {
            for (round, signature) in inner.dag_state.precomputed_round_sigs() {
                let _ = connection
                    .sender
                    .send(NetworkMessage::PartialSig(PartialSig {
                        kind: PartialSigKind::Round(round),
                        signer: own_id,
                        signature,
                    }))
                    .await;
            }
            for (leader_ref, signature) in inner.dag_state.precomputed_leader_sigs() {
                let _ = connection
                    .sender
                    .send(NetworkMessage::PartialSig(PartialSig {
                        kind: PartialSigKind::Leader(leader_ref),
                        signer: own_id,
                        signature,
                    }))
                    .await;
            }
        }

        inner.syncer.authority_connection(peer_id, true).await;

        tracing::debug!(
            "Connection from {:?} to {:?} is established",
            own_id,
            peer_id
        );
        while let Some(message) = inner.recv_or_stopped(&mut connection.receiver).await {
            if !handler.handle_message(message).await {
                break;
            }
        }

        tracing::debug!("Connection between {own_id} and {peer_id} is dropped");
        inner.peer_senders.write().remove(&peer_id);
        inner.syncer.authority_connection(peer_id, false).await;
        handler.shutdown().await;
        block_fetcher.remove_authority(peer_id).await;
        None
    }

    async fn leader_timeout_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        let leader_timeout = inner.leader_timeout;
        loop {
            let notified = inner.threshold_clock_notify.notified();
            let round = if inner.dag_state.consensus_protocol == ConsensusProtocol::SailfishPlusPlus
            {
                inner.dag_state.proposal_round().saturating_sub(1)
            } else {
                inner
                    .dag_state
                    .last_own_block_ref()
                    .map(|b| b.round())
                    .unwrap_or_default()
            };
            select! {
                _sleep = sleep(leader_timeout) => {
                    tracing::debug!("Timeout in round {round}");
                    // SailfishPlusPlus: send LocalTimeout so the service can
                    // sign and aggregate a timeout certificate for the round
                    // we're stuck on (the leader at `round` hasn't been
                    // certified in time).
                    if let Some(ref sf) = inner.sailfish_handle {
                        if round > 0 {
                            sf.send(SailfishServiceMessage::LocalTimeout(round));
                        }
                    }
                    inner.syncer.force_new_block(round).await;
                }
                _notified = notified => {
                    // Round advanced — restart timer
                }
                _stopped = inner.stopped() => {
                    return None;
                }
            }
        }
    }

    /// StarfishSpeed soft timeout: attempt block creation using the base
    /// Starfish readiness check (no strong-vote quorum requirement).
    async fn soft_block_timeout_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        let soft_timeout = inner.soft_block_timeout;
        let mut armed_round = inner.dag_state.threshold_clock_round();
        loop {
            while inner.dag_state.threshold_clock_round() <= armed_round {
                let notified = inner.threshold_clock_notify.notified();
                select! {
                    _notified = notified => {}
                    _stopped = inner.stopped() => {
                        return None;
                    }
                }
            }

            armed_round = inner.dag_state.threshold_clock_round();
            let notified = inner.threshold_clock_notify.notified();
            select! {
                _sleep = sleep(soft_timeout) => {
                    tracing::debug!(
                        "StarfishSpeed soft block timeout in threshold round {armed_round}"
                    );
                    inner.syncer.try_new_block_relaxed(armed_round).await;
                }
                _notified = notified => {
                    // Round advanced — restart timer
                }
                _stopped = inner.stopped() => {
                    return None;
                }
            }
        }
    }

    async fn commit_timeout_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        let commit_timeout = Duration::from_millis(10);
        loop {
            let notified = inner.block_ready_notify.notified();
            let round = inner
                .dag_state
                .last_own_block_ref()
                .map(|b| b.round())
                .unwrap_or_default();
            select! {
                _sleep = sleep(commit_timeout) => {
                    tracing::debug!("Commit timeout in round {round}");
                    // try commit
                    inner.syncer.force_commit().await;

                }
                _notified = notified => {
                    // todo - more then one round timeout can happen, need to fix this
                    inner.syncer.force_commit().await;
                }
                _stopped = inner.stopped() => {
                    return None;
                }
            }
        }
    }

    async fn cleanup_task(
        inner: Arc<NetworkSyncerInner<H, C>>,
        bls_service: Option<BlsServiceHandle>,
        sf_service: Option<SailfishServiceHandle>,
    ) -> Option<()> {
        let cleanup_interval = Duration::from_secs(10);
        loop {
            select! {
                _sleep = sleep(cleanup_interval) => {
                    inner.syncer.cleanup().await;
                    let gc_round = inner.dag_state.gc_round();
                    inner.gc_round.store(gc_round, Ordering::Relaxed);

                    // Notify BLS service to clean up old aggregator state.
                    if let Some(ref bls) = bls_service {
                        bls.send(BlsServiceMessage::Cleanup(gc_round));
                    }

                    // Notify Sailfish service to clean up old aggregator state.
                    if let Some(ref sf) = sf_service {
                        sf.send(SailfishServiceMessage::Cleanup(gc_round));
                    }

                    // Evict stale entries from CordialKnowledge
                    // using per-authority eviction rounds.
                    let eviction_rounds = inner.dag_state.evicted_rounds();
                    if eviction_rounds.iter().any(|&r| r > 0) {
                        inner.cordial_knowledge.send(
                            CordialKnowledgeMessage::EvictBelow(eviction_rounds),
                        );
                    }
                }
                _stopped = inner.stopped() => {
                    return None;
                }
            }
        }
    }

    pub async fn await_completion(self) -> Result<(), JoinError> {
        self.main_task.await
    }
}

impl<H: BlockHandler + 'static, C: CommitObserver + 'static> NetworkSyncerInner<H, C> {
    // Returns None either if channel is closed or NetworkSyncerInner receives stop
    // signal
    async fn recv_or_stopped<T>(&self, channel: &mut mpsc::Receiver<T>) -> Option<T> {
        select! {
            stopped = self.stop.send(()) => {
                assert!(stopped.is_err());
                None
            }
            data = channel.recv() => {
                data
            }
        }
    }

    async fn stopped(&self) {
        let _ = self.stop.send(()).await;
    }
}

impl SyncerSignals for NetworkSyncSignals {
    fn new_block_ready(&mut self) {
        self.block_ready_notify.notify_waiters();
    }

    fn threshold_clock_round_advanced(&mut self, _round: RoundNumber) {
        self.threshold_clock_notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{SignatureBytes, TransactionsCommitment},
        types::{BaseTransaction, BlockReference},
    };

    #[tokio::test]
    async fn threshold_clock_signal_notifies_waiters() {
        let block_ready_notify = Arc::new(Notify::new());
        let threshold_clock_notify = Arc::new(Notify::new());
        let mut signals = NetworkSyncSignals {
            block_ready_notify,
            threshold_clock_notify: threshold_clock_notify.clone(),
        };

        let wait = threshold_clock_notify.notified();
        signals.threshold_clock_round_advanced(5);
        wait.await;
    }

    #[test]
    fn acknowledgments_imply_peer_knows_shard_data() {
        let ack_ref = BlockReference::new_test(2, 3);
        let block = Data::new(VerifiedBlock::new(
            0,
            4,
            vec![BlockReference::new_test(0, 3)],
            vec![ack_ref],
            0,
            SignatureBytes::default(),
            Vec::<BaseTransaction>::new(),
            TransactionsCommitment::default(),
            None,
            None,
            None,
        ));

        let mut ck = ConnectionKnowledge::new(1, 4);
        infer_peer_knowledge_from_received_batch(&mut ck, &[block], &[], &[]);

        assert!(ck.knows_header(&ack_ref));
        assert!(ck.knows_shard(&ack_ref));
    }
}
