// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
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
    broadcaster::{BlockDisseminator, BlockFetcher, BroadcasterParameters, DataRequester},
    committee::Committee,
    consensus::universal_committer::UniversalCommitter,
    cordial_knowledge::{CordialKnowledgeHandle, CordialKnowledgeMessage},
    core::Core,
    core_thread::CoreThreadDispatcher,
    crypto::BlsSignatureBytes,
    dag_state::{ConsensusProtocol, DagState},
    data::Data,
    metrics::{Metrics, UtilizationTimerVecExt},
    network::{BlockBatch, Connection, Network, NetworkMessage},
    runtime::{Handle, JoinError, JoinHandle, sleep},
    syncer::{CommitObserver, Syncer, SyncerSignals},
    types::{
        AuthorityIndex, BlockDigest, BlockReference, RoundNumber, VerifiedBlock,
        format_authority_index,
    },
};

const MAX_FILTER_SIZE: usize = 100_000;

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

    /// Returns `true` if the digest is already tracked in the filter.
    fn contains(&self, digest: &BlockDigest) -> bool {
        self.digests.read().contains(digest)
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
                status.count < self.info_length && (status.bitmap & (1u128 << shard_index)) == 0
            }
            None => true,
        }
    }

    fn add(&self, digest: BlockDigest, shard_index: usize) {
        let mut digests = self.digests.write();
        let mut queue = self.queue.write();

        let entry = digests.entry(digest).or_insert_with(|| {
            queue.push_back(digest);
            ShardStatus {
                count: 0,
                bitmap: 0,
            }
        });
        let mask = 1u128 << shard_index;
        if entry.bitmap & mask == 0 {
            entry.bitmap |= mask;
            entry.count += 1;
        }

        while queue.len() > MAX_FILTER_SIZE {
            if let Some(removed) = queue.pop_front() {
                digests.remove(&removed);
            }
        }
    }

    /// Mark a digest as fully available (stop accepting further shards).
    fn mark_full(&self, digest: BlockDigest) {
        let mut digests = self.digests.write();
        let mut queue = self.queue.write();

        let entry = digests.entry(digest).or_insert_with(|| {
            queue.push_back(digest);
            ShardStatus {
                count: 0,
                bitmap: 0,
            }
        });
        entry.count = self.info_length;
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
}

impl<H: BlockHandler + 'static, C: CommitObserver + 'static> ConnectionHandler<H, C> {
    fn new(
        connection: &Connection,
        universal_committer: UniversalCommitter,
        inner: Arc<NetworkSyncerInner<H, C>>,
        metrics: Arc<Metrics>,
        filter_for_blocks: Arc<FilterForBlocks>,
        filter_for_shards: Arc<FilterForShards>,
    ) -> Self {
        let consensus_protocol = inner.dag_state.consensus_protocol;
        let committee_size = inner.dag_state.committee_size;
        let broadcaster_parameters = BroadcasterParameters::new(committee_size, consensus_protocol);
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
        }
    }

    async fn start(&mut self) {
        // Data requester is needed in theory only for StarfishPull. However, we enable
        // it for Starfish as well because of the practical way we update the
        // DAG known by other validators
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::StarfishPull
                | ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishS
                | ConsensusProtocol::StarfishL
        ) {
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
            NetworkMessage::DacPartialSig(block_ref, signer, sig) => {
                if signer == self.peer_id {
                    self.inner
                        .syncer
                        .add_dac_partial_sig(block_ref, signer, sig)
                        .await;
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
            match self.consensus_protocol {
                ConsensusProtocol::Mysticeti | ConsensusProtocol::StarfishPull => {
                    self.disseminator.disseminate_own_blocks(round).await;
                }
                ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishS
                | ConsensusProtocol::StarfishL
                | ConsensusProtocol::CordialMiners => {
                    self.disseminator.disseminate_all_blocks_push().await;
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
            for block in full_blocks.iter().chain(headers.iter()) {
                // Peer knows this block's header (they sent it to us)
                ck.mark_header_known(*block.reference());
                // Peer knows the header of every parent (causal history)
                for parent_ref in block.block_references() {
                    ck.mark_header_known(*parent_ref);
                }
                // Acknowledgments only prove the peer knows the acknowledged
                // block headers.
                for ack_ref in block.acknowledgments() {
                    ck.mark_header_known(ack_ref);
                }
            }
            for shard in &shards {
                ck.mark_header_known(shard.block_reference);
                ck.mark_shard_known(shard.block_reference);
            }
        }

        // Separate full blocks by whether they carry transactions
        let mut blocks_with_transactions = Vec::new();
        let mut blocks_without_transactions = Vec::new();
        for block in full_blocks {
            if block.transactions().is_some() {
                blocks_with_transactions.push(block);
            } else {
                blocks_without_transactions.push(block);
            }
        }

        // Header-only blocks go into the without-transactions path
        blocks_without_transactions.extend(headers);

        // First process blocks without transactions (causal history shards/headers)
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::StarfishPull
                | ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishS
                | ConsensusProtocol::StarfishL
        ) {
            self.process_blocks_without_transactions(blocks_without_transactions)
                .await;
        }

        // Process standalone shards — route directly to shard reconstructor
        if !shards.is_empty() {
            self.process_standalone_shards(shards).await;
        }

        // Then process blocks with transactions
        self.process_blocks_with_transactions(blocks_with_transactions)
            .await;

        drop(timer);
    }

    async fn process_standalone_shards(&mut self, shards: Vec<crate::network::ShardPayload>) {
        use crate::shard_reconstructor::ShardMessage;

        let maybe_tx = self.inner.shard_tx.lock().clone();
        let Some(shard_tx) = maybe_tx else { return };
        let connection_knowledge = self
            .inner
            .cordial_knowledge
            .connection_knowledge(self.peer_id);
        let committee_size = self.inner.committee.len();

        let mut batch = Vec::new();

        for payload in shards {
            if !self
                .filter_for_shards
                .needed(&payload.block_reference.digest, payload.shard.shard_index())
            {
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

            if let Some(ck) = connection_knowledge.as_ref() {
                ck.write()
                    .mark_shard_useful_from_peer(payload.block_reference);
            }

            // Attach shard to DAG block for immediate relay.
            if self
                .inner
                .dag_state
                .attach_shard_data(payload.block_reference, &payload.shard)
            {
                self.inner
                    .cordial_knowledge
                    .send(CordialKnowledgeMessage::NewShard(payload.block_reference));
            }

            batch.push(ShardMessage::Shard {
                block_reference: payload.block_reference,
                merkle_root: payload.shard.transactions_commitment(),
                shard: payload.shard.shard().clone(),
                shard_index: payload.shard.shard_index(),
            });
            self.filter_for_shards
                .add(payload.block_reference.digest, payload.shard.shard_index());
        }

        if !batch.is_empty() {
            let _ = shard_tx.send(batch).await;
        }
    }

    async fn process_blocks_without_transactions(&mut self, blocks: Vec<Data<VerifiedBlock>>) {
        let connection_knowledge = self
            .inner
            .cordial_knowledge
            .connection_knowledge(self.peer_id);
        let incoming_digests: Vec<_> = blocks.iter().map(|block| block.digest()).collect();
        let needed_before_verify = self.filter_for_blocks.needed_headers(&incoming_digests);
        let mut verified_blocks: Vec<VerifiedBlock> = Vec::new();

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
                Ok(shard) => debug_assert!(shard.is_none(), "shard must be None for header-only blocks"),
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

            if let Some(ck) = connection_knowledge.as_ref() {
                let mut ck = ck.write();
                ck.mark_header_useful_from_peer(*block.reference());
            }
            verified_blocks.push(block);
        }

        let mut new_data_blocks = Vec::new();
        let mut digests_to_insert = Vec::new();
        for storage_block in verified_blocks {
            let digest = storage_block.digest();
            let send_to_core = !self.filter_for_blocks.contains(&digest);
            digests_to_insert.push(digest);
            if send_to_core {
                let mut storage_block = storage_block;
                storage_block.preserialize();
                debug_assert!(
                    storage_block.serialized_header_bytes().is_some(),
                    "header must be preserialized before entering core"
                );
                new_data_blocks.push(Data::new(storage_block));
            }
        }

        if !digests_to_insert.is_empty() {
            self.filter_for_blocks.insert_batch(&digests_to_insert);
        }

        tracing::debug!(
            "To be processed after verification from {:?}, {} new blocks without transactions {:?}",
            self.peer,
            new_data_blocks.len(),
            new_data_blocks
        );
        if !new_data_blocks.is_empty() {
            // Notify CordialKnowledge about new headers entering the DAG
            for block in new_data_blocks.iter() {
                self.inner
                    .cordial_knowledge
                    .send(CordialKnowledgeMessage::NewHeader(*block.reference()));
            }
            let (missing_parents, processed_additional_refs) =
                self.inner.syncer.add_headers(new_data_blocks).await;
            if !missing_parents.is_empty() {
                let missing_parents = missing_parents.iter().copied().collect::<Vec<_>>();
                tracing::debug!(
                    "Make request missing parents of header/shard blocks {:?} from peer {:?}",
                    missing_parents,
                    self.peer
                );
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

    async fn process_blocks_with_transactions(&mut self, blocks: Vec<Data<VerifiedBlock>>) {
        let connection_knowledge = self
            .inner
            .cordial_knowledge
            .connection_knowledge(self.peer_id);
        let mut verified_data_blocks = Vec::new();
        let mut verified_has_shard = Vec::new();
        let shard_tx = self.inner.shard_tx.lock().clone();

        for data_block in blocks {
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
            // Insert shard sidecar into DAG index
            if let Some(s) = shard.as_ref() {
                self.inner
                    .dag_state
                    .insert_shard(*block.reference(), s.clone());
            }
            if let Some(ck) = connection_knowledge.as_ref() {
                let mut ck = ck.write();
                ck.mark_header_useful_from_peer(*block.reference());
                if shard.is_some() {
                    ck.mark_shard_useful_from_peer(*block.reference());
                }
            }
            self.filter_for_blocks.insert_batch(&[block.digest()]);
            self.filter_for_shards.mark_full(block.digest());
            let has_shard = shard.is_some();
            let mut block = block;
            block.preserialize();
            debug_assert!(
                block.serialized_header_bytes().is_some(),
                "header must be preserialized before entering core"
            );
            verified_data_blocks.push(Data::new(block));
            verified_has_shard.push(has_shard);
        }

        // Notify reconstructor to stop collecting shards for these blocks (batched).
        if let Some(shard_tx) = shard_tx.as_ref() {
            let full_block_msgs: Vec<_> = verified_data_blocks
                .iter()
                .map(|b| crate::shard_reconstructor::ShardMessage::FullBlock(*b.reference()))
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
            // Notify CordialKnowledge about new headers (and shards) entering the DAG
            for (block, &has_shard) in verified_data_blocks.iter().zip(verified_has_shard.iter()) {
                self.inner
                    .cordial_knowledge
                    .send(CordialKnowledgeMessage::NewHeader(*block.reference()));
                if has_shard {
                    self.inner
                        .cordial_knowledge
                        .send(CordialKnowledgeMessage::NewShard(*block.reference()));
                }
            }
            let (_pending_block_references, missing_parents, _processed_additional_blocks) =
                self.inner.syncer.add_blocks(verified_data_blocks).await;
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
                | ConsensusProtocol::StarfishPull
                | ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishS
                | ConsensusProtocol::StarfishL
        ) {
            tracing::debug!(
                "Received request missing data {:?} from peer {:?}",
                block_references,
                self.peer
            );
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
            ConsensusProtocol::StarfishPull
                | ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishS
                | ConsensusProtocol::StarfishL
        ) {
            tracing::debug!(
                "Received request missing data {:?} from peer {:?}",
                block_references,
                self.peer
            );
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
    dac_routing_task: Option<JoinHandle<()>>,
    cordial_knowledge_task: JoinHandle<()>,
}

pub struct NetworkSyncerInner<H: BlockHandler, C: CommitObserver> {
    pub syncer: CoreThreadDispatcher<H, Arc<Notify>, C>,
    pub dag_state: DagState,
    pub notify: Arc<Notify>,
    pub committee: Arc<Committee>,
    stop: mpsc::Sender<()>,
    pub gc_round: Arc<AtomicU64>,
    pub shard_tx:
        parking_lot::Mutex<Option<mpsc::Sender<Vec<crate::shard_reconstructor::ShardMessage>>>>,
    pub cordial_knowledge: CordialKnowledgeHandle,
    /// Per-peer message senders for direct unicast (e.g. DAC partial sigs).
    pub peer_senders: parking_lot::RwLock<AHashMap<AuthorityIndex, mpsc::Sender<NetworkMessage>>>,
}

impl<H: BlockHandler + 'static, C: CommitObserver + 'static> NetworkSyncer<H, C> {
    pub fn start(
        network: Network,
        mut core: Core<H>,
        mut commit_observer: C,
        metrics: Arc<Metrics>,
        dac_outbox_rx: Option<mpsc::UnboundedReceiver<(BlockReference, BlsSignatureBytes)>>,
        bls_cert_aggregator: Option<crate::bls_certificate_aggregator::BlsCertificateAggregator>,
    ) -> Self {
        let handle = Handle::current();
        let notify = Arc::new(Notify::new());
        let (committed, committed_leaders_count) = core.take_recovered_committed();
        commit_observer.recover_committed(committed, committed_leaders_count);
        let committee = core.committee().clone();
        let dag_state = core.dag_state().clone();
        let _store = core.store();
        let universal_committer = core.get_universal_committer();
        let mut syncer = Syncer::new(
            core,
            bls_cert_aggregator,
            notify.clone(),
            commit_observer,
            metrics.clone(),
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
                | ConsensusProtocol::StarfishS
                | ConsensusProtocol::StarfishL
                | ConsensusProtocol::StarfishPull
        );
        let gc_round = Arc::new(AtomicU64::new(dag_state.gc_round()));
        let (shard_tx, decoded_rx) = if is_starfish {
            let (decoded_tx, decoded_rx) =
                mpsc::channel::<crate::shard_reconstructor::DecodedBlocks>(1000);
            let reconstructor_handle = crate::shard_reconstructor::start_shard_reconstructor(
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
            CordialKnowledgeHandle::new(committee.len());
        let cordial_knowledge_task = handle.spawn(cordial_knowledge_actor.run());

        let inner = Arc::new(NetworkSyncerInner {
            notify,
            syncer,
            dag_state: dag_state.clone(),
            committee,
            stop: stop_sender.clone(),
            gc_round,
            shard_tx: parking_lot::Mutex::new(shard_tx),
            cordial_knowledge: cordial_knowledge_handle,
            peer_senders: parking_lot::RwLock::new(AHashMap::new()),
        });

        // Start bridge task that forwards reconstructed transaction data to core
        let bridge_task = decoded_rx.map(|mut decoded_rx| {
            let bridge_inner = inner.clone();
            handle.spawn(async move {
                while let Some(items) = decoded_rx.recv().await {
                    // Notify CordialKnowledge: reconstruction proves we have both
                    // the header (already known) and the shard data.
                    for item in &items {
                        bridge_inner
                            .cordial_knowledge
                            .send(CordialKnowledgeMessage::NewShard(item.block_reference));
                    }
                    bridge_inner.syncer.add_transaction_data(items).await;
                }
            })
        });
        // Spawn DAC routing task: drains Core's outbox and routes DAC partial
        // sigs to the target block author via peer_senders.
        let dac_routing_task = dac_outbox_rx.map(|mut rx| {
            let routing_inner = inner.clone();
            handle.spawn(async move {
                while let Some((block_ref, sig)) = rx.recv().await {
                    let target = block_ref.authority;
                    let msg = NetworkMessage::DacPartialSig(
                        block_ref,
                        routing_inner.dag_state.get_own_authority_index(),
                        sig,
                    );
                    if let Some(sender) = routing_inner.peer_senders.read().get(&target) {
                        let _ = sender.try_send(msg);
                    }
                }
            })
        });
        let block_fetcher = Arc::new(BlockFetcher::start());
        let main_task = handle.spawn(Self::run(
            network,
            universal_committer,
            inner.clone(),
            block_fetcher,
            metrics.clone(),
        ));
        Self {
            inner,
            main_task,
            stop: stop_receiver,
            bridge_task,
            dac_routing_task,
            cordial_knowledge_task,
        }
    }

    pub async fn shutdown(self) -> Syncer<H, Arc<Notify>, C> {
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
        // The DAC routing task holds an `Arc` to `inner` and waits on a
        // receiver whose sender lives inside the core thread. Abort it here to
        // break that shutdown cycle before unwrapping `inner`.
        if let Some(dac_task) = self.dac_routing_task {
            dac_task.abort();
            dac_task.await.ok();
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
    ) {
        let mut connections: HashMap<usize, JoinHandle<Option<()>>> = HashMap::new();
        let handle = Handle::current();
        let leader_timeout_task = handle.spawn(Self::leader_timeout_task(inner.clone()));

        let commit_timeout_task = handle.spawn(Self::commit_timeout_task(inner.clone()));
        let cleanup_task = handle.spawn(Self::cleanup_task(inner.clone()));
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
            ));
            connections.insert(peer_id, task);
        }
        join_all(
            connections
                .into_values()
                .chain([leader_timeout_task, commit_timeout_task, cleanup_task].into_iter()),
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
        );
        handler.start().await;

        let peer_id = handler.peer_id;
        let own_id = handler.own_id;

        // Register peer sender for direct unicast messages (DAC partial sigs).
        inner
            .peer_senders
            .write()
            .insert(peer_id, connection.sender.clone());

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
        let leader_timeout = Duration::from_millis(600);
        loop {
            let notified = inner.notify.notified();
            let round = inner
                .dag_state
                .last_own_block_ref()
                .map(|b| b.round())
                .unwrap_or_default();
            select! {
                _sleep = sleep(leader_timeout) => {
                    tracing::debug!("Timeout in round {round}");
                    // todo - more then one round timeout can happen, need to fix this
                    inner.syncer.force_new_block(round).await;

                }
                _notified = notified => {
                    // restart loop
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
            let notified = inner.notify.notified();
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

    async fn cleanup_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        let cleanup_interval = Duration::from_secs(10);
        loop {
            select! {
                _sleep = sleep(cleanup_interval) => {
                    inner.syncer.cleanup().await;
                    let gc_round = inner.dag_state.gc_round();
                    inner.gc_round.store(gc_round, Ordering::Relaxed);

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

impl SyncerSignals for Arc<Notify> {
    fn new_block_ready(&mut self) {
        self.notify_waiters();
    }
}
