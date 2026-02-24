// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::block_store::ConsensusProtocol;
use crate::consensus::universal_committer::UniversalCommitter;
use crate::data::Data;
use crate::decoder::CachedStatementBlockDecoder;
use crate::metrics::UtilizationTimerVecExt;
use crate::rocks_store::RocksStore;
use crate::runtime::sleep;
use crate::synchronizer::{DataRequestor, UpdaterMissingAuthorities};
use crate::types::{BlockDigest, BlockReference, RoundNumber, VerifiedStatementBlock};
use crate::{
    block_handler::BlockHandler,
    block_store::BlockStore,
    committee::Committee,
    core::Core,
    core_thread::CoreThreadDispatcher,
    metrics::Metrics,
    network::{Connection, Network, NetworkMessage},
    runtime::{timestamp_utc, Handle, JoinError, JoinHandle},
    syncer::{CommitObserver, Syncer, SyncerSignals},
    synchronizer::{BlockDisseminator, BlockFetcher, SynchronizerParameters},
    types::{format_authority_index, AuthorityIndex},
};
use futures::future::join_all;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::collections::{HashSet, VecDeque};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::RwLock;
use tokio::time::Instant;
use tokio::{
    select,
    sync::{mpsc, oneshot, Notify},
};

const MAX_FILTER_SIZE: usize = 100_000;

struct FilterForBlocks {
    info_length: usize,
    digests: parking_lot::RwLock<HashMap<BlockDigest, StatusFilter>>,
    queue: parking_lot::RwLock<VecDeque<BlockDigest>>,
}
enum Status {
    Full,
    Shard(usize),
    Header,
}
impl Status {
    fn get_status(block: &VerifiedStatementBlock, peer: usize) -> Self {
        if block.statements().is_some() {
            Status::Full
        } else if block.encoded_shard().is_some() {
            Status::Shard(peer)
        } else {
            Status::Header
        }
    }
}
enum StatusFilter {
    Full,
    Shards { count: usize, bitmap: u128 },
    Header,
}

impl StatusFilter {
    fn from_status(status: &Status) -> Self {
        match status {
            Status::Full => StatusFilter::Full,
            Status::Shard(peer) => StatusFilter::Shards {
                count: 1,
                bitmap: 1u128 << peer,
            },
            Status::Header => StatusFilter::Header,
        }
    }

    /// Apply an incoming status. Returns `true` if this digest was already fully covered.
    fn transition(&mut self, status: &Status, info_length: usize) -> bool {
        match (status, &*self) {
            (_, StatusFilter::Full) => true,
            (Status::Header, _) => true,
            (Status::Full, _) => {
                *self = StatusFilter::Full;
                false
            }
            (Status::Shard(peer), StatusFilter::Shards { count, bitmap }) => {
                let mask = 1u128 << peer;
                if *bitmap & mask != 0 {
                    return true;
                }
                let new_count = *count + 1;
                let new_bitmap = *bitmap | mask;
                if new_count >= info_length {
                    *self = StatusFilter::Full;
                } else {
                    *self = StatusFilter::Shards {
                        count: new_count,
                        bitmap: new_bitmap,
                    };
                }
                false
            }
            (Status::Shard(peer), StatusFilter::Header) => {
                *self = StatusFilter::Shards {
                    count: 1,
                    bitmap: 1u128 << peer,
                };
                false
            }
        }
    }
}

impl FilterForBlocks {
    fn new(info_length: usize) -> Self {
        Self {
            info_length,
            digests: parking_lot::RwLock::new(HashMap::new()),
            queue: parking_lot::RwLock::new(VecDeque::new()),
        }
    }

    fn add_batch(&self, new_digests: Vec<(BlockDigest, Status)>) -> Vec<BlockDigest> {
        let mut already_inserted = Vec::new();
        let mut queue_updates = Vec::new();

        {
            let mut digests = self.digests.write();

            for (digest, status) in &new_digests {
                if let Some(existing) = digests.get_mut(digest) {
                    if existing.transition(status, self.info_length) {
                        already_inserted.push(*digest);
                    }
                } else {
                    digests.insert(*digest, StatusFilter::from_status(status));
                    queue_updates.push(*digest);
                }
            }
        }

        {
            let mut queue = self.queue.write();
            for digest in queue_updates {
                queue.push_back(digest);
            }

            while queue.len() > MAX_FILTER_SIZE {
                if let Some(removed) = queue.pop_front() {
                    self.digests.write().remove(&removed);
                }
            }
        }

        already_inserted
    }

    ///  Checks whether the block is needed based on its digest and status.
    fn is_needed(&self, digest: &BlockDigest, status: Status) -> bool {
        match status {
            Status::Header => {
                // Header is needed if not already in the filter
                !self.digests.read().contains_key(digest)
            }
            Status::Shard(peer) => {
                // Shard is needed if not already in the filter or if the number of shards is not sufficient
                let digests = self.digests.read();
                match digests.get(digest) {
                    Some(StatusFilter::Full) => false,
                    Some(StatusFilter::Header) => true,
                    Some(StatusFilter::Shards { count: _, bitmap }) => {
                        let mask = 1u128 << peer;
                        (*bitmap & mask) == 0
                    }
                    None => true,
                }
            }
            Status::Full => {
                let digests = self.digests.read();
                !matches!(digests.get(digest), Some(StatusFilter::Full))
            }
        }
    }
}

/// Per-connection state for `connection_task`. Groups the 15+ shared locals
/// into a struct so the 400-line match body can be split into focused handlers.
struct ConnectionHandler<H: BlockHandler + 'static, C: CommitObserver + 'static> {
    consensus_protocol: ConsensusProtocol,
    inner: Arc<NetworkSyncerInner<H, C>>,
    metrics: Arc<Metrics>,
    filter_for_blocks: Arc<FilterForBlocks>,
    disseminator: BlockDisseminator<H, C>,
    data_requestor: DataRequestor<H, C>,
    updater_missing_authorities: UpdaterMissingAuthorities,
    authorities_with_missing_blocks_by_myself_from_peer: Arc<RwLock<Vec<Instant>>>,
    authorities_with_missing_blocks_by_peer_from_me: Arc<RwLock<Vec<Instant>>>,
    encoder: ReedSolomonEncoder,
    decoder: ReedSolomonDecoder,
    peer_id: AuthorityIndex,
    peer_usize: usize,
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
    ) -> Self {
        let consensus_protocol = inner.block_store.consensus_protocol;
        let committee_size = inner.block_store.committee_size;
        let now = Instant::now();
        let authorities_with_missing_blocks_by_myself_from_peer =
            Arc::new(RwLock::new(vec![now; committee_size]));
        let authorities_with_missing_blocks_by_peer_from_me =
            Arc::new(RwLock::new(vec![now; committee_size]));
        let synchronizer_parameters =
            SynchronizerParameters::new(committee_size, consensus_protocol);
        let peer_id = connection.peer_id as AuthorityIndex;

        let disseminator = BlockDisseminator::new(
            peer_id,
            connection.sender.clone(),
            universal_committer,
            inner.clone(),
            synchronizer_parameters.clone(),
            metrics.clone(),
            authorities_with_missing_blocks_by_peer_from_me.clone(),
        );
        let data_requestor = DataRequestor::new(
            peer_id,
            connection.sender.clone(),
            inner.clone(),
            synchronizer_parameters.clone(),
        );
        let updater_missing_authorities = UpdaterMissingAuthorities::new(
            peer_id,
            connection.sender.clone(),
            synchronizer_parameters,
            authorities_with_missing_blocks_by_myself_from_peer.clone(),
        );

        let encoder = ReedSolomonEncoder::new(2, 4, 64).expect("Encoder should be created");
        let decoder = ReedSolomonDecoder::new(2, 4, 64).expect("Decoder should be created");
        let own_id = inner.block_store.get_own_authority_index();
        let peer = format_authority_index(peer_id);

        Self {
            consensus_protocol,
            inner,
            metrics,
            filter_for_blocks,
            disseminator,
            data_requestor,
            updater_missing_authorities,
            authorities_with_missing_blocks_by_myself_from_peer,
            authorities_with_missing_blocks_by_peer_from_me,
            encoder,
            decoder,
            peer_id,
            peer_usize: peer_id as usize,
            peer,
            own_id,
            sender: connection.sender.clone(),
        }
    }

    async fn start(&mut self) {
        // Data requestor is needed in theory only for StarfishPull. However, we enable it for
        // Starfish as well because of the practical way we update the DAG known by other validators
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::StarfishPull
                | ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishS
        ) {
            self.data_requestor.start().await;
        }
        // To save some bandwidth, we start the updater about authorities with missing blocks for Starfish
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::Starfish | ConsensusProtocol::StarfishS
        ) {
            self.updater_missing_authorities.start().await;
        }
    }

    /// Dispatch a single message. Returns `true` to continue, `false` to break the loop.
    async fn handle_message(&mut self, message: NetworkMessage) -> bool {
        match message {
            NetworkMessage::SubscribeBroadcastRequest(round) => {
                self.handle_subscribe(round).await;
            }
            NetworkMessage::Batch(blocks) => {
                self.handle_batch(blocks).await;
            }
            NetworkMessage::MissingHistoryRequest(block_ref) => {
                self.handle_missing_history_request(block_ref).await;
            }
            NetworkMessage::AuthoritiesWithMissingBlocks(authorities) => {
                self.handle_authorities_missing_blocks(authorities).await;
            }
            NetworkMessage::MissingParentsRequest(refs) => {
                return self.handle_missing_parents_request(refs).await;
            }
            NetworkMessage::MissingTxDataRequest(refs) => {
                return self.handle_missing_tx_data_request(refs).await;
            }
        }
        true
    }

    async fn handle_subscribe(&mut self, round: RoundNumber) {
        if self.inner.block_store.byzantine_strategy.is_some() {
            let round = 0;
            self.disseminator.disseminate_own_blocks(round).await;
        } else {
            match self.consensus_protocol {
                ConsensusProtocol::Mysticeti | ConsensusProtocol::StarfishPull => {
                    self.disseminator.disseminate_own_blocks(round).await;
                }
                ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishS
                | ConsensusProtocol::CordialMiners => {
                    self.disseminator.disseminate_all_blocks_push().await;
                }
            }
        }
    }

    async fn handle_batch(&mut self, blocks: Vec<Data<VerifiedStatementBlock>>) {
        let timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Network: verify blocks");
        let mut blocks_with_statements = Vec::new();
        let mut blocks_without_statements = Vec::new();
        for block in blocks {
            if block.statements().is_some() {
                blocks_with_statements.push(block);
            } else {
                blocks_without_statements.push(block);
            }
        }
        let mut authorities_to_be_updated: HashSet<AuthorityIndex> = HashSet::new();

        // First process blocks without statements (causal history shards)
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::StarfishPull
                | ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishS
        ) {
            self.process_blocks_without_statements(
                blocks_without_statements,
                &mut authorities_to_be_updated,
            )
            .await;
        }

        // Then process blocks with statements
        self.process_blocks_with_statements(blocks_with_statements, authorities_to_be_updated)
            .await;

        drop(timer);
    }

    async fn process_blocks_without_statements(
        &mut self,
        blocks: Vec<Data<VerifiedStatementBlock>>,
        authorities_to_be_updated: &mut HashSet<AuthorityIndex>,
    ) {
        let mut verified_data_blocks = Vec::new();
        for data_block in blocks {
            let mut block: VerifiedStatementBlock = (*data_block).clone();
            tracing::debug!("Received {} from {}", block, self.peer);
            let block_status = Status::get_status(&block, self.peer_usize);
            let contains_new_shard_or_header = self
                .filter_for_blocks
                .is_needed(&block.digest(), block_status);
            if !contains_new_shard_or_header {
                self.metrics.filtered_blocks_total.inc();
                continue;
            }
            if let Err(e) = block.verify(
                &self.inner.committee,
                self.own_id as usize,
                self.peer_id as usize,
                &mut self.encoder,
                self.consensus_protocol,
            ) {
                tracing::warn!(
                    "Rejected incorrect block {} from {}: {:?}",
                    block.reference(),
                    self.peer,
                    e
                );
                // todo: Terminate connection upon receiving incorrect block.
                break;
            }
            let (ready_to_reconstruct, cached_block) =
                self.inner.block_store.ready_to_reconstruct(&block);
            if ready_to_reconstruct {
                let mut cached_block = cached_block.expect("Should be Some");
                cached_block.copy_shard(&block);
                let reconstructed_block = self.decoder.decode_shards(
                    &self.inner.committee,
                    &mut self.encoder,
                    cached_block,
                    self.own_id,
                );
                if let Some(reconstructed) = reconstructed_block {
                    self.metrics
                        .reconstructed_blocks_total
                        .with_label_values(&["connection_task"])
                        .inc();
                    block = reconstructed;
                    tracing::debug!(
                        "Reconstruction of block {:?} within connection task is successful",
                        block
                    );
                } else {
                    tracing::debug!(
                        "Incorrect reconstruction of block {:?} within connection task",
                        block
                    );
                }
            }
            let block_status = Status::get_status(&block, self.peer_usize);
            let contains_new_shard_or_header = self
                .filter_for_blocks
                .is_needed(&block.digest(), block_status);
            let storage_block = block;
            let transmission_block = storage_block.from_storage_to_transmission(self.own_id);
            if !contains_new_shard_or_header {
                self.metrics.processed_after_filtering_total.inc();
                continue;
            }
            let data_storage_block = Data::new(storage_block);
            let data_transmission_block = Data::new(transmission_block);
            verified_data_blocks.push((data_storage_block, data_transmission_block));
        }

        tracing::debug!(
            "To be processed after verification from {:?}, {} blocks without statements {:?}",
            self.peer,
            verified_data_blocks.len(),
            verified_data_blocks
        );
        if !verified_data_blocks.is_empty() {
            let mut batch_with_status = Vec::new();
            for block in &verified_data_blocks {
                batch_with_status.push((
                    block.0.digest(),
                    Status::get_status(&block.0, self.peer_usize),
                ))
            }
            self.filter_for_blocks.add_batch(batch_with_status);
            let (_, _, processed_additional_blocks_without_statements) =
                self.inner.syncer.add_blocks(verified_data_blocks).await;
            self.metrics
                .used_additional_blocks_total
                .inc_by(processed_additional_blocks_without_statements.len() as u64);
            authorities_to_be_updated.extend(
                processed_additional_blocks_without_statements
                    .iter()
                    .map(|b| b.authority),
            );
            tracing::debug!(
                "Processed additional blocks from peer {:?}: {:?}",
                self.peer,
                processed_additional_blocks_without_statements
            );
        }
    }

    async fn process_blocks_with_statements(
        &mut self,
        blocks: Vec<Data<VerifiedStatementBlock>>,
        mut authorities_to_be_updated: HashSet<AuthorityIndex>,
    ) {
        let mut verified_data_blocks = Vec::new();
        for data_block in blocks {
            let mut block: VerifiedStatementBlock = (*data_block).clone();
            tracing::debug!("Received {} from {}", block, self.peer);
            let block_status = Status::get_status(&block, self.peer_usize);
            let contains_new_shard_or_header = self
                .filter_for_blocks
                .is_needed(&block.digest(), block_status);
            if !contains_new_shard_or_header {
                self.metrics.filtered_blocks_total.inc();
                continue;
            }
            if let Err(e) = block.verify(
                &self.inner.committee,
                self.own_id as usize,
                self.peer_id as usize,
                &mut self.encoder,
                self.consensus_protocol,
            ) {
                tracing::warn!(
                    "Rejected incorrect block {} from {}: {:?}",
                    block.reference(),
                    self.peer,
                    e
                );
                // todo: Terminate connection upon receiving incorrect block.
                break;
            }
            let storage_block = block;
            let transmission_block = match self.consensus_protocol {
                ConsensusProtocol::Mysticeti | ConsensusProtocol::CordialMiners => {
                    storage_block.clone()
                }
                ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishS
                | ConsensusProtocol::StarfishPull => {
                    storage_block.from_storage_to_transmission(self.own_id)
                }
            };
            self.filter_for_blocks
                .add_batch(vec![(storage_block.digest(), Status::Full)]);
            let data_storage_block = Data::new(storage_block);
            let data_transmission_block = Data::new(transmission_block);
            verified_data_blocks.push((data_storage_block, data_transmission_block));
        }

        tracing::debug!(
            "To be processed after verification from {:?}, {} blocks with statements {:?}",
            self.peer,
            verified_data_blocks.len(),
            verified_data_blocks
        );
        if !verified_data_blocks.is_empty() {
            let (pending_block_references, missing_parents, _processed_additional_blocks) =
                self.inner.syncer.add_blocks(verified_data_blocks).await;
            if !missing_parents.is_empty() {
                authorities_to_be_updated.extend(missing_parents.iter().map(|b| b.authority));
                tracing::debug!(
                    "Missing parents when processing block from peer {:?}: {:?}",
                    self.peer,
                    missing_parents
                );
            }
            match self.consensus_protocol {
                ConsensusProtocol::StarfishPull => {
                    let max_round_ref = pending_block_references
                        .into_iter()
                        .max_by_key(|r| r.round());
                    if let Some(block_ref) = max_round_ref {
                        tracing::debug!(
                            "Make request missing history of block {:?} from peer {:?}",
                            block_ref,
                            self.peer
                        );
                        if let Ok(permit) = self.sender.try_reserve() {
                            permit.send(NetworkMessage::MissingHistoryRequest(block_ref));
                        }
                    }
                }
                ConsensusProtocol::Mysticeti => {
                    if !missing_parents.is_empty() {
                        let missing_parents = missing_parents.iter().copied().collect::<Vec<_>>();
                        tracing::debug!(
                            "Make request missing parents of blocks {:?} from peer {:?}",
                            missing_parents,
                            self.peer
                        );
                        if let Ok(permit) = self.sender.try_reserve() {
                            permit.send(NetworkMessage::MissingParentsRequest(missing_parents));
                        }
                    }
                }
                ConsensusProtocol::CordialMiners => {}
                ConsensusProtocol::Starfish | ConsensusProtocol::StarfishS => {
                    if !authorities_to_be_updated.is_empty() {
                        let now = Instant::now();
                        let mut authorities_with_missing_blocks = self
                            .authorities_with_missing_blocks_by_myself_from_peer
                            .write()
                            .await;
                        tracing::debug!(
                            "Authorities updates for peer {:?} are {:?}",
                            self.peer,
                            authorities_to_be_updated
                        );
                        for authority in authorities_to_be_updated {
                            authorities_with_missing_blocks[authority as usize] = now;
                        }
                        drop(authorities_with_missing_blocks);
                    }
                }
            }
        }
    }

    async fn handle_missing_history_request(&mut self, block_reference: BlockReference) {
        if self.consensus_protocol == ConsensusProtocol::StarfishPull {
            tracing::debug!(
                "Received request missing history for block {:?} from peer {:?}",
                block_reference,
                self.peer
            );
            if self.inner.block_store.byzantine_strategy.is_none() {
                self.disseminator
                    .push_block_history_with_shards(block_reference)
                    .await;
            }
        }
    }

    async fn handle_authorities_missing_blocks(&self, authorities: Vec<AuthorityIndex>) {
        let now = Instant::now();
        tracing::debug!(
            "Received authorities with missing blocks {:?} from peer {:?}",
            authorities
                .iter()
                .map(|a| format_authority_index(*a))
                .collect::<Vec<_>>(),
            self.peer
        );
        let mut guard = self
            .authorities_with_missing_blocks_by_peer_from_me
            .write()
            .await;
        for authority in authorities {
            guard[authority as usize] = now;
        }
    }

    /// Returns `true` to continue, `false` to break the connection loop.
    async fn handle_missing_parents_request(
        &mut self,
        block_references: Vec<BlockReference>,
    ) -> bool {
        if self.consensus_protocol == ConsensusProtocol::Mysticeti {
            tracing::debug!(
                "Received request missing data {:?} from peer {:?}",
                block_references,
                self.peer
            );
            if self.inner.block_store.byzantine_strategy.is_none() {
                if self
                    .disseminator
                    .send_storage_blocks(self.peer_id, block_references)
                    .await
                    .is_none()
                {
                    return false;
                }
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
        ) {
            tracing::debug!(
                "Received request missing data {:?} from peer {:?}",
                block_references,
                self.peer
            );
            if self.inner.block_store.byzantine_strategy.is_none() {
                if self
                    .disseminator
                    .send_transmission_blocks(self.peer_id, block_references)
                    .await
                    .is_none()
                {
                    return false;
                }
            }
        }
        true
    }

    async fn shutdown(self) {
        self.disseminator.shutdown().await;
        self.data_requestor.shutdown().await;
        self.updater_missing_authorities.shutdown().await;
    }
}

pub struct NetworkSyncer<H: BlockHandler, C: CommitObserver> {
    inner: Arc<NetworkSyncerInner<H, C>>,
    main_task: JoinHandle<()>,
    syncer_task: oneshot::Receiver<()>,
    flusher_task: oneshot::Receiver<()>,
    stop: mpsc::Receiver<()>,
}

pub struct NetworkSyncerInner<H: BlockHandler, C: CommitObserver> {
    pub syncer: CoreThreadDispatcher<H, Arc<Notify>, C>,
    pub block_store: BlockStore,
    pub notify: Arc<Notify>,
    pub committee: Arc<Committee>,
    stop: mpsc::Sender<()>,
    epoch_close_signal: mpsc::Sender<()>,
    pub epoch_closing_time: Arc<AtomicU64>,
}

impl<H: BlockHandler + 'static, C: CommitObserver + 'static> NetworkSyncer<H, C> {
    pub fn start(
        network: Network,
        mut core: Core<H>,
        mut commit_observer: C,
        shutdown_grace_period: Duration,
        metrics: Arc<Metrics>,
    ) -> Self {
        let handle = Handle::current();
        let notify = Arc::new(Notify::new());
        let committed = core.take_recovered_committed_blocks();
        commit_observer.recover_committed(committed);
        let committee = core.committee().clone();
        let block_store = core.block_store().clone();
        let rocks_store = core.rocks_store();
        let epoch_closing_time = core.epoch_closing_time();
        let universal_committer = core.get_universal_committer();
        let mut syncer = Syncer::new(core, notify.clone(), commit_observer, metrics.clone());
        syncer.force_new_block(0);
        let syncer = CoreThreadDispatcher::start(syncer);
        let (stop_sender, stop_receiver) = mpsc::channel(1);
        stop_sender.try_send(()).unwrap(); // occupy the only available permit, so that all other calls to send() will block
        let (epoch_sender, epoch_receiver) = mpsc::channel(1);
        epoch_sender.try_send(()).unwrap(); // occupy the only available permit, so that all other calls to send() will block
        let inner = Arc::new(NetworkSyncerInner {
            notify,
            syncer,
            block_store,
            committee,
            stop: stop_sender.clone(),
            epoch_close_signal: epoch_sender.clone(),
            epoch_closing_time,
        });
        let block_fetcher = Arc::new(BlockFetcher::start());
        let main_task = handle.spawn(Self::run(
            network,
            universal_committer,
            inner.clone(),
            epoch_receiver,
            shutdown_grace_period,
            block_fetcher,
            metrics.clone(),
        ));
        let syncer_task =
            AsyncRocksDBSyncer::start(stop_sender.clone(), epoch_sender, rocks_store.clone());
        let flusher_task = AsyncRocksDBFlusher::start(stop_sender, rocks_store);
        Self {
            inner,
            main_task,
            stop: stop_receiver,
            syncer_task,
            flusher_task,
        }
    }

    pub async fn shutdown(self) -> Syncer<H, Arc<Notify>, C> {
        drop(self.stop);
        // todo - wait for network shutdown as well
        self.main_task.await.ok();
        self.syncer_task.await.ok();
        self.flusher_task.await.ok();
        let Ok(inner) = Arc::try_unwrap(self.inner) else {
            panic!("Shutdown failed - not all resources are freed after main task is completed");
        };
        inner.syncer.stop()
    }

    async fn run(
        mut network: Network,
        universal_committer: UniversalCommitter,
        inner: Arc<NetworkSyncerInner<H, C>>,
        epoch_close_signal: mpsc::Receiver<()>,
        shutdown_grace_period: Duration,
        block_fetcher: Arc<BlockFetcher>,
        metrics: Arc<Metrics>,
    ) {
        let mut connections: HashMap<usize, JoinHandle<Option<()>>> = HashMap::new();
        let handle = Handle::current();
        let leader_timeout_task = handle.spawn(Self::leader_timeout_task(
            inner.clone(),
            epoch_close_signal,
            shutdown_grace_period,
        ));

        let commit_timeout_task = handle.spawn(Self::commit_timeout_task(
            inner.clone(),
            shutdown_grace_period,
        ));
        let cleanup_task = handle.spawn(Self::cleanup_task(inner.clone()));
        let filter_for_blocks = Arc::new(FilterForBlocks::new(inner.committee.info_length()));
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
    }

    async fn connection_task(
        mut connection: Connection,
        universal_committer: UniversalCommitter,
        inner: Arc<NetworkSyncerInner<H, C>>,
        block_fetcher: Arc<BlockFetcher>,
        metrics: Arc<Metrics>,
        filter_for_blocks: Arc<FilterForBlocks>,
    ) -> Option<()> {
        let last_seen = inner
            .block_store
            .last_seen_by_authority(connection.peer_id as AuthorityIndex);
        connection
            .sender
            .send(NetworkMessage::SubscribeBroadcastRequest(last_seen))
            .await
            .ok()?;

        let mut handler = ConnectionHandler::new(
            &connection,
            universal_committer,
            inner.clone(),
            metrics,
            filter_for_blocks,
        );
        handler.start().await;

        let peer_id = handler.peer_id;
        let own_id = handler.own_id;
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
        inner.syncer.authority_connection(peer_id, false).await;
        handler.shutdown().await;
        block_fetcher.remove_authority(peer_id).await;
        None
    }

    async fn leader_timeout_task(
        inner: Arc<NetworkSyncerInner<H, C>>,
        mut epoch_close_signal: mpsc::Receiver<()>,
        shutdown_grace_period: Duration,
    ) -> Option<()> {
        let leader_timeout = Duration::from_millis(600);
        loop {
            let notified = inner.notify.notified();
            let round = inner
                .block_store
                .last_own_block_ref()
                .map(|b| b.round())
                .unwrap_or_default();
            let closing_time = inner.epoch_closing_time.load(Ordering::Relaxed);
            let shutdown_duration = if closing_time != 0 {
                shutdown_grace_period.saturating_sub(
                    timestamp_utc().saturating_sub(Duration::from_millis(closing_time)),
                )
            } else {
                Duration::MAX
            };
            if Duration::is_zero(&shutdown_duration) {
                return None;
            }
            select! {
                _sleep = sleep(leader_timeout) => {
                    tracing::debug!("Timeout in round {round}");
                    // todo - more then one round timeout can happen, need to fix this
                    inner.syncer.force_new_block(round).await;

                }
                _notified = notified => {
                    // restart loop
                }
                _epoch_shutdown = sleep(shutdown_duration) => {
                    tracing::info!("Shutting down sync after epoch close");
                    epoch_close_signal.close();
                }
                _stopped = inner.stopped() => {
                    return None;
                }
            }
        }
    }

    async fn commit_timeout_task(
        inner: Arc<NetworkSyncerInner<H, C>>,
        shutdown_grace_period: Duration,
    ) -> Option<()> {
        let commit_timeout = Duration::from_millis(10);
        loop {
            let notified = inner.notify.notified();
            let round = inner
                .block_store
                .last_own_block_ref()
                .map(|b| b.round())
                .unwrap_or_default();
            let closing_time = inner.epoch_closing_time.load(Ordering::Relaxed);
            let shutdown_duration = if closing_time != 0 {
                shutdown_grace_period.saturating_sub(
                    timestamp_utc().saturating_sub(Duration::from_millis(closing_time)),
                )
            } else {
                Duration::MAX
            };
            if Duration::is_zero(&shutdown_duration) {
                return None;
            }
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
                    // Keep read lock for everything else
                    inner.syncer.cleanup().await;
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
    // Returns None either if channel is closed or NetworkSyncerInner receives stop signal
    async fn recv_or_stopped<T>(&self, channel: &mut mpsc::Receiver<T>) -> Option<T> {
        select! {
            stopped = self.stop.send(()) => {
                assert!(stopped.is_err());
                None
            }
            closed = self.epoch_close_signal.send(()) => {
                assert!(closed.is_err());
                None
            }
            data = channel.recv() => {
                data
            }
        }
    }

    async fn stopped(&self) {
        select! {
            stopped = self.stop.send(()) => {
                assert!(stopped.is_err());
            }
            closed = self.epoch_close_signal.send(()) => {
                assert!(closed.is_err());
            }
        }
    }
}

impl SyncerSignals for Arc<Notify> {
    fn new_block_ready(&mut self) {
        self.notify_waiters();
    }
}

pub struct AsyncRocksDBSyncer {
    stop: mpsc::Sender<()>,
    epoch_signal: mpsc::Sender<()>,
    rocks_store: Arc<RocksStore>,
    runtime: tokio::runtime::Handle,
}

pub struct AsyncRocksDBFlusher {
    stop: mpsc::Sender<()>,
    rocks_store: Arc<RocksStore>,
    runtime: tokio::runtime::Handle,
}

impl AsyncRocksDBSyncer {
    pub fn start(
        stop: mpsc::Sender<()>,
        epoch_signal: mpsc::Sender<()>,
        rocks_store: Arc<RocksStore>,
    ) -> oneshot::Receiver<()> {
        let (_sender, receiver) = oneshot::channel();
        let this = Self {
            stop,
            epoch_signal,
            rocks_store,
            runtime: tokio::runtime::Handle::current(),
        };
        std::thread::Builder::new()
            .name("rocksdb-syncer".to_string())
            .spawn(move || this.run())
            .expect("Failed to spawn rocksdb-syncer");
        receiver
    }

    pub fn run(mut self) {
        let runtime = self.runtime.clone();
        loop {
            if runtime.block_on(self.wait_next()) {
                return;
            }
            self.rocks_store
                .sync()
                .expect("Failed to sync rocksdb store");
        }
    }

    async fn wait_next(&mut self) -> bool {
        const SYNC_INTERVAL_MS: u64 = 1000;
        select! {
            _wait = sleep(Duration::from_millis(SYNC_INTERVAL_MS)) => {
                false
            }
            _signal = self.stop.send(()) => {
                true
            }
            _ = self.epoch_signal.send(()) => {
                false
            }
        }
    }
}

impl AsyncRocksDBFlusher {
    pub fn start(stop: mpsc::Sender<()>, rocks_store: Arc<RocksStore>) -> oneshot::Receiver<()> {
        let (_sender, receiver) = oneshot::channel();
        let this = Self {
            stop,
            rocks_store,
            runtime: tokio::runtime::Handle::current(),
        };
        std::thread::Builder::new()
            .name("rocksdb-flusher".to_string())
            .spawn(move || this.run())
            .expect("Failed to spawn rocksdb-flusher");
        receiver
    }

    pub fn run(mut self) {
        let runtime = self.runtime.clone();
        loop {
            if runtime.block_on(self.wait_next()) {
                return;
            }
            self.rocks_store
                .flush_pending_batches()
                .expect("Failed to flush rocksdb store");
        }
    }

    async fn wait_next(&mut self) -> bool {
        const FLUSH_INTERVAL_MS: u64 = 20;
        select! {
            _wait = sleep(Duration::from_millis(FLUSH_INTERVAL_MS)) => {
                false
            }
            _signal = self.stop.send(()) => {
                true
            }
        }
    }
}
