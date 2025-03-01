// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use futures::future::join_all;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    select,
    sync::{mpsc, oneshot, Notify},
};

use crate::block_store::ConsensusProtocol;
use crate::consensus::universal_committer::UniversalCommitter;
use crate::data::Data;
use crate::decoder::CachedStatementBlockDecoder;
use crate::metrics::UtilizationTimerVecExt;
use crate::rocks_store::RocksStore;
use crate::runtime::sleep;
use crate::synchronizer::DataRequestor;
use crate::types::{BlockReference, VerifiedStatementBlock};
use crate::{
    block_handler::BlockHandler,
    block_store::BlockStore,
    committee::Committee,
    config::NodePublicConfig,
    core::Core,
    core_thread::CoreThreadDispatcher,
    metrics::Metrics,
    network::{Connection, Network, NetworkMessage},
    runtime::{timestamp_utc, Handle, JoinError, JoinHandle},
    syncer::{CommitObserver, Syncer, SyncerSignals},
    synchronizer::{BlockDisseminator, BlockFetcher, SynchronizerParameters},
    types::{format_authority_index, AuthorityIndex},
};

/// The maximum number of blocks that can be requested in a single message.
pub const MAXIMUM_BLOCK_REQUEST: usize = 10;

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
        public_config: &NodePublicConfig,
    ) -> Self {
        let authority_index = core.authority();
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
        let block_fetcher = Arc::new(BlockFetcher::start(
            authority_index,
            inner.clone(),
            metrics.clone(),
            public_config.parameters.enable_synchronizer,
        ));
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
    ) -> Option<()> {
        let consensus_protocol = inner.block_store.consensus_protocol;
        let committee_size = inner.block_store.committee_size;
        let synchronizer_parameters =
            SynchronizerParameters::new(committee_size, consensus_protocol);
        let last_seen = inner
            .block_store
            .last_seen_by_authority(connection.peer_id as AuthorityIndex);
        connection
            .sender
            .send(NetworkMessage::SubscribeBroadcastRequest(last_seen))
            .await
            .ok()?;

        let mut disseminator = BlockDisseminator::new(
            connection.peer_id as AuthorityIndex,
            connection.sender.clone(),
            universal_committer,
            inner.clone(),
            synchronizer_parameters.clone(),
            metrics.clone(),
        );
        let mut data_requestor = DataRequestor::new(
            connection.peer_id as AuthorityIndex,
            connection.sender.clone(),
            inner.clone(),
            synchronizer_parameters.clone(),
        );
        if consensus_protocol == ConsensusProtocol::StarfishPull {
            data_requestor.start().await;
        }

        let mut encoder = ReedSolomonEncoder::new(2, 4, 64).expect("Encoder should be created");
        let mut decoder = ReedSolomonDecoder::new(2, 4, 64).expect("Decoder should be created");

        let peer_id = connection.peer_id as AuthorityIndex;
        inner.syncer.authority_connection(peer_id, true).await;

        let peer = format_authority_index(peer_id);
        let own_id = inner.block_store.get_own_authority_index();

        tracing::debug!(
            "Connection from {:?} to {:?} is established",
            own_id,
            peer_id
        );
        while let Some(message) = inner.recv_or_stopped(&mut connection.receiver).await {
            match message {
                NetworkMessage::SubscribeBroadcastRequest(round) => {
                    if inner.block_store.byzantine_strategy.is_some() {
                        let round = 0;
                        disseminator.disseminate_own_blocks(round).await;
                    } else {
                        // For Mysticeti and Starfish disseminate
                        // own blocks only. For Starfish push and Cordial Miners, push all blocks
                        match consensus_protocol {
                            ConsensusProtocol::Mysticeti | ConsensusProtocol::StarfishPull => {
                                disseminator.disseminate_own_blocks(round).await;
                            }
                            ConsensusProtocol::Starfish | ConsensusProtocol::CordialMiners => {
                                disseminator.disseminate_all_blocks_push().await;
                            }
                        }
                    }
                }
                NetworkMessage::Batch(blocks) => {
                    let timer = metrics
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
                    // First process blocks without statements which could be in the causal history
                    if consensus_protocol == ConsensusProtocol::StarfishPull
                        || consensus_protocol == ConsensusProtocol::Starfish
                    {
                        let mut verified_data_blocks = Vec::new();
                        for data_block in blocks_without_statements {
                            let mut block: VerifiedStatementBlock = (*data_block).clone();
                            tracing::debug!("Received {} from {}", block, peer);
                            let contains_new_shard_or_header =
                                inner.block_store.contains_new_shard_or_header(&block);
                            if !contains_new_shard_or_header {
                                continue;
                            }
                            if let Err(e) = block.verify(
                                &inner.committee,
                                own_id as usize,
                                peer_id as usize,
                                &mut encoder,
                                consensus_protocol,
                            ) {
                                tracing::warn!(
                                    "Rejected incorrect block {} from {}: {:?}",
                                    block.reference(),
                                    peer,
                                    e
                                );
                                // todo: Terminate connection upon receiving incorrect block.
                                break;
                            }
                            let (ready_to_reconstruct, cached_block) =
                                inner.block_store.ready_to_reconstruct(&block);
                            if ready_to_reconstruct {
                                let mut cached_block = cached_block.expect("Should be Some");
                                cached_block.copy_shard(&block);
                                let reconstructed_block = decoder.decode_shards(
                                    &inner.committee,
                                    &mut encoder,
                                    cached_block,
                                    own_id,
                                );
                                if reconstructed_block.is_some() {
                                    block = reconstructed_block.expect("Should be Some");
                                    tracing::debug!("Reconstruction of block {:?} within connection task is successful", block);
                                } else {
                                    tracing::debug!("Incorrect reconstruction of block {:?} within connection task", block);
                                }
                            }
                            let storage_block = block;
                            let transmission_block =
                                storage_block.from_storage_to_transmission(own_id);
                            let contains_new_shard_or_header = inner
                                .block_store
                                .contains_new_shard_or_header(&storage_block);
                            if !contains_new_shard_or_header {
                                continue;
                            }
                            let data_storage_block = Data::new(storage_block);
                            let data_transmission_block = Data::new(transmission_block);
                            verified_data_blocks
                                .push((data_storage_block, data_transmission_block));
                        }

                        tracing::debug!("To be processed after verification from {:?}, {} blocks without statements {:?}", peer, verified_data_blocks.len(), verified_data_blocks);
                        if !verified_data_blocks.is_empty() {
                            inner.syncer.add_blocks(verified_data_blocks).await;
                        }
                    }

                    // Second process blocks with statements
                    let mut verified_data_blocks = Vec::new();
                    for data_block in blocks_with_statements {
                        let mut block: VerifiedStatementBlock = (*data_block).clone();
                        tracing::debug!("Received {} from {}", block, peer);
                        let contains_new_shard_or_header =
                            inner.block_store.contains_new_shard_or_header(&block);
                        if !contains_new_shard_or_header {
                            continue;
                        }
                        if let Err(e) = block.verify(
                            &inner.committee,
                            own_id as usize,
                            peer_id as usize,
                            &mut encoder,
                            consensus_protocol,
                        ) {
                            tracing::warn!(
                                "Rejected incorrect block {} from {}: {:?}",
                                block.reference(),
                                peer,
                                e
                            );
                            // todo: Terminate connection upon receiving incorrect block.
                            break;
                        }
                        let storage_block = block;
                        let transmission_block = match consensus_protocol {
                            ConsensusProtocol::Mysticeti | ConsensusProtocol::CordialMiners => {
                                storage_block.clone()
                            }
                            ConsensusProtocol::Starfish | ConsensusProtocol::StarfishPull => {
                                storage_block.from_storage_to_transmission(own_id)
                            }
                        };
                        let contains_new_shard_or_header = inner
                            .block_store
                            .contains_new_shard_or_header(&storage_block);
                        if !contains_new_shard_or_header {
                            continue;
                        }
                        let data_storage_block = Data::new(storage_block);
                        let data_transmission_block = Data::new(transmission_block);
                        verified_data_blocks.push((data_storage_block, data_transmission_block));
                    }

                    tracing::debug!("To be processed after verification from {:?}, {} blocks with statements {:?}", peer, verified_data_blocks.len(), verified_data_blocks);
                    if !verified_data_blocks.is_empty() {
                        let (pending_block_references, missing_parents) =
                            inner.syncer.add_blocks(verified_data_blocks).await;
                        match consensus_protocol {
                            ConsensusProtocol::StarfishPull => {
                                let mut max_round_pending_block_reference: Option<BlockReference> = None;
                                for block_reference in pending_block_references {
                                    if max_round_pending_block_reference.is_none() ||
                                        block_reference.round() > max_round_pending_block_reference.unwrap().round() {
                                        max_round_pending_block_reference = Some(block_reference);
                                    }
                                }
                                if max_round_pending_block_reference.is_some() {
                                    tracing::debug!(
                                        "Make request missing history of block {:?} from peer {:?}",
                                        max_round_pending_block_reference.unwrap(),
                                        peer
                                    );
                                    Self::request_missing_history_block(
                                        max_round_pending_block_reference.unwrap(),
                                        &connection.sender,
                                    );
                                }
                            }
                            ConsensusProtocol::Mysticeti => {
                                if !missing_parents.is_empty() {
                                    let missing_parents =
                                        missing_parents.iter().copied().collect::<Vec<_>>();
                                    tracing::debug!("Make request missing parents of blocks {:?} from peer {:?}", missing_parents, peer);
                                    Self::request_parents_blocks(
                                        missing_parents,
                                        &connection.sender,
                                    );
                                }
                            }
                            ConsensusProtocol::Starfish | ConsensusProtocol::CordialMiners => {}
                        }
                    }

                    drop(timer);
                }

                NetworkMessage::MissingHistoryRequest(block_reference) => {
                    if consensus_protocol == ConsensusProtocol::StarfishPull {
                        tracing::debug!(
                            "Received request missing history for block {:?} from peer {:?}",
                            block_reference,
                            peer
                        );
                        if inner.block_store.byzantine_strategy.is_none() {
                            disseminator
                                .push_block_history_with_shards(block_reference)
                                .await;
                        }
                    }
                }
                NetworkMessage::MissingParentsRequest(block_references) => {
                    if consensus_protocol == ConsensusProtocol::Mysticeti {
                        tracing::debug!(
                            "Received request missing data {:?} from peer {:?}",
                            block_references,
                            peer
                        );
                        if inner.block_store.byzantine_strategy.is_none() {
                            let authority = connection.peer_id as AuthorityIndex;
                            if disseminator
                                .send_storage_blocks(authority, block_references)
                                .await
                                .is_none()
                            {
                                break;
                            }
                        }
                    }
                }
                NetworkMessage::MissingTxDataRequest(block_references) => {
                    if consensus_protocol == ConsensusProtocol::StarfishPull {
                        tracing::debug!(
                            "Received request missing data {:?} from peer {:?}",
                            block_references,
                            peer
                        );
                        if inner.block_store.byzantine_strategy.is_none() {
                            let authority = connection.peer_id as AuthorityIndex;
                            if disseminator
                                .send_transmission_blocks(authority, block_references)
                                .await
                                .is_none()
                            {
                                break;
                            }
                        }
                    }
                }
            }
        }
        tracing::debug!("Connection between {own_id} and {peer_id} is dropped");
        inner.syncer.authority_connection(peer_id, false).await;
        disseminator.shutdown().await;
        data_requestor.shutdown().await;
        block_fetcher.remove_authority(peer_id).await;
        None
    }

    fn request_missing_history_block(block: BlockReference, sender: &mpsc::Sender<NetworkMessage>) {
        if let Ok(permit) = sender.try_reserve() {
            permit.send(NetworkMessage::MissingHistoryRequest(block));
        }
    }

    fn request_parents_blocks(blocks: Vec<BlockReference>, sender: &mpsc::Sender<NetworkMessage>) {
        if let Ok(permit) = sender.try_reserve() {
            permit.send(NetworkMessage::MissingParentsRequest(blocks));
        }
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
#[cfg(test)]
mod tests {
    use crate::runtime::sleep;
    use crate::test_util::{check_commits, network_syncers};
    use std::time::Duration;

    #[tokio::test]
    #[ignore]
    async fn test_network_sync() {
        let network_syncers = network_syncers(4).await;
        println!("Started");
        sleep(Duration::from_secs(3)).await;
        println!("Done");
        let mut syncers = vec![];
        for network_syncer in network_syncers {
            let syncer = network_syncer.shutdown().await;
            syncers.push(syncer);
        }

        check_commits(&syncers);
    }
}

#[cfg(test)]
#[cfg(feature = "simulator")]
mod sim_tests {
    use std::{
        sync::{atomic::Ordering, Arc},
        time::Duration,
    };

    use tokio::sync::Notify;

    use super::NetworkSyncer;
    use crate::runtime::sleep;
    use crate::test_util::byzantine_simulated_network_syncers_with_epoch_duration;
    use crate::{
        block_handler::{RealCommitHandler, TestBlockHandler},
        config,
        future_simulator::SimulatedExecutorState,
        runtime,
        simulator_tracing::setup_simulator_tracing,
        syncer::Syncer,
        test_util::{
            check_commits, honest_simulated_network_syncers_with_epoch_duration, print_stats,
            rng_at_seed, simulated_network_syncers,
        },
    };

    async fn wait_for_epoch_to_close(
        network_syncers: Vec<NetworkSyncer<TestBlockHandler, RealCommitHandler>>,
    ) -> Vec<Syncer<TestBlockHandler, Arc<Notify>, RealCommitHandler>> {
        let mut any_closed = false;
        while !any_closed {
            for net_sync in network_syncers.iter() {
                if net_sync.inner.epoch_closing_time.load(Ordering::Relaxed) != 0 {
                    any_closed = true;
                }
            }
            sleep(Duration::from_secs(10)).await;
        }
        sleep(config::node_defaults::default_shutdown_grace_period()).await;
        let mut syncers = vec![];
        for net_sync in network_syncers {
            let syncer = net_sync.shutdown().await;
            syncers.push(syncer);
        }
        syncers
    }

    #[test]
    fn test_byzantine_committee_epoch() {
        let n = 10;
        let number_byzantine = 1;
        let byzantine_strategy = "delayed".to_string(); // timeout, equivocate, delayed
        SimulatedExecutorState::run(
            rng_at_seed(0),
            test_byzantine_committee_latency_measure(n, number_byzantine, byzantine_strategy),
        );
    }

    async fn test_byzantine_committee_latency_measure(
        n: usize,
        number_byzantine: usize,
        byzantine_strategy: String,
    ) {
        let rounds_in_epoch = 50;
        let (simulated_network, network_syncers, mut reporters) =
            byzantine_simulated_network_syncers_with_epoch_duration(
                n,
                number_byzantine,
                byzantine_strategy,
                rounds_in_epoch,
            );
        simulated_network.connect_all().await;
        let syncers = wait_for_epoch_to_close(network_syncers).await;
        print_stats(&syncers, &mut reporters);
    }
    #[test]
    fn test_honest_committee_exact_commits_in_epoch() {
        SimulatedExecutorState::run(
            rng_at_seed(0),
            test_honest_committee_exact_commits_in_epoch_async(),
        );
    }

    async fn test_honest_committee_exact_commits_in_epoch_async() {
        let n = 4;
        let rounds_in_epoch = 100;
        let (simulated_network, network_syncers, mut reporters) =
            honest_simulated_network_syncers_with_epoch_duration(n, rounds_in_epoch);
        simulated_network.connect_all().await;
        let syncers = wait_for_epoch_to_close(network_syncers).await;
        let canonical_commit_seq = syncers[0].commit_observer().committed_leaders().clone();
        for syncer in &syncers {
            let commit_seq = syncer.commit_observer().committed_leaders().clone();
            //assert_eq!(canonical_commit_seq, commit_seq);
        }
        print_stats(&syncers, &mut reporters);
    }

    #[test]
    fn test_network_sync_sim_all_up() {
        setup_simulator_tracing();
        SimulatedExecutorState::run(rng_at_seed(0), test_network_sync_sim_all_up_async());
    }

    async fn test_network_sync_sim_all_up_async() {
        let (simulated_network, network_syncers, mut reporters) = simulated_network_syncers(4);
        simulated_network.connect_all().await;
        sleep(Duration::from_secs(20)).await;
        let mut syncers = vec![];
        for network_syncer in network_syncers {
            let syncer = network_syncer.shutdown().await;
            syncers.push(syncer);
        }

        check_commits(&syncers);
        print_stats(&syncers, &mut reporters);
    }

    #[test]
    fn test_network_sync_sim_one_down() {
        setup_simulator_tracing();
        SimulatedExecutorState::run(rng_at_seed(0), test_network_sync_sim_one_down_async());
    }

    // All peers except for peer A are connected in this test
    // Peer A is disconnected from everything
    async fn test_network_sync_sim_one_down_async() {
        let (simulated_network, network_syncers, mut reporters) = simulated_network_syncers(4);
        simulated_network.connect_some(|a, _b| a != 0).await;
        println!("Started");
        sleep(Duration::from_secs(40)).await;
        println!("Done");
        let mut syncers = vec![];
        for network_syncer in network_syncers {
            let syncer = network_syncer.shutdown().await;
            syncers.push(syncer);
        }

        check_commits(&syncers);
        print_stats(&syncers, &mut reporters);
    }

    #[test]
    fn test_network_partition() {
        setup_simulator_tracing();
        SimulatedExecutorState::run(rng_at_seed(0), test_network_partition_async());
    }

    // All peers except for peer A are connected in this test. Peer A is disconnected from everyone
    // except for peer B. This test ensures that A eventually manages to commit by syncing with B.
    async fn test_network_partition_async() {
        let (simulated_network, network_syncers, mut reporters) = simulated_network_syncers(10);
        // Disconnect all A from all peers except for B.
        simulated_network
            .connect_some(|a, b| a != 0 || (a == 0 && b == 1))
            .await;

        println!("Started");
        sleep(Duration::from_secs(40)).await;
        println!("Done");
        let mut syncers = vec![];
        for network_syncer in network_syncers {
            let syncer = network_syncer.shutdown().await;
            syncers.push(syncer);
        }

        // Ensure no conflicts.
        check_commits(&syncers);
        print_stats(&syncers, &mut reporters);
    }
}
