// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, thread};

use ahash::AHashSet;
use tokio::sync::{mpsc, oneshot};

use crate::{
    block_handler::BlockHandler,
    bls_certificate_aggregator::CertificateEvent,
    dag_state::DataSource,
    data::Data,
    metrics::{Metrics, UtilizationTimerExt},
    syncer::{CommitObserver, Syncer, SyncerSignals},
    types::{
        AuthorityIndex, BlockReference, ProvableShard, ReconstructedTransactionData, RoundNumber,
        VerifiedBlock,
    },
};

pub struct CoreThreadDispatcher<H: BlockHandler, S: SyncerSignals, C: CommitObserver> {
    sender: mpsc::Sender<CoreThreadCommand>,
    join_handle: thread::JoinHandle<Syncer<H, S, C>>,
    metrics: Arc<Metrics>,
}

pub struct CoreThread<H: BlockHandler, S: SyncerSignals, C: CommitObserver> {
    syncer: Syncer<H, S, C>,
    receiver: mpsc::Receiver<CoreThreadCommand>,
}

enum CoreThreadCommand {
    AddBlocks(
        Vec<(Data<VerifiedBlock>, Option<ProvableShard>)>,
        DataSource,
        oneshot::Sender<(
            Vec<BlockReference>,
            AHashSet<BlockReference>,
            Vec<BlockReference>,
        )>,
    ),
    AddHeaders(
        Vec<Data<VerifiedBlock>>,
        DataSource,
        oneshot::Sender<(AHashSet<BlockReference>, Vec<BlockReference>)>,
    ),
    AddTransactionData(
        Vec<ReconstructedTransactionData>,
        DataSource,
        oneshot::Sender<()>,
    ),
    ForceNewBlock(RoundNumber, oneshot::Sender<()>),
    /// Attempt block creation with relaxed readiness checks (StarfishSpeed soft
    /// timeout).
    TryNewBlockRelaxed(RoundNumber, oneshot::Sender<()>),
    ForceCommit(oneshot::Sender<()>),
    Cleanup(oneshot::Sender<()>),
    /// Indicate that a connection to an authority was established.
    ConnectionEstablished(AuthorityIndex, oneshot::Sender<()>),
    /// Indicate that a connection to an authority was dropped.
    ConnectionDropped(AuthorityIndex, oneshot::Sender<()>),
    /// A peer has subscribed to us (sent us SubscribeBroadcastRequest).
    PeerSubscribed(AuthorityIndex, oneshot::Sender<()>),
    /// Apply BLS certificate events from the BLS verification service.
    ApplyCertificateEvents(Vec<CertificateEvent>, oneshot::Sender<()>),
    /// Apply Sailfish RBC-certified vertices on the core thread.
    ApplySailfishCertificates(Vec<BlockReference>, oneshot::Sender<()>),
}

impl<H: BlockHandler + 'static, S: SyncerSignals + 'static, C: CommitObserver + 'static>
    CoreThreadDispatcher<H, S, C>
{
    pub fn start(syncer: Syncer<H, S, C>) -> Self {
        let (sender, receiver) = mpsc::channel(10_000);
        let metrics = syncer.core().metrics.clone();
        let core_thread = CoreThread { syncer, receiver };
        let join_handle = thread::Builder::new()
            .name("core_thread".to_string())
            .spawn(move || core_thread.run())
            .unwrap();
        Self {
            sender,
            join_handle,
            metrics,
        }
    }

    pub fn stop(self) -> Syncer<H, S, C> {
        drop(self.sender);
        self.join_handle.join().unwrap()
    }

    pub async fn add_blocks(
        &self,
        blocks: Vec<(Data<VerifiedBlock>, Option<ProvableShard>)>,
        source: DataSource,
    ) -> (
        Vec<BlockReference>,
        AHashSet<BlockReference>,
        Vec<BlockReference>,
    ) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::AddBlocks(blocks, source, sender))
            .await;
        receiver.await.expect("core thread is not expected to stop")
    }

    pub async fn add_headers(
        &self,
        headers: Vec<Data<VerifiedBlock>>,
        source: DataSource,
    ) -> (AHashSet<BlockReference>, Vec<BlockReference>) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::AddHeaders(headers, source, sender))
            .await;
        receiver.await.expect("core thread is not expected to stop")
    }

    pub async fn add_transaction_data(
        &self,
        items: Vec<ReconstructedTransactionData>,
        source: DataSource,
    ) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::AddTransactionData(items, source, sender))
            .await;
        receiver.await.expect("core thread is not expected to stop")
    }

    pub async fn force_commit(&self) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::ForceCommit(sender)).await;
        receiver.await.expect("core thread is not expected to stop")
    }

    pub async fn force_new_block(&self, round: RoundNumber) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::ForceNewBlock(round, sender))
            .await;
        receiver.await.expect("core thread is not expected to stop");
    }

    pub async fn try_new_block_relaxed(&self, round: RoundNumber) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::TryNewBlockRelaxed(round, sender))
            .await;
        receiver.await.expect("core thread is not expected to stop");
    }

    pub async fn cleanup(&self) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::Cleanup(sender)).await;
        receiver.await.expect("core thread is not expected to stop");
    }

    /// Update the syncer with the connection status of an authority. This
    /// function must be called whenever a connection to an authority is
    /// established or dropped.
    pub async fn authority_connection(&self, authority: AuthorityIndex, connected: bool) {
        let (sender, receiver) = oneshot::channel();
        let status = if connected {
            CoreThreadCommand::ConnectionEstablished(authority, sender)
        } else {
            CoreThreadCommand::ConnectionDropped(authority, sender)
        };
        self.send(status).await;
        receiver.await.expect("core thread is not expected to stop")
    }

    /// Apply Sailfish RBC-certified vertices on the core thread.
    pub async fn apply_sailfish_certificates(&self, certified_refs: Vec<BlockReference>) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::ApplySailfishCertificates(
            certified_refs,
            sender,
        ))
            .await;
        receiver.await.expect("core thread is not expected to stop");
    }

    /// Apply BLS certificate events from the BLS verification service.
    pub async fn apply_certificate_events(&self, events: Vec<CertificateEvent>) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::ApplyCertificateEvents(events, sender))
            .await;
        receiver.await.expect("core thread is not expected to stop");
    }

    /// Record that a peer has sent us a SubscribeBroadcastRequest.
    pub async fn peer_subscribed(&self, authority: AuthorityIndex) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::PeerSubscribed(authority, sender))
            .await;
        receiver.await.expect("core thread is not expected to stop");
    }

    async fn send(&self, command: CoreThreadCommand) {
        self.metrics.core_lock_enqueued.inc();
        self.metrics.core_queue_length.inc();
        if self.sender.send(command).await.is_err() {
            panic!("core thread is not expected to stop");
        }
    }
}

impl<H: BlockHandler, S: SyncerSignals, C: CommitObserver> CoreThread<H, S, C> {
    pub fn run(mut self) -> Syncer<H, S, C> {
        tracing::info!("Started core thread with tid {}", gettid::gettid());
        let metrics = self.syncer.core().metrics.clone();
        while let Some(command) = self.receiver.blocking_recv() {
            let _timer = metrics.core_lock_util.utilization_timer();
            metrics.core_lock_dequeued.inc();
            metrics.core_queue_length.dec();
            match command {
                CoreThreadCommand::AddBlocks(blocks, source, sender) => {
                    metrics
                        .core_thread_tasks_total
                        .with_label_values(&["add_blocks"])
                        .inc();
                    let (
                        pending_blocks_with_transactions,
                        missing_references,
                        used_additional_references,
                    ) = self.syncer.add_blocks(blocks, source);
                    sender
                        .send((
                            pending_blocks_with_transactions,
                            missing_references,
                            used_additional_references,
                        ))
                        .ok();
                }
                CoreThreadCommand::AddHeaders(headers, source, sender) => {
                    metrics
                        .core_thread_tasks_total
                        .with_label_values(&["add_headers"])
                        .inc();
                    let result = self.syncer.add_headers(headers, source);
                    sender.send(result).ok();
                }
                CoreThreadCommand::AddTransactionData(items, source, sender) => {
                    metrics
                        .core_thread_tasks_total
                        .with_label_values(&["add_transaction_data"])
                        .inc();
                    self.syncer.add_transaction_data(items, source);
                    sender.send(()).ok();
                }
                CoreThreadCommand::ForceNewBlock(round, sender) => {
                    metrics
                        .core_thread_tasks_total
                        .with_label_values(&["force_new_block"])
                        .inc();
                    self.syncer.force_new_block(round);
                    sender.send(()).ok();
                }
                CoreThreadCommand::TryNewBlockRelaxed(round, sender) => {
                    metrics
                        .core_thread_tasks_total
                        .with_label_values(&["try_new_block_relaxed"])
                        .inc();
                    self.syncer.try_new_block_relaxed(round);
                    sender.send(()).ok();
                }
                CoreThreadCommand::ForceCommit(sender) => {
                    metrics
                        .core_thread_tasks_total
                        .with_label_values(&["force_commit"])
                        .inc();
                    self.syncer.try_new_commit();
                    sender.send(()).ok();
                }
                CoreThreadCommand::Cleanup(sender) => {
                    metrics
                        .core_thread_tasks_total
                        .with_label_values(&["cleanup"])
                        .inc();
                    self.syncer.cleanup();
                    sender.send(()).ok();
                }
                CoreThreadCommand::ConnectionEstablished(authority, sender) => {
                    metrics
                        .core_thread_tasks_total
                        .with_label_values(&["connection_established"])
                        .inc();
                    self.syncer.connected_authorities.insert(authority);
                    self.syncer
                        .metrics
                        .subscribed_to_peers
                        .set(self.syncer.connected_authorities.len() as i64);
                    sender.send(()).ok();
                }
                CoreThreadCommand::ConnectionDropped(authority, sender) => {
                    metrics
                        .core_thread_tasks_total
                        .with_label_values(&["connection_dropped"])
                        .inc();
                    self.syncer.connected_authorities.remove(&authority);
                    self.syncer.subscribed_by_authorities.remove(&authority);
                    self.syncer.recompute_subscriber_stake();
                    self.syncer
                        .metrics
                        .subscribed_to_peers
                        .set(self.syncer.connected_authorities.len() as i64);
                    self.syncer
                        .metrics
                        .subscribed_by_peers
                        .set(self.syncer.subscribed_by_authorities.len() as i64);
                    sender.send(()).ok();
                }
                CoreThreadCommand::PeerSubscribed(authority, sender) => {
                    metrics
                        .core_thread_tasks_total
                        .with_label_values(&["peer_subscribed"])
                        .inc();
                    self.syncer.subscribed_by_authorities.insert(authority);
                    self.syncer.recompute_subscriber_stake();
                    self.syncer
                        .metrics
                        .subscribed_by_peers
                        .set(self.syncer.subscribed_by_authorities.len() as i64);
                    sender.send(()).ok();
                }
                CoreThreadCommand::ApplyCertificateEvents(events, sender) => {
                    metrics
                        .core_thread_tasks_total
                        .with_label_values(&["apply_certificate_events"])
                        .inc();
                    self.syncer.apply_certificate_events(events);
                    sender.send(()).ok();
                }
                CoreThreadCommand::ApplySailfishCertificates(certified_refs, sender) => {
                    metrics
                        .core_thread_tasks_total
                        .with_label_values(&["apply_sailfish_certificates"])
                        .inc();
                    self.syncer.apply_sailfish_certificates(certified_refs);
                    sender.send(()).ok();
                }
            }
        }
        self.syncer
    }
}
