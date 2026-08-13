// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, io, net::SocketAddr, ops::Range, sync::Arc, time::Duration};

use futures::{
    FutureExt,
    future::{Either, select, select_all},
};
use rand::{Rng, SeedableRng, prelude::ThreadRng, rngs::StdRng, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpSocket, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    runtime::Handle,
    sync::{mpsc, watch},
    time::Instant,
};

use crate::{
    config::{NodeParameters, NodePublicConfig},
    dag_state::DataSource,
    data::Data,
    metrics::{Metrics, print_network_address_table},
    runtime,
    runtime::JoinHandle,
    starfish_rbc::{RbcCanonicalHeader, RbcHeaderProposal, RbcPhase, RbcPhaseMessage},
    stat::HistogramSender,
    types::{
        AuthorityIndex, AuthoritySet, BlockReference, CertMessage, CertMessageKind, PartialSig,
        ProvableShard, RoundNumber, SailfishNoVoteMsg, SailfishTimeoutMsg, TransactionData,
        VerifiedBlock,
    },
};

const PING_INTERVAL: Duration = Duration::from_secs(3);
pub(crate) const RBC_DAG_PRIORITY_CHANNEL_CAPACITY: usize = 64;
pub(crate) const RBC_DAG_PROACTIVE_CHANNEL_CAPACITY: usize = 64;
const NETWORK_SCHEDULED_LANE_CAPACITY: usize = 64;
const NETWORK_SCHEDULED_LANE_BYTE_CAPACITY: usize = 256 * 1024 * 1024;

// Max buffer size controls the max amount of data (in bytes) to
// be sent/received when sending batches of blocks. Based on the
// committee size we control the max number of transactions in a
// block. We aim to send committee_size own blocks and
// committee_size * committee_size other blocks (encoded).
// 80*1024 transactions in blocks in one round = 40 MB pure txs data
// encoded shards could take up to 120 MB, resulting in 160 MB total
const MAX_BUFFER_SIZE: u32 = 170 * 1024 * 1024;

#[allow(unused)]
// AWS regions and their names
const REGIONS: [&str; 10] = [
    "us-east-1",      // USE1
    "us-west-1",      // USW1
    "ca-central-1",   // CAC1
    "eu-west-1",      // EUW1
    "eu-south-1",     // EUS2
    "eu-north-1",     // EUN1
    "sa-east-1",      // SAE1
    "ap-south-1",     // APS1
    "ap-southeast-1", // APSE2
    "ap-northeast-1", // APNE1
];

// RTT table for 10 AWS regions, in milliseconds.
const RTT_LATENCY_TABLE: [[u32; 10]; 10] = [
    [1, 14, 104, 112, 198, 65, 68, 110, 201, 146],
    [14, 1, 106, 122, 196, 78, 67, 103, 189, 142],
    [104, 106, 1, 215, 281, 163, 29, 50, 143, 238],
    [112, 122, 215, 1, 309, 175, 176, 220, 299, 254],
    [198, 196, 281, 309, 1, 137, 254, 268, 150, 101],
    [65, 78, 163, 175, 137, 1, 127, 172, 226, 108],
    [68, 67, 29, 176, 254, 127, 1, 38, 125, 199],
    [110, 103, 50, 220, 268, 172, 38, 1, 148, 245],
    [201, 189, 143, 299, 150, 226, 125, 148, 1, 140],
    [146, 142, 238, 254, 101, 108, 199, 245, 140, 1],
];

/// A shard shipped independently of its block header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardPayload {
    pub block_reference: BlockReference,
    pub shard: ProvableShard,
}

/// Non-authoritative Starfish-RBC-DAG carrier used by the persisted shadow
/// runtime. Both byte strings use the versioned canonical codecs from
/// `starfish_rbc_dag`; the network envelope deliberately adds no second
/// identity or authentication scheme. The optional application payload is an
/// untrusted availability sidecar: receivers must verify it against the
/// transaction commitment in the carrier-authenticated application header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbcDagShadowCarrier {
    pub canonical_carrier: Vec<u8>,
    pub authentication_sidecar: Vec<u8>,
    pub application_payload: Option<Arc<TransactionData>>,
}

impl PartialEq for RbcDagShadowCarrier {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_carrier == other.canonical_carrier
            && self.authentication_sidecar == other.authentication_sidecar
            && match (&self.application_payload, &other.application_payload) {
                (Some(left), Some(right)) => left.transactions() == right.transactions(),
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            }
    }
}

impl Eq for RbcDagShadowCarrier {}

/// Content-only response for a phase-evidenced shadow carrier. Recovery can
/// satisfy READY/delivery, but it cannot grant optimistic admission or ECHO.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RbcDagShadowCarrierResponse {
    pub reference: BlockReference,
    pub canonical_carrier: Vec<u8>,
}

/// Canonical carrier content plus one exact authentication-sidecar variant
/// retained by a phase-evidence holder. The requester recomputes `reference`
/// and verifies only its receiver-specific entry. A valid entry grants the
/// same authority as ordinary relayed ingress; an invalid entry falls back to
/// content-only recovery without blaming the author or holder.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RbcDagShadowCarrierEnvelopeResponse {
    pub reference: BlockReference,
    pub canonical_carrier: Vec<u8>,
    pub authentication_sidecar: Vec<u8>,
}

/// Request one exact carrier-clock slot from a peer. Keeping synchronization
/// slot-addressed prevents an untrusted peer from choosing an unbounded range
/// of history to return.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct RbcDagShadowCarrierSyncRequest {
    pub author: AuthorityIndex,
    pub round: RoundNumber,
}

/// Full response for one exact carrier-clock slot. The receiver validates that
/// the canonical carrier has the requested author and round, and authenticates
/// the sidecar before admitting it.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RbcDagShadowCarrierSyncResponse {
    pub author: AuthorityIndex,
    pub round: RoundNumber,
    pub canonical_carrier: Vec<u8>,
    pub authentication_sidecar: Vec<u8>,
}

/// Full transaction payload for one application header already authorized by
/// an authenticated or phase-evidenced embedded carrier. The payload itself
/// grants no authority and must be checked against the header commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbcDagApplicationPayloadResponse {
    pub application: BlockReference,
    pub transaction_data: Arc<TransactionData>,
}

/// A structured batch of block data, ordered by decreasing information density:
/// full blocks first, then header-only blocks, then standalone shards.
///
/// The `useful_*_authors` bitmasks tell the receiving peer which authorities'
/// content the sender would find useful in return on future transmissions.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockBatch {
    /// Provenance of this batch — how the sender produced it.
    pub source: DataSource,
    /// Full blocks (header + transactions + optional shard).
    pub full_blocks: Vec<Data<VerifiedBlock>>,
    /// Header-only blocks (no payload) — causal history the peer may not have.
    pub headers: Vec<Data<VerifiedBlock>>,
    /// Verified shards for blocks the peer already has the header for.
    pub shards: Vec<ShardPayload>,
    /// Bitmask: which authorities' headers would be useful from the receiving
    /// peer.
    pub useful_headers_authors: AuthoritySet,
    /// Bitmask: which authorities' shards would be useful from the receiving
    /// peer.
    pub useful_shards_authors: AuthoritySet,
}

impl BlockBatch {
    /// Wrap a flat list of blocks as a batch with only the `full_blocks` field
    /// populated. Used for backward-compatible call sites that don't yet
    /// distinguish headers/shards.
    pub fn full_only(source: DataSource, blocks: Vec<Data<VerifiedBlock>>) -> Self {
        Self {
            source,
            full_blocks: blocks,
            headers: Vec::new(),
            shards: Vec::new(),
            useful_headers_authors: AuthoritySet::default(),
            useful_shards_authors: AuthoritySet::default(),
        }
    }

    /// Wrap a list of shard payloads as a batch with only the `shards` field
    /// populated.
    pub fn shards_only(source: DataSource, shards: Vec<ShardPayload>) -> Self {
        Self {
            source,
            full_blocks: Vec::new(),
            headers: Vec::new(),
            shards,
            useful_headers_authors: AuthoritySet::default(),
            useful_shards_authors: AuthoritySet::default(),
        }
    }

    /// Total number of items across all sections.
    pub fn len(&self) -> usize {
        self.full_blocks.len() + self.headers.len() + self.shards.len()
    }

    /// Whether the batch carries no data at all.
    pub fn is_empty(&self) -> bool {
        self.full_blocks.is_empty() && self.headers.is_empty() && self.shards.is_empty()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum NetworkMessage {
    SubscribeBroadcastRequest(RoundNumber), // subscribe from round number excluding
    /// A structured batch of block data.
    Batch(Box<BlockBatch>),
    /// Request specific block (blocks with full data are sent)
    MissingParentsRequest(Vec<BlockReference>),
    /// Request a tx data for a few specific block references (only shards are
    /// sent).
    MissingTxDataRequest(Vec<BlockReference>),
    /// Standalone partial BLS signature (DAC, round pre-sign, or leader
    /// pre-sign).
    PartialSig(PartialSig),
    /// SailfishPlusPlus: Optimistic RBC message with phase metadata.
    CertMessage(CertMessage),
    /// SailfishPlusPlus: Batched optimistic RBC messages.
    CertBatch(Vec<CertMessage>),
    /// SailfishPlusPlus: Signed timeout message for round advancement.
    SailfishTimeout(SailfishTimeoutMsg),
    /// SailfishPlusPlus: Signed no-vote message for leader skip proof.
    SailfishNoVote(SailfishNoVoteMsg),
    /// Bluestreak: request voting blocks for an unprovable certificate.
    /// Carries the leader reference and a bitmask of authorities whose
    /// voting blocks the requester already has.
    UnprovableCertificateRequest {
        leader_ref: BlockReference,
        known_voters: AuthoritySet,
    },
    /// Compressed-ref protocols: request blocks at a specific round that
    /// the requester doesn't yet have.
    RoundGapRequest {
        round: RoundNumber,
        known_authorities: AuthoritySet,
    },
    /// Starfish-RBC: direct-author canonical header and receiver-specific
    /// initial proof.
    RbcInitial(RbcHeaderProposal),
    /// Starfish-RBC: direct, recipient-specific ECHO or READY testimony.
    RbcPhase(RbcPhaseMessage),
    /// Starfish-RBC: request canonical header content for a phase-evidenced
    /// block reference.
    RbcHeaderRequest(BlockReference),
    /// Starfish-RBC: return canonical header content. The receiver recomputes
    /// and checks its content-addressed reference before accepting it.
    RbcHeaderResponse(RbcCanonicalHeader),
    /// Starfish-RBC-DAG milestone-three shadow carrier. This path is
    /// observational and never feeds the authoritative DAG or consensus.
    RbcDagShadowCarrier(RbcDagShadowCarrier),
    /// Request canonical content after embedded phase evidence arrives before
    /// the corresponding shadow carrier.
    RbcDagShadowCarrierRequest(BlockReference),
    /// Return content only; the receiver recomputes and checks the reference.
    RbcDagShadowCarrierResponse(RbcDagShadowCarrierResponse),
    /// Starfish-RBC-DAG milestone-four synchronization for one exact
    /// `(author, round)` carrier-clock slot.
    RbcDagShadowCarrierSyncRequest(RbcDagShadowCarrierSyncRequest),
    /// Full canonical carrier and authentication sidecar for an exact
    /// carrier-clock slot. Receivers validate the duplicated slot identity.
    RbcDagShadowCarrierSyncResponse(RbcDagShadowCarrierSyncResponse),
    /// Request transaction data for one exact application header already
    /// authorized through the embedded carrier protocol.
    RbcDagApplicationPayloadRequest(BlockReference),
    /// Return commitment-checked transaction data for an authorized embedded
    /// application header. The response is not an author proof.
    RbcDagApplicationPayloadResponse(RbcDagApplicationPayloadResponse),
    /// Return canonical carrier content with one exact retained
    /// authentication-sidecar variant. Appended after the frozen V1 message
    /// family so every preceding bincode enum discriminant remains stable.
    RbcDagShadowCarrierEnvelopeResponse(RbcDagShadowCarrierEnvelopeResponse),
    /// Signature-free single-DAG recovery response carrying the exact header,
    /// optional payload, and the author's complete MAC vector. Appended so
    /// every preceding bincode discriminant remains stable.
    RbcHeaderEnvelopeResponse(RbcHeaderProposal),
}

impl NetworkMessage {
    fn request_type(&self) -> &'static str {
        match self {
            Self::SubscribeBroadcastRequest(_) => "subscribe_broadcast",
            Self::Batch(_) => "batch",
            Self::MissingParentsRequest(_) => "missing_parents",
            Self::MissingTxDataRequest(_) => "missing_tx_data",
            Self::PartialSig(..) => "partial_sig",
            Self::CertMessage(message) => match message.kind {
                CertMessageKind::Echo => "cert_echo",
                CertMessageKind::Vote => "cert_vote",
                CertMessageKind::Ready => "cert_ready",
            },
            Self::CertBatch(_) => "cert_batch",
            Self::SailfishTimeout(_) => "sailfish_timeout",
            Self::SailfishNoVote(_) => "sailfish_no_vote",
            Self::UnprovableCertificateRequest { .. } => "unprovable_cert_request",
            Self::RoundGapRequest { .. } => "round_gap_request",
            Self::RbcInitial(_) => "rbc_initial",
            Self::RbcPhase(message) => match message.phase() {
                RbcPhase::Echo => "rbc_echo",
                RbcPhase::Ready => "rbc_ready",
            },
            Self::RbcHeaderRequest(_) => "rbc_header_request",
            Self::RbcHeaderResponse(_) => "rbc_header_response",
            Self::RbcDagShadowCarrier(_) => "rbc_dag_shadow_carrier",
            Self::RbcDagShadowCarrierRequest(_) => "rbc_dag_shadow_carrier_request",
            Self::RbcDagShadowCarrierResponse(_) => "rbc_dag_shadow_carrier_response",
            Self::RbcDagShadowCarrierSyncRequest(_) => "rbc_dag_shadow_carrier_sync_request",
            Self::RbcDagShadowCarrierSyncResponse(_) => "rbc_dag_shadow_carrier_sync_response",
            Self::RbcDagApplicationPayloadRequest(_) => "rbc_dag_application_payload_request",
            Self::RbcDagApplicationPayloadResponse(_) => "rbc_dag_application_payload_response",
            Self::RbcDagShadowCarrierEnvelopeResponse(_) => {
                "rbc_dag_shadow_carrier_envelope_response"
            }
            Self::RbcHeaderEnvelopeResponse(_) => "rbc_header_envelope_response",
        }
    }
}

pub struct Network {
    connection_receiver: mpsc::Receiver<Connection>,
    server_task: JoinHandle<()>,
}

pub struct Connection {
    pub peer_id: usize,
    pub sender: mpsc::Sender<NetworkMessage>,
    /// Exact RBC-DAG repair remains distinct from ordinary/proactive traffic
    /// until the socket scheduler makes its final priority decision.
    pub(crate) rbc_dag_priority_sender: mpsc::Sender<NetworkMessage>,
    /// Proactive RBC-DAG carriers remain bounded independently of the
    /// connection's legacy ordinary channel.
    pub(crate) rbc_dag_proactive_sender: mpsc::Sender<NetworkMessage>,
    /// Terminal writer/scheduler failure for fail-closed authoritative users.
    pub(crate) outbound_failure: watch::Receiver<Option<String>>,
    /// Keep the connection-scoped failure signal open while this public
    /// connection is alive. Cancelling the writer because the read half
    /// disconnected or a newer socket replaced it is not a terminal writer
    /// failure and must not look like one to authoritative users.
    _outbound_failure_lifetime: watch::Sender<Option<String>>,
    pub receiver: mpsc::Receiver<NetworkMessage>,
}

impl Drop for Network {
    fn drop(&mut self) {
        // Dropping a Tokio JoinHandle detaches its task. Abort explicitly so
        // a panic in the network-sync main loop cannot leave the listener
        // alive and sharing SO_REUSEPORT with a later benchmark.
        self.server_task.abort();
    }
}

impl Network {
    pub async fn load(
        parameters: &NodePublicConfig,
        our_id: AuthorityIndex,
        local_addr: SocketAddr,
        metrics: Arc<Metrics>,
    ) -> Self {
        let addresses = parameters.all_network_addresses().collect::<Vec<_>>();
        print_network_address_table(&addresses);
        Self::from_socket_addresses(
            &addresses,
            our_id as usize,
            local_addr,
            metrics,
            &parameters.parameters,
        )
        .await
    }

    pub fn connection_receiver(&mut self) -> &mut mpsc::Receiver<Connection> {
        &mut self.connection_receiver
    }

    /// Abort the background server task so the TCP listener is released.
    pub fn abort_server(&self) {
        self.server_task.abort();
    }

    #[cfg(test)]
    async fn abort_and_wait(mut self) -> Result<(), tokio::task::JoinError> {
        self.server_task.abort();
        (&mut self.server_task).await
    }

    pub async fn from_socket_addresses(
        addresses: &[SocketAddr],
        our_id: usize,
        local_addr: SocketAddr,
        metrics: Arc<Metrics>,
        node_parameters: &NodeParameters,
    ) -> Self {
        if our_id >= addresses.len() {
            panic!(
                "our_id {our_id} is larger then address length {}",
                addresses.len()
            );
        }
        let (latency_table, scaled_mask) = generate_latency_table(addresses.len(), node_parameters);
        let server = {
            let socket = if local_addr.is_ipv4() {
                TcpSocket::new_v4().unwrap()
            } else {
                TcpSocket::new_v6().unwrap()
            };
            socket.set_reuseaddr(true).unwrap();
            socket.set_reuseport(true).unwrap();
            socket.bind(local_addr).unwrap();
            socket.listen(1024).unwrap()
        };
        let mut worker_senders: HashMap<SocketAddr, mpsc::UnboundedSender<TcpStream>> =
            HashMap::default();
        let handle = Handle::current();
        let (connection_sender, connection_receiver) = mpsc::channel(16);
        for (id, address) in addresses.iter().enumerate() {
            if id == our_id {
                continue;
            }
            let (sender, receiver) = mpsc::unbounded_channel();
            assert!(
                worker_senders.insert(*address, sender).is_none(),
                "Duplicated address {address} in list"
            );
            handle.spawn(
                Worker {
                    peer: *address,
                    peer_id: id,
                    connection_sender: connection_sender.clone(),
                    bind_addr: bind_addr(local_addr),
                    metrics: metrics.clone(),
                    active_immediately: id < our_id,
                    extra_connection_latency: latency_table[id][our_id],
                    extra_connection_scaled: scaled_mask[id][our_id],
                    compress_network: node_parameters.compress_network,
                }
                .run(receiver),
            );
        }
        let server_task = handle.spawn(
            Server {
                server,
                worker_senders,
            }
            .run(),
        );
        Self {
            connection_receiver,
            server_task,
        }
    }
}

struct Server {
    server: TcpListener,
    worker_senders: HashMap<SocketAddr, mpsc::UnboundedSender<TcpStream>>,
}

impl Server {
    async fn run(self) {
        loop {
            let (socket, remote_peer) = self.server.accept().await.expect("Accept failed");
            let remote_peer = remote_to_local_port(remote_peer);
            if let Some(sender) = self.worker_senders.get(&remote_peer) {
                sender.send(socket).ok();
            } else {
                tracing::warn!("Dropping connection from unknown peer {remote_peer}");
            }
        }
    }
}

// just ignore these two functions for now :)
fn remote_to_local_port(mut remote_peer: SocketAddr) -> SocketAddr {
    match &mut remote_peer {
        SocketAddr::V4(v4) => {
            v4.set_port(v4.port() / 10);
        }
        SocketAddr::V6(v6) => {
            v6.set_port(v6.port() / 10);
        }
    }
    remote_peer
}

fn bind_addr(mut local_peer: SocketAddr) -> SocketAddr {
    match &mut local_peer {
        SocketAddr::V4(v4) => {
            v4.set_port(v4.port() * 10);
        }
        SocketAddr::V6(v6) => {
            v6.set_port(v6.port() * 10);
        }
    }
    local_peer
}

const NETWORK_MESSAGE_CHANNEL_CAPACITY: usize = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScheduledNetworkClass {
    Priority,
    Ordinary,
}

enum ScheduledNetworkPayload {
    Message {
        wire_bytes: Vec<u8>,
        request_type: &'static str,
    },
    Ping([u8; 12]),
}

impl ScheduledNetworkPayload {
    fn len(&self) -> usize {
        match self {
            Self::Message { wire_bytes, .. } => wire_bytes.len().saturating_add(4),
            Self::Ping(bytes) => bytes.len(),
        }
    }
}

#[cfg(test)]
fn scheduled_ping_value(payload: &ScheduledNetworkPayload) -> Option<i64> {
    match payload {
        ScheduledNetworkPayload::Ping(bytes) => Some(decode_ping(&bytes[4..])),
        ScheduledNetworkPayload::Message { .. } => None,
    }
}

struct ScheduledNetworkWrite {
    ready_at: Instant,
    sequence: u64,
    payload: ScheduledNetworkPayload,
}

struct ScheduledNetworkLane {
    writes: Vec<ScheduledNetworkWrite>,
    bytes: usize,
    count_capacity: usize,
    byte_capacity: usize,
}

impl ScheduledNetworkLane {
    fn new(count_capacity: usize, byte_capacity: usize) -> Self {
        Self {
            writes: Vec::new(),
            bytes: 0,
            count_capacity,
            byte_capacity,
        }
    }

    /// Reserve enough room for the largest legal frame before receiving the
    /// next opaque `NetworkMessage`. This makes the post-serialization byte
    /// bound strict without pulling an item out of a backpressured channel
    /// that cannot yet be admitted.
    fn can_receive_max_frame(&self) -> bool {
        const MAX_FRAMED_BYTES: usize = MAX_BUFFER_SIZE as usize + 4;
        self.writes.len() < self.count_capacity
            && self.bytes <= self.byte_capacity.saturating_sub(MAX_FRAMED_BYTES)
    }

    fn push(&mut self, write: ScheduledNetworkWrite) -> Result<(), ScheduledNetworkWrite> {
        let bytes = write.payload.len();
        let Some(next_bytes) = self.bytes.checked_add(bytes) else {
            return Err(write);
        };
        if self.writes.len() >= self.count_capacity || next_bytes > self.byte_capacity {
            return Err(write);
        }
        self.bytes = next_bytes;
        self.writes.push(write);
        Ok(())
    }

    fn ready_index(&self, now: Instant) -> Option<usize> {
        self.writes
            .iter()
            .enumerate()
            .filter(|(_, write)| write.ready_at <= now)
            .min_by_key(|(_, write)| (write.ready_at, write.sequence))
            .map(|(index, _)| index)
    }

    fn pop_ready(&mut self, now: Instant) -> Option<ScheduledNetworkWrite> {
        let index = self.ready_index(now)?;
        let write = self.writes.swap_remove(index);
        self.bytes = self
            .bytes
            .checked_sub(write.payload.len())
            .expect("scheduled network byte accounting cannot underflow");
        Some(write)
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.writes.iter().map(|write| write.ready_at).min()
    }

    fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }
}

struct ScheduledNetworkWrites {
    priority: ScheduledNetworkLane,
    ordinary: ScheduledNetworkLane,
    next_sequence: u64,
}

impl ScheduledNetworkWrites {
    fn production() -> Self {
        Self::new(
            NETWORK_SCHEDULED_LANE_CAPACITY,
            NETWORK_SCHEDULED_LANE_BYTE_CAPACITY,
        )
    }

    fn new(lane_count_capacity: usize, lane_byte_capacity: usize) -> Self {
        Self {
            priority: ScheduledNetworkLane::new(lane_count_capacity, lane_byte_capacity),
            ordinary: ScheduledNetworkLane::new(lane_count_capacity, lane_byte_capacity),
            next_sequence: 0,
        }
    }

    fn lane(&self, class: ScheduledNetworkClass) -> &ScheduledNetworkLane {
        match class {
            ScheduledNetworkClass::Priority => &self.priority,
            ScheduledNetworkClass::Ordinary => &self.ordinary,
        }
    }

    fn lane_mut(&mut self, class: ScheduledNetworkClass) -> &mut ScheduledNetworkLane {
        match class {
            ScheduledNetworkClass::Priority => &mut self.priority,
            ScheduledNetworkClass::Ordinary => &mut self.ordinary,
        }
    }

    fn can_receive(&self, class: ScheduledNetworkClass) -> bool {
        self.lane(class).can_receive_max_frame()
    }

    fn push(
        &mut self,
        class: ScheduledNetworkClass,
        ready_at: Instant,
        payload: ScheduledNetworkPayload,
    ) -> io::Result<()> {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.lane_mut(class)
            .push(ScheduledNetworkWrite {
                ready_at,
                sequence,
                payload,
            })
            .map_err(|write| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    format!(
                        "scheduled {:?} network lane exhausted at {} bytes",
                        class,
                        write.payload.len()
                    ),
                )
            })
    }

    fn pop_ready(&mut self, now: Instant) -> Option<ScheduledNetworkWrite> {
        self.priority
            .pop_ready(now)
            .or_else(|| self.ordinary.pop_ready(now))
    }

    fn next_deadline(&self) -> Option<Instant> {
        match (self.priority.next_deadline(), self.ordinary.next_deadline()) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
    }

    fn is_empty(&self) -> bool {
        self.priority.is_empty() && self.ordinary.is_empty()
    }
}

struct Worker {
    peer: SocketAddr,
    peer_id: usize,
    connection_sender: mpsc::Sender<Connection>,
    bind_addr: SocketAddr,
    metrics: Arc<Metrics>,
    active_immediately: bool,
    extra_connection_latency: f64,
    extra_connection_scaled: bool,
    compress_network: bool,
}

struct WorkerConnection {
    sender: mpsc::Sender<NetworkMessage>,
    receiver: mpsc::Receiver<NetworkMessage>,
    rbc_dag_priority_receiver: mpsc::Receiver<NetworkMessage>,
    rbc_dag_proactive_receiver: mpsc::Receiver<NetworkMessage>,
    outbound_failure: watch::Sender<Option<String>>,
    metrics: Arc<Metrics>,
    peer_id: usize,
    compress_network: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OrdinaryAdmissionSource {
    Proactive,
    Legacy,
}

impl OrdinaryAdmissionSource {
    fn alternate(self) -> Self {
        match self {
            Self::Proactive => Self::Legacy,
            Self::Legacy => Self::Proactive,
        }
    }

    fn try_receive(
        self,
        proactive_receiver: &mut mpsc::Receiver<NetworkMessage>,
        legacy_receiver: &mut mpsc::Receiver<NetworkMessage>,
    ) -> Result<NetworkMessage, mpsc::error::TryRecvError> {
        match self {
            Self::Proactive => proactive_receiver.try_recv(),
            Self::Legacy => legacy_receiver.try_recv(),
        }
    }
}

fn admit_ordinary_fairly(
    scheduled: &mut ScheduledNetworkWrites,
    proactive_receiver: &mut mpsc::Receiver<NetworkMessage>,
    legacy_receiver: &mut mpsc::Receiver<NetworkMessage>,
    proactive_closed: &mut bool,
    legacy_closed: &mut bool,
    next_source: &mut OrdinaryAdmissionSource,
    effective_latency: f64,
    compress_network: bool,
    metrics: &Metrics,
) -> io::Result<bool> {
    if !scheduled.can_receive(ScheduledNetworkClass::Ordinary) {
        return Ok(false);
    }
    let Some(message) = try_receive_ordinary_fairly(
        proactive_receiver,
        legacy_receiver,
        proactive_closed,
        legacy_closed,
        next_source,
    ) else {
        return Ok(false);
    };
    schedule_network_message(
        scheduled,
        ScheduledNetworkClass::Ordinary,
        message,
        effective_latency,
        compress_network,
        metrics,
    )?;
    Ok(true)
}

fn try_receive_ordinary_fairly(
    proactive_receiver: &mut mpsc::Receiver<NetworkMessage>,
    legacy_receiver: &mut mpsc::Receiver<NetworkMessage>,
    proactive_closed: &mut bool,
    legacy_closed: &mut bool,
    next_source: &mut OrdinaryAdmissionSource,
) -> Option<NetworkMessage> {
    for source in [*next_source, next_source.alternate()] {
        if match source {
            OrdinaryAdmissionSource::Proactive => *proactive_closed,
            OrdinaryAdmissionSource::Legacy => *legacy_closed,
        } {
            continue;
        }
        match source.try_receive(proactive_receiver, legacy_receiver) {
            Ok(message) => {
                *next_source = source.alternate();
                return Some(message);
            }
            Err(mpsc::error::TryRecvError::Empty) => {}
            Err(mpsc::error::TryRecvError::Disconnected) => match source {
                OrdinaryAdmissionSource::Proactive => *proactive_closed = true,
                OrdinaryAdmissionSource::Legacy => *legacy_closed = true,
            },
        }
    }
    None
}

impl Worker {
    const ACTIVE_HANDSHAKE: u64 = 0xFEFE0000;
    const PASSIVE_HANDSHAKE: u64 = 0x0000AEAE;
    const MAX_BUFFER_SIZE: u32 = MAX_BUFFER_SIZE;

    async fn run(self, mut receiver: mpsc::UnboundedReceiver<TcpStream>) -> Option<()> {
        let initial_delay = if self.active_immediately {
            Duration::ZERO
        } else {
            sample_delay(Duration::from_secs(1)..Duration::from_secs(5))
        };
        let mut work = self.connect_and_handle(initial_delay, self.peer).boxed();
        loop {
            match select(work, receiver.recv().boxed()).await {
                Either::Left((_work, _receiver)) => {
                    let delay = sample_delay(Duration::from_secs(1)..Duration::from_secs(5));
                    work = self.connect_and_handle(delay, self.peer).boxed();
                }
                Either::Right((received, _work)) => {
                    // A closed channel means the server is terminated.
                    let received = received?;
                    tracing::debug!("Replaced connection for {}", self.peer_id);
                    work = self.handle_passive_stream(received).boxed();
                }
            }
        }
    }

    async fn connect_and_handle(&self, delay: Duration, peer: SocketAddr) -> io::Result<()> {
        // this is critical to avoid race between active and passive connections
        runtime::sleep(delay).await;
        let mut stream = loop {
            let socket = if self.bind_addr.is_ipv4() {
                TcpSocket::new_v4().unwrap()
            } else {
                TcpSocket::new_v6().unwrap()
            };
            socket.set_reuseport(true).unwrap();
            socket.bind(self.bind_addr).unwrap();
            match socket.connect(peer).await {
                Ok(stream) => break stream,
                Err(_err) => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };
        stream.set_nodelay(true)?;
        stream.write_u64(Self::ACTIVE_HANDSHAKE).await?;
        let handshake = stream.read_u64().await?;
        if handshake != Self::PASSIVE_HANDSHAKE {
            tracing::warn!("Invalid passive handshake: {handshake}");
            return Ok(());
        }
        let Some(connection) = self.make_connection().await else {
            // todo - pass signal to break the main loop
            return Ok(());
        };
        Self::handle_stream(
            stream,
            connection,
            self.extra_connection_latency,
            self.extra_connection_scaled,
        )
        .await
    }

    async fn handle_passive_stream(&self, mut stream: TcpStream) -> io::Result<()> {
        stream.set_nodelay(true)?;
        stream.write_u64(Self::PASSIVE_HANDSHAKE).await?;
        let handshake = stream.read_u64().await?;
        if handshake != Self::ACTIVE_HANDSHAKE {
            tracing::warn!("Invalid active handshake: {handshake}");
            return Ok(());
        }
        let Some(connection) = self.make_connection().await else {
            // todo - pass signal to break the main loop
            return Ok(());
        };
        Self::handle_stream(
            stream,
            connection,
            self.extra_connection_latency,
            self.extra_connection_scaled,
        )
        .await
    }

    async fn handle_stream(
        stream: TcpStream,
        connection: WorkerConnection,
        extra_connection_latency: f64,
        extra_connection_scaled: bool,
    ) -> io::Result<()> {
        let WorkerConnection {
            sender,
            receiver,
            rbc_dag_priority_receiver,
            rbc_dag_proactive_receiver,
            outbound_failure,
            metrics,
            peer_id,
            compress_network,
        } = connection;
        tracing::debug!("Connected to {}", peer_id);
        let (reader, writer) = stream.into_split();
        let (pong_sender, pong_receiver) = mpsc::channel(16);
        let latency_sender = metrics
            .connection_latency_sender
            .get(peer_id)
            .expect(
                "Can not locate connection_latency_sender \
                metric - did you initialize metrics with \
                correct committee?",
            )
            .clone();
        let write_metrics = metrics.clone();
        let write_fut = async move {
            let result = Self::handle_write_stream(
                writer,
                receiver,
                rbc_dag_priority_receiver,
                rbc_dag_proactive_receiver,
                pong_receiver,
                latency_sender,
                write_metrics,
                extra_connection_latency,
                extra_connection_scaled,
                compress_network,
            )
            .await;
            if let Err(error) = &result {
                outbound_failure.send_replace(Some(error.to_string()));
            }
            result
        }
        .boxed();
        let read_fut =
            Self::handle_read_stream(reader, sender, pong_sender, metrics, compress_network)
                .boxed();
        let (r, _, _) = select_all([write_fut, read_fut]).await;
        tracing::debug!("Disconnected from {}", peer_id);
        r
    }

    async fn handle_write_stream(
        mut writer: OwnedWriteHalf,
        mut receiver: mpsc::Receiver<NetworkMessage>,
        mut rbc_dag_priority_receiver: mpsc::Receiver<NetworkMessage>,
        mut rbc_dag_proactive_receiver: mpsc::Receiver<NetworkMessage>,
        mut pong_receiver: mpsc::Receiver<i64>,
        latency_sender: HistogramSender<Duration>,
        metrics: Arc<Metrics>,
        connection_latency: f64,
        connection_scaled: bool,
        compress_network: bool,
    ) -> io::Result<()> {
        let start = Instant::now();
        let effective_latency = effective_latency(connection_latency, connection_scaled);
        let mut scheduled = ScheduledNetworkWrites::production();
        let mut ordinary_closed = false;
        let mut priority_closed = false;
        let mut proactive_closed = false;
        let mut pong_closed = false;
        let mut ping_deadline = start + PING_INTERVAL;
        let mut next_ordinary_source = OrdinaryAdmissionSource::Proactive;

        loop {
            // Keep socket liveness independent of application throughput. A
            // continuously ready zero-latency data lane must not prevent the
            // read half from handing us pings (and eventually blocking on its
            // bounded pong channel), nor postpone our periodic ping forever.
            let now = Instant::now();
            service_network_keepalive(
                &mut scheduled,
                &mut pong_receiver,
                &mut pong_closed,
                start,
                now,
                &mut ping_deadline,
                effective_latency,
                &latency_sender,
            )?;

            // Always admit queued exact repair before ordinary traffic. The
            // two scheduled lanes have independent 64-item/byte bounds, so a
            // proactive burst cannot consume repair capacity.
            while scheduled.can_receive(ScheduledNetworkClass::Priority) {
                match rbc_dag_priority_receiver.try_recv() {
                    Ok(message) => schedule_network_message(
                        &mut scheduled,
                        ScheduledNetworkClass::Priority,
                        message,
                        effective_latency,
                        compress_network,
                        &metrics,
                    )?,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        priority_closed = true;
                        break;
                    }
                }
            }
            while admit_ordinary_fairly(
                &mut scheduled,
                &mut rbc_dag_proactive_receiver,
                &mut receiver,
                &mut proactive_closed,
                &mut ordinary_closed,
                &mut next_ordinary_source,
                effective_latency,
                compress_network,
                &metrics,
            )? {}

            if let Some(write) = scheduled.pop_ready(Instant::now()) {
                write_scheduled_network_payload(&mut writer, write.payload, &metrics).await?;
                continue;
            }
            if ordinary_closed && priority_closed && proactive_closed && scheduled.is_empty() {
                return Ok(());
            }

            let next_write_deadline = scheduled.next_deadline();
            let next_deadline =
                next_write_deadline.map_or(ping_deadline, |deadline| deadline.min(ping_deadline));
            tokio::select! {
                biased;
                message = rbc_dag_priority_receiver.recv(),
                    if !priority_closed
                        && scheduled.can_receive(ScheduledNetworkClass::Priority) => {
                    match message {
                        Some(message) => schedule_network_message(
                            &mut scheduled,
                            ScheduledNetworkClass::Priority,
                            message,
                            effective_latency,
                            compress_network,
                            &metrics,
                        )?,
                        None => priority_closed = true,
                    }
                }
                pong = pong_receiver.recv(),
                    if !pong_closed
                        && scheduled.can_receive(ScheduledNetworkClass::Priority) => {
                    match pong {
                        Some(pong) => schedule_or_observe_pong(
                            &mut scheduled,
                            pong,
                            start,
                            Instant::now(),
                            effective_latency,
                            &latency_sender,
                        )?,
                        None => pong_closed = true,
                    }
                }
                message = rbc_dag_proactive_receiver.recv(),
                    if !proactive_closed
                        && scheduled.can_receive(ScheduledNetworkClass::Ordinary) => {
                    match message {
                        Some(message) => {
                            schedule_network_message(
                                &mut scheduled,
                                ScheduledNetworkClass::Ordinary,
                                message,
                                effective_latency,
                                compress_network,
                                &metrics,
                            )?;
                            next_ordinary_source = OrdinaryAdmissionSource::Legacy;
                        }
                        None => proactive_closed = true,
                    }
                }
                message = receiver.recv(),
                    if !ordinary_closed
                        && scheduled.can_receive(ScheduledNetworkClass::Ordinary) => {
                    match message {
                        Some(message) => {
                            schedule_network_message(
                                &mut scheduled,
                                ScheduledNetworkClass::Ordinary,
                                message,
                                effective_latency,
                                compress_network,
                                &metrics,
                            )?;
                            next_ordinary_source = OrdinaryAdmissionSource::Proactive;
                        }
                        None => ordinary_closed = true,
                    }
                }
                _ = tokio::time::sleep_until(next_deadline) => {}
            }
        }
    }

    async fn handle_read_stream(
        mut stream: OwnedReadHalf,
        sender: mpsc::Sender<NetworkMessage>,
        pong_sender: mpsc::Sender<i64>,
        metrics: Arc<Metrics>,
        compress_network: bool,
    ) -> io::Result<()> {
        // Reusable receive buffer. Grow on demand up to MAX_BUFFER_SIZE.
        // Avoid allocating MAX_BUFFER_SIZE for every connection — that
        // explodes memory at 100-200 validators (full mesh).
        let mut buf: Vec<u8> = Vec::new();
        let bytes_received_total = metrics.bytes_received_total.clone();
        loop {
            let size = stream.read_u32().await?;
            if size > Self::MAX_BUFFER_SIZE {
                tracing::warn!("Invalid size: {size}");
                return Ok(());
            }
            if size == 0 {
                // ping message
                let ping_len = PING_SIZE - 4 /*Already read size(u32)*/;
                if buf.len() < ping_len {
                    buf.resize(ping_len, 0);
                }
                let ping_buf = &mut buf[..ping_len];
                let read = stream.read_exact(ping_buf).await?;
                assert_eq!(read, ping_buf.len());
                bytes_received_total.inc_by(read as u64);
                let pong = decode_ping(ping_buf);
                if pong_sender.send(pong).await.is_err() {
                    return Ok(()); // write stream closed
                }
                continue;
            }
            let size = size as usize;
            if buf.len() < size {
                buf.resize(size, 0);
            }
            let msg_buf = &mut buf[..size];
            let read = stream.read_exact(msg_buf).await?;
            assert_eq!(read, msg_buf.len());
            bytes_received_total.inc_by(read as u64);
            let deserialize_result = if compress_network {
                match lz4_flex::decompress_size_prepended(msg_buf) {
                    Ok(decompressed) => bincode::deserialize::<NetworkMessage>(&decompressed).ok(),
                    Err(e) => {
                        tracing::warn!("lz4 decompression failed: {e}");
                        None
                    }
                }
            } else {
                bincode::deserialize::<NetworkMessage>(msg_buf).ok()
            };
            match deserialize_result {
                Some(message) => {
                    let request_type = message.request_type();
                    metrics
                        .network_message_bytes_received_total
                        .with_label_values(&[request_type])
                        .inc_by(read as u64 + 4);
                    if sender.send(message).await.is_err() {
                        // todo - pass signal to break main loop
                        return Ok(());
                    }
                    metrics
                        .network_requests_received_total
                        .with_label_values(&[request_type])
                        .inc();
                }
                None => {
                    tracing::warn!("Failed to decompress and/or deserialize");
                    return Ok(());
                }
            }
        }
    }

    async fn make_connection(&self) -> Option<WorkerConnection> {
        let (network_in_sender, network_in_receiver) =
            mpsc::channel(NETWORK_MESSAGE_CHANNEL_CAPACITY);
        let (network_out_sender, network_out_receiver) =
            mpsc::channel(NETWORK_MESSAGE_CHANNEL_CAPACITY);
        let (rbc_dag_priority_sender, rbc_dag_priority_receiver) =
            mpsc::channel(RBC_DAG_PRIORITY_CHANNEL_CAPACITY);
        let (rbc_dag_proactive_sender, rbc_dag_proactive_receiver) =
            mpsc::channel(RBC_DAG_PROACTIVE_CHANNEL_CAPACITY);
        let (outbound_failure, outbound_failure_receiver) = watch::channel(None);
        let connection = Connection {
            peer_id: self.peer_id,
            sender: network_out_sender,
            rbc_dag_priority_sender,
            rbc_dag_proactive_sender,
            outbound_failure: outbound_failure_receiver,
            _outbound_failure_lifetime: outbound_failure.clone(),
            receiver: network_in_receiver,
        };
        self.connection_sender.send(connection).await.ok()?;
        Some(WorkerConnection {
            sender: network_in_sender,
            receiver: network_out_receiver,
            rbc_dag_priority_receiver,
            rbc_dag_proactive_receiver,
            outbound_failure,
            metrics: self.metrics.clone(),
            peer_id: self.peer_id,
            compress_network: self.compress_network,
        })
    }
}

fn schedule_network_message(
    scheduled: &mut ScheduledNetworkWrites,
    class: ScheduledNetworkClass,
    message: NetworkMessage,
    effective_latency: f64,
    compress_network: bool,
    metrics: &Metrics,
) -> io::Result<()> {
    let request_type = message.request_type();
    let serialized = bincode::serialize(&message).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("network message serialization failed: {error}"),
        )
    })?;
    let wire_bytes = if compress_network {
        metrics
            .bytes_uncompressed_sent_total
            .inc_by(serialized.len() as u64);
        lz4_flex::compress_prepend_size(&serialized)
    } else {
        serialized
    };
    if wire_bytes.len() > MAX_BUFFER_SIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "serialized network message is {} bytes, maximum {}",
                wire_bytes.len(),
                MAX_BUFFER_SIZE
            ),
        ));
    }
    scheduled.push(
        class,
        Instant::now() + generate_latency(effective_latency),
        ScheduledNetworkPayload::Message {
            wire_bytes,
            request_type,
        },
    )
}

fn schedule_or_observe_pong(
    scheduled: &mut ScheduledNetworkWrites,
    ping: i64,
    start: Instant,
    now: Instant,
    effective_latency: f64,
    latency_sender: &HistogramSender<Duration>,
) -> io::Result<()> {
    if ping == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "received a zero ping",
        ));
    }
    if ping > 0 {
        let pong = ping
            .checked_neg()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ping cannot be negated"))?;
        return scheduled.push(
            ScheduledNetworkClass::Priority,
            now + generate_latency(effective_latency),
            ScheduledNetworkPayload::Ping(encode_ping(pong)),
        );
    }
    let our_ping = ping
        .checked_neg()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid pong"))?;
    let elapsed = now.saturating_duration_since(start).as_micros() as u64;
    let delay = elapsed.checked_sub(our_ping).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "pong timestamp is greater than the local clock",
        )
    })?;
    latency_sender.observe(Duration::from_micros(delay));
    Ok(())
}

fn service_network_keepalive(
    scheduled: &mut ScheduledNetworkWrites,
    pong_receiver: &mut mpsc::Receiver<i64>,
    pong_closed: &mut bool,
    start: Instant,
    now: Instant,
    ping_deadline: &mut Instant,
    effective_latency: f64,
    latency_sender: &HistogramSender<Duration>,
) -> io::Result<()> {
    if !*pong_closed && scheduled.can_receive(ScheduledNetworkClass::Priority) {
        match pong_receiver.try_recv() {
            Ok(pong) => schedule_or_observe_pong(
                scheduled,
                pong,
                start,
                now,
                effective_latency,
                latency_sender,
            )?,
            Err(mpsc::error::TryRecvError::Empty) => {}
            Err(mpsc::error::TryRecvError::Disconnected) => *pong_closed = true,
        }
    }
    if now >= *ping_deadline {
        if scheduled.can_receive(ScheduledNetworkClass::Priority) {
            let ping_time = now.saturating_duration_since(start).as_micros() as i64;
            if ping_time > 0 {
                scheduled.push(
                    ScheduledNetworkClass::Priority,
                    now + generate_latency(effective_latency),
                    ScheduledNetworkPayload::Ping(encode_ping(ping_time)),
                )?;
            }
        }
        *ping_deadline = now + PING_INTERVAL;
    }
    Ok(())
}

async fn write_scheduled_network_payload(
    writer: &mut OwnedWriteHalf,
    payload: ScheduledNetworkPayload,
    metrics: &Metrics,
) -> io::Result<()> {
    match payload {
        ScheduledNetworkPayload::Message {
            wire_bytes,
            request_type,
        } => {
            let wire_len = u32::try_from(wire_bytes.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "network frame length exceeds u32",
                )
            })?;
            writer.write_u32(wire_len).await?;
            writer.write_all(&wire_bytes).await?;
            let framed_len = wire_bytes.len() as u64 + 4;
            metrics.bytes_sent_total.inc_by(framed_len);
            metrics
                .network_requests_sent_total
                .with_label_values(&[request_type])
                .inc();
            metrics
                .network_message_bytes_sent_total
                .with_label_values(&[request_type])
                .inc_by(framed_len);
        }
        ScheduledNetworkPayload::Ping(bytes) => {
            writer.write_all(&bytes).await?;
            metrics.bytes_sent_total.inc_by(bytes.len() as u64);
        }
    }
    Ok(())
}

/// Generates a latency table for a geodistributed network.
/// `n` is the number of nodes.
/// `seed` is a global seed used for deterministic generation.
/// If `seed == 0`, the table is initialized with all zeros.
/// expected mean latency for a quorum of nodes should be below within expected
/// thresholds
fn generate_latency_table(
    n: usize,
    node_params: &NodeParameters,
) -> (Vec<Vec<f64>>, Vec<Vec<bool>>) {
    let mut resulting_table = vec![vec![]; n];

    // Priority: uniform_latency_ms > mimic_latency > zero
    if let Some(uniform_latency) = node_params.uniform_latency_ms {
        // NEW: Use uniform latency
        for item in resulting_table.iter_mut().take(n) {
            for _j in 0..n {
                item.push(uniform_latency)
            }
        }
    } else if !node_params.mimic_latency {
        // Existing: zero latency
        for item in resulting_table.iter_mut().take(n) {
            for _j in 0..n {
                item.push(0.0)
            }
        }
    } else {
        // Existing: AWS RTT table
        for (i, item) in resulting_table.iter_mut().enumerate().take(n) {
            for j in 0..n {
                let index_i = i % RTT_LATENCY_TABLE.len();
                let index_j = j % RTT_LATENCY_TABLE.len();
                item.push(RTT_LATENCY_TABLE[index_i][index_j] as f64 / 2.0)
            }
        }
    }

    // Adversarial-latency static doubling: same-region (small base latency)
    // peers stay stable — any cell with base < threshold is exempt. Of the
    // remaining cross-region peers per row, `adversarial_latency_percent`%
    // are statically marked "scaled"; their per-message latency is doubled
    // for the entire run. Selection is deterministic per row, so every node
    // generates the same table without coordination.
    let mut scaled_mask = vec![vec![false; n]; n];
    if node_params.adversarial_latency && n > 1 {
        let percent = node_params.adversarial_latency_percent.min(100) as usize;
        for (i, row) in scaled_mask.iter_mut().enumerate() {
            let candidates: Vec<usize> = (0..n)
                .filter(|&j| {
                    j != i && resulting_table[i][j] >= ADVERSARIAL_LATENCY_NEAR_THRESHOLD_MS
                })
                .collect();
            let scaled_per_row = (candidates.len() * percent).div_ceil(100);
            let mut rng = StdRng::seed_from_u64(ADVERSARIAL_LATENCY_SEED ^ i as u64);
            let mut shuffled = candidates;
            shuffled.shuffle(&mut rng);
            for &j in shuffled.iter().take(scaled_per_row) {
                row[j] = true;
            }
        }
    }

    (resulting_table, scaled_mask)
}

/// Multiplier applied to scaled cells' base latency for the entire run.
const ADVERSARIAL_LATENCY_MULT: f64 = 5.0;

/// Seed for the per-row deterministic shuffle that picks the scaled subset.
/// XOR'd with the row index so every node computes the same selection
/// without coordination.
const ADVERSARIAL_LATENCY_SEED: u64 = 0xADBA_0000_0000_0000;

/// Cells with base latency strictly below this threshold (in milliseconds)
/// are exempt from doubling. Picked above typical AWS same-region RTTs
/// (~0.5-2 ms) and below cross-region minima (~30 ms).
const ADVERSARIAL_LATENCY_NEAR_THRESHOLD_MS: f64 = 5.0;

/// Returns the per-call effective latency. Cells flagged `scaled` carry
/// `base * ADVERSARIAL_LATENCY_MULT` for the entire run; everything else
/// is returned unchanged.
fn effective_latency(base: f64, scaled: bool) -> f64 {
    if scaled && base != 0.0 {
        base * ADVERSARIAL_LATENCY_MULT
    } else {
        base
    }
}

fn generate_latency(mean: f64) -> Duration {
    let mut rng = rand::thread_rng();

    // Define a constant deviation percentage (e.g., ±3% of the mean)
    let deviation_percentage = 0.03; // 3%

    // Calculate the deviation based on the mean
    let deviation = mean * deviation_percentage;

    // Generate latency by adding the random deviation to the mean
    let latency = mean + rng.gen_range(-deviation..=deviation);

    // Return the latency as a Duration (in milliseconds)
    Duration::from_millis(latency as u64)
}

fn sample_delay(range: Range<Duration>) -> Duration {
    ThreadRng::default().gen_range(range)
}

const PING_SIZE: usize = 12;
fn encode_ping(message: i64) -> [u8; PING_SIZE] {
    let mut m = [0u8; 12];
    m[4..].copy_from_slice(&message.to_le_bytes());
    m
}

fn decode_ping(message: &[u8]) -> i64 {
    let mut m = [0u8; 8];
    m.copy_from_slice(message); // asserts message.len() == 8
    i64::from_le_bytes(m)
}

#[cfg(test)]
mod tests {
    use prometheus::Registry;

    use super::*;
    use crate::{
        committee::Committee,
        crypto::{AsBytes, MacTag, TransactionsCommitment, dummy_signer},
        starfish_rbc::{RbcInitialProof, RbcPhaseMessage},
        types::{BaseTransaction, Transaction},
    };

    const NETWORK_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(6);

    fn scheduled_test_message(marker: RoundNumber) -> ScheduledNetworkPayload {
        let message = NetworkMessage::SubscribeBroadcastRequest(marker);
        ScheduledNetworkPayload::Message {
            wire_bytes: bincode::serialize(&message).unwrap(),
            request_type: message.request_type(),
        }
    }

    fn scheduled_test_marker(write: ScheduledNetworkWrite) -> RoundNumber {
        let ScheduledNetworkPayload::Message { wire_bytes, .. } = write.payload else {
            panic!("expected a scheduled network message");
        };
        let NetworkMessage::SubscribeBroadcastRequest(marker) =
            bincode::deserialize(&wire_bytes).unwrap()
        else {
            panic!("expected a scheduled subscription marker");
        };
        marker
    }

    fn outbound_test_marker(message: NetworkMessage) -> RoundNumber {
        let NetworkMessage::SubscribeBroadcastRequest(marker) = message else {
            panic!("expected an outbound subscription marker");
        };
        marker
    }

    #[test]
    fn ordinary_admission_alternates_continuously_ready_sources() {
        let (proactive_sender, mut proactive_receiver) = mpsc::channel(8);
        let (legacy_sender, mut legacy_receiver) = mpsc::channel(8);
        for marker in 10..14 {
            proactive_sender
                .try_send(NetworkMessage::SubscribeBroadcastRequest(marker))
                .unwrap();
        }
        for marker in 20..24 {
            legacy_sender
                .try_send(NetworkMessage::SubscribeBroadcastRequest(marker))
                .unwrap();
        }
        let mut proactive_closed = false;
        let mut legacy_closed = false;
        let mut next = OrdinaryAdmissionSource::Proactive;
        let markers = (0..8)
            .map(|_| {
                outbound_test_marker(
                    try_receive_ordinary_fairly(
                        &mut proactive_receiver,
                        &mut legacy_receiver,
                        &mut proactive_closed,
                        &mut legacy_closed,
                        &mut next,
                    )
                    .expect("both saturated sources should remain admissible"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(markers, vec![10, 20, 11, 21, 12, 22, 13, 23]);
    }

    #[test]
    fn ordinary_admission_falls_through_without_losing_its_fair_turn() {
        let (proactive_sender, mut proactive_receiver) = mpsc::channel(4);
        let (legacy_sender, mut legacy_receiver) = mpsc::channel(4);
        legacy_sender
            .try_send(NetworkMessage::SubscribeBroadcastRequest(20))
            .unwrap();
        let mut proactive_closed = false;
        let mut legacy_closed = false;
        let mut next = OrdinaryAdmissionSource::Proactive;
        assert_eq!(
            outbound_test_marker(
                try_receive_ordinary_fairly(
                    &mut proactive_receiver,
                    &mut legacy_receiver,
                    &mut proactive_closed,
                    &mut legacy_closed,
                    &mut next,
                )
                .unwrap(),
            ),
            20
        );
        proactive_sender
            .try_send(NetworkMessage::SubscribeBroadcastRequest(10))
            .unwrap();
        assert_eq!(
            outbound_test_marker(
                try_receive_ordinary_fairly(
                    &mut proactive_receiver,
                    &mut legacy_receiver,
                    &mut proactive_closed,
                    &mut legacy_closed,
                    &mut next,
                )
                .unwrap(),
            ),
            10
        );
    }

    #[test]
    fn keepalive_is_serviced_before_a_continuously_ready_data_lane() {
        let (mut histogram, latency_sender) = crate::stat::histogram::<Duration>();
        let (pong_sender, mut pong_receiver) = mpsc::channel(16);
        pong_sender.try_send(7).unwrap();
        let start = Instant::now();
        let now = start + PING_INTERVAL;
        let mut ping_deadline = now;
        let mut pong_closed = false;
        let mut scheduled = ScheduledNetworkWrites::new(64, NETWORK_SCHEDULED_LANE_BYTE_CAPACITY);
        scheduled
            .push(
                ScheduledNetworkClass::Ordinary,
                start,
                scheduled_test_message(10),
            )
            .unwrap();

        service_network_keepalive(
            &mut scheduled,
            &mut pong_receiver,
            &mut pong_closed,
            start,
            now,
            &mut ping_deadline,
            0.0,
            &latency_sender,
        )
        .unwrap();

        let first = scheduled.pop_ready(now).unwrap();
        assert_eq!(scheduled_ping_value(&first.payload), Some(-7));
        let second = scheduled.pop_ready(now).unwrap();
        assert_eq!(
            scheduled_ping_value(&second.payload),
            Some(PING_INTERVAL.as_micros() as i64)
        );
        assert_eq!(scheduled_test_marker(scheduled.pop_ready(now).unwrap()), 10);
        histogram.receive_all();
        assert_eq!(histogram.total_count(), 0);
        assert_eq!(ping_deadline, now + PING_INTERVAL);
    }

    #[test]
    fn normal_writer_cancellation_does_not_close_failure_signal() {
        let (writer_failure, worker_failure) = watch::channel(None::<String>);
        let connection_lifetime = writer_failure.clone();
        drop(writer_failure);
        assert!(matches!(worker_failure.has_changed(), Ok(false)));
        drop(connection_lifetime);
        assert!(worker_failure.has_changed().is_err());
    }

    #[test]
    fn scheduled_writer_preserves_ready_priority_under_zero_and_aws_latency() {
        let now = Instant::now();
        for latency in [Duration::ZERO, Duration::from_millis(130)] {
            let mut scheduled = ScheduledNetworkWrites::new(64, 1024 * 1024);
            scheduled
                .push(
                    ScheduledNetworkClass::Ordinary,
                    now + latency,
                    scheduled_test_message(10),
                )
                .unwrap();
            scheduled
                .push(
                    ScheduledNetworkClass::Priority,
                    now + latency,
                    scheduled_test_message(20),
                )
                .unwrap();
            assert_eq!(
                scheduled_test_marker(scheduled.pop_ready(now + latency).unwrap()),
                20
            );
            assert_eq!(
                scheduled_test_marker(scheduled.pop_ready(now + latency).unwrap()),
                10
            );
        }
    }

    #[test]
    fn scheduled_writer_does_not_send_unready_priority_ahead_of_ready_ordinary() {
        let now = Instant::now();
        let mut scheduled = ScheduledNetworkWrites::new(64, 1024 * 1024);
        scheduled
            .push(
                ScheduledNetworkClass::Priority,
                now + Duration::from_millis(200),
                scheduled_test_message(20),
            )
            .unwrap();
        scheduled
            .push(
                ScheduledNetworkClass::Ordinary,
                now + Duration::from_millis(100),
                scheduled_test_message(10),
            )
            .unwrap();
        assert_eq!(
            scheduled_test_marker(
                scheduled
                    .pop_ready(now + Duration::from_millis(100))
                    .unwrap()
            ),
            10
        );
        assert!(
            scheduled
                .pop_ready(now + Duration::from_millis(199))
                .is_none()
        );
        assert_eq!(
            scheduled_test_marker(
                scheduled
                    .pop_ready(now + Duration::from_millis(200))
                    .unwrap()
            ),
            20
        );
    }

    #[test]
    fn scheduled_writer_bounds_each_lane_without_cross_lane_eviction() {
        let now = Instant::now();
        let one = scheduled_test_message(1);
        let framed_bytes = one.len();
        let mut scheduled = ScheduledNetworkWrites::new(2, framed_bytes * 2);
        for marker in [1, 2] {
            scheduled
                .push(
                    ScheduledNetworkClass::Ordinary,
                    now,
                    scheduled_test_message(marker),
                )
                .unwrap();
        }
        assert!(
            scheduled
                .push(
                    ScheduledNetworkClass::Ordinary,
                    now,
                    scheduled_test_message(3),
                )
                .is_err()
        );
        // Saturating the proactive/ordinary lane cannot consume priority
        // count or byte credit.
        for marker in [10, 11] {
            scheduled
                .push(
                    ScheduledNetworkClass::Priority,
                    now,
                    scheduled_test_message(marker),
                )
                .unwrap();
        }
        assert_eq!(scheduled.priority.writes.len(), 2);
        assert_eq!(scheduled.ordinary.writes.len(), 2);
        assert_eq!(scheduled.priority.bytes, framed_bytes * 2);
        assert_eq!(scheduled.ordinary.bytes, framed_bytes * 2);
        assert_eq!(scheduled_test_marker(scheduled.pop_ready(now).unwrap()), 10);
        assert_eq!(scheduled_test_marker(scheduled.pop_ready(now).unwrap()), 11);
        assert_eq!(scheduled_test_marker(scheduled.pop_ready(now).unwrap()), 1);
    }

    #[tokio::test]
    async fn connection_priority_channel_is_bounded_and_failure_is_observable() {
        let (priority_sender, mut priority_receiver) =
            mpsc::channel(RBC_DAG_PRIORITY_CHANNEL_CAPACITY);
        for marker in 0..RBC_DAG_PRIORITY_CHANNEL_CAPACITY as RoundNumber {
            priority_sender
                .try_send(NetworkMessage::SubscribeBroadcastRequest(marker))
                .unwrap();
        }
        assert!(matches!(
            priority_sender.try_send(NetworkMessage::SubscribeBroadcastRequest(999)),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        assert!(priority_receiver.recv().await.is_some());
        priority_sender
            .try_send(NetworkMessage::SubscribeBroadcastRequest(999))
            .unwrap();

        let (failure_sender, mut failure_receiver) = watch::channel(None);
        failure_sender.send_replace(Some("scheduler saturated".to_owned()));
        failure_receiver.changed().await.unwrap();
        assert_eq!(
            failure_receiver.borrow().as_deref(),
            Some("scheduler saturated")
        );
    }

    async fn connected_pair(
        addresses: &[SocketAddr; 2],
        parameters: &NodeParameters,
    ) -> (Network, Network, Connection, Connection) {
        let committee = Committee::new_for_benchmarks(2);
        let metrics_0 = Metrics::new(&Registry::new(), Some(&committee), None, None).0;
        let metrics_1 = Metrics::new(&Registry::new(), Some(&committee), None, None).0;
        let mut network_0 =
            Network::from_socket_addresses(addresses, 0, addresses[0], metrics_0, parameters).await;
        let mut network_1 =
            Network::from_socket_addresses(addresses, 1, addresses[1], metrics_1, parameters).await;

        let (connection_0, connection_1) = tokio::time::timeout(NETWORK_LIFECYCLE_TIMEOUT, async {
            tokio::join!(
                network_0.connection_receiver().recv(),
                network_1.connection_receiver().recv(),
            )
        })
        .await
        .expect("two-node network did not connect before the lifecycle timeout");
        let connection_0 = connection_0.expect("authority 0 connection channel closed");
        let connection_1 = connection_1.expect("authority 1 connection channel closed");
        assert_eq!(connection_0.peer_id, 1);
        assert_eq!(connection_1.peer_id, 0);
        (network_0, network_1, connection_0, connection_1)
    }

    async fn assert_bidirectional_round_trip(
        connection_0: &mut Connection,
        connection_1: &mut Connection,
        marker: RoundNumber,
    ) {
        connection_0
            .sender
            .send(NetworkMessage::SubscribeBroadcastRequest(marker))
            .await
            .unwrap();
        connection_1
            .sender
            .send(NetworkMessage::SubscribeBroadcastRequest(marker + 1))
            .await
            .unwrap();

        let (received_by_0, received_by_1) =
            tokio::time::timeout(NETWORK_LIFECYCLE_TIMEOUT, async {
                tokio::join!(connection_0.receiver.recv(), connection_1.receiver.recv())
            })
            .await
            .expect("two-node network did not exchange messages before the lifecycle timeout");
        assert!(matches!(
            received_by_0,
            Some(NetworkMessage::SubscribeBroadcastRequest(round)) if round == marker + 1
        ));
        assert!(matches!(
            received_by_1,
            Some(NetworkMessage::SubscribeBroadcastRequest(round)) if round == marker
        ));
    }

    async fn abort_network_pair(network_0: Network, network_1: Network) {
        // Match production shutdown: abort both listeners together. Awaiting
        // the server tasks makes listener release deterministic for this test;
        // dropping their worker senders must then cancel every scoped stream
        // future and its OwnedWriteHalf.
        let (result_0, result_1) =
            tokio::join!(network_0.abort_and_wait(), network_1.abort_and_wait());
        assert!(result_0.is_err_and(|error| error.is_cancelled()));
        assert!(result_1.is_err_and(|error| error.is_cancelled()));
    }

    async fn same_port_rebind_case(addresses: [SocketAddr; 2], latency_ms: Option<f64>) {
        let parameters = NodeParameters {
            mimic_latency: false,
            uniform_latency_ms: latency_ms,
            ..NodeParameters::default()
        };

        for cycle in 0..2 {
            let (network_0, network_1, mut connection_0, mut connection_1) =
                connected_pair(&addresses, &parameters).await;
            assert_bidirectional_round_trip(&mut connection_0, &mut connection_1, 10 + cycle).await;

            // NetworkSyncer drops its connection tasks before aborting the
            // listener. Reproduce that ordering, then immediately construct
            // the next cycle on the identical listener and active-bind ports.
            drop(connection_0);
            drop(connection_1);
            abort_network_pair(network_0, network_1).await;
        }
    }

    fn variant_index(message: &NetworkMessage) -> u32 {
        let bytes = bincode::serialize(message).unwrap();
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    }

    #[test]
    fn rbc_wire_variants_are_append_only_and_roundtrip() {
        // This pre-existing last variant is frozen at index 10. Adding RBC
        // messages must not renumber any legacy bincode discriminant.
        let legacy = NetworkMessage::RoundGapRequest {
            round: 7,
            known_authorities: AuthoritySet::default(),
        };
        assert_eq!(variant_index(&legacy), 10);

        let header = RbcCanonicalHeader::try_new(
            0,
            1,
            Vec::new(),
            Vec::new(),
            11,
            TransactionsCommitment::default(),
        )
        .unwrap();
        let block_ref = header.reference();
        let initial = NetworkMessage::RbcInitial(RbcHeaderProposal::new(
            header.clone(),
            RbcInitialProof::Ed25519(dummy_signer().sign_digest(&[0xA1; 32])),
        ));
        let phase = NetworkMessage::RbcPhase(RbcPhaseMessage::new_for_test(
            block_ref,
            1,
            2,
            RbcPhase::Ready,
            MacTag::from_bytes([0xA2; 32]),
        ));
        let request = NetworkMessage::RbcHeaderRequest(block_ref);
        let response = NetworkMessage::RbcHeaderResponse(header);
        let application_payload = Arc::new(TransactionData::new(vec![BaseTransaction::Share(
            Transaction::new(vec![0xAC; 8]),
        )]));
        let shadow = NetworkMessage::RbcDagShadowCarrier(RbcDagShadowCarrier {
            canonical_carrier: vec![0xA3, 0xA4],
            authentication_sidecar: vec![0xA5],
            application_payload: Some(Arc::clone(&application_payload)),
        });
        let shadow_request = NetworkMessage::RbcDagShadowCarrierRequest(block_ref);
        let shadow_response =
            NetworkMessage::RbcDagShadowCarrierResponse(RbcDagShadowCarrierResponse {
                reference: block_ref,
                canonical_carrier: vec![0xA6, 0xA7],
            });
        let shadow_envelope_response = NetworkMessage::RbcDagShadowCarrierEnvelopeResponse(
            RbcDagShadowCarrierEnvelopeResponse {
                reference: block_ref,
                canonical_carrier: vec![0xB6, 0xB7],
                authentication_sidecar: vec![0xB8, 0xB9],
            },
        );
        let sync_request =
            NetworkMessage::RbcDagShadowCarrierSyncRequest(RbcDagShadowCarrierSyncRequest {
                author: 2,
                round: 23,
            });
        let sync_response =
            NetworkMessage::RbcDagShadowCarrierSyncResponse(RbcDagShadowCarrierSyncResponse {
                author: 2,
                round: 23,
                canonical_carrier: vec![0xA8, 0xA9],
                authentication_sidecar: vec![0xAA, 0xAB],
            });
        let payload_request = NetworkMessage::RbcDagApplicationPayloadRequest(block_ref);
        let payload_response =
            NetworkMessage::RbcDagApplicationPayloadResponse(RbcDagApplicationPayloadResponse {
                application: block_ref,
                transaction_data: application_payload,
            });

        for (message, expected_index, expected_kind) in [
            (initial, 11, "rbc_initial"),
            (phase, 12, "rbc_ready"),
            (request, 13, "rbc_header_request"),
            (response, 14, "rbc_header_response"),
            (shadow, 15, "rbc_dag_shadow_carrier"),
            (shadow_request, 16, "rbc_dag_shadow_carrier_request"),
            (shadow_response, 17, "rbc_dag_shadow_carrier_response"),
            (sync_request, 18, "rbc_dag_shadow_carrier_sync_request"),
            (sync_response, 19, "rbc_dag_shadow_carrier_sync_response"),
            (payload_request, 20, "rbc_dag_application_payload_request"),
            (payload_response, 21, "rbc_dag_application_payload_response"),
            (
                shadow_envelope_response,
                22,
                "rbc_dag_shadow_carrier_envelope_response",
            ),
        ] {
            assert_eq!(variant_index(&message), expected_index);
            assert_eq!(message.request_type(), expected_kind);
            let encoded = bincode::serialize(&message).unwrap();
            let decoded: NetworkMessage = bincode::deserialize(&encoded).unwrap();
            assert_eq!(decoded.request_type(), expected_kind);
            assert_eq!(variant_index(&decoded), expected_index);
        }
    }

    #[test]
    fn rbc_dag_shadow_carrier_sync_payloads_roundtrip_exactly() {
        let request = RbcDagShadowCarrierSyncRequest {
            author: 3,
            round: 41,
        };
        let encoded =
            bincode::serialize(&NetworkMessage::RbcDagShadowCarrierSyncRequest(request)).unwrap();
        let decoded: NetworkMessage = bincode::deserialize(&encoded).unwrap();
        assert!(matches!(
            decoded,
            NetworkMessage::RbcDagShadowCarrierSyncRequest(decoded) if decoded == request
        ));

        let response = RbcDagShadowCarrierSyncResponse {
            author: 3,
            round: 41,
            canonical_carrier: vec![0xC1, 0xC2, 0xC3],
            authentication_sidecar: vec![0xD1, 0xD2],
        };
        let encoded = bincode::serialize(&NetworkMessage::RbcDagShadowCarrierSyncResponse(
            response.clone(),
        ))
        .unwrap();
        let decoded: NetworkMessage = bincode::deserialize(&encoded).unwrap();
        assert!(matches!(
            decoded,
            NetworkMessage::RbcDagShadowCarrierSyncResponse(decoded) if decoded == response
        ));
    }

    #[test]
    fn rbc_dag_application_payload_sidecars_roundtrip_exactly() {
        let application = BlockReference::new_test(2, 17);
        let transaction_data = Arc::new(TransactionData::new(vec![BaseTransaction::Share(
            Transaction::new(vec![0xE1, 0xE2, 0xE3]),
        )]));
        let carrier = RbcDagShadowCarrier {
            canonical_carrier: vec![0xC1, 0xC2],
            authentication_sidecar: vec![0xD1],
            application_payload: Some(Arc::clone(&transaction_data)),
        };
        let encoded = bincode::serialize(&NetworkMessage::RbcDagShadowCarrier(carrier)).unwrap();
        let decoded: NetworkMessage = bincode::deserialize(&encoded).unwrap();
        let NetworkMessage::RbcDagShadowCarrier(decoded) = decoded else {
            panic!("decoded a different network-message variant");
        };
        assert_eq!(decoded.canonical_carrier, vec![0xC1, 0xC2]);
        assert_eq!(decoded.authentication_sidecar, vec![0xD1]);
        let decoded_payload = decoded
            .application_payload
            .expect("application payload should survive the wire round trip");
        assert_eq!(decoded_payload.number_transactions(), 1);
        let BaseTransaction::Share(transaction) = &decoded_payload.transactions()[0];
        assert_eq!(transaction.as_bytes(), &[0xE1, 0xE2, 0xE3]);

        let payloadless = RbcDagShadowCarrier {
            canonical_carrier: vec![0xC3],
            authentication_sidecar: vec![0xD2],
            application_payload: None,
        };
        let encoded =
            bincode::serialize(&NetworkMessage::RbcDagShadowCarrier(payloadless)).unwrap();
        assert_eq!(
            encoded,
            vec![
                15, 0, 0, 0, // frozen enum discriminant
                1, 0, 0, 0, 0, 0, 0, 0, 0xC3, // canonical carrier bytes
                1, 0, 0, 0, 0, 0, 0, 0, 0xD2, // authentication sidecar bytes
                0,    // no application payload
            ],
            "payloadless carrier wire grammar changed",
        );
        let decoded: NetworkMessage = bincode::deserialize(&encoded).unwrap();
        assert!(matches!(
            decoded,
            NetworkMessage::RbcDagShadowCarrier(RbcDagShadowCarrier {
                application_payload: None,
                ..
            })
        ));

        let request = NetworkMessage::RbcDagApplicationPayloadRequest(application);
        assert_eq!(variant_index(&request), 20);
        let encoded = bincode::serialize(&request).unwrap();
        let decoded: NetworkMessage = bincode::deserialize(&encoded).unwrap();
        assert!(matches!(
            decoded,
            NetworkMessage::RbcDagApplicationPayloadRequest(decoded) if decoded == application
        ));

        let response =
            NetworkMessage::RbcDagApplicationPayloadResponse(RbcDagApplicationPayloadResponse {
                application,
                transaction_data,
            });
        assert_eq!(variant_index(&response), 21);
        let encoded = bincode::serialize(&response).unwrap();
        let decoded: NetworkMessage = bincode::deserialize(&encoded).unwrap();
        let NetworkMessage::RbcDagApplicationPayloadResponse(decoded) = decoded else {
            panic!("decoded a different network-message variant");
        };
        assert_eq!(decoded.application, application);
        assert_eq!(decoded.transaction_data.number_transactions(), 1);
        let BaseTransaction::Share(transaction) = &decoded.transaction_data.transactions()[0];
        assert_eq!(transaction.as_bytes(), &[0xE1, 0xE2, 0xE3]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scoped_connection_tasks_allow_immediate_same_port_rebind() {
        // Active sockets bind to listener_port * 10. Keep those derived ports
        // below the usual Linux ephemeral range to avoid unrelated allocation
        // races while staying above the repository's validator-test fixtures.
        same_port_rebind_case(
            [
                SocketAddr::from(([127, 0, 0, 1], 3_200)),
                SocketAddr::from(([127, 0, 0, 1], 3_201)),
            ],
            None,
        )
        .await;
        // Any nonzero configured latency selects the JoinSet-backed writer
        // branch, so this also covers cancellation of its in-flight tasks.
        same_port_rebind_case(
            [
                SocketAddr::from(([127, 0, 0, 1], 3_220)),
                SocketAddr::from(([127, 0, 0, 1], 3_221)),
            ],
            Some(5.0),
        )
        .await;
    }
}
