// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    panic::AssertUnwindSafe,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ahash::{AHashMap, AHashSet};
use futures::{FutureExt, future::join_all};
use rand::seq::SliceRandom;
use reed_solomon_simd::ReedSolomonEncoder;
use tokio::time::Instant;
use tokio::{
    select,
    sync::{Notify, Semaphore, mpsc, watch},
};

use crate::{
    block_handler::BlockHandler,
    bls_certificate_aggregator::{BlsCertificateAggregator, CertificateEvent},
    bls_service::{BlsServiceHandle, BlsServiceMessage, start_bls_service},
    broadcaster::{BlockDisseminator, BlockFetcher, BroadcasterParameters, DataRequester},
    committee::Committee,
    config::{DisseminationMode, NodeParameters},
    consensus::universal_committer::UniversalCommitter,
    cordial_knowledge::{
        ConnectionKnowledge, CordialKnowledgeHandle, CordialKnowledgeMessage, UsefulAuthorsMessage,
    },
    core::Core,
    core_thread::CoreThreadDispatcher,
    crypto::{Blake3Hasher, BlsSigner, MacKey, TransactionsCommitment},
    dag_state::{ConsensusProtocol, DagState, DataSource},
    data::Data,
    metrics::{
        Metrics, RBC_DAG_COMMIT_DISTANCE_PHYSICAL_BACKWARD,
        RBC_DAG_COMMIT_DISTANCE_PHYSICAL_FORWARD, RBC_DAG_LATENCY_CREATION_TO_FRONTIER_APPLIED,
        UtilizationTimerVecExt,
    },
    network::{BlockBatch, Connection, Network, NetworkMessage, RbcDagShadowCarrier, ShardPayload},
    runtime::{Handle, JoinError, JoinHandle, sleep},
    sailfish_service::{
        SailfishCertEvent, SailfishServiceHandle, SailfishServiceMessage, start_sailfish_service,
    },
    shard_reconstructor::{DecodedBlocks, ShardMessage, start_shard_reconstructor},
    starfish_rbc::{PinnedRbcHeader, RbcCanonicalHeader, RbcCommitteeId, RbcProtocolInstanceId},
    starfish_rbc_dag::{
        CandidateCarrierV1, MAX_CARRIER_CONTENT_SIZE_V1, RbcDagCommitteeContextV1, RbcDagContextV1,
        RbcDagProtocolInstanceId, projection::ProjectionDecisionV1, storage::ShadowWalSyncPolicyV1,
    },
    starfish_rbc_dag_shadow::{
        CommittedApplicationDiagnosticV1, CommittedFrontierDeltaV1, ShadowAuthorizerV1,
        ShadowDeliveryComparisonV1, ShadowDeliveryIdentityV1,
    },
    starfish_rbc_dag_shadow_service::{
        ShadowApplicationAuthorizationBasisV1, ShadowServiceErrorV1, ShadowServiceEventV1,
        StarfishRbcDagShadowServiceHandleV1,
        start_starfish_rbc_dag_authoritative_clock_service_with_metrics_v1,
        start_starfish_rbc_dag_autonomous_clock_service_paused_with_metrics_v1,
        start_starfish_rbc_dag_autonomous_clock_service_with_metrics_v1,
        start_starfish_rbc_dag_shadow_service_with_metrics_v1,
    },
    starfish_rbc_service::{
        RbcInitialAuthenticator, RbcPhaseAuthorityV1, RbcServiceEvent, RbcServiceHandle,
        start_starfish_rbc_service_with_phase_authority,
    },
    syncer::{CommitObserver, Syncer, SyncerSignals},
    types::{
        AuthorityIndex, AuthoritySet, BlockAuthentication, BlockAuthenticationScheme, BlockDigest,
        BlockReference, PartialSig, PartialSigKind, ProvableShard, ReconstructedTransactionData,
        RoundNumber, TimestampNs, TransactionData, VerifiedBlock, format_authority_index,
    },
};

const MAX_FILTER_SIZE: usize = 100_000;
const SAILFISH_CERT_BATCH_FLUSH_INTERVAL: Duration = Duration::from_millis(5);
const SAILFISH_CERT_BATCH_MAX_LEN: usize = 256;
const STARFISH_RBC_HEADER_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const STARFISH_RBC_DAG_SHADOW_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const STARFISH_RBC_DAG_CONTROL_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const STARFISH_RBC_DAG_CORE_CONTROL_CAPACITY: usize = 64;
const STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY: usize = 64;
// Priority entries contain at most one carrier or application payload plus a
// bounded authentication/frame reserve. Proactive carriers may contain both.
// Count and byte accounting are independent so a future wire-size regression
// cannot turn the fixed key caps into an unbounded memory reservoir.
const STARFISH_RBC_DAG_OUTBOUND_FRAME_RESERVE: usize = 128 * 1024;
const STARFISH_RBC_DAG_OUTBOUND_PRIORITY_ENTRY_BYTES: usize =
    MAX_CARRIER_CONTENT_SIZE_V1 + STARFISH_RBC_DAG_OUTBOUND_FRAME_RESERVE;
const STARFISH_RBC_DAG_OUTBOUND_PROACTIVE_ENTRY_BYTES: usize =
    MAX_CARRIER_CONTENT_SIZE_V1 * 2 + STARFISH_RBC_DAG_OUTBOUND_FRAME_RESERVE;
const STARFISH_RBC_DAG_OUTBOUND_PRIORITY_BYTES: usize =
    STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY * MAX_CARRIER_CONTENT_SIZE_V1;
const STARFISH_RBC_DAG_OUTBOUND_PROACTIVE_BYTES: usize =
    STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY * MAX_CARRIER_CONTENT_SIZE_V1;
const STARFISH_RBC_DAG_AUTONOMOUS_INSTANCE_CONTEXT: &str =
    "STARFISH_RBC_DAG_AUTONOMOUS_CLOCK_V1_PROTOCOL_INSTANCE";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RbcDagOutboundKeyV1 {
    Proactive(BlockReference),
    CarrierRequest(BlockReference),
    CarrierResponse(BlockReference),
    CarrierEnvelopeResponse(BlockReference),
    SyncRequest(AuthorityIndex, RoundNumber),
    SyncResponse(AuthorityIndex, RoundNumber),
    ApplicationPayloadRequest(BlockReference),
    ApplicationPayloadResponse(BlockReference),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RbcDagOutboundClassV1 {
    Priority,
    Proactive,
}

impl RbcDagOutboundClassV1 {
    fn label(self) -> &'static str {
        match self {
            Self::Priority => "priority",
            Self::Proactive => "proactive",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RbcDagOutboundEnqueueV1 {
    Added,
    Coalesced,
}

#[derive(Debug)]
enum RbcDagOutboundMailboxErrorV1 {
    Unsupported,
    InvalidProactive(String),
    Serialization(String),
    EntryTooLarge {
        class: RbcDagOutboundClassV1,
        actual: usize,
        maximum: usize,
    },
    KeyCapacity {
        class: RbcDagOutboundClassV1,
        capacity: usize,
    },
    ByteCapacity {
        class: RbcDagOutboundClassV1,
        attempted: usize,
        capacity: usize,
    },
    ConflictingDuplicate {
        class: RbcDagOutboundClassV1,
        key: RbcDagOutboundKeyV1,
    },
    DownstreamSaturated(RbcDagOutboundClassV1),
    DownstreamClosed,
    Failed(String),
}

impl fmt::Display for RbcDagOutboundMailboxErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(formatter, "unsupported non-RBC-DAG outbound message"),
            Self::InvalidProactive(error) => {
                write!(formatter, "invalid proactive carrier: {error}")
            }
            Self::Serialization(error) => {
                write!(formatter, "outbound message serialization failed: {error}")
            }
            Self::EntryTooLarge {
                class,
                actual,
                maximum,
            } => write!(
                formatter,
                "{} outbound entry is {actual} bytes, maximum {maximum}",
                class.label(),
            ),
            Self::KeyCapacity { class, capacity } => write!(
                formatter,
                "{} outbound key capacity {capacity} exhausted",
                class.label(),
            ),
            Self::ByteCapacity {
                class,
                attempted,
                capacity,
            } => write!(
                formatter,
                "{} outbound byte capacity {capacity} exhausted by {attempted} bytes",
                class.label(),
            ),
            Self::ConflictingDuplicate { class, key } => write!(
                formatter,
                "conflicting {} outbound duplicate for {key:?}",
                class.label(),
            ),
            Self::DownstreamSaturated(class) => {
                write!(
                    formatter,
                    "downstream {} network channel saturated",
                    class.label()
                )
            }
            Self::DownstreamClosed => write!(formatter, "downstream network sender closed"),
            Self::Failed(reason) => write!(formatter, "outbound mailbox already failed: {reason}"),
        }
    }
}

struct RbcDagOutboundEntryV1 {
    message: NetworkMessage,
    framed_bytes: usize,
}

struct RbcDagOutboundLaneV1 {
    order: VecDeque<RbcDagOutboundKeyV1>,
    entries: AHashMap<RbcDagOutboundKeyV1, RbcDagOutboundEntryV1>,
    bytes: usize,
    key_capacity: usize,
    byte_capacity: usize,
    entry_byte_capacity: usize,
}

impl RbcDagOutboundLaneV1 {
    fn new(key_capacity: usize, byte_capacity: usize, entry_byte_capacity: usize) -> Self {
        Self {
            order: VecDeque::new(),
            entries: AHashMap::new(),
            bytes: 0,
            key_capacity,
            byte_capacity,
            entry_byte_capacity,
        }
    }

    fn enqueue(
        &mut self,
        class: RbcDagOutboundClassV1,
        key: RbcDagOutboundKeyV1,
        entry: RbcDagOutboundEntryV1,
    ) -> Result<RbcDagOutboundEnqueueV1, RbcDagOutboundMailboxErrorV1> {
        if let Some(existing) = self.entries.get(&key) {
            return if rbc_dag_outbound_messages_equal(&existing.message, &entry.message) {
                Ok(RbcDagOutboundEnqueueV1::Coalesced)
            } else {
                Err(RbcDagOutboundMailboxErrorV1::ConflictingDuplicate { class, key })
            };
        }
        if entry.framed_bytes > self.entry_byte_capacity {
            return Err(RbcDagOutboundMailboxErrorV1::EntryTooLarge {
                class,
                actual: entry.framed_bytes,
                maximum: self.entry_byte_capacity,
            });
        }
        if self.entries.len() >= self.key_capacity {
            return Err(RbcDagOutboundMailboxErrorV1::KeyCapacity {
                class,
                capacity: self.key_capacity,
            });
        }
        let attempted = self.bytes.checked_add(entry.framed_bytes).ok_or(
            RbcDagOutboundMailboxErrorV1::ByteCapacity {
                class,
                attempted: usize::MAX,
                capacity: self.byte_capacity,
            },
        )?;
        if attempted > self.byte_capacity {
            return Err(RbcDagOutboundMailboxErrorV1::ByteCapacity {
                class,
                attempted,
                capacity: self.byte_capacity,
            });
        }
        self.bytes = attempted;
        self.order.push_back(key);
        assert!(self.entries.insert(key, entry).is_none());
        Ok(RbcDagOutboundEnqueueV1::Added)
    }

    fn pop_front(&mut self) -> Option<NetworkMessage> {
        let key = self.order.pop_front()?;
        let entry = self
            .entries
            .remove(&key)
            .expect("queued RBC-DAG outbound key retains its exact entry");
        self.bytes = self
            .bytes
            .checked_sub(entry.framed_bytes)
            .expect("RBC-DAG outbound byte accounting cannot underflow");
        Some(entry.message)
    }
}

struct RbcDagOutboundMailboxStateV1 {
    priority: RbcDagOutboundLaneV1,
    proactive: RbcDagOutboundLaneV1,
    failure: Option<String>,
}

impl RbcDagOutboundMailboxStateV1 {
    fn production() -> Self {
        Self {
            priority: RbcDagOutboundLaneV1::new(
                STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY,
                STARFISH_RBC_DAG_OUTBOUND_PRIORITY_BYTES,
                STARFISH_RBC_DAG_OUTBOUND_PRIORITY_ENTRY_BYTES,
            ),
            proactive: RbcDagOutboundLaneV1::new(
                STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY,
                STARFISH_RBC_DAG_OUTBOUND_PROACTIVE_BYTES,
                STARFISH_RBC_DAG_OUTBOUND_PROACTIVE_ENTRY_BYTES,
            ),
            failure: None,
        }
    }
}

struct RbcDagOutboundMailboxInnerV1 {
    state: parking_lot::Mutex<RbcDagOutboundMailboxStateV1>,
    notified: Notify,
}

#[derive(Clone)]
struct RbcDagOutboundMailboxV1 {
    inner: Arc<RbcDagOutboundMailboxInnerV1>,
}

impl RbcDagOutboundMailboxV1 {
    fn new() -> Self {
        Self::from_state(RbcDagOutboundMailboxStateV1::production())
    }

    fn from_state(state: RbcDagOutboundMailboxStateV1) -> Self {
        Self {
            inner: Arc::new(RbcDagOutboundMailboxInnerV1 {
                state: parking_lot::Mutex::new(state),
                notified: Notify::new(),
            }),
        }
    }

    #[cfg(test)]
    fn enqueue(
        &self,
        message: NetworkMessage,
        committee: &RbcDagCommitteeContextV1,
    ) -> Result<RbcDagOutboundEnqueueV1, RbcDagOutboundMailboxErrorV1> {
        self.enqueue_with_proactive_reference(message, committee, None)
    }

    fn enqueue_with_proactive_reference(
        &self,
        message: NetworkMessage,
        committee: &RbcDagCommitteeContextV1,
        proactive_reference: Option<BlockReference>,
    ) -> Result<RbcDagOutboundEnqueueV1, RbcDagOutboundMailboxErrorV1> {
        if let Some(reason) = self.inner.state.lock().failure.clone() {
            return Err(RbcDagOutboundMailboxErrorV1::Failed(reason));
        }
        let (class, key) =
            match rbc_dag_outbound_classification(&message, committee, proactive_reference) {
                Ok(classification) => classification,
                Err(error) => {
                    self.fail(&error);
                    return Err(error);
                }
            };
        let framed_bytes = match bincode::serialized_size(&message)
            .map_err(|error| RbcDagOutboundMailboxErrorV1::Serialization(error.to_string()))
            .and_then(|size| {
                usize::try_from(size)
                    .ok()
                    .and_then(|size| size.checked_add(4))
                    .ok_or_else(|| {
                        RbcDagOutboundMailboxErrorV1::Serialization(
                            "framed size does not fit usize".to_owned(),
                        )
                    })
            }) {
            Ok(framed_bytes) => framed_bytes,
            Err(error) => {
                self.fail(&error);
                return Err(error);
            }
        };
        let entry = RbcDagOutboundEntryV1 {
            message,
            framed_bytes,
        };
        let mut state = self.inner.state.lock();
        if let Some(reason) = state.failure.clone() {
            return Err(RbcDagOutboundMailboxErrorV1::Failed(reason));
        }
        let result = match class {
            RbcDagOutboundClassV1::Priority => state.priority.enqueue(class, key, entry),
            RbcDagOutboundClassV1::Proactive => state.proactive.enqueue(class, key, entry),
        };
        match result {
            Ok(outcome) => {
                drop(state);
                if outcome == RbcDagOutboundEnqueueV1::Added {
                    self.inner.notified.notify_one();
                }
                Ok(outcome)
            }
            Err(error) => {
                state.failure = Some(error.to_string());
                drop(state);
                self.inner.notified.notify_waiters();
                Err(error)
            }
        }
    }

    fn fail(&self, error: &RbcDagOutboundMailboxErrorV1) {
        let mut state = self.inner.state.lock();
        state.failure.get_or_insert_with(|| error.to_string());
        drop(state);
        self.inner.notified.notify_waiters();
    }

    fn try_pop(&self) -> Option<(RbcDagOutboundClassV1, NetworkMessage)> {
        let mut state = self.inner.state.lock();
        if state.failure.is_some() {
            return None;
        }
        state
            .priority
            .pop_front()
            .map(|message| (RbcDagOutboundClassV1::Priority, message))
            .or_else(|| {
                state
                    .proactive
                    .pop_front()
                    .map(|message| (RbcDagOutboundClassV1::Proactive, message))
            })
    }

    async fn recv(&self) -> Option<(RbcDagOutboundClassV1, NetworkMessage)> {
        loop {
            let notified = self.inner.notified.notified();
            if let Some(message) = self.try_pop() {
                return Some(message);
            }
            if self.inner.state.lock().failure.is_some() {
                return None;
            }
            notified.await;
        }
    }
}

fn rbc_dag_outbound_classification(
    message: &NetworkMessage,
    committee: &RbcDagCommitteeContextV1,
    proactive_reference: Option<BlockReference>,
) -> Result<(RbcDagOutboundClassV1, RbcDagOutboundKeyV1), RbcDagOutboundMailboxErrorV1> {
    let priority = RbcDagOutboundClassV1::Priority;
    match message {
        NetworkMessage::RbcDagShadowCarrier(carrier) => {
            let reference = match proactive_reference {
                Some(reference) => reference,
                None => rbc_dag_proactive_reference(carrier, committee)?,
            };
            Ok((
                RbcDagOutboundClassV1::Proactive,
                RbcDagOutboundKeyV1::Proactive(reference),
            ))
        }
        NetworkMessage::RbcDagShadowCarrierRequest(reference) => {
            Ok((priority, RbcDagOutboundKeyV1::CarrierRequest(*reference)))
        }
        NetworkMessage::RbcDagShadowCarrierResponse(response) => Ok((
            priority,
            RbcDagOutboundKeyV1::CarrierResponse(response.reference),
        )),
        NetworkMessage::RbcDagShadowCarrierEnvelopeResponse(response) => Ok((
            priority,
            RbcDagOutboundKeyV1::CarrierEnvelopeResponse(response.reference),
        )),
        NetworkMessage::RbcDagShadowCarrierSyncRequest(request) => Ok((
            priority,
            RbcDagOutboundKeyV1::SyncRequest(request.author, request.round),
        )),
        NetworkMessage::RbcDagShadowCarrierSyncResponse(response) => Ok((
            priority,
            RbcDagOutboundKeyV1::SyncResponse(response.author, response.round),
        )),
        NetworkMessage::RbcDagApplicationPayloadRequest(application) => Ok((
            priority,
            RbcDagOutboundKeyV1::ApplicationPayloadRequest(*application),
        )),
        NetworkMessage::RbcDagApplicationPayloadResponse(response) => Ok((
            priority,
            RbcDagOutboundKeyV1::ApplicationPayloadResponse(response.application),
        )),
        _ => Err(RbcDagOutboundMailboxErrorV1::Unsupported),
    }
}

fn rbc_dag_proactive_reference(
    carrier: &RbcDagShadowCarrier,
    committee: &RbcDagCommitteeContextV1,
) -> Result<BlockReference, RbcDagOutboundMailboxErrorV1> {
    let candidate =
        CandidateCarrierV1::decode_wire_with_committee(&carrier.canonical_carrier, committee, None)
            .map_err(|error| RbcDagOutboundMailboxErrorV1::InvalidProactive(error.to_string()))?;
    let canonical = candidate
        .canonical_wire_bytes()
        .map_err(|error| RbcDagOutboundMailboxErrorV1::InvalidProactive(error.to_string()))?;
    if canonical != carrier.canonical_carrier {
        return Err(RbcDagOutboundMailboxErrorV1::InvalidProactive(
            "non-canonical carrier wire".to_owned(),
        ));
    }
    Ok(candidate.reference())
}

fn rbc_dag_outbound_messages_equal(left: &NetworkMessage, right: &NetworkMessage) -> bool {
    match (left, right) {
        (NetworkMessage::RbcDagShadowCarrier(left), NetworkMessage::RbcDagShadowCarrier(right)) => {
            left == right
        }
        (
            NetworkMessage::RbcDagShadowCarrierRequest(left),
            NetworkMessage::RbcDagShadowCarrierRequest(right),
        ) => left == right,
        (
            NetworkMessage::RbcDagShadowCarrierResponse(left),
            NetworkMessage::RbcDagShadowCarrierResponse(right),
        ) => left == right,
        (
            NetworkMessage::RbcDagShadowCarrierEnvelopeResponse(left),
            NetworkMessage::RbcDagShadowCarrierEnvelopeResponse(right),
        ) => left == right,
        (
            NetworkMessage::RbcDagShadowCarrierSyncRequest(left),
            NetworkMessage::RbcDagShadowCarrierSyncRequest(right),
        ) => left == right,
        (
            NetworkMessage::RbcDagShadowCarrierSyncResponse(left),
            NetworkMessage::RbcDagShadowCarrierSyncResponse(right),
        ) => left == right,
        (
            NetworkMessage::RbcDagApplicationPayloadRequest(left),
            NetworkMessage::RbcDagApplicationPayloadRequest(right),
        ) => left == right,
        (
            NetworkMessage::RbcDagApplicationPayloadResponse(left),
            NetworkMessage::RbcDagApplicationPayloadResponse(right),
        ) => {
            left.application == right.application
                && left.transaction_data.transactions() == right.transaction_data.transactions()
        }
        _ => false,
    }
}

fn current_timestamp_ns() -> TimestampNs {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(TimestampNs::MAX)
}

fn latency_since_timestamps(
    creation_times: impl IntoIterator<Item = TimestampNs>,
    now_ns: TimestampNs,
) -> (u64, u64, u64) {
    creation_times.into_iter().fold(
        (0u64, 0u64, 0u64),
        |(total, samples, maximum), creation_time| {
            let latency = now_ns.saturating_sub(creation_time);
            (
                total.saturating_add(latency),
                samples.saturating_add(1),
                maximum.max(latency),
            )
        },
    )
}

#[derive(Default)]
struct CommitRoundDistanceBatch {
    physical_forward: (u64, u64, u64),
    physical_backward: (u64, u64, u64),
}

impl CommitRoundDistanceBatch {
    fn from_diagnostics(
        diagnostics: impl IntoIterator<Item = CommittedApplicationDiagnosticV1>,
    ) -> Self {
        let mut batch = Self::default();
        for diagnostic in diagnostics {
            let aggregate = if diagnostic.physical_carrier_round_delta >= 0 {
                &mut batch.physical_forward
            } else {
                &mut batch.physical_backward
            };
            let value = diagnostic.physical_carrier_round_delta.unsigned_abs();
            aggregate.0 = aggregate.0.saturating_add(value);
            aggregate.1 = aggregate.1.saturating_add(1);
            aggregate.2 = aggregate.2.max(value);
        }
        batch
    }

    fn observe(self, metrics: &Metrics) {
        for (kind, (total, samples, maximum)) in [
            (
                RBC_DAG_COMMIT_DISTANCE_PHYSICAL_FORWARD,
                self.physical_forward,
            ),
            (
                RBC_DAG_COMMIT_DISTANCE_PHYSICAL_BACKWARD,
                self.physical_backward,
            ),
        ] {
            metrics.observe_starfish_rbc_dag_commit_round_distance(kind, total, samples, maximum);
        }
    }
}

/// Recover the exact locally selected Starfish-RBC chain so the persisted
/// non-authoritative shadow can reconcile a WAL that ended before the direct
/// DAG. The newest local block determines the branch when a Byzantine test
/// produced more than one value in a round.
fn recovered_local_rbc_headers<H: BlockHandler>(
    core: &Core<H>,
) -> Result<Vec<RbcCanonicalHeader>, String> {
    if !core.dag_state().consensus_protocol.is_starfish_rbc() || core.last_proposed() == 0 {
        return Ok(Vec::new());
    }

    let own_authority = core.authority();
    let store = core.store();
    let mut current = core.last_own_block().clone();
    let mut reversed = Vec::with_capacity(current.round() as usize);
    loop {
        if current.round() == 0 {
            break;
        }
        if current.authority() != own_authority {
            return Err(format!(
                "recovered local chain contains authority {} at round {} (expected {})",
                current.authority(),
                current.round(),
                own_authority
            ));
        }
        reversed.push(
            RbcCanonicalHeader::from_block_header(current.header()).map_err(|error| {
                format!(
                    "recovered local Starfish-RBC header {} is not canonical: {error}",
                    current.reference()
                )
            })?,
        );
        if current.round() == 1 {
            break;
        }

        let expected_round = current.round() - 1;
        let predecessor = current
            .block_references()
            .iter()
            .find(|reference| {
                reference.authority == own_authority && reference.round == expected_round
            })
            .copied()
            .ok_or_else(|| {
                format!(
                    "recovered local Starfish-RBC block {} has no own predecessor at round {}",
                    current.reference(),
                    expected_round
                )
            })?;
        current = core
            .dag_state()
            .get_blocks_at_authority_round(own_authority, expected_round)
            .into_iter()
            .find(|block| block.reference() == &predecessor)
            .or_else(|| store.get_block(&predecessor).ok().flatten())
            .ok_or_else(|| {
                format!("recovered local Starfish-RBC predecessor {predecessor} is unavailable")
            })?;
    }
    reversed.reverse();
    Ok(reversed)
}

fn shadow_transport_error_invalidates_run(error: &ShadowServiceErrorV1) -> bool {
    match error {
        ShadowServiceErrorV1::Stopped => true,
        #[cfg(test)]
        ShadowServiceErrorV1::Overloaded { .. } => true,
        _ => false,
    }
}

fn invalidate_shadow_run(metrics: &Metrics) {
    // Exactly one verdict is active for a configured shadow mode, but setting
    // both to zero makes every transport/startup failure fail closed without
    // duplicating mode knowledge throughout the network plumbing.
    metrics.starfish_rbc_dag_shadow_comparison_valid.set(0);
    metrics.starfish_rbc_dag_shadow_clock_valid.set(0);
}

fn rbc_dag_shadow_protocol_instance(
    direct_instance: [u8; 32],
    autonomous_clock: bool,
) -> RbcDagProtocolInstanceId {
    let bytes = if autonomous_clock {
        // Autonomous heartbeat carriers intentionally do not authenticate in
        // the same namespace as milestone-three's direct-header mirror. This
        // makes a heterogeneous deployment fail closed at the shadow boundary
        // instead of cross-admitting application and control carriers.
        let mut hasher = Blake3Hasher::new_derive_key(STARFISH_RBC_DAG_AUTONOMOUS_INSTANCE_CONTEXT);
        hasher.update(&direct_instance);
        *hasher.finalize().as_bytes()
    } else {
        direct_instance
    };
    RbcDagProtocolInstanceId::new(bytes)
        .expect("a configured direct RBC instance and its derived namespace are nonzero")
}

/// Enforce the MAC experiment's transport contract before cryptographic
/// verification:
///
/// - a full vector is accepted only on proactive block streaming directly from
///   the block's claimed author;
/// - every relay and synchronization path must carry one recipient tag;
/// - a direct author stream must carry the full vector, so recipients retain
///   the material needed for one-hop relay.
fn verify_mac_transport(
    block: &VerifiedBlock,
    authentication_scheme: BlockAuthenticationScheme,
    peer_id: AuthorityIndex,
    source: DataSource,
) -> eyre::Result<()> {
    if authentication_scheme != BlockAuthenticationScheme::MacVector {
        return Ok(());
    }

    let direct_author_stream = peer_id == block.authority()
        && matches!(
            source,
            DataSource::BlockBundleStreaming | DataSource::BlockBundleStreamingHeader
        );

    match block.authentication() {
        BlockAuthentication::MacVector(_) if direct_author_stream => Ok(()),
        BlockAuthentication::MacVector(_) => eyre::bail!(
            "Full MAC vector for block {} must arrive via direct author block streaming; \
             received from authority {} with source {}",
            block.reference(),
            peer_id,
            source,
        ),
        BlockAuthentication::MacTag(_) if !direct_author_stream => Ok(()),
        BlockAuthentication::MacTag(_) => eyre::bail!(
            "Direct author block stream for block {} must carry the full MAC vector",
            block.reference(),
        ),
        _ => Ok(()),
    }
}

fn verify_starfish_rbc_transaction_payload(
    canonical_header: &RbcCanonicalHeader,
    transaction_data: Arc<TransactionData>,
    committee: &Committee,
    own_id: AuthorityIndex,
    peer_id: AuthorityIndex,
    encoder: &mut ReedSolomonEncoder,
    authentication_scheme: BlockAuthenticationScheme,
    mac_keys: &[MacKey],
) -> eyre::Result<ReconstructedTransactionData> {
    let block_reference = canonical_header.reference();
    let transaction_data = Arc::try_unwrap(transaction_data).unwrap_or_else(|data| (*data).clone());
    let (block_header, _) = canonical_header.to_authentication_free_block().into_parts();
    let mut block = VerifiedBlock::from_parts(block_header, Some(transaction_data));
    let Some(mut shard_data) = block.verify_with_authentication(
        committee,
        own_id as usize,
        peer_id as usize,
        encoder,
        ConsensusProtocol::StarfishRbc,
        authentication_scheme,
        mac_keys,
    )?
    else {
        eyre::bail!("Starfish-RBC transaction payload for {block_reference} is empty");
    };
    block.preserialize();
    shard_data.preserialize();
    let transaction_data = block
        .transaction_data()
        .expect("verified RBC payload must contain transaction data")
        .clone();
    Ok(ReconstructedTransactionData {
        block_reference,
        transaction_data,
        shard_data,
    })
}

/// Prepare blocks forwarded through relay or synchronization paths for a
/// specific peer. Legacy MAC-experiment blocks retain their complete vector
/// only at direct recipients; forwarding selects the destination's tag. A
/// tag-only copy cannot be forwarded again and is therefore omitted.
/// Starfish-RBC carriers are authentication-free and remain forwardable: the
/// separate RBC service, rather than the carrier, controls clean admission.
pub(crate) fn prepare_forwarded_blocks_for_peer(
    authentication_scheme: BlockAuthenticationScheme,
    consensus_protocol: ConsensusProtocol,
    recipient: AuthorityIndex,
    blocks: Vec<Data<VerifiedBlock>>,
) -> Vec<Data<VerifiedBlock>> {
    if authentication_scheme != BlockAuthenticationScheme::MacVector
        || consensus_protocol.is_starfish_rbc()
    {
        return blocks;
    }

    blocks
        .into_iter()
        .filter_map(|block| {
            block
                .with_recipient_mac(recipient)
                .map(Data::new)
                .or_else(|| {
                    tracing::debug!(
                        "Cannot forward MAC-authenticated block {} to authority {}: \
                         complete MAC vector is unavailable",
                        block.reference(),
                        recipient,
                    );
                    None
                })
        })
        .collect()
}

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

async fn run_rbc_dag_outbound_worker(
    mailbox: RbcDagOutboundMailboxV1,
    proactive_sender: mpsc::Sender<NetworkMessage>,
    priority_sender: mpsc::Sender<NetworkMessage>,
    mut outbound_failure: watch::Receiver<Option<String>>,
) -> Result<(), RbcDagOutboundMailboxErrorV1> {
    loop {
        if let Some(reason) = outbound_failure.borrow().clone() {
            return Err(RbcDagOutboundMailboxErrorV1::Failed(reason));
        }
        let next = tokio::select! {
            biased;
            changed = outbound_failure.changed() => {
                if changed.is_err() {
                    return Err(RbcDagOutboundMailboxErrorV1::DownstreamClosed);
                }
                continue;
            }
            next = mailbox.recv() => next,
        };
        let Some((class, message)) = next else {
            let state = mailbox.inner.state.lock();
            return match &state.failure {
                Some(reason) => Err(RbcDagOutboundMailboxErrorV1::Failed(reason.clone())),
                None => Ok(()),
            };
        };
        let result = match class {
            RbcDagOutboundClassV1::Priority => priority_sender.try_send(message),
            RbcDagOutboundClassV1::Proactive => proactive_sender.try_send(message),
        };
        match result {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(RbcDagOutboundMailboxErrorV1::DownstreamSaturated(class));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(RbcDagOutboundMailboxErrorV1::DownstreamClosed);
            }
        }
    }
}

async fn broadcast_sailfish_cert_messages(
    senders: &[mpsc::Sender<NetworkMessage>],
    cert_messages: &[crate::types::CertMessage],
) {
    if cert_messages.is_empty() {
        return;
    }

    if cert_messages.len() == 1 {
        let cert_message = cert_messages[0].clone();
        for sender in senders {
            send_network_message_reliably(
                sender,
                NetworkMessage::CertMessage(cert_message.clone()),
            )
            .await;
        }
        return;
    }

    let cert_batch = cert_messages.to_vec();
    for sender in senders {
        send_network_message_reliably(sender, NetworkMessage::CertBatch(cert_batch.clone())).await;
    }
}

fn select_random_peers<R>(
    mut candidates: Vec<AuthorityIndex>,
    max_peers: usize,
    rng: &mut R,
) -> Vec<AuthorityIndex>
where
    R: rand::Rng + ?Sized,
{
    candidates.shuffle(rng);
    candidates.truncate(candidates.len().min(max_peers));
    candidates
}

fn select_random_peer_senders<H, C>(
    inner: &Arc<NetworkSyncerInner<H, C>>,
    max_peers: usize,
) -> Vec<(AuthorityIndex, mpsc::Sender<NetworkMessage>)>
where
    H: BlockHandler,
    C: CommitObserver,
{
    let peer_senders = inner.peer_senders.read();
    let candidates = select_random_peers(
        peer_senders.keys().copied().collect(),
        max_peers,
        &mut rand::thread_rng(),
    );
    candidates
        .into_iter()
        .filter_map(|authority| {
            peer_senders
                .get(&authority)
                .map(|sender| (authority, sender.clone()))
        })
        .collect()
}

fn eligible_missing_parent_refs(
    missing_refs: &[BlockReference],
    first_seen: &mut AHashMap<BlockReference, Instant>,
    last_requested: &mut AHashMap<BlockReference, Instant>,
    now: Instant,
    retry_interval: Duration,
) -> Vec<BlockReference> {
    let pending: AHashSet<_> = missing_refs.iter().copied().collect();
    first_seen.retain(|block_ref, _| pending.contains(block_ref));
    last_requested.retain(|block_ref, _| pending.contains(block_ref));

    missing_refs
        .iter()
        .filter_map(|block_ref| {
            let first = first_seen.entry(*block_ref).or_insert(now);
            if now.duration_since(*first) < retry_interval {
                return None;
            }
            if let Some(last) = last_requested.get(block_ref) {
                if now.duration_since(*last) < retry_interval {
                    return None;
                }
            }
            Some(*block_ref)
        })
        .collect()
}

struct FilterForBlocks {
    digests: parking_lot::RwLock<AHashSet<BlockDigest>>,
    full_mac_vectors: parking_lot::RwLock<AHashSet<BlockDigest>>,
    queue: parking_lot::RwLock<VecDeque<BlockDigest>>,
}

impl FilterForBlocks {
    fn new() -> Self {
        Self {
            digests: parking_lot::RwLock::new(AHashSet::new()),
            full_mac_vectors: parking_lot::RwLock::new(AHashSet::new()),
            queue: parking_lot::RwLock::new(VecDeque::new()),
        }
    }

    fn contains_batch(&self, digests: &[BlockDigest]) -> Vec<bool> {
        let set = self.digests.read();
        digests.iter().map(|d| set.contains(d)).collect()
    }

    fn contains_full_mac_batch(&self, digests: &[BlockDigest]) -> Vec<bool> {
        let set = self.full_mac_vectors.read();
        digests.iter().map(|d| set.contains(d)).collect()
    }

    fn insert_batch(&self, blocks: &[(BlockDigest, bool)]) {
        let mut digests = self.digests.write();
        let mut full_mac_vectors = self.full_mac_vectors.write();
        let mut queue = self.queue.write();

        for (digest, has_full_mac_vector) in blocks {
            if digests.insert(*digest) {
                queue.push_back(*digest);
            }
            if *has_full_mac_vector {
                full_mac_vectors.insert(*digest);
            }
        }

        while queue.len() > MAX_FILTER_SIZE {
            if let Some(removed) = queue.pop_front() {
                digests.remove(&removed);
                full_mac_vectors.remove(&removed);
            }
        }
    }

    /// Inserts all verified copies and returns `true` for each copy that adds
    /// either a new block reference or the first full MAC vector for a
    /// previously recipient-tag-only reference.
    fn insert_and_report_useful(&self, blocks: &[(BlockDigest, bool)]) -> Vec<bool> {
        let mut set = self.digests.write();
        let mut full_mac_vectors = self.full_mac_vectors.write();
        let mut queue = self.queue.write();

        let is_useful: Vec<bool> = blocks
            .iter()
            .map(|(digest, has_full_mac_vector)| {
                let is_new = set.insert(*digest);
                if is_new {
                    queue.push_back(*digest);
                }
                let is_mac_upgrade = *has_full_mac_vector && full_mac_vectors.insert(*digest);
                is_new || is_mac_upgrade
            })
            .collect();

        while queue.len() > MAX_FILTER_SIZE {
            if let Some(removed) = queue.pop_front() {
                set.remove(&removed);
                full_mac_vectors.remove(&removed);
            }
        }
        is_useful
    }

    /// For each header, returns `true` if it is either unseen or upgrades a
    /// previously seen recipient-only MAC to a full vector.
    fn needed_headers(&self, batch: &[(BlockDigest, bool)]) -> Vec<bool> {
        let digests = self.digests.read();
        let full_mac_vectors = self.full_mac_vectors.read();
        let mut seen_in_batch = AHashMap::with_capacity(batch.len());

        batch
            .iter()
            .map(|(digest, has_full_mac_vector)| {
                let was_seen = digests.contains(digest) || seen_in_batch.contains_key(digest);
                let had_full_mac_vector = seen_in_batch
                    .get(digest)
                    .copied()
                    .unwrap_or_else(|| full_mac_vectors.contains(digest));
                let is_needed = !was_seen || (*has_full_mac_vector && !had_full_mac_vector);
                seen_in_batch
                    .entry(*digest)
                    .and_modify(|full| *full |= *has_full_mac_vector)
                    .or_insert(*has_full_mac_vector);
                is_needed
            })
            .collect()
    }
}

#[derive(Clone, Copy)]
struct ShardStatus {
    count: usize,
    bitmap: AuthoritySet,
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
                    && !status.bitmap.contains(shard_index as AuthorityIndex)
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
                    bitmap: AuthoritySet::default(),
                    full_block_received: false,
                }
            });
            let authority = shard_index as AuthorityIndex;
            if !entry.bitmap.contains(authority) {
                entry.bitmap.insert(authority);
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
                    bitmap: AuthoritySet::default(),
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

/// Spawn the per-connection worker task that drains raw shard payloads,
/// verifies their merkle proofs, applies the dedup filter, and forwards the
/// surviving shards to the global shard reconstructor. Running off the
/// connection's main loop keeps verification work off the path that handles
/// the next incoming network message.
fn spawn_standalone_shard_worker<H: BlockHandler + 'static, C: CommitObserver + 'static>(
    mut rx: mpsc::UnboundedReceiver<Vec<ShardPayload>>,
    inner: Arc<NetworkSyncerInner<H, C>>,
    filter_for_shards: Arc<FilterForShards>,
    metrics: Arc<Metrics>,
    committee_size: usize,
    peer: String,
) {
    tokio::spawn(async move {
        while let Some(shards) = rx.recv().await {
            let maybe_tx = inner.shard_tx.lock().clone();
            let Some(shard_tx) = maybe_tx else { continue };

            let mut verified: Vec<(BlockReference, ShardMessage, usize)> =
                Vec::with_capacity(shards.len());
            for payload in shards {
                let shard_index = payload.shard.shard_index();
                if !filter_for_shards.needed(&payload.block_reference.digest, shard_index) {
                    metrics.filtered_shards_total.inc();
                    continue;
                }
                if !payload.shard.verify(committee_size) {
                    tracing::warn!(
                        "Standalone shard for {:?} from {} failed Merkle proof — dropped",
                        payload.block_reference,
                        peer
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

            let filter_entries: Vec<_> = verified
                .iter()
                .map(|(r, _, idx)| (r.digest, *idx))
                .collect();
            filter_for_shards.add_batch(&filter_entries);

            let batch: Vec<_> = verified.into_iter().map(|(_, msg, _)| msg).collect();
            if !batch.is_empty() {
                let _ = shard_tx.send(batch);
            }
        }
    });
}

/// Spawn the per-connection worker task that drains header-only block
/// batches, verifies them, and inserts them into the local DAG. Running off
/// the connection's main loop keeps verify + `add_headers` work off the path
/// that handles the next incoming network message.
fn spawn_header_worker<H: BlockHandler + 'static, C: CommitObserver + 'static>(
    mut rx: mpsc::UnboundedReceiver<(Vec<Data<VerifiedBlock>>, DataSource)>,
    inner: Arc<NetworkSyncerInner<H, C>>,
    filter_for_blocks: Arc<FilterForBlocks>,
    metrics: Arc<Metrics>,
    sender: mpsc::Sender<NetworkMessage>,
    bls_service: Option<BlsServiceHandle>,
    consensus_protocol: ConsensusProtocol,
    peer: String,
    peer_id: AuthorityIndex,
    own_id: AuthorityIndex,
) {
    tokio::spawn(async move {
        let mut encoder = ReedSolomonEncoder::new(2, 4, 2).expect("Encoder should be created");
        while let Some((blocks, source)) = rx.recv().await {
            let connection_knowledge = inner.cordial_knowledge.connection_knowledge(peer_id);
            let incoming_headers: Vec<_> = blocks
                .iter()
                .map(|block| (block.digest(), block.has_full_mac_vector()))
                .collect();
            let needed_before_verify = filter_for_blocks.needed_headers(&incoming_headers);
            let mut verified_blocks: Vec<VerifiedBlock> = Vec::new();

            for (data_block, is_needed) in blocks.into_iter().zip(needed_before_verify) {
                if !is_needed {
                    metrics.filtered_blocks_total.inc();
                    continue;
                }
                let mut block: VerifiedBlock = (*data_block).clone();
                tracing::debug!("Received {} from {}", block, peer);
                if let Err(e) = verify_mac_transport(
                    &block,
                    inner.dag_state.block_authentication_scheme,
                    peer_id,
                    source,
                ) {
                    tracing::warn!(
                        "Rejected incorrectly transported block {} from {}: {:?}",
                        block.reference(),
                        peer,
                        e
                    );
                    break;
                }
                match block.verify_with_authentication(
                    &inner.committee,
                    own_id as usize,
                    peer_id as usize,
                    &mut encoder,
                    consensus_protocol,
                    inner.dag_state.block_authentication_scheme,
                    &inner.mac_keys,
                ) {
                    Ok(shard) => {
                        debug_assert!(shard.is_none(), "shard must be None for header-only blocks")
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Rejected incorrect block {} from {}: {:?}",
                            block.reference(),
                            peer,
                            e
                        );
                        break;
                    }
                };
                verified_blocks.push(block);
            }

            if let Some(ck) = connection_knowledge.as_ref() {
                let refs: Vec<_> = verified_blocks.iter().map(|b| *b.reference()).collect();
                let mut ck = ck.write();
                ck.mark_headers_useful_from_peer(&refs);
            }

            let filter_entries: Vec<_> = verified_blocks
                .iter()
                .map(|block| (block.digest(), block.has_full_mac_vector()))
                .collect();
            let is_useful = filter_for_blocks.insert_and_report_useful(&filter_entries);
            let mut new_data_blocks = Vec::new();
            for (storage_block, is_useful) in verified_blocks.into_iter().zip(is_useful) {
                if is_useful {
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
                "To be processed after verification from {:?}, source={}, {} new \
                 blocks without transactions {:?}",
                peer,
                source,
                new_data_blocks.len(),
                new_data_blocks
            );
            if new_data_blocks.is_empty() {
                continue;
            }

            if let Some(ref bls) = bls_service {
                bls.send(BlsServiceMessage::ProcessBlocks(new_data_blocks.clone()));
            }
            let header_refs = new_data_blocks
                .iter()
                .map(|block| *block.reference())
                .collect();
            inner
                .cordial_knowledge
                .send(CordialKnowledgeMessage::DagParts {
                    headers: header_refs,
                    shards: Vec::new(),
                });
            // Note: shard usefulness is no longer derived from header
            // arrival. Headers are too noisy a trigger — push-mode
            // disseminates the entire causal cone, lighting up every
            // authority in the bitmask. Instead, the
            // `UsefulShardsFromPeers` signal fires only when this
            // validator sends a `MissingTxDataRequest` (see
            // `BlockDisseminator::request_missing_data_blocks` in
            // broadcaster.rs), which reflects real outstanding demand.
            let (missing_parents, processed_additional_refs) =
                inner.syncer.add_headers(new_data_blocks, source).await;
            if !missing_parents.is_empty() {
                let missing_parents = missing_parents.iter().copied().collect::<Vec<_>>();
                tracing::debug!(
                    "Make request missing parents of header/shard blocks {:?} \
                     from peer {:?} after source={}",
                    missing_parents,
                    peer,
                    source
                );
                metrics
                    .block_sync_requests_sent
                    .with_label_values(&[&peer_id.to_string()])
                    .inc();
                sender
                    .send(NetworkMessage::MissingParentsRequest(missing_parents))
                    .await
                    .ok();
            }
            metrics
                .used_additional_blocks_total
                .inc_by(processed_additional_refs.len() as u64);
        }
    });
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
    peer: String,
    own_id: AuthorityIndex,
    sender: mpsc::Sender<NetworkMessage>,
    /// Hand-off channel into the per-connection standalone-shard worker
    /// task. The main connection loop fires raw shard payloads here and
    /// returns immediately; the worker verifies merkle proofs and forwards
    /// to the global shard reconstructor.
    standalone_shard_tx: mpsc::UnboundedSender<Vec<ShardPayload>>,
    /// Hand-off channel into the per-connection header worker task. The
    /// main connection loop fires header-only block batches here and
    /// returns immediately; the worker verifies, filters, and inserts
    /// the headers into the DAG.
    header_tx: mpsc::UnboundedSender<(Vec<Data<VerifiedBlock>>, DataSource)>,
    bls_service: Option<BlsServiceHandle>,
    sailfish_service: Option<SailfishServiceHandle>,
    starfish_rbc_service: Option<RbcServiceHandle>,
    starfish_rbc_dag_shadow_service: Option<StarfishRbcDagShadowServiceHandleV1>,
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
        let starfish_rbc_service = inner.starfish_rbc_service.clone();
        let starfish_rbc_dag_shadow_service = inner.starfish_rbc_dag_shadow_service.clone();
        let peer = format_authority_index(peer_id);

        let (standalone_shard_tx, standalone_shard_rx) = mpsc::unbounded_channel();
        spawn_standalone_shard_worker(
            standalone_shard_rx,
            inner.clone(),
            filter_for_shards.clone(),
            metrics.clone(),
            committee_size,
            peer.clone(),
        );

        let (header_tx, header_rx) = mpsc::unbounded_channel();
        spawn_header_worker(
            header_rx,
            inner.clone(),
            filter_for_blocks.clone(),
            metrics.clone(),
            connection.sender.clone(),
            bls_service.clone(),
            consensus_protocol,
            peer.clone(),
            peer_id,
            own_id,
        );

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
            standalone_shard_tx,
            header_tx,
            bls_service,
            sailfish_service,
            starfish_rbc_service,
            starfish_rbc_dag_shadow_service,
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
        if !self.inner.embedded_rbc_authority
            && matches!(
                self.consensus_protocol,
                ConsensusProtocol::Starfish
                    | ConsensusProtocol::StarfishRbc
                    | ConsensusProtocol::StarfishSpeed
                    | ConsensusProtocol::StarfishBls
                    | ConsensusProtocol::SparseStarfishSpeed
            )
        {
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
                if self.inner.embedded_rbc_authority {
                    tracing::warn!(
                        peer = self.peer_id,
                        "Rejected generic block batch while embedded RBC-DAG authority is active"
                    );
                } else {
                    self.handle_batch(*blocks).await;
                }
            }
            NetworkMessage::MissingParentsRequest(refs) => {
                if self.inner.embedded_rbc_authority {
                    tracing::debug!(
                        peer = self.peer_id,
                        count = refs.len(),
                        "Ignored legacy missing-parent request in standalone RBC-DAG mode"
                    );
                    return true;
                }
                return self.handle_missing_parents_request(refs).await;
            }
            NetworkMessage::MissingTxDataRequest(refs) => {
                if self.inner.embedded_rbc_authority {
                    tracing::debug!(
                        peer = self.peer_id,
                        count = refs.len(),
                        "Ignored legacy transaction-data request in standalone RBC-DAG mode"
                    );
                    return true;
                }
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
            NetworkMessage::CertBatch(messages) => {
                tracing::debug!(
                    "Received Sailfish cert batch from peer {} with {} messages",
                    self.peer_id,
                    messages.len(),
                );
                for message in messages {
                    if message.sender != self.peer_id {
                        tracing::debug!(
                            "Rejected CertBatch message: sender {} != peer {}",
                            message.sender,
                            self.peer_id,
                        );
                        continue;
                    }
                    if let Some(ref sf) = self.sailfish_service {
                        sf.send(SailfishServiceMessage::CertMessage(message));
                    }
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
            NetworkMessage::UnprovableCertificateRequest {
                leader_ref,
                known_voters,
            } => {
                return self
                    .handle_unprovable_cert_request(leader_ref, known_voters)
                    .await;
            }
            NetworkMessage::RoundGapRequest {
                round,
                known_authorities,
            } => {
                return self
                    .handle_round_gap_request(round, known_authorities)
                    .await;
            }
            NetworkMessage::RbcInitial(proposal) => {
                if let Some(ref rbc) = self.starfish_rbc_service {
                    if let Err(error) = rbc.direct_initial(self.peer_id, proposal) {
                        tracing::warn!("Failed to forward Starfish-RBC INIT: {error}");
                    }
                }
            }
            NetworkMessage::RbcPhase(message) => {
                if let Some(ref rbc) = self.starfish_rbc_service {
                    if let Err(error) = rbc.phase(self.peer_id, message) {
                        tracing::warn!("Failed to forward Starfish-RBC phase: {error}");
                    }
                }
            }
            NetworkMessage::RbcHeaderRequest(block_ref) => {
                if let Some(ref rbc) = self.starfish_rbc_service {
                    if let Err(error) = rbc.header_request(self.peer_id, block_ref) {
                        tracing::warn!("Failed to forward Starfish-RBC header request: {error}");
                    }
                }
            }
            NetworkMessage::RbcHeaderResponse(header) => {
                if let Some(ref rbc) = self.starfish_rbc_service {
                    if let Err(error) = rbc.header_response(self.peer_id, header) {
                        tracing::warn!("Failed to forward Starfish-RBC header response: {error}");
                    }
                }
            }
            NetworkMessage::RbcDagShadowCarrier(envelope) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow.carrier_reliably(self.peer_id, envelope).await {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!("Failed to forward RBC-DAG shadow carrier: {error}");
                    }
                }
            }
            NetworkMessage::RbcDagShadowCarrierRequest(reference) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow
                        .carrier_request_reliably(self.peer_id, reference)
                        .await
                    {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!("Failed to forward RBC-DAG shadow request: {error}");
                    }
                }
            }
            NetworkMessage::RbcDagShadowCarrierResponse(response) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow
                        .carrier_response_reliably(self.peer_id, response)
                        .await
                    {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!("Failed to forward RBC-DAG shadow response: {error}");
                    }
                }
            }
            NetworkMessage::RbcDagShadowCarrierEnvelopeResponse(response) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow
                        .carrier_envelope_response_reliably(self.peer_id, response)
                        .await
                    {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!(
                            "Failed to forward RBC-DAG shadow envelope response: {error}"
                        );
                    }
                }
            }
            NetworkMessage::RbcDagShadowCarrierSyncRequest(request) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow
                        .carrier_sync_request_reliably(self.peer_id, request)
                        .await
                    {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!(
                            "Failed to forward RBC-DAG shadow carrier sync request: {error}"
                        );
                    }
                }
            }
            NetworkMessage::RbcDagShadowCarrierSyncResponse(response) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow
                        .carrier_sync_response_reliably(self.peer_id, response)
                        .await
                    {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!(
                            "Failed to forward RBC-DAG shadow carrier sync response: {error}"
                        );
                    }
                }
            }
            NetworkMessage::RbcDagApplicationPayloadRequest(application) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow
                        .application_payload_request_reliably(self.peer_id, application)
                        .await
                    {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!(
                            ?application,
                            peer = self.peer_id,
                            "Failed to forward RBC-DAG application-payload request: {error}"
                        );
                    }
                }
            }
            NetworkMessage::RbcDagApplicationPayloadResponse(response) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow
                        .application_payload_response_reliably(self.peer_id, response)
                        .await
                    {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!(
                            peer = self.peer_id,
                            "Failed to forward RBC-DAG application-payload response: {error}"
                        );
                    }
                }
            }
        }
        true
    }

    async fn handle_subscribe(&mut self, round: RoundNumber) {
        self.inner.syncer.peer_subscribed(self.peer_id).await;
        self.inner
            .cordial_knowledge
            .send(CordialKnowledgeMessage::ResetPeerKnown {
                peer: self.peer_id,
                after_round: round,
            });
        if self.inner.embedded_rbc_authority {
            // Application headers and payloads are disseminated exclusively
            // by authenticated carrier events in standalone mode.
            return;
        }
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

        tracing::debug!(
            "Received batch from peer {:?}: source={}, full_blocks={}, headers={}, shards={}",
            self.peer,
            source,
            full_blocks.len(),
            headers.len(),
            shards.len()
        );

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
        if !useful_headers_authors.is_empty() || !useful_shards_authors.is_empty() {
            let max_round = full_blocks
                .iter()
                .chain(headers.iter())
                .map(|b| b.round())
                .chain(shards.iter().map(|payload| payload.block_reference.round))
                .max()
                .unwrap_or(0);
            self.inner
                .cordial_knowledge
                .send(CordialKnowledgeMessage::UsefulAuthors(Box::new(
                    UsefulAuthorsMessage {
                        peer: self.peer_id,
                        headers: useful_headers_authors,
                        shards: useful_shards_authors,
                        round: max_round,
                    },
                )));
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
                | ConsensusProtocol::SailfishPlusPlus
                | ConsensusProtocol::Bluestreak
                | ConsensusProtocol::MysticetiBls => {
                    blocks_with_transactions.push(block);
                }
                ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishRbc
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
                | ConsensusProtocol::SparseStarfishSpeed => {
                    if block.transactions().is_some() {
                        blocks_with_transactions.push(block);
                    } else {
                        blocks_without_transactions.push(block);
                    }
                }
            }
        }

        // Process full blocks first.
        self.process_full_blocks(blocks_with_transactions, source)
            .await;

        // Header-only blocks are only valid for Starfish erasure-coding
        // variants. SailfishPlusPlus and Mysticeti require full blocks;
        // reject any headers a peer may have sent. Hand the header batch
        // off to the per-connection header worker so the main connection
        // loop does not block on verify / DAG insertion.
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishRbc
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
                | ConsensusProtocol::SparseStarfishSpeed
        ) {
            blocks_without_transactions.extend(headers);
            if !blocks_without_transactions.is_empty() {
                let header_source = match source {
                    DataSource::BlockBundleStreaming => DataSource::BlockBundleStreamingHeader,
                    other => other,
                };
                let _ = self
                    .header_tx
                    .send((blocks_without_transactions, header_source));
            }
        } else if !headers.is_empty() {
            tracing::warn!(
                "Rejecting {} header-only blocks from peer {} \
                 (not supported by {:?})",
                headers.len(),
                self.peer_id,
                self.consensus_protocol,
            );
        }

        // Process standalone shards last so that any full blocks that
        // landed above can cancel in-flight reconstruction work via
        // ShardMessage::FullBlock before we accumulate more shards. The
        // verification + forwarding happens on a per-connection worker
        // task so the main connection loop does not block on merkle
        // proof checks.
        if !shards.is_empty() {
            let _ = self.standalone_shard_tx.send(shards);
        }

        drop(timer);
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
        let full_mac_known = self
            .filter_for_blocks
            .contains_full_mac_batch(&incoming_digests);
        let shard_full = self.filter_for_shards.has_full_batch(&incoming_digests);

        // --- verify loop (no lock acquisitions) ---
        let mut verified: Vec<(VerifiedBlock, Option<ProvableShard>)> = Vec::new();
        for (index, data_block) in blocks.into_iter().enumerate() {
            let bk = block_known[index];
            let sf = shard_full[index];
            let incoming_has_full_mac = data_block.has_full_mac_vector();
            if bk && sf && (!incoming_has_full_mac || full_mac_known[index]) {
                self.metrics.filtered_blocks_total.inc();
                continue;
            }
            let mut block: VerifiedBlock = (*data_block).clone();
            tracing::debug!("Received {} from {}", block, self.peer);
            if let Err(e) = verify_mac_transport(
                &block,
                self.inner.dag_state.block_authentication_scheme,
                self.peer_id,
                source,
            ) {
                tracing::warn!(
                    "Rejected incorrectly transported block {} from {}: {:?}",
                    block.reference(),
                    self.peer,
                    e
                );
                break;
            }
            let shard = match block.verify_with_authentication(
                &self.inner.committee,
                self.own_id as usize,
                self.peer_id as usize,
                &mut self.encoder,
                self.consensus_protocol,
                self.inner.dag_state.block_authentication_scheme,
                &self.inner.mac_keys,
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
        let verified_filter_entries: Vec<_> = verified
            .iter()
            .map(|(block, _)| (block.digest(), block.has_full_mac_vector()))
            .collect();
        let verified_digests: Vec<_> = verified_filter_entries
            .iter()
            .map(|(digest, _)| *digest)
            .collect();
        self.filter_for_blocks
            .insert_batch(&verified_filter_entries);
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
                let _ = shard_tx.send(full_block_msgs);
            }
        }

        tracing::debug!(
            "To be processed after verification from {:?}, source={}, {} \
             blocks with transactions {:?}",
            self.peer,
            source,
            verified_data_blocks.len(),
            verified_data_blocks
        );
        if verified_data_blocks.is_empty() {
            return;
        }
        // Send block copies to BLS service for signature verification.
        if let Some(ref bls) = self.bls_service {
            bls.send(BlsServiceMessage::ProcessBlocks(
                verified_data_blocks.clone(),
            ));
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
                "Missing parents when processing block from peer {:?} after source={}: {:?}",
                self.peer,
                source,
                missing_parents
            );
            let missing_parents_vec = missing_parents.iter().copied().collect::<Vec<_>>();
            tracing::debug!(
                "Make request missing parents of blocks {:?} from peer \
                 {:?} after source={}",
                missing_parents_vec,
                self.peer,
                source
            );
            self.metrics
                .block_sync_requests_sent
                .with_label_values(&[&self.peer_id.to_string()])
                .inc();
            self.sender
                .send(NetworkMessage::MissingParentsRequest(missing_parents_vec))
                .await
                .ok();
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
                | ConsensusProtocol::MysticetiBls
                | ConsensusProtocol::CordialMiners
                | ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
                | ConsensusProtocol::SailfishPlusPlus
                | ConsensusProtocol::Bluestreak
                | ConsensusProtocol::SparseStarfishSpeed
                | ConsensusProtocol::StarfishRbc
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
            let available = self
                .inner
                .dag_state
                .get_storage_blocks(&block_references)
                .into_iter()
                .flatten()
                .count();
            let unavailable = block_references.len().saturating_sub(available);
            tracing::debug!(
                "MissingParentsRequest stats for peer {:?}: requested={}, \
                 available={}, unavailable={}, serving_allowed={}",
                self.peer,
                block_references.len(),
                available,
                unavailable,
                self.inner.dag_state.byzantine_strategy.is_none()
            );
            if self.inner.dissemination_mode == DisseminationMode::PushUseful {
                if let Some(ck) = self
                    .inner
                    .cordial_knowledge
                    .connection_knowledge(self.peer_id)
                {
                    let mut ck = ck.write();
                    let mut useful_headers_mask = AuthoritySet::default();
                    for block_ref in &block_references {
                        useful_headers_mask.insert(block_ref.authority);
                    }
                    if !useful_headers_mask.is_empty() {
                        let current_round = self.inner.dag_state.highest_round();
                        ck.update_useful_authors_to_peer(
                            useful_headers_mask,
                            AuthoritySet::default(),
                            current_round,
                        );
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
                | ConsensusProtocol::SparseStarfishSpeed
                | ConsensusProtocol::StarfishRbc
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

    /// Respond with voting blocks for a Bluestreak unprovable certificate.
    /// Returns `true` to continue, `false` to break the connection loop.
    async fn handle_unprovable_cert_request(
        &mut self,
        leader_ref: BlockReference,
        known_voters: AuthoritySet,
    ) -> bool {
        if self.consensus_protocol != ConsensusProtocol::Bluestreak {
            return true;
        }
        // Voting blocks live at leader_ref.round + 1 and reference the leader.
        let voting_round = leader_ref.round + 1;
        let voting_blocks = self.inner.dag_state.get_blocks_by_round(voting_round);
        let missing: Vec<_> = voting_blocks
            .into_iter()
            .filter(|b| {
                !known_voters.contains(b.authority()) && b.block_references().contains(&leader_ref)
            })
            .collect();
        let missing = prepare_forwarded_blocks_for_peer(
            self.inner.dag_state.block_authentication_scheme,
            self.consensus_protocol,
            self.peer_id,
            missing,
        );
        tracing::debug!(
            "UnprovableCertificateRequest from peer {:?} for leader {}: \
             known_voters={}, serving_blocks={}",
            self.peer,
            leader_ref,
            known_voters.count_ones(),
            missing.len()
        );
        if missing.is_empty() {
            return true;
        }
        let batch = BlockBatch::full_only(DataSource::UnprovableCertificateResponse, missing);
        self.sender
            .send(NetworkMessage::Batch(Box::new(batch)))
            .await
            .ok()
            .is_some()
    }

    /// Respond with blocks at the requested round that the requester doesn't
    /// yet have. Returns `true` to continue, `false` to break the connection
    /// loop.
    async fn handle_round_gap_request(
        &mut self,
        round: RoundNumber,
        known_authorities: AuthoritySet,
    ) -> bool {
        if !self.consensus_protocol.uses_compressed_refs() {
            return true;
        }
        let blocks = self.inner.dag_state.get_blocks_by_round(round);
        let missing: Vec<_> = blocks
            .into_iter()
            .filter(|b| !known_authorities.contains(b.authority()))
            .collect();
        let missing = prepare_forwarded_blocks_for_peer(
            self.inner.dag_state.block_authentication_scheme,
            self.consensus_protocol,
            self.peer_id,
            missing,
        );
        if missing.is_empty() {
            return true;
        }
        tracing::debug!(
            "RoundGapRequest from peer {:?} for round {}: \
             known_authorities={}, serving_blocks={}",
            self.peer,
            round,
            known_authorities.count_ones(),
            missing.len()
        );
        let batch = BlockBatch::full_only(DataSource::RoundGapResponse, missing);
        self.sender
            .send(NetworkMessage::Batch(Box::new(batch)))
            .await
            .ok()
            .is_some()
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
    rbc_event_task: Option<JoinHandle<()>>,
    rbc_service_task: Option<JoinHandle<()>>,
    rbc_dag_shadow_event_task: Option<JoinHandle<()>>,
    rbc_dag_core_control_task: Option<JoinHandle<()>>,
    rbc_dag_assignment_task: Option<JoinHandle<()>>,
    rbc_dag_shadow_service_task: Option<JoinHandle<()>>,
    rbc_dag_clock_bridge_state: Option<watch::Receiver<RbcDagClockBridgeStateV1>>,
    cordial_knowledge_task: JoinHandle<()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RbcDagClockBridgeStateV1 {
    Pending,
    Failed,
    Activated,
}

type RbcDagPayloadVerificationTaskV1 =
    JoinHandle<Result<eyre::Result<ReconstructedTransactionData>, tokio::task::JoinError>>;

enum RbcDagAuthorizedPayloadV1 {
    None,
    AlreadyAvailable(Option<Arc<TransactionData>>),
    Verify(RbcDagPayloadVerificationTaskV1),
}

enum RbcDagCoreControlCommandV1 {
    AuthorizedApplicationObserved {
        carrier: BlockReference,
        header: RbcCanonicalHeader,
        authorization_basis: ShadowApplicationAuthorizationBasisV1,
        payload: RbcDagAuthorizedPayloadV1,
    },
    Frontier(CommittedFrontierDeltaV1),
    /// Every recovery application and frontier preceding this marker must be
    /// fully applied before activation is legal.
    Ready,
    Activate,
    /// Intentional end-of-stream marker. A sender disappearing without this
    /// marker is an authoritative runtime failure.
    Drain,
}

enum RbcDagApplicationAssignmentCommandV1 {
    Assigned(BlockReference),
    Drain,
}

#[derive(Default)]
struct RbcDagCoreControlGateV1 {
    startup_ready: bool,
    clean_drain: bool,
}

impl RbcDagCoreControlGateV1 {
    fn record_ready(&mut self) {
        self.startup_ready = true;
    }

    fn activation_allowed(&self) -> bool {
        self.startup_ready
    }

    fn record_clean_drain(&mut self) {
        self.clean_drain = true;
    }
}

async fn wait_for_rbc_dag_clock_bridge_activation(
    bridge_state: &mut watch::Receiver<RbcDagClockBridgeStateV1>,
) -> Result<(), String> {
    loop {
        match *bridge_state.borrow_and_update() {
            RbcDagClockBridgeStateV1::Pending => {}
            RbcDagClockBridgeStateV1::Failed => {
                return Err(
                    "RBC-DAG startup recovery was invalid before Core clock activation".to_string(),
                );
            }
            RbcDagClockBridgeStateV1::Activated => return Ok(()),
        }
        bridge_state
            .changed()
            .await
            .map_err(|_| "RBC-DAG event bridge stopped before Core clock activation".to_string())?;
    }
}

fn fail_rbc_dag_clock_bridge(bridge_tx: Option<&watch::Sender<RbcDagClockBridgeStateV1>>) {
    if let Some(bridge_tx) = bridge_tx {
        // Failure is permanently terminal, including after a caller already
        // observed activation. No later authority command may reach Core.
        bridge_tx.send_if_modified(|state| {
            if *state != RbcDagClockBridgeStateV1::Failed {
                *state = RbcDagClockBridgeStateV1::Failed;
                true
            } else {
                false
            }
        });
    }
}

fn rbc_dag_clock_bridge_failed(
    bridge_tx: Option<&watch::Sender<RbcDagClockBridgeStateV1>>,
) -> bool {
    bridge_tx.is_some_and(|bridge_tx| *bridge_tx.borrow() == RbcDagClockBridgeStateV1::Failed)
}

pub(crate) struct NetworkSyncSignals {
    block_ready_notify: Arc<Notify>,
    proposal_round_notify: Arc<Notify>,
}

pub struct NetworkSyncerInner<H: BlockHandler, C: CommitObserver> {
    syncer: CoreThreadDispatcher<H, NetworkSyncSignals, C>,
    pub dag_state: DagState,
    pub block_ready_notify: Arc<Notify>,
    pub proposal_round_notify: Arc<Notify>,
    pub committee: Arc<Committee>,
    pub mac_keys: Arc<Vec<MacKey>>,
    pub dissemination_mode: DisseminationMode,
    pub causal_push_shard_round_lag: RoundNumber,
    stop: mpsc::Sender<()>,
    pub gc_round: Arc<AtomicU32>,
    pub shard_tx: parking_lot::Mutex<
        Option<mpsc::UnboundedSender<Vec<crate::shard_reconstructor::ShardMessage>>>,
    >,
    pub cordial_knowledge: CordialKnowledgeHandle,
    /// Per-peer message senders for direct unicast (e.g. DAC partial sigs).
    pub peer_senders: parking_lot::RwLock<AHashMap<AuthorityIndex, mpsc::Sender<NetworkMessage>>>,
    /// Nonblocking ingress to per-connection RBC outbound workers. Keeping
    /// these queues separate prevents one backpressured peer from delaying
    /// another peer or the actor's local HeaderStaged/Delivered effects.
    rbc_peer_senders:
        parking_lot::RwLock<AHashMap<AuthorityIndex, mpsc::UnboundedSender<NetworkMessage>>>,
    /// Bounded, keyed RBC-DAG transport mailboxes. Exact repair is admitted
    /// independently of proactive carrier fan-out and drains first.
    rbc_dag_peer_mailboxes: parking_lot::RwLock<AHashMap<AuthorityIndex, RbcDagOutboundMailboxV1>>,
    pub leader_timeout: Duration,
    pub soft_block_timeout: Duration,
    metrics: Arc<Metrics>,
    rbc_dag_clock_bridge_tx: Option<watch::Sender<RbcDagClockBridgeStateV1>>,
    rbc_dag_shutdown_started: Arc<AtomicBool>,
    /// Sailfish++ service handle for sending control messages
    /// (timeout/no-vote). None for non-SailfishPlusPlus protocols.
    pub sailfish_handle: Option<SailfishServiceHandle>,
    /// When true, only typed carrier-authorized application ingress may reach
    /// the core. Peer-controlled block batches and legacy data-recovery paths
    /// are rejected even if their serialized `DataSource` claims authority.
    pub embedded_rbc_authority: bool,
    /// Central Starfish-RBC service. Connection workers only forward their
    /// trusted peer identity and wire payload into this single owner.
    pub(crate) starfish_rbc_service: Option<RbcServiceHandle>,
    /// Non-authoritative persisted embedded-RBC shadow. It emits only network
    /// and metric events and can never call the core dispatcher.
    pub(crate) starfish_rbc_dag_shadow_service: Option<StarfishRbcDagShadowServiceHandleV1>,
    /// Wall-clock at NetworkSyncer start; consumed by time-dependent
    /// Byzantine strategies (e.g. RampUpWithholding) to ramp behavior
    /// over a fixed schedule.
    pub start_time: std::time::Instant,
}

struct RbcDagAppliedFrontierObservationV1 {
    carrier_count: u64,
    application_count: u64,
    application_creation_times: Vec<TimestampNs>,
    commit_round_distances: CommitRoundDistanceBatch,
}

trait RbcDagCoreControlTargetV1: Send + Sync {
    async fn stage_authorized_application(
        &self,
        header: RbcCanonicalHeader,
        authorization_basis: ShadowApplicationAuthorizationBasisV1,
    ) -> Result<(), String>;

    fn restore_available_application(
        &self,
        application: BlockReference,
        payload: Option<Arc<TransactionData>>,
    ) -> Result<(), String>;

    async fn materialize_authorized_payload(
        &self,
        item: ReconstructedTransactionData,
    ) -> Result<(), String>;

    async fn apply_frontier(&self, delta: CommittedFrontierDeltaV1) -> Result<bool, String>;

    async fn activate_authority(&self) -> Result<(), String>;

    async fn apply_assignment(&self, reference: BlockReference) -> Result<(), String>;
}

impl<H: BlockHandler + 'static, C: CommitObserver + 'static> RbcDagCoreControlTargetV1
    for NetworkSyncerInner<H, C>
{
    async fn stage_authorized_application(
        &self,
        header: RbcCanonicalHeader,
        authorization_basis: ShadowApplicationAuthorizationBasisV1,
    ) -> Result<(), String> {
        let block_ref = header.reference();
        let (missing_parents, _) = self.syncer.add_authorized_rbc_dag_header(header).await;
        self.cordial_knowledge
            .send(CordialKnowledgeMessage::DagParts {
                headers: vec![block_ref],
                shards: Vec::new(),
            });
        if !missing_parents.is_empty() {
            tracing::debug!(
                ?block_ref,
                ?missing_parents,
                ?authorization_basis,
                "Authorized RBC-DAG application waits for parent materialization"
            );
        }
        Ok(())
    }

    fn restore_available_application(
        &self,
        application: BlockReference,
        payload: Option<Arc<TransactionData>>,
    ) -> Result<(), String> {
        // The actor is intentionally stopped before the authoritative FIFO is
        // drained. Core already owns this data-available block, and restart
        // recovery deterministically rehydrates the corresponding shadow
        // state, so no actor callback is required while shutting down.
        if self.rbc_dag_shutdown_started.load(Ordering::Acquire) {
            return Ok(());
        }
        let shadow = self
            .starfish_rbc_dag_shadow_service
            .as_ref()
            .ok_or_else(|| "authoritative payload callback target is unavailable".to_owned())?;
        if let Some(payload) = payload {
            shadow
                .verified_application_payload(application, payload)
                .map_err(|error| error.to_string())?;
        }
        shadow
            .application_data_available(application)
            .map_err(|error| error.to_string())
    }

    async fn materialize_authorized_payload(
        &self,
        item: ReconstructedTransactionData,
    ) -> Result<(), String> {
        let block_ref = item.block_reference;
        self.cordial_knowledge
            .send(CordialKnowledgeMessage::DagParts {
                headers: Vec::new(),
                shards: vec![block_ref],
            });
        if let Some(shard_tx) = self.shard_tx.lock().as_ref() {
            let _ = shard_tx.send(vec![ShardMessage::FullBlock(block_ref)]);
        }
        let verified_payload = Arc::new(item.transaction_data.clone());
        self.syncer.add_authorized_rbc_dag_payload(item).await;
        // Core materialization is durable authority work and must complete
        // before a queued frontier. The actor callback is ephemeral and the
        // actor has already been stopped by the graceful shutdown protocol.
        if self.rbc_dag_shutdown_started.load(Ordering::Acquire) {
            return Ok(());
        }
        self.starfish_rbc_dag_shadow_service
            .as_ref()
            .ok_or_else(|| "authoritative payload callback target is unavailable".to_owned())?
            .verified_application_payload(block_ref, verified_payload)
            .map_err(|error| error.to_string())
    }

    async fn apply_frontier(&self, delta: CommittedFrontierDeltaV1) -> Result<bool, String> {
        self.syncer
            .apply_starfish_rbc_dag_frontier(delta)
            .await
            .map_err(|error| error.to_string())
    }

    async fn activate_authority(&self) -> Result<(), String> {
        self.syncer.activate_starfish_rbc_dag_authority().await;
        Ok(())
    }

    async fn apply_assignment(&self, reference: BlockReference) -> Result<(), String> {
        self.syncer
            .apply_starfish_rbc_dag_application_assigned(reference)
            .await;
        Ok(())
    }
}

impl RbcDagAppliedFrontierObservationV1 {
    fn from_delta(delta: &CommittedFrontierDeltaV1) -> Self {
        Self {
            carrier_count: delta.carriers.len() as u64,
            application_count: delta.applications.len() as u64,
            application_creation_times: delta
                .applications
                .iter()
                .map(RbcCanonicalHeader::meta_creation_time_ns)
                .collect(),
            commit_round_distances: CommitRoundDistanceBatch::from_diagnostics(
                delta.application_diagnostics.iter().copied(),
            ),
        }
    }

    fn observe(self, metrics: &Metrics) {
        let (total_ns, samples, max_ns) =
            latency_since_timestamps(self.application_creation_times, current_timestamp_ns());
        metrics.observe_starfish_rbc_dag_pipeline_latency_ns(
            RBC_DAG_LATENCY_CREATION_TO_FRONTIER_APPLIED,
            total_ns,
            samples,
            max_ns,
        );
        self.commit_round_distances.observe(metrics);
        metrics.starfish_rbc_dag_frontier_applied();
        metrics
            .starfish_rbc_dag_shadow_inputs_total
            .with_label_values(&["frontier", "committed"])
            .inc();
        metrics
            .starfish_rbc_dag_shadow_inputs_total
            .with_label_values(&["frontier", "carrier"])
            .inc_by(self.carrier_count);
        metrics
            .starfish_rbc_dag_shadow_inputs_total
            .with_label_values(&["frontier", "application"])
            .inc_by(self.application_count);
    }
}

fn fail_rbc_dag_authority(
    metrics: &Metrics,
    bridge_tx: Option<&watch::Sender<RbcDagClockBridgeStateV1>>,
    reason: &str,
) {
    invalidate_shadow_run(metrics);
    fail_rbc_dag_clock_bridge(bridge_tx);
    tracing::error!(
        reason,
        "RBC-DAG authoritative Core-control worker failed closed"
    );
}

fn fail_rbc_dag_outbound_transport(
    metrics: &Metrics,
    bridge_tx: Option<&watch::Sender<RbcDagClockBridgeStateV1>>,
    embedded_rbc_authority: bool,
    recipient: AuthorityIndex,
    error: &RbcDagOutboundMailboxErrorV1,
) {
    metrics
        .starfish_rbc_dag_shadow_inputs_total
        .with_label_values(&["network", "overloaded"])
        .inc();
    if embedded_rbc_authority {
        fail_rbc_dag_authority(
            metrics,
            bridge_tx,
            &format!("RBC-DAG outbound mailbox for authority {recipient} failed: {error}"),
        );
    } else {
        invalidate_shadow_run(metrics);
        tracing::error!(
            peer = recipient,
            ?error,
            "RBC-DAG observational outbound mailbox failed"
        );
    }
}

struct RbcDagEventRouterGuardV1 {
    metrics: Arc<Metrics>,
    bridge_tx: watch::Sender<RbcDagClockBridgeStateV1>,
    clean_exit: bool,
}

impl RbcDagEventRouterGuardV1 {
    fn new(metrics: Arc<Metrics>, bridge_tx: watch::Sender<RbcDagClockBridgeStateV1>) -> Self {
        Self {
            metrics,
            bridge_tx,
            clean_exit: false,
        }
    }

    fn record_clean_exit(&mut self) {
        self.clean_exit = true;
    }
}

impl Drop for RbcDagEventRouterGuardV1 {
    fn drop(&mut self) {
        if !self.clean_exit {
            fail_rbc_dag_authority(
                &self.metrics,
                Some(&self.bridge_tx),
                "RBC-DAG authoritative event router stopped unexpectedly",
            );
        }
    }
}

async fn drain_rbc_dag_authorized_payload(payload: RbcDagAuthorizedPayloadV1) {
    if let RbcDagAuthorizedPayloadV1::Verify(payload_verification) = payload {
        // Await rather than merely drop the JoinHandle: dropping detaches the
        // verifier and could let Reed-Solomon work outlive Core shutdown.
        let _ = payload_verification.await;
    }
}

async fn drain_rbc_dag_control_command_payload(command: RbcDagCoreControlCommandV1) {
    if let RbcDagCoreControlCommandV1::AuthorizedApplicationObserved { payload, .. } = command {
        drain_rbc_dag_authorized_payload(payload).await;
    }
}

async fn enqueue_rbc_dag_core_control(
    sender: &mpsc::Sender<RbcDagCoreControlCommandV1>,
    command: RbcDagCoreControlCommandV1,
    metrics: &Metrics,
    bridge_tx: Option<&watch::Sender<RbcDagClockBridgeStateV1>>,
) -> bool {
    let drain = matches!(command, RbcDagCoreControlCommandV1::Drain);
    if !drain && rbc_dag_clock_bridge_failed(bridge_tx) {
        drain_rbc_dag_control_command_payload(command).await;
        return false;
    }
    match sender.send(command).await {
        Ok(()) => return true,
        Err(error) => drain_rbc_dag_control_command_payload(error.0).await,
    }
    fail_rbc_dag_authority(
        metrics,
        bridge_tx,
        "bounded RBC-DAG Core-control channel closed unexpectedly",
    );
    false
}

async fn run_rbc_dag_core_control_worker<T: RbcDagCoreControlTargetV1 + 'static>(
    target: Arc<T>,
    metrics: Arc<Metrics>,
    bridge_tx: watch::Sender<RbcDagClockBridgeStateV1>,
    shutdown_started: Arc<AtomicBool>,
    mut commands: mpsc::Receiver<RbcDagCoreControlCommandV1>,
) {
    let mut gate = RbcDagCoreControlGateV1::default();
    while let Some(command) = commands.recv().await {
        if matches!(command, RbcDagCoreControlCommandV1::Drain) {
            gate.record_clean_drain();
            break;
        }
        if rbc_dag_clock_bridge_failed(Some(&bridge_tx)) {
            drain_rbc_dag_control_command_payload(command).await;
            continue;
        }
        if !shutdown_started.load(Ordering::Acquire)
            && metrics.starfish_rbc_dag_shadow_clock_valid.get() == 0
        {
            fail_rbc_dag_authority(
                &metrics,
                Some(&bridge_tx),
                "authoritative runtime validity was revoked",
            );
            drain_rbc_dag_control_command_payload(command).await;
            continue;
        }

        match command {
            RbcDagCoreControlCommandV1::AuthorizedApplicationObserved {
                carrier,
                header,
                authorization_basis,
                payload,
            } => {
                let block_ref = header.reference();
                if let Err(error) = target
                    .stage_authorized_application(header, authorization_basis)
                    .await
                {
                    fail_rbc_dag_authority(
                        &metrics,
                        Some(&bridge_tx),
                        &format!("authorized header insertion failed for {block_ref}: {error}"),
                    );
                    drain_rbc_dag_authorized_payload(payload).await;
                    continue;
                }

                let item = match payload {
                    RbcDagAuthorizedPayloadV1::None => continue,
                    RbcDagAuthorizedPayloadV1::AlreadyAvailable(payload) => {
                        if !shutdown_started.load(Ordering::Acquire) {
                            if let Err(error) =
                                target.restore_available_application(block_ref, payload)
                            {
                                fail_rbc_dag_authority(
                                    &metrics,
                                    Some(&bridge_tx),
                                    &format!(
                                        "materialized payload callback failed for {block_ref}: {error}"
                                    ),
                                );
                            }
                        }
                        continue;
                    }
                    RbcDagAuthorizedPayloadV1::Verify(payload_verification) => {
                        match payload_verification.await {
                            Ok(Ok(Ok(item))) => item,
                            // Payload bytes remain untrusted even when their
                            // enclosing header is authorized. Reject only this
                            // observation so another holder can recover it.
                            Ok(Ok(Err(error))) => {
                                tracing::warn!(
                                    ?carrier,
                                    ?block_ref,
                                    ?authorization_basis,
                                    ?error,
                                    "Rejected RBC-DAG application payload"
                                );
                                continue;
                            }
                            Ok(Err(error)) | Err(error)
                                if shutdown_started.load(Ordering::Acquire) =>
                            {
                                tracing::debug!(
                                    ?block_ref,
                                    ?error,
                                    "RBC-DAG payload verifier stopped during shutdown"
                                );
                                continue;
                            }
                            Ok(Err(error)) | Err(error) => {
                                fail_rbc_dag_authority(
                                    &metrics,
                                    Some(&bridge_tx),
                                    &format!(
                                        "authorized payload verifier stopped for {block_ref} in carrier {carrier}: {error}"
                                    ),
                                );
                                continue;
                            }
                        }
                    }
                };
                if rbc_dag_clock_bridge_failed(Some(&bridge_tx)) {
                    continue;
                }
                if let Err(error) = target.materialize_authorized_payload(item).await {
                    fail_rbc_dag_authority(
                        &metrics,
                        Some(&bridge_tx),
                        &format!("verified payload callback failed for {block_ref}: {error}"),
                    );
                }
            }
            RbcDagCoreControlCommandV1::Frontier(delta) => {
                let observation = RbcDagAppliedFrontierObservationV1::from_delta(&delta);
                match target.apply_frontier(delta).await {
                    Ok(true) => observation.observe(&metrics),
                    // Exact replay is an idempotent Core acknowledgment. It
                    // must not double-count application or frontier effects.
                    Ok(false) => {}
                    Err(error) => fail_rbc_dag_authority(
                        &metrics,
                        Some(&bridge_tx),
                        &format!("authoritative frontier was rejected: {error}"),
                    ),
                }
            }
            RbcDagCoreControlCommandV1::Ready => gate.record_ready(),
            RbcDagCoreControlCommandV1::Activate => {
                if !gate.activation_allowed() {
                    fail_rbc_dag_authority(
                        &metrics,
                        Some(&bridge_tx),
                        "clock activation arrived before the startup recovery barrier",
                    );
                    continue;
                }
                if let Err(error) = target.activate_authority().await {
                    fail_rbc_dag_authority(
                        &metrics,
                        Some(&bridge_tx),
                        &format!("Core authority activation failed: {error}"),
                    );
                    continue;
                }
                if rbc_dag_clock_bridge_failed(Some(&bridge_tx)) {
                    continue;
                }
                metrics.starfish_rbc_dag_shadow_clock_valid.set(1);
                bridge_tx.send_if_modified(|state| {
                    if *state == RbcDagClockBridgeStateV1::Pending {
                        *state = RbcDagClockBridgeStateV1::Activated;
                        true
                    } else {
                        false
                    }
                });
            }
            RbcDagCoreControlCommandV1::Drain => unreachable!("drain handled above"),
        }
    }

    if !gate.clean_drain {
        fail_rbc_dag_authority(
            &metrics,
            Some(&bridge_tx),
            "RBC-DAG Core-control sender disappeared before a graceful drain",
        );
    }
}

async fn run_rbc_dag_application_assignment_worker<T: RbcDagCoreControlTargetV1 + 'static>(
    target: Arc<T>,
    metrics: Arc<Metrics>,
    bridge_tx: watch::Sender<RbcDagClockBridgeStateV1>,
    shutdown_started: Arc<AtomicBool>,
    mut assignments: mpsc::Receiver<RbcDagApplicationAssignmentCommandV1>,
) {
    let mut clean_drain = false;
    while let Some(command) = assignments.recv().await {
        match command {
            RbcDagApplicationAssignmentCommandV1::Drain => {
                clean_drain = true;
                break;
            }
            RbcDagApplicationAssignmentCommandV1::Assigned(reference) => {
                // Assignments release an ephemeral producer gate. The local
                // application was already durably fixed before this event, so
                // creating a fresh Core block while the shadow actor is
                // stopped is both unnecessary and unsafe.
                if shutdown_started.load(Ordering::Acquire) {
                    continue;
                }
                if rbc_dag_clock_bridge_failed(Some(&bridge_tx)) {
                    continue;
                }
                if let Err(error) = target.apply_assignment(reference).await {
                    fail_rbc_dag_authority(
                        &metrics,
                        Some(&bridge_tx),
                        &format!("Core application-assignment acknowledgment failed: {error}"),
                    );
                }
            }
        }
    }
    if !clean_drain && !shutdown_started.load(Ordering::Acquire) {
        fail_rbc_dag_authority(
            &metrics,
            Some(&bridge_tx),
            "RBC-DAG assignment sender disappeared unexpectedly",
        );
    }
}

impl<H: BlockHandler + 'static, C: CommitObserver + 'static> NetworkSyncer<H, C> {
    pub async fn start(
        network: Network,
        mut core: Core<H>,
        mut commit_observer: C,
        metrics: Arc<Metrics>,
        node_parameters: NodeParameters,
        starfish_rbc_dag_shadow_wal: PathBuf,
        partial_sig_outbox_rx: Option<mpsc::UnboundedReceiver<PartialSig>>,
        bls_cert_aggregator: Option<BlsCertificateAggregator>,
        bls_signer: Option<BlsSigner>,
        rbc_dag_clock_start_paused: bool,
    ) -> Self {
        let handle = Handle::current();
        let block_ready_notify = Arc::new(Notify::new());
        let proposal_round_notify = Arc::new(Notify::new());
        let embedded_rbc_authority = node_parameters.starfish_rbc_dag_embedded_rbc_authority;
        let (committed, committed_leaders_count) =
            core.take_recovered_committed(embedded_rbc_authority);
        commit_observer.recover_committed(committed, committed_leaders_count);
        let committee = core.committee().clone();
        let mac_keys = core.mac_keys();
        let dag_state = core.dag_state().clone();
        let rbc_dag_frontier_recovery_cursor = embedded_rbc_authority
            .then(|| core.rbc_dag_frontier_recovery_cursor())
            .flatten();
        let recovered_shadow_local_headers = if node_parameters.starfish_rbc_dag_shadow {
            match recovered_local_rbc_headers(&core) {
                Ok(headers) => Some(headers),
                Err(error) if embedded_rbc_authority => {
                    panic!(
                        "embedded RBC-DAG authority cannot start without reconcilable local history: {error}"
                    );
                }
                Err(error) => {
                    // A partial local history would make delivery comparisons
                    // meaningless in mirror mode and make autonomous local
                    // application-origin reconciliation unsafe. Disable the
                    // RBC-DAG runtime while allowing the legacy path to continue.
                    tracing::error!(
                        "Disabling RBC-DAG runtime because recovered direct headers cannot be reconciled: {error}"
                    );
                    None
                }
            }
        } else {
            None
        };
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
        let is_sailfish_pp = dag_state.consensus_protocol.is_sailfish_pp();
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
        let (starfish_rbc_service, rbc_event_rx, rbc_service_task) =
            if dag_state.consensus_protocol.is_starfish_rbc() && !embedded_rbc_authority {
                let protocol_instance = node_parameters
                .starfish_rbc_protocol_instance
                .and_then(|bytes| RbcProtocolInstanceId::new(bytes).ok())
                .expect(
                    "validated Starfish-RBC configuration must contain a nonzero protocol instance",
                );
                let initial_authenticator = match dag_state.block_authentication_scheme {
                    BlockAuthenticationScheme::Ed25519 => {
                        RbcInitialAuthenticator::Ed25519(core.get_signer().clone())
                    }
                    BlockAuthenticationScheme::MlDsa44 => {
                        RbcInitialAuthenticator::MlDsa44(core.get_ml_dsa_44_signer().clone())
                    }
                    BlockAuthenticationScheme::MlDsa65 => {
                        RbcInitialAuthenticator::MlDsa65(core.get_ml_dsa_65_signer().clone())
                    }
                    BlockAuthenticationScheme::MacVector => RbcInitialAuthenticator::Mac,
                };
                let (service, events, task) = start_starfish_rbc_service_with_phase_authority(
                    committee.clone(),
                    dag_state.get_own_authority_index(),
                    protocol_instance,
                    dag_state.block_authentication_scheme,
                    mac_keys.clone(),
                    initial_authenticator,
                    dag_state.highest_round(),
                    STARFISH_RBC_HEADER_RETRY_INTERVAL,
                    RbcPhaseAuthorityV1::Direct,
                )
                .expect("validated Starfish-RBC configuration must start its service");
                (Some(service), Some(events), Some(task))
            } else {
                (None, None, None)
            };
        let rbc_dag_committee_context = recovered_shadow_local_headers.as_ref().map(|_| {
            RbcDagCommitteeContextV1::new(committee.clone())
                .expect("validated committee must initialize the RBC-DAG shadow")
        });
        let (starfish_rbc_dag_shadow_service, rbc_dag_shadow_event_rx, rbc_dag_shadow_service_task) =
            if let Some(recovered_local_headers) = recovered_shadow_local_headers {
                let protocol_instance_bytes = node_parameters
                    .starfish_rbc_protocol_instance
                    .expect("validated shadow configuration must share the direct RBC instance");
                let protocol_instance = rbc_dag_shadow_protocol_instance(
                    protocol_instance_bytes,
                    node_parameters.starfish_rbc_dag_autonomous_clock,
                );
                let committee_context = rbc_dag_committee_context
                    .clone()
                    .expect("RBC-DAG runtime must retain its validated committee context");
                let context = RbcDagContextV1::new_with_committee(
                    protocol_instance,
                    &committee_context,
                    dag_state.block_authentication_scheme,
                );
                let authorizer = match dag_state.block_authentication_scheme {
                    BlockAuthenticationScheme::Ed25519 => {
                        ShadowAuthorizerV1::Ed25519(core.get_signer().clone())
                    }
                    BlockAuthenticationScheme::MlDsa44 => {
                        ShadowAuthorizerV1::MlDsa44(core.get_ml_dsa_44_signer().clone())
                    }
                    BlockAuthenticationScheme::MlDsa65 => {
                        ShadowAuthorizerV1::MlDsa65(core.get_ml_dsa_65_signer().clone())
                    }
                    BlockAuthenticationScheme::MacVector => {
                        ShadowAuthorizerV1::MacVector(mac_keys.as_ref().clone())
                    }
                };
                // -1 means the background WAL replay has not completed yet;
                // Ready moves the active observational mode to 1 unless work
                // was already shed (0). The inactive verdict remains zero.
                if node_parameters.starfish_rbc_dag_autonomous_clock {
                    metrics.starfish_rbc_dag_shadow_clock_valid.set(-1);
                    metrics.starfish_rbc_dag_shadow_comparison_valid.set(0);
                } else {
                    metrics.starfish_rbc_dag_shadow_comparison_valid.set(-1);
                    metrics.starfish_rbc_dag_shadow_clock_valid.set(0);
                }
                let started = if node_parameters.starfish_rbc_dag_autonomous_clock {
                    let wal_sync_policy = if node_parameters.starfish_rbc_dag_shadow_buffered_wal {
                        ShadowWalSyncPolicyV1::OnShutdown
                    } else {
                        ShadowWalSyncPolicyV1::EveryBatch
                    };
                    if embedded_rbc_authority {
                        start_starfish_rbc_dag_authoritative_clock_service_with_metrics_v1(
                            starfish_rbc_dag_shadow_wal,
                            committee_context,
                            dag_state.get_own_authority_index(),
                            context,
                            authorizer,
                            recovered_local_headers,
                            // The idle carrier pacemaker deliberately shares the
                            // resolved Starfish leader timeout. Application and
                            // embedded RBC phase carriers remain event-driven.
                            node_parameters.leader_timeout,
                            node_parameters
                                .starfish_rbc_dag_consensus_timeout
                                .unwrap_or(node_parameters.leader_timeout),
                            wal_sync_policy,
                            Arc::clone(&metrics),
                            rbc_dag_frontier_recovery_cursor,
                            !rbc_dag_clock_start_paused,
                            node_parameters.starfish_rbc_dag_vote_qc_fast_path,
                        )
                    } else {
                        let start = if rbc_dag_clock_start_paused {
                            start_starfish_rbc_dag_autonomous_clock_service_paused_with_metrics_v1
                        } else {
                            start_starfish_rbc_dag_autonomous_clock_service_with_metrics_v1
                        };
                        start(
                            starfish_rbc_dag_shadow_wal,
                            committee_context,
                            dag_state.get_own_authority_index(),
                            context,
                            authorizer,
                            recovered_local_headers,
                            node_parameters.leader_timeout,
                            wal_sync_policy,
                            Arc::clone(&metrics),
                        )
                    }
                } else {
                    let wal_sync_policy = if node_parameters.starfish_rbc_dag_shadow_buffered_wal {
                        ShadowWalSyncPolicyV1::OnShutdown
                    } else {
                        ShadowWalSyncPolicyV1::EveryBatch
                    };
                    start_starfish_rbc_dag_shadow_service_with_metrics_v1(
                        starfish_rbc_dag_shadow_wal,
                        committee_context,
                        dag_state.get_own_authority_index(),
                        context,
                        authorizer,
                        recovered_local_headers,
                        wal_sync_policy,
                        Arc::clone(&metrics),
                    )
                };
                match started {
                    Ok((service, events, task)) => (Some(service), Some(events), Some(task)),
                    Err(error) if embedded_rbc_authority => {
                        panic!("embedded RBC-DAG authority failed to start: {error}");
                    }
                    Err(error) => {
                        invalidate_shadow_run(&metrics);
                        tracing::error!("Disabling Starfish-RBC-DAG runtime: {error}");
                        (None, None, None)
                    }
                }
            } else {
                (None, None, None)
            };
        let syncer = Syncer::new(
            core,
            NetworkSyncSignals {
                block_ready_notify: block_ready_notify.clone(),
                proposal_round_notify: proposal_round_notify.clone(),
            },
            commit_observer,
            metrics.clone(),
            bls_msg_tx.clone(),
            sf_msg_tx.clone(),
            starfish_rbc_service.clone(),
            starfish_rbc_dag_shadow_service.clone(),
            embedded_rbc_authority,
        );
        let initial_round = syncer.core().next_block_round();
        let syncer = CoreThreadDispatcher::start(syncer);
        if !embedded_rbc_authority {
            // Embedded authority production is released by the ordered Ready
            // bridge only after replayed frontier receipts are durable.
            syncer.force_new_block(initial_round).await;
        }
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
                | ConsensusProtocol::SparseStarfishSpeed
                | ConsensusProtocol::StarfishRbc
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

        // Create CordialKnowledge actor. The dag knowledge `Arc` is owned
        // by `DagState` (built during `open()` for push modes); we share
        // the same handle so the actor and the broadcaster's reads target
        // the same `RwLock`.
        let (cordial_knowledge_handle, cordial_knowledge_actor) = CordialKnowledgeHandle::new(
            committee.len(),
            dag_state.dag_knowledge(),
            metrics.clone(),
        );
        dag_state.attach_cordial_knowledge(cordial_knowledge_handle.clone());
        let cordial_knowledge_task = handle.spawn(cordial_knowledge_actor.run());

        let (rbc_dag_clock_bridge_tx, rbc_dag_clock_bridge_state) = if node_parameters
            .starfish_rbc_dag_autonomous_clock
            && starfish_rbc_dag_shadow_service.is_some()
        {
            let (tx, rx) = watch::channel(RbcDagClockBridgeStateV1::Pending);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let rbc_dag_shutdown_started = Arc::new(AtomicBool::new(false));

        let inner = Arc::new(NetworkSyncerInner {
            block_ready_notify,
            dag_state: dag_state.clone(),
            syncer,
            proposal_round_notify,
            committee,
            mac_keys,
            dissemination_mode,
            causal_push_shard_round_lag: node_parameters.causal_push_shard_round_lag,
            stop: stop_sender.clone(),
            gc_round,
            shard_tx: parking_lot::Mutex::new(shard_tx),
            cordial_knowledge: cordial_knowledge_handle,
            peer_senders: parking_lot::RwLock::new(AHashMap::new()),
            rbc_peer_senders: parking_lot::RwLock::new(AHashMap::new()),
            rbc_dag_peer_mailboxes: parking_lot::RwLock::new(AHashMap::new()),
            leader_timeout: node_parameters.leader_timeout,
            soft_block_timeout: node_parameters.soft_block_timeout,
            metrics: metrics.clone(),
            rbc_dag_clock_bridge_tx: rbc_dag_clock_bridge_tx.clone(),
            rbc_dag_shutdown_started: rbc_dag_shutdown_started.clone(),
            sailfish_handle: sf_handle_for_inner,
            embedded_rbc_authority,
            starfish_rbc_service: starfish_rbc_service.clone(),
            starfish_rbc_dag_shadow_service: starfish_rbc_dag_shadow_service.clone(),
            start_time: std::time::Instant::now(),
        });

        // Bridge the single-owner RBC actor to direct network unicasts and to
        // the core thread's dirty/clean DAG boundaries. Header staging never
        // implies delivery; only a typed `Delivered` effect can mark a vertex
        // clean.
        let rbc_event_task = rbc_event_rx.map(|mut event_rx| {
            let event_inner = inner.clone();
            let rbc_metrics = metrics.clone();
            handle.spawn(async move {
                let mut payload_encoder = ReedSolomonEncoder::new(2, 4, 2)
                    .expect("Starfish-RBC payload encoder should be created");
                while let Some(event) = event_rx.recv().await {
                    match event {
                        RbcServiceEvent::Network { recipient, message } => {
                            let sender =
                                event_inner.rbc_peer_senders.read().get(&recipient).cloned();
                            if let Some(sender) = sender {
                                if sender.send(message).is_err() {
                                    tracing::debug!(
                                        "Starfish-RBC outbound worker for authority {} stopped",
                                        recipient
                                    );
                                }
                            } else {
                                // Local INITs and phase intents are retained by
                                // the actor and replayed when this peer connects.
                                tracing::debug!(
                                    "Deferring Starfish-RBC message for disconnected authority {}",
                                    recipient
                                );
                            }
                        }
                        RbcServiceEvent::HeaderStaged(header) => {
                            let mut block = header.header().to_authentication_free_block();
                            block.preserialize();
                            let block_ref = *block.reference();
                            event_inner
                                .cordial_knowledge
                                .send(CordialKnowledgeMessage::DagParts {
                                    headers: vec![block_ref],
                                    shards: Vec::new(),
                                });
                            let (missing_parents, _) = event_inner
                                .syncer
                                .add_headers(
                                    vec![Data::new(block)],
                                    DataSource::BlockBundleStreamingHeader,
                                )
                                .await;
                            if !missing_parents.is_empty() {
                                tracing::debug!(
                                    "Starfish-RBC staged header {} waits for dependencies {:?}",
                                    block_ref,
                                    missing_parents
                                );
                            }
                        }
                        RbcServiceEvent::TransactionPayloadStaged {
                            peer,
                            header,
                            transaction_data,
                        } => {
                            let block_ref = header.reference();
                            let item = match verify_starfish_rbc_transaction_payload(
                                header.header(),
                                transaction_data,
                                &event_inner.committee,
                                event_inner.dag_state.get_own_authority_index(),
                                peer,
                                &mut payload_encoder,
                                event_inner.dag_state.block_authentication_scheme,
                                &event_inner.mac_keys,
                            ) {
                                Ok(item) => item,
                                Err(error) => {
                                    tracing::warn!(
                                        ?block_ref,
                                        peer,
                                        ?error,
                                        "Rejected Starfish-RBC transaction payload"
                                    );
                                    continue;
                                }
                            };
                            event_inner
                                .cordial_knowledge
                                .send(CordialKnowledgeMessage::DagParts {
                                    headers: Vec::new(),
                                    shards: vec![block_ref],
                                });
                            if let Some(shard_tx) = event_inner.shard_tx.lock().as_ref() {
                                let _ = shard_tx.send(vec![ShardMessage::FullBlock(block_ref)]);
                            }
                            event_inner
                                .syncer
                                .add_transaction_data(vec![item], DataSource::StarfishRbcPayload)
                                .await;
                        }
                        RbcServiceEvent::Delivered(header) => {
                            if let Some(ref shadow) =
                                event_inner.starfish_rbc_dag_shadow_service
                            {
                                let canonical = header.header();
                                let identity = ShadowDeliveryIdentityV1::new(
                                    canonical.reference().authority,
                                    canonical.reference().round,
                                    canonical.transactions_commitment(),
                                );
                                if let Err(error) = shadow.direct_delivered(identity) {
                                    if shadow_transport_error_invalidates_run(&error) {
                                        invalidate_shadow_run(&rbc_metrics);
                                    }
                                    tracing::warn!(
                                        "Failed to notify RBC-DAG shadow of direct delivery: {error}"
                                    );
                                }
                            }
                            event_inner
                                .syncer
                                .apply_starfish_rbc_deliveries(vec![header])
                                .await;
                        }
                        RbcServiceEvent::Rejected { peer, error } => {
                            tracing::warn!(
                                "Rejected Starfish-RBC input from {:?}: {}",
                                peer,
                                error
                            );
                        }
                    }
                }
            })
        });

        let embedded_rbc_committee_id = embedded_rbc_authority.then(|| {
            RbcCommitteeId::derive(&inner.committee)
                .expect("validated direct RBC committee must retain a stable identifier")
        });
        let (rbc_dag_core_control_tx, rbc_dag_core_control_task) = if embedded_rbc_authority {
            let (control_tx, control_rx) = mpsc::channel(STARFISH_RBC_DAG_CORE_CONTROL_CAPACITY);
            let worker_inner = inner.clone();
            let worker_metrics = metrics.clone();
            let worker_bridge_tx = rbc_dag_clock_bridge_tx
                .as_ref()
                .expect("embedded authority must supervise clock activation")
                .clone();
            let panic_metrics = metrics.clone();
            let panic_bridge_tx = worker_bridge_tx.clone();
            let worker_shutdown_started = rbc_dag_shutdown_started.clone();
            let task = handle.spawn(async move {
                if AssertUnwindSafe(run_rbc_dag_core_control_worker(
                    worker_inner,
                    worker_metrics,
                    worker_bridge_tx,
                    worker_shutdown_started,
                    control_rx,
                ))
                .catch_unwind()
                .await
                .is_err()
                {
                    fail_rbc_dag_authority(
                        &panic_metrics,
                        Some(&panic_bridge_tx),
                        "RBC-DAG Core-control worker panicked",
                    );
                }
            });
            (Some(control_tx), Some(task))
        } else {
            (None, None)
        };
        let (rbc_dag_assignment_tx, rbc_dag_assignment_task) = if embedded_rbc_authority {
            // Capacity one plus the single in-flight dispatcher call preserves
            // assignment order with a strict two-item bound, independently of
            // remote payload verification in the authority FIFO.
            let (assignment_tx, assignment_rx) = mpsc::channel(1);
            let assignment_inner = inner.clone();
            let assignment_metrics = metrics.clone();
            let assignment_bridge_tx = rbc_dag_clock_bridge_tx
                .as_ref()
                .expect("embedded authority must supervise assignments")
                .clone();
            let assignment_shutdown_started = rbc_dag_shutdown_started.clone();
            let panic_metrics = metrics.clone();
            let panic_bridge_tx = assignment_bridge_tx.clone();
            let task = handle.spawn(async move {
                if AssertUnwindSafe(run_rbc_dag_application_assignment_worker(
                    assignment_inner,
                    assignment_metrics,
                    assignment_bridge_tx,
                    assignment_shutdown_started,
                    assignment_rx,
                ))
                .catch_unwind()
                .await
                .is_err()
                {
                    fail_rbc_dag_authority(
                        &panic_metrics,
                        Some(&panic_bridge_tx),
                        "RBC-DAG assignment worker panicked",
                    );
                }
            });
            (Some(assignment_tx), Some(task))
        } else {
            (None, None)
        };
        let rbc_dag_shadow_event_task = rbc_dag_shadow_event_rx.map(|mut event_rx| {
            let event_inner = inner.clone();
            let rbc_dag_committee_context = rbc_dag_committee_context
                .clone()
                .expect("RBC-DAG event router must retain its validated committee context");
            let shadow_metrics = metrics.clone();
            let rbc_dag_clock_bridge_tx = rbc_dag_clock_bridge_tx.clone();
            let rbc_dag_core_control_tx = rbc_dag_core_control_tx;
            let rbc_dag_assignment_tx = rbc_dag_assignment_tx;
            let rbc_dag_shutdown_started = rbc_dag_shutdown_started;
            handle.spawn(async move {
                // A local broadcast emits the same canonical carrier once per
                // recipient. Validate it on the first event and reuse only its
                // exact reference while the bytes remain identical; receiver
                // authentication and canonical decoding are unchanged.
                let mut last_proactive_carrier: Option<(Vec<u8>, BlockReference)> = None;
                let mut router_guard = embedded_rbc_authority.then(|| {
                    RbcDagEventRouterGuardV1::new(
                        shadow_metrics.clone(),
                        rbc_dag_clock_bridge_tx
                            .as_ref()
                            .expect("embedded authority must supervise its event router")
                            .clone(),
                    )
                });
                // Keep expensive Reed-Solomon work off the carrier event
                // router. Verification remains parallel, while the bounded
                // Core-control worker awaits its handles in exact service
                // order before applying a later frontier or activation.
                let payload_verification_limit = Arc::new(Semaphore::new(4));
                while let Some(event) = event_rx.recv().await {
                    match event {
                        ShadowServiceEventV1::Network { recipient, message } => {
                            // The per-peer keyed mailbox bounds both proactive
                            // history and exact-repair traffic. Distinct-key
                            // saturation is a transport failure: no proactive
                            // item is silently evicted to make room for a
                            // newer one.
                            let mailbox = event_inner
                                .rbc_dag_peer_mailboxes
                                .read()
                                .get(&recipient)
                                .cloned();
                            if let Some(mailbox) = mailbox {
                                let proactive_reference = match &message {
                                    NetworkMessage::RbcDagShadowCarrier(carrier) => {
                                        if let Some(reference) = last_proactive_carrier
                                            .as_ref()
                                            .filter(|(canonical, _)| {
                                                canonical == &carrier.canonical_carrier
                                            })
                                            .map(|(_, reference)| *reference)
                                        {
                                            Some(reference)
                                        } else {
                                            match rbc_dag_proactive_reference(
                                                carrier,
                                                &rbc_dag_committee_context,
                                            ) {
                                                Ok(reference) => {
                                                    last_proactive_carrier = Some((
                                                        carrier.canonical_carrier.clone(),
                                                        reference,
                                                    ));
                                                    Some(reference)
                                                }
                                                Err(error) => {
                                                    mailbox.fail(&error);
                                                    fail_rbc_dag_outbound_transport(
                                                        &shadow_metrics,
                                                        rbc_dag_clock_bridge_tx.as_ref(),
                                                        embedded_rbc_authority,
                                                        recipient,
                                                        &error,
                                                    );
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                    _ => None,
                                };
                                match mailbox.enqueue_with_proactive_reference(
                                    message,
                                    &rbc_dag_committee_context,
                                    proactive_reference,
                                ) {
                                    Ok(RbcDagOutboundEnqueueV1::Added) => shadow_metrics
                                        .starfish_rbc_dag_shadow_inputs_total
                                        .with_label_values(&["network", "sent"])
                                        .inc(),
                                    Ok(RbcDagOutboundEnqueueV1::Coalesced) => shadow_metrics
                                        .starfish_rbc_dag_shadow_inputs_total
                                        .with_label_values(&["network", "coalesced"])
                                        .inc(),
                                    Err(error) => fail_rbc_dag_outbound_transport(
                                        &shadow_metrics,
                                        rbc_dag_clock_bridge_tx.as_ref(),
                                        embedded_rbc_authority,
                                        recipient,
                                        &error,
                                    ),
                                }
                            } else {
                                shadow_metrics
                                    .starfish_rbc_dag_shadow_inputs_total
                                    .with_label_values(&["network", "disconnected"])
                                    .inc();
                                // No observation was lost: the actor retains
                                // local carriers and replays them when this
                                // peer connects.
                            }
                        }
                        ShadowServiceEventV1::Delivered(identity) => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_inputs_total
                                .with_label_values(&["delivery", "shadow"])
                                .inc();
                            tracing::debug!(?identity, "RBC-DAG shadow delivered carrier");
                        }
                        ShadowServiceEventV1::EmbeddedApplicationDelivered { carrier, header } => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_inputs_total
                                .with_label_values(&["delivery", "embedded_application"])
                                .inc();
                            tracing::debug!(
                                ?carrier,
                                application = ?header.reference(),
                                "RBC-DAG shadow delivered embedded application header"
                            );
                            if embedded_rbc_authority {
                                match PinnedRbcHeader::validate_with_committee_id(
                                    header,
                                    &event_inner.committee,
                                    embedded_rbc_committee_id
                                        .expect("embedded authority must cache its committee ID"),
                                ) {
                                    Ok(_) => {}
                                    Err(error) => {
                                        fail_rbc_dag_authority(
                                            &shadow_metrics,
                                            rbc_dag_clock_bridge_tx.as_ref(),
                                            &format!(
                                                "embedded carrier {carrier:?} delivered an invalid application header: {error}"
                                            ),
                                        );
                                    }
                                }
                            }
                        }
                        ShadowServiceEventV1::AuthorizedApplicationObserved {
                            carrier,
                            header,
                            payload,
                            authorization_basis,
                        } => {
                            if !embedded_rbc_authority {
                                tracing::debug!(
                                    ?carrier,
                                    ?authorization_basis,
                                    "Ignoring standalone application event outside embedded authority mode"
                                );
                                continue;
                            }
                            // Once authority has failed, do not even start a
                            // new payload verifier. Commands already accepted
                            // by the bounded FIFO are joined by its worker.
                            if rbc_dag_clock_bridge_failed(rbc_dag_clock_bridge_tx.as_ref()) {
                                continue;
                            }
                            let pinned = match PinnedRbcHeader::validate_with_committee_id(
                                header,
                                &event_inner.committee,
                                embedded_rbc_committee_id
                                    .expect("embedded authority must cache its committee ID"),
                            ) {
                                Ok(pinned) => pinned,
                                Err(error) => {
                                    fail_rbc_dag_authority(
                                        &shadow_metrics,
                                        rbc_dag_clock_bridge_tx.as_ref(),
                                        &format!(
                                            "carrier {carrier:?} emitted an invalid authorized application header ({authorization_basis:?}): {error}"
                                        ),
                                    );
                                    continue;
                                }
                            };
                            let canonical = pinned.header().clone();
                            let block_ref = canonical.reference();
                            let control_payload = if event_inner
                                .dag_state
                                .is_data_available(&block_ref)
                            {
                                let Some(block) =
                                    event_inner.dag_state.get_storage_block(block_ref)
                                else {
                                    fail_rbc_dag_authority(
                                        &shadow_metrics,
                                        rbc_dag_clock_bridge_tx.as_ref(),
                                        &format!(
                                            "data-available application {block_ref} has no storage block"
                                        ),
                                    );
                                    continue;
                                };
                                let transaction_data = block.transaction_data().cloned();
                                if transaction_data.is_none()
                                    && canonical.transactions_commitment()
                                        != TransactionsCommitment::default()
                                {
                                    fail_rbc_dag_authority(
                                        &shadow_metrics,
                                        rbc_dag_clock_bridge_tx.as_ref(),
                                        &format!(
                                            "data-available application {block_ref} has no transaction payload"
                                        ),
                                    );
                                    continue;
                                }
                                // Empty committed transaction sets are
                                // data-available without a TransactionData
                                // allocation. The ordered availability callback
                                // remains required, but there is no payload to
                                // verify or cache.
                                RbcDagAuthorizedPayloadV1::AlreadyAvailable(
                                    transaction_data.map(Arc::new),
                                )
                            } else if let Some(transaction_data) = payload {
                                let payload_verification_limit =
                                    payload_verification_limit.clone();
                                let committee = event_inner.committee.clone();
                                let mac_keys = event_inner.mac_keys.clone();
                                let own_id = event_inner.dag_state.get_own_authority_index();
                                let authentication_scheme =
                                    event_inner.dag_state.block_authentication_scheme;
                                let verification_header = canonical.clone();
                                let task = tokio::spawn(async move {
                                let permit = payload_verification_limit
                                    .acquire_owned()
                                    .await
                                    .expect("RBC-DAG payload semaphore remains open");
                                    tokio::task::spawn_blocking(move || {
                                    let _permit = permit;
                                    let mut encoder = ReedSolomonEncoder::new(2, 4, 2)
                                        .expect("RBC-DAG payload encoder should be created");
                                    verify_starfish_rbc_transaction_payload(
                                            &verification_header,
                                        transaction_data,
                                        &committee,
                                        own_id,
                                        block_ref.authority,
                                        &mut encoder,
                                        authentication_scheme,
                                        &mac_keys,
                                    )
                                })
                                    .await
                                });
                                RbcDagAuthorizedPayloadV1::Verify(task)
                            } else {
                                RbcDagAuthorizedPayloadV1::None
                            };
                            if let Some(ref control_tx) = rbc_dag_core_control_tx {
                                enqueue_rbc_dag_core_control(
                                    control_tx,
                                    RbcDagCoreControlCommandV1::AuthorizedApplicationObserved {
                                        carrier,
                                        header: canonical,
                                        authorization_basis,
                                        payload: control_payload,
                                    },
                                    &shadow_metrics,
                                    rbc_dag_clock_bridge_tx.as_ref(),
                                )
                                .await;
                            }
                        }
                        ShadowServiceEventV1::ApplicationAssigned(reference) => {
                            if let Some(ref assignment_tx) = rbc_dag_assignment_tx {
                                if rbc_dag_clock_bridge_failed(rbc_dag_clock_bridge_tx.as_ref()) {
                                    continue;
                                }
                                // Assignment releases the one-outstanding
                                // producer gate and has no frontier/recovery
                                // dependency. Keep it off the payload-heavy
                                // FIFO; capacity one preserves exact order
                                // without spawning unbounded tasks.
                                if assignment_tx
                                    .send(RbcDagApplicationAssignmentCommandV1::Assigned(
                                        reference,
                                    ))
                                    .await
                                    .is_err()
                                {
                                    fail_rbc_dag_authority(
                                        &shadow_metrics,
                                        rbc_dag_clock_bridge_tx.as_ref(),
                                        "bounded RBC-DAG assignment channel closed unexpectedly",
                                    );
                                }
                            }
                        }
                        ShadowServiceEventV1::FrontierCommitted(delta) => {
                            if let Some(ref control_tx) = rbc_dag_core_control_tx {
                                enqueue_rbc_dag_core_control(
                                    control_tx,
                                    RbcDagCoreControlCommandV1::Frontier(delta),
                                    &shadow_metrics,
                                    rbc_dag_clock_bridge_tx.as_ref(),
                                )
                                .await;
                            } else {
                                shadow_metrics.starfish_rbc_dag_frontier_ignored();
                            }
                        }
                        ShadowServiceEventV1::VertexProjected(reference) => {
                            shadow_metrics
                                .starfish_rbc_dag_projected_vertices_total
                                .inc();
                            tracing::debug!(?reference, "RBC-DAG consensus vertex projected");
                        }
                        ShadowServiceEventV1::LeaderDecided(decision) => {
                            let outcome = match decision {
                                ProjectionDecisionV1::DirectCommit { .. } => "direct_commit",
                                ProjectionDecisionV1::DirectSkip { .. } => "direct_skip",
                                ProjectionDecisionV1::IndirectCommit { .. } => "indirect_commit",
                                ProjectionDecisionV1::IndirectSkip { .. } => "indirect_skip",
                                ProjectionDecisionV1::Undecided { .. } => "undecided",
                            };
                            shadow_metrics
                                .starfish_rbc_dag_projection_decisions_total
                                .with_label_values(&[outcome])
                                .inc();
                            tracing::debug!(?decision, "RBC-DAG projected leader decided");
                        }
                        ShadowServiceEventV1::ComparisonBacklog {
                            unpaired_direct,
                            unpaired_shadow,
                            max_round_lag,
                        } => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_unpaired_direct
                                .set(i64::try_from(unpaired_direct).unwrap_or(i64::MAX));
                            shadow_metrics
                                .starfish_rbc_dag_shadow_unpaired_shadow
                                .set(i64::try_from(unpaired_shadow).unwrap_or(i64::MAX));
                            shadow_metrics
                                .starfish_rbc_dag_shadow_unpaired_max_round_lag
                                .set(i64::from(max_round_lag));
                        }
                        ShadowServiceEventV1::Comparison(comparison) => {
                            let outcome = match &comparison {
                                ShadowDeliveryComparisonV1::Match => "match",
                                ShadowDeliveryComparisonV1::Mismatch {
                                    direct_only,
                                    shadow_only,
                                } if !direct_only.is_empty() && shadow_only.is_empty() => {
                                    "direct_only"
                                }
                                ShadowDeliveryComparisonV1::Mismatch {
                                    direct_only,
                                    shadow_only,
                                } if direct_only.is_empty() && !shadow_only.is_empty() => {
                                    "shadow_only"
                                }
                                ShadowDeliveryComparisonV1::Mismatch { .. } => "mismatch",
                                ShadowDeliveryComparisonV1::Ambiguous { .. } => "ambiguous",
                            };
                            shadow_metrics
                                .starfish_rbc_dag_shadow_delivery_comparisons_total
                                .with_label_values(&[outcome])
                                .inc();
                        }
                        ShadowServiceEventV1::Input { kind, outcome } => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_inputs_total
                                .with_label_values(&[kind, outcome])
                                .inc();
                        }
                        ShadowServiceEventV1::WalAppended {
                            batches,
                            records,
                            durable,
                        } => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_wal_appended_batches_total
                                .inc_by(batches);
                            shadow_metrics
                                .starfish_rbc_dag_shadow_wal_appended_records_total
                                .inc_by(records);
                            if durable {
                                shadow_metrics
                                    .starfish_rbc_dag_shadow_wal_durable_batches_total
                                    .inc_by(batches);
                                shadow_metrics
                                    .starfish_rbc_dag_shadow_wal_durable_records_total
                                    .inc_by(records);
                            }
                        }
                        ShadowServiceEventV1::Ready { autonomous_clock } => {
                            if autonomous_clock && embedded_rbc_authority {
                                if let Some(ref control_tx) = rbc_dag_core_control_tx {
                                    // FIFO placement makes this a barrier over
                                    // every recovered header, payload, and
                                    // committed frontier emitted before Ready.
                                    enqueue_rbc_dag_core_control(
                                        control_tx,
                                        RbcDagCoreControlCommandV1::Ready,
                                        &shadow_metrics,
                                        rbc_dag_clock_bridge_tx.as_ref(),
                                    )
                                    .await;
                                }
                            } else {
                                let verdict =
                                    &shadow_metrics.starfish_rbc_dag_shadow_comparison_valid;
                                if verdict.get() != 0 {
                                    verdict.set(1);
                                }
                            }
                        }
                        ShadowServiceEventV1::ClockActivated => {
                            if let Some(ref control_tx) = rbc_dag_core_control_tx {
                                enqueue_rbc_dag_core_control(
                                    control_tx,
                                    RbcDagCoreControlCommandV1::Activate,
                                    &shadow_metrics,
                                    rbc_dag_clock_bridge_tx.as_ref(),
                                )
                                .await;
                            } else if shadow_metrics.starfish_rbc_dag_shadow_clock_valid.get() == 0 {
                                fail_rbc_dag_clock_bridge(rbc_dag_clock_bridge_tx.as_ref());
                            } else {
                                shadow_metrics.starfish_rbc_dag_shadow_clock_valid.set(1);
                                if let Some(ref bridge_tx) = rbc_dag_clock_bridge_tx {
                                    bridge_tx.send_replace(RbcDagClockBridgeStateV1::Activated);
                                }
                            }
                        }
                        ShadowServiceEventV1::ClockState {
                            open_round,
                            phase_backlog,
                            admitted_authors,
                            admitted_stake,
                            buffered_authenticated,
                        } => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_carrier_round
                                .set(i64::from(open_round));
                            shadow_metrics
                                .starfish_rbc_dag_shadow_phase_backlog
                                .set(i64::try_from(phase_backlog).unwrap_or(i64::MAX));
                            shadow_metrics
                                .starfish_rbc_dag_shadow_admitted_authors
                                .set(i64::try_from(admitted_authors).unwrap_or(i64::MAX));
                            shadow_metrics
                                .starfish_rbc_dag_shadow_admitted_stake
                                .set(i64::try_from(admitted_stake).unwrap_or(i64::MAX));
                            shadow_metrics
                                .starfish_rbc_dag_shadow_buffered_authenticated
                                .set(i64::try_from(buffered_authenticated).unwrap_or(i64::MAX));
                        }
                        ShadowServiceEventV1::Recovered {
                            batches,
                            discarded_tail_bytes,
                        } => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_wal_replayed_batches
                                .set(batches as i64);
                            shadow_metrics
                                .starfish_rbc_dag_shadow_wal_discarded_tail_bytes_total
                                .inc_by(discarded_tail_bytes);
                        }
                        ShadowServiceEventV1::PendingRecovery(pending) => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_pending_recovery
                                .set(pending as i64);
                        }
                        ShadowServiceEventV1::Rejected { peer, error } => {
                            if peer.is_none() {
                                if embedded_rbc_authority {
                                    fail_rbc_dag_authority(
                                        &shadow_metrics,
                                        rbc_dag_clock_bridge_tx.as_ref(),
                                        &format!(
                                            "RBC-DAG actor rejected authoritative runtime input: {error}"
                                        ),
                                    );
                                } else {
                                    invalidate_shadow_run(&shadow_metrics);
                                }
                            }
                            tracing::warn!(
                                "Rejected RBC-DAG runtime input from {:?}: {}",
                                peer,
                                error
                            );
                        }
                    }
                }
                if rbc_dag_shutdown_started.load(Ordering::Acquire) {
                    if let Some(ref assignment_tx) = rbc_dag_assignment_tx {
                        let _ = assignment_tx
                            .send(RbcDagApplicationAssignmentCommandV1::Drain)
                            .await;
                    }
                }
                if let Some(ref control_tx) = rbc_dag_core_control_tx {
                    if rbc_dag_shutdown_started.load(Ordering::Acquire) {
                        enqueue_rbc_dag_core_control(
                            control_tx,
                            RbcDagCoreControlCommandV1::Drain,
                            &shadow_metrics,
                            rbc_dag_clock_bridge_tx.as_ref(),
                        )
                        .await;
                    } else {
                        fail_rbc_dag_authority(
                            &shadow_metrics,
                            rbc_dag_clock_bridge_tx.as_ref(),
                            "RBC-DAG actor event stream closed unexpectedly",
                        );
                    }
                }
                if let Some(ref mut router_guard) = router_guard {
                    router_guard.record_clean_exit();
                }
            })
        });

        // Start bridge task that forwards reconstructed transaction data to core
        let bridge_task = decoded_rx.map(|mut decoded_rx| {
            let bridge_inner = inner.clone();
            handle.spawn(async move {
                while let Some(items) = decoded_rx.recv().await {
                    // Reconstruction proves we now have the shard data for the
                    // entire batch.
                    let shard_refs = items
                        .iter()
                        .map(|item| item.block_reference)
                        .collect::<Vec<_>>();
                    bridge_inner
                        .cordial_knowledge
                        .send(CordialKnowledgeMessage::DagParts {
                            headers: Vec::new(),
                            shards: shard_refs.clone(),
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
                inner.proposal_round_notify.clone(),
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
                let mut cert_flush_interval =
                    tokio::time::interval(SAILFISH_CERT_BATCH_FLUSH_INTERVAL);
                cert_flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                cert_flush_interval.tick().await;
                let mut pending_cert_messages = Vec::new();

                loop {
                    select! {
                        maybe_events = event_rx.recv() => {
                            let Some(events) = maybe_events else {
                                break;
                            };

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
                                            pending_cert_messages.push(message.clone());
                                        }
                                        SailfishCertEvent::BroadcastTimeout(msg) => {
                                            if !pending_cert_messages.is_empty() {
                                                broadcast_sailfish_cert_messages(
                                                    &senders,
                                                    &pending_cert_messages,
                                                )
                                                .await;
                                                pending_cert_messages.clear();
                                            }
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
                                            let leader_tx = event_inner
                                                .peer_senders
                                                .read()
                                                .get(&next_leader)
                                                .cloned();
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

                                if pending_cert_messages.len() >= SAILFISH_CERT_BATCH_MAX_LEN {
                                    broadcast_sailfish_cert_messages(
                                        &senders,
                                        &pending_cert_messages,
                                    )
                                    .await;
                                    pending_cert_messages.clear();
                                }
                            }
                        }
                        _ = cert_flush_interval.tick(), if !pending_cert_messages.is_empty() => {
                            let senders: Vec<_> =
                                event_inner.peer_senders.read().values().cloned().collect();
                            broadcast_sailfish_cert_messages(&senders, &pending_cert_messages)
                                .await;
                            pending_cert_messages.clear();
                        }
                    }
                }

                if !pending_cert_messages.is_empty() {
                    let senders: Vec<_> =
                        event_inner.peer_senders.read().values().cloned().collect();
                    broadcast_sailfish_cert_messages(&senders, &pending_cert_messages).await;
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
            rbc_event_task,
            rbc_service_task,
            rbc_dag_shadow_event_task,
            rbc_dag_core_control_task,
            rbc_dag_assignment_task,
            rbc_dag_shadow_service_task,
            rbc_dag_clock_bridge_state,
            cordial_knowledge_task,
        }
    }

    pub(crate) async fn activate_starfish_rbc_dag_clock(&self) -> Result<(), String> {
        let shadow = self
            .inner
            .starfish_rbc_dag_shadow_service
            .clone()
            .ok_or_else(|| "RBC-DAG clock service is not running".to_string())?;
        let mut bridge_state = self
            .rbc_dag_clock_bridge_state
            .clone()
            .ok_or_else(|| "RBC-DAG autonomous event bridge is not running".to_string())?;
        match *bridge_state.borrow() {
            RbcDagClockBridgeStateV1::Pending => {}
            RbcDagClockBridgeStateV1::Failed => {
                return Err(
                    "RBC-DAG startup recovery was invalid before clock activation".to_string(),
                );
            }
            RbcDagClockBridgeStateV1::Activated => return Ok(()),
        }

        shadow
            .activate_clock()
            .await
            .map_err(|error| format!("RBC-DAG clock activation failed: {error}"))?;
        wait_for_rbc_dag_clock_bridge_activation(&mut bridge_state).await
    }

    pub(crate) async fn shutdown(self) -> Option<Syncer<H, NetworkSyncSignals, C>> {
        drop(self.stop);
        // Stop new network/main ingress before asking the authoritative actor
        // to close. The actor, ordered router, bounded workers, and Core must
        // all remain alive until their already accepted work is drained.
        self.main_task.await.ok();
        self.inner
            .rbc_dag_shutdown_started
            .store(true, Ordering::Release);

        let mut shadow_shutdown_timed_out = false;
        if let Some(ref shadow) = self.inner.starfish_rbc_dag_shadow_service {
            let shutdown_timeout = if self.inner.embedded_rbc_authority {
                STARFISH_RBC_DAG_CONTROL_DRAIN_TIMEOUT
            } else {
                STARFISH_RBC_DAG_SHADOW_SHUTDOWN_TIMEOUT
            };
            match tokio::time::timeout(shutdown_timeout, shadow.shutdown()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!("RBC-DAG runtime did not acknowledge shutdown: {error}");
                    if self.inner.embedded_rbc_authority {
                        fail_rbc_dag_authority(
                            &self.inner.metrics,
                            self.inner.rbc_dag_clock_bridge_tx.as_ref(),
                            &format!("authoritative actor shutdown failed: {error}"),
                        );
                    }
                }
                Err(_) => {
                    shadow_shutdown_timed_out = true;
                    tracing::warn!("Timed out stopping RBC-DAG runtime");
                    if self.inner.embedded_rbc_authority {
                        fail_rbc_dag_authority(
                            &self.inner.metrics,
                            self.inner.rbc_dag_clock_bridge_tx.as_ref(),
                            "authoritative actor shutdown timed out",
                        );
                    }
                }
            }
        }

        let mut rbc_dag_shadow_service_task = self.rbc_dag_shadow_service_task;
        if let Some(mut actor_task) = rbc_dag_shadow_service_task.take() {
            if shadow_shutdown_timed_out {
                actor_task.abort();
                actor_task.await.ok();
            } else {
                match tokio::time::timeout(STARFISH_RBC_DAG_CONTROL_DRAIN_TIMEOUT, &mut actor_task)
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        if self.inner.embedded_rbc_authority {
                            fail_rbc_dag_authority(
                                &self.inner.metrics,
                                self.inner.rbc_dag_clock_bridge_tx.as_ref(),
                                &format!(
                                    "authoritative RBC-DAG actor supervisor failed during shutdown: {error}"
                                ),
                            );
                        } else {
                            tracing::warn!(
                                "RBC-DAG actor supervisor failed during shutdown: {error}"
                            );
                        }
                    }
                    Err(_) => {
                        fail_rbc_dag_authority(
                            &self.inner.metrics,
                            self.inner.rbc_dag_clock_bridge_tx.as_ref(),
                            "RBC-DAG actor supervisor did not stop after shutdown",
                        );
                        actor_task.abort();
                        actor_task.await.ok();
                    }
                }
            }
        }

        if let Some(mut router_task) = self.rbc_dag_shadow_event_task {
            match tokio::time::timeout(STARFISH_RBC_DAG_CONTROL_DRAIN_TIMEOUT, &mut router_task)
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => fail_rbc_dag_authority(
                    &self.inner.metrics,
                    self.inner.rbc_dag_clock_bridge_tx.as_ref(),
                    &format!("RBC-DAG event router failed during shutdown: {error}"),
                ),
                Err(_) => {
                    fail_rbc_dag_authority(
                        &self.inner.metrics,
                        self.inner.rbc_dag_clock_bridge_tx.as_ref(),
                        "RBC-DAG event router drain timed out",
                    );
                    router_task.abort();
                    router_task.await.ok();
                }
            }
        }

        for (name, task) in [
            ("assignment", self.rbc_dag_assignment_task),
            ("Core-control", self.rbc_dag_core_control_task),
        ] {
            let Some(mut task) = task else {
                continue;
            };
            match tokio::time::timeout(STARFISH_RBC_DAG_CONTROL_DRAIN_TIMEOUT, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => fail_rbc_dag_authority(
                    &self.inner.metrics,
                    self.inner.rbc_dag_clock_bridge_tx.as_ref(),
                    &format!("RBC-DAG {name} worker failed during shutdown: {error}"),
                ),
                Err(_) => {
                    fail_rbc_dag_authority(
                        &self.inner.metrics,
                        self.inner.rbc_dag_clock_bridge_tx.as_ref(),
                        &format!("RBC-DAG {name} worker drain timed out"),
                    );
                    task.abort();
                    task.await.ok();
                }
            }
        }

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
        // Stop RBC event ingress first, but keep the service actor alive while
        // the core queue drains: an already queued core action may still
        // synchronously select another local INIT.
        if let Some(rbc_task) = self.rbc_event_task {
            rbc_task.abort();
            rbc_task.await.ok();
        }
        let rbc_service_task = self.rbc_service_task;
        // Stop the cordial knowledge actor.
        self.cordial_knowledge_task.abort();
        self.cordial_knowledge_task.await.ok();
        // Some auxiliary tasks (e.g. per-round timeout timers) are spawned
        // detached and only notice shutdown once they get a chance to poll and
        // observe `stopped()`. Give them a short window to drop their `Arc`s
        // before insisting on `try_unwrap`.
        let mut inner_arc = self.inner;
        let unwrap_deadline = Instant::now() + Duration::from_secs(2);
        let inner = loop {
            match Arc::try_unwrap(inner_arc) {
                Ok(inner) => break inner,
                Err(arc) => {
                    if Instant::now() >= unwrap_deadline {
                        tracing::error!(
                            "Validator shutdown timed out waiting for auxiliary network workers"
                        );
                        if let Some(task) = rbc_service_task {
                            task.abort();
                        }
                        return None;
                    }
                    inner_arc = arc;
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        };
        // `inner` is now exclusive, so no auxiliary task can enqueue after
        // this FIFO barrier. Awaiting it keeps the runtime available to the
        // RBC actor while any earlier core action completes. The barrier is
        // fallible because the core thread may concurrently panic while the
        // remaining workers still need deterministic cleanup.
        let _ = inner.syncer.flush_for_shutdown().await;
        let syncer = match inner.syncer.stop() {
            Ok(syncer) => Some(syncer),
            Err(_) => {
                tracing::error!("Core thread terminated before validator shutdown completed");
                None
            }
        };
        if let Some(rbc_service_task) = rbc_service_task {
            rbc_service_task.abort();
            rbc_service_task.await.ok();
        }
        syncer
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.main_task.is_finished() || self.inner.syncer.is_finished()
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
        let soft_block_timeout_task = if inner.dag_state.consensus_protocol.uses_strong_vote() {
            Some(handle.spawn(Self::soft_block_timeout_task(inner.clone())))
        } else {
            None
        };

        // Embedded RBC-DAG frontiers are the sole commit authority. The
        // legacy 10 ms commit poll is a no-op in that mode and otherwise
        // needlessly submits roughly 100 core-thread commands per second.
        let commit_timeout_task = (!inner.embedded_rbc_authority)
            .then(|| handle.spawn(Self::commit_timeout_task(inner.clone())));
        let cleanup_task = handle.spawn(Self::cleanup_task(
            inner.clone(),
            bls_service.clone(),
            sf_service.clone(),
        ));
        let missing_parent_pull_task = handle.spawn(Self::missing_parent_pull_task(
            inner.clone(),
            metrics.clone(),
        ));
        let cert_pull_task = if inner
            .dag_state
            .consensus_protocol
            .carries_unprovable_certificate()
        {
            Some(handle.spawn(Self::unprovable_cert_pull_task(inner.clone())))
        } else {
            None
        };
        let round_gap_pull_task = if inner.dag_state.consensus_protocol.uses_compressed_refs() {
            Some(handle.spawn(Self::round_gap_pull_task(inner.clone())))
        } else {
            None
        };
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
                .chain([leader_timeout_task, cleanup_task, missing_parent_pull_task])
                .chain(commit_timeout_task)
                .chain(soft_block_timeout_task)
                .chain(cert_pull_task)
                .chain(round_gap_pull_task),
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

        let shadow_metrics = metrics.clone();
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
        let rbc_outbound_task = inner.starfish_rbc_service.is_some().then(|| {
            let (rbc_sender, mut rbc_receiver) = mpsc::unbounded_channel();
            inner.rbc_peer_senders.write().insert(peer_id, rbc_sender);
            let network_sender = connection.sender.clone();
            Handle::current().spawn(async move {
                while let Some(message) = rbc_receiver.recv().await {
                    send_network_message_reliably(&network_sender, message).await;
                }
            })
        });
        let rbc_dag_outbound_task = inner.starfish_rbc_dag_shadow_service.is_some().then(|| {
            let mailbox = RbcDagOutboundMailboxV1::new();
            inner
                .rbc_dag_peer_mailboxes
                .write()
                .insert(peer_id, mailbox.clone());
            let proactive_sender = connection.rbc_dag_proactive_sender.clone();
            let priority_sender = connection.rbc_dag_priority_sender.clone();
            let outbound_failure = connection.outbound_failure.clone();
            let worker_metrics = shadow_metrics.clone();
            let worker_bridge_tx = inner.rbc_dag_clock_bridge_tx.clone();
            let authoritative = inner.embedded_rbc_authority;
            Handle::current().spawn(async move {
                if let Err(error) = run_rbc_dag_outbound_worker(
                    mailbox,
                    proactive_sender,
                    priority_sender,
                    outbound_failure,
                )
                .await
                {
                    if authoritative {
                        fail_rbc_dag_authority(
                            &worker_metrics,
                            worker_bridge_tx.as_ref(),
                            &format!(
                                "RBC-DAG outbound worker for authority {peer_id} failed: {error}"
                            ),
                        );
                    } else {
                        invalidate_shadow_run(&worker_metrics);
                        tracing::error!(
                            peer = peer_id,
                            ?error,
                            "RBC-DAG observational outbound worker failed"
                        );
                    }
                }
            })
        });
        if let Some(ref rbc) = inner.starfish_rbc_service {
            if let Err(error) = rbc.peer_connected(peer_id) {
                tracing::warn!(
                    "Failed to notify Starfish-RBC service that authority {} connected: {}",
                    peer_id,
                    error
                );
            }
        }
        if let Some(ref shadow) = inner.starfish_rbc_dag_shadow_service {
            if let Err(error) = shadow.peer_connected(peer_id) {
                if shadow_transport_error_invalidates_run(&error) {
                    invalidate_shadow_run(&shadow_metrics);
                }
                tracing::warn!(
                    "Failed to notify RBC-DAG shadow that authority {} connected: {}",
                    peer_id,
                    error
                );
            }
        }

        if inner.dag_state.consensus_protocol.uses_bls() {
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
        if let Some(ref rbc) = inner.starfish_rbc_service {
            if let Err(error) = rbc.peer_disconnected(peer_id) {
                tracing::warn!(
                    "Failed to notify Starfish-RBC service that authority {} disconnected: {}",
                    peer_id,
                    error
                );
            }
        }
        if let Some(ref shadow) = inner.starfish_rbc_dag_shadow_service {
            if let Err(error) = shadow.peer_disconnected(peer_id) {
                if shadow_transport_error_invalidates_run(&error) {
                    invalidate_shadow_run(&shadow_metrics);
                }
                tracing::warn!(
                    "Failed to notify RBC-DAG shadow that authority {} disconnected: {}",
                    peer_id,
                    error
                );
            }
        }
        inner.peer_senders.write().remove(&peer_id);
        inner.rbc_peer_senders.write().remove(&peer_id);
        inner.rbc_dag_peer_mailboxes.write().remove(&peer_id);
        if let Some(rbc_outbound_task) = rbc_outbound_task {
            rbc_outbound_task.abort();
            rbc_outbound_task.await.ok();
        }
        if let Some(rbc_dag_outbound_task) = rbc_dag_outbound_task {
            rbc_dag_outbound_task.abort();
            rbc_dag_outbound_task.await.ok();
        }
        inner.syncer.authority_connection(peer_id, false).await;
        handler.shutdown().await;
        block_fetcher.remove_authority(peer_id).await;
        None
    }

    async fn leader_timeout_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        let mut armed_round = inner.dag_state.proposal_round().saturating_sub(1);
        loop {
            while inner.dag_state.proposal_round() <= armed_round {
                let proposal_round_advanced = inner.proposal_round_notify.notified();
                select! {
                    _notified = proposal_round_advanced => {}
                    _stopped = inner.stopped() => {
                        return None;
                    }
                }
            }

            let current_round = inner.dag_state.proposal_round();
            for round in armed_round + 1..=current_round {
                let timer_inner = inner.clone();
                Handle::current().spawn(async move {
                    let leader_timeout = timer_inner.leader_timeout;
                    select! {
                        _sleep = sleep(leader_timeout) => {
                            tracing::debug!("Timeout for proposal round {round}");
                            if let Some(ref sf) = timer_inner.sailfish_handle {
                                let leader_round = round.saturating_sub(1);
                                if leader_round > 0 {
                                    sf.send(SailfishServiceMessage::LocalTimeout(leader_round));
                                }
                            }
                            timer_inner.syncer.force_new_block(round).await;
                        }
                        _stopped = timer_inner.stopped() => {}
                    }
                });
            }
            armed_round = current_round;
        }
    }

    /// Strong-vote soft timeout (StarfishSpeed / SparseStarfishSpeed): once a
    /// proposal round can be entered but the strong-vote quorum has not formed,
    /// fall back to the base Starfish readiness check and propose a blame
    /// block. Armed on the proposal round so dual-DAG protocols (where the
    /// proposal round can lag the threshold clock) fire for the round they
    /// can actually enter.
    async fn soft_block_timeout_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        let soft_timeout = inner.soft_block_timeout;
        let mut armed_round = inner.dag_state.proposal_round();
        loop {
            while inner.dag_state.proposal_round() <= armed_round {
                let notified = inner.proposal_round_notify.notified();
                select! {
                    _notified = notified => {}
                    _stopped = inner.stopped() => {
                        return None;
                    }
                }
            }

            armed_round = inner.dag_state.proposal_round();
            let notified = inner.proposal_round_notify.notified();
            select! {
                _sleep = sleep(soft_timeout) => {
                    tracing::debug!("Soft block timeout in proposal round {armed_round}");
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

    /// Periodically re-requests block-manager parents that are still missing,
    /// fanning requests out to a few random peers instead of only the original
    /// sender.
    async fn missing_parent_pull_task(
        inner: Arc<NetworkSyncerInner<H, C>>,
        metrics: Arc<Metrics>,
    ) -> Option<()> {
        if inner.embedded_rbc_authority {
            return None;
        }
        const SCAN_INTERVAL: Duration = Duration::from_millis(500);
        const PEER_COUNT: usize = 2;

        let mut first_seen: AHashMap<BlockReference, Instant> = AHashMap::new();
        let mut last_requested: AHashMap<BlockReference, Instant> = AHashMap::new();

        loop {
            select! {
                _ = sleep(SCAN_INTERVAL) => {}
                _ = inner.stopped() => { return None; }
            }

            let missing_refs = inner.syncer.missing_parent_references().await;
            let now = Instant::now();
            let eligible_refs = eligible_missing_parent_refs(
                &missing_refs,
                &mut first_seen,
                &mut last_requested,
                now,
                SCAN_INTERVAL,
            );
            if eligible_refs.is_empty() {
                continue;
            }

            let senders = select_random_peer_senders(&inner, PEER_COUNT);
            if senders.is_empty() {
                continue;
            }

            tracing::debug!(
                "Retry missing parents {:?} from {} random peers",
                eligible_refs,
                senders.len()
            );
            for (peer, sender) in &senders {
                metrics
                    .block_sync_requests_sent
                    .with_label_values(&[&peer.to_string()])
                    .inc();
                send_network_message_reliably(
                    sender,
                    NetworkMessage::MissingParentsRequest(eligible_refs.clone()),
                )
                .await;
            }

            for block_ref in eligible_refs {
                last_requested.insert(block_ref, now);
            }
        }
    }

    /// Periodically scans for stalled Bluestreak unprovable certificates and
    /// requests missing voting blocks from random peers.
    async fn unprovable_cert_pull_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        const SCAN_INTERVAL: Duration = Duration::from_millis(100);
        const PEER_COUNT: usize = 2;

        // Tracking is keyed by (leader_ref, strong) so that standard and
        // strong cert flavors are rate-limited independently (SSFS).
        let mut first_seen: AHashMap<(BlockReference, bool), Instant> = AHashMap::new();
        let mut last_requested: AHashMap<(BlockReference, bool), Instant> = AHashMap::new();

        loop {
            select! {
                _ = sleep(SCAN_INTERVAL) => {}
                _ = inner.stopped() => { return None; }
            }

            let pending = inner.dag_state.pending_unprovable_certificates();
            let now = Instant::now();

            // Prune tracking maps for cert keys no longer pending.
            first_seen.retain(|k, _| pending.iter().any(|(lr, strong, _)| (*lr, *strong) == *k));
            last_requested
                .retain(|k, _| pending.iter().any(|(lr, strong, _)| (*lr, *strong) == *k));

            for (leader_ref, strong, known_voters) in &pending {
                let key = (*leader_ref, *strong);
                // Must have been waiting >= SCAN_INTERVAL before first request.
                let first = first_seen.entry(key).or_insert(now);
                if now.duration_since(*first) < SCAN_INTERVAL {
                    continue;
                }
                // Rate limit: one request per cert flavor per interval.
                if let Some(last) = last_requested.get(&key) {
                    if now.duration_since(*last) < SCAN_INTERVAL {
                        continue;
                    }
                }

                let senders = select_random_peer_senders(&inner, PEER_COUNT);
                if senders.is_empty() {
                    continue;
                }

                tracing::debug!(
                    "Request unprovable certificate support for leader {} \
                     (strong={}) from {} peers (known_voters={})",
                    leader_ref,
                    strong,
                    senders.len(),
                    known_voters.count_ones()
                );
                for (_peer, sender) in &senders {
                    let msg = NetworkMessage::UnprovableCertificateRequest {
                        leader_ref: *leader_ref,
                        known_voters: *known_voters,
                    };
                    let _ = sender.send(msg).await;
                }

                last_requested.insert(key, now);
            }
        }
    }

    /// Periodically checks whether the node's proposal round lags behind
    /// the highest observed DAG round. When the gap persists for two
    /// consecutive ticks, requests missing blocks at `highest_round - 1`
    /// from 2 random peers.
    async fn round_gap_pull_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        const SCAN_INTERVAL: Duration = Duration::from_millis(100);
        const PEER_COUNT: usize = 2;

        let mut gap_detected = false;

        loop {
            select! {
                _ = sleep(SCAN_INTERVAL) => {}
                _ = inner.stopped() => { return None; }
            }

            let highest_round = inner.dag_state.highest_round();
            let proposal_round = inner.dag_state.proposal_round();

            if proposal_round < highest_round {
                if !gap_detected {
                    gap_detected = true;
                    continue;
                }

                let senders = select_random_peer_senders(&inner, PEER_COUNT);
                if senders.is_empty() {
                    continue;
                }

                let target_round = highest_round - 1;
                let blocks = inner.dag_state.get_blocks_by_round_cached(target_round);
                let mut known_authorities = AuthoritySet::default();
                for b in blocks.iter() {
                    known_authorities.insert(b.authority());
                }

                tracing::debug!(
                    "Round gap detected: proposal_round={}, highest_round={}, \
                     requesting round {} from {} peers (known={})",
                    proposal_round,
                    highest_round,
                    target_round,
                    senders.len(),
                    known_authorities.count_ones()
                );

                for (_peer, sender) in &senders {
                    let msg = NetworkMessage::RoundGapRequest {
                        round: target_round,
                        known_authorities,
                    };
                    let _ = sender.send(msg).await;
                }

                // Reset so the two-tick gate must re-activate before the
                // next request.
                gap_detected = false;
            } else {
                gap_detected = false;
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

    fn proposal_round_advanced(&mut self, _round: RoundNumber) {
        self.proposal_round_notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use prometheus::Registry;
    use rand::{SeedableRng, rngs::StdRng};
    use tokio::sync::oneshot;

    use super::*;
    use crate::{
        crypto::{self, SignatureBytes},
        encoder::ShardEncoder,
        network::{
            RbcDagShadowCarrier, RbcDagShadowCarrierSyncRequest, RbcDagShadowCarrierSyncResponse,
        },
        starfish_rbc_dag::{
            CarrierHeaderV1Args, ConsensusVertexReference, carrier_genesis_reference,
        },
        types::{BaseTransaction, BlockReference, Transaction, TransactionData},
    };

    fn rbc_dag_outbound_test_carrier(
        committee: &Committee,
        creation_time_ns: TimestampNs,
    ) -> (BlockReference, NetworkMessage) {
        let candidate = CandidateCarrierV1::try_new(
            CarrierHeaderV1Args {
                author: 0,
                carrier_round: 1,
                own_prev: carrier_genesis_reference(0),
                weak_parents: vec![carrier_genesis_reference(1), carrier_genesis_reference(2)],
                transactions_commitment: TransactionsCommitment::default(),
                application_header: None,
                data_acknowledgments: Vec::new(),
                phase_batch: Vec::new(),
                consensus_vertex: None,
                creation_time_ns,
            },
            committee,
        )
        .unwrap();
        let reference = candidate.reference();
        (
            reference,
            NetworkMessage::RbcDagShadowCarrier(RbcDagShadowCarrier {
                canonical_carrier: candidate.canonical_wire_bytes().unwrap(),
                authentication_sidecar: vec![0xA5],
                application_payload: None,
            }),
        )
    }

    fn rbc_dag_outbound_test_sync_request(round: RoundNumber) -> NetworkMessage {
        NetworkMessage::RbcDagShadowCarrierSyncRequest(RbcDagShadowCarrierSyncRequest {
            author: 1,
            round,
        })
    }

    fn rbc_dag_outbound_test_sync_response(round: RoundNumber, marker: u8) -> NetworkMessage {
        NetworkMessage::RbcDagShadowCarrierSyncResponse(RbcDagShadowCarrierSyncResponse {
            author: 1,
            round,
            canonical_carrier: vec![marker],
            authentication_sidecar: vec![marker.wrapping_add(1)],
        })
    }

    #[derive(Default)]
    struct TestRbcDagCoreControlStateV1 {
        staged: Vec<BlockReference>,
        available: Vec<(BlockReference, bool)>,
        materialized: Vec<BlockReference>,
        assignments: Vec<BlockReference>,
        frontier_results: VecDeque<Result<bool, String>>,
        activations: usize,
        events: Vec<&'static str>,
    }

    #[derive(Default)]
    struct TestRbcDagCoreControlTargetV1 {
        state: Mutex<TestRbcDagCoreControlStateV1>,
        assignment_observed: Notify,
    }

    impl RbcDagCoreControlTargetV1 for TestRbcDagCoreControlTargetV1 {
        async fn stage_authorized_application(
            &self,
            header: RbcCanonicalHeader,
            _authorization_basis: ShadowApplicationAuthorizationBasisV1,
        ) -> Result<(), String> {
            let mut state = self.state.lock().unwrap();
            state.staged.push(header.reference());
            state.events.push("header");
            Ok(())
        }

        fn restore_available_application(
            &self,
            application: BlockReference,
            payload: Option<Arc<TransactionData>>,
        ) -> Result<(), String> {
            let mut state = self.state.lock().unwrap();
            state.available.push((application, payload.is_some()));
            state.events.push("available");
            Ok(())
        }

        async fn materialize_authorized_payload(
            &self,
            item: ReconstructedTransactionData,
        ) -> Result<(), String> {
            let mut state = self.state.lock().unwrap();
            state.materialized.push(item.block_reference);
            state.events.push("payload");
            Ok(())
        }

        async fn apply_frontier(&self, _delta: CommittedFrontierDeltaV1) -> Result<bool, String> {
            let mut state = self.state.lock().unwrap();
            state.events.push("frontier");
            state.frontier_results.pop_front().unwrap_or(Ok(true))
        }

        async fn activate_authority(&self) -> Result<(), String> {
            let mut state = self.state.lock().unwrap();
            state.activations += 1;
            state.events.push("activate");
            Ok(())
        }

        async fn apply_assignment(&self, reference: BlockReference) -> Result<(), String> {
            let mut state = self.state.lock().unwrap();
            state.assignments.push(reference);
            state.events.push("assignment");
            drop(state);
            self.assignment_observed.notify_waiters();
            Ok(())
        }
    }

    fn rbc_dag_worker_test_metrics() -> Arc<Metrics> {
        let registry = Registry::new();
        let (metrics, _) = Metrics::new(&registry, None, Some("starfish-rbc"), None);
        metrics.starfish_rbc_dag_shadow_clock_valid.set(-1);
        metrics
    }

    fn rbc_dag_worker_test_application() -> (RbcCanonicalHeader, ReconstructedTransactionData) {
        let committee = Committee::new_test(vec![1; 4]);
        let transactions = vec![BaseTransaction::Share(Transaction::new(vec![7; 64]))];
        let mut commitment_encoder =
            ReedSolomonEncoder::new(2, 4, 2).expect("encoder should be created");
        let encoded = commitment_encoder.encode_transactions(
            &transactions,
            committee.info_length(),
            committee.len() - committee.info_length(),
        );
        let (commitment, _) = TransactionsCommitment::new_from_encoded_transactions(&encoded, 1);
        let canonical = RbcCanonicalHeader::try_new(
            0,
            1,
            vec![
                BlockReference::new_test(0, 0),
                BlockReference::new_test(1, 0),
                BlockReference::new_test(2, 0),
            ],
            Vec::new(),
            11,
            commitment,
        )
        .unwrap();
        let mut verifier = ReedSolomonEncoder::new(2, 4, 2).expect("encoder should be created");
        let item = verify_starfish_rbc_transaction_payload(
            &canonical,
            Arc::new(TransactionData::new(transactions)),
            &committee,
            1,
            0,
            &mut verifier,
            BlockAuthenticationScheme::MacVector,
            &[],
        )
        .unwrap();
        (canonical, item)
    }

    fn rbc_dag_worker_test_delta() -> CommittedFrontierDeltaV1 {
        let carrier = BlockReference::new_test(0, 1);
        CommittedFrontierDeltaV1 {
            output_sequence: 1,
            anchor: ConsensusVertexReference::new(carrier, 1),
            frontier: Vec::new(),
            carriers: Vec::new(),
            applications: Vec::new(),
            application_diagnostics: Vec::new(),
        }
    }

    #[test]
    fn rbc_dag_outbound_mailbox_coalesces_exact_duplicates_and_rejects_conflicts() {
        let committee = Committee::new_test(vec![1; 4]);
        let committee_context = RbcDagCommitteeContextV1::new(committee).unwrap();
        let mailbox = RbcDagOutboundMailboxV1::new();
        assert_eq!(
            mailbox
                .enqueue(
                    rbc_dag_outbound_test_sync_response(7, 0xA1),
                    &committee_context,
                )
                .unwrap(),
            RbcDagOutboundEnqueueV1::Added
        );
        assert_eq!(
            mailbox
                .enqueue(
                    rbc_dag_outbound_test_sync_response(7, 0xA1),
                    &committee_context,
                )
                .unwrap(),
            RbcDagOutboundEnqueueV1::Coalesced
        );
        assert!(matches!(
            mailbox.enqueue(
                rbc_dag_outbound_test_sync_response(7, 0xB1),
                &committee_context,
            ),
            Err(RbcDagOutboundMailboxErrorV1::ConflictingDuplicate {
                class: RbcDagOutboundClassV1::Priority,
                key: RbcDagOutboundKeyV1::SyncResponse(1, 7),
            })
        ));
        let state = mailbox.inner.state.lock();
        assert_eq!(state.priority.entries.len(), 1);
        assert_eq!(state.priority.order.len(), 1);
    }

    #[test]
    fn rbc_dag_outbound_mailbox_drains_priority_before_proactive() {
        let committee = Committee::new_test(vec![1; 4]);
        let committee_context = RbcDagCommitteeContextV1::new(committee.clone()).unwrap();
        let mailbox = RbcDagOutboundMailboxV1::new();
        let (reference, proactive) = rbc_dag_outbound_test_carrier(&committee, 11);
        mailbox.enqueue(proactive, &committee_context).unwrap();
        mailbox
            .enqueue(rbc_dag_outbound_test_sync_request(9), &committee_context)
            .unwrap();

        let (class, first) = mailbox.try_pop().unwrap();
        assert_eq!(class, RbcDagOutboundClassV1::Priority);
        assert!(matches!(
            first,
            NetworkMessage::RbcDagShadowCarrierSyncRequest(RbcDagShadowCarrierSyncRequest {
                author: 1,
                round: 9,
            })
        ));
        let (class, second) = mailbox.try_pop().unwrap();
        assert_eq!(class, RbcDagOutboundClassV1::Proactive);
        assert!(matches!(
            rbc_dag_outbound_classification(&second, &committee_context, None)
                .unwrap()
                .1,
            RbcDagOutboundKeyV1::Proactive(actual) if actual == reference
        ));
    }

    #[test]
    fn rbc_dag_outbound_mailbox_never_evicts_a_unique_proactive_reference() {
        let committee = Committee::new_test(vec![1; 4]);
        let committee_context = RbcDagCommitteeContextV1::new(committee.clone()).unwrap();
        let mailbox = RbcDagOutboundMailboxV1::new();
        let mut first_reference = None;
        for marker in 1..=STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY {
            let (reference, message) =
                rbc_dag_outbound_test_carrier(&committee, marker as TimestampNs);
            first_reference.get_or_insert(reference);
            assert_eq!(
                mailbox.enqueue(message, &committee_context).unwrap(),
                RbcDagOutboundEnqueueV1::Added
            );
        }
        let (_, overflow) = rbc_dag_outbound_test_carrier(
            &committee,
            STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY as TimestampNs + 1,
        );
        assert!(matches!(
            mailbox.enqueue(overflow, &committee_context),
            Err(RbcDagOutboundMailboxErrorV1::KeyCapacity {
                class: RbcDagOutboundClassV1::Proactive,
                capacity: STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY,
            })
        ));
        let state = mailbox.inner.state.lock();
        assert_eq!(
            state.proactive.entries.len(),
            STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY
        );
        assert!(
            state
                .proactive
                .entries
                .contains_key(&RbcDagOutboundKeyV1::Proactive(first_reference.unwrap()))
        );
    }

    #[test]
    fn rbc_dag_outbound_mailbox_bounds_distinct_priority_keys_and_bytes() {
        let committee = Committee::new_test(vec![1; 4]);
        let committee_context = RbcDagCommitteeContextV1::new(committee).unwrap();
        let mailbox = RbcDagOutboundMailboxV1::new();
        for round in 1..=STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY as RoundNumber {
            mailbox
                .enqueue(
                    rbc_dag_outbound_test_sync_request(round),
                    &committee_context,
                )
                .unwrap();
        }
        assert!(matches!(
            mailbox.enqueue(
                rbc_dag_outbound_test_sync_request(
                    STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY as RoundNumber + 1,
                ),
                &committee_context,
            ),
            Err(RbcDagOutboundMailboxErrorV1::KeyCapacity {
                class: RbcDagOutboundClassV1::Priority,
                capacity: STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY,
            })
        ));
        assert_eq!(
            mailbox.inner.state.lock().priority.entries.len(),
            STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY
        );

        let first = rbc_dag_outbound_test_sync_request(1);
        let framed_bytes = usize::try_from(bincode::serialized_size(&first).unwrap())
            .unwrap()
            .checked_add(4)
            .unwrap();
        let byte_bounded = RbcDagOutboundMailboxV1::from_state(RbcDagOutboundMailboxStateV1 {
            priority: RbcDagOutboundLaneV1::new(
                STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY,
                framed_bytes * 2 - 1,
                framed_bytes,
            ),
            proactive: RbcDagOutboundLaneV1::new(
                STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY,
                STARFISH_RBC_DAG_OUTBOUND_PROACTIVE_BYTES,
                STARFISH_RBC_DAG_OUTBOUND_PROACTIVE_ENTRY_BYTES,
            ),
            failure: None,
        });
        byte_bounded.enqueue(first, &committee_context).unwrap();
        assert!(matches!(
            byte_bounded.enqueue(rbc_dag_outbound_test_sync_request(2), &committee_context,),
            Err(RbcDagOutboundMailboxErrorV1::ByteCapacity {
                class: RbcDagOutboundClassV1::Priority,
                ..
            })
        ));
        let state = byte_bounded.inner.state.lock();
        assert_eq!(state.priority.entries.len(), 1);
        assert_eq!(state.priority.bytes, framed_bytes);
    }

    #[test]
    fn rbc_dag_outbound_saturation_fails_authority_or_observation_explicitly() {
        let error = RbcDagOutboundMailboxErrorV1::KeyCapacity {
            class: RbcDagOutboundClassV1::Proactive,
            capacity: STARFISH_RBC_DAG_OUTBOUND_KEY_CAPACITY,
        };
        let authority_metrics = rbc_dag_worker_test_metrics();
        let (authority_bridge, authority_state) =
            watch::channel(RbcDagClockBridgeStateV1::Activated);
        fail_rbc_dag_outbound_transport(
            &authority_metrics,
            Some(&authority_bridge),
            true,
            2,
            &error,
        );
        assert_eq!(*authority_state.borrow(), RbcDagClockBridgeStateV1::Failed);
        assert_eq!(
            authority_metrics.starfish_rbc_dag_shadow_clock_valid.get(),
            0
        );

        let observation_metrics = rbc_dag_worker_test_metrics();
        let (observation_bridge, observation_state) =
            watch::channel(RbcDagClockBridgeStateV1::Activated);
        fail_rbc_dag_outbound_transport(
            &observation_metrics,
            Some(&observation_bridge),
            false,
            2,
            &error,
        );
        assert_eq!(
            *observation_state.borrow(),
            RbcDagClockBridgeStateV1::Activated
        );
        assert_eq!(
            observation_metrics
                .starfish_rbc_dag_shadow_clock_valid
                .get(),
            0
        );
    }

    #[tokio::test]
    async fn proposal_round_signal_notifies_waiters() {
        let block_ready_notify = Arc::new(Notify::new());
        let proposal_round_notify = Arc::new(Notify::new());
        let mut signals = NetworkSyncSignals {
            block_ready_notify,
            proposal_round_notify: proposal_round_notify.clone(),
        };

        let wait = proposal_round_notify.notified();
        signals.proposal_round_advanced(5);
        wait.await;
    }

    #[tokio::test]
    async fn rbc_dag_clock_bridge_activation_ack_is_fail_closed() {
        let (bridge_tx, mut bridge_state) = watch::channel(RbcDagClockBridgeStateV1::Pending);
        fail_rbc_dag_clock_bridge(Some(&bridge_tx));

        let error = wait_for_rbc_dag_clock_bridge_activation(&mut bridge_state)
            .await
            .unwrap_err();
        assert!(error.contains("startup recovery was invalid"));
    }

    #[tokio::test]
    async fn rbc_dag_clock_bridge_activation_ack_is_observable_without_a_lost_wakeup() {
        let (bridge_tx, mut bridge_state) = watch::channel(RbcDagClockBridgeStateV1::Pending);
        bridge_tx.send_replace(RbcDagClockBridgeStateV1::Activated);

        wait_for_rbc_dag_clock_bridge_activation(&mut bridge_state)
            .await
            .unwrap();

        // A caller that already observed activation remains returned, while
        // every later observer and authority command sees permanent failure.
        fail_rbc_dag_clock_bridge(Some(&bridge_tx));
        assert_eq!(
            *bridge_state.borrow_and_update(),
            RbcDagClockBridgeStateV1::Failed
        );
    }

    #[tokio::test]
    async fn rbc_dag_assignment_lane_is_not_delayed_by_payload_verification() {
        let target = Arc::new(TestRbcDagCoreControlTargetV1::default());
        let metrics = rbc_dag_worker_test_metrics();
        let (bridge_tx, _bridge_rx) = watch::channel(RbcDagClockBridgeStateV1::Pending);
        let shutdown_started = Arc::new(AtomicBool::new(false));
        let (control_tx, control_rx) = mpsc::channel(1);
        let (assignment_tx, assignment_rx) = mpsc::channel(1);
        let control_task = tokio::spawn(run_rbc_dag_core_control_worker(
            target.clone(),
            metrics.clone(),
            bridge_tx.clone(),
            shutdown_started.clone(),
            control_rx,
        ));
        let assignment_task = tokio::spawn(run_rbc_dag_application_assignment_worker(
            target.clone(),
            metrics,
            bridge_tx,
            shutdown_started,
            assignment_rx,
        ));
        let (release_payload, wait_for_payload) = oneshot::channel::<()>();
        let payload_task = tokio::spawn(async move {
            wait_for_payload.await.unwrap();
            Ok(Err(eyre::eyre!("delayed untrusted payload")))
        });
        let (header, _) = rbc_dag_worker_test_application();
        control_tx
            .send(RbcDagCoreControlCommandV1::AuthorizedApplicationObserved {
                carrier: BlockReference::new_test(1, 2),
                header,
                authorization_basis: ShadowApplicationAuthorizationBasisV1::Delivered,
                payload: RbcDagAuthorizedPayloadV1::Verify(payload_task),
            })
            .await
            .unwrap();

        let assignment = BlockReference::new_test(0, 3);
        let observed = target.assignment_observed.notified();
        assignment_tx
            .send(RbcDagApplicationAssignmentCommandV1::Assigned(assignment))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_millis(100), observed)
            .await
            .expect("assignment must bypass the blocked payload FIFO");
        assert_eq!(target.state.lock().unwrap().assignments, vec![assignment]);

        release_payload.send(()).unwrap();
        control_tx
            .send(RbcDagCoreControlCommandV1::Drain)
            .await
            .unwrap();
        assignment_tx
            .send(RbcDagApplicationAssignmentCommandV1::Drain)
            .await
            .unwrap();
        control_task.await.unwrap();
        assignment_task.await.unwrap();
    }

    #[tokio::test]
    async fn rbc_dag_router_fail_fast_blocks_assignment_while_payload_is_slow() {
        let target = Arc::new(TestRbcDagCoreControlTargetV1::default());
        let metrics = rbc_dag_worker_test_metrics();
        let (bridge_tx, bridge_rx) = watch::channel(RbcDagClockBridgeStateV1::Pending);
        let shutdown_started = Arc::new(AtomicBool::new(false));
        let (control_tx, control_rx) = mpsc::channel(1);
        let (assignment_tx, assignment_rx) = mpsc::channel(1);
        let control_task = tokio::spawn(run_rbc_dag_core_control_worker(
            target.clone(),
            metrics.clone(),
            bridge_tx.clone(),
            shutdown_started.clone(),
            control_rx,
        ));
        let assignment_task = tokio::spawn(run_rbc_dag_application_assignment_worker(
            target.clone(),
            metrics.clone(),
            bridge_tx.clone(),
            shutdown_started,
            assignment_rx,
        ));
        let (release_payload, wait_for_payload) = oneshot::channel::<()>();
        let (header, _) = rbc_dag_worker_test_application();
        control_tx
            .send(RbcDagCoreControlCommandV1::AuthorizedApplicationObserved {
                carrier: BlockReference::new_test(1, 2),
                header,
                authorization_basis: ShadowApplicationAuthorizationBasisV1::Delivered,
                payload: RbcDagAuthorizedPayloadV1::Verify(tokio::spawn(async move {
                    wait_for_payload.await.unwrap();
                    Ok(Err(eyre::eyre!("slow untrusted payload")))
                })),
            })
            .await
            .unwrap();

        // This models a router-known invalid header: failure is published
        // synchronously instead of sitting behind the slow FIFO command.
        fail_rbc_dag_authority(
            &metrics,
            Some(&bridge_tx),
            "router rejected an invalid authoritative header",
        );
        let assignment = BlockReference::new_test(0, 3);
        assignment_tx
            .send(RbcDagApplicationAssignmentCommandV1::Assigned(assignment))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(*bridge_rx.borrow(), RbcDagClockBridgeStateV1::Failed);
        assert!(target.state.lock().unwrap().assignments.is_empty());

        release_payload.send(()).unwrap();
        control_tx
            .send(RbcDagCoreControlCommandV1::Drain)
            .await
            .unwrap();
        assignment_tx
            .send(RbcDagApplicationAssignmentCommandV1::Drain)
            .await
            .unwrap();
        control_task.await.unwrap();
        assignment_task.await.unwrap();
    }

    #[tokio::test]
    async fn rbc_dag_worker_failure_blocks_later_assignment_at_apply_boundary() {
        let target = Arc::new(TestRbcDagCoreControlTargetV1::default());
        target
            .state
            .lock()
            .unwrap()
            .frontier_results
            .push_back(Err("rejected frontier".to_owned()));
        let metrics = rbc_dag_worker_test_metrics();
        let (bridge_tx, mut bridge_rx) = watch::channel(RbcDagClockBridgeStateV1::Pending);
        let shutdown_started = Arc::new(AtomicBool::new(false));
        let (control_tx, control_rx) = mpsc::channel(2);
        let (assignment_tx, assignment_rx) = mpsc::channel(1);
        let control_task = tokio::spawn(run_rbc_dag_core_control_worker(
            target.clone(),
            metrics.clone(),
            bridge_tx.clone(),
            shutdown_started.clone(),
            control_rx,
        ));
        let assignment_task = tokio::spawn(run_rbc_dag_application_assignment_worker(
            target.clone(),
            metrics,
            bridge_tx,
            shutdown_started,
            assignment_rx,
        ));

        control_tx
            .send(RbcDagCoreControlCommandV1::Frontier(
                rbc_dag_worker_test_delta(),
            ))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_millis(100), async {
            while *bridge_rx.borrow_and_update() != RbcDagClockBridgeStateV1::Failed {
                bridge_rx.changed().await.unwrap();
            }
        })
        .await
        .expect("frontier rejection must fail authority promptly");

        assignment_tx
            .send(RbcDagApplicationAssignmentCommandV1::Assigned(
                BlockReference::new_test(0, 3),
            ))
            .await
            .unwrap();
        control_tx
            .send(RbcDagCoreControlCommandV1::Drain)
            .await
            .unwrap();
        assignment_tx
            .send(RbcDagApplicationAssignmentCommandV1::Drain)
            .await
            .unwrap();
        control_task.await.unwrap();
        assignment_task.await.unwrap();

        assert!(target.state.lock().unwrap().assignments.is_empty());
    }

    #[tokio::test]
    async fn rbc_dag_bad_attached_payload_allows_later_valid_materialization() {
        let target = Arc::new(TestRbcDagCoreControlTargetV1::default());
        let metrics = rbc_dag_worker_test_metrics();
        let (bridge_tx, bridge_rx) = watch::channel(RbcDagClockBridgeStateV1::Pending);
        let (control_tx, control_rx) = mpsc::channel(4);
        let worker = tokio::spawn(run_rbc_dag_core_control_worker(
            target.clone(),
            metrics,
            bridge_tx,
            Arc::new(AtomicBool::new(false)),
            control_rx,
        ));
        let (header, valid_item) = rbc_dag_worker_test_application();
        let application = header.reference();
        control_tx
            .send(RbcDagCoreControlCommandV1::AuthorizedApplicationObserved {
                carrier: BlockReference::new_test(1, 2),
                header: header.clone(),
                authorization_basis: ShadowApplicationAuthorizationBasisV1::Delivered,
                payload: RbcDagAuthorizedPayloadV1::Verify(tokio::spawn(async {
                    Ok(Err(eyre::eyre!("bad attached bytes")))
                })),
            })
            .await
            .unwrap();
        control_tx
            .send(RbcDagCoreControlCommandV1::AuthorizedApplicationObserved {
                carrier: BlockReference::new_test(2, 3),
                header,
                authorization_basis: ShadowApplicationAuthorizationBasisV1::Delivered,
                payload: RbcDagAuthorizedPayloadV1::Verify(tokio::spawn(async move {
                    Ok(Ok(valid_item))
                })),
            })
            .await
            .unwrap();
        control_tx
            .send(RbcDagCoreControlCommandV1::Drain)
            .await
            .unwrap();
        worker.await.unwrap();

        assert_ne!(*bridge_rx.borrow(), RbcDagClockBridgeStateV1::Failed);
        let state = target.state.lock().unwrap();
        assert_eq!(state.staged, vec![application, application]);
        assert_eq!(state.materialized, vec![application]);
    }

    #[tokio::test]
    async fn rbc_dag_exact_frontier_replay_has_no_applied_metric_or_effect() {
        let target = Arc::new(TestRbcDagCoreControlTargetV1::default());
        target
            .state
            .lock()
            .unwrap()
            .frontier_results
            .push_back(Ok(false));
        let metrics = rbc_dag_worker_test_metrics();
        let applied_before = metrics
            .starfish_rbc_dag_frontier_events_total
            .with_label_values(&["applied"])
            .get();
        let (bridge_tx, _bridge_rx) = watch::channel(RbcDagClockBridgeStateV1::Pending);
        let (control_tx, control_rx) = mpsc::channel(2);
        let worker = tokio::spawn(run_rbc_dag_core_control_worker(
            target,
            metrics.clone(),
            bridge_tx,
            Arc::new(AtomicBool::new(false)),
            control_rx,
        ));
        control_tx
            .send(RbcDagCoreControlCommandV1::Frontier(
                rbc_dag_worker_test_delta(),
            ))
            .await
            .unwrap();
        control_tx
            .send(RbcDagCoreControlCommandV1::Drain)
            .await
            .unwrap();
        worker.await.unwrap();
        assert_eq!(
            metrics
                .starfish_rbc_dag_frontier_events_total
                .with_label_values(&["applied"])
                .get(),
            applied_before
        );
    }

    #[tokio::test]
    async fn rbc_dag_graceful_drain_applies_queued_frontier_before_exit() {
        let target = Arc::new(TestRbcDagCoreControlTargetV1::default());
        let metrics = rbc_dag_worker_test_metrics();
        let (bridge_tx, bridge_rx) = watch::channel(RbcDagClockBridgeStateV1::Pending);
        let (control_tx, control_rx) = mpsc::channel(4);
        let worker = tokio::spawn(run_rbc_dag_core_control_worker(
            target.clone(),
            metrics,
            bridge_tx,
            Arc::new(AtomicBool::new(true)),
            control_rx,
        ));
        let (release_payload, wait_for_payload) = oneshot::channel::<()>();
        let (header, item) = rbc_dag_worker_test_application();
        control_tx
            .send(RbcDagCoreControlCommandV1::AuthorizedApplicationObserved {
                carrier: BlockReference::new_test(1, 2),
                header,
                authorization_basis: ShadowApplicationAuthorizationBasisV1::Delivered,
                payload: RbcDagAuthorizedPayloadV1::Verify(tokio::spawn(async move {
                    wait_for_payload.await.unwrap();
                    Ok(Ok(item))
                })),
            })
            .await
            .unwrap();
        control_tx
            .send(RbcDagCoreControlCommandV1::Frontier(
                rbc_dag_worker_test_delta(),
            ))
            .await
            .unwrap();
        control_tx
            .send(RbcDagCoreControlCommandV1::Drain)
            .await
            .unwrap();
        assert!(!worker.is_finished());
        release_payload.send(()).unwrap();
        worker.await.unwrap();

        assert_ne!(*bridge_rx.borrow(), RbcDagClockBridgeStateV1::Failed);
        assert_eq!(
            target.state.lock().unwrap().events,
            vec!["header", "payload", "frontier"]
        );
    }

    #[tokio::test]
    async fn rbc_dag_shutdown_skips_actor_callback_and_assignment_but_applies_frontier() {
        let target = Arc::new(TestRbcDagCoreControlTargetV1::default());
        let metrics = rbc_dag_worker_test_metrics();
        let (bridge_tx, bridge_rx) = watch::channel(RbcDagClockBridgeStateV1::Pending);
        let shutdown_started = Arc::new(AtomicBool::new(true));
        let (control_tx, control_rx) = mpsc::channel(3);
        let (assignment_tx, assignment_rx) = mpsc::channel(1);
        let control_task = tokio::spawn(run_rbc_dag_core_control_worker(
            target.clone(),
            metrics.clone(),
            bridge_tx.clone(),
            shutdown_started.clone(),
            control_rx,
        ));
        let assignment_task = tokio::spawn(run_rbc_dag_application_assignment_worker(
            target.clone(),
            metrics,
            bridge_tx,
            shutdown_started,
            assignment_rx,
        ));
        let (header, _) = rbc_dag_worker_test_application();
        control_tx
            .send(RbcDagCoreControlCommandV1::AuthorizedApplicationObserved {
                carrier: BlockReference::new_test(1, 2),
                header,
                authorization_basis: ShadowApplicationAuthorizationBasisV1::Delivered,
                payload: RbcDagAuthorizedPayloadV1::AlreadyAvailable(None),
            })
            .await
            .unwrap();
        control_tx
            .send(RbcDagCoreControlCommandV1::Frontier(
                rbc_dag_worker_test_delta(),
            ))
            .await
            .unwrap();
        assignment_tx
            .send(RbcDagApplicationAssignmentCommandV1::Assigned(
                BlockReference::new_test(0, 3),
            ))
            .await
            .unwrap();
        control_tx
            .send(RbcDagCoreControlCommandV1::Drain)
            .await
            .unwrap();
        assignment_tx
            .send(RbcDagApplicationAssignmentCommandV1::Drain)
            .await
            .unwrap();
        control_task.await.unwrap();
        assignment_task.await.unwrap();

        assert_ne!(*bridge_rx.borrow(), RbcDagClockBridgeStateV1::Failed);
        let state = target.state.lock().unwrap();
        assert!(state.available.is_empty());
        assert!(state.assignments.is_empty());
        assert_eq!(state.events, vec!["header", "frontier"]);
    }

    #[tokio::test]
    async fn rbc_dag_empty_available_application_precedes_ready_and_activation() {
        let target = Arc::new(TestRbcDagCoreControlTargetV1::default());
        let metrics = rbc_dag_worker_test_metrics();
        let (bridge_tx, bridge_rx) = watch::channel(RbcDagClockBridgeStateV1::Pending);
        let (control_tx, control_rx) = mpsc::channel(4);
        let worker = tokio::spawn(run_rbc_dag_core_control_worker(
            target.clone(),
            metrics,
            bridge_tx,
            Arc::new(AtomicBool::new(false)),
            control_rx,
        ));
        let header = RbcCanonicalHeader::try_new(
            0,
            1,
            vec![
                BlockReference::new_test(0, 0),
                BlockReference::new_test(1, 0),
                BlockReference::new_test(2, 0),
            ],
            Vec::new(),
            11,
            TransactionsCommitment::default(),
        )
        .unwrap();
        let application = header.reference();
        for command in [
            RbcDagCoreControlCommandV1::AuthorizedApplicationObserved {
                carrier: BlockReference::new_test(1, 2),
                header,
                authorization_basis: ShadowApplicationAuthorizationBasisV1::Delivered,
                payload: RbcDagAuthorizedPayloadV1::AlreadyAvailable(None),
            },
            RbcDagCoreControlCommandV1::Ready,
            RbcDagCoreControlCommandV1::Activate,
            RbcDagCoreControlCommandV1::Drain,
        ] {
            control_tx.send(command).await.unwrap();
        }
        worker.await.unwrap();
        assert_eq!(*bridge_rx.borrow(), RbcDagClockBridgeStateV1::Activated);
        let state = target.state.lock().unwrap();
        assert_eq!(state.available, vec![(application, false)]);
        assert_eq!(state.events, vec!["header", "available", "activate"]);
    }

    #[test]
    fn starfish_rbc_initial_payload_is_commitment_checked() {
        let committee = Committee::new_test(vec![1; 4]);
        let transactions = vec![BaseTransaction::Share(Transaction::new(vec![7; 64]))];
        let mut commitment_encoder =
            ReedSolomonEncoder::new(2, 4, 2).expect("encoder should be created");
        let encoded = commitment_encoder.encode_transactions(
            &transactions,
            committee.info_length(),
            committee.len() - committee.info_length(),
        );
        let (commitment, _) = TransactionsCommitment::new_from_encoded_transactions(&encoded, 1);
        let canonical = RbcCanonicalHeader::try_new(
            0,
            1,
            vec![
                BlockReference::new_test(0, 0),
                BlockReference::new_test(1, 0),
                BlockReference::new_test(2, 0),
            ],
            Vec::new(),
            11,
            commitment,
        )
        .unwrap();
        let payload = Arc::new(TransactionData::new(transactions.clone()));
        let mut verifier = ReedSolomonEncoder::new(2, 4, 2).expect("encoder should be created");
        let verified = verify_starfish_rbc_transaction_payload(
            &canonical,
            payload,
            &committee,
            1,
            0,
            &mut verifier,
            BlockAuthenticationScheme::MacVector,
            &[],
        )
        .unwrap();
        assert_eq!(verified.block_reference, canonical.reference());
        assert_eq!(verified.transaction_data.transactions(), &transactions);
        assert_eq!(verified.shard_data.shard_index(), 1);

        let tampered = Arc::new(TransactionData::new(vec![BaseTransaction::Share(
            Transaction::new(vec![8; 64]),
        )]));
        assert!(
            verify_starfish_rbc_transaction_payload(
                &canonical,
                tampered,
                &committee,
                1,
                0,
                &mut verifier,
                BlockAuthenticationScheme::MacVector,
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn block_filter_allows_exactly_one_tag_to_full_mac_upgrade() {
        let filter = FilterForBlocks::new();
        let digest = BlockReference::new_test(1, 7).digest;

        assert_eq!(
            filter.needed_headers(&[(digest, false), (digest, true), (digest, true)]),
            vec![true, true, false]
        );
        assert_eq!(
            filter.insert_and_report_useful(&[(digest, false)]),
            vec![true]
        );
        assert_eq!(filter.needed_headers(&[(digest, false)]), vec![false]);
        assert_eq!(filter.needed_headers(&[(digest, true)]), vec![true]);
        assert_eq!(
            filter.insert_and_report_useful(&[(digest, true), (digest, true)]),
            vec![true, false]
        );
        assert_eq!(filter.needed_headers(&[(digest, true)]), vec![false]);
        assert_eq!(filter.contains_full_mac_batch(&[digest]), vec![true]);
    }

    #[test]
    fn full_mac_vectors_require_direct_author_block_streaming() {
        let committee = Committee::new_for_benchmarks(4);
        let keyrings = crypto::mac_keyrings_for_test(committee.len());
        let mut full = VerifiedBlock::new(
            1,
            1,
            Vec::new(),
            Vec::new(),
            0,
            SignatureBytes::default(),
            Vec::new(),
            None,
            None,
            None,
            None,
        );
        let tags = keyrings[1]
            .iter()
            .enumerate()
            .map(|(recipient, key)| key.compute_tag(1, recipient as AuthorityIndex, &full.digest()))
            .collect();
        full.header.authentication = BlockAuthentication::MacVector(tags);

        assert!(
            verify_mac_transport(
                &full,
                BlockAuthenticationScheme::MacVector,
                1,
                DataSource::BlockBundleStreaming,
            )
            .is_ok()
        );
        assert!(
            verify_mac_transport(
                &full,
                BlockAuthenticationScheme::MacVector,
                1,
                DataSource::BlockBundleStreamingHeader,
            )
            .is_ok()
        );
        assert!(
            verify_mac_transport(
                &full,
                BlockAuthenticationScheme::MacVector,
                2,
                DataSource::BlockBundleStreaming,
            )
            .is_err()
        );
        assert!(
            verify_mac_transport(
                &full,
                BlockAuthenticationScheme::MacVector,
                1,
                DataSource::BlockHeaderRequest,
            )
            .is_err()
        );

        let tagged = full.with_recipient_mac(0).unwrap();
        assert!(
            verify_mac_transport(
                &tagged,
                BlockAuthenticationScheme::MacVector,
                2,
                DataSource::BlockBundleStreaming,
            )
            .is_ok()
        );
        assert!(
            verify_mac_transport(
                &tagged,
                BlockAuthenticationScheme::MacVector,
                1,
                DataSource::BlockHeaderRequest,
            )
            .is_ok()
        );
        assert!(
            verify_mac_transport(
                &tagged,
                BlockAuthenticationScheme::MacVector,
                1,
                DataSource::BlockBundleStreaming,
            )
            .is_err()
        );

        let round_gap_blocks = prepare_forwarded_blocks_for_peer(
            BlockAuthenticationScheme::MacVector,
            ConsensusProtocol::Bluestreak,
            0,
            vec![Data::new(full)],
        );
        assert_eq!(round_gap_blocks.len(), 1);
        assert!(matches!(
            round_gap_blocks[0].authentication(),
            BlockAuthentication::MacTag(_)
        ));
        assert!(
            verify_mac_transport(
                &round_gap_blocks[0],
                BlockAuthenticationScheme::MacVector,
                2,
                DataSource::RoundGapResponse,
            )
            .is_ok()
        );
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
            None,
            None,
            None,
            None,
        ));

        let mut ck = ConnectionKnowledge::new(1, 4);
        infer_peer_knowledge_from_received_batch(&mut ck, &[block], &[], &[]);

        assert!(ck.knows_header(&ack_ref));
        assert!(ck.knows_shard(&ack_ref));
    }

    #[test]
    fn missing_parent_retry_waits_and_retries_after_interval() {
        const INTERVAL: Duration = Duration::from_millis(500);

        let missing = BlockReference::new_test(3, 7);
        let now = Instant::now();
        let mut first_seen = AHashMap::new();
        let mut last_requested = AHashMap::new();

        assert!(
            eligible_missing_parent_refs(
                &[missing],
                &mut first_seen,
                &mut last_requested,
                now,
                INTERVAL,
            )
            .is_empty()
        );
        assert_eq!(first_seen.get(&missing), Some(&now));

        let eligible = eligible_missing_parent_refs(
            &[missing],
            &mut first_seen,
            &mut last_requested,
            now + INTERVAL,
            INTERVAL,
        );
        assert_eq!(eligible, vec![missing]);

        last_requested.insert(missing, now + INTERVAL);
        assert!(
            eligible_missing_parent_refs(
                &[missing],
                &mut first_seen,
                &mut last_requested,
                now + INTERVAL + Duration::from_millis(100),
                INTERVAL,
            )
            .is_empty()
        );

        let eligible = eligible_missing_parent_refs(
            &[missing],
            &mut first_seen,
            &mut last_requested,
            now + INTERVAL * 2,
            INTERVAL,
        );
        assert_eq!(eligible, vec![missing]);
    }

    #[test]
    fn missing_parent_retry_prunes_resolved_refs() {
        const INTERVAL: Duration = Duration::from_millis(500);

        let missing = BlockReference::new_test(1, 9);
        let now = Instant::now();
        let mut first_seen = AHashMap::from_iter([(missing, now)]);
        let mut last_requested = AHashMap::from_iter([(missing, now)]);

        assert!(
            eligible_missing_parent_refs(
                &[],
                &mut first_seen,
                &mut last_requested,
                now + INTERVAL,
                INTERVAL,
            )
            .is_empty()
        );
        assert!(first_seen.is_empty());
        assert!(last_requested.is_empty());
    }

    #[test]
    fn random_peer_selection_is_capped() {
        let candidates: Vec<AuthorityIndex> = (0..10).collect();
        let mut rng = StdRng::seed_from_u64(7);
        let selected = select_random_peers(candidates.clone(), 5, &mut rng);
        let unique: AHashSet<_> = selected.iter().copied().collect();

        assert_eq!(selected.len(), 5);
        assert_eq!(unique.len(), selected.len());
        assert!(selected.iter().all(|peer| candidates.contains(peer)));
    }

    #[test]
    fn autonomous_carriers_use_a_distinct_authentication_namespace() {
        let direct = [0x5A; 32];
        let mirror = rbc_dag_shadow_protocol_instance(direct, false);
        let autonomous = rbc_dag_shadow_protocol_instance(direct, true);

        assert_eq!(mirror.as_bytes(), &direct);
        assert_ne!(autonomous, mirror);
        assert_eq!(
            autonomous,
            rbc_dag_shadow_protocol_instance(direct, true),
            "derived autonomous namespace must be deterministic across nodes"
        );
    }
}
