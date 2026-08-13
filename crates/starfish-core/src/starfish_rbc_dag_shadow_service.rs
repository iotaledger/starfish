// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Async, non-authoritative network adapter for the persisted RBC-DAG shadow.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use tokio::{
    sync::{
        mpsc::{self, error::TrySendError},
        oneshot,
    },
    task::JoinHandle,
};

use crate::{
    crypto::{MAC_TAG_SIZE, ML_DSA_44_SIGNATURE_SIZE, ML_DSA_65_SIGNATURE_SIZE, SIGNATURE_SIZE},
    network::{NetworkMessage, RbcDagShadowCarrier, RbcDagShadowCarrierResponse},
    starfish_rbc::RbcCanonicalHeader,
    starfish_rbc_dag::{
        MAX_CARRIER_CONTENT_SIZE_V1, RbcDagCommitteeContextV1, RbcDagContextV1,
        model::{ModelEffect, ModelError},
    },
    starfish_rbc_dag_shadow::{
        ShadowAuthorizerV1, ShadowDeliveryComparisonV1, ShadowDeliveryIdentityV1,
        ShadowDeliverySlotV1, ShadowErrorV1, ShadowIngressDispositionV1, ShadowOpenReportV1,
        ShadowOutboundEnvelopeV1, StarfishRbcDagShadowV1,
    },
    types::{AuthorityIndex, BlockAuthenticationScheme, BlockReference, RoundNumber, TimestampNs},
};

// A shadow run must absorb one complete committee fan-in plus a small reserve
// for the local carrier and control notifications before its single fsync
// owner can drain. At the four-MiB carrier cap, allowing at most 64 queued
// inputs also caps carrier payload retention at 256 MiB (plus bounded
// sidecars and allocator overhead). Larger committees are rejected for this
// benchmark prototype instead of silently under-sizing the queue and
// reporting incomparable results.
// Use the full bounded allowance even for a small committee. A single fan-in
// reserve is insufficient when several round bursts arrive while the actor is
// synchronously making the previous transition durable.
const SHADOW_SERVICE_MIN_INPUT_CAPACITY_V1: usize = 64;
const SHADOW_SERVICE_MAX_INPUT_CAPACITY_V1: usize = 64;
const SHADOW_SERVICE_CONTROL_RESERVE_V1: usize = 5;
const SHADOW_SERVICE_EVENT_CAPACITY_V1: usize = 16;
const SHADOW_RECOVERY_RETRY_INTERVAL_V1: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ShadowLocalCarrierV1 {
    author: AuthorityIndex,
    round: RoundNumber,
    transactions_commitment: crate::crypto::TransactionsCommitment,
    creation_time_ns: TimestampNs,
}

impl ShadowLocalCarrierV1 {
    fn from_direct_header(header: &RbcCanonicalHeader) -> Self {
        Self {
            author: header.reference().authority,
            round: header.reference().round,
            transactions_commitment: header.transactions_commitment(),
            creation_time_ns: header.meta_creation_time_ns(),
        }
    }
}

enum ShadowServiceMessageV1 {
    LocalCarrier(ShadowLocalCarrierV1),
    Carrier {
        peer: AuthorityIndex,
        envelope: RbcDagShadowCarrier,
    },
    CarrierRequest {
        peer: AuthorityIndex,
        reference: BlockReference,
    },
    CarrierResponse {
        peer: AuthorityIndex,
        response: RbcDagShadowCarrierResponse,
    },
    DirectDeliveriesChanged,
    TopologyChanged,
    RetryRecovery,
    Shutdown(oneshot::Sender<Result<(), ShadowServiceErrorV1>>),
}

#[derive(Clone)]
pub(crate) struct StarfishRbcDagShadowServiceHandleV1 {
    sender: mpsc::Sender<ShadowServiceMessageV1>,
    max_sidecar_size: usize,
    own_authority: AuthorityIndex,
    committee_size: usize,
    input_capacity: usize,
    desired_topology: Arc<Mutex<BTreeMap<AuthorityIndex, (bool, u64)>>>,
    desired_direct_deliveries: Arc<Mutex<BTreeSet<ShadowDeliveryIdentityV1>>>,
    invalidated_by_overload: Arc<Mutex<Option<&'static str>>>,
}

impl StarfishRbcDagShadowServiceHandleV1 {
    fn send(&self, message: ShadowServiceMessageV1) -> Result<(), ShadowServiceErrorV1> {
        let kind = message.kind();
        if let Some(reason) = *self.invalidated_by_overload.lock() {
            return Err(ShadowServiceErrorV1::BenchmarkInvalid { reason });
        }
        self.sender.try_send(message).map_err(|error| match error {
            TrySendError::Full(_) => {
                *self.invalidated_by_overload.lock() = Some(kind);
                ShadowServiceErrorV1::Overloaded {
                    kind,
                    capacity: self.input_capacity,
                }
            }
            TrySendError::Closed(_) => ShadowServiceErrorV1::Stopped,
        })
    }

    pub(crate) fn local_header(
        &self,
        header: &RbcCanonicalHeader,
    ) -> Result<(), ShadowServiceErrorV1> {
        self.send(ShadowServiceMessageV1::LocalCarrier(
            ShadowLocalCarrierV1::from_direct_header(header),
        ))
    }

    pub(crate) fn carrier(
        &self,
        peer: AuthorityIndex,
        envelope: RbcDagShadowCarrier,
    ) -> Result<(), ShadowServiceErrorV1> {
        validate_wire_size(
            "carrier",
            envelope.canonical_carrier.len(),
            MAX_CARRIER_CONTENT_SIZE_V1,
        )?;
        validate_wire_size(
            "authentication sidecar",
            envelope.authentication_sidecar.len(),
            self.max_sidecar_size,
        )?;
        self.send(ShadowServiceMessageV1::Carrier { peer, envelope })
    }

    pub(crate) fn carrier_request(
        &self,
        peer: AuthorityIndex,
        reference: BlockReference,
    ) -> Result<(), ShadowServiceErrorV1> {
        self.send(ShadowServiceMessageV1::CarrierRequest { peer, reference })
    }

    pub(crate) fn carrier_response(
        &self,
        peer: AuthorityIndex,
        response: RbcDagShadowCarrierResponse,
    ) -> Result<(), ShadowServiceErrorV1> {
        validate_wire_size(
            "carrier response",
            response.canonical_carrier.len(),
            MAX_CARRIER_CONTENT_SIZE_V1,
        )?;
        self.send(ShadowServiceMessageV1::CarrierResponse { peer, response })
    }

    pub(crate) fn direct_delivered(
        &self,
        identity: ShadowDeliveryIdentityV1,
    ) -> Result<(), ShadowServiceErrorV1> {
        if identity.author as usize >= self.committee_size {
            return Err(ShadowServiceErrorV1::UnknownAuthority(identity.author));
        }
        if !self.desired_direct_deliveries.lock().insert(identity) {
            return Ok(());
        }
        match self
            .sender
            .try_send(ShadowServiceMessageV1::DirectDeliveriesChanged)
        {
            Ok(()) | Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Closed(_)) => Err(ShadowServiceErrorV1::Stopped),
        }
    }

    pub(crate) fn peer_connected(&self, peer: AuthorityIndex) -> Result<(), ShadowServiceErrorV1> {
        self.update_peer(peer, true)
    }

    pub(crate) fn peer_disconnected(
        &self,
        peer: AuthorityIndex,
    ) -> Result<(), ShadowServiceErrorV1> {
        self.update_peer(peer, false)
    }

    pub(crate) async fn shutdown(&self) -> Result<(), ShadowServiceErrorV1> {
        let (reply, receiver) = oneshot::channel();
        self.sender
            .send(ShadowServiceMessageV1::Shutdown(reply))
            .await
            .map_err(|_| ShadowServiceErrorV1::Stopped)?;
        receiver.await.map_err(|_| ShadowServiceErrorV1::Stopped)?
    }

    fn update_peer(
        &self,
        peer: AuthorityIndex,
        connected: bool,
    ) -> Result<(), ShadowServiceErrorV1> {
        if peer as usize >= self.committee_size {
            return Err(ShadowServiceErrorV1::UnknownAuthority(peer));
        }
        if peer == self.own_authority {
            return Err(ShadowServiceErrorV1::Loopback(peer));
        }
        let mut topology = self.desired_topology.lock();
        let state = topology.entry(peer).or_insert((false, 0));
        if state.0 != connected {
            state.0 = connected;
            state.1 = state.1.saturating_add(1);
        }
        drop(topology);
        match self
            .sender
            .try_send(ShadowServiceMessageV1::TopologyChanged)
        {
            Ok(()) | Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Closed(_)) => Err(ShadowServiceErrorV1::Stopped),
        }
    }
}

impl ShadowServiceMessageV1 {
    fn kind(&self) -> &'static str {
        match self {
            Self::LocalCarrier(_) => "local",
            Self::Carrier { .. } => "carrier",
            Self::CarrierRequest { .. } => "carrier_request",
            Self::CarrierResponse { .. } => "carrier_response",
            Self::DirectDeliveriesChanged => "direct_deliveries_changed",
            Self::TopologyChanged => "topology_changed",
            Self::RetryRecovery => "recovery_retry",
            Self::Shutdown(_) => "shutdown",
        }
    }
}

#[derive(Debug)]
pub(crate) enum ShadowServiceEventV1 {
    Ready,
    ComparisonBacklog {
        unpaired_direct: usize,
        unpaired_shadow: usize,
        max_round_lag: RoundNumber,
    },
    Network {
        recipient: AuthorityIndex,
        message: NetworkMessage,
    },
    Delivered(ShadowDeliveryIdentityV1),
    Comparison(ShadowDeliveryComparisonV1),
    Input {
        kind: &'static str,
        outcome: &'static str,
    },
    WalDurable {
        batches: u64,
        records: u64,
    },
    Recovered {
        batches: u64,
        discarded_tail_bytes: u64,
    },
    PendingRecovery(usize),
    Rejected {
        peer: Option<AuthorityIndex>,
        error: String,
    },
}

#[derive(Debug)]
pub(crate) enum ShadowServiceErrorV1 {
    Shadow(ShadowErrorV1),
    StartTask(tokio::task::JoinError),
    Stopped,
    Overloaded {
        kind: &'static str,
        capacity: usize,
    },
    BenchmarkInvalid {
        reason: &'static str,
    },
    InputTooLarge {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    CommitteeBurstTooLarge {
        committee_size: usize,
        maximum_capacity: usize,
    },
    UnknownAuthority(AuthorityIndex),
    Loopback(AuthorityIndex),
    ConflictingLocalHeader(RoundNumber),
    MissingRecoveredLocalHeader(RoundNumber),
    RecoveredLocalHeaderMismatch(RoundNumber),
    LocalHeaderAuthority {
        expected: AuthorityIndex,
        actual: AuthorityIndex,
    },
    UnauthenticatedCarrierRetained,
    UnexpectedResponse(BlockReference),
    ResponseFromNonHolder {
        peer: AuthorityIndex,
        reference: BlockReference,
    },
}

impl fmt::Display for ShadowServiceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shadow(error) => error.fmt(formatter),
            Self::StartTask(error) => write!(
                formatter,
                "Starfish-RBC-DAG shadow startup task failed: {error}"
            ),
            Self::Stopped => formatter.write_str("Starfish-RBC-DAG shadow service stopped"),
            Self::Overloaded { kind, capacity } => write!(
                formatter,
                "Starfish-RBC-DAG shadow {kind} input was dropped because the queue is full \
                 (capacity {capacity}); benchmark comparison is invalid"
            ),
            Self::BenchmarkInvalid { reason } => write!(
                formatter,
                "Starfish-RBC-DAG shadow benchmark was disabled after dropping {reason} input"
            ),
            Self::InputTooLarge {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "Starfish-RBC-DAG shadow {field} is {actual} bytes, above the {maximum}-byte limit"
            ),
            Self::CommitteeBurstTooLarge {
                committee_size,
                maximum_capacity,
            } => write!(
                formatter,
                "Starfish-RBC-DAG shadow committee size {committee_size} needs a burst queue of \
                 {}, above the memory-safe capacity limit {maximum_capacity}",
                committee_size
                    .saturating_sub(1)
                    .saturating_add(SHADOW_SERVICE_CONTROL_RESERVE_V1),
            ),
            Self::UnknownAuthority(authority) => {
                write!(formatter, "unknown shadow peer authority {authority}")
            }
            Self::Loopback(authority) => {
                write!(formatter, "shadow peer authority {authority} is local")
            }
            Self::ConflictingLocalHeader(round) => write!(
                formatter,
                "conflicting direct headers supplied for queued shadow round {round}"
            ),
            Self::MissingRecoveredLocalHeader(round) => write!(
                formatter,
                "persisted shadow carrier at round {round} has no matching recovered direct header"
            ),
            Self::RecoveredLocalHeaderMismatch(round) => write!(
                formatter,
                "persisted shadow carrier and recovered direct header disagree at round {round}"
            ),
            Self::LocalHeaderAuthority { expected, actual } => write!(
                formatter,
                "shadow local header authority {actual} does not match local authority {expected}"
            ),
            Self::UnauthenticatedCarrierRetained => formatter.write_str(
                "shadow carrier authentication failed; canonical content was retained candidate-only",
            ),
            Self::UnexpectedResponse(reference) => {
                write!(formatter, "unexpected shadow response for {reference}")
            }
            Self::ResponseFromNonHolder { peer, reference } => write!(
                formatter,
                "shadow response for {reference} came from non-holder {peer}"
            ),
        }
    }
}

impl Error for ShadowServiceErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Shadow(error) => Some(error),
            Self::StartTask(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ShadowErrorV1> for ShadowServiceErrorV1 {
    fn from(error: ShadowErrorV1) -> Self {
        Self::Shadow(error)
    }
}

pub(crate) fn start_starfish_rbc_dag_shadow_service_v1(
    path: impl AsRef<Path>,
    committee: RbcDagCommitteeContextV1,
    own_authority: AuthorityIndex,
    context: RbcDagContextV1,
    authorizer: ShadowAuthorizerV1,
    recovered_local_headers: Vec<RbcCanonicalHeader>,
) -> Result<
    (
        StarfishRbcDagShadowServiceHandleV1,
        mpsc::Receiver<ShadowServiceEventV1>,
        JoinHandle<()>,
    ),
    ShadowServiceErrorV1,
> {
    let committee_size = committee.committee().len();
    let input_capacity = shadow_input_capacity(committee_size)?;
    let max_sidecar_size =
        authentication_sidecar_size(context.authentication_scheme(), committee_size);
    let path = path.as_ref().to_path_buf();
    let mut pending_local = BTreeMap::new();
    for header in recovered_local_headers {
        let local = ShadowLocalCarrierV1::from_direct_header(&header);
        if local.author != own_authority {
            return Err(ShadowServiceErrorV1::LocalHeaderAuthority {
                expected: own_authority,
                actual: local.author,
            });
        }
        if let Some(previous) = pending_local.insert(local.round, local) {
            if previous != local {
                return Err(ShadowServiceErrorV1::ConflictingLocalHeader(local.round));
            }
        }
    }
    let (message_tx, message_rx) = mpsc::channel(input_capacity);
    let (event_tx, event_rx) = mpsc::channel(SHADOW_SERVICE_EVENT_CAPACITY_V1);
    let desired_topology = Arc::new(Mutex::new(BTreeMap::new()));
    let desired_direct_deliveries = Arc::new(Mutex::new(BTreeSet::new()));
    let invalidated_by_overload = Arc::new(Mutex::new(None));
    let retry_tx = message_tx.downgrade();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SHADOW_RECOVERY_RETRY_INTERVAL_V1);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            let Some(retry_tx) = retry_tx.upgrade() else {
                break;
            };
            match retry_tx.try_send(ShadowServiceMessageV1::RetryRecovery) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Closed(_)) => break,
            }
        }
    });
    let startup_events = event_tx.clone();
    let actor_desired_topology = Arc::clone(&desired_topology);
    let actor_desired_direct_deliveries = Arc::clone(&desired_direct_deliveries);
    let actor_invalidated_by_overload = Arc::clone(&invalidated_by_overload);
    let task = tokio::spawn(async move {
        let opened = tokio::task::spawn_blocking(move || {
            StarfishRbcDagShadowV1::open(path, committee, own_authority, context, authorizer)
        })
        .await;
        let (core, open_report) = match opened {
            Ok(Ok(opened)) => opened,
            Ok(Err(error)) => {
                let _ = startup_events
                    .send(ShadowServiceEventV1::Rejected {
                        peer: None,
                        error: error.to_string(),
                    })
                    .await;
                return;
            }
            Err(error) => {
                let _ = startup_events
                    .send(ShadowServiceEventV1::Rejected {
                        peer: None,
                        error: ShadowServiceErrorV1::StartTask(error).to_string(),
                    })
                    .await;
                return;
            }
        };
        let persisted_local = match core.local_outbound_metadata() {
            Ok(metadata) => metadata
                .into_iter()
                .map(|(round, commitment, creation_time_ns)| {
                    (round, (commitment, creation_time_ns))
                })
                .collect::<BTreeMap<_, _>>(),
            Err(error) => {
                let _ = startup_events
                    .send(ShadowServiceEventV1::Rejected {
                        peer: None,
                        error: error.to_string(),
                    })
                    .await;
                return;
            }
        };
        let durable_round = core.local_carrier_round();
        for (round, (commitment, creation_time_ns)) in &persisted_local {
            let Some(recovered) = pending_local.get(round) else {
                let _ = startup_events
                    .send(ShadowServiceEventV1::Rejected {
                        peer: None,
                        error: ShadowServiceErrorV1::MissingRecoveredLocalHeader(*round)
                            .to_string(),
                    })
                    .await;
                return;
            };
            if recovered.transactions_commitment != *commitment
                || recovered.creation_time_ns != *creation_time_ns
            {
                let _ = startup_events
                    .send(ShadowServiceEventV1::Rejected {
                        peer: None,
                        error: ShadowServiceErrorV1::RecoveredLocalHeaderMismatch(*round)
                            .to_string(),
                    })
                    .await;
                return;
            }
        }
        if let Some(round) = pending_local
            .keys()
            .copied()
            .find(|round| *round < durable_round && !persisted_local.contains_key(round))
        {
            let _ = startup_events
                .send(ShadowServiceEventV1::Rejected {
                    peer: None,
                    error: ShadowServiceErrorV1::RecoveredLocalHeaderMismatch(round).to_string(),
                })
                .await;
            return;
        }
        let reported_shadow_deliveries = match core.delivered_identities() {
            Ok(identities) => identities.into_iter().collect::<BTreeSet<_>>(),
            Err(error) => {
                let _ = startup_events
                    .send(ShadowServiceEventV1::Rejected {
                        peer: None,
                        error: error.to_string(),
                    })
                    .await;
                return;
            }
        };
        let recovered_shadow_deliveries = reported_shadow_deliveries.clone();
        let reported_shadow_delivery_slots = reported_shadow_deliveries
            .iter()
            .map(delivery_slot)
            .collect();
        let comparison_backlog = ShadowComparisonBacklogV1::new(reported_shadow_delivery_slots);
        pending_local.retain(|round, _| *round >= core.local_carrier_round());
        let state = ShadowServiceStateV1 {
            core,
            own_authority,
            committee_size,
            events: event_tx,
            connected: BTreeSet::new(),
            desired_topology: actor_desired_topology,
            desired_direct_deliveries: actor_desired_direct_deliveries,
            observed_topology: BTreeMap::new(),
            invalidated_by_overload: actor_invalidated_by_overload,
            pending_local,
            pending_recovery: BTreeMap::new(),
            recovery_last_attempt: BTreeMap::new(),
            direct_deliveries: BTreeSet::new(),
            reported_shadow_deliveries,
            recovered_shadow_deliveries,
            comparison_backlog,
            reported_matches: BTreeSet::new(),
            reported_mismatches: BTreeSet::new(),
            reported_conflicts: BTreeSet::new(),
            fatal: false,
        };
        if let Err(error) = tokio::task::spawn_blocking(move || {
            run_shadow_service(state, message_rx, open_report);
        })
        .await
        {
            let _ = startup_events
                .send(ShadowServiceEventV1::Rejected {
                    peer: None,
                    error: format!("Starfish-RBC-DAG shadow actor task failed: {error}"),
                })
                .await;
        }
    });
    Ok((
        StarfishRbcDagShadowServiceHandleV1 {
            sender: message_tx,
            max_sidecar_size,
            own_authority,
            committee_size,
            input_capacity,
            desired_topology,
            desired_direct_deliveries,
            invalidated_by_overload,
        },
        event_rx,
        task,
    ))
}

struct ShadowComparisonBacklogV1 {
    direct_slots: BTreeSet<ShadowDeliverySlotV1>,
    reported_shadow_slots: BTreeSet<ShadowDeliverySlotV1>,
    // Recovered shadow slots are deliberately absent from this set: they may
    // pair a current direct observation but are not current-process timing
    // observations and therefore cannot create shadow-only backlog.
    epoch_shadow_slots: BTreeSet<ShadowDeliverySlotV1>,
    unpaired_direct_slots: BTreeSet<ShadowDeliverySlotV1>,
    unpaired_shadow_slots: BTreeSet<ShadowDeliverySlotV1>,
    latest_epoch_round: RoundNumber,
}

impl ShadowComparisonBacklogV1 {
    fn new(reported_shadow_slots: BTreeSet<ShadowDeliverySlotV1>) -> Self {
        Self {
            direct_slots: BTreeSet::new(),
            reported_shadow_slots,
            epoch_shadow_slots: BTreeSet::new(),
            unpaired_direct_slots: BTreeSet::new(),
            unpaired_shadow_slots: BTreeSet::new(),
            latest_epoch_round: 0,
        }
    }

    fn observe_direct(&mut self, slot: ShadowDeliverySlotV1) {
        self.observe_epoch_round(slot);
        if self.direct_slots.insert(slot) {
            if !self.reported_shadow_slots.contains(&slot) {
                self.unpaired_direct_slots.insert(slot);
            }
            self.unpaired_shadow_slots.remove(&slot);
        }
    }

    fn observe_epoch_shadow(&mut self, slot: ShadowDeliverySlotV1) {
        self.observe_epoch_round(slot);
        self.reported_shadow_slots.insert(slot);
        if self.epoch_shadow_slots.insert(slot) {
            if !self.direct_slots.contains(&slot) {
                self.unpaired_shadow_slots.insert(slot);
            }
            self.unpaired_direct_slots.remove(&slot);
        }
    }

    fn observe_epoch_round(&mut self, slot: ShadowDeliverySlotV1) {
        self.latest_epoch_round = self.latest_epoch_round.max(slot.round);
    }

    fn counts(&self) -> (usize, usize, RoundNumber) {
        let max_round_lag = self
            .unpaired_direct_slots
            .union(&self.unpaired_shadow_slots)
            .map(|slot| self.latest_epoch_round.saturating_sub(slot.round))
            .max()
            .unwrap_or(0);
        (
            self.unpaired_direct_slots.len(),
            self.unpaired_shadow_slots.len(),
            max_round_lag,
        )
    }
}

struct ShadowServiceStateV1 {
    core: StarfishRbcDagShadowV1,
    own_authority: AuthorityIndex,
    committee_size: usize,
    events: mpsc::Sender<ShadowServiceEventV1>,
    connected: BTreeSet<AuthorityIndex>,
    desired_topology: Arc<Mutex<BTreeMap<AuthorityIndex, (bool, u64)>>>,
    desired_direct_deliveries: Arc<Mutex<BTreeSet<ShadowDeliveryIdentityV1>>>,
    observed_topology: BTreeMap<AuthorityIndex, (bool, u64)>,
    invalidated_by_overload: Arc<Mutex<Option<&'static str>>>,
    pending_local: BTreeMap<RoundNumber, ShadowLocalCarrierV1>,
    pending_recovery: BTreeMap<BlockReference, BTreeSet<AuthorityIndex>>,
    recovery_last_attempt: BTreeMap<(BlockReference, AuthorityIndex), Instant>,
    direct_deliveries: BTreeSet<ShadowDeliveryIdentityV1>,
    reported_shadow_deliveries: BTreeSet<ShadowDeliveryIdentityV1>,
    recovered_shadow_deliveries: BTreeSet<ShadowDeliveryIdentityV1>,
    comparison_backlog: ShadowComparisonBacklogV1,
    reported_matches: BTreeSet<ShadowDeliveryIdentityV1>,
    reported_mismatches: BTreeSet<(ShadowDeliveryIdentityV1, ShadowDeliveryIdentityV1)>,
    reported_conflicts: BTreeSet<ShadowDeliverySlotV1>,
    fatal: bool,
}

impl ShadowServiceStateV1 {
    fn emit(&self, event: ShadowServiceEventV1) {
        let _ = self.events.blocking_send(event);
    }

    fn reject(&self, peer: Option<AuthorityIndex>, error: impl fmt::Display) {
        self.emit(ShadowServiceEventV1::Rejected {
            peer,
            error: error.to_string(),
        });
    }

    fn emit_comparison_backlog(&self) {
        let (unpaired_direct, unpaired_shadow, max_round_lag) = self.comparison_backlog.counts();
        self.emit(ShadowServiceEventV1::ComparisonBacklog {
            unpaired_direct,
            unpaired_shadow,
            max_round_lag,
        });
    }

    fn validate_peer(&self, peer: AuthorityIndex) -> Result<(), ShadowServiceErrorV1> {
        if peer as usize >= self.committee_size {
            return Err(ShadowServiceErrorV1::UnknownAuthority(peer));
        }
        if peer == self.own_authority {
            return Err(ShadowServiceErrorV1::Loopback(peer));
        }
        Ok(())
    }

    fn reconcile_topology(&mut self) {
        let desired = self.desired_topology.lock().clone();
        let mut newly_connected = Vec::new();
        for (peer, state) in &desired {
            if self.observed_topology.get(peer) == Some(state) {
                continue;
            }
            self.recovery_last_attempt
                .retain(|(_, holder), _| holder != peer);
            if state.0 {
                self.connected.insert(*peer);
                newly_connected.push(*peer);
            } else {
                self.connected.remove(peer);
            }
        }
        self.observed_topology = desired;
        if !newly_connected.is_empty() {
            let retransmissions = self.core.retransmissions();
            for peer in newly_connected {
                for envelope in &retransmissions {
                    self.send_envelope(peer, envelope);
                }
            }
            self.flush_recovery_requests();
        }
    }

    fn reconcile_direct_deliveries(&mut self) {
        let desired = self.desired_direct_deliveries.lock().clone();
        let newly_observed = desired
            .difference(&self.direct_deliveries)
            .copied()
            .collect::<Vec<_>>();
        for identity in newly_observed {
            self.direct_deliveries.insert(identity);
            let slot = delivery_slot(&identity);
            self.comparison_backlog.observe_direct(slot);
            self.emit(ShadowServiceEventV1::Input {
                kind: "delivery",
                outcome: "direct",
            });
            self.emit_slot_comparison(slot);
        }
        if !desired.is_empty() {
            self.emit_comparison_backlog();
        }
    }

    fn observe_external_invalidation(&mut self) -> bool {
        let reason = *self.invalidated_by_overload.lock();
        if let Some(reason) = reason {
            self.mark_fatal(ShadowServiceErrorV1::BenchmarkInvalid { reason });
            true
        } else {
            false
        }
    }

    fn mark_fatal(&mut self, error: impl fmt::Display) {
        if self.fatal {
            return;
        }
        self.fatal = true;
        if self.invalidated_by_overload.lock().is_none() {
            *self.invalidated_by_overload.lock() = Some("fatal_core");
        }
        self.emit(ShadowServiceEventV1::Input {
            kind: "benchmark",
            outcome: "invalid",
        });
        self.reject(None, error);
    }

    fn broadcast(&self, envelope: &ShadowOutboundEnvelopeV1) {
        for recipient in 0..self.committee_size {
            let recipient = recipient as AuthorityIndex;
            if recipient != self.own_authority {
                self.send_envelope(recipient, envelope);
            }
        }
    }

    fn send_envelope(&self, recipient: AuthorityIndex, envelope: &ShadowOutboundEnvelopeV1) {
        self.emit(ShadowServiceEventV1::Network {
            recipient,
            message: NetworkMessage::RbcDagShadowCarrier(RbcDagShadowCarrier {
                canonical_carrier: envelope.canonical_carrier_wire().to_vec(),
                authentication_sidecar: envelope.authentication_sidecar().to_vec(),
            }),
        });
    }

    fn report_wal_delta(&self, before: (u64, u64)) {
        let after = self.core.wal_counts();
        let batches = after.0.saturating_sub(before.0);
        let records = after.1.saturating_sub(before.1);
        if batches != 0 || records != 0 {
            self.emit(ShadowServiceEventV1::WalDurable { batches, records });
        }
    }

    fn process_effects(&mut self, effects: Vec<ModelEffect>) {
        for effect in effects {
            match effect {
                ModelEffect::NeedCarrier { target, holders } => {
                    self.pending_recovery.entry(target).or_default().extend(
                        holders.into_iter().filter(|holder| {
                            *holder != self.own_authority
                                && (*holder as usize) < self.committee_size
                        }),
                    );
                }
                ModelEffect::Delivered(reference) => {
                    self.pending_recovery.remove(&reference);
                }
                ModelEffect::PrefixAdvanced { .. } | ModelEffect::CarrierRoundAdvanced(_) => {}
            }
        }
        self.reconcile_pending_recovery();
        self.flush_recovery_requests();
        self.emit(ShadowServiceEventV1::PendingRecovery(
            self.pending_recovery.len(),
        ));
        self.report_new_shadow_deliveries();
    }

    fn reconcile_pending_recovery(&mut self) {
        self.pending_recovery
            .retain(|target, _| self.core.retained_candidate_wire(*target).is_none());
        self.recovery_last_attempt.retain(|(target, holder), _| {
            self.pending_recovery
                .get(target)
                .is_some_and(|holders| holders.contains(holder))
        });
    }

    fn enqueue_local(&mut self, local: ShadowLocalCarrierV1) {
        if local.author != self.own_authority {
            self.reject(
                None,
                ShadowServiceErrorV1::LocalHeaderAuthority {
                    expected: self.own_authority,
                    actual: local.author,
                },
            );
            return;
        }
        let durable_round = self.core.local_carrier_round();
        if local.round < durable_round {
            self.emit(ShadowServiceEventV1::Input {
                kind: "local",
                outcome: "already_durable",
            });
            return;
        }
        if let Some(existing) = self.pending_local.get(&local.round) {
            if existing == &local {
                self.emit(ShadowServiceEventV1::Input {
                    kind: "local",
                    outcome: "duplicate",
                });
            } else {
                self.reject(
                    None,
                    ShadowServiceErrorV1::ConflictingLocalHeader(local.round),
                );
            }
            return;
        }
        let round = local.round;
        self.pending_local.insert(round, local);
        if round != durable_round || !self.core.can_create_carrier() {
            self.emit(ShadowServiceEventV1::Input {
                kind: "local",
                outcome: "queued",
            });
        }
        self.retry_pending_local();
    }

    /// Create only the exact round opened by the durable carrier clock. A
    /// future direct header remains queued until authenticated carrier input
    /// advances the model; recovered historical headers below that clock are
    /// harmless idempotent replays.
    fn retry_pending_local(&mut self) {
        loop {
            let durable_round = self.core.local_carrier_round();
            self.pending_local
                .retain(|round, _| *round >= durable_round);
            if !self.core.can_create_carrier() {
                return;
            }
            let Some(local) = self.pending_local.remove(&durable_round) else {
                return;
            };
            let before = self.core.wal_counts();
            match self.core.create_local_carrier(
                local.round,
                local.transactions_commitment,
                local.creation_time_ns,
            ) {
                Ok((envelope, effects)) => {
                    self.emit(ShadowServiceEventV1::Input {
                        kind: "local",
                        outcome: "accepted",
                    });
                    self.report_wal_delta(before);
                    self.broadcast(&envelope);
                    self.process_effects(effects);
                }
                Err(ShadowErrorV1::Model(ModelError::LocalRoundNotOpen(_))) => {
                    self.pending_local.insert(local.round, local);
                    self.emit(ShadowServiceEventV1::Input {
                        kind: "local",
                        outcome: "queued",
                    });
                    return;
                }
                Err(error) => {
                    self.emit(ShadowServiceEventV1::Input {
                        kind: "local",
                        outcome: "rejected",
                    });
                    self.mark_fatal(error);
                    return;
                }
            }
        }
    }

    fn flush_recovery_requests(&mut self) {
        let now = Instant::now();
        let mut requests = Vec::new();
        for (reference, holders) in &self.pending_recovery {
            for holder in holders {
                if self.connected.contains(holder)
                    && self
                        .recovery_last_attempt
                        .get(&(*reference, *holder))
                        .is_none_or(|last| {
                            now.saturating_duration_since(*last)
                                >= SHADOW_RECOVERY_RETRY_INTERVAL_V1
                        })
                {
                    requests.push((*reference, *holder));
                }
            }
        }
        for (reference, holder) in requests {
            self.recovery_last_attempt.insert((reference, holder), now);
            self.emit(ShadowServiceEventV1::Network {
                recipient: holder,
                message: NetworkMessage::RbcDagShadowCarrierRequest(reference),
            });
        }
    }

    fn report_new_shadow_deliveries(&mut self) {
        let identities: BTreeSet<_> = match self.core.delivered_identities() {
            Ok(identities) => identities.into_iter().collect(),
            Err(error) => {
                self.reject(None, error);
                return;
            }
        };
        let new_identities = identities
            .difference(&self.reported_shadow_deliveries)
            .copied()
            .collect::<Vec<_>>();
        self.reported_shadow_deliveries = identities;
        for identity in &new_identities {
            let slot = delivery_slot(identity);
            self.comparison_backlog.observe_epoch_shadow(slot);
            self.emit(ShadowServiceEventV1::Delivered(*identity));
            self.emit_slot_comparison(slot);
            self.emit_comparison_backlog();
        }
    }

    fn emit_slot_comparison(&mut self, slot: ShadowDeliverySlotV1) {
        let direct = self
            .direct_deliveries
            .iter()
            .filter(|identity| delivery_slot(identity) == slot)
            .copied()
            .collect::<Vec<_>>();
        let shadow = self
            .reported_shadow_deliveries
            .iter()
            .filter(|identity| delivery_slot(identity) == slot)
            .copied()
            .collect::<Vec<_>>();
        if direct.is_empty() || shadow.is_empty() {
            return;
        }
        if direct.len() > 1 || shadow.len() > 1 {
            if self.reported_conflicts.insert(slot) {
                self.emit(ShadowServiceEventV1::Comparison(
                    ShadowDeliveryComparisonV1::Ambiguous { slots: vec![slot] },
                ));
            }
            return;
        }
        let direct = direct[0];
        let shadow = shadow[0];
        if direct == shadow {
            if self.reported_matches.insert(direct) {
                if self.recovered_shadow_deliveries.contains(&shadow) {
                    self.emit(ShadowServiceEventV1::Input {
                        kind: "comparison",
                        outcome: "recovered_match",
                    });
                }
                self.emit(ShadowServiceEventV1::Comparison(
                    ShadowDeliveryComparisonV1::Match,
                ));
            }
        } else if self.reported_mismatches.insert((direct, shadow)) {
            self.emit(ShadowServiceEventV1::Comparison(
                ShadowDeliveryComparisonV1::Mismatch {
                    direct_only: vec![direct],
                    shadow_only: vec![shadow],
                },
            ));
        }
    }
}

fn run_shadow_service(
    mut state: ShadowServiceStateV1,
    mut messages: mpsc::Receiver<ShadowServiceMessageV1>,
    open_report: ShadowOpenReportV1,
) {
    if open_report.replayed_batches() != 0 || open_report.discarded_tail_bytes() != 0 {
        state.emit(ShadowServiceEventV1::Recovered {
            batches: open_report.replayed_batches(),
            discarded_tail_bytes: open_report.discarded_tail_bytes(),
        });
    }
    state.reconcile_topology();
    state.reconcile_direct_deliveries();
    if !state.observe_external_invalidation() {
        state.emit(ShadowServiceEventV1::Ready);
        state.emit_comparison_backlog();
        state.process_effects(open_report.recovery_effects().to_vec());
        state.retry_pending_local();
    }

    while !state.fatal {
        let Some(message) = messages.blocking_recv() else {
            break;
        };
        let message = match message {
            ShadowServiceMessageV1::Shutdown(reply) => {
                let events = state.events.clone();
                let result = state
                    .core
                    .shutdown()
                    .map(|_| ())
                    .map_err(ShadowServiceErrorV1::from);
                if reply.send(result).is_err() {
                    let _ = events.blocking_send(ShadowServiceEventV1::Rejected {
                        peer: None,
                        error: "shadow shutdown acknowledgment receiver was dropped".to_owned(),
                    });
                }
                return;
            }
            message => message,
        };
        if state.observe_external_invalidation() {
            break;
        }
        match message {
            ShadowServiceMessageV1::LocalCarrier(local) => {
                state.enqueue_local(local);
            }
            ShadowServiceMessageV1::Carrier { peer, envelope } => {
                if let Err(error) = state.validate_peer(peer) {
                    state.reject(Some(peer), error);
                    continue;
                }
                let before = state.core.wal_counts();
                match state.core.receive_or_retain_from_peer(
                    &envelope.canonical_carrier,
                    &envelope.authentication_sidecar,
                    peer,
                ) {
                    Ok(outcome) => {
                        let outcome_label = match outcome.disposition() {
                            ShadowIngressDispositionV1::Authenticated => "authenticated",
                            ShadowIngressDispositionV1::CandidateRetained => {
                                "retained_unauthenticated"
                            }
                            ShadowIngressDispositionV1::IgnoredDuplicateConflictOrStale => {
                                "ignored"
                            }
                        };
                        state.emit(ShadowServiceEventV1::Input {
                            kind: "carrier",
                            outcome: outcome_label,
                        });
                        state.report_wal_delta(before);
                        state.process_effects(outcome.effects().to_vec());
                        state.retry_pending_local();
                        if outcome.disposition() == ShadowIngressDispositionV1::CandidateRetained {
                            state.reject(
                                Some(peer),
                                ShadowServiceErrorV1::UnauthenticatedCarrierRetained,
                            );
                        }
                    }
                    Err(error) => {
                        state.emit(ShadowServiceEventV1::Input {
                            kind: "carrier",
                            outcome: "rejected",
                        });
                        if is_fatal_core_error(&error) {
                            state.mark_fatal(error);
                        } else {
                            state.reject(Some(peer), error);
                        }
                    }
                }
            }
            ShadowServiceMessageV1::CarrierRequest { peer, reference } => {
                if let Err(error) = state.validate_peer(peer) {
                    state.reject(Some(peer), error);
                    continue;
                }
                if let Some(canonical_carrier) = state.core.retained_candidate_wire(reference) {
                    state.emit(ShadowServiceEventV1::Network {
                        recipient: peer,
                        message: NetworkMessage::RbcDagShadowCarrierResponse(
                            RbcDagShadowCarrierResponse {
                                reference,
                                canonical_carrier,
                            },
                        ),
                    });
                }
            }
            ShadowServiceMessageV1::CarrierResponse { peer, response } => {
                if let Err(error) = state.validate_peer(peer) {
                    state.reject(Some(peer), error);
                    continue;
                }
                let Some(holders) = state.pending_recovery.get(&response.reference) else {
                    state.reject(
                        Some(peer),
                        ShadowServiceErrorV1::UnexpectedResponse(response.reference),
                    );
                    continue;
                };
                if !holders.contains(&peer) {
                    state.reject(
                        Some(peer),
                        ShadowServiceErrorV1::ResponseFromNonHolder {
                            peer,
                            reference: response.reference,
                        },
                    );
                    continue;
                }
                let before = state.core.wal_counts();
                match state
                    .core
                    .recover_candidate_for(response.reference, &response.canonical_carrier)
                {
                    Ok(effects) => {
                        state.pending_recovery.remove(&response.reference);
                        state
                            .recovery_last_attempt
                            .retain(|(target, _), _| *target != response.reference);
                        state.emit(ShadowServiceEventV1::Input {
                            kind: "recovery",
                            outcome: "accepted",
                        });
                        state.report_wal_delta(before);
                        state.process_effects(effects);
                        state.retry_pending_local();
                    }
                    Err(error) => {
                        state.emit(ShadowServiceEventV1::Input {
                            kind: "recovery",
                            outcome: "rejected",
                        });
                        if is_fatal_core_error(&error) {
                            state.mark_fatal(error);
                        } else {
                            state.reject(Some(peer), error);
                        }
                    }
                }
            }
            ShadowServiceMessageV1::DirectDeliveriesChanged => {
                state.reconcile_direct_deliveries();
            }
            ShadowServiceMessageV1::TopologyChanged => state.reconcile_topology(),
            ShadowServiceMessageV1::RetryRecovery => {
                state.reconcile_topology();
                state.reconcile_pending_recovery();
                state.flush_recovery_requests();
            }
            ShadowServiceMessageV1::Shutdown(_) => unreachable!("shutdown handled before dispatch"),
        }
        state.reconcile_topology();
        state.reconcile_direct_deliveries();
    }
    let events = state.events.clone();
    if let Err(error) = state.core.shutdown() {
        let _ = events.blocking_send(ShadowServiceEventV1::Rejected {
            peer: None,
            error: error.to_string(),
        });
    }
}

fn delivery_slot(identity: &ShadowDeliveryIdentityV1) -> ShadowDeliverySlotV1 {
    ShadowDeliverySlotV1 {
        author: identity.author,
        round: identity.round,
    }
}

fn authentication_sidecar_size(scheme: BlockAuthenticationScheme, committee_size: usize) -> usize {
    const SIDECAR_HEADER_SIZE: usize = 3;
    SIDECAR_HEADER_SIZE
        + match scheme {
            BlockAuthenticationScheme::Ed25519 => SIGNATURE_SIZE,
            BlockAuthenticationScheme::MlDsa44 => ML_DSA_44_SIGNATURE_SIZE,
            BlockAuthenticationScheme::MlDsa65 => ML_DSA_65_SIGNATURE_SIZE,
            BlockAuthenticationScheme::MacVector => committee_size.saturating_mul(MAC_TAG_SIZE),
        }
}

fn shadow_input_capacity(committee_size: usize) -> Result<usize, ShadowServiceErrorV1> {
    let committee_burst = committee_size
        .saturating_sub(1)
        .saturating_add(SHADOW_SERVICE_CONTROL_RESERVE_V1);
    if committee_burst > SHADOW_SERVICE_MAX_INPUT_CAPACITY_V1 {
        return Err(ShadowServiceErrorV1::CommitteeBurstTooLarge {
            committee_size,
            maximum_capacity: SHADOW_SERVICE_MAX_INPUT_CAPACITY_V1,
        });
    }
    Ok(committee_burst.max(SHADOW_SERVICE_MIN_INPUT_CAPACITY_V1))
}

fn validate_wire_size(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), ShadowServiceErrorV1> {
    if actual > maximum {
        Err(ShadowServiceErrorV1::InputTooLarge {
            field,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn is_fatal_core_error(error: &ShadowErrorV1) -> bool {
    matches!(
        error,
        ShadowErrorV1::Wal(_)
            | ShadowErrorV1::PostDurabilityCommit(_)
            | ShadowErrorV1::PostDurabilityJournal(_)
            | ShadowErrorV1::Poisoned
    )
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tempfile::TempDir;
    use tokio::time::timeout;

    use super::*;
    use crate::{
        committee::Committee,
        crypto::{TransactionsCommitment, mac_keyrings_for_test},
        starfish_rbc_dag::{
            CandidateCarrierV1, CarrierAuthorizerV1, CarrierHeaderV1Args, RbcDagProtocolInstanceId,
            RbcPhaseStatementV1, carrier_genesis_reference,
        },
        types::{BlockDigest, VerifiedBlock},
    };

    const N: usize = 4;
    const EVENT_TIMEOUT: Duration = Duration::from_secs(5);

    struct Harness {
        _directory: TempDir,
        committee: RbcDagCommitteeContextV1,
        context: RbcDagContextV1,
        keyrings: Vec<Vec<crate::crypto::MacKey>>,
        paths: Vec<std::path::PathBuf>,
    }

    impl Harness {
        fn new() -> Self {
            let committee = Committee::new_test(vec![1; N]);
            let committee = RbcDagCommitteeContextV1::new(Arc::clone(&committee)).unwrap();
            let context = RbcDagContextV1::new_with_committee(
                RbcDagProtocolInstanceId::new([0xD7; 32]).unwrap(),
                &committee,
                BlockAuthenticationScheme::MacVector,
            );
            let directory = tempfile::tempdir().unwrap();
            let paths = (0..N)
                .map(|authority| directory.path().join(format!("shadow-{authority}.wal")))
                .collect();
            Self {
                _directory: directory,
                committee,
                context,
                keyrings: mac_keyrings_for_test(N),
                paths,
            }
        }

        fn start(
            &self,
            authority: AuthorityIndex,
            recovered: Vec<RbcCanonicalHeader>,
        ) -> (
            StarfishRbcDagShadowServiceHandleV1,
            mpsc::Receiver<ShadowServiceEventV1>,
            JoinHandle<()>,
        ) {
            start_starfish_rbc_dag_shadow_service_v1(
                &self.paths[authority as usize],
                self.committee.clone(),
                authority,
                self.context,
                ShadowAuthorizerV1::MacVector(self.keyrings[authority as usize].clone()),
                recovered,
            )
            .unwrap()
        }

        fn envelope(
            &self,
            candidate: &CandidateCarrierV1,
            author: AuthorityIndex,
        ) -> RbcDagShadowCarrier {
            let authentication = self
                .context
                .authenticate_with_committee(
                    candidate,
                    &self.committee,
                    CarrierAuthorizerV1::MacVector {
                        authority: author,
                        keys: &self.keyrings[author as usize],
                    },
                )
                .unwrap();
            RbcDagShadowCarrier {
                canonical_carrier: candidate.canonical_wire_bytes().unwrap(),
                authentication_sidecar: authentication.canonical_wire_bytes(),
            }
        }
    }

    async fn next_event(events: &mut mpsc::Receiver<ShadowServiceEventV1>) -> ShadowServiceEventV1 {
        timeout(EVENT_TIMEOUT, events.recv())
            .await
            .expect("shadow actor timed out")
            .expect("shadow actor stopped")
    }

    async fn wait_ready(events: &mut mpsc::Receiver<ShadowServiceEventV1>) {
        loop {
            match next_event(events).await {
                ShadowServiceEventV1::Ready => return,
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("shadow startup failed: {error}")
                }
                _ => {}
            }
        }
    }

    async fn wait_backlog(
        events: &mut mpsc::Receiver<ShadowServiceEventV1>,
        expected: (usize, usize, RoundNumber),
    ) {
        loop {
            match next_event(events).await {
                ShadowServiceEventV1::ComparisonBacklog {
                    unpaired_direct,
                    unpaired_shadow,
                    max_round_lag,
                } if (unpaired_direct, unpaired_shadow, max_round_lag) == expected => return,
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("shadow service rejected input while waiting for backlog: {error}")
                }
                _ => {}
            }
        }
    }

    async fn next_carrier(
        events: &mut mpsc::Receiver<ShadowServiceEventV1>,
        expected_recipient: AuthorityIndex,
    ) -> RbcDagShadowCarrier {
        loop {
            if let ShadowServiceEventV1::Network {
                recipient,
                message: NetworkMessage::RbcDagShadowCarrier(envelope),
            } = next_event(events).await
            {
                if recipient == expected_recipient {
                    return envelope;
                }
            }
        }
    }

    async fn stop(
        handle: StarfishRbcDagShadowServiceHandleV1,
        events: mpsc::Receiver<ShadowServiceEventV1>,
        task: JoinHandle<()>,
    ) {
        drop(events);
        handle.shutdown().await.unwrap();
        task.await.unwrap();
    }

    async fn startup_rejection(mut events: mpsc::Receiver<ShadowServiceEventV1>) -> String {
        loop {
            match next_event(&mut events).await {
                ShadowServiceEventV1::Rejected { peer: None, error } => return error,
                ShadowServiceEventV1::Ready => panic!("invalid shadow startup became ready"),
                _ => {}
            }
        }
    }

    fn direct_header(author: AuthorityIndex, round: RoundNumber, marker: u8) -> RbcCanonicalHeader {
        RbcCanonicalHeader::try_new(
            author,
            round,
            (0..N)
                .map(|authority| {
                    *VerifiedBlock::new_genesis(authority as AuthorityIndex).reference()
                })
                .collect(),
            Vec::new(),
            u64::from(round) * 1_000 + u64::from(marker),
            TransactionsCommitment::from_bytes([marker; 32]),
        )
        .unwrap()
    }

    fn round_one_candidate(
        author: AuthorityIndex,
        committee: &RbcDagCommitteeContextV1,
        marker: u8,
    ) -> CandidateCarrierV1 {
        let weak_parents = committee
            .committee()
            .authorities()
            .filter(|authority| *authority != author)
            .take(2)
            .map(carrier_genesis_reference)
            .collect();
        CandidateCarrierV1::try_new_with_committee(
            CarrierHeaderV1Args {
                author,
                carrier_round: 1,
                own_prev: carrier_genesis_reference(author),
                weak_parents,
                transactions_commitment: TransactionsCommitment::from_bytes([marker; 32]),
                data_acknowledgments: Vec::new(),
                phase_batch: Vec::new(),
                consensus_vertex: None,
                creation_time_ns: u64::from(marker),
            },
            committee,
        )
        .unwrap()
    }

    #[test]
    fn comparison_backlog_excludes_recovery_and_ages_old_holes() {
        let recovered = ShadowDeliverySlotV1 {
            author: 0,
            round: 10,
        };
        let mut backlog = ShadowComparisonBacklogV1::new(BTreeSet::from([recovered]));
        assert_eq!(backlog.counts(), (0, 0, 0));

        // A direct replay can pair with recovered shadow state without
        // inventing a current-epoch shadow observation.
        backlog.observe_direct(recovered);
        assert_eq!(backlog.counts(), (0, 0, 0));

        let old_hole = ShadowDeliverySlotV1 {
            author: 1,
            round: 11,
        };
        backlog.observe_direct(old_hole);
        assert_eq!(backlog.counts(), (1, 0, 0));

        let newer = ShadowDeliverySlotV1 {
            author: 2,
            round: 15,
        };
        backlog.observe_direct(newer);
        backlog.observe_epoch_shadow(newer);
        assert_eq!(backlog.counts(), (1, 0, 4));

        backlog.observe_epoch_shadow(old_hole);
        assert_eq!(backlog.counts(), (0, 0, 0));
    }

    #[tokio::test]
    async fn service_emits_initial_and_direct_backlog() {
        let harness = Harness::new();
        let (handle, mut events, task) = harness.start(0, Vec::new());
        wait_ready(&mut events).await;
        wait_backlog(&mut events, (0, 0, 0)).await;

        handle
            .direct_delivered(ShadowDeliveryIdentityV1::new(
                1,
                7,
                TransactionsCommitment::from_bytes([0xB7; 32]),
            ))
            .unwrap();
        wait_backlog(&mut events, (1, 0, 0)).await;

        stop(handle, events, task).await;
    }

    fn phase_carrier(
        author: AuthorityIndex,
        statement: RbcPhaseStatementV1,
        committee: &RbcDagCommitteeContextV1,
    ) -> CandidateCarrierV1 {
        let previous = |authority: AuthorityIndex| BlockReference {
            authority,
            round: 1,
            digest: BlockDigest::from([0xA0 + authority as u8; 32]),
        };
        CandidateCarrierV1::try_new_with_committee(
            CarrierHeaderV1Args {
                author,
                carrier_round: 2,
                own_prev: previous(author),
                weak_parents: committee
                    .committee()
                    .authorities()
                    .filter(|authority| *authority != author)
                    .take(2)
                    .map(previous)
                    .collect(),
                transactions_commitment: TransactionsCommitment::from_bytes(
                    [0xB0 + author as u8; 32],
                ),
                data_acknowledgments: Vec::new(),
                phase_batch: vec![statement],
                consensus_vertex: None,
                creation_time_ns: 2,
            },
            committee,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn restart_replays_matching_and_rejects_inconsistent_direct_history() {
        let harness = Harness::new();
        let direct = direct_header(0, 1, 0x41);
        let (handle, mut events, task) = harness.start(0, vec![direct.clone()]);
        wait_ready(&mut events).await;
        let original = next_carrier(&mut events, 1).await;
        stop(handle, events, task).await;

        let (restarted, mut restarted_events, restarted_task) =
            harness.start(0, vec![direct.clone()]);
        let mut replayed = false;
        loop {
            match next_event(&mut restarted_events).await {
                ShadowServiceEventV1::Recovered { batches, .. } => replayed = batches > 0,
                ShadowServiceEventV1::Ready => break,
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("valid shadow restart failed: {error}")
                }
                _ => {}
            }
        }
        assert!(replayed, "valid shadow restart did not replay its WAL");
        restarted.peer_connected(1).unwrap();
        assert_eq!(next_carrier(&mut restarted_events, 1).await, original);
        stop(restarted, restarted_events, restarted_task).await;

        let (missing_handle, missing_events, missing_task) = harness.start(0, Vec::new());
        let missing = startup_rejection(missing_events).await;
        assert!(missing.contains("has no matching recovered direct header"));
        drop(missing_handle);
        missing_task.await.unwrap();

        let divergent = direct_header(0, 1, 0x42);
        let (divergent_handle, divergent_events, divergent_task) =
            harness.start(0, vec![divergent]);
        let mismatch = startup_rejection(divergent_events).await;
        assert!(mismatch.contains("disagree at round 1"));
        drop(divergent_handle);
        divergent_task.await.unwrap();
    }

    #[tokio::test]
    async fn local_carrier_broadcasts_one_identical_full_mac_vector_per_peer() {
        let harness = Harness::new();
        let (handle, mut events, task) = harness.start(0, Vec::new());
        wait_ready(&mut events).await;
        handle.local_header(&direct_header(0, 1, 0x11)).unwrap();

        let mut by_recipient = BTreeMap::new();
        while by_recipient.len() < N - 1 {
            if let ShadowServiceEventV1::Network {
                recipient,
                message: NetworkMessage::RbcDagShadowCarrier(envelope),
            } = next_event(&mut events).await
            {
                by_recipient.insert(recipient, envelope);
            }
        }
        assert_eq!(
            by_recipient.keys().copied().collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        let first = &by_recipient[&1];
        assert_eq!(first.authentication_sidecar.len(), 3 + N * MAC_TAG_SIZE);
        for envelope in by_recipient.values() {
            assert_eq!(envelope, first);
        }
        let candidate = CandidateCarrierV1::decode_wire_with_committee(
            &first.canonical_carrier,
            &harness.committee,
            None,
        )
        .unwrap();
        assert_eq!(candidate.header().carrier_round(), 1);
        stop(handle, events, task).await;
    }

    #[tokio::test]
    async fn poisoned_receiver_mac_is_retained_candidate_only_and_served() {
        let harness = Harness::new();
        let (author, mut author_events, author_task) = harness.start(0, Vec::new());
        wait_ready(&mut author_events).await;
        author.local_header(&direct_header(0, 1, 0x21)).unwrap();
        let mut envelope = next_carrier(&mut author_events, 2).await;
        let candidate = CandidateCarrierV1::decode_wire_with_committee(
            &envelope.canonical_carrier,
            &harness.committee,
            None,
        )
        .unwrap();
        envelope.authentication_sidecar[3 + 2 * MAC_TAG_SIZE] ^= 1;

        let (receiver, mut receiver_events, receiver_task) = harness.start(2, Vec::new());
        wait_ready(&mut receiver_events).await;
        receiver.carrier(0, envelope.clone()).unwrap();
        let mut retained = false;
        let mut rejected = false;
        while !retained || !rejected {
            match next_event(&mut receiver_events).await {
                ShadowServiceEventV1::Input {
                    kind: "carrier",
                    outcome: "retained_unauthenticated",
                } => retained = true,
                ShadowServiceEventV1::Rejected { peer: Some(0), .. } => rejected = true,
                ShadowServiceEventV1::Delivered(_) => {
                    panic!("candidate-only retention must not grant admission/delivery")
                }
                _ => {}
            }
        }
        receiver.carrier_request(1, candidate.reference()).unwrap();
        loop {
            if let ShadowServiceEventV1::Network {
                recipient: 1,
                message: NetworkMessage::RbcDagShadowCarrierResponse(response),
            } = next_event(&mut receiver_events).await
            {
                assert_eq!(response.reference, candidate.reference());
                assert_eq!(response.canonical_carrier, envelope.canonical_carrier);
                break;
            }
        }
        stop(author, author_events, author_task).await;
        stop(receiver, receiver_events, receiver_task).await;
    }

    #[tokio::test]
    async fn reconnect_replays_exact_persisted_envelope() {
        let harness = Harness::new();
        let (handle, mut events, task) = harness.start(0, Vec::new());
        wait_ready(&mut events).await;
        handle.local_header(&direct_header(0, 1, 0x31)).unwrap();
        let original = next_carrier(&mut events, 1).await;
        handle.peer_connected(1).unwrap();
        let first_replay = next_carrier(&mut events, 1).await;
        assert_eq!(first_replay, original);
        handle.peer_disconnected(1).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        handle.peer_connected(1).unwrap();
        let second_replay = next_carrier(&mut events, 1).await;
        assert_eq!(second_replay, original);
        stop(handle, events, task).await;
    }

    #[tokio::test]
    async fn queued_round_waits_for_shadow_quorum_then_broadcasts_exact_next_round() {
        let harness = Harness::new();
        let (handle, mut events, task) = harness.start(0, Vec::new());
        wait_ready(&mut events).await;
        let round_two = direct_header(0, 2, 0x42);
        handle.local_header(&round_two).unwrap();
        handle.local_header(&direct_header(0, 1, 0x41)).unwrap();
        let round_one_wire = next_carrier(&mut events, 1).await;
        let round_one = CandidateCarrierV1::decode_wire_with_committee(
            &round_one_wire.canonical_carrier,
            &harness.committee,
            None,
        )
        .unwrap();
        assert_eq!(round_one.header().carrier_round(), 1);

        for author in [1, 2] {
            let candidate = round_one_candidate(author, &harness.committee, 0x50 + author as u8);
            handle
                .carrier(author, harness.envelope(&candidate, author))
                .unwrap();
        }
        let round_two_wire = loop {
            let envelope = next_carrier(&mut events, 1).await;
            let candidate = CandidateCarrierV1::decode_wire_with_committee(
                &envelope.canonical_carrier,
                &harness.committee,
                None,
            )
            .unwrap();
            if candidate.header().carrier_round() == 2 {
                break candidate;
            }
        };
        assert_eq!(
            round_two_wire.header().transactions_commitment(),
            round_two.transactions_commitment()
        );
        stop(handle, events, task).await;
    }

    #[tokio::test]
    async fn recovery_binds_holder_and_reference_then_compares_only_paired_slot_once() {
        let harness = Harness::new();
        let (handle, mut events, task) = harness.start(3, Vec::new());
        wait_ready(&mut events).await;
        handle.peer_connected(0).unwrap();
        handle.peer_connected(1).unwrap();
        let target = round_one_candidate(2, &harness.committee, 0x61);
        for sender in [0, 1] {
            let outer = phase_carrier(
                sender,
                RbcPhaseStatementV1::Ready {
                    target: target.reference(),
                },
                &harness.committee,
            );
            handle
                .carrier(sender, harness.envelope(&outer, sender))
                .unwrap();
        }
        let requested = loop {
            if let ShadowServiceEventV1::Network {
                recipient,
                message: NetworkMessage::RbcDagShadowCarrierRequest(reference),
            } = next_event(&mut events).await
            {
                if recipient == 0 || recipient == 1 {
                    break reference;
                }
            }
        };
        assert_eq!(requested, target.reference());

        handle
            .carrier_response(
                2,
                RbcDagShadowCarrierResponse {
                    reference: target.reference(),
                    canonical_carrier: target.canonical_wire_bytes().unwrap(),
                },
            )
            .unwrap();
        loop {
            if let ShadowServiceEventV1::Rejected {
                peer: Some(2),
                error,
            } = next_event(&mut events).await
            {
                assert!(error.contains("non-holder"));
                break;
            }
        }

        let wrong = round_one_candidate(2, &harness.committee, 0x62);
        handle
            .carrier_response(
                0,
                RbcDagShadowCarrierResponse {
                    reference: target.reference(),
                    canonical_carrier: wrong.canonical_wire_bytes().unwrap(),
                },
            )
            .unwrap();
        loop {
            if let ShadowServiceEventV1::Rejected {
                peer: Some(0),
                error,
            } = next_event(&mut events).await
            {
                assert!(error.contains("ReferenceMismatch"));
                break;
            }
        }

        let retried = timeout(Duration::from_secs(2), async {
            loop {
                if let ShadowServiceEventV1::Network {
                    message: NetworkMessage::RbcDagShadowCarrierRequest(reference),
                    ..
                } = next_event(&mut events).await
                {
                    break reference;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(retried, target.reference());

        handle
            .carrier_response(
                1,
                RbcDagShadowCarrierResponse {
                    reference: target.reference(),
                    canonical_carrier: target.canonical_wire_bytes().unwrap(),
                },
            )
            .unwrap();
        let identity = loop {
            if let ShadowServiceEventV1::Delivered(identity) = next_event(&mut events).await {
                break identity;
            }
        };
        assert_eq!(identity.author, 2);
        assert_eq!(identity.round, 1);
        handle.direct_delivered(identity).unwrap();
        loop {
            if let ShadowServiceEventV1::Comparison(comparison) = next_event(&mut events).await {
                assert_eq!(comparison, ShadowDeliveryComparisonV1::Match);
                break;
            }
        }
        let conflicting = ShadowDeliveryIdentityV1::new(
            identity.author,
            identity.round,
            TransactionsCommitment::from_bytes([0xEE; 32]),
        );
        handle.direct_delivered(conflicting).unwrap();
        loop {
            if let ShadowServiceEventV1::Comparison(comparison) = next_event(&mut events).await {
                assert_eq!(
                    comparison,
                    ShadowDeliveryComparisonV1::Ambiguous {
                        slots: vec![ShadowDeliverySlotV1 {
                            author: identity.author,
                            round: identity.round,
                        }],
                    }
                );
                break;
            }
        }
        stop(handle, events, task).await;
    }

    #[tokio::test]
    async fn bounded_input_reports_overload_but_shutdown_waits_for_capacity() {
        let input_capacity = shadow_input_capacity(N).unwrap();
        let (sender, mut receiver) = mpsc::channel(input_capacity);
        let handle = StarfishRbcDagShadowServiceHandleV1 {
            sender,
            max_sidecar_size: 3 + N * MAC_TAG_SIZE,
            own_authority: 0,
            committee_size: N,
            input_capacity,
            desired_topology: Arc::new(Mutex::new(BTreeMap::new())),
            desired_direct_deliveries: Arc::new(Mutex::new(BTreeSet::new())),
            invalidated_by_overload: Arc::new(Mutex::new(None)),
        };
        for round in 0..input_capacity {
            handle
                .carrier(
                    1,
                    RbcDagShadowCarrier {
                        canonical_carrier: vec![round as u8],
                        authentication_sidecar: Vec::new(),
                    },
                )
                .unwrap();
        }
        assert!(matches!(
            handle.carrier(
                1,
                RbcDagShadowCarrier {
                    canonical_carrier: vec![0xFF],
                    authentication_sidecar: Vec::new(),
                },
            ),
            Err(ShadowServiceErrorV1::Overloaded {
                kind: "carrier",
                capacity,
            })
            if capacity == input_capacity
        ));

        let shutdown_handle = handle.clone();
        let shutdown = tokio::spawn(async move { shutdown_handle.shutdown().await });
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());
        while let Some(message) = receiver.recv().await {
            if let ShadowServiceMessageV1::Shutdown(reply) = message {
                reply.send(Ok(())).unwrap();
                break;
            }
        }
        shutdown.await.unwrap().unwrap();

        let (sender, _receiver) = mpsc::channel(1);
        let oversized = StarfishRbcDagShadowServiceHandleV1 {
            sender,
            max_sidecar_size: 3 + N * MAC_TAG_SIZE,
            own_authority: 0,
            committee_size: N,
            input_capacity: 1,
            desired_topology: Arc::new(Mutex::new(BTreeMap::new())),
            desired_direct_deliveries: Arc::new(Mutex::new(BTreeSet::new())),
            invalidated_by_overload: Arc::new(Mutex::new(None)),
        };
        assert!(matches!(
            oversized.carrier(
                1,
                RbcDagShadowCarrier {
                    canonical_carrier: vec![0; MAX_CARRIER_CONTENT_SIZE_V1 + 1],
                    authentication_sidecar: Vec::new(),
                },
            ),
            Err(ShadowServiceErrorV1::InputTooLarge {
                field: "carrier",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn sixty_validator_burst_fits_before_the_actor_drains() {
        const LARGE_N: usize = 60;
        let input_capacity = shadow_input_capacity(LARGE_N).unwrap();
        assert_eq!(input_capacity, SHADOW_SERVICE_MAX_INPUT_CAPACITY_V1);
        let (sender, _receiver) = mpsc::channel(input_capacity);
        let invalidated = Arc::new(Mutex::new(None));
        let handle = StarfishRbcDagShadowServiceHandleV1 {
            sender,
            max_sidecar_size: 3 + LARGE_N * MAC_TAG_SIZE,
            own_authority: 0,
            committee_size: LARGE_N,
            input_capacity,
            desired_topology: Arc::new(Mutex::new(BTreeMap::new())),
            desired_direct_deliveries: Arc::new(Mutex::new(BTreeSet::new())),
            invalidated_by_overload: Arc::clone(&invalidated),
        };
        for peer in 1..LARGE_N {
            handle
                .carrier(
                    peer as AuthorityIndex,
                    RbcDagShadowCarrier {
                        canonical_carrier: vec![peer as u8],
                        authentication_sidecar: Vec::new(),
                    },
                )
                .unwrap();
        }
        for _ in 0..SHADOW_SERVICE_CONTROL_RESERVE_V1 {
            handle.send(ShadowServiceMessageV1::RetryRecovery).unwrap();
        }
        assert_eq!(*invalidated.lock(), None);
        assert!(matches!(
            shadow_input_capacity(LARGE_N + 1),
            Err(ShadowServiceErrorV1::CommitteeBurstTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn dropping_all_handles_stops_actor_despite_retry_timer() {
        let harness = Harness::new();
        let (handle, events, task) = harness.start(0, Vec::new());
        drop(handle);
        drop(events);
        timeout(EVENT_TIMEOUT, task)
            .await
            .expect("retry timer retained a strong input sender")
            .unwrap();
    }
}
