// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Async network adapter for the persisted RBC-DAG research runtime.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;

use tokio::{
    sync::{
        mpsc::{self, error::TrySendError},
        oneshot, watch,
    },
    task::JoinHandle,
};

use crate::{
    crypto::{
        MAC_TAG_SIZE, ML_DSA_44_SIGNATURE_SIZE, ML_DSA_65_SIGNATURE_SIZE, SIGNATURE_SIZE,
        TransactionsCommitment,
    },
    metrics::{
        Metrics, RBC_DAG_LATENCY_CREATION_TO_ASSIGNMENT, RBC_DAG_LATENCY_CREATION_TO_DELIVERY,
        RBC_DAG_LATENCY_CREATION_TO_FRONTIER_GENERATED,
    },
    network::{
        NetworkMessage, RbcDagApplicationPayloadResponse, RbcDagShadowCarrier,
        RbcDagShadowCarrierEnvelopeResponse, RbcDagShadowCarrierResponse,
        RbcDagShadowCarrierSyncRequest, RbcDagShadowCarrierSyncResponse,
    },
    starfish_rbc::RbcCanonicalHeader,
    starfish_rbc_dag::{
        CandidateCarrierV1, ConsensusVertexReference, MAX_CARRIER_CONTENT_SIZE_V1,
        RbcDagCommitteeContextV1, RbcDagContextV1,
        model::{
            EXECUTABLE_MODEL_ADMISSION_WINDOW_V1, EXECUTABLE_MODEL_BUFFER_WINDOW_V1, ModelEffect,
            ModelError,
        },
        projection::ProjectionDecisionV1,
        storage::ShadowWalSyncPolicyV1,
    },
    starfish_rbc_dag_shadow::{
        CommittedFrontierDeltaV1, RbcDagFrontierRecoveryCursorV1, ShadowAuthorizerV1,
        ShadowDeliveryComparisonV1, ShadowDeliveryIdentityV1, ShadowDeliverySlotV1, ShadowErrorV1,
        ShadowIngressDispositionV1, ShadowOpenReportV1, ShadowOutboundEnvelopeV1,
        StarfishRbcDagShadowV1,
    },
    types::{
        AuthorityIndex, BlockAuthenticationScheme, BlockReference, RoundNumber, TimestampNs,
        TransactionData,
    },
};

// A mirror run must absorb one complete committee fan-in plus a small reserve;
// autonomous repair additionally budgets a simultaneous request and response
// per peer. At the four-MiB carrier cap, allowing at most 128 queued inputs
// caps carrier payload retention at 512 MiB (plus bounded sidecars and
// allocator overhead). This permits 124 mirror validators or 42 autonomous
// validators, including the 40-validator comparison profile. Larger committees
// are rejected for this benchmark prototype
// instead of silently under-sizing the queue and reporting incomparable
// results.
// Use the full bounded allowance even for a small committee. A single fan-in
// reserve is insufficient when several round bursts arrive while the actor is
// synchronously making the previous transition durable.
const SHADOW_SERVICE_MIN_INPUT_CAPACITY_V1: usize = 64;
const SHADOW_SERVICE_MAX_INPUT_CAPACITY_V1: usize = 128;
const SHADOW_SERVICE_CONTROL_RESERVE_V1: usize = 5;
const SHADOW_SERVICE_EVENT_CAPACITY_V1: usize = 16;
const SHADOW_MAINTENANCE_INTERVAL_V1: Duration = Duration::from_millis(100);
const SHADOW_APPLICATION_SUBMISSION_GRACE_V1: Duration = Duration::from_millis(100);
const SHADOW_APPLICATION_SUBMISSION_GRACE_COMMITTEE_STEP_V1: usize = 10;
const SHADOW_RECOVERY_RETRY_INTERVAL_V1: Duration = Duration::from_millis(500);
const SHADOW_CARRIER_SYNC_RETRY_INTERVAL_V1: Duration = Duration::from_millis(100);
// At most sixteen distinct exact slots may bypass the duplicate retry interval
// per requester. Even at the four-MiB carrier ceiling this bounds one
// interval's replay exposure to 64 MiB; ordinary network backpressure remains
// the second bound. Production should replace this prototype credit with a
// configured byte-rate budget.
const SHADOW_CARRIER_SYNC_MAX_ADVANCING_BURST_V1: usize = 16;
/// Exact repair is an independently bounded priority lane. The same cap is
/// used for outstanding request slots and for responses coalesced outside the
/// ordinary actor FIFO.
const SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1: usize = 64;
const SHADOW_CARRIER_SYNC_MIN_GRACE_INTERVAL_V1: Duration = Duration::from_millis(500);
/// This prototype applies the existing four-MiB canonical-content/default
/// block ceiling as a conservative serialized-payload preflight. The network
/// frame ceiling is larger; a dedicated configurable payload limit remains a
/// deployment-hardening boundary. Keeping only a bounded recent window stops
/// unsolicited sidecars from turning the actor into an unbounded cache.
// Bound the materialized-payload/quarantine cache independently from history,
// but size it for the same three-message-per-peer fan-in that the autonomous
// actor accepts. A fixed 64-entry callback map is insufficient at n=40: two
// adjacent carrier waves can complete verification while the actor applies
// the previous wave. The global 128 ceiling keeps the testbed bound explicit.
const SHADOW_APPLICATION_PAYLOAD_MIN_CAPACITY_V1: usize = 64;
const SHADOW_APPLICATION_PAYLOAD_MAX_SIZE_V1: usize = MAX_CARRIER_CONTENT_SIZE_V1;
const SHADOW_APPLICATION_PAYLOAD_RETRY_INTERVAL_V1: Duration = Duration::from_millis(500);
/// Bound healthy physical-carrier production independently of actor/network
/// scheduling. The 600-ms Starfish pacemaker therefore permits at most about
/// 33 normal carriers/s, while validity-backed repair retains its separately
/// bounded burst lane.
const SHADOW_NORMAL_CARRIER_SPACING_DIVISOR_V1: u32 = 20;
const SHADOW_NORMAL_CARRIER_MIN_SPACING_V1: Duration = Duration::from_millis(1);

fn shadow_application_payload_capacity(committee_size: usize) -> usize {
    committee_size.saturating_mul(3).clamp(
        SHADOW_APPLICATION_PAYLOAD_MIN_CAPACITY_V1,
        SHADOW_SERVICE_MAX_INPUT_CAPACITY_V1,
    )
}

fn shadow_application_submission_grace(committee_size: usize) -> Duration {
    let fan_in_groups = committee_size
        .max(1)
        .div_ceil(SHADOW_APPLICATION_SUBMISSION_GRACE_COMMITTEE_STEP_V1);
    SHADOW_APPLICATION_SUBMISSION_GRACE_V1
        .checked_div(u32::try_from(fan_in_groups).unwrap_or(u32::MAX))
        .unwrap_or_default()
}

type CarrierSyncSlotV1 = (RoundNumber, AuthorityIndex);
type DesiredCarrierSyncResponseV1 = (AuthorityIndex, RbcDagShadowCarrierSyncResponse);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NormalCarrierDeadlineV1 {
    generation: u64,
    deadline: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConsensusTimeoutDeadlineV1 {
    generation: u64,
    slot: RoundNumber,
    deadline: Instant,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CarrierSyncInspectionV1 {
    open_round: RoundNumber,
    target: Option<RoundNumber>,
    outstanding: usize,
    desired_responses: usize,
    max_outstanding: usize,
    max_desired_responses: usize,
}

/// Runtime role of the persisted carrier actor.
///
/// Mirror mode preserves milestone three's one-to-one comparison against
/// direct Starfish-RBC headers. Autonomous mode opens an independent carrier
/// clock and owns embedded-RBC certification plus clean projection decisions.
/// It deliberately does not call the legacy core dispatcher: replacing the
/// temporary application-output scaffold is the M7 boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShadowServiceModeV1 {
    DirectMirror,
    AutonomousClock { heartbeat_interval: Duration },
}

impl ShadowServiceModeV1 {
    fn is_autonomous(self) -> bool {
        matches!(self, Self::AutonomousClock { .. })
    }

    fn heartbeat_interval(self) -> Option<Duration> {
        match self {
            Self::DirectMirror => None,
            Self::AutonomousClock { heartbeat_interval } => Some(heartbeat_interval),
        }
    }

    fn carrier_sync_grace_interval(self) -> Duration {
        self.heartbeat_interval()
            .map(|interval| interval.saturating_mul(2))
            .unwrap_or_default()
            .max(SHADOW_CARRIER_SYNC_MIN_GRACE_INTERVAL_V1)
    }
}

/// Per-logical-slot Starfish creation pacemaker.
///
/// The physical heartbeat runs on a fixed grid, so its tick time cannot also
/// be the C2 origin: a logical slot may have opened only an instant before the
/// tick. C2 is armed once A1 is locally true for this exact slot. C3 remains
/// an immediate, independently sufficient catch-up condition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConsensusPacemakerV1 {
    slot: RoundNumber,
    c2_armed_at: Option<Instant>,
    c2_timed_out: bool,
}

impl ConsensusPacemakerV1 {
    fn new(slot: RoundNumber) -> Self {
        Self {
            slot,
            c2_armed_at: None,
            c2_timed_out: false,
        }
    }

    fn fallback_allowed(
        &mut self,
        slot: RoundNumber,
        a1_ready: bool,
        c3_ready: bool,
        leader_timeout: Duration,
        now: Instant,
    ) -> bool {
        if self.slot != slot {
            self.slot = slot;
            self.c2_armed_at = None;
            self.c2_timed_out = false;
        }
        if a1_ready {
            self.c2_armed_at.get_or_insert(now);
        } else {
            // Eligible projection is monotonic, so this is principally a
            // fail-closed guard against arming from the wrong logical slot.
            self.c2_armed_at = None;
            self.c2_timed_out = false;
        }
        c3_ready
            || self.c2_timed_out
            || self
                .c2_armed_at
                .is_some_and(|armed| now.saturating_duration_since(armed) >= leader_timeout)
    }

    fn observe_timeout(&mut self, slot: RoundNumber) -> bool {
        if self.slot != slot || self.c2_armed_at.is_none() {
            return false;
        }
        self.c2_timed_out = true;
        true
    }
}

#[derive(Clone, Debug)]
struct ShadowLocalCarrierV1 {
    author: AuthorityIndex,
    round: RoundNumber,
    transactions_commitment: TransactionsCommitment,
    creation_time_ns: TimestampNs,
    application_header: RbcCanonicalHeader,
    application_payload: Option<Arc<TransactionData>>,
    /// True only when the live core submitted this header and is waiting for
    /// an `ApplicationAssigned` flow-control acknowledgment. Recovered direct
    /// history may be assigned during WAL reconciliation without a live
    /// producer gate to release.
    acknowledge_assignment: bool,
}

impl ShadowLocalCarrierV1 {
    #[cfg(test)]
    fn from_direct_header(header: &RbcCanonicalHeader) -> Self {
        Self::from_direct_header_with_payload(header, None)
    }

    fn from_direct_header_with_payload(
        header: &RbcCanonicalHeader,
        application_payload: Option<Arc<TransactionData>>,
    ) -> Self {
        Self::from_direct_header_with_ack(header, application_payload, true)
    }

    fn from_recovered_direct_header(header: &RbcCanonicalHeader) -> Self {
        Self::from_direct_header_with_ack(header, None, false)
    }

    fn from_direct_header_with_ack(
        header: &RbcCanonicalHeader,
        application_payload: Option<Arc<TransactionData>>,
        acknowledge_assignment: bool,
    ) -> Self {
        Self {
            author: header.reference().authority,
            round: header.reference().round,
            transactions_commitment: header.transactions_commitment(),
            creation_time_ns: header.meta_creation_time_ns(),
            application_header: header.clone(),
            application_payload,
            acknowledge_assignment,
        }
    }

    fn same_application(&self, other: &Self) -> bool {
        self.author == other.author
            && self.round == other.round
            && self.transactions_commitment == other.transactions_commitment
            && self.creation_time_ns == other.creation_time_ns
            && self.application_header == other.application_header
    }
}

impl PartialEq for ShadowLocalCarrierV1 {
    fn eq(&self, other: &Self) -> bool {
        self.same_application(other)
            && application_payloads_equal(
                self.application_payload.as_deref(),
                other.application_payload.as_deref(),
            )
            && self.acknowledge_assignment == other.acknowledge_assignment
    }
}

impl Eq for ShadowLocalCarrierV1 {}

enum ShadowServiceMessageV1 {
    ActivateClock(oneshot::Sender<()>),
    LocalApplicationsChanged,
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
    CarrierEnvelopeResponse {
        peer: AuthorityIndex,
        response: RbcDagShadowCarrierEnvelopeResponse,
    },
    CarrierSyncRequest {
        peer: AuthorityIndex,
        request: RbcDagShadowCarrierSyncRequest,
    },
    CarrierSyncResponsesChanged,
    ApplicationPayloadRequest {
        peer: AuthorityIndex,
        application: BlockReference,
    },
    ApplicationPayloadResponse {
        peer: AuthorityIndex,
        response: RbcDagApplicationPayloadResponse,
    },
    VerifiedApplicationPayloadsChanged,
    DirectDeliveriesChanged,
    TopologyChanged,
    RetryRecovery,
    HeartbeatTick,
    NormalCarrierDeadline {
        generation: u64,
    },
    ConsensusTimeoutDeadline {
        generation: u64,
        slot: RoundNumber,
    },
    DataAvailabilityChanged,
    #[cfg(test)]
    InspectRbcProgress(oneshot::Sender<(usize, usize)>),
    #[cfg(test)]
    InspectCarrierSync(oneshot::Sender<CarrierSyncInspectionV1>),
    Shutdown(oneshot::Sender<Result<(), ShadowServiceErrorV1>>),
}

#[derive(Clone)]
pub(crate) struct StarfishRbcDagShadowServiceHandleV1 {
    sender: mpsc::Sender<ShadowServiceMessageV1>,
    max_sidecar_size: usize,
    own_authority: AuthorityIndex,
    committee_size: usize,
    #[cfg(test)]
    input_capacity: usize,
    mode: ShadowServiceModeV1,
    desired_topology: Arc<Mutex<BTreeMap<AuthorityIndex, (bool, u64)>>>,
    desired_local_applications: Arc<Mutex<BTreeMap<RoundNumber, ShadowLocalCarrierV1>>>,
    /// Exact `(round, author)` responses outside the ordinary actor FIFO.
    /// Catch-up must not wait behind the proactive future carriers it is
    /// intended to overtake.
    desired_carrier_sync_responses:
        Arc<Mutex<BTreeMap<CarrierSyncSlotV1, DesiredCarrierSyncResponseV1>>>,
    desired_verified_application_payloads:
        Arc<Mutex<BTreeMap<BlockReference, Arc<TransactionData>>>>,
    desired_direct_deliveries: Arc<Mutex<BTreeSet<ShadowDeliveryIdentityV1>>>,
    desired_available_applications: Arc<Mutex<BTreeSet<BlockReference>>>,
    invalidated_by_overload: Arc<Mutex<Option<&'static str>>>,
}

impl StarfishRbcDagShadowServiceHandleV1 {
    #[cfg(test)]
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

    async fn send_reliably(
        &self,
        message: ShadowServiceMessageV1,
    ) -> Result<(), ShadowServiceErrorV1> {
        if let Some(reason) = *self.invalidated_by_overload.lock() {
            return Err(ShadowServiceErrorV1::BenchmarkInvalid { reason });
        }
        self.sender
            .send(message)
            .await
            .map_err(|_| ShadowServiceErrorV1::Stopped)
    }

    pub(crate) fn local_header(
        &self,
        header: &RbcCanonicalHeader,
    ) -> Result<(), ShadowServiceErrorV1> {
        self.local_application(header, None)
    }

    /// Coalescing producer boundary for a standalone embedded application.
    /// The optional payload is availability data only; its header remains the
    /// sole identity and is commitment-checked inside the actor before use.
    pub(crate) fn local_application(
        &self,
        header: &RbcCanonicalHeader,
        application_payload: Option<Arc<TransactionData>>,
    ) -> Result<(), ShadowServiceErrorV1> {
        if let Some(reason) = *self.invalidated_by_overload.lock() {
            return Err(ShadowServiceErrorV1::BenchmarkInvalid { reason });
        }
        if let Some(payload) = &application_payload {
            validate_application_payload_size(payload)?;
        }
        let local =
            ShadowLocalCarrierV1::from_direct_header_with_payload(header, application_payload);
        let mut desired = self.desired_local_applications.lock();
        if let Some(existing) = desired.get_mut(&local.round) {
            if !existing.same_application(&local) {
                return Err(ShadowServiceErrorV1::ConflictingLocalHeader(local.round));
            }
            merge_application_payload(
                &mut existing.application_payload,
                local.application_payload,
                existing.application_header.reference(),
            )?;
            existing.acknowledge_assignment |= local.acknowledge_assignment;
            return Ok(());
        }
        let capacity = shadow_application_payload_capacity(self.committee_size);
        if desired.len() >= capacity {
            return Err(ShadowServiceErrorV1::ApplicationStateCapacity { capacity });
        }
        desired.insert(local.round, local);
        drop(desired);
        match self
            .sender
            .try_send(ShadowServiceMessageV1::LocalApplicationsChanged)
        {
            Ok(()) | Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Closed(_)) => Err(ShadowServiceErrorV1::Stopped),
        }
    }

    #[cfg(test)]
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
        if let Some(payload) = &envelope.application_payload {
            validate_application_payload_size(payload)?;
        }
        self.send(ShadowServiceMessageV1::Carrier { peer, envelope })
    }

    pub(crate) async fn carrier_reliably(
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
        if let Some(payload) = &envelope.application_payload {
            validate_application_payload_size(payload)?;
        }
        self.send_reliably(ShadowServiceMessageV1::Carrier { peer, envelope })
            .await
    }

    #[cfg(test)]
    pub(crate) fn carrier_request(
        &self,
        peer: AuthorityIndex,
        reference: BlockReference,
    ) -> Result<(), ShadowServiceErrorV1> {
        self.send(ShadowServiceMessageV1::CarrierRequest { peer, reference })
    }

    pub(crate) async fn carrier_request_reliably(
        &self,
        peer: AuthorityIndex,
        reference: BlockReference,
    ) -> Result<(), ShadowServiceErrorV1> {
        self.send_reliably(ShadowServiceMessageV1::CarrierRequest { peer, reference })
            .await
    }

    #[cfg(test)]
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

    pub(crate) async fn carrier_response_reliably(
        &self,
        peer: AuthorityIndex,
        response: RbcDagShadowCarrierResponse,
    ) -> Result<(), ShadowServiceErrorV1> {
        validate_wire_size(
            "carrier response",
            response.canonical_carrier.len(),
            MAX_CARRIER_CONTENT_SIZE_V1,
        )?;
        self.send_reliably(ShadowServiceMessageV1::CarrierResponse { peer, response })
            .await
    }

    #[cfg(test)]
    pub(crate) fn carrier_envelope_response(
        &self,
        peer: AuthorityIndex,
        response: RbcDagShadowCarrierEnvelopeResponse,
    ) -> Result<(), ShadowServiceErrorV1> {
        self.validate_carrier_envelope_response(&response)?;
        self.send(ShadowServiceMessageV1::CarrierEnvelopeResponse { peer, response })
    }

    pub(crate) async fn carrier_envelope_response_reliably(
        &self,
        peer: AuthorityIndex,
        response: RbcDagShadowCarrierEnvelopeResponse,
    ) -> Result<(), ShadowServiceErrorV1> {
        self.validate_carrier_envelope_response(&response)?;
        self.send_reliably(ShadowServiceMessageV1::CarrierEnvelopeResponse { peer, response })
            .await
    }

    fn validate_carrier_envelope_response(
        &self,
        response: &RbcDagShadowCarrierEnvelopeResponse,
    ) -> Result<(), ShadowServiceErrorV1> {
        validate_wire_size(
            "carrier envelope response",
            response.canonical_carrier.len(),
            MAX_CARRIER_CONTENT_SIZE_V1,
        )?;
        validate_wire_size(
            "carrier envelope response authentication sidecar",
            response.authentication_sidecar.len(),
            self.max_sidecar_size,
        )
    }

    #[cfg(test)]
    pub(crate) fn carrier_sync_request(
        &self,
        peer: AuthorityIndex,
        request: RbcDagShadowCarrierSyncRequest,
    ) -> Result<(), ShadowServiceErrorV1> {
        if !self.mode.is_autonomous() {
            return Ok(());
        }
        self.send(ShadowServiceMessageV1::CarrierSyncRequest { peer, request })
    }

    pub(crate) async fn carrier_sync_request_reliably(
        &self,
        peer: AuthorityIndex,
        request: RbcDagShadowCarrierSyncRequest,
    ) -> Result<(), ShadowServiceErrorV1> {
        if !self.mode.is_autonomous() {
            return Ok(());
        }
        self.send_reliably(ShadowServiceMessageV1::CarrierSyncRequest { peer, request })
            .await
    }

    #[cfg(test)]
    pub(crate) fn carrier_sync_response(
        &self,
        peer: AuthorityIndex,
        response: RbcDagShadowCarrierSyncResponse,
    ) -> Result<(), ShadowServiceErrorV1> {
        self.enqueue_carrier_sync_response(peer, response)
    }

    pub(crate) async fn carrier_sync_response_reliably(
        &self,
        peer: AuthorityIndex,
        response: RbcDagShadowCarrierSyncResponse,
    ) -> Result<(), ShadowServiceErrorV1> {
        self.enqueue_carrier_sync_response(peer, response)
    }

    fn enqueue_carrier_sync_response(
        &self,
        peer: AuthorityIndex,
        response: RbcDagShadowCarrierSyncResponse,
    ) -> Result<(), ShadowServiceErrorV1> {
        if !self.mode.is_autonomous() {
            return Ok(());
        }
        if peer as usize >= self.committee_size {
            return Err(ShadowServiceErrorV1::UnknownAuthority(peer));
        }
        validate_wire_size(
            "carrier sync response",
            response.canonical_carrier.len(),
            MAX_CARRIER_CONTENT_SIZE_V1,
        )?;
        validate_wire_size(
            "carrier sync authentication sidecar",
            response.authentication_sidecar.len(),
            self.max_sidecar_size,
        )?;
        if response.author != peer {
            return Err(ShadowServiceErrorV1::UnexpectedSyncResponse {
                author: response.author,
                round: response.round,
            });
        }

        let slot = (response.round, response.author);
        let mut desired = self.desired_carrier_sync_responses.lock();
        match desired.get(&slot) {
            Some((existing_peer, existing)) if *existing_peer == peer && *existing == response => {
                return Ok(());
            }
            Some(_) => {
                return Err(ShadowServiceErrorV1::UnexpectedSyncResponse {
                    author: response.author,
                    round: response.round,
                });
            }
            None if desired.len() >= SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1 => {
                return Err(ShadowServiceErrorV1::CarrierSyncResponseCapacity {
                    capacity: SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1,
                });
            }
            None => {}
        }
        desired.insert(slot, (peer, response));
        drop(desired);
        match self
            .sender
            .try_send(ShadowServiceMessageV1::CarrierSyncResponsesChanged)
        {
            Ok(()) | Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Closed(_)) => Err(ShadowServiceErrorV1::Stopped),
        }
    }

    #[cfg(test)]
    pub(crate) fn application_payload_request(
        &self,
        peer: AuthorityIndex,
        application: BlockReference,
    ) -> Result<(), ShadowServiceErrorV1> {
        self.send(ShadowServiceMessageV1::ApplicationPayloadRequest { peer, application })
    }

    pub(crate) async fn application_payload_request_reliably(
        &self,
        peer: AuthorityIndex,
        application: BlockReference,
    ) -> Result<(), ShadowServiceErrorV1> {
        self.send_reliably(ShadowServiceMessageV1::ApplicationPayloadRequest { peer, application })
            .await
    }

    #[cfg(test)]
    pub(crate) fn application_payload_response(
        &self,
        peer: AuthorityIndex,
        response: RbcDagApplicationPayloadResponse,
    ) -> Result<(), ShadowServiceErrorV1> {
        validate_application_payload_size(&response.transaction_data)?;
        self.send(ShadowServiceMessageV1::ApplicationPayloadResponse { peer, response })
    }

    pub(crate) async fn application_payload_response_reliably(
        &self,
        peer: AuthorityIndex,
        response: RbcDagApplicationPayloadResponse,
    ) -> Result<(), ShadowServiceErrorV1> {
        validate_application_payload_size(&response.transaction_data)?;
        self.send_reliably(ShadowServiceMessageV1::ApplicationPayloadResponse { peer, response })
            .await
    }

    /// Trusted callback from the sole transaction-commitment verifier. The
    /// actor accepts it only for an already-authorized application reference;
    /// network payload bytes can never call this path directly.
    pub(crate) fn verified_application_payload(
        &self,
        application: BlockReference,
        payload: Arc<TransactionData>,
    ) -> Result<(), ShadowServiceErrorV1> {
        if let Some(reason) = *self.invalidated_by_overload.lock() {
            return Err(ShadowServiceErrorV1::BenchmarkInvalid { reason });
        }
        validate_application_payload_size(&payload)?;
        let mut desired = self.desired_verified_application_payloads.lock();
        if let Some(existing) = desired.get(&application) {
            if !application_payloads_equal(Some(existing.as_ref()), Some(payload.as_ref())) {
                return Err(ShadowServiceErrorV1::ConflictingApplicationPayload(
                    application,
                ));
            }
            return Ok(());
        }
        let capacity = shadow_application_payload_capacity(self.committee_size);
        if desired.len() >= capacity {
            return Err(ShadowServiceErrorV1::ApplicationStateCapacity { capacity });
        }
        desired.insert(application, payload);
        drop(desired);
        match self
            .sender
            .try_send(ShadowServiceMessageV1::VerifiedApplicationPayloadsChanged)
        {
            Ok(()) | Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Closed(_)) => Err(ShadowServiceErrorV1::Stopped),
        }
    }

    pub(crate) fn direct_delivered(
        &self,
        identity: ShadowDeliveryIdentityV1,
    ) -> Result<(), ShadowServiceErrorV1> {
        if self.mode.is_autonomous() {
            return Ok(());
        }
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

    pub(crate) fn application_data_available(
        &self,
        application: BlockReference,
    ) -> Result<(), ShadowServiceErrorV1> {
        if !self.mode.is_autonomous() {
            return Ok(());
        }
        if application.authority as usize >= self.committee_size {
            return Err(ShadowServiceErrorV1::UnknownAuthority(
                application.authority,
            ));
        }
        if !self
            .desired_available_applications
            .lock()
            .insert(application)
        {
            return Ok(());
        }
        match self
            .sender
            .try_send(ShadowServiceMessageV1::DataAvailabilityChanged)
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

    /// Release a coordinated autonomous-clock start barrier. This operation
    /// is idempotent: after the first successful activation, later callers
    /// receive an acknowledgment without resetting the heartbeat epoch.
    pub(crate) async fn activate_clock(&self) -> Result<(), ShadowServiceErrorV1> {
        if !self.mode.is_autonomous() {
            return Ok(());
        }
        let (reply, receiver) = oneshot::channel();
        self.send_reliably(ShadowServiceMessageV1::ActivateClock(reply))
            .await?;
        receiver.await.map_err(|_| ShadowServiceErrorV1::Stopped)
    }

    #[cfg(test)]
    async fn inspect_rbc_progress(&self) -> Result<(usize, usize), ShadowServiceErrorV1> {
        let (reply, receiver) = oneshot::channel();
        self.sender
            .send(ShadowServiceMessageV1::InspectRbcProgress(reply))
            .await
            .map_err(|_| ShadowServiceErrorV1::Stopped)?;
        receiver.await.map_err(|_| ShadowServiceErrorV1::Stopped)
    }

    #[cfg(test)]
    async fn inspect_carrier_sync(&self) -> Result<CarrierSyncInspectionV1, ShadowServiceErrorV1> {
        let (reply, receiver) = oneshot::channel();
        self.sender
            .send(ShadowServiceMessageV1::InspectCarrierSync(reply))
            .await
            .map_err(|_| ShadowServiceErrorV1::Stopped)?;
        receiver.await.map_err(|_| ShadowServiceErrorV1::Stopped)
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
    #[cfg(test)]
    fn kind(&self) -> &'static str {
        match self {
            Self::ActivateClock(_) => "activate_clock",
            Self::LocalApplicationsChanged => "local_applications_changed",
            Self::Carrier { .. } => "carrier",
            Self::CarrierRequest { .. } => "carrier_request",
            Self::CarrierResponse { .. } => "carrier_response",
            Self::CarrierEnvelopeResponse { .. } => "carrier_envelope_response",
            Self::CarrierSyncRequest { .. } => "carrier_sync_request",
            Self::CarrierSyncResponsesChanged => "carrier_sync_responses_changed",
            Self::ApplicationPayloadRequest { .. } => "application_payload_request",
            Self::ApplicationPayloadResponse { .. } => "application_payload_response",
            Self::VerifiedApplicationPayloadsChanged => "verified_application_payloads_changed",
            Self::DirectDeliveriesChanged => "direct_deliveries_changed",
            Self::TopologyChanged => "topology_changed",
            Self::RetryRecovery => "recovery_retry",
            Self::HeartbeatTick => "heartbeat_tick",
            Self::NormalCarrierDeadline { .. } => "normal_carrier_deadline",
            Self::ConsensusTimeoutDeadline { .. } => "consensus_timeout_deadline",
            Self::DataAvailabilityChanged => "data_availability_changed",
            Self::InspectRbcProgress(_) => "inspect_rbc_progress",
            Self::InspectCarrierSync(_) => "inspect_carrier_sync",
            Self::Shutdown(_) => "shutdown",
        }
    }
}

/// Exact protocol fact permitting an embedded application header to leave the
/// shadow actor. Payload availability is deliberately absent from this enum:
/// bytes can accompany authority, but can never create it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShadowApplicationAuthorizationBasisV1 {
    LocallyFixed,
    ReceiverAuthenticated,
    Delivered,
}

#[derive(Debug)]
pub(crate) enum ShadowServiceEventV1 {
    Ready {
        autonomous_clock: bool,
    },
    /// The autonomous actor has crossed its one-way coordinated-start
    /// barrier. Local carrier creation and exact repair are enabled, and the
    /// first physical heartbeat is one full interval after this event.
    ClockActivated,
    ClockState {
        open_round: RoundNumber,
        phase_backlog: usize,
        admitted_authors: usize,
        admitted_stake: u64,
        buffered_authenticated: usize,
    },
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
    EmbeddedApplicationDelivered {
        carrier: BlockReference,
        header: RbcCanonicalHeader,
    },
    /// An application header whose enclosing carrier has an exact local,
    /// receiver-authenticated, or delivered authorization basis. A later
    /// repeat may enrich an earlier header-only event with its verified
    /// transaction payload.
    AuthorizedApplicationObserved {
        carrier: BlockReference,
        header: RbcCanonicalHeader,
        payload: Option<Arc<TransactionData>>,
        authorization_basis: ShadowApplicationAuthorizationBasisV1,
    },
    /// The exact direct application header has been durably assigned to one
    /// local carrier. In embedded-authority mode this is the flow-control
    /// acknowledgment that permits the core to produce the next application
    /// header; it is not a delivery or commit certificate.
    ApplicationAssigned(BlockReference),
    VertexProjected(ConsensusVertexReference),
    LeaderDecided(ProjectionDecisionV1),
    FrontierCommitted(CommittedFrontierDeltaV1),
    Comparison(ShadowDeliveryComparisonV1),
    Input {
        kind: &'static str,
        outcome: &'static str,
    },
    WalAppended {
        batches: u64,
        records: u64,
        durable: bool,
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
    #[cfg(test)]
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
        required_capacity: usize,
        maximum_capacity: usize,
    },
    UnknownAuthority(AuthorityIndex),
    Loopback(AuthorityIndex),
    ConflictingLocalHeader(RoundNumber),
    ConflictingApplicationPayload(BlockReference),
    ApplicationStateCapacity {
        capacity: usize,
    },
    CarrierSyncResponseCapacity {
        capacity: usize,
    },
    ApplicationPayloadSerialization(String),
    ApplicationPayloadResponseFromUnexpectedPeer {
        peer: AuthorityIndex,
        application: BlockReference,
    },
    MissingRecoveredLocalHeader(RoundNumber),
    RecoveredLocalHeaderMismatch(RoundNumber),
    AutonomousWalContainsInvalidCarrier(RoundNumber),
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
    InvalidHeartbeatInterval,
    InvalidConsensusTimeout,
    SyncRequestForForeignAuthor {
        expected: AuthorityIndex,
        actual: AuthorityIndex,
    },
    UnexpectedSyncResponse {
        author: AuthorityIndex,
        round: RoundNumber,
    },
    SyncResponseSlotMismatch {
        expected_author: AuthorityIndex,
        expected_round: RoundNumber,
        actual_author: AuthorityIndex,
        actual_round: RoundNumber,
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
            #[cfg(test)]
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
                required_capacity,
                maximum_capacity,
            } => write!(
                formatter,
                "Starfish-RBC-DAG shadow committee size {committee_size} needs a burst queue of \
                 {required_capacity}, above the memory-safe capacity limit {maximum_capacity}",
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
            Self::ConflictingApplicationPayload(application) => write!(
                formatter,
                "conflicting transaction payloads supplied for embedded application {application}"
            ),
            Self::ApplicationStateCapacity { capacity } => write!(
                formatter,
                "embedded application state reached its bounded capacity of {capacity} entries"
            ),
            Self::CarrierSyncResponseCapacity { capacity } => write!(
                formatter,
                "exact carrier-sync response state reached its bounded capacity of {capacity} slots"
            ),
            Self::ApplicationPayloadSerialization(error) => write!(
                formatter,
                "embedded application payload could not be size-checked: {error}"
            ),
            Self::ApplicationPayloadResponseFromUnexpectedPeer { peer, application } => write!(
                formatter,
                "embedded application payload response for {application} came from unrequested authority {peer}"
            ),
            Self::MissingRecoveredLocalHeader(round) => write!(
                formatter,
                "persisted shadow carrier at round {round} has no matching recovered direct header"
            ),
            Self::RecoveredLocalHeaderMismatch(round) => write!(
                formatter,
                "persisted shadow carrier and recovered direct header disagree at round {round}"
            ),
            Self::AutonomousWalContainsInvalidCarrier(round) => write!(
                formatter,
                "autonomous carrier-clock WAL contains an invalid local carrier at round {round}"
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
            Self::InvalidHeartbeatInterval => formatter.write_str(
                "Starfish-RBC-DAG autonomous heartbeat interval must be nonzero",
            ),
            Self::InvalidConsensusTimeout => formatter.write_str(
                "Starfish-RBC-DAG logical consensus timeout must be nonzero",
            ),
            Self::SyncRequestForForeignAuthor { expected, actual } => write!(
                formatter,
                "shadow carrier sync request asked authority {expected} to serve authority {actual}"
            ),
            Self::UnexpectedSyncResponse { author, round } => write!(
                formatter,
                "unexpected shadow carrier sync response for authority {author} round {round}"
            ),
            Self::SyncResponseSlotMismatch {
                expected_author,
                expected_round,
                actual_author,
                actual_round,
            } => write!(
                formatter,
                "shadow carrier sync response for authority {expected_author} round {expected_round} contained authority {actual_author} round {actual_round}"
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

#[cfg(test)]
pub(crate) fn start_starfish_rbc_dag_shadow_service_v1(
    path: impl AsRef<Path>,
    committee: RbcDagCommitteeContextV1,
    own_authority: AuthorityIndex,
    context: RbcDagContextV1,
    authorizer: ShadowAuthorizerV1,
    recovered_local_headers: Vec<RbcCanonicalHeader>,
    wal_sync_policy: ShadowWalSyncPolicyV1,
) -> Result<
    (
        StarfishRbcDagShadowServiceHandleV1,
        mpsc::Receiver<ShadowServiceEventV1>,
        JoinHandle<()>,
    ),
    ShadowServiceErrorV1,
> {
    start_starfish_rbc_dag_shadow_service_with_mode_v1(
        path,
        committee,
        own_authority,
        context,
        authorizer,
        recovered_local_headers,
        ShadowServiceModeV1::DirectMirror,
        None,
        wal_sync_policy,
        None,
        None,
        true,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn start_starfish_rbc_dag_shadow_service_with_metrics_v1(
    path: impl AsRef<Path>,
    committee: RbcDagCommitteeContextV1,
    own_authority: AuthorityIndex,
    context: RbcDagContextV1,
    authorizer: ShadowAuthorizerV1,
    recovered_local_headers: Vec<RbcCanonicalHeader>,
    wal_sync_policy: ShadowWalSyncPolicyV1,
    metrics: Arc<Metrics>,
) -> Result<
    (
        StarfishRbcDagShadowServiceHandleV1,
        mpsc::Receiver<ShadowServiceEventV1>,
        JoinHandle<()>,
    ),
    ShadowServiceErrorV1,
> {
    start_starfish_rbc_dag_shadow_service_with_mode_v1(
        path,
        committee,
        own_authority,
        context,
        authorizer,
        recovered_local_headers,
        ShadowServiceModeV1::DirectMirror,
        None,
        wal_sync_policy,
        Some(metrics),
        None,
        true,
        false,
    )
}

#[cfg(test)]
pub(crate) fn start_starfish_rbc_dag_autonomous_clock_service_v1(
    path: impl AsRef<Path>,
    committee: RbcDagCommitteeContextV1,
    own_authority: AuthorityIndex,
    context: RbcDagContextV1,
    authorizer: ShadowAuthorizerV1,
    recovered_local_headers: Vec<RbcCanonicalHeader>,
    heartbeat_interval: Duration,
    wal_sync_policy: ShadowWalSyncPolicyV1,
) -> Result<
    (
        StarfishRbcDagShadowServiceHandleV1,
        mpsc::Receiver<ShadowServiceEventV1>,
        JoinHandle<()>,
    ),
    ShadowServiceErrorV1,
> {
    if heartbeat_interval.is_zero() {
        return Err(ShadowServiceErrorV1::InvalidHeartbeatInterval);
    }
    start_starfish_rbc_dag_shadow_service_with_mode_v1(
        path,
        committee,
        own_authority,
        context,
        authorizer,
        recovered_local_headers,
        ShadowServiceModeV1::AutonomousClock { heartbeat_interval },
        None,
        wal_sync_policy,
        None,
        None,
        true,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn start_starfish_rbc_dag_autonomous_clock_service_with_metrics_v1(
    path: impl AsRef<Path>,
    committee: RbcDagCommitteeContextV1,
    own_authority: AuthorityIndex,
    context: RbcDagContextV1,
    authorizer: ShadowAuthorizerV1,
    recovered_local_headers: Vec<RbcCanonicalHeader>,
    heartbeat_interval: Duration,
    wal_sync_policy: ShadowWalSyncPolicyV1,
    metrics: Arc<Metrics>,
) -> Result<
    (
        StarfishRbcDagShadowServiceHandleV1,
        mpsc::Receiver<ShadowServiceEventV1>,
        JoinHandle<()>,
    ),
    ShadowServiceErrorV1,
> {
    if heartbeat_interval.is_zero() {
        return Err(ShadowServiceErrorV1::InvalidHeartbeatInterval);
    }
    start_starfish_rbc_dag_shadow_service_with_mode_v1(
        path,
        committee,
        own_authority,
        context,
        authorizer,
        recovered_local_headers,
        ShadowServiceModeV1::AutonomousClock { heartbeat_interval },
        None,
        wal_sync_policy,
        Some(metrics),
        None,
        true,
        false,
    )
}

/// Start an autonomous runtime whose protocol clock remains paused after WAL
/// open/replay and `Ready`. The caller must invoke
/// [`StarfishRbcDagShadowServiceHandleV1::activate_clock`] after its external
/// startup barrier is satisfied. Ordinary start APIs remain active-by-default.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_starfish_rbc_dag_autonomous_clock_service_paused_with_metrics_v1(
    path: impl AsRef<Path>,
    committee: RbcDagCommitteeContextV1,
    own_authority: AuthorityIndex,
    context: RbcDagContextV1,
    authorizer: ShadowAuthorizerV1,
    recovered_local_headers: Vec<RbcCanonicalHeader>,
    heartbeat_interval: Duration,
    wal_sync_policy: ShadowWalSyncPolicyV1,
    metrics: Arc<Metrics>,
) -> Result<
    (
        StarfishRbcDagShadowServiceHandleV1,
        mpsc::Receiver<ShadowServiceEventV1>,
        JoinHandle<()>,
    ),
    ShadowServiceErrorV1,
> {
    if heartbeat_interval.is_zero() {
        return Err(ShadowServiceErrorV1::InvalidHeartbeatInterval);
    }
    start_starfish_rbc_dag_shadow_service_with_mode_v1(
        path,
        committee,
        own_authority,
        context,
        authorizer,
        recovered_local_headers,
        ShadowServiceModeV1::AutonomousClock { heartbeat_interval },
        None,
        wal_sync_policy,
        Some(metrics),
        None,
        false,
        false,
    )
}

/// Start the embedded-authority runtime with Core's exact durable recovery
/// cursor. Unlike the compatibility autonomous wrappers, this is the
/// production restart API: it fails closed unless the actor WAL reconciles
/// the cursor and its unapplied suffix is bounded.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_starfish_rbc_dag_authoritative_clock_service_with_metrics_v1(
    path: impl AsRef<Path>,
    committee: RbcDagCommitteeContextV1,
    own_authority: AuthorityIndex,
    context: RbcDagContextV1,
    authorizer: ShadowAuthorizerV1,
    recovered_local_headers: Vec<RbcCanonicalHeader>,
    heartbeat_interval: Duration,
    consensus_timeout: Duration,
    wal_sync_policy: ShadowWalSyncPolicyV1,
    metrics: Arc<Metrics>,
    recovery_cursor: Option<RbcDagFrontierRecoveryCursorV1>,
    clock_starts_active: bool,
    vote_qc_fast_path: bool,
) -> Result<
    (
        StarfishRbcDagShadowServiceHandleV1,
        mpsc::Receiver<ShadowServiceEventV1>,
        JoinHandle<()>,
    ),
    ShadowServiceErrorV1,
> {
    if heartbeat_interval.is_zero() {
        return Err(ShadowServiceErrorV1::InvalidHeartbeatInterval);
    }
    if consensus_timeout.is_zero() {
        return Err(ShadowServiceErrorV1::InvalidConsensusTimeout);
    }
    start_starfish_rbc_dag_shadow_service_with_mode_v1(
        path,
        committee,
        own_authority,
        context,
        authorizer,
        recovered_local_headers,
        ShadowServiceModeV1::AutonomousClock { heartbeat_interval },
        Some(consensus_timeout),
        wal_sync_policy,
        Some(metrics),
        recovery_cursor,
        clock_starts_active,
        vote_qc_fast_path,
    )
}

fn spawn_consensus_timeout_deadline_task(
    mut deadline_rx: watch::Receiver<Option<ConsensusTimeoutDeadlineV1>>,
    timeout_tx: mpsc::WeakSender<ShadowServiceMessageV1>,
) {
    tokio::spawn(async move {
        loop {
            if deadline_rx.changed().await.is_err() {
                return;
            }
            let Some(mut target) = *deadline_rx.borrow_and_update() else {
                continue;
            };
            'scheduled: loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(target.deadline)) => {
                        if *deadline_rx.borrow() != Some(target) {
                            break 'scheduled;
                        }
                        let Some(sender) = timeout_tx.upgrade() else {
                            return;
                        };
                        let message = ShadowServiceMessageV1::ConsensusTimeoutDeadline {
                            generation: target.generation,
                            slot: target.slot,
                        };
                        // A full actor FIFO must not pin a strong sender after
                        // the actor cancels/replaces this deadline or exits.
                        // The watch branch aborts the pending send; any wake
                        // already queued is rejected by its generation.
                        tokio::select! {
                            biased;
                            changed = deadline_rx.changed() => {
                                if changed.is_err() {
                                    return;
                                }
                                match *deadline_rx.borrow_and_update() {
                                    Some(replacement) => {
                                        target = replacement;
                                        continue 'scheduled;
                                    }
                                    None => break 'scheduled,
                                }
                            }
                            sent = sender.send(message) => {
                                if sent.is_err() {
                                    return;
                                }
                                break 'scheduled;
                            }
                        }
                    }
                    changed = deadline_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        match *deadline_rx.borrow_and_update() {
                            Some(replacement) => target = replacement,
                            None => break 'scheduled,
                        }
                    }
                }
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn start_starfish_rbc_dag_shadow_service_with_mode_v1(
    path: impl AsRef<Path>,
    committee: RbcDagCommitteeContextV1,
    own_authority: AuthorityIndex,
    context: RbcDagContextV1,
    authorizer: ShadowAuthorizerV1,
    recovered_local_headers: Vec<RbcCanonicalHeader>,
    mode: ShadowServiceModeV1,
    consensus_timeout: Option<Duration>,
    wal_sync_policy: ShadowWalSyncPolicyV1,
    metrics: Option<Arc<Metrics>>,
    recovery_cursor: Option<RbcDagFrontierRecoveryCursorV1>,
    clock_starts_active: bool,
    vote_qc_fast_path: bool,
) -> Result<
    (
        StarfishRbcDagShadowServiceHandleV1,
        mpsc::Receiver<ShadowServiceEventV1>,
        JoinHandle<()>,
    ),
    ShadowServiceErrorV1,
> {
    let committee_size = committee.committee().len();
    let consensus_timeout = consensus_timeout
        .or_else(|| mode.heartbeat_interval())
        .unwrap_or_default();
    let input_capacity = shadow_input_capacity(committee_size, mode)?;
    let max_sidecar_size =
        authentication_sidecar_size(context.authentication_scheme(), committee_size);
    let path = path.as_ref().to_path_buf();
    let mut pending_local = BTreeMap::new();
    for header in recovered_local_headers {
        let local = ShadowLocalCarrierV1::from_recovered_direct_header(&header);
        if local.author != own_authority {
            return Err(ShadowServiceErrorV1::LocalHeaderAuthority {
                expected: own_authority,
                actual: local.author,
            });
        }
        let round = local.round;
        if let Some(previous) = pending_local.insert(round, local.clone()) {
            if previous != local {
                return Err(ShadowServiceErrorV1::ConflictingLocalHeader(round));
            }
        }
    }
    let (message_tx, message_rx) = mpsc::channel(input_capacity);
    let (event_tx, event_rx) = mpsc::channel(SHADOW_SERVICE_EVENT_CAPACITY_V1);
    let desired_topology = Arc::new(Mutex::new(BTreeMap::new()));
    let desired_local_applications = Arc::new(Mutex::new(BTreeMap::new()));
    let desired_carrier_sync_responses = Arc::new(Mutex::new(BTreeMap::new()));
    let desired_verified_application_payloads = Arc::new(Mutex::new(BTreeMap::new()));
    let desired_direct_deliveries = Arc::new(Mutex::new(BTreeSet::new()));
    let desired_available_applications = Arc::new(Mutex::new(BTreeSet::new()));
    let invalidated_by_overload = Arc::new(Mutex::new(None));
    let retry_notification_pending = Arc::new(AtomicBool::new(false));
    let heartbeat_notification_pending = Arc::new(AtomicBool::new(false));
    // The physical heartbeat is deliberately created only after the actor
    // crosses its one-way activation barrier. In paused benchmark startup,
    // validators can therefore spend arbitrarily different amounts of time
    // opening WALs and establishing topology without inheriting staggered
    // timer phases or accumulating missed ticks.
    let (clock_activation_tx, mut clock_activation_rx) = watch::channel(false);
    let (normal_carrier_deadline_tx, mut normal_carrier_deadline_rx) =
        watch::channel(None::<NormalCarrierDeadlineV1>);
    let (consensus_timeout_deadline_tx, consensus_timeout_deadline_rx) =
        watch::channel(None::<ConsensusTimeoutDeadlineV1>);
    let retry_tx = message_tx.downgrade();
    let retry_pending = Arc::clone(&retry_notification_pending);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SHADOW_MAINTENANCE_INTERVAL_V1);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            let Some(retry_tx) = retry_tx.upgrade() else {
                break;
            };
            if retry_pending.swap(true, Ordering::AcqRel) {
                continue;
            }
            match retry_tx.try_send(ShadowServiceMessageV1::RetryRecovery) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => retry_pending.store(false, Ordering::Release),
                Err(TrySendError::Closed(_)) => {
                    retry_pending.store(false, Ordering::Release);
                    break;
                }
            }
        }
    });
    if let Some(heartbeat_interval) = mode.heartbeat_interval() {
        let heartbeat_tx = message_tx.downgrade();
        let heartbeat_pending = Arc::clone(&heartbeat_notification_pending);
        tokio::spawn(async move {
            if clock_activation_rx
                .wait_for(|active| *active)
                .await
                .is_err()
            {
                return;
            }
            let first_tick = tokio::time::Instant::now() + heartbeat_interval;
            let mut interval = tokio::time::interval_at(first_tick, heartbeat_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Some(heartbeat_tx) = heartbeat_tx.upgrade() else {
                    break;
                };
                if heartbeat_pending.swap(true, Ordering::AcqRel) {
                    continue;
                }
                match heartbeat_tx.try_send(ShadowServiceMessageV1::HeartbeatTick) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        heartbeat_pending.store(false, Ordering::Release);
                    }
                    Err(TrySendError::Closed(_)) => {
                        heartbeat_pending.store(false, Ordering::Release);
                        break;
                    }
                }
            }
        });
    }
    // One persistent, generation-tagged deadline task replaces per-attempt
    // sleeps. Repeated normal creation requests only replace the desired
    // deadline in the watch channel; a stale queued wake is harmless.
    let normal_carrier_tx = message_tx.downgrade();
    tokio::spawn(async move {
        loop {
            if normal_carrier_deadline_rx.changed().await.is_err() {
                return;
            }
            let Some(mut target) = *normal_carrier_deadline_rx.borrow_and_update() else {
                continue;
            };
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(target.deadline)) => {
                        if *normal_carrier_deadline_rx.borrow() != Some(target) {
                            break;
                        }
                        let Some(sender) = normal_carrier_tx.upgrade() else {
                            return;
                        };
                        if sender
                            .send(ShadowServiceMessageV1::NormalCarrierDeadline {
                                generation: target.generation,
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }
                        break;
                    }
                    changed = normal_carrier_deadline_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        match *normal_carrier_deadline_rx.borrow_and_update() {
                            Some(replacement) => target = replacement,
                            None => break,
                        }
                    }
                }
            }
        }
    });
    spawn_consensus_timeout_deadline_task(consensus_timeout_deadline_rx, message_tx.downgrade());
    let startup_events = event_tx.clone();
    let actor_desired_topology = Arc::clone(&desired_topology);
    let actor_desired_local_applications = Arc::clone(&desired_local_applications);
    let actor_desired_carrier_sync_responses = Arc::clone(&desired_carrier_sync_responses);
    let actor_desired_verified_application_payloads =
        Arc::clone(&desired_verified_application_payloads);
    let actor_desired_direct_deliveries = Arc::clone(&desired_direct_deliveries);
    let actor_desired_available_applications = Arc::clone(&desired_available_applications);
    let actor_invalidated_by_overload = Arc::clone(&invalidated_by_overload);
    let actor_retry_notification_pending = Arc::clone(&retry_notification_pending);
    let actor_heartbeat_notification_pending = Arc::clone(&heartbeat_notification_pending);
    let actor_committee = committee.clone();
    let task = tokio::spawn(async move {
        let opened = tokio::task::spawn_blocking(move || {
            if mode.is_autonomous() {
                StarfishRbcDagShadowV1::open_authoritative_with_wal_sync_policy(
                    path,
                    committee,
                    own_authority,
                    context,
                    authorizer,
                    wal_sync_policy,
                    recovery_cursor,
                    vote_qc_fast_path,
                )
            } else {
                StarfishRbcDagShadowV1::open_with_wal_sync_policy(
                    path,
                    committee,
                    own_authority,
                    context,
                    authorizer,
                    wal_sync_policy,
                )
            }
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
                .map(|metadata| {
                    (
                        metadata.round,
                        (
                            metadata.transactions_commitment,
                            metadata.creation_time_ns,
                            metadata.control_shape,
                            metadata.application,
                        ),
                    )
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
        let mut assigned_applications = BTreeSet::new();
        let durable_round = core.local_carrier_round();
        if mode.is_autonomous() {
            for (carrier_round, (commitment, _, control_shape, application)) in &persisted_local {
                if !*control_shape {
                    let _ = startup_events
                        .send(ShadowServiceEventV1::Rejected {
                            peer: None,
                            error: ShadowServiceErrorV1::AutonomousWalContainsInvalidCarrier(
                                *carrier_round,
                            )
                            .to_string(),
                        })
                        .await;
                    return;
                }
                let Some(application) = application else {
                    if *commitment != crate::crypto::TransactionsCommitment::default() {
                        let _ = startup_events
                            .send(ShadowServiceEventV1::Rejected {
                                peer: None,
                                error: ShadowServiceErrorV1::AutonomousWalContainsInvalidCarrier(
                                    *carrier_round,
                                )
                                .to_string(),
                            })
                            .await;
                        return;
                    }
                    continue;
                };
                let Some(recovered) = pending_local.get(&application.round) else {
                    let _ = startup_events
                        .send(ShadowServiceEventV1::Rejected {
                            peer: None,
                            error: ShadowServiceErrorV1::MissingRecoveredLocalHeader(
                                application.round,
                            )
                            .to_string(),
                        })
                        .await;
                    return;
                };
                if recovered.application_header.reference() != *application
                    || recovered.transactions_commitment != *commitment
                {
                    let _ = startup_events
                        .send(ShadowServiceEventV1::Rejected {
                            peer: None,
                            error: ShadowServiceErrorV1::RecoveredLocalHeaderMismatch(
                                application.round,
                            )
                            .to_string(),
                        })
                        .await;
                    return;
                }
                assigned_applications.insert(*application);
            }
            pending_local.retain(|_, local| {
                !assigned_applications.contains(&local.application_header.reference())
            });
        } else {
            for (round, (commitment, creation_time_ns, _, application)) in &persisted_local {
                if application.is_some() {
                    let _ = startup_events
                        .send(ShadowServiceEventV1::Rejected {
                            peer: None,
                            error: ShadowServiceErrorV1::RecoveredLocalHeaderMismatch(*round)
                                .to_string(),
                        })
                        .await;
                    return;
                }
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
                        error: ShadowServiceErrorV1::RecoveredLocalHeaderMismatch(round)
                            .to_string(),
                    })
                    .await;
                return;
            }
            pending_local.retain(|round, _| *round >= core.local_carrier_round());
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
        let recovered_application_headers = match core.delivered_application_headers() {
            Ok(headers) => headers,
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
        let reported_application_deliveries = recovered_application_headers
            .iter()
            .map(|(_, header)| header.reference())
            .collect();
        let mut authorized_applications = BTreeMap::new();
        for (carrier, header) in recovered_application_headers
            .into_iter()
            .rev()
            .take(shadow_application_payload_capacity(committee_size))
        {
            authorized_applications.insert(
                header.reference(),
                AuthorizedApplicationStateV1 {
                    carrier,
                    header,
                    authorization_basis: ShadowApplicationAuthorizationBasisV1::Delivered,
                    verified_payload: None,
                    observed_payload: None,
                    observed_payload_at: None,
                    holders: BTreeSet::new(),
                    request_last_attempt: BTreeMap::new(),
                    emitted_header: false,
                    emitted_observed_payload: false,
                },
            );
        }
        let reported_shadow_delivery_slots = reported_shadow_deliveries
            .iter()
            .map(delivery_slot)
            .collect();
        let comparison_backlog = ShadowComparisonBacklogV1::new(reported_shadow_delivery_slots);
        let sync_round = core.local_carrier_round();
        let consensus_pacemaker = ConsensusPacemakerV1::new(core.next_local_consensus_round());
        let state = ShadowServiceStateV1 {
            core,
            committee: actor_committee,
            mode,
            clock_active: false,
            clock_activation_tx,
            wal_sync_policy,
            metrics,
            own_authority,
            committee_size,
            events: event_tx,
            connected: BTreeSet::new(),
            catch_up_hint_high_water: BTreeMap::new(),
            far_future_hint_high_water: BTreeMap::new(),
            desired_topology: actor_desired_topology,
            desired_local_applications: actor_desired_local_applications,
            desired_carrier_sync_responses: actor_desired_carrier_sync_responses,
            desired_verified_application_payloads: actor_desired_verified_application_payloads,
            desired_direct_deliveries: actor_desired_direct_deliveries,
            desired_available_applications: actor_desired_available_applications,
            observed_topology: BTreeMap::new(),
            invalidated_by_overload: actor_invalidated_by_overload,
            pending_local,
            assigned_applications,
            pending_data_availability: BTreeSet::new(),
            pending_recovery: BTreeMap::new(),
            recovery_last_attempt: BTreeMap::new(),
            sync_last_attempt: BTreeMap::new(),
            sync_last_served: BTreeMap::new(),
            authorized_applications,
            quarantined_application_payloads: BTreeMap::new(),
            payload_last_served: BTreeMap::new(),
            sync_round,
            sync_round_opened_at: Instant::now(),
            sync_catch_up: false,
            sync_catch_up_limit_future: false,
            sync_catch_up_target: None,
            #[cfg(test)]
            sync_max_outstanding: 0,
            #[cfg(test)]
            sync_max_desired_responses: 0,
            awaiting_application_submission: false,
            application_submission_deadline: None,
            consensus_pacemaker,
            consensus_timeout,
            normal_carrier_min_spacing: mode
                .heartbeat_interval()
                .and_then(|interval| interval.checked_div(SHADOW_NORMAL_CARRIER_SPACING_DIVISOR_V1))
                .unwrap_or_default()
                .max(SHADOW_NORMAL_CARRIER_MIN_SPACING_V1),
            normal_carrier_next_allowed_at: None,
            normal_carrier_requested: false,
            normal_carrier_generation: 0,
            normal_carrier_deadline: None,
            normal_carrier_deadline_tx,
            consensus_timeout_generation: 0,
            consensus_timeout_deadline: None,
            consensus_timeout_deadline_tx,
            retry_notification_pending: actor_retry_notification_pending,
            heartbeat_notification_pending: actor_heartbeat_notification_pending,
            direct_deliveries: BTreeSet::new(),
            reported_shadow_deliveries,
            reported_application_deliveries,
            recovered_shadow_deliveries,
            comparison_backlog,
            reported_matches: BTreeSet::new(),
            reported_mismatches: BTreeSet::new(),
            reported_conflicts: BTreeSet::new(),
            fatal: false,
        };
        if let Err(error) = tokio::task::spawn_blocking(move || {
            run_shadow_service(state, message_rx, open_report, clock_starts_active);
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
            #[cfg(test)]
            input_capacity,
            mode,
            desired_topology,
            desired_local_applications,
            desired_carrier_sync_responses,
            desired_verified_application_payloads,
            desired_direct_deliveries,
            desired_available_applications,
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

#[derive(Clone, Debug)]
struct AuthorizedApplicationStateV1 {
    carrier: BlockReference,
    header: RbcCanonicalHeader,
    authorization_basis: ShadowApplicationAuthorizationBasisV1,
    verified_payload: Option<Arc<TransactionData>>,
    observed_payload: Option<Arc<TransactionData>>,
    observed_payload_at: Option<Instant>,
    holders: BTreeSet<AuthorityIndex>,
    request_last_attempt: BTreeMap<AuthorityIndex, Instant>,
    emitted_header: bool,
    emitted_observed_payload: bool,
}

#[derive(Clone, Debug)]
struct QuarantinedApplicationPayloadV1 {
    application: BlockReference,
    holder: AuthorityIndex,
    payload: Option<Arc<TransactionData>>,
}

/// Per-requester exact-slot replay limiter. A lagging honest peer may consume
/// a bounded set of distinct rounds faster than the healthy carrier clock,
/// independent of response/request ordering. Replays of a round already
/// served in the current interval and a seventeenth distinct round are
/// throttled.
#[derive(Clone, Debug)]
struct CarrierSyncServeWindowV1 {
    started_at: Instant,
    served_rounds: BTreeSet<RoundNumber>,
}

impl CarrierSyncServeWindowV1 {
    fn first(round: RoundNumber, now: Instant) -> Self {
        let mut served_rounds = BTreeSet::new();
        served_rounds.insert(round);
        Self {
            started_at: now,
            served_rounds,
        }
    }

    fn permits(&mut self, round: RoundNumber, now: Instant) -> bool {
        if now.saturating_duration_since(self.started_at) >= SHADOW_CARRIER_SYNC_RETRY_INTERVAL_V1 {
            self.started_at = now;
            self.served_rounds.clear();
        }
        if self.served_rounds.contains(&round)
            || self.served_rounds.len() >= SHADOW_CARRIER_SYNC_MAX_ADVANCING_BURST_V1
        {
            return false;
        }
        self.served_rounds.insert(round)
    }
}

fn carrier_sync_pipeline_depth(committee_size: usize) -> usize {
    let remote_authors = committee_size.saturating_sub(1);
    if remote_authors == 0 {
        return 0;
    }
    SHADOW_CARRIER_SYNC_MAX_ADVANCING_BURST_V1
        .min(SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1 / remote_authors)
}

/// Produce the bounded round-major repair window. `target == None` is the
/// healthy/moderate single-round path; a catch-up target opens only enough
/// consecutive rounds to keep all `n - 1` authors inside the global credit.
fn carrier_sync_pipeline_slots(
    current_round: RoundNumber,
    target: Option<RoundNumber>,
    committee_size: usize,
    connected: &BTreeSet<AuthorityIndex>,
) -> Vec<CarrierSyncSlotV1> {
    let depth = carrier_sync_pipeline_depth(committee_size);
    if depth == 0 {
        return Vec::new();
    }
    let depth_delta = RoundNumber::try_from(depth.saturating_sub(1)).unwrap_or(RoundNumber::MAX);
    let last_round = current_round
        .saturating_add(depth_delta)
        .min(target.unwrap_or(current_round));
    if last_round < current_round {
        return Vec::new();
    }
    (current_round..=last_round)
        .flat_map(|round| connected.iter().copied().map(move |author| (round, author)))
        .take(SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1)
        .collect()
}

struct ShadowServiceStateV1 {
    core: StarfishRbcDagShadowV1,
    committee: RbcDagCommitteeContextV1,
    mode: ShadowServiceModeV1,
    /// One-way coordinated-start latch for the autonomous protocol clock.
    /// Mirror mode never consults this flag.
    clock_active: bool,
    clock_activation_tx: watch::Sender<bool>,
    wal_sync_policy: ShadowWalSyncPolicyV1,
    metrics: Option<Arc<Metrics>>,
    own_authority: AuthorityIndex,
    committee_size: usize,
    events: mpsc::Sender<ShadowServiceEventV1>,
    connected: BTreeSet<AuthorityIndex>,
    /// Distinct transport-authenticated peers that exposed a carrier beyond
    /// the local admission/retention horizon. Validity stake is required
    /// before this performance-only hint can enable aggressive catch-up, so a
    /// Byzantine minority cannot force the node into repair mode.
    catch_up_hint_high_water: BTreeMap<AuthorityIndex, RoundNumber>,
    /// Subset of catch-up hints that were outside the authenticated 64-round
    /// retention horizon. Only validity stake in this set disables proactive
    /// future buffering; ordinary small skew keeps the useful retained tail.
    far_future_hint_high_water: BTreeMap<AuthorityIndex, RoundNumber>,
    desired_topology: Arc<Mutex<BTreeMap<AuthorityIndex, (bool, u64)>>>,
    desired_local_applications: Arc<Mutex<BTreeMap<RoundNumber, ShadowLocalCarrierV1>>>,
    desired_carrier_sync_responses:
        Arc<Mutex<BTreeMap<CarrierSyncSlotV1, DesiredCarrierSyncResponseV1>>>,
    desired_verified_application_payloads:
        Arc<Mutex<BTreeMap<BlockReference, Arc<TransactionData>>>>,
    desired_direct_deliveries: Arc<Mutex<BTreeSet<ShadowDeliveryIdentityV1>>>,
    desired_available_applications: Arc<Mutex<BTreeSet<BlockReference>>>,
    observed_topology: BTreeMap<AuthorityIndex, (bool, u64)>,
    invalidated_by_overload: Arc<Mutex<Option<&'static str>>>,
    pending_local: BTreeMap<RoundNumber, ShadowLocalCarrierV1>,
    assigned_applications: BTreeSet<BlockReference>,
    pending_data_availability: BTreeSet<BlockReference>,
    pending_recovery: BTreeMap<BlockReference, BTreeSet<AuthorityIndex>>,
    recovery_last_attempt: BTreeMap<(BlockReference, AuthorityIndex), Instant>,
    sync_last_attempt: BTreeMap<CarrierSyncSlotV1, Instant>,
    sync_last_served: BTreeMap<AuthorityIndex, CarrierSyncServeWindowV1>,
    authorized_applications: BTreeMap<BlockReference, AuthorizedApplicationStateV1>,
    quarantined_application_payloads: BTreeMap<BlockReference, QuarantinedApplicationPayloadV1>,
    payload_last_served: BTreeMap<AuthorityIndex, (BlockReference, Instant)>,
    sync_round: RoundNumber,
    sync_round_opened_at: Instant,
    sync_catch_up: bool,
    sync_catch_up_limit_future: bool,
    sync_catch_up_target: Option<RoundNumber>,
    #[cfg(test)]
    sync_max_outstanding: usize,
    #[cfg(test)]
    sync_max_desired_responses: usize,
    /// A successful application-carrier assignment just released the core's
    /// one-outstanding producer gate. Give that exact producer a bounded
    /// maintenance epoch to submit its successor before any normal phase or
    /// fallback work spends the next physical slot on a control carrier.
    /// Repair traffic remains independently bounded and may bypass this
    /// scheduling preference.
    awaiting_application_submission: bool,
    application_submission_deadline: Option<Instant>,
    consensus_pacemaker: ConsensusPacemakerV1,
    /// Logical C2 fallback deadline. This is independent of the physical
    /// heartbeat so experiments can vary consensus permission without
    /// changing proactive carrier push cadence.
    consensus_timeout: Duration,
    normal_carrier_min_spacing: Duration,
    normal_carrier_next_allowed_at: Option<Instant>,
    normal_carrier_requested: bool,
    normal_carrier_generation: u64,
    normal_carrier_deadline: Option<NormalCarrierDeadlineV1>,
    normal_carrier_deadline_tx: watch::Sender<Option<NormalCarrierDeadlineV1>>,
    consensus_timeout_generation: u64,
    consensus_timeout_deadline: Option<ConsensusTimeoutDeadlineV1>,
    consensus_timeout_deadline_tx: watch::Sender<Option<ConsensusTimeoutDeadlineV1>>,
    retry_notification_pending: Arc<AtomicBool>,
    heartbeat_notification_pending: Arc<AtomicBool>,
    direct_deliveries: BTreeSet<ShadowDeliveryIdentityV1>,
    reported_shadow_deliveries: BTreeSet<ShadowDeliveryIdentityV1>,
    reported_application_deliveries: BTreeSet<BlockReference>,
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

    fn activate_clock(&mut self) {
        if !self.mode.is_autonomous() || self.clock_active {
            return;
        }
        self.clock_active = true;
        let now = Instant::now();
        self.sync_round = self.core.local_carrier_round();
        self.sync_round_opened_at = now;
        self.cancel_consensus_timeout_deadline();
        self.consensus_pacemaker =
            ConsensusPacemakerV1::new(self.core.next_local_consensus_round());
        self.awaiting_application_submission = false;
        self.application_submission_deadline = None;
        self.heartbeat_notification_pending
            .store(false, Ordering::Release);

        // Queue the ordered activation observation before releasing the timer
        // task. Even if the event channel is temporarily full, no heartbeat
        // can be generated ahead of `ClockActivated`.
        self.emit(ShadowServiceEventV1::ClockActivated);
        self.clock_activation_tx.send_replace(true);
        self.emit_clock_state();
    }

    fn emit_recovered_authorized_applications(&mut self) {
        let applications = self
            .authorized_applications
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for application in applications {
            self.emit_authorized_application_if_new(application);
        }
    }

    fn emit_autonomous_recovery_and_ready(&mut self, open_report: &ShadowOpenReportV1) {
        self.emit_recovered_authorized_applications();
        for delta in open_report.recovered_committed_frontiers() {
            self.emit(ShadowServiceEventV1::FrontierCommitted(delta.clone()));
        }
        self.process_effects(open_report.recovery_effects().to_vec());
        self.emit(ShadowServiceEventV1::Ready {
            autonomous_clock: true,
        });
    }

    fn reject(&self, peer: Option<AuthorityIndex>, error: impl fmt::Display) {
        self.emit(ShadowServiceEventV1::Rejected {
            peer,
            error: error.to_string(),
        });
    }

    fn emit_comparison_backlog(&self) {
        if self.mode.is_autonomous() {
            return;
        }
        let (unpaired_direct, unpaired_shadow, max_round_lag) = self.comparison_backlog.counts();
        self.emit(ShadowServiceEventV1::ComparisonBacklog {
            unpaired_direct,
            unpaired_shadow,
            max_round_lag,
        });
    }

    fn emit_clock_state(&self) {
        if !self.mode.is_autonomous() {
            return;
        }
        self.record_pipeline_state();
        self.emit(ShadowServiceEventV1::ClockState {
            open_round: self.core.local_carrier_round(),
            phase_backlog: self.core.pending_phase_backlog_len(),
            admitted_authors: self.core.current_round_admitted_author_count(),
            admitted_stake: self.core.current_round_admitted_stake(),
            buffered_authenticated: self.core.buffered_authenticated_carrier_count(),
        });
    }

    fn record_pipeline_state(&self) {
        let Some(metrics) = &self.metrics else {
            return;
        };
        let projection = self.core.projection_runtime_snapshot();
        metrics.set_starfish_rbc_dag_pipeline_state(
            self.pending_local.len(),
            projection.pending_candidates,
            projection.highest_projected_round,
            projection.next_undecided_round,
            projection.next_undecided_projected_stake,
            projection.last_committed_round,
            projection.hol_reason.metric_label(),
        );
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

    fn decode_application_carrier(
        &self,
        canonical_carrier: &[u8],
    ) -> Result<Option<(BlockReference, RbcCanonicalHeader)>, ShadowErrorV1> {
        let candidate = CandidateCarrierV1::decode_wire_with_committee(
            canonical_carrier,
            &self.committee,
            None,
        )
        .map_err(ShadowErrorV1::Carrier)?;
        Ok(candidate
            .header()
            .application_header()
            .cloned()
            .map(|header| (candidate.reference(), header)))
    }

    fn make_application_state_room(&mut self, application: BlockReference) {
        let capacity = shadow_application_payload_capacity(self.committee_size);
        if self.authorized_applications.contains_key(&application)
            || self.authorized_applications.len() < capacity
        {
            return;
        }
        if let Some((evicted, _)) = self.authorized_applications.pop_first() {
            self.quarantined_application_payloads
                .retain(|_, retained| retained.application != evicted);
        }
    }

    fn emit_authorized_application_if_new(&mut self, application: BlockReference) {
        let event = self
            .authorized_applications
            .get_mut(&application)
            .and_then(|state| {
                let should_emit = !state.emitted_header
                    || (state.observed_payload.is_some() && !state.emitted_observed_payload);
                should_emit.then(|| {
                    state.emitted_header = true;
                    state.emitted_observed_payload |= state.observed_payload.is_some();
                    ShadowServiceEventV1::AuthorizedApplicationObserved {
                        carrier: state.carrier,
                        header: state.header.clone(),
                        payload: state
                            .observed_payload
                            .clone()
                            .or_else(|| state.verified_payload.clone()),
                        authorization_basis: state.authorization_basis,
                    }
                })
            });
        if let Some(event) = event {
            self.emit(event);
        }
    }

    fn authorize_application(
        &mut self,
        carrier: BlockReference,
        header: RbcCanonicalHeader,
        payload: Option<Arc<TransactionData>>,
        payload_is_verified: bool,
        holder: Option<AuthorityIndex>,
        authorization_basis: ShadowApplicationAuthorizationBasisV1,
    ) -> Result<(), ShadowServiceErrorV1> {
        let application = header.reference();
        self.make_application_state_room(application);
        let state = self
            .authorized_applications
            .entry(application)
            .or_insert_with(|| AuthorizedApplicationStateV1 {
                carrier,
                header: header.clone(),
                authorization_basis,
                verified_payload: None,
                observed_payload: None,
                observed_payload_at: None,
                holders: BTreeSet::new(),
                request_last_attempt: BTreeMap::new(),
                emitted_header: false,
                emitted_observed_payload: false,
            });
        if state.header != header {
            return Err(ShadowServiceErrorV1::ConflictingApplicationPayload(
                application,
            ));
        }
        if let Some(holder) = holder {
            state.holders.insert(holder);
        }
        if payload_is_verified {
            merge_application_payload(&mut state.verified_payload, payload, application)?;
        } else {
            let observed = payload.is_some();
            merge_application_payload(&mut state.observed_payload, payload, application)?;
            if observed {
                state.observed_payload_at = Some(Instant::now());
            }
        }
        self.emit_authorized_application_if_new(application);
        self.flush_application_payload_requests();
        Ok(())
    }

    fn quarantine_application(
        &mut self,
        carrier: BlockReference,
        application: BlockReference,
        holder: AuthorityIndex,
        payload: Option<Arc<TransactionData>>,
    ) -> Result<(), ShadowServiceErrorV1> {
        if !self.quarantined_application_payloads.contains_key(&carrier)
            && self.quarantined_application_payloads.len()
                >= shadow_application_payload_capacity(self.committee_size)
        {
            self.quarantined_application_payloads.pop_first();
        }
        let retained = self
            .quarantined_application_payloads
            .entry(carrier)
            .or_insert(QuarantinedApplicationPayloadV1 {
                application,
                holder,
                payload: None,
            });
        if retained.application != application {
            return Err(ShadowServiceErrorV1::ConflictingApplicationPayload(
                application,
            ));
        }
        merge_application_payload(&mut retained.payload, payload, application)
    }

    fn observe_carrier_application(
        &mut self,
        peer: AuthorityIndex,
        canonical_carrier: &[u8],
        payload: Option<Arc<TransactionData>>,
        disposition: ShadowIngressDispositionV1,
    ) -> Result<(), ShadowServiceErrorV1> {
        if disposition == ShadowIngressDispositionV1::IgnoredFutureOutsideBuffer {
            return Ok(());
        }
        let Some((carrier, header)) = self.decode_application_carrier(canonical_carrier)? else {
            return Ok(());
        };
        let application = header.reference();
        let (observed_payload, payload_error) = match payload {
            Some(payload) => match validate_application_payload_size(&payload) {
                Ok(()) => (Some(payload), None),
                Err(error) => (None, Some(error)),
            },
            None => (None, None),
        };
        match disposition {
            ShadowIngressDispositionV1::Authenticated => self.authorize_application(
                carrier,
                header,
                observed_payload,
                false,
                Some(peer),
                ShadowApplicationAuthorizationBasisV1::ReceiverAuthenticated,
            )?,
            ShadowIngressDispositionV1::CandidateRetained => {
                self.quarantine_application(carrier, application, peer, observed_payload)?
            }
            ShadowIngressDispositionV1::IgnoredDuplicateConflictOrStale => {
                if self
                    .authorized_applications
                    .get(&application)
                    .is_some_and(|state| state.carrier == carrier)
                {
                    self.authorize_application(
                        carrier,
                        header,
                        observed_payload,
                        false,
                        Some(peer),
                        ShadowApplicationAuthorizationBasisV1::ReceiverAuthenticated,
                    )?;
                } else if self.quarantined_application_payloads.contains_key(&carrier) {
                    self.quarantine_application(carrier, application, peer, observed_payload)?;
                }
            }
            ShadowIngressDispositionV1::IgnoredFutureOutsideBuffer => {}
        }
        if let Some(error) = payload_error {
            return Err(error);
        }
        Ok(())
    }

    fn authorize_delivered_application(
        &mut self,
        carrier: BlockReference,
        header: RbcCanonicalHeader,
    ) -> Result<(), ShadowServiceErrorV1> {
        let retained = self.quarantined_application_payloads.remove(&carrier);
        let holder = retained.as_ref().map(|retained| retained.holder);
        let payload = retained.and_then(|retained| retained.payload);
        self.authorize_application(
            carrier,
            header,
            payload,
            false,
            holder,
            ShadowApplicationAuthorizationBasisV1::Delivered,
        )
    }

    fn flush_application_payload_requests(&mut self) {
        let now = Instant::now();
        let connected = &self.connected;
        let mut requests = Vec::new();
        for (application, state) in &self.authorized_applications {
            // The default commitment is the canonical proof of an empty
            // application payload. DagState marks such a header available as
            // soon as it is materialized, so there are no payload bytes to
            // recover and no peer can produce a meaningful response.
            if state.header.transactions_commitment() == TransactionsCommitment::default()
                || state.verified_payload.is_some()
                || state.observed_payload_at.is_some_and(|observed| {
                    now.saturating_duration_since(observed)
                        < SHADOW_APPLICATION_PAYLOAD_RETRY_INTERVAL_V1
                })
                || state.request_last_attempt.values().any(|last| {
                    now.saturating_duration_since(*last)
                        < SHADOW_APPLICATION_PAYLOAD_RETRY_INTERVAL_V1
                })
            {
                continue;
            }
            let peer = state
                .holders
                .iter()
                .copied()
                .filter(|holder| connected.contains(holder))
                .chain(connected.iter().copied())
                .find(|holder| {
                    state.request_last_attempt.get(holder).is_none_or(|last| {
                        now.saturating_duration_since(*last)
                            >= SHADOW_APPLICATION_PAYLOAD_RETRY_INTERVAL_V1
                    })
                });
            if let Some(peer) = peer {
                requests.push((*application, peer));
            }
        }
        for (application, peer) in requests {
            let Some(state) = self.authorized_applications.get_mut(&application) else {
                continue;
            };
            state.observed_payload = None;
            state.observed_payload_at = None;
            state.emitted_observed_payload = false;
            state.request_last_attempt.clear();
            state.request_last_attempt.insert(peer, now);
            self.emit(ShadowServiceEventV1::Network {
                recipient: peer,
                message: NetworkMessage::RbcDagApplicationPayloadRequest(application),
            });
        }
    }

    fn handle_application_payload_request(
        &mut self,
        peer: AuthorityIndex,
        application: BlockReference,
    ) {
        let now = Instant::now();
        if self
            .payload_last_served
            .get(&peer)
            .is_some_and(|(_, last)| {
                now.saturating_duration_since(*last) < SHADOW_APPLICATION_PAYLOAD_RETRY_INTERVAL_V1
            })
        {
            self.emit(ShadowServiceEventV1::Input {
                kind: "application_payload_request",
                outcome: "rate_limited",
            });
            return;
        }
        let Some(payload) = self
            .authorized_applications
            .get(&application)
            .and_then(|state| state.verified_payload.clone())
        else {
            self.emit(ShadowServiceEventV1::Input {
                kind: "application_payload_request",
                outcome: "not_found",
            });
            return;
        };
        self.payload_last_served.insert(peer, (application, now));
        self.emit(ShadowServiceEventV1::Network {
            recipient: peer,
            message: NetworkMessage::RbcDagApplicationPayloadResponse(
                RbcDagApplicationPayloadResponse {
                    application,
                    transaction_data: payload,
                },
            ),
        });
    }

    fn handle_application_payload_response(
        &mut self,
        peer: AuthorityIndex,
        response: RbcDagApplicationPayloadResponse,
    ) -> Result<(), ShadowServiceErrorV1> {
        let application = response.application;
        let Some(state) = self.authorized_applications.get(&application) else {
            // Verification and network delivery run outside the actor. A
            // solicited response can therefore arrive after the bounded
            // application window evicted its state. Core either already saw
            // the payload or later recovery will reauthorize the header; the
            // delayed bytes must not invalidate an otherwise healthy run.
            self.emit(ShadowServiceEventV1::Input {
                kind: "application_payload_response",
                outcome: "stale_ignored",
            });
            return Ok(());
        };
        if state.verified_payload.is_some() {
            return Ok(());
        }
        if !state.request_last_attempt.contains_key(&peer) {
            return Err(
                ShadowServiceErrorV1::ApplicationPayloadResponseFromUnexpectedPeer {
                    peer,
                    application,
                },
            );
        }
        validate_application_payload_size(&response.transaction_data)?;
        let state = self
            .authorized_applications
            .get_mut(&application)
            .expect("authorized application cannot disappear during validation");
        let duplicate = application_payloads_equal(
            state.observed_payload.as_deref(),
            Some(response.transaction_data.as_ref()),
        );
        merge_application_payload(
            &mut state.observed_payload,
            Some(response.transaction_data),
            application,
        )?;
        state.observed_payload_at = Some(Instant::now());
        if !duplicate {
            state.emitted_observed_payload = false;
        }
        self.emit_authorized_application_if_new(application);
        Ok(())
    }

    fn handle_verified_application_payload(
        &mut self,
        application: BlockReference,
        payload: Arc<TransactionData>,
    ) -> Result<(), ShadowServiceErrorV1> {
        let Some(state) = self.authorized_applications.get_mut(&application) else {
            // Core verification/materialization is deliberately offloaded
            // from this actor. Its completion may therefore trail the bounded
            // authorized-application retention window. The payload already
            // reached Core; it must not turn normal bounded eviction into a
            // protocol rejection or invalidate the benchmark.
            self.emit(ShadowServiceEventV1::Input {
                kind: "verified_application_payload",
                outcome: "stale_ignored",
            });
            return Ok(());
        };
        merge_application_payload(&mut state.verified_payload, Some(payload), application)?;
        state.observed_payload = None;
        state.observed_payload_at = None;
        state.request_last_attempt.clear();
        self.emit(ShadowServiceEventV1::Input {
            kind: "verified_application_payload",
            outcome: "cached",
        });
        Ok(())
    }

    fn reconcile_local_applications(&mut self) {
        let desired = std::mem::take(&mut *self.desired_local_applications.lock());
        if !desired.is_empty() {
            self.awaiting_application_submission = false;
            self.application_submission_deadline = None;
        }
        for local in desired.into_values() {
            self.enqueue_local(local);
        }
    }

    fn reconcile_verified_application_payloads(&mut self) {
        let desired = std::mem::take(&mut *self.desired_verified_application_payloads.lock());
        for (application, payload) in desired {
            if let Err(error) = self.handle_verified_application_payload(application, payload) {
                self.reject(None, error);
            }
        }
    }

    fn validity_backed_high_water(
        &self,
        hints: &BTreeMap<AuthorityIndex, RoundNumber>,
    ) -> Option<RoundNumber> {
        let mut candidate_rounds = hints.values().copied().collect::<Vec<_>>();
        candidate_rounds.sort_unstable();
        candidate_rounds.dedup();
        candidate_rounds.into_iter().rev().find(|round| {
            let stake = hints
                .iter()
                .filter(|(_, high_water)| **high_water >= *round)
                .filter_map(|(authority, _)| self.committee.committee().get_stake(*authority))
                .fold(0, u64::saturating_add);
            self.committee.committee().is_valid(stake)
        })
    }

    fn observe_catch_up_hint(
        &mut self,
        peer: AuthorityIndex,
        round: RoundNumber,
        outside_retention: bool,
    ) {
        if !self.mode.is_autonomous() {
            return;
        }
        self.catch_up_hint_high_water
            .entry(peer)
            .and_modify(|high_water| *high_water = (*high_water).max(round))
            .or_insert(round);
        if outside_retention {
            self.far_future_hint_high_water
                .entry(peer)
                .and_modify(|high_water| *high_water = (*high_water).max(round))
                .or_insert(round);
        }
        let high_water = self.validity_backed_high_water(&self.catch_up_hint_high_water);
        let far_high_water = self.validity_backed_high_water(&self.far_future_hint_high_water);
        // Ordinary authenticated lookahead inside the 64-round retention
        // window is the healthy proactive pipeline, not evidence that exact
        // catch-up is needed. Starting a 64-slot repair episode for those
        // observations made healthy nodes continuously request data they had
        // already buffered. Activate pipelined catch-up only after validity
        // stake reports a round outside normal retention.
        let activated = !self.sync_catch_up && far_high_water.is_some();
        let limited = !self.sync_catch_up_limit_future && far_high_water.is_some();
        if far_high_water.is_some() {
            let high_water = high_water.expect("far-future hints are also catch-up hints");
            self.sync_catch_up_target = Some(
                self.sync_catch_up_target
                    .map_or(high_water, |target| target.max(high_water)),
            );
            self.sync_catch_up = true;
        }
        if activated {
            self.emit(ShadowServiceEventV1::Input {
                kind: "carrier_sync_catch_up",
                outcome: "validity_outside_retention_hints",
            });
        }
        if limited {
            self.sync_catch_up = true;
            self.sync_catch_up_limit_future = true;
        }
    }

    fn observe_ingress_catch_up_hint(
        &mut self,
        peer: AuthorityIndex,
        canonical_carrier: &[u8],
        disposition: ShadowIngressDispositionV1,
        open_round_before: RoundNumber,
    ) {
        let Ok((_, hint_round, _)) = self.core.candidate_slot(canonical_carrier) else {
            return;
        };
        // Count deltas are not a sound lookahead signal: the same ingress can
        // advance the clock, promote older buffered slots, and leave the total
        // flat. Classify against the pre-ingress open round instead.
        let authenticated_future = disposition == ShadowIngressDispositionV1::Authenticated
            && hint_round > open_round_before.saturating_add(EXECUTABLE_MODEL_ADMISSION_WINDOW_V1);
        let future_ignored = disposition == ShadowIngressDispositionV1::IgnoredFutureOutsideBuffer;
        if !future_ignored && !authenticated_future {
            return;
        }
        self.observe_catch_up_hint(
            peer,
            hint_round,
            hint_round > open_round_before.saturating_add(EXECUTABLE_MODEL_BUFFER_WINDOW_V1),
        );
    }

    /// Highest physical carrier round reported by validity stake while still
    /// retained by the normal future window. A carrier at round `target`
    /// proves that a live producer may already have opened `target + 1`, so
    /// local catch-up is complete only after our open round passes it.
    fn retained_future_target(&self) -> Option<RoundNumber> {
        if !self.mode.is_autonomous() || self.sync_catch_up {
            return None;
        }
        let target = self.validity_backed_high_water(&self.catch_up_hint_high_water)?;
        (self.core.local_carrier_round() <= target).then_some(target)
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
            self.sync_last_attempt
                .retain(|(_, author), _| author != peer);
            self.sync_last_served
                .retain(|requester, _| requester != peer);
            self.payload_last_served.remove(peer);
            for application in self.authorized_applications.values_mut() {
                application.request_last_attempt.remove(peer);
            }
            if state.0 {
                self.connected.insert(*peer);
                newly_connected.push(*peer);
            } else {
                self.connected.remove(peer);
                self.catch_up_hint_high_water.remove(peer);
                self.far_future_hint_high_water.remove(peer);
            }
        }
        self.observed_topology = desired;
        if !newly_connected.is_empty() {
            if self.mode.is_autonomous() {
                // Autonomous history is synchronized one exact slot at a
                // time. Replaying the entire retained run on every reconnect
                // would create an unbounded burst as heartbeats accumulate.
                // The first physical carrier may have been fixed before the
                // network connection existed, so round one needs the same
                // immediate exact-slot repair as every later reconnect.
                self.flush_carrier_sync_requests(true);
            } else {
                let retransmissions = self.core.retransmissions();
                for peer in newly_connected {
                    for envelope in &retransmissions {
                        self.send_envelope(peer, envelope);
                    }
                }
            }
            self.flush_recovery_requests();
            self.flush_application_payload_requests();
        }
    }

    fn reconcile_direct_deliveries(&mut self) {
        if self.mode.is_autonomous() {
            return;
        }
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
        self.broadcast_with_application_payload(envelope, None);
    }

    fn broadcast_with_application_payload(
        &self,
        envelope: &ShadowOutboundEnvelopeV1,
        application_payload: Option<Arc<TransactionData>>,
    ) {
        for recipient in 0..self.committee_size {
            let recipient = recipient as AuthorityIndex;
            if recipient != self.own_authority {
                self.send_envelope_with_application_payload(
                    recipient,
                    envelope,
                    application_payload.clone(),
                );
            }
        }
    }

    fn send_envelope(&self, recipient: AuthorityIndex, envelope: &ShadowOutboundEnvelopeV1) {
        self.send_envelope_with_application_payload(recipient, envelope, None);
    }

    fn send_envelope_with_application_payload(
        &self,
        recipient: AuthorityIndex,
        envelope: &ShadowOutboundEnvelopeV1,
        application_payload: Option<Arc<TransactionData>>,
    ) {
        self.emit(ShadowServiceEventV1::Network {
            recipient,
            message: NetworkMessage::RbcDagShadowCarrier(RbcDagShadowCarrier {
                canonical_carrier: envelope.canonical_carrier_wire().to_vec(),
                authentication_sidecar: envelope.authentication_sidecar().to_vec(),
                application_payload,
            }),
        });
    }

    fn report_wal_delta(&self, before: (u64, u64)) {
        let after = self.core.wal_counts();
        let batches = after.0.saturating_sub(before.0);
        let records = after.1.saturating_sub(before.1);
        if batches != 0 || records != 0 {
            self.emit(ShadowServiceEventV1::WalAppended {
                batches,
                records,
                durable: self.wal_sync_policy == ShadowWalSyncPolicyV1::EveryBatch,
            });
        }
    }

    fn process_effects(&mut self, effects: Vec<ModelEffect>) {
        let newly_delivered = effects
            .iter()
            .filter_map(|effect| match effect {
                ModelEffect::Delivered(reference) | ModelEffect::DeliveryPromised(reference) => {
                    Some(*reference)
                }
                ModelEffect::NeedCarrier { .. }
                | ModelEffect::PrefixAdvanced { .. }
                | ModelEffect::CarrierRoundAdvanced(_) => None,
            })
            .collect::<Vec<_>>();
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
                ModelEffect::Delivered(reference) | ModelEffect::DeliveryPromised(reference) => {
                    self.pending_recovery.remove(&reference);
                }
                ModelEffect::PrefixAdvanced { .. } => {}
                ModelEffect::CarrierRoundAdvanced(_) => {}
            }
        }
        self.reconcile_pending_recovery();
        self.flush_recovery_requests();
        self.emit(ShadowServiceEventV1::PendingRecovery(
            self.pending_recovery.len(),
        ));
        self.reconcile_data_availability();
        self.report_new_shadow_deliveries(&newly_delivered);
        self.report_projection_progress();
        self.flush_carrier_sync_requests(false);
        self.refresh_consensus_pacemaker();
        self.emit_clock_state();
    }

    fn reconcile_data_availability(&mut self) {
        if !self.mode.is_autonomous() {
            return;
        }
        let incoming = std::mem::take(&mut *self.desired_available_applications.lock());
        self.pending_data_availability.extend(incoming);
        let pending = self
            .pending_data_availability
            .iter()
            .copied()
            .collect::<Vec<_>>();
        for application in pending {
            let carriers = self.core.application_carriers(application);
            if carriers.is_empty() {
                continue;
            }
            for carrier in &carriers {
                if self.core.carrier_data_available(*carrier) {
                    continue;
                }
                let before = self.core.wal_counts();
                match self.core.mark_carrier_data_available(*carrier) {
                    Ok(effects) => {
                        self.report_wal_delta(before);
                        self.process_effects(effects);
                    }
                    Err(error) => {
                        self.mark_fatal(error);
                        return;
                    }
                }
            }
            if carriers
                .iter()
                .all(|carrier| self.core.carrier_data_available(*carrier))
            {
                self.pending_data_availability.remove(&application);
            }
        }
    }

    fn report_projection_progress(&mut self) {
        for projected in self.core.drain_projected_vertices() {
            self.emit(ShadowServiceEventV1::VertexProjected(projected));
        }
        for decision in self.core.drain_projection_decisions() {
            self.emit(ShadowServiceEventV1::LeaderDecided(decision));
        }
        for delta in self.core.drain_committed_frontiers() {
            if let Some(metrics) = &self.metrics {
                let (total_ns, samples, max_ns) = latency_since_header_creation(
                    delta.applications.iter(),
                    current_timestamp_ns(),
                );
                metrics.observe_starfish_rbc_dag_pipeline_latency_ns(
                    RBC_DAG_LATENCY_CREATION_TO_FRONTIER_GENERATED,
                    total_ns,
                    samples,
                    max_ns,
                );
                metrics.starfish_rbc_dag_frontier_generated();
            }
            self.emit(ShadowServiceEventV1::FrontierCommitted(delta));
        }
    }

    fn refresh_consensus_pacemaker(&mut self) {
        let _ = self.consensus_fallback_allowed_at(Instant::now());
    }

    fn consensus_fallback_allowed_at(&mut self, now: Instant) -> bool {
        if !self.clock_active {
            return false;
        }
        if !self.mode.is_autonomous() {
            return false;
        }
        let leader_timeout = self.consensus_timeout;
        let slot = self.core.next_local_consensus_round();
        let a1_ready = slot == 1
            || self
                .core
                .has_projected_consensus_quorum(slot.saturating_sub(1));
        let c3_ready = self.core.has_projected_consensus_quorum(slot);
        if self.consensus_pacemaker.slot != slot {
            self.cancel_consensus_timeout_deadline();
        }
        let fallback_allowed = self.consensus_pacemaker.fallback_allowed(
            slot,
            a1_ready,
            c3_ready,
            leader_timeout,
            now,
        );
        if fallback_allowed {
            // C3 or an elapsed C2 already authorizes this exact slot. The
            // normal-carrier permit may defer creation, but it will re-check
            // the same monotonic evidence and does not need another timeout.
            self.cancel_consensus_timeout_deadline();
        } else if let Some(armed_at) = self.consensus_pacemaker.c2_armed_at {
            let deadline = armed_at.checked_add(leader_timeout).unwrap_or(now);
            self.schedule_consensus_timeout_deadline(slot, deadline);
        } else {
            self.cancel_consensus_timeout_deadline();
        }
        fallback_allowed
    }

    fn cancel_consensus_timeout_deadline(&mut self) {
        if self.consensus_timeout_deadline.take().is_some() {
            self.consensus_timeout_generation = self.consensus_timeout_generation.wrapping_add(1);
            self.consensus_timeout_deadline_tx.send_replace(None);
        }
    }

    fn schedule_consensus_timeout_deadline(&mut self, slot: RoundNumber, deadline: Instant) {
        if self
            .consensus_timeout_deadline
            .is_some_and(|scheduled| scheduled.slot == slot && scheduled.deadline == deadline)
        {
            return;
        }
        self.consensus_timeout_generation = self.consensus_timeout_generation.wrapping_add(1);
        let scheduled = ConsensusTimeoutDeadlineV1 {
            generation: self.consensus_timeout_generation,
            slot,
            deadline,
        };
        self.consensus_timeout_deadline = Some(scheduled);
        self.consensus_timeout_deadline_tx
            .send_replace(Some(scheduled));
    }

    fn observe_consensus_timeout_deadline(&mut self, generation: u64, slot: RoundNumber) {
        let Some(scheduled) = self.consensus_timeout_deadline else {
            return;
        };
        if scheduled.generation != generation || scheduled.slot != slot {
            return;
        }
        if Instant::now() < scheduled.deadline {
            // Fail closed if an internal wake is ever observed early. Notify
            // the persistent task so it continues waiting for the exact
            // actor-owned deadline.
            self.consensus_timeout_deadline_tx
                .send_replace(Some(scheduled));
            return;
        }
        self.consensus_timeout_deadline = None;
        self.consensus_timeout_deadline_tx.send_replace(None);
        if self.core.next_local_consensus_round() != slot
            || !self.consensus_pacemaker.observe_timeout(slot)
        {
            return;
        }
        self.awaiting_application_submission = false;
        self.application_submission_deadline = None;
    }

    fn cancel_normal_carrier_deadline(&mut self) {
        if self.normal_carrier_deadline.take().is_some() {
            self.normal_carrier_generation = self.normal_carrier_generation.wrapping_add(1);
            self.normal_carrier_deadline_tx.send_replace(None);
        }
    }

    fn record_carrier_created(&mut self, now: Instant) {
        self.normal_carrier_requested = false;
        self.cancel_normal_carrier_deadline();
        self.normal_carrier_next_allowed_at = Some(
            now.checked_add(self.normal_carrier_min_spacing)
                .unwrap_or(now),
        );
    }

    fn schedule_normal_carrier_deadline(&mut self, deadline: Instant) {
        self.normal_carrier_requested = true;
        if self
            .normal_carrier_deadline
            .is_some_and(|scheduled| scheduled.deadline == deadline)
        {
            return;
        }
        self.normal_carrier_generation = self.normal_carrier_generation.wrapping_add(1);
        let scheduled = NormalCarrierDeadlineV1 {
            generation: self.normal_carrier_generation,
            deadline,
        };
        self.normal_carrier_deadline = Some(scheduled);
        self.normal_carrier_deadline_tx
            .send_replace(Some(scheduled));
    }

    /// Request one normally paced carrier. All application, phase, heartbeat,
    /// and C1/C2/C3 creation paths share this permit. Only validity-backed
    /// exact/retained repair may call the unpaced primitive directly.
    fn try_create_autonomous_carrier(&mut self) {
        if !self.mode.is_autonomous() || !self.clock_active {
            self.emit_clock_state();
            return;
        }
        let now = Instant::now();
        if let Some(deadline) = self.normal_carrier_next_allowed_at {
            if now < deadline {
                self.schedule_normal_carrier_deadline(deadline);
                return;
            }
        }
        self.normal_carrier_requested = false;
        self.cancel_normal_carrier_deadline();
        let _ = self.try_create_autonomous_carrier_now();
    }

    fn observe_normal_carrier_deadline(&mut self, generation: u64) {
        let Some(scheduled) = self.normal_carrier_deadline else {
            return;
        };
        if scheduled.generation != generation {
            return;
        }
        self.normal_carrier_deadline = None;
        self.normal_carrier_deadline_tx.send_replace(None);
        if self.normal_carrier_requested {
            self.try_create_autonomous_carrier();
        }
    }

    /// C2 and C3 are creation triggers, not merely permission for the next
    /// fixed heartbeat. Attempt at most one carrier outside `process_effects`
    /// so reducing a locally created carrier cannot recurse into creation.
    fn drive_consensus_fallback(&mut self) {
        if !self.clock_active {
            return;
        }
        let fallback_allowed = self.consensus_fallback_allowed_at(Instant::now());
        if !fallback_allowed
            || !self.mode.is_autonomous()
            || !self.core.can_create_carrier()
            || (self.awaiting_application_submission && self.pending_local.is_empty())
            || self.fatal
        {
            return;
        }
        self.try_create_autonomous_carrier();
    }

    fn try_create_autonomous_carrier_now(&mut self) -> bool {
        if !self.mode.is_autonomous() || !self.clock_active {
            self.emit_clock_state();
            return false;
        }
        let allow_no_vote = self.consensus_fallback_allowed_at(Instant::now());
        if !self.core.can_create_carrier() {
            self.emit_clock_state();
            return false;
        }
        let creation_time_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .try_into()
            .unwrap_or(TimestampNs::MAX);
        let before = self.core.wal_counts();
        let consensus_slot = self.core.next_local_consensus_round();
        let c1_ready = self.core.local_consensus_vertex_c1_ready();
        let c3_ready = self.core.has_projected_consensus_quorum(consensus_slot);
        let application_round = self.pending_local.keys().next().copied();
        let application = application_round.and_then(|round| self.pending_local.remove(&round));
        let result = match &application {
            Some(application) => self.core.create_local_application_carrier(
                application.application_header.clone(),
                creation_time_ns,
                allow_no_vote,
            ),
            None => self
                .core
                .create_local_control_heartbeat(creation_time_ns, allow_no_vote),
        };
        match result {
            Ok((envelope, effects)) => {
                let fixed_consensus_vertex =
                    self.core.next_local_consensus_round() > consensus_slot;
                self.record_carrier_created(Instant::now());
                let initial_application_payload = application
                    .as_ref()
                    .and_then(|application| application.application_payload.clone());
                let assigned_application = application
                    .as_ref()
                    .filter(|application| application.acknowledge_assignment)
                    .map(|application| application.application_header.reference());
                if let Some(application) = &application {
                    if let Some(metrics) = &self.metrics {
                        let latency_ns =
                            creation_time_ns.saturating_sub(application.creation_time_ns);
                        metrics.observe_starfish_rbc_dag_pipeline_latency_ns(
                            RBC_DAG_LATENCY_CREATION_TO_ASSIGNMENT,
                            latency_ns,
                            1,
                            latency_ns,
                        );
                    }
                    self.assigned_applications
                        .insert(application.application_header.reference());
                }
                // The application left the pending queue atomically with the
                // successful carrier transition. Publish that state before
                // releasing the producer gate or fan-out so observers cannot
                // retain a stale nonzero current-depth gauge.
                self.record_pipeline_state();
                self.emit(ShadowServiceEventV1::Input {
                    kind: if application_round.is_some() {
                        "application_carrier"
                    } else {
                        "heartbeat"
                    },
                    outcome: "accepted",
                });
                let consensus_vertex_outcome = if !fixed_consensus_vertex {
                    "omitted"
                } else if consensus_slot == 1 {
                    "bootstrap"
                } else if c1_ready {
                    "c1"
                } else if c3_ready {
                    "c3"
                } else if allow_no_vote {
                    "c2"
                } else {
                    "unexpected"
                };
                self.emit(ShadowServiceEventV1::Input {
                    kind: "consensus_vertex",
                    outcome: consensus_vertex_outcome,
                });
                // Keep the existing aggregate stable while exposing whether
                // an available logical vertex was fixed on an application
                // carrier or spent on a control/phase carrier. This is an
                // event-local benchmark diagnostic and does not affect the
                // carrier, journal, or consensus bytes.
                self.emit(ShadowServiceEventV1::Input {
                    kind: if application_round.is_some() {
                        "application_consensus_vertex"
                    } else {
                        "control_consensus_vertex"
                    },
                    outcome: consensus_vertex_outcome,
                });
                self.report_wal_delta(before);
                if let Some(reference) = assigned_application {
                    self.awaiting_application_submission = true;
                    self.application_submission_deadline = Instant::now()
                        .checked_add(shadow_application_submission_grace(self.committee_size));
                    self.emit(ShadowServiceEventV1::ApplicationAssigned(reference));
                }
                if let Some(application) = application {
                    if let Err(error) = self.authorize_application(
                        envelope.reference(),
                        application.application_header,
                        application.application_payload,
                        true,
                        None,
                        ShadowApplicationAuthorizationBasisV1::LocallyFixed,
                    ) {
                        self.reject(None, error);
                    }
                }
                self.broadcast_with_application_payload(&envelope, initial_application_payload);
                self.process_effects(effects);
                true
            }
            Err(ShadowErrorV1::Model(ModelError::LocalRoundNotOpen(_))) => {
                if let Some(application) = application {
                    self.pending_local.insert(application.round, application);
                }
                // The local slot is open syntactically but cannot yet name a
                // quorum of exact previous-round admitted parents. A later
                // authenticated ingress or timer tick retries it.
                self.emit(ShadowServiceEventV1::Input {
                    kind: "heartbeat",
                    outcome: "waiting_for_quorum",
                });
                self.emit_clock_state();
                false
            }
            Err(error) => {
                if let Some(application) = application {
                    self.pending_local.insert(application.round, application);
                }
                self.mark_fatal(error);
                false
            }
        }
    }

    /// While repairing a lagging clock, fix our next control carrier as soon
    /// as its exact previous-round quorum is available. Waiting for the
    /// normal heartbeat interval would cap catch-up at the production rate,
    /// so a node behind a continuously advancing committee could never close
    /// the gap. Healthy rounds still remain paced exclusively by the timer.
    fn drive_autonomous_catch_up(&mut self) {
        if !self.clock_active {
            return;
        }
        for _ in 0..carrier_sync_pipeline_depth(self.committee_size) {
            if !self.sync_catch_up || !self.core.can_create_carrier() || self.fatal {
                break;
            }
            let round_before = self.core.local_carrier_round();
            let _ = self.try_create_autonomous_carrier_now();
            if self.core.local_carrier_round() == round_before {
                break;
            }
        }
    }

    /// Drain a validity-backed in-window tail without opening an exact repair
    /// episode. Every iteration independently requires the exact predecessor
    /// quorum and advances at most one physical round. Bound one actor turn so
    /// its carrier fan-out remains within the same 64-message credit as exact
    /// synchronization (`depth * (n - 1) <= 64`).
    fn drive_retained_future_catch_up(&mut self) {
        if !self.clock_active || self.fatal {
            return;
        }
        let Some(target) = self.retained_future_target() else {
            return;
        };
        for _ in 0..carrier_sync_pipeline_depth(self.committee_size) {
            if self.core.local_carrier_round() > target || !self.core.local_parent_quorum_ready() {
                break;
            }
            let round_before = self.core.local_carrier_round();
            let _ = self.try_create_autonomous_carrier_now();
            if self.core.local_carrier_round() == round_before {
                break;
            }
        }
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
        if let Some(payload) = &local.application_payload {
            if let Err(error) = validate_application_payload_size(payload) {
                self.reject(None, error);
                return;
            }
        }
        if self.mode.is_autonomous() {
            let application_reference = local.application_header.reference();
            if self.assigned_applications.contains(&application_reference) {
                self.emit(ShadowServiceEventV1::Input {
                    kind: "application",
                    outcome: "already_assigned",
                });
                return;
            }
            if let Some(existing) = self.pending_local.get_mut(&local.round) {
                if existing.same_application(&local) {
                    let result = merge_application_payload(
                        &mut existing.application_payload,
                        local.application_payload,
                        application_reference,
                    );
                    existing.acknowledge_assignment |= local.acknowledge_assignment;
                    if let Err(error) = result {
                        self.reject(None, error);
                        return;
                    }
                    self.emit(ShadowServiceEventV1::Input {
                        kind: "application",
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
            self.pending_local.insert(local.round, local);
            self.emit(ShadowServiceEventV1::Input {
                kind: "application",
                outcome: "queued",
            });
            // Capture queue occupancy before an immediately available carrier
            // slot drains it; the current gauge will return to zero while the
            // high-water mark preserves short head-of-line bursts.
            self.record_pipeline_state();
            self.retry_pending_local();
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
        if let Some(existing) = self.pending_local.get_mut(&local.round) {
            if existing.same_application(&local) {
                let result = merge_application_payload(
                    &mut existing.application_payload,
                    local.application_payload,
                    existing.application_header.reference(),
                );
                existing.acknowledge_assignment |= local.acknowledge_assignment;
                if let Err(error) = result {
                    self.reject(None, error);
                    return;
                }
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
        if self.mode.is_autonomous() {
            // The producer is released only after its previous application
            // carrier is durably fixed. Phase effects from that transition
            // are processed synchronously and would otherwise consume the
            // newly opened physical slot before the producer's successor can
            // cross the ordered Core bridge. Piggyback those phases on the
            // successor when it arrives. A deadline anchored at assignment
            // retries the phase carrier after 100 ms, so a stalled producer
            // cannot stop physical RBC progress.
            if self.awaiting_application_submission && self.pending_local.is_empty() {
                let now = Instant::now();
                if let Some(deadline) = self.application_submission_deadline {
                    if now < deadline {
                        self.schedule_normal_carrier_deadline(deadline);
                        return;
                    }
                }
                self.awaiting_application_submission = false;
                self.application_submission_deadline = None;
            }
            while (!self.pending_local.is_empty() || self.core.has_pending_application_phase_work())
                && self.core.can_create_carrier()
                && !self.fatal
            {
                let round_before = self.core.local_carrier_round();
                self.try_create_autonomous_carrier();
                if self.core.local_carrier_round() == round_before {
                    break;
                }
            }
            return;
        }
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
        if self.mode.is_autonomous() && !self.clock_active {
            return;
        }
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

    fn flush_carrier_sync_requests(&mut self, force: bool) {
        if !self.mode.is_autonomous() || !self.clock_active {
            return;
        }
        let round = self.core.local_carrier_round();
        let now = Instant::now();
        if round != self.sync_round {
            self.sync_round = round;
            self.sync_round_opened_at = now;
        }
        self.sync_last_attempt.retain(|(attempt_round, author), _| {
            *attempt_round >= round
                && self.connected.contains(author)
                && self
                    .core
                    .authenticated_reference(*author, *attempt_round)
                    .is_none()
        });
        // A complete retained predecessor quorum can advance locally without
        // network repair. In particular, suppress an already-expired ordinary
        // grace timer while the current actor turn is about to drain that
        // tail. A missing quorum still falls through to exact current-slot
        // repair after the normal grace interval.
        if !force
            && self.retained_future_target().is_some()
            && self.core.local_parent_quorum_ready()
        {
            return;
        }
        if !force
            && !self.sync_catch_up
            && now.saturating_duration_since(self.sync_round_opened_at)
                < self.mode.carrier_sync_grace_interval()
        {
            return;
        }
        let target = self
            .sync_catch_up
            .then_some(self.sync_catch_up_target)
            .flatten();
        let candidates =
            carrier_sync_pipeline_slots(round, target, self.committee_size, &self.connected);
        for (request_round, author) in candidates {
            if self
                .core
                .authenticated_reference(author, request_round)
                .is_some()
            {
                continue;
            }
            let slot = (request_round, author);
            let should_send = match self.sync_last_attempt.get(&slot) {
                Some(last) => {
                    now.saturating_duration_since(*last) >= SHADOW_CARRIER_SYNC_RETRY_INTERVAL_V1
                }
                None => self.sync_last_attempt.len() < SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1,
            };
            if !should_send {
                continue;
            }
            self.sync_last_attempt.insert(slot, now);
            #[cfg(test)]
            {
                self.sync_max_outstanding =
                    self.sync_max_outstanding.max(self.sync_last_attempt.len());
            }
            self.emit(ShadowServiceEventV1::Network {
                recipient: author,
                message: NetworkMessage::RbcDagShadowCarrierSyncRequest(
                    RbcDagShadowCarrierSyncRequest {
                        author,
                        round: request_round,
                    },
                ),
            });
            self.emit(ShadowServiceEventV1::Input {
                kind: "carrier_sync_request",
                outcome: "sent",
            });
        }
        self.finish_catch_up_if_drained();
    }

    fn finish_catch_up_if_drained(&mut self) {
        if !self.sync_catch_up {
            return;
        }
        let Some(target) = self.sync_catch_up_target else {
            return;
        };
        if self.core.local_carrier_round() < target
            || !self.sync_last_attempt.is_empty()
            || !self.desired_carrier_sync_responses.lock().is_empty()
        {
            return;
        }
        self.sync_catch_up = false;
        self.sync_catch_up_limit_future = false;
        self.sync_catch_up_target = None;
        self.catch_up_hint_high_water.clear();
        self.far_future_hint_high_water.clear();
        self.emit(ShadowServiceEventV1::Input {
            kind: "carrier_sync_catch_up",
            outcome: "target_reached",
        });
    }

    fn handle_carrier_sync_request(
        &mut self,
        peer: AuthorityIndex,
        request: RbcDagShadowCarrierSyncRequest,
    ) {
        if !self.clock_active {
            self.emit(ShadowServiceEventV1::Input {
                kind: "carrier_sync_request",
                outcome: "paused",
            });
            return;
        }
        if request.author != self.own_authority {
            self.reject(
                Some(peer),
                ShadowServiceErrorV1::SyncRequestForForeignAuthor {
                    expected: self.own_authority,
                    actual: request.author,
                },
            );
            return;
        }
        if request.round > self.core.local_carrier_round() {
            self.emit(ShadowServiceEventV1::Input {
                kind: "carrier_sync_request",
                outcome: "future_not_found",
            });
            return;
        }
        let now = Instant::now();
        let permitted = match self.sync_last_served.get_mut(&peer) {
            Some(window) => window.permits(request.round, now),
            None => {
                self.sync_last_served
                    .insert(peer, CarrierSyncServeWindowV1::first(request.round, now));
                true
            }
        };
        if !permitted {
            self.emit(ShadowServiceEventV1::Input {
                kind: "carrier_sync_request",
                outcome: "rate_limited",
            });
            return;
        }
        let Some(envelope) = self.core.local_outbound_envelope(request.round) else {
            self.emit(ShadowServiceEventV1::Input {
                kind: "carrier_sync_request",
                outcome: "not_found",
            });
            return;
        };
        self.emit(ShadowServiceEventV1::Network {
            recipient: peer,
            message: NetworkMessage::RbcDagShadowCarrierSyncResponse(
                RbcDagShadowCarrierSyncResponse {
                    author: request.author,
                    round: request.round,
                    canonical_carrier: envelope.canonical_carrier_wire().to_vec(),
                    authentication_sidecar: envelope.authentication_sidecar().to_vec(),
                },
            ),
        });
        self.emit(ShadowServiceEventV1::Input {
            kind: "carrier_sync_request",
            outcome: "served",
        });
    }

    fn handle_carrier_sync_response(
        &mut self,
        peer: AuthorityIndex,
        response: RbcDagShadowCarrierSyncResponse,
    ) {
        let expected = (response.round, response.author);
        if peer != response.author {
            self.reject(
                Some(peer),
                ShadowServiceErrorV1::UnexpectedSyncResponse {
                    author: response.author,
                    round: response.round,
                },
            );
            return;
        }
        let (actual_author, actual_round, actual_reference) =
            match self.core.candidate_slot(&response.canonical_carrier) {
                Ok(slot) => slot,
                Err(error) => {
                    self.reject(Some(peer), error);
                    return;
                }
            };
        if actual_author != response.author || actual_round != response.round {
            self.reject(
                Some(peer),
                ShadowServiceErrorV1::SyncResponseSlotMismatch {
                    expected_author: response.author,
                    expected_round: response.round,
                    actual_author,
                    actual_round,
                },
            );
            return;
        }
        if response.round < self.core.local_carrier_round()
            || self
                .core
                .authenticated_reference(response.author, response.round)
                .is_some()
        {
            self.sync_last_attempt.remove(&expected);
            self.emit(ShadowServiceEventV1::Input {
                kind: "carrier_sync_response",
                outcome: "ignored_already_admitted_or_stale",
            });
            return;
        }
        if !self.sync_last_attempt.contains_key(&expected) {
            self.reject(
                Some(peer),
                ShadowServiceErrorV1::UnexpectedSyncResponse {
                    author: response.author,
                    round: response.round,
                },
            );
            return;
        }
        let before = self.core.wal_counts();
        // Exact requested responses always use the normal 64-round
        // authenticated window, including while unsolicited proactive
        // traffic is narrowed in far catch-up mode.
        match self.core.receive_or_retain_from_peer(
            &response.canonical_carrier,
            &response.authentication_sidecar,
            peer,
        ) {
            Ok(outcome) => {
                let outcome_label = match outcome.disposition() {
                    ShadowIngressDispositionV1::Authenticated => "authenticated",
                    ShadowIngressDispositionV1::CandidateRetained => "retained_unauthenticated",
                    ShadowIngressDispositionV1::IgnoredDuplicateConflictOrStale => "ignored",
                    ShadowIngressDispositionV1::IgnoredFutureOutsideBuffer => "future_ignored",
                };
                self.emit(ShadowServiceEventV1::Input {
                    kind: "carrier_sync_response",
                    outcome: outcome_label,
                });
                if let Err(error) = self.observe_carrier_application(
                    peer,
                    &response.canonical_carrier,
                    None,
                    outcome.disposition(),
                ) {
                    self.reject(Some(peer), error);
                }
                if outcome.disposition() == ShadowIngressDispositionV1::Authenticated
                    && self
                        .core
                        .authenticated_reference(response.author, response.round)
                        == Some(actual_reference)
                {
                    // Every fresh process repairs its carrier fixed before
                    // topology registration at round one. That alone is not
                    // lag evidence and must not turn healthy startup into a
                    // permanent exact-sync loop. Later authenticated repairs
                    // do prove that this clock missed live traffic.
                    if response.round > 1 {
                        self.observe_catch_up_hint(peer, response.round, false);
                    }
                }
                self.report_wal_delta(before);
                self.process_effects(outcome.effects().to_vec());
                self.retry_pending_local();
                if self
                    .core
                    .authenticated_reference(response.author, response.round)
                    .is_some()
                {
                    self.sync_last_attempt.remove(&expected);
                }
                if self.sync_catch_up {
                    self.flush_carrier_sync_requests(true);
                }
                if outcome.disposition() == ShadowIngressDispositionV1::CandidateRetained {
                    self.reject(
                        Some(peer),
                        ShadowServiceErrorV1::UnauthenticatedCarrierRetained,
                    );
                }
            }
            Err(error) => {
                self.emit(ShadowServiceEventV1::Input {
                    kind: "carrier_sync_response",
                    outcome: "rejected",
                });
                if is_fatal_core_error(&error) {
                    self.mark_fatal(error);
                } else {
                    self.reject(Some(peer), error);
                }
            }
        }
    }

    /// Drain exact-slot repair ahead of the ordinary proactive-carrier FIFO.
    /// A globally bounded set of exact `(round, author)` responses is retained
    /// by the handle. This is the priority seam a lagging honest node needs to
    /// consume pipelined repair while a live quorum continues producing future
    /// carriers.
    fn reconcile_carrier_sync_responses(&mut self) {
        if !self.clock_active {
            return;
        }
        loop {
            #[cfg(test)]
            {
                self.sync_max_desired_responses = self
                    .sync_max_desired_responses
                    .max(self.desired_carrier_sync_responses.lock().len());
            }
            let current_round = self.core.local_carrier_round();
            let next = {
                let mut desired = self.desired_carrier_sync_responses.lock();
                let exact_slot = desired.iter().find_map(|(slot, (_, response))| {
                    (response.round == current_round).then_some(*slot)
                });
                let slot = exact_slot.or_else(|| desired.keys().next().copied());
                slot.and_then(|slot| desired.remove(&slot))
            };
            let Some((peer, response)) = next else {
                break;
            };
            if let Err(error) = self.validate_peer(peer) {
                self.reject(Some(peer), error);
                continue;
            }
            self.handle_carrier_sync_response(peer, response);
            if self.fatal {
                break;
            }
        }
    }

    fn report_new_shadow_deliveries(&mut self, references: &[BlockReference]) {
        for reference in references {
            let identity = match self.core.delivery_identity(*reference) {
                Ok(identity) => identity,
                Err(error) => {
                    self.reject(None, error);
                    return;
                }
            };
            if !self.reported_shadow_deliveries.insert(identity) {
                continue;
            }
            let slot = delivery_slot(&identity);
            if !self.mode.is_autonomous() {
                self.comparison_backlog.observe_epoch_shadow(slot);
            }
            self.emit(ShadowServiceEventV1::Delivered(identity));
            self.emit_slot_comparison(slot);
            self.emit_comparison_backlog();
            match self.core.delivered_application_header(*reference) {
                Ok(Some((carrier, header))) => {
                    if let Err(error) =
                        self.authorize_delivered_application(carrier, header.clone())
                    {
                        self.reject(None, error);
                        return;
                    }
                    if self
                        .reported_application_deliveries
                        .insert(header.reference())
                    {
                        if let Some(metrics) = &self.metrics {
                            let latency_ns = current_timestamp_ns()
                                .saturating_sub(header.meta_creation_time_ns());
                            metrics.observe_starfish_rbc_dag_pipeline_latency_ns(
                                RBC_DAG_LATENCY_CREATION_TO_DELIVERY,
                                latency_ns,
                                1,
                                latency_ns,
                            );
                        }
                        self.emit(ShadowServiceEventV1::EmbeddedApplicationDelivered {
                            carrier,
                            header,
                        });
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    self.reject(None, error);
                    return;
                }
            }
        }
    }

    fn emit_slot_comparison(&mut self, slot: ShadowDeliverySlotV1) {
        if self.mode.is_autonomous() {
            return;
        }
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
    clock_starts_active: bool,
) {
    if open_report.replayed_batches() != 0 || open_report.discarded_tail_bytes() != 0 {
        state.emit(ShadowServiceEventV1::Recovered {
            batches: open_report.replayed_batches(),
            discarded_tail_bytes: open_report.discarded_tail_bytes(),
        });
    }
    state.reconcile_topology();
    state.reconcile_local_applications();
    state.reconcile_verified_application_payloads();
    state.reconcile_direct_deliveries();
    if !state.observe_external_invalidation() {
        if state.mode.is_autonomous() {
            // Replay-derived authority and effects must cross the ordered
            // event bridge before readiness can release an authoritative
            // Core. Clock activation follows Ready in the active-by-default
            // path and remains an explicit later message when coordinated.
            state.emit_autonomous_recovery_and_ready(&open_report);
            if clock_starts_active {
                state.activate_clock();
                state.retry_pending_local();
            }
        } else {
            // Direct mirror mode is observational and preserves its existing
            // Ready-first event contract for comparison consumers.
            state.emit(ShadowServiceEventV1::Ready {
                autonomous_clock: false,
            });
            state.emit_recovered_authorized_applications();
            state.emit_comparison_backlog();
            state.process_effects(open_report.recovery_effects().to_vec());
            state.retry_pending_local();
        }
        state.drive_consensus_fallback();
        if state.mode.is_autonomous() {
            state.emit_clock_state();
        }
    }

    while !state.fatal {
        state.reconcile_carrier_sync_responses();
        if state.fatal {
            break;
        }
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
        match &message {
            ShadowServiceMessageV1::RetryRecovery => state
                .retry_notification_pending
                .store(false, Ordering::Release),
            ShadowServiceMessageV1::HeartbeatTick => state
                .heartbeat_notification_pending
                .store(false, Ordering::Release),
            _ => {}
        }
        match message {
            ShadowServiceMessageV1::ActivateClock(reply) => {
                state.activate_clock();
                // A paused open may already hold a recovered or live local
                // application. Release that event-driven work immediately
                // after the ordered ClockActivated observation; control-only
                // production still waits for the fresh heartbeat epoch.
                state.retry_pending_local();
                let _ = reply.send(());
            }
            ShadowServiceMessageV1::LocalApplicationsChanged => {
                state.reconcile_local_applications();
            }
            ShadowServiceMessageV1::Carrier { peer, envelope } => {
                if let Err(error) = state.validate_peer(peer) {
                    state.reject(Some(peer), error);
                    continue;
                }
                let before = state.core.wal_counts();
                let open_round_before = state.core.local_carrier_round();
                let catchup_limited = state.sync_catch_up_limit_future;
                match state.core.receive_or_retain_from_peer_with_future_window(
                    &envelope.canonical_carrier,
                    &envelope.authentication_sidecar,
                    peer,
                    if catchup_limited {
                        0
                    } else {
                        EXECUTABLE_MODEL_BUFFER_WINDOW_V1
                    },
                ) {
                    Ok(outcome) => {
                        let future_ignored = outcome.disposition()
                            == ShadowIngressDispositionV1::IgnoredFutureOutsideBuffer;
                        let outcome_label = match outcome.disposition() {
                            ShadowIngressDispositionV1::Authenticated => "authenticated",
                            ShadowIngressDispositionV1::CandidateRetained => {
                                "retained_unauthenticated"
                            }
                            ShadowIngressDispositionV1::IgnoredDuplicateConflictOrStale => {
                                "ignored"
                            }
                            ShadowIngressDispositionV1::IgnoredFutureOutsideBuffer
                                if catchup_limited =>
                            {
                                "catchup_future_ignored"
                            }
                            ShadowIngressDispositionV1::IgnoredFutureOutsideBuffer => {
                                "future_ignored"
                            }
                        };
                        state.emit(ShadowServiceEventV1::Input {
                            kind: "carrier",
                            outcome: outcome_label,
                        });
                        state.observe_ingress_catch_up_hint(
                            peer,
                            &envelope.canonical_carrier,
                            outcome.disposition(),
                            open_round_before,
                        );
                        if let Err(error) = state.observe_carrier_application(
                            peer,
                            &envelope.canonical_carrier,
                            envelope.application_payload,
                            outcome.disposition(),
                        ) {
                            state.reject(Some(peer), error);
                        }
                        state.report_wal_delta(before);
                        state.process_effects(outcome.effects().to_vec());
                        // A coalesced producer notification may sit behind
                        // this ingress in the bounded actor FIFO even though
                        // its exact application is already present in the
                        // shared desired map. Reconcile it before phase work
                        // consumes the carrier round that this ingress opens.
                        state.reconcile_local_applications();
                        state.retry_pending_local();
                        if future_ignored {
                            state.flush_carrier_sync_requests(true);
                        }
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
                if let Some(envelope) = state.core.retained_authenticated_envelope(reference) {
                    state.emit(ShadowServiceEventV1::Network {
                        recipient: peer,
                        message: NetworkMessage::RbcDagShadowCarrierEnvelopeResponse(
                            RbcDagShadowCarrierEnvelopeResponse {
                                reference,
                                canonical_carrier: envelope.canonical_carrier_wire().to_vec(),
                                authentication_sidecar: envelope.authentication_sidecar().to_vec(),
                            },
                        ),
                    });
                } else if let Some(canonical_carrier) =
                    state.core.retained_candidate_wire(reference)
                {
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
                if state
                    .core
                    .retained_candidate_wire(response.reference)
                    .is_some()
                {
                    state.emit(ShadowServiceEventV1::Input {
                        kind: "recovery",
                        outcome: "ignored_already_retained",
                    });
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
                        if let Err(error) = state.observe_carrier_application(
                            peer,
                            &response.canonical_carrier,
                            None,
                            ShadowIngressDispositionV1::CandidateRetained,
                        ) {
                            state.reject(Some(peer), error);
                        }
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
            ShadowServiceMessageV1::CarrierEnvelopeResponse { peer, response } => {
                if let Err(error) = state.validate_peer(peer) {
                    state.reject(Some(peer), error);
                    continue;
                }
                if state
                    .core
                    .authenticated_reference(response.reference.authority, response.reference.round)
                    == Some(response.reference)
                {
                    state.emit(ShadowServiceEventV1::Input {
                        kind: "recovery",
                        outcome: "ignored_already_authenticated",
                    });
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
                match state.core.recover_or_admit_from_peer(
                    response.reference,
                    &response.canonical_carrier,
                    &response.authentication_sidecar,
                    peer,
                ) {
                    Ok(outcome) => {
                        state.pending_recovery.remove(&response.reference);
                        state
                            .recovery_last_attempt
                            .retain(|(target, _), _| *target != response.reference);
                        state.emit(ShadowServiceEventV1::Input {
                            kind: "recovery",
                            outcome: match outcome.disposition() {
                                ShadowIngressDispositionV1::Authenticated => {
                                    "accepted_authenticated"
                                }
                                ShadowIngressDispositionV1::CandidateRetained => {
                                    "accepted_content_only"
                                }
                                ShadowIngressDispositionV1::IgnoredDuplicateConflictOrStale => {
                                    "ignored_duplicate"
                                }
                                ShadowIngressDispositionV1::IgnoredFutureOutsideBuffer => {
                                    "future_ignored"
                                }
                            },
                        });
                        if let Err(error) = state.observe_carrier_application(
                            peer,
                            &response.canonical_carrier,
                            None,
                            outcome.disposition(),
                        ) {
                            state.reject(Some(peer), error);
                        }
                        state.report_wal_delta(before);
                        state.process_effects(outcome.effects().to_vec());
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
            ShadowServiceMessageV1::CarrierSyncRequest { peer, request } => {
                if let Err(error) = state.validate_peer(peer) {
                    state.reject(Some(peer), error);
                    continue;
                }
                state.handle_carrier_sync_request(peer, request);
            }
            ShadowServiceMessageV1::CarrierSyncResponsesChanged => {}
            ShadowServiceMessageV1::ApplicationPayloadRequest { peer, application } => {
                if let Err(error) = state.validate_peer(peer) {
                    state.reject(Some(peer), error);
                    continue;
                }
                state.handle_application_payload_request(peer, application);
            }
            ShadowServiceMessageV1::ApplicationPayloadResponse { peer, response } => {
                if let Err(error) = state.validate_peer(peer) {
                    state.reject(Some(peer), error);
                    continue;
                }
                if let Err(error) = state.handle_application_payload_response(peer, response) {
                    state.reject(Some(peer), error);
                }
            }
            ShadowServiceMessageV1::VerifiedApplicationPayloadsChanged => {}
            ShadowServiceMessageV1::DirectDeliveriesChanged => {
                state.reconcile_direct_deliveries();
            }
            ShadowServiceMessageV1::TopologyChanged => {}
            ShadowServiceMessageV1::RetryRecovery => {
                state.reconcile_local_applications();
                state.retry_pending_local();
                state.reconcile_pending_recovery();
                state.flush_recovery_requests();
                state.flush_carrier_sync_requests(false);
                state.flush_application_payload_requests();
            }
            ShadowServiceMessageV1::HeartbeatTick => {
                state.awaiting_application_submission = false;
                state.application_submission_deadline = None;
                state.try_create_autonomous_carrier();
            }
            ShadowServiceMessageV1::NormalCarrierDeadline { generation } => {
                state.observe_normal_carrier_deadline(generation);
            }
            ShadowServiceMessageV1::ConsensusTimeoutDeadline { generation, slot } => {
                state.observe_consensus_timeout_deadline(generation, slot);
            }
            ShadowServiceMessageV1::DataAvailabilityChanged => {
                state.reconcile_data_availability();
            }
            #[cfg(test)]
            ShadowServiceMessageV1::InspectRbcProgress(reply) => {
                let progress = (
                    state.core.optimistic_promise_count(),
                    state
                        .core
                        .certified_delivery_count()
                        .expect("test progress inspection requires unambiguous deliveries"),
                );
                let _ = reply.send(progress);
            }
            #[cfg(test)]
            ShadowServiceMessageV1::InspectCarrierSync(reply) => {
                let desired_responses = state.desired_carrier_sync_responses.lock().len();
                state.sync_max_desired_responses =
                    state.sync_max_desired_responses.max(desired_responses);
                let _ = reply.send(CarrierSyncInspectionV1 {
                    open_round: state.core.local_carrier_round(),
                    target: state.sync_catch_up_target,
                    outstanding: state.sync_last_attempt.len(),
                    desired_responses,
                    max_outstanding: state.sync_max_outstanding,
                    max_desired_responses: state.sync_max_desired_responses,
                });
            }
            ShadowServiceMessageV1::Shutdown(_) => unreachable!("shutdown handled before dispatch"),
        }
        state.reconcile_topology();
        state.reconcile_local_applications();
        state.reconcile_carrier_sync_responses();
        state.reconcile_verified_application_payloads();
        state.reconcile_direct_deliveries();
        state.drive_consensus_fallback();
        state.drive_autonomous_catch_up();
        state.drive_retained_future_catch_up();
        state.flush_carrier_sync_requests(false);
        state.flush_application_payload_requests();
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

fn current_timestamp_ns() -> TimestampNs {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(TimestampNs::MAX)
}

fn latency_since_header_creation<'a>(
    headers: impl Iterator<Item = &'a RbcCanonicalHeader>,
    now_ns: TimestampNs,
) -> (u64, u64, u64) {
    headers.fold((0u64, 0u64, 0u64), |(total, samples, maximum), header| {
        let latency = now_ns.saturating_sub(header.meta_creation_time_ns());
        (
            total.saturating_add(latency),
            samples.saturating_add(1),
            maximum.max(latency),
        )
    })
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

fn shadow_input_capacity(
    committee_size: usize,
    mode: ShadowServiceModeV1,
) -> Result<usize, ShadowServiceErrorV1> {
    let peer_count = committee_size.saturating_sub(1);
    let peer_burst_factor = if mode.is_autonomous() { 3 } else { 1 };
    let committee_burst = peer_count
        .saturating_mul(peer_burst_factor)
        .saturating_add(SHADOW_SERVICE_CONTROL_RESERVE_V1);
    if committee_burst > SHADOW_SERVICE_MAX_INPUT_CAPACITY_V1 {
        return Err(ShadowServiceErrorV1::CommitteeBurstTooLarge {
            committee_size,
            required_capacity: committee_burst,
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

fn validate_application_payload_size(
    payload: &TransactionData,
) -> Result<(), ShadowServiceErrorV1> {
    let actual = bincode::serialized_size(payload)
        .map_err(|error| ShadowServiceErrorV1::ApplicationPayloadSerialization(error.to_string()))?
        .try_into()
        .unwrap_or(usize::MAX);
    validate_wire_size(
        "application payload",
        actual,
        SHADOW_APPLICATION_PAYLOAD_MAX_SIZE_V1,
    )
}

fn application_payloads_equal(
    left: Option<&TransactionData>,
    right: Option<&TransactionData>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.transactions() == right.transactions(),
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

fn merge_application_payload(
    retained: &mut Option<Arc<TransactionData>>,
    incoming: Option<Arc<TransactionData>>,
    application: BlockReference,
) -> Result<(), ShadowServiceErrorV1> {
    let Some(incoming) = incoming else {
        return Ok(());
    };
    match retained {
        Some(existing)
            if !application_payloads_equal(Some(existing.as_ref()), Some(incoming.as_ref())) =>
        {
            Err(ShadowServiceErrorV1::ConflictingApplicationPayload(
                application,
            ))
        }
        Some(_) => Ok(()),
        None => {
            *retained = Some(incoming);
            Ok(())
        }
    }
}

fn is_fatal_core_error(error: &ShadowErrorV1) -> bool {
    matches!(
        error,
        ShadowErrorV1::Wal(_) | ShadowErrorV1::PostModelJournal(_) | ShadowErrorV1::Poisoned
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
        },
        time::Duration,
    };

    use prometheus::Registry;
    use tempfile::TempDir;
    use tokio::time::timeout;

    use super::*;
    use crate::{
        committee::Committee,
        crypto::{TransactionsCommitment, mac_keyrings_for_test},
        encoder::{Encoder, ShardEncoder},
        starfish_rbc_dag::{
            CandidateCarrierV1, CarrierAuthorizerV1, CarrierHeaderV1Args, LeaderChoiceV1,
            RbcDagProtocolInstanceId, RbcPhaseStatementV1, carrier_genesis_reference,
        },
        types::{BaseTransaction, BlockDigest, Transaction, VerifiedBlock},
    };

    const N: usize = 4;
    const EVENT_TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn carrier_sync_limiter_is_order_independent_and_throttles_replay() {
        let start = Instant::now();
        let first = SHADOW_CARRIER_SYNC_MAX_ADVANCING_BURST_V1 as RoundNumber;
        let mut limiter = CarrierSyncServeWindowV1::first(first, start);
        for round in (1..first).rev() {
            assert!(limiter.permits(round, start));
        }
        let next = first.saturating_add(1);
        assert!(!limiter.permits(next, start));
        assert!(!limiter.permits(1, start));

        let later = start + SHADOW_CARRIER_SYNC_RETRY_INTERVAL_V1;
        assert!(limiter.permits(next, later));
        assert!(!limiter.permits(next, later));
        assert!(limiter.permits(1, later));
    }

    #[test]
    fn ten_validator_sync_window_is_round_major_and_bounded_to_sixty_three_slots() {
        let connected = (1..10)
            .map(|authority| authority as AuthorityIndex)
            .collect();
        let slots = carrier_sync_pipeline_slots(40, Some(100), 10, &connected);

        assert_eq!(carrier_sync_pipeline_depth(10), 7);
        assert_eq!(slots.len(), 63);
        assert_eq!(slots.first(), Some(&(40, 1)));
        assert_eq!(slots.last(), Some(&(46, 9)));
        assert!(slots.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(!slots.iter().any(|(round, _)| *round >= 47));
        assert!(slots.len() <= SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1);

        let moderate = carrier_sync_pipeline_slots(40, None, 10, &connected);
        assert_eq!(moderate.len(), 9);
        assert!(moderate.iter().all(|(round, _)| *round == 40));
    }

    #[test]
    fn exact_sync_responses_coalesce_by_slot_without_overwrite() {
        let (sender, _receiver) = mpsc::channel(1);
        let desired = Arc::new(Mutex::new(BTreeMap::new()));
        let handle = StarfishRbcDagShadowServiceHandleV1 {
            sender,
            max_sidecar_size: 3 + N * MAC_TAG_SIZE,
            own_authority: 0,
            committee_size: N,
            input_capacity: 1,
            mode: ShadowServiceModeV1::AutonomousClock {
                heartbeat_interval: Duration::from_secs(1),
            },
            desired_topology: Arc::new(Mutex::new(BTreeMap::new())),
            desired_local_applications: Arc::new(Mutex::new(BTreeMap::new())),
            desired_carrier_sync_responses: Arc::clone(&desired),
            desired_verified_application_payloads: Arc::new(Mutex::new(BTreeMap::new())),
            desired_direct_deliveries: Arc::new(Mutex::new(BTreeSet::new())),
            desired_available_applications: Arc::new(Mutex::new(BTreeSet::new())),
            invalidated_by_overload: Arc::new(Mutex::new(None)),
        };
        let response = |author, round, marker| RbcDagShadowCarrierSyncResponse {
            author,
            round,
            canonical_carrier: vec![marker],
            authentication_sidecar: Vec::new(),
        };

        let first = response(1, 7, 0xA1);
        let later = response(1, 8, 0xA2);
        handle.carrier_sync_response(1, first.clone()).unwrap();
        handle.carrier_sync_response(1, later.clone()).unwrap();
        handle.carrier_sync_response(1, first.clone()).unwrap();
        assert_eq!(desired.lock().len(), 2);
        assert_eq!(desired.lock().get(&(7, 1)).unwrap().1, first);
        assert_eq!(desired.lock().get(&(8, 1)).unwrap().1, later);

        assert!(matches!(
            handle.carrier_sync_response(1, response(1, 7, 0xFF)),
            Err(ShadowServiceErrorV1::UnexpectedSyncResponse {
                author: 1,
                round: 7,
            })
        ));
        assert_eq!(
            desired.lock().get(&(7, 1)).unwrap().1.canonical_carrier,
            vec![0xA1]
        );

        'fill: for round in 1..=RoundNumber::MAX {
            for author in 1..N as AuthorityIndex {
                if desired.lock().len() == SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1 {
                    break 'fill;
                }
                if desired.lock().contains_key(&(round, author)) {
                    continue;
                }
                handle
                    .carrier_sync_response(author, response(author, round, author as u8))
                    .unwrap();
            }
        }
        assert_eq!(desired.lock().len(), SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1);
        assert!(matches!(
            handle.carrier_sync_response(1, response(1, 10_000, 0xCC)),
            Err(ShadowServiceErrorV1::CarrierSyncResponseCapacity {
                capacity: SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1,
            })
        ));
    }

    #[tokio::test]
    async fn catch_up_target_is_the_monotone_validity_stake_high_water() {
        let harness = Harness::new();
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let (state, _events, _message_rx, _message_tx) =
            standalone_autonomous_state(core, harness.committee.clone(), Duration::from_secs(60));
        tokio::task::spawn_blocking(move || {
            let mut state = state;
            state.observe_catch_up_hint(1, 100, true);
            assert_eq!(state.sync_catch_up_target, None);
            state.observe_catch_up_hint(2, 70, true);
            assert_eq!(state.sync_catch_up_target, Some(70));
            assert!(state.sync_catch_up);
            assert!(state.sync_catch_up_limit_future);

            state.observe_catch_up_hint(3, 90, true);
            assert_eq!(state.sync_catch_up_target, Some(90));
            state.observe_catch_up_hint(2, 110, true);
            assert_eq!(state.sync_catch_up_target, Some(100));
            state.observe_catch_up_hint(1, 80, true);
            assert_eq!(state.sync_catch_up_target, Some(100));
            state.core.shutdown().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn in_window_future_hints_do_not_start_exact_catch_up() {
        let harness = Harness::new();
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let (state, _events, _message_rx, _message_tx) =
            standalone_autonomous_state(core, harness.committee.clone(), Duration::from_secs(60));
        tokio::task::spawn_blocking(move || {
            let mut state = state;
            state.observe_catch_up_hint(1, 40, false);
            assert_eq!(state.retained_future_target(), None);
            // Two remote hints carry validity stake in the four-node test,
            // but both remain inside normal authenticated retention.
            state.observe_catch_up_hint(2, 40, false);
            assert_eq!(
                state.validity_backed_high_water(&state.catch_up_hint_high_water),
                Some(40)
            );
            assert_eq!(state.retained_future_target(), Some(40));
            assert!(!state.sync_catch_up);
            assert!(!state.sync_catch_up_limit_future);
            assert_eq!(state.sync_catch_up_target, None);
            state.core.shutdown().unwrap();
        })
        .await
        .unwrap();
    }

    fn producer_carrier(
        committee: &RbcDagCommitteeContextV1,
        chains: &[Vec<BlockReference>],
        author: AuthorityIndex,
        round: RoundNumber,
    ) -> CandidateCarrierV1 {
        let previous = |authority: AuthorityIndex| {
            if round == 1 {
                carrier_genesis_reference(authority)
            } else {
                chains[authority as usize][round as usize - 2]
            }
        };
        let mut parent_stake = committee
            .committee()
            .get_stake(author)
            .expect("producer authority belongs to the committee");
        let mut weak_parents = Vec::new();
        for parent_authority in committee.committee().authorities() {
            // Authority zero is the lagger. A live quorum of the other
            // producers must remain able to extend without naming its stale
            // physical chain.
            if parent_authority == 0 || parent_authority == author {
                continue;
            }
            weak_parents.push(previous(parent_authority));
            parent_stake = parent_stake.saturating_add(
                committee
                    .committee()
                    .get_stake(parent_authority)
                    .expect("parent authority belongs to the committee"),
            );
            if parent_stake >= committee.committee().quorum_threshold() {
                break;
            }
        }
        CandidateCarrierV1::try_new_with_committee(
            CarrierHeaderV1Args {
                author,
                carrier_round: round,
                own_prev: previous(author),
                weak_parents,
                transactions_commitment: TransactionsCommitment::default(),
                application_header: None,
                data_acknowledgments: Vec::new(),
                phase_batch: Vec::new(),
                consensus_vertex: None,
                creation_time_ns: round.into(),
            },
            committee,
        )
        .unwrap()
    }

    fn feed_producer_round(
        state: &mut ShadowServiceStateV1,
        harness: &Harness,
        chains: &mut [Vec<BlockReference>],
        round: RoundNumber,
    ) {
        let open_before = state.core.local_carrier_round();
        for author in 1..state.committee_size as AuthorityIndex {
            let candidate = producer_carrier(&harness.committee, chains, author, round);
            let reference = candidate.reference();
            let envelope = harness.envelope(&candidate, author);
            let outcome = state
                .core
                .receive_or_retain_from_peer(
                    &envelope.canonical_carrier,
                    &envelope.authentication_sidecar,
                    author,
                )
                .unwrap();
            assert_eq!(
                outcome.disposition(),
                ShadowIngressDispositionV1::Authenticated
            );
            state.observe_ingress_catch_up_hint(
                author,
                &envelope.canonical_carrier,
                outcome.disposition(),
                open_before,
            );
            state.process_effects(outcome.effects().to_vec());
            chains[author as usize].push(reference);
        }
    }

    async fn assert_retained_future_tail_closes_without_exact_sync(n: usize, initial_tail: u32) {
        let harness = Harness::new_with_n(n);
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let (mut state, mut events, _messages, _message_tx) = standalone_autonomous_state(
            core,
            harness.committee.clone(),
            Duration::from_secs(60 * 60),
        );
        let sync_requests = Arc::new(AtomicUsize::new(0));
        let sync_requests_observed = Arc::clone(&sync_requests);
        let event_drain = tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                if matches!(
                    event,
                    ShadowServiceEventV1::Network {
                        message: NetworkMessage::RbcDagShadowCarrierSyncRequest(_),
                        ..
                    }
                ) {
                    sync_requests_observed.fetch_add(1, AtomicOrdering::Relaxed);
                }
            }
        });

        tokio::task::spawn_blocking(move || {
            let mut chains = vec![Vec::new(); n];
            state.connected = (1..n as AuthorityIndex).collect();
            state.clock_active = false;
            for round in 1..=initial_tail {
                feed_producer_round(&mut state, &harness, &mut chains, round);
            }
            assert_eq!(state.core.local_carrier_round(), 1);
            assert_eq!(state.retained_future_target(), Some(initial_tail));

            state.activate_clock();
            state.sync_round_opened_at = Instant::now() - Duration::from_secs(60 * 60 * 3);
            let depth = carrier_sync_pipeline_depth(n) as RoundNumber;
            let mut healthy_round = initial_tail;
            for _ in 0..initial_tail.saturating_add(4) {
                // Keep the healthy quorum producing while the lagger consumes
                // its retained tail.
                healthy_round = healthy_round.saturating_add(1);
                feed_producer_round(&mut state, &harness, &mut chains, healthy_round);
                let before = state.core.local_carrier_round();
                state.drive_retained_future_catch_up();
                let after = state.core.local_carrier_round();
                assert!(after.saturating_sub(before) <= depth);
                state.flush_carrier_sync_requests(false);
                if healthy_round.saturating_add(1).saturating_sub(after) <= 2 {
                    break;
                }
            }
            let gap = healthy_round
                .saturating_add(1)
                .saturating_sub(state.core.local_carrier_round());
            assert!(gap <= 2, "retained local catch-up plateaued with gap {gap}");
            assert!(!state.sync_catch_up);
            assert!(!state.sync_catch_up_limit_future);

            let buffered_capacity = EXECUTABLE_MODEL_BUFFER_WINDOW_V1
                .saturating_sub(EXECUTABLE_MODEL_ADMISSION_WINDOW_V1)
                as usize
                * n.saturating_sub(1);
            assert!(state.core.buffered_authenticated_carrier_count() <= buffered_capacity);

            // Stop producers and prove the target-carrier off-by-one: fixing
            // the hinted carrier round opens its successor.
            if let Some(final_target) = state.retained_future_target() {
                for _ in 0..initial_tail.saturating_add(4) {
                    state.drive_retained_future_catch_up();
                    if state.core.local_carrier_round() > final_target {
                        break;
                    }
                }
                assert_eq!(state.core.local_carrier_round(), final_target + 1);
            }
            state.core.shutdown().unwrap();
        })
        .await
        .unwrap();
        event_drain.await.unwrap();
        assert_eq!(sync_requests.load(AtomicOrdering::Relaxed), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn four_node_retained_gap_seventeen_closes_without_exact_sync() {
        assert_retained_future_tail_closes_without_exact_sync(4, 17).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ten_node_retained_gap_thirty_two_closes_without_exact_sync() {
        assert_retained_future_tail_closes_without_exact_sync(10, 32).await;
    }

    #[tokio::test]
    async fn requested_future_response_uses_normal_window_during_far_catch_up() {
        let harness = Harness::new();
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let (state, _events, _message_rx, _message_tx) =
            standalone_autonomous_state(core, harness.committee.clone(), Duration::from_secs(60));
        let round = 10;
        let previous = |authority: AuthorityIndex| BlockReference {
            authority,
            round: round - 1,
            digest: BlockDigest::from([0x70 + authority as u8; 32]),
        };
        let candidate = CandidateCarrierV1::try_new_with_committee(
            CarrierHeaderV1Args {
                author: 1,
                carrier_round: round,
                own_prev: previous(1),
                weak_parents: [0, 2].into_iter().map(previous).collect(),
                transactions_commitment: TransactionsCommitment::default(),
                application_header: None,
                data_acknowledgments: Vec::new(),
                phase_batch: Vec::new(),
                consensus_vertex: None,
                creation_time_ns: round.into(),
            },
            &harness.committee,
        )
        .unwrap();
        let reference = candidate.reference();
        let envelope = harness.envelope(&candidate, 1);
        tokio::task::spawn_blocking(move || {
            let mut state = state;
            state.sync_catch_up_limit_future = true;
            state.sync_last_attempt.insert((round, 1), Instant::now());
            state.handle_carrier_sync_response(
                1,
                RbcDagShadowCarrierSyncResponse {
                    author: 1,
                    round,
                    canonical_carrier: envelope.canonical_carrier,
                    authentication_sidecar: envelope.authentication_sidecar,
                },
            );

            assert_eq!(state.core.local_carrier_round(), 1);
            assert_eq!(
                state.core.authenticated_reference(1, round),
                Some(reference)
            );
            assert!(!state.sync_last_attempt.contains_key(&(round, 1)));
            state.core.shutdown().unwrap();
        })
        .await
        .unwrap();
    }

    #[test]
    fn consensus_pacemaker_fixed_grid_does_not_inherit_c2_for_a_new_slot() {
        let timeout = Duration::from_millis(100);
        let origin = Instant::now();
        let mut pacemaker = ConsensusPacemakerV1::new(2);

        assert!(!pacemaker.fallback_allowed(2, true, false, timeout, origin));
        assert!(pacemaker.fallback_allowed(2, true, false, timeout, origin + timeout));
        assert!(
            !pacemaker.fallback_allowed(3, true, false, timeout, origin + timeout),
            "a fixed-grid tick at the instant slot 3 opens must reset C2"
        );
        assert!(!pacemaker.fallback_allowed(
            3,
            true,
            false,
            timeout,
            origin + timeout + timeout - Duration::from_nanos(1),
        ));
        assert!(pacemaker.fallback_allowed(3, true, false, timeout, origin + timeout + timeout,));
    }

    #[test]
    fn consensus_pacemaker_c2_starts_only_when_a1_becomes_ready() {
        let timeout = Duration::from_millis(100);
        let origin = Instant::now();
        let mut pacemaker = ConsensusPacemakerV1::new(4);

        assert!(!pacemaker.fallback_allowed(4, false, false, timeout, origin));
        assert!(!pacemaker.fallback_allowed(
            4,
            false,
            false,
            timeout,
            origin + timeout.saturating_mul(10),
        ));
        let a1_at = origin + timeout.saturating_mul(10);
        assert!(!pacemaker.fallback_allowed(4, true, false, timeout, a1_at));
        assert!(!pacemaker.fallback_allowed(
            4,
            true,
            false,
            timeout,
            a1_at + timeout - Duration::from_nanos(1),
        ));
        assert!(pacemaker.fallback_allowed(4, true, false, timeout, a1_at + timeout));
    }

    #[test]
    fn consensus_pacemaker_c3_authorizes_immediate_slot_bound_catch_up() {
        let timeout = Duration::from_secs(60);
        let origin = Instant::now();
        let mut pacemaker = ConsensusPacemakerV1::new(7);

        assert!(pacemaker.fallback_allowed(7, false, true, timeout, origin));
        assert!(
            !pacemaker.fallback_allowed(8, false, false, timeout, origin),
            "C3 evidence for slot 7 must not leak into slot 8"
        );
    }

    #[tokio::test]
    async fn service_c3_emits_a_control_carrier_without_waiting_for_the_fixed_grid() {
        let harness = Harness::new();
        let (mut core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let reference = |authority, consensus_round, marker| {
            ConsensusVertexReference::new(
                BlockReference {
                    authority,
                    round: 100 + consensus_round,
                    digest: BlockDigest::from([marker; 32]),
                },
                consensus_round,
            )
        };

        let round_one_leader = reference(1, 1, 0x11);
        core.inject_projected_consensus_for_test(
            round_one_leader,
            Vec::new(),
            LeaderChoiceV1::NoVote {
                leader_author: 0,
                leader_round: 0,
            },
        );
        for (author, choice) in [
            (
                0,
                LeaderChoiceV1::Vote {
                    leader: round_one_leader,
                },
            ),
            (
                1,
                LeaderChoiceV1::Vote {
                    leader: round_one_leader,
                },
            ),
            (
                3,
                LeaderChoiceV1::NoVote {
                    leader_author: 1,
                    leader_round: 1,
                },
            ),
        ] {
            core.inject_projected_consensus_for_test(
                reference(author, 2, 0x20 + author as u8),
                vec![round_one_leader],
                choice,
            );
        }
        for author in [1, 2, 3] {
            core.inject_projected_consensus_for_test(
                reference(author, 3, 0x30 + author as u8),
                Vec::new(),
                LeaderChoiceV1::NoVote {
                    leader_author: 2,
                    leader_round: 2,
                },
            );
        }
        core.set_next_local_consensus_round_for_test(3);
        assert!(core.has_projected_consensus_quorum(3));

        let (state, mut event_rx, _message_rx, _message_tx) = standalone_autonomous_state(
            core,
            harness.committee.clone(),
            Duration::from_secs(60 * 60),
        );

        let state = tokio::task::spawn_blocking(move || {
            let mut state = state;
            state.drive_consensus_fallback();
            state
        })
        .await
        .unwrap();
        assert_eq!(state.core.next_local_consensus_round(), 4);
        let mut emitted = None;
        while let Ok(event) = event_rx.try_recv() {
            if let ShadowServiceEventV1::Network {
                message: NetworkMessage::RbcDagShadowCarrier(carrier),
                ..
            } = event
            {
                emitted = Some(carrier);
                break;
            }
        }
        let emitted = emitted.expect("C3 must schedule a carrier immediately");
        let candidate = CandidateCarrierV1::decode_wire_with_committee(
            &emitted.canonical_carrier,
            &harness.committee,
            None,
        )
        .unwrap();
        let vertex = candidate
            .header()
            .consensus_vertex()
            .expect("C3 carrier must contain the lagging logical slot");
        assert_eq!(vertex.consensus_round(), 3);
        assert_eq!(
            vertex.leader_choice(),
            LeaderChoiceV1::NoVote {
                leader_author: 2,
                leader_round: 2,
            }
        );
        state.core.shutdown().unwrap();
    }

    #[tokio::test]
    async fn service_c2_deadline_message_creates_without_waiting_for_the_next_grid_tick() {
        let harness = Harness::new();
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let heartbeat_interval = Duration::from_secs(60);
        let consensus_timeout = Duration::from_millis(20);
        let (mut state, mut event_rx, mut message_rx, _message_tx) =
            standalone_autonomous_state(core, harness.committee.clone(), heartbeat_interval);
        state.consensus_timeout = consensus_timeout;

        state.refresh_consensus_pacemaker();
        assert_eq!(state.mode.heartbeat_interval(), Some(heartbeat_interval));
        assert_eq!(state.core.local_carrier_round(), 1);
        let (generation, slot) = match timeout(Duration::from_secs(1), message_rx.recv())
            .await
            .expect("slot-bound C2 deadline was not scheduled")
        {
            Some(ShadowServiceMessageV1::ConsensusTimeoutDeadline { generation, slot }) => {
                (generation, slot)
            }
            other => panic!(
                "unexpected deadline message: {:?}",
                other.map(|message| message.kind())
            ),
        };
        assert_eq!(slot, 1);
        state.observe_consensus_timeout_deadline(generation, slot);
        assert!(state.consensus_pacemaker.c2_timed_out);

        let state = tokio::task::spawn_blocking(move || {
            state.drive_consensus_fallback();
            state
        })
        .await
        .unwrap();
        assert!(!state.core.can_create_carrier());
        assert_eq!(state.core.next_local_consensus_round(), 2);
        let mut emitted = false;
        while let Ok(event) = event_rx.try_recv() {
            emitted |= matches!(
                event,
                ShadowServiceEventV1::Network {
                    message: NetworkMessage::RbcDagShadowCarrier(_),
                    ..
                }
            );
        }
        assert!(emitted, "C2 deadline must schedule a carrier immediately");
        state.core.shutdown().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn consensus_timeout_deadline_coalesces_and_rejects_stale_wakes() {
        let harness = Harness::new();
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let (mut state, _event_rx, _message_rx, _message_tx) = standalone_autonomous_state(
            core,
            harness.committee.clone(),
            Duration::from_secs(60 * 60),
        );

        state.refresh_consensus_pacemaker();
        let scheduled = state
            .consensus_timeout_deadline
            .expect("C2 readiness did not arm its persistent deadline");
        assert_eq!(scheduled.slot, 1);

        // Repeated ingress/maintenance observations for one logical slot
        // share one generation and one physical timer.
        for _ in 0..8 {
            state.refresh_consensus_pacemaker();
            assert_eq!(state.consensus_timeout_deadline, Some(scheduled));
            assert_eq!(state.consensus_timeout_generation, scheduled.generation);
        }

        state.observe_consensus_timeout_deadline(
            scheduled.generation.wrapping_sub(1),
            scheduled.slot,
        );
        assert_eq!(state.consensus_timeout_deadline, Some(scheduled));
        assert!(!state.consensus_pacemaker.c2_timed_out);

        // Make the unit-state deadline due without sleeping for an hour. The
        // current generation is consumed once; a duplicate queued wake is a
        // no-op and cannot authorize a different slot.
        let due = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap_or_else(Instant::now);
        let due_scheduled = ConsensusTimeoutDeadlineV1 {
            deadline: due,
            ..scheduled
        };
        state.consensus_timeout_deadline = Some(due_scheduled);
        state
            .consensus_timeout_deadline_tx
            .send_replace(Some(due_scheduled));
        state.observe_consensus_timeout_deadline(due_scheduled.generation, due_scheduled.slot);
        assert_eq!(state.consensus_timeout_deadline, None);
        assert!(state.consensus_pacemaker.c2_timed_out);
        state.observe_consensus_timeout_deadline(due_scheduled.generation, due_scheduled.slot);
        assert_eq!(state.consensus_timeout_deadline, None);

        // Replacing the actor-owned target leaves exactly one desired
        // deadline. Advancing the logical slot cancels it, and its already
        // queued generation remains harmless.
        let replacement_deadline = Instant::now() + Duration::from_secs(60 * 60);
        state.schedule_consensus_timeout_deadline(1, replacement_deadline);
        let replacement = state.consensus_timeout_deadline.unwrap();
        assert_ne!(replacement.generation, scheduled.generation);
        state.core.set_next_local_consensus_round_for_test(2);
        state.refresh_consensus_pacemaker();
        assert_eq!(state.consensus_pacemaker.slot, 2);
        assert_eq!(state.consensus_timeout_deadline, None);
        state.observe_consensus_timeout_deadline(replacement.generation, replacement.slot);
        assert_eq!(state.consensus_timeout_deadline, None);

        state.core.shutdown().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn normal_carrier_deadline_coalesces_and_rejects_stale_generations() {
        let harness = Harness::new();
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let (mut state, mut event_rx, _message_rx, _message_tx) = standalone_autonomous_state(
            core,
            harness.committee.clone(),
            Duration::from_secs(60 * 60),
        );

        tokio::task::spawn_blocking(move || {
            state.normal_carrier_min_spacing = Duration::from_secs(60 * 60);
            state.try_create_autonomous_carrier();
            assert_eq!(state.core.local_carrier_round(), 1);
            assert!(!state.core.can_create_carrier());

            // Every normal trigger while the permit is closed must share one
            // generation and one deadline, regardless of its source.
            state.try_create_autonomous_carrier();
            let scheduled = state
                .normal_carrier_deadline
                .expect("closed permit did not schedule its persistent wake");
            assert!(state.normal_carrier_requested);
            for _ in 0..8 {
                state.try_create_autonomous_carrier();
                assert_eq!(state.normal_carrier_deadline, Some(scheduled));
                assert_eq!(state.normal_carrier_generation, scheduled.generation);
            }

            let stale_generation = scheduled.generation.wrapping_sub(1);
            state.observe_normal_carrier_deadline(stale_generation);
            assert_eq!(state.normal_carrier_deadline, Some(scheduled));
            assert!(state.normal_carrier_requested);

            // Admit the exact predecessor quorum so the current wake can fix
            // one, and only one, successor carrier. Move the deterministic
            // unit-state deadline to the past instead of sleeping for an hour.
            let mut chains = vec![Vec::new(); N];
            feed_producer_round(&mut state, &harness, &mut chains, 1);
            assert_eq!(state.core.local_carrier_round(), 2);
            assert!(state.core.can_create_carrier());
            let due = Instant::now()
                .checked_sub(Duration::from_millis(1))
                .unwrap_or_else(Instant::now);
            let due_scheduled = NormalCarrierDeadlineV1 {
                generation: scheduled.generation,
                deadline: due,
            };
            state.normal_carrier_next_allowed_at = Some(due);
            state.normal_carrier_deadline = Some(due_scheduled);
            state
                .normal_carrier_deadline_tx
                .send_replace(Some(due_scheduled));

            state.observe_normal_carrier_deadline(due_scheduled.generation);
            assert_eq!(state.core.local_carrier_round(), 2);
            assert!(!state.core.can_create_carrier());
            assert!(!state.normal_carrier_requested);
            assert_eq!(state.normal_carrier_deadline, None);

            // A duplicate queued wake for the generation just consumed is a
            // no-op and cannot spend another physical slot.
            state.observe_normal_carrier_deadline(due_scheduled.generation);
            assert_eq!(state.core.local_carrier_round(), 2);
            assert!(!state.core.can_create_carrier());
            state.core.shutdown().unwrap();
        })
        .await
        .unwrap();

        let proactive_carriers = std::iter::from_fn(|| event_rx.try_recv().ok())
            .filter(|event| {
                matches!(
                    event,
                    ShadowServiceEventV1::Network {
                        message: NetworkMessage::RbcDagShadowCarrier(_),
                        ..
                    }
                )
            })
            .count();
        assert_eq!(proactive_carriers, 2 * (N - 1));
    }

    struct Harness {
        _directory: TempDir,
        committee: RbcDagCommitteeContextV1,
        context: RbcDagContextV1,
        keyrings: Vec<Vec<crate::crypto::MacKey>>,
        paths: Vec<std::path::PathBuf>,
    }

    impl Harness {
        fn new() -> Self {
            Self::new_with_n(N)
        }

        fn new_with_n(n: usize) -> Self {
            let committee = Committee::new_test(vec![1; n]);
            let committee = RbcDagCommitteeContextV1::new(Arc::clone(&committee)).unwrap();
            let context = RbcDagContextV1::new_with_committee(
                RbcDagProtocolInstanceId::new([0xD7; 32]).unwrap(),
                &committee,
                BlockAuthenticationScheme::MacVector,
            );
            let directory = tempfile::tempdir().unwrap();
            let paths = (0..n)
                .map(|authority| directory.path().join(format!("shadow-{authority}.wal")))
                .collect();
            Self {
                _directory: directory,
                committee,
                context,
                keyrings: mac_keyrings_for_test(n),
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
                ShadowWalSyncPolicyV1::EveryBatch,
            )
            .unwrap()
        }

        fn start_autonomous(
            &self,
            authority: AuthorityIndex,
        ) -> (
            StarfishRbcDagShadowServiceHandleV1,
            mpsc::Receiver<ShadowServiceEventV1>,
            JoinHandle<()>,
        ) {
            self.start_autonomous_with_interval(authority, Duration::from_secs(60 * 60))
        }

        fn start_autonomous_with_interval(
            &self,
            authority: AuthorityIndex,
            heartbeat_interval: Duration,
        ) -> (
            StarfishRbcDagShadowServiceHandleV1,
            mpsc::Receiver<ShadowServiceEventV1>,
            JoinHandle<()>,
        ) {
            self.start_autonomous_with_policy(
                authority,
                heartbeat_interval,
                ShadowWalSyncPolicyV1::EveryBatch,
            )
        }

        fn start_autonomous_with_policy(
            &self,
            authority: AuthorityIndex,
            heartbeat_interval: Duration,
            wal_sync_policy: ShadowWalSyncPolicyV1,
        ) -> (
            StarfishRbcDagShadowServiceHandleV1,
            mpsc::Receiver<ShadowServiceEventV1>,
            JoinHandle<()>,
        ) {
            start_starfish_rbc_dag_autonomous_clock_service_v1(
                &self.paths[authority as usize],
                self.committee.clone(),
                authority,
                self.context,
                ShadowAuthorizerV1::MacVector(self.keyrings[authority as usize].clone()),
                Vec::new(),
                heartbeat_interval,
                wal_sync_policy,
            )
            .unwrap()
        }

        fn start_autonomous_paused_with_interval(
            &self,
            authority: AuthorityIndex,
            heartbeat_interval: Duration,
        ) -> (
            StarfishRbcDagShadowServiceHandleV1,
            mpsc::Receiver<ShadowServiceEventV1>,
            JoinHandle<()>,
        ) {
            start_starfish_rbc_dag_shadow_service_with_mode_v1(
                &self.paths[authority as usize],
                self.committee.clone(),
                authority,
                self.context,
                ShadowAuthorizerV1::MacVector(self.keyrings[authority as usize].clone()),
                Vec::new(),
                ShadowServiceModeV1::AutonomousClock { heartbeat_interval },
                None,
                ShadowWalSyncPolicyV1::EveryBatch,
                None,
                None,
                false,
                false,
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
                application_payload: None,
            }
        }
    }

    fn standalone_autonomous_state(
        core: StarfishRbcDagShadowV1,
        committee: RbcDagCommitteeContextV1,
        leader_timeout: Duration,
    ) -> (
        ShadowServiceStateV1,
        mpsc::Receiver<ShadowServiceEventV1>,
        mpsc::Receiver<ShadowServiceMessageV1>,
        mpsc::Sender<ShadowServiceMessageV1>,
    ) {
        let slot = core.next_local_consensus_round();
        let committee_size = committee.committee().len();
        let (event_tx, event_rx) = mpsc::channel(128);
        let (message_tx, message_rx) = mpsc::channel(8);
        let (clock_activation_tx, _clock_activation_rx) = watch::channel(true);
        let (normal_carrier_deadline_tx, _normal_carrier_deadline_rx) = watch::channel(None);
        let (consensus_timeout_deadline_tx, consensus_timeout_deadline_rx) = watch::channel(None);
        spawn_consensus_timeout_deadline_task(
            consensus_timeout_deadline_rx,
            message_tx.downgrade(),
        );
        let state = ShadowServiceStateV1 {
            core,
            committee,
            mode: ShadowServiceModeV1::AutonomousClock {
                heartbeat_interval: leader_timeout,
            },
            clock_active: true,
            clock_activation_tx,
            wal_sync_policy: ShadowWalSyncPolicyV1::EveryBatch,
            metrics: None,
            own_authority: 0,
            committee_size,
            events: event_tx,
            connected: BTreeSet::new(),
            catch_up_hint_high_water: BTreeMap::new(),
            far_future_hint_high_water: BTreeMap::new(),
            desired_topology: Arc::new(Mutex::new(BTreeMap::new())),
            desired_local_applications: Arc::new(Mutex::new(BTreeMap::new())),
            desired_carrier_sync_responses: Arc::new(Mutex::new(BTreeMap::new())),
            desired_verified_application_payloads: Arc::new(Mutex::new(BTreeMap::new())),
            desired_direct_deliveries: Arc::new(Mutex::new(BTreeSet::new())),
            desired_available_applications: Arc::new(Mutex::new(BTreeSet::new())),
            observed_topology: BTreeMap::new(),
            invalidated_by_overload: Arc::new(Mutex::new(None)),
            pending_local: BTreeMap::new(),
            assigned_applications: BTreeSet::new(),
            pending_data_availability: BTreeSet::new(),
            pending_recovery: BTreeMap::new(),
            recovery_last_attempt: BTreeMap::new(),
            sync_last_attempt: BTreeMap::new(),
            sync_last_served: BTreeMap::new(),
            authorized_applications: BTreeMap::new(),
            quarantined_application_payloads: BTreeMap::new(),
            payload_last_served: BTreeMap::new(),
            sync_round: 1,
            sync_round_opened_at: Instant::now(),
            sync_catch_up: false,
            sync_catch_up_limit_future: false,
            sync_catch_up_target: None,
            sync_max_outstanding: 0,
            sync_max_desired_responses: 0,
            awaiting_application_submission: false,
            application_submission_deadline: None,
            consensus_pacemaker: ConsensusPacemakerV1::new(slot),
            consensus_timeout: leader_timeout,
            // Existing state-level tests invoke creation synchronously and do
            // not run the service deadline task. Keep their historical
            // immediate behavior unless a pacer test overrides this field.
            normal_carrier_min_spacing: Duration::ZERO,
            normal_carrier_next_allowed_at: None,
            normal_carrier_requested: false,
            normal_carrier_generation: 0,
            normal_carrier_deadline: None,
            normal_carrier_deadline_tx,
            consensus_timeout_generation: 0,
            consensus_timeout_deadline: None,
            consensus_timeout_deadline_tx,
            retry_notification_pending: Arc::new(AtomicBool::new(false)),
            heartbeat_notification_pending: Arc::new(AtomicBool::new(false)),
            direct_deliveries: BTreeSet::new(),
            reported_shadow_deliveries: BTreeSet::new(),
            reported_application_deliveries: BTreeSet::new(),
            recovered_shadow_deliveries: BTreeSet::new(),
            comparison_backlog: ShadowComparisonBacklogV1::new(BTreeSet::new()),
            reported_matches: BTreeSet::new(),
            reported_mismatches: BTreeSet::new(),
            reported_conflicts: BTreeSet::new(),
            fatal: false,
        };
        (state, event_rx, message_rx, message_tx)
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
                ShadowServiceEventV1::Ready { .. } => return,
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("shadow startup failed: {error}")
                }
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn recovered_control_frontier_precedes_ready_and_clock_activation() {
        let harness = Harness::new();
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let (mut state, mut events, _messages, _message_tx) =
            standalone_autonomous_state(core, harness.committee.clone(), Duration::from_secs(60));
        state.clock_active = false;
        let delta = CommittedFrontierDeltaV1 {
            output_sequence: 1,
            anchor: ConsensusVertexReference::new(BlockReference::new_test(1, 10), 7),
            frontier: vec![None; harness.committee.committee().len()],
            carriers: Vec::new(),
            applications: Vec::new(),
            application_diagnostics: Vec::new(),
        };
        let report =
            ShadowOpenReportV1::with_recovered_committed_frontiers_for_test(vec![delta.clone()]);

        state = tokio::task::spawn_blocking(move || {
            state.emit_autonomous_recovery_and_ready(&report);
            state
        })
        .await
        .unwrap();
        assert!(matches!(
            next_event(&mut events).await,
            ShadowServiceEventV1::FrontierCommitted(actual) if actual == delta
        ));
        loop {
            match next_event(&mut events).await {
                ShadowServiceEventV1::Ready {
                    autonomous_clock: true,
                } => break,
                ShadowServiceEventV1::PendingRecovery(_)
                | ShadowServiceEventV1::ClockState { .. } => {}
                unexpected => panic!("unexpected recovery-prefix event: {unexpected:?}"),
            }
        }
        assert!(events.try_recv().is_err());

        state = tokio::task::spawn_blocking(move || {
            state.activate_clock();
            state
        })
        .await
        .unwrap();
        assert!(matches!(
            next_event(&mut events).await,
            ShadowServiceEventV1::ClockActivated
        ));
        state.core.shutdown().unwrap();
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

    #[allow(clippy::too_many_arguments)]
    async fn pump_autonomous_until_round(
        handles: &[StarfishRbcDagShadowServiceHandleV1],
        events: &mut [mpsc::Receiver<ShadowServiceEventV1>],
        open_rounds: &mut [RoundNumber],
        deliveries: &mut [usize],
        application_deliveries: &mut [BTreeSet<BlockReference>],
        committed_frontiers: &mut [Vec<CommittedFrontierDeltaV1>],
        sync_requests: &mut usize,
        projected_vertices: &mut usize,
        projected_decisions: &mut usize,
        max_buffered_authenticated: &mut usize,
        rejections: &mut Vec<String>,
        target_open_round: RoundNumber,
        pump_timeout: Duration,
    ) {
        timeout(pump_timeout, async {
            let mut pending_network = VecDeque::new();
            loop {
                let mut progressed = false;
                for sender in 0..events.len() {
                    // Route at most one event per node per pass. Draining one
                    // sender completely can fill a target actor while that
                    // target is blocked publishing into its own bounded event
                    // channel, creating a test-router cycle absent from the
                    // independent production bridges.
                    if let Ok(event) = events[sender].try_recv() {
                        progressed = true;
                        match event {
                            ShadowServiceEventV1::Network { recipient, message } => {
                                let recipient = recipient as usize;
                                let service_message = match message {
                                    NetworkMessage::RbcDagShadowCarrier(envelope) => {
                                        ShadowServiceMessageV1::Carrier {
                                            peer: sender as AuthorityIndex,
                                            envelope,
                                        }
                                    }
                                    NetworkMessage::RbcDagShadowCarrierRequest(reference) => {
                                        ShadowServiceMessageV1::CarrierRequest {
                                            peer: sender as AuthorityIndex,
                                            reference,
                                        }
                                    }
                                    NetworkMessage::RbcDagShadowCarrierResponse(response) => {
                                        ShadowServiceMessageV1::CarrierResponse {
                                            peer: sender as AuthorityIndex,
                                            response,
                                        }
                                    }
                                    NetworkMessage::RbcDagShadowCarrierEnvelopeResponse(
                                        response,
                                    ) => ShadowServiceMessageV1::CarrierEnvelopeResponse {
                                        peer: sender as AuthorityIndex,
                                        response,
                                    },
                                    NetworkMessage::RbcDagShadowCarrierSyncRequest(request) => {
                                        *sync_requests = sync_requests.saturating_add(1);
                                        ShadowServiceMessageV1::CarrierSyncRequest {
                                            peer: sender as AuthorityIndex,
                                            request,
                                        }
                                    }
                                    NetworkMessage::RbcDagShadowCarrierSyncResponse(response) => {
                                        handles[recipient]
                                            .carrier_sync_response(
                                                sender as AuthorityIndex,
                                                response,
                                            )
                                            .unwrap();
                                        continue;
                                    }
                                    NetworkMessage::RbcDagApplicationPayloadRequest(application) => {
                                        ShadowServiceMessageV1::ApplicationPayloadRequest {
                                            peer: sender as AuthorityIndex,
                                            application,
                                        }
                                    }
                                    NetworkMessage::RbcDagApplicationPayloadResponse(response) => {
                                        ShadowServiceMessageV1::ApplicationPayloadResponse {
                                            peer: sender as AuthorityIndex,
                                            response,
                                        }
                                    }
                                    unexpected => panic!(
                                        "autonomous shadow emitted unexpected network message: {unexpected:?}"
                                    ),
                                };
                                pending_network.push_back((recipient, service_message));
                            }
                            ShadowServiceEventV1::ClockState {
                                open_round,
                                buffered_authenticated,
                                ..
                            } => {
                                open_rounds[sender] = open_rounds[sender].max(open_round);
                                *max_buffered_authenticated =
                                    (*max_buffered_authenticated).max(buffered_authenticated);
                            }
                            ShadowServiceEventV1::Delivered(_) => {
                                deliveries[sender] = deliveries[sender].saturating_add(1);
                            }
                            ShadowServiceEventV1::EmbeddedApplicationDelivered {
                                header,
                                ..
                            } => {
                                application_deliveries[sender].insert(header.reference());
                            }
                            ShadowServiceEventV1::AuthorizedApplicationObserved {
                                header,
                                payload,
                                ..
                            } => {
                                let reference = header.reference();
                                if let Some(payload) = payload {
                                    handles[sender]
                                        .verified_application_payload(reference, payload)
                                        .unwrap();
                                }
                                // The production bridge emits availability
                                // only after the typed header (and optional
                                // payload) is concretely installed in Core.
                                handles[sender].application_data_available(reference).unwrap();
                            }
                            ShadowServiceEventV1::VertexProjected(_) => {
                                *projected_vertices = projected_vertices.saturating_add(1);
                            }
                            ShadowServiceEventV1::LeaderDecided(_) => {
                                *projected_decisions = projected_decisions.saturating_add(1);
                            }
                            ShadowServiceEventV1::FrontierCommitted(delta) => {
                                committed_frontiers[sender].push(delta);
                            }
                            ShadowServiceEventV1::Rejected { error, .. }
                                if error.contains("unexpected shadow response") =>
                            {
                                rejections.push(error);
                            }
                            ShadowServiceEventV1::Rejected { error, .. } => {
                                rejections.push(error.clone());
                                panic!("autonomous shadow rejected valid test traffic: {error}")
                            }
                            _ => {}
                        }
                    }
                }
                let pending = pending_network.len();
                for _ in 0..pending {
                    let (recipient, message) = pending_network
                        .pop_front()
                        .expect("pending network length was captured");
                    match handles[recipient].sender.try_send(message) {
                        Ok(()) => progressed = true,
                        Err(TrySendError::Full(message)) => {
                            pending_network.push_back((recipient, message));
                        }
                        Err(TrySendError::Closed(_)) => {
                            panic!("autonomous shadow target actor stopped")
                        }
                    }
                }
                if open_rounds
                    .iter()
                    .all(|round| *round >= target_open_round)
                    && pending_network.is_empty()
                {
                    return;
                }
                if !progressed {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                } else {
                    tokio::task::yield_now().await;
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "autonomous clock did not open round {target_open_round}; open={open_rounds:?}, sync_requests={sync_requests}"
            )
        });
    }

    async fn pump_online_prefix_until_round(
        handles: &[StarfishRbcDagShadowServiceHandleV1],
        events: &mut [mpsc::Receiver<ShadowServiceEventV1>],
        open_rounds: &mut [RoundNumber],
        online: usize,
        target_open_round: RoundNumber,
    ) {
        timeout(EVENT_TIMEOUT, async {
            loop {
                let mut progressed = false;
                for sender in 0..events.len() {
                    while let Ok(event) = events[sender].try_recv() {
                        progressed = true;
                        match event {
                            ShadowServiceEventV1::Network { recipient, message }
                                if sender < online && (recipient as usize) < online =>
                            {
                                let recipient = recipient as usize;
                                match message {
                                    NetworkMessage::RbcDagShadowCarrier(envelope) => handles
                                        [recipient]
                                        .carrier(sender as AuthorityIndex, envelope)
                                        .unwrap(),
                                    NetworkMessage::RbcDagShadowCarrierRequest(reference) => handles
                                        [recipient]
                                        .carrier_request(sender as AuthorityIndex, reference)
                                        .unwrap(),
                                    NetworkMessage::RbcDagShadowCarrierResponse(response) => handles
                                        [recipient]
                                        .carrier_response(sender as AuthorityIndex, response)
                                        .unwrap(),
                                    NetworkMessage::RbcDagShadowCarrierEnvelopeResponse(
                                        response,
                                    ) => handles[recipient]
                                        .carrier_envelope_response(
                                            sender as AuthorityIndex,
                                            response,
                                        )
                                        .unwrap(),
                                    NetworkMessage::RbcDagShadowCarrierSyncRequest(request) => {
                                        handles[recipient]
                                            .carrier_sync_request(
                                                sender as AuthorityIndex,
                                                request,
                                            )
                                            .unwrap();
                                    }
                                    NetworkMessage::RbcDagShadowCarrierSyncResponse(response) => {
                                        handles[recipient]
                                            .carrier_sync_response(
                                                sender as AuthorityIndex,
                                                response,
                                            )
                                            .unwrap();
                                    }
                                    NetworkMessage::RbcDagApplicationPayloadRequest(application) => {
                                        handles[recipient]
                                            .application_payload_request(
                                                sender as AuthorityIndex,
                                                application,
                                            )
                                            .unwrap();
                                    }
                                    NetworkMessage::RbcDagApplicationPayloadResponse(response) => {
                                        handles[recipient]
                                            .application_payload_response(
                                                sender as AuthorityIndex,
                                                response,
                                            )
                                            .unwrap();
                                    }
                                    unexpected => panic!(
                                        "autonomous shadow emitted unexpected network message: {unexpected:?}"
                                    ),
                                }
                            }
                            ShadowServiceEventV1::Network { .. } => {}
                            ShadowServiceEventV1::ClockState { open_round, .. } => {
                                open_rounds[sender] = open_rounds[sender].max(open_round);
                            }
                            ShadowServiceEventV1::AuthorizedApplicationObserved {
                                header,
                                payload,
                                ..
                            } => {
                                let reference = header.reference();
                                if let Some(payload) = payload {
                                    handles[sender]
                                        .verified_application_payload(reference, payload)
                                        .unwrap();
                                }
                                handles[sender].application_data_available(reference).unwrap();
                            }
                            ShadowServiceEventV1::Rejected { error, .. } => {
                                panic!("autonomous shadow rejected valid test traffic: {error}")
                            }
                            _ => {}
                        }
                    }
                }
                if open_rounds[..online]
                    .iter()
                    .all(|round| *round >= target_open_round)
                {
                    return;
                }
                if !progressed {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                } else {
                    tokio::task::yield_now().await;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("online prefix did not open round {target_open_round}"));
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
                ShadowServiceEventV1::Ready { .. } => {
                    panic!("invalid shadow startup became ready")
                }
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

    fn application_header_and_payload(
        author: AuthorityIndex,
        round: RoundNumber,
        marker: u8,
        committee: &RbcDagCommitteeContextV1,
    ) -> (RbcCanonicalHeader, Arc<TransactionData>) {
        let payload = Arc::new(TransactionData::new(vec![BaseTransaction::Share(
            Transaction::new(vec![marker; 64]),
        )]));
        let info_length = committee.committee().info_length();
        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let encoded = encoder.encode_transactions(
            payload.transactions(),
            info_length,
            committee.committee().len() - info_length,
        );
        let commitment =
            TransactionsCommitment::new_from_encoded_transactions(&encoded, author as usize).0;
        let header = RbcCanonicalHeader::try_new(
            author,
            round,
            committee
                .committee()
                .authorities()
                .map(|authority| *VerifiedBlock::new_genesis(authority).reference())
                .collect(),
            Vec::new(),
            u64::from(round) * 1_000 + u64::from(marker),
            commitment,
        )
        .unwrap();
        (header, payload)
    }

    fn round_one_application_candidate(
        author: AuthorityIndex,
        application_header: RbcCanonicalHeader,
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
                transactions_commitment: application_header.transactions_commitment(),
                application_header: Some(application_header),
                data_acknowledgments: Vec::new(),
                phase_batch: Vec::new(),
                consensus_vertex: None,
                creation_time_ns: u64::from(marker),
            },
            committee,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn far_future_application_is_ignored_before_authentication_or_payload_observation() {
        let harness = Harness::new();
        let (header, payload) = application_header_and_payload(0, 1, 0xC0, &harness.committee);
        let previous = |authority: AuthorityIndex| BlockReference {
            authority,
            round: 65,
            digest: BlockDigest::from([0xC0 + authority as u8; 32]),
        };
        let candidate = CandidateCarrierV1::try_new_with_committee(
            CarrierHeaderV1Args {
                author: 0,
                carrier_round: 66,
                own_prev: previous(0),
                weak_parents: [1, 2].into_iter().map(previous).collect(),
                transactions_commitment: header.transactions_commitment(),
                application_header: Some(header),
                data_acknowledgments: Vec::new(),
                phase_batch: Vec::new(),
                consensus_vertex: None,
                creation_time_ns: 66,
            },
            &harness.committee,
        )
        .unwrap();
        let (receiver, mut events, task) = harness.start_autonomous(1);
        wait_ready(&mut events).await;
        receiver.peer_connected(0).unwrap();
        loop {
            if let ShadowServiceEventV1::Network {
                recipient: 0,
                message: NetworkMessage::RbcDagShadowCarrierSyncRequest(request),
            } = next_event(&mut events).await
            {
                assert_eq!((request.author, request.round), (0, 1));
                break;
            }
        }
        tokio::time::sleep(SHADOW_CARRIER_SYNC_RETRY_INTERVAL_V1).await;
        receiver
            .carrier(
                0,
                RbcDagShadowCarrier {
                    canonical_carrier: candidate.canonical_wire_bytes().unwrap(),
                    authentication_sidecar: vec![0xff],
                    application_payload: Some(payload),
                },
            )
            .unwrap();

        let mut ignored = false;
        let mut repair_requested = false;
        while !ignored || !repair_requested {
            match next_event(&mut events).await {
                ShadowServiceEventV1::Input {
                    kind: "carrier",
                    outcome: "future_ignored",
                } => ignored = true,
                ShadowServiceEventV1::Network {
                    recipient: 0,
                    message: NetworkMessage::RbcDagShadowCarrierSyncRequest(request),
                } => {
                    assert_eq!((request.author, request.round), (0, 1));
                    repair_requested = true;
                }
                ShadowServiceEventV1::AuthorizedApplicationObserved { .. } => {
                    panic!("far-future application was observed")
                }
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("far-future application was rejected instead of ignored: {error}")
                }
                _ => {}
            }
        }
        stop(receiver, events, task).await;
    }

    #[tokio::test]
    async fn initial_payload_fanout_and_authenticated_observation_are_exact() {
        let harness = Harness::new();
        let (header, payload) = application_header_and_payload(0, 1, 0xC1, &harness.committee);

        let (author, mut author_events, author_task) = harness.start_autonomous(0);
        wait_ready(&mut author_events).await;
        author
            .local_application(&header, Some(Arc::clone(&payload)))
            .unwrap();
        let mut assigned = false;
        let mut locally_authorized = false;
        let initial = loop {
            match next_event(&mut author_events).await {
                ShadowServiceEventV1::ApplicationAssigned(reference)
                    if reference == header.reference() =>
                {
                    assigned = true;
                }
                ShadowServiceEventV1::AuthorizedApplicationObserved {
                    header: observed,
                    authorization_basis: ShadowApplicationAuthorizationBasisV1::LocallyFixed,
                    ..
                } if observed == header => {
                    assert!(
                        assigned,
                        "producer gate must be released before materialization"
                    );
                    locally_authorized = true;
                }
                ShadowServiceEventV1::Network {
                    recipient: 1,
                    message: NetworkMessage::RbcDagShadowCarrier(initial),
                } => {
                    assert!(locally_authorized);
                    break initial;
                }
                _ => {}
            }
        };
        assert!(initial.application_payload.is_some());
        let candidate = CandidateCarrierV1::decode_wire_with_committee(
            &initial.canonical_carrier,
            &harness.committee,
            None,
        )
        .unwrap();
        assert_eq!(
            candidate
                .header()
                .application_header()
                .map(RbcCanonicalHeader::reference),
            Some(header.reference())
        );

        let (receiver, mut receiver_events, receiver_task) = harness.start_autonomous(1);
        wait_ready(&mut receiver_events).await;
        receiver.carrier(0, initial).unwrap();
        loop {
            match next_event(&mut receiver_events).await {
                ShadowServiceEventV1::AuthorizedApplicationObserved {
                    carrier,
                    header: observed,
                    payload: Some(observed_payload),
                    authorization_basis:
                        ShadowApplicationAuthorizationBasisV1::ReceiverAuthenticated,
                } => {
                    assert_eq!(carrier, candidate.reference());
                    assert_eq!(observed, header);
                    assert!(application_payloads_equal(
                        Some(observed_payload.as_ref()),
                        Some(payload.as_ref())
                    ));
                    break;
                }
                ShadowServiceEventV1::Delivered(_) => {
                    panic!("fresh receiver authentication should stage before delivery")
                }
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("valid authenticated application was rejected: {error}")
                }
                _ => {}
            }
        }
        stop(author, author_events, author_task).await;
        stop(receiver, receiver_events, receiver_task).await;
    }

    #[tokio::test]
    async fn authorized_empty_application_never_requests_payload_across_retries() {
        let harness = Harness::new();
        let header = RbcCanonicalHeader::try_new(
            0,
            1,
            harness
                .committee
                .committee()
                .authorities()
                .map(|authority| *VerifiedBlock::new_genesis(authority).reference())
                .collect(),
            Vec::new(),
            1_001,
            TransactionsCommitment::default(),
        )
        .unwrap();
        let candidate =
            round_one_application_candidate(0, header.clone(), &harness.committee, 0xC4);

        let (receiver, mut events, task) = harness.start_autonomous(1);
        wait_ready(&mut events).await;
        receiver.peer_connected(0).unwrap();
        receiver
            .carrier(0, harness.envelope(&candidate, 0))
            .unwrap();

        let mut authorized = false;
        let deadline =
            Instant::now() + SHADOW_APPLICATION_PAYLOAD_RETRY_INTERVAL_V1.saturating_mul(3);
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let event = match timeout(remaining, events.recv()).await {
                Ok(Some(event)) => event,
                Ok(None) => panic!("shadow actor stopped while checking empty application"),
                Err(_) => break,
            };
            match event {
                ShadowServiceEventV1::AuthorizedApplicationObserved {
                    header: observed,
                    payload: None,
                    authorization_basis:
                        ShadowApplicationAuthorizationBasisV1::ReceiverAuthenticated,
                    ..
                } if observed == header => {
                    authorized = true;
                    receiver
                        .application_data_available(header.reference())
                        .expect("empty authorized application must accept the DA callback");
                }
                ShadowServiceEventV1::Network {
                    message: NetworkMessage::RbcDagApplicationPayloadRequest(application),
                    ..
                } if application == header.reference() => {
                    panic!("empty authorized application must not request payload bytes")
                }
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("empty authorized application was rejected: {error}")
                }
                _ => {}
            }
        }
        assert!(authorized, "empty application header was not authorized");
        stop(receiver, events, task).await;
    }

    #[tokio::test]
    async fn authorized_payload_recovery_is_peer_bound_verified_and_coalesced() {
        let harness = Harness::new();
        let (header, payload) = application_header_and_payload(0, 1, 0xC4, &harness.committee);
        let candidate =
            round_one_application_candidate(0, header.clone(), &harness.committee, 0xC5);
        let envelope = harness.envelope(&candidate, 0);

        let (receiver, mut events, task) = harness.start_autonomous(1);
        wait_ready(&mut events).await;
        receiver.peer_connected(0).unwrap();
        receiver.peer_connected(2).unwrap();
        receiver.carrier(0, envelope).unwrap();

        let mut observed_header = false;
        let mut requested = false;
        while !observed_header || !requested {
            match next_event(&mut events).await {
                ShadowServiceEventV1::AuthorizedApplicationObserved {
                    header: observed,
                    payload: None,
                    authorization_basis:
                        ShadowApplicationAuthorizationBasisV1::ReceiverAuthenticated,
                    ..
                } if observed == header => observed_header = true,
                ShadowServiceEventV1::Network {
                    recipient: 0,
                    message: NetworkMessage::RbcDagApplicationPayloadRequest(application),
                } if application == header.reference() => requested = true,
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("authorized header-only carrier was rejected: {error}")
                }
                _ => {}
            }
        }

        receiver
            .application_payload_response(
                2,
                RbcDagApplicationPayloadResponse {
                    application: header.reference(),
                    transaction_data: Arc::clone(&payload),
                },
            )
            .unwrap();
        loop {
            if let ShadowServiceEventV1::Rejected {
                peer: Some(2),
                error,
            } = next_event(&mut events).await
            {
                assert!(error.contains("unrequested authority"));
                break;
            }
        }

        receiver
            .application_payload_response(
                0,
                RbcDagApplicationPayloadResponse {
                    application: header.reference(),
                    transaction_data: Arc::clone(&payload),
                },
            )
            .unwrap();
        loop {
            if let ShadowServiceEventV1::AuthorizedApplicationObserved {
                header: observed,
                payload: Some(observed_payload),
                ..
            } = next_event(&mut events).await
            {
                assert_eq!(observed, header);
                assert!(application_payloads_equal(
                    Some(observed_payload.as_ref()),
                    Some(payload.as_ref())
                ));
                break;
            }
        }

        receiver
            .application_payload_response(
                0,
                RbcDagApplicationPayloadResponse {
                    application: header.reference(),
                    transaction_data: Arc::clone(&payload),
                },
            )
            .unwrap();
        receiver
            .verified_application_payload(header.reference(), Arc::clone(&payload))
            .unwrap();
        receiver
            .application_payload_request(2, header.reference())
            .unwrap();
        loop {
            match next_event(&mut events).await {
                ShadowServiceEventV1::Network {
                    recipient: 2,
                    message: NetworkMessage::RbcDagApplicationPayloadResponse(response),
                } => {
                    assert_eq!(response.application, header.reference());
                    assert!(application_payloads_equal(
                        Some(response.transaction_data.as_ref()),
                        Some(payload.as_ref())
                    ));
                    break;
                }
                ShadowServiceEventV1::AuthorizedApplicationObserved {
                    payload: Some(_), ..
                } => panic!("duplicate payload response emitted duplicate application work"),
                _ => {}
            }
        }
        receiver
            .application_payload_request(2, header.reference())
            .unwrap();
        loop {
            if let ShadowServiceEventV1::Input {
                kind: "application_payload_request",
                outcome: "rate_limited",
            } = next_event(&mut events).await
            {
                break;
            }
        }
        stop(receiver, events, task).await;
    }

    #[tokio::test]
    async fn application_and_quarantine_maps_remain_bounded() {
        let harness = Harness::new();
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let (state, _events, _message_rx, _message_tx) = standalone_autonomous_state(
            core,
            harness.committee.clone(),
            Duration::from_secs(60 * 60),
        );
        tokio::task::spawn_blocking(move || {
            let mut state = state;
            let capacity = shadow_application_payload_capacity(N);
            for offset in 0..=capacity {
                let round = offset as RoundNumber + 1;
                let header = direct_header(0, round, offset as u8);
                state
                    .authorize_application(
                        BlockReference::new_test(0, 1_000 + round),
                        header,
                        None,
                        false,
                        None,
                        ShadowApplicationAuthorizationBasisV1::Delivered,
                    )
                    .unwrap();
            }
            assert_eq!(state.authorized_applications.len(), capacity);

            for offset in 0..=capacity {
                let round = offset as RoundNumber + 1;
                state
                    .quarantine_application(
                        BlockReference::new_test(1, 2_000 + round),
                        BlockReference::new_test(1, round),
                        1,
                        None,
                    )
                    .unwrap();
            }
            assert_eq!(state.quarantined_application_payloads.len(), capacity);
            state.core.shutdown().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn delayed_verified_payload_for_evicted_application_is_stale_not_rejected() {
        let harness = Harness::new();
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let (state, mut events, _message_rx, _message_tx) = standalone_autonomous_state(
            core,
            harness.committee.clone(),
            Duration::from_secs(60 * 60),
        );
        tokio::task::spawn_blocking(move || {
            let mut state = state;
            let mut applications = Vec::new();
            for offset in 0..=shadow_application_payload_capacity(N) {
                let round = offset as RoundNumber + 1;
                let header = direct_header(0, round, offset as u8);
                applications.push(header.reference());
                state
                    .authorize_application(
                        BlockReference::new_test(0, 3_000 + round),
                        header,
                        None,
                        false,
                        None,
                        ShadowApplicationAuthorizationBasisV1::Delivered,
                    )
                    .unwrap();
            }
            let evicted = applications
                .into_iter()
                .find(|application| !state.authorized_applications.contains_key(application))
                .expect("one authorized application must be evicted at capacity plus one");
            let delayed_payload = Arc::new(TransactionData::new(vec![BaseTransaction::Share(
                Transaction::new(vec![0xD3; 64]),
            )]));
            state
                .desired_verified_application_payloads
                .lock()
                .insert(evicted, delayed_payload);
            state.reconcile_verified_application_payloads();
            assert!(
                state
                    .desired_verified_application_payloads
                    .lock()
                    .is_empty()
            );
            assert!(!state.fatal);
            state.core.shutdown().unwrap();
        })
        .await
        .unwrap();

        let mut observed_stale = false;
        while let Ok(event) = events.try_recv() {
            match event {
                ShadowServiceEventV1::Input {
                    kind: "verified_application_payload",
                    outcome: "stale_ignored",
                } => observed_stale = true,
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("delayed verified callback was rejected: {error}")
                }
                _ => {}
            }
        }
        assert!(observed_stale, "stale callback outcome was not reported");
    }

    #[tokio::test]
    async fn delayed_payload_response_for_evicted_application_is_stale_not_rejected() {
        let harness = Harness::new();
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let (state, mut events, _message_rx, _message_tx) = standalone_autonomous_state(
            core,
            harness.committee.clone(),
            Duration::from_secs(60 * 60),
        );
        tokio::task::spawn_blocking(move || {
            let mut state = state;
            let evicted = BlockReference::new_test(1, 1);
            let payload = Arc::new(TransactionData::new(vec![BaseTransaction::Share(
                Transaction::new(vec![0xD4; 64]),
            )]));
            state
                .handle_application_payload_response(
                    1,
                    RbcDagApplicationPayloadResponse {
                        application: evicted,
                        transaction_data: payload,
                    },
                )
                .expect("late network completion must be an idempotent stale observation");
            assert!(!state.fatal);
            state.core.shutdown().unwrap();
        })
        .await
        .unwrap();

        let mut observed_stale = false;
        while let Ok(event) = events.try_recv() {
            match event {
                ShadowServiceEventV1::Input {
                    kind: "application_payload_response",
                    outcome: "stale_ignored",
                } => observed_stale = true,
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("delayed payload response was rejected: {error}")
                }
                _ => {}
            }
        }
        assert!(
            observed_stale,
            "stale network response outcome was not reported"
        );
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
                application_header: None,
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn instrumented_autonomous_service_records_assignment_and_queue_state() {
        let harness = Harness::new();
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(&registry, None, None, None);
        metrics.metrics_active.store(true, Ordering::Relaxed);
        let (handle, mut events, task) =
            start_starfish_rbc_dag_autonomous_clock_service_with_metrics_v1(
                &harness.paths[0],
                harness.committee.clone(),
                0,
                harness.context,
                ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
                Vec::new(),
                Duration::from_secs(60 * 60),
                ShadowWalSyncPolicyV1::EveryBatch,
                Arc::clone(&metrics),
            )
            .unwrap();
        wait_ready(&mut events).await;

        let application = direct_header(0, 1, 0xA1);
        handle.local_header(&application).unwrap();
        let mut application_assigned = false;
        timeout(EVENT_TIMEOUT, async {
            loop {
                match events.recv().await {
                    Some(ShadowServiceEventV1::ApplicationAssigned(reference)) => {
                        application_assigned = true;
                        assert_eq!(reference, application.reference());
                    }
                    Some(ShadowServiceEventV1::Network {
                        recipient: 1,
                        message: NetworkMessage::RbcDagShadowCarrier(_),
                    }) => {
                        assert!(
                            application_assigned,
                            "the local producer gate must be released before network fan-out"
                        );
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("carrier transition did not publish its assignment and network events");
        assert!(application_assigned);
        assert_eq!(
            metrics
                .starfish_rbc_dag_pipeline_latency_samples_total
                .with_label_values(&[RBC_DAG_LATENCY_CREATION_TO_ASSIGNMENT])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_pipeline_queue_depth
                .with_label_values(&["local"])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_pipeline_queue_depth_max
                .with_label_values(&["local"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_projection_hol_state
                .with_label_values(&["insufficient_lookahead"])
                .get(),
            1
        );

        stop(handle, events, task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recovered_application_assignment_does_not_release_a_live_producer_gate() {
        let harness = Harness::new();
        let application = direct_header(0, 1, 0xA2);
        let (handle, mut events, task) = start_starfish_rbc_dag_autonomous_clock_service_v1(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
            vec![application],
            Duration::from_secs(60 * 60),
            ShadowWalSyncPolicyV1::EveryBatch,
        )
        .unwrap();

        timeout(EVENT_TIMEOUT, async {
            loop {
                match events.recv().await {
                    Some(ShadowServiceEventV1::ApplicationAssigned(reference)) => panic!(
                        "recovered application {reference} has no live producer gate to release"
                    ),
                    Some(ShadowServiceEventV1::Network {
                        recipient: 1,
                        message: NetworkMessage::RbcDagShadowCarrier(_),
                    }) => break,
                    Some(ShadowServiceEventV1::Rejected { error, .. }) => {
                        panic!("recovered application was rejected: {error}")
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("recovered application was not assigned to the open carrier");

        stop(handle, events, task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_duplicate_upgrades_recovered_pending_application_to_exactly_one_ack() {
        let harness = Harness::new();
        let application = direct_header(0, 1, 0xA3);
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let (mut state, mut events, _message_rx, _message_tx) = standalone_autonomous_state(
            core,
            harness.committee.clone(),
            Duration::from_secs(60 * 60),
        );
        state.pending_local.insert(
            application.reference().round,
            ShadowLocalCarrierV1::from_recovered_direct_header(&application),
        );

        let expected_reference = application.reference();
        let state = tokio::task::spawn_blocking(move || {
            state.enqueue_local(ShadowLocalCarrierV1::from_direct_header(&application));
            assert!(
                state
                    .pending_local
                    .get(&application.reference().round)
                    .is_some_and(|pending| pending.acknowledge_assignment)
            );
            state.try_create_autonomous_carrier();
            state
        })
        .await
        .unwrap();
        let acknowledgments = std::iter::from_fn(|| events.try_recv().ok())
            .filter_map(|event| match event {
                ShadowServiceEventV1::ApplicationAssigned(reference) => Some(reference),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(acknowledgments, vec![expected_reference]);
        state.core.shutdown().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn application_submission_grace_is_anchored_bounded_and_coalesced() {
        let harness = Harness::new();
        let (core, _) = StarfishRbcDagShadowV1::open(
            &harness.paths[0],
            harness.committee.clone(),
            0,
            harness.context,
            ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
        )
        .unwrap();
        let (mut state, _events, _message_rx, _message_tx) = standalone_autonomous_state(
            core,
            harness.committee.clone(),
            Duration::from_secs(60 * 60),
        );

        let round = state.core.local_carrier_round();
        let deadline = Instant::now() + Duration::from_secs(60);
        state.awaiting_application_submission = true;
        state.application_submission_deadline = Some(deadline);
        state.retry_pending_local();
        assert_eq!(state.core.local_carrier_round(), round);
        assert_eq!(
            state
                .normal_carrier_deadline
                .expect("the grace must reuse the coalesced carrier wake")
                .deadline,
            deadline
        );

        let generation = state.normal_carrier_generation;
        state.retry_pending_local();
        assert_eq!(state.normal_carrier_generation, generation);
        state.application_submission_deadline = Some(Instant::now());
        state.retry_pending_local();
        assert!(!state.awaiting_application_submission);
        assert_eq!(state.application_submission_deadline, None);
        state.core.shutdown().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn paused_autonomous_clock_uses_one_idempotent_fresh_activation_epoch() {
        let harness = Harness::new();
        let heartbeat_interval = Duration::from_millis(120);
        let (handle, mut events, task) =
            harness.start_autonomous_paused_with_interval(0, heartbeat_interval);
        wait_ready(&mut events).await;

        // Neither the dormant timer nor an explicitly injected stale tick may
        // fix a carrier while the external coordinated-start barrier is shut.
        tokio::time::sleep(heartbeat_interval.saturating_mul(4)).await;
        handle.send(ShadowServiceMessageV1::HeartbeatTick).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let inspection = handle.inspect_carrier_sync().await.unwrap();
        assert_eq!(inspection.open_round, 1);
        while let Ok(event) = events.try_recv() {
            assert!(!matches!(event, ShadowServiceEventV1::ClockActivated));
            assert!(
                !matches!(event, ShadowServiceEventV1::Network { .. }),
                "paused autonomous clock emitted protocol network traffic: {event:?}"
            );
        }

        let activated_at = Instant::now();
        handle.activate_clock().await.unwrap();
        handle.activate_clock().await.unwrap();

        let mut activation_events = 0;
        let early_network = timeout(heartbeat_interval / 2, async {
            loop {
                match events.recv().await {
                    Some(ShadowServiceEventV1::ClockActivated) => activation_events += 1,
                    Some(ShadowServiceEventV1::Network { .. }) => return,
                    Some(ShadowServiceEventV1::Rejected { error, .. }) => {
                        panic!("activated clock rejected input: {error}")
                    }
                    Some(_) => {}
                    None => panic!("activated clock stopped before its first heartbeat"),
                }
            }
        })
        .await;
        assert!(
            early_network.is_err(),
            "activation inherited a stale heartbeat deadline"
        );
        assert_eq!(activation_events, 1, "activation was not idempotent");

        timeout(
            heartbeat_interval.saturating_mul(3),
            next_carrier(&mut events, 1),
        )
        .await
        .expect("fresh activation epoch did not produce its first heartbeat");
        assert!(
            activated_at.elapsed() >= heartbeat_interval.saturating_sub(Duration::from_millis(20)),
            "first heartbeat did not wait one fresh interval"
        );

        stop(handle, events, task).await;
    }

    async fn assert_autonomous_zero_load_progress(n: usize) {
        let harness = Harness::new_with_n(n);
        let mut handles = Vec::new();
        let mut events = Vec::new();
        let mut tasks = Vec::new();
        for authority in 0..n as AuthorityIndex {
            // Exercise the production 600 ms clock so the shared 30 ms
            // normal-carrier permit advances under real wall time. The test
            // still injects heartbeat triggers explicitly for determinism.
            let (handle, mut node_events, task) =
                harness.start_autonomous_with_interval(authority, Duration::from_millis(600));
            loop {
                match next_event(&mut node_events).await {
                    ShadowServiceEventV1::Ready { autonomous_clock } => {
                        assert!(autonomous_clock);
                        break;
                    }
                    ShadowServiceEventV1::Rejected { error, .. } => {
                        panic!("autonomous shadow startup failed: {error}")
                    }
                    _ => {}
                }
            }
            handles.push(handle);
            events.push(node_events);
            tasks.push(task);
        }

        let mut open_rounds = vec![1; n];
        let mut deliveries = vec![0; n];
        let mut application_deliveries = vec![BTreeSet::new(); n];
        let mut committed_frontiers = vec![Vec::new(); n];
        let mut sync_requests = 0;
        let mut projected_vertices = 0;
        let mut projected_decisions = 0;
        let mut max_buffered_authenticated = 0;
        let mut rejections = Vec::new();
        for (authority, handle) in handles.iter().enumerate() {
            for peer in 0..n {
                if peer != authority {
                    handle.peer_connected(peer as AuthorityIndex).unwrap();
                }
            }
        }
        for fixed_round in 1..=18 {
            for handle in &handles {
                handle.send(ShadowServiceMessageV1::HeartbeatTick).unwrap();
            }
            pump_autonomous_until_round(
                &handles,
                &mut events,
                &mut open_rounds,
                &mut deliveries,
                &mut application_deliveries,
                &mut committed_frontiers,
                &mut sync_requests,
                &mut projected_vertices,
                &mut projected_decisions,
                &mut max_buffered_authenticated,
                &mut rejections,
                fixed_round + 1,
                EVENT_TIMEOUT,
            )
            .await;
            if fixed_round == 2 {
                for (authority, handle) in handles.iter().enumerate() {
                    let (optimistic_promises, certified_deliveries) =
                        handle.inspect_rbc_progress().await.unwrap();
                    assert!(
                        optimistic_promises > 0,
                        "authority {authority} did not lock an optimistic ECHO promise by the round-two carrier"
                    );
                    assert_eq!(
                        certified_deliveries, 0,
                        "authority {authority} certified a carrier before the later READY round"
                    );
                }
            }
        }

        assert!(
            deliveries.iter().all(|count| *count > 0),
            "every node must RBC-deliver mature heartbeat carriers: {deliveries:?}"
        );
        assert!(open_rounds.iter().all(|round| *round >= 19));
        assert!(projected_vertices >= n * 3);
        assert!(
            committed_frontiers
                .iter()
                .all(|commits| !commits.is_empty()),
            "every node must commit at least one certified frontier: {committed_frontiers:?}"
        );
        assert!(
            projected_decisions > 0,
            "clean projection did not decide: vertices={projected_vertices}, rounds={open_rounds:?}"
        );
        assert_eq!(
            sync_requests,
            n * (n - 1),
            "each connection must repair exactly the round-one carrier fixed before topology registration"
        );

        drop(events);
        for handle in &handles {
            handle.shutdown().await.unwrap();
        }
        for task in tasks {
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn autonomous_application_header_wins_the_open_carrier_slot_and_uses_v2() {
        let harness = Harness::new();
        let (handle, mut events, task) = harness.start_autonomous(0);
        wait_ready(&mut events).await;
        let application = direct_header(0, 1, 0x6A);
        handle.local_header(&application).unwrap();

        let envelope = next_carrier(&mut events, 1).await;
        let candidate = CandidateCarrierV1::decode_wire_with_committee(
            &envelope.canonical_carrier,
            &harness.committee,
            None,
        )
        .unwrap();
        assert_eq!(candidate.header().carrier_round(), 1);
        assert_eq!(candidate.header().application_header(), Some(&application));
        assert_eq!(
            envelope.canonical_carrier[1],
            crate::starfish_rbc_dag::CARRIER_WIRE_FORMAT_VERSION_V2
        );

        handle.shutdown().await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn embedded_rbc_delivers_every_application_header_from_the_carrier_dag() {
        let harness = Harness::new();
        let mut handles = Vec::new();
        let mut events = Vec::new();
        let mut tasks = Vec::new();
        for authority in 0..N as AuthorityIndex {
            let (handle, mut node_events, task) =
                harness.start_autonomous_with_interval(authority, Duration::from_millis(600));
            wait_ready(&mut node_events).await;
            handles.push(handle);
            events.push(node_events);
            tasks.push(task);
        }
        for (authority, handle) in handles.iter().enumerate() {
            for peer in 0..N {
                if peer != authority {
                    handle.peer_connected(peer as AuthorityIndex).unwrap();
                }
            }
        }

        // Empty application commitments have no shard reconstruction event.
        // They must become intrinsically data-available from their exact
        // canonical header or the certified projection stalls behind them.
        let applications = (0..N as AuthorityIndex)
            .map(|authority| direct_header(authority, 1, 0))
            .collect::<Vec<_>>();
        let expected = applications
            .iter()
            .map(RbcCanonicalHeader::reference)
            .collect::<BTreeSet<_>>();
        for (handle, application) in handles.iter().zip(&applications) {
            handle.local_header(application).unwrap();
        }

        let mut open_rounds = vec![1; N];
        let mut deliveries = vec![0; N];
        let mut application_deliveries = vec![BTreeSet::new(); N];
        let mut committed_frontiers = vec![Vec::new(); N];
        let mut sync_requests = 0;
        let mut projected_vertices = 0;
        let mut projected_decisions = 0;
        let mut max_buffered_authenticated = 0;
        let mut rejections = Vec::new();
        pump_autonomous_until_round(
            &handles,
            &mut events,
            &mut open_rounds,
            &mut deliveries,
            &mut application_deliveries,
            &mut committed_frontiers,
            &mut sync_requests,
            &mut projected_vertices,
            &mut projected_decisions,
            &mut max_buffered_authenticated,
            &mut rejections,
            5,
            EVENT_TIMEOUT,
        )
        .await;
        // The first directly committed consensus frontier may predate the
        // round-one application deliveries. Advance enough certified carrier
        // rounds for a later committed frontier to include that closed prefix.
        for fixed_round in 5..=40 {
            for handle in &handles {
                handle.send(ShadowServiceMessageV1::HeartbeatTick).unwrap();
            }
            pump_autonomous_until_round(
                &handles,
                &mut events,
                &mut open_rounds,
                &mut deliveries,
                &mut application_deliveries,
                &mut committed_frontiers,
                &mut sync_requests,
                &mut projected_vertices,
                &mut projected_decisions,
                &mut max_buffered_authenticated,
                &mut rejections,
                fixed_round + 1,
                EVENT_TIMEOUT,
            )
            .await;
            if committed_frontiers.iter().all(|commits| {
                commits
                    .iter()
                    .flat_map(|delta| delta.applications.iter().map(RbcCanonicalHeader::reference))
                    .collect::<BTreeSet<_>>()
                    == expected
            }) {
                break;
            }
        }

        assert!(
            application_deliveries
                .iter()
                .all(|delivered| delivered == &expected),
            "every node must deliver every exact embedded application: {application_deliveries:?}"
        );
        assert!(
            open_rounds.iter().all(|round| *round >= 5),
            "the carrier DAG must keep advancing after application delivery"
        );
        assert_eq!(
            sync_requests,
            N * (N - 1),
            "each connection must repair exactly the round-one carrier fixed before topology registration"
        );
        assert!(
            projected_vertices >= N,
            "empty embedded applications must not stall clean projection"
        );
        let committed_applications = committed_frontiers
            .iter()
            .map(|commits| {
                commits
                    .iter()
                    .flat_map(|delta| delta.applications.iter().map(RbcCanonicalHeader::reference))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert!(
            committed_applications
                .iter()
                .all(|applications| applications == &committed_applications[0]),
            "equal certified frontiers must output byte-identical application order: {committed_applications:?}"
        );
        assert_eq!(
            committed_applications[0]
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            expected,
            "the committed frontier closure must output every exact application once; commits={committed_frontiers:?}"
        );

        drop(events);
        for handle in &handles {
            handle.shutdown().await.unwrap();
        }
        for task in tasks {
            task.await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn four_node_autonomous_zero_load_clock_delivers_mature_heartbeats() {
        assert_autonomous_zero_load_progress(4).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn seven_node_autonomous_zero_load_clock_delivers_mature_heartbeats() {
        assert_autonomous_zero_load_progress(7).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn autonomous_exact_slot_sync_is_bounded_and_late_response_is_idempotent() {
        let harness = Harness::new();
        let heartbeat_interval = Duration::from_millis(250);
        let (author, mut author_events, author_task) =
            harness.start_autonomous_with_interval(0, heartbeat_interval);
        let (receiver, mut receiver_events, receiver_task) =
            harness.start_autonomous_with_interval(1, heartbeat_interval);
        loop {
            if let ShadowServiceEventV1::Ready { autonomous_clock } =
                next_event(&mut author_events).await
            {
                assert!(autonomous_clock);
                break;
            }
        }
        loop {
            if let ShadowServiceEventV1::Ready { autonomous_clock } =
                next_event(&mut receiver_events).await
            {
                assert!(autonomous_clock);
                break;
            }
        }

        author.send(ShadowServiceMessageV1::HeartbeatTick).unwrap();
        let proactive = next_carrier(&mut author_events, 1).await;
        receiver.peer_connected(0).unwrap();
        tokio::time::sleep(SHADOW_CARRIER_SYNC_MIN_GRACE_INTERVAL_V1).await;

        let request = loop {
            if let ShadowServiceEventV1::Network {
                recipient: 0,
                message: NetworkMessage::RbcDagShadowCarrierSyncRequest(request),
            } = next_event(&mut receiver_events).await
            {
                break request;
            }
        };
        assert_eq!((request.author, request.round), (0, 1));
        author.carrier_sync_request(1, request).unwrap();
        let response = loop {
            if let ShadowServiceEventV1::Network {
                recipient: 1,
                message: NetworkMessage::RbcDagShadowCarrierSyncResponse(response),
            } = next_event(&mut author_events).await
            {
                break response;
            }
        };
        assert_eq!(response.canonical_carrier, proactive.canonical_carrier);
        assert_eq!(
            response.authentication_sidecar,
            proactive.authentication_sidecar
        );
        receiver.carrier_sync_response(0, response.clone()).unwrap();
        loop {
            match next_event(&mut receiver_events).await {
                ShadowServiceEventV1::Input {
                    kind: "carrier_sync_response",
                    outcome: "authenticated",
                } => break,
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("valid exact-slot response was rejected: {error}")
                }
                _ => {}
            }
        }

        // A proactive/response race can leave an authenticated response in
        // flight after the slot was admitted. It is an idempotent replay, not
        // peer misbehavior and not a benchmark-invalidating error.
        receiver.carrier_sync_response(0, response).unwrap();
        loop {
            match next_event(&mut receiver_events).await {
                ShadowServiceEventV1::Input {
                    kind: "carrier_sync_response",
                    outcome: "ignored_already_admitted_or_stale",
                } => break,
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("late exact-slot response was not idempotent: {error}")
                }
                _ => {}
            }
        }

        // One requester cannot amplify repeated reads of a retained large
        // carrier faster than the bounded synchronization interval.
        author.carrier_sync_request(1, request).unwrap();
        loop {
            if let ShadowServiceEventV1::Input {
                kind: "carrier_sync_request",
                outcome: "rate_limited",
            } = next_event(&mut author_events).await
            {
                break;
            }
        }

        stop(author, author_events, author_task).await;
        stop(receiver, receiver_events, receiver_task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pipelined_exact_sync_closes_gap_beyond_retention_while_producers_run() {
        let harness = Harness::new();
        let mut handles = Vec::new();
        let mut events = Vec::new();
        let mut tasks = Vec::new();
        for authority in 0..N as AuthorityIndex {
            let (handle, mut node_events, task) = harness.start_autonomous_with_policy(
                authority,
                Duration::from_millis(600),
                ShadowWalSyncPolicyV1::OnShutdown,
            );
            wait_ready(&mut node_events).await;
            handles.push(handle);
            events.push(node_events);
            tasks.push(task);
        }

        // Establish round one for all validators, then let a quorum advance
        // while authority 3 is offline and receives none of the proactive
        // carriers. Starting the gap at round two makes reconnect request
        // exact repair immediately. The normal pacer drives the healthy
        // prefix, while the later lagger convergence must use the bounded
        // validity-backed repair lane rather than wait for normal permits.
        for (authority, handle) in handles.iter().enumerate() {
            for peer in 0..N {
                if peer != authority {
                    handle.peer_connected(peer as AuthorityIndex).unwrap();
                }
            }
        }
        let mut open_rounds = vec![1; N];
        let mut deliveries = vec![0; N];
        let mut application_deliveries = vec![BTreeSet::new(); N];
        let mut committed_frontiers = vec![Vec::new(); N];
        let mut sync_requests = 0;
        let mut projected_vertices = 0;
        let mut projected_decisions = 0;
        let mut max_buffered_authenticated = 0;
        let mut rejections = Vec::new();
        for handle in &handles {
            handle.send(ShadowServiceMessageV1::HeartbeatTick).unwrap();
        }
        pump_autonomous_until_round(
            &handles,
            &mut events,
            &mut open_rounds,
            &mut deliveries,
            &mut application_deliveries,
            &mut committed_frontiers,
            &mut sync_requests,
            &mut projected_vertices,
            &mut projected_decisions,
            &mut max_buffered_authenticated,
            &mut rejections,
            2,
            EVENT_TIMEOUT,
        )
        .await;
        for authority in 0..3 {
            handles[authority].peer_disconnected(3).unwrap();
            handles[3]
                .peer_disconnected(authority as AuthorityIndex)
                .unwrap();
        }
        for fixed_round in 2..=72 {
            for handle in &handles[..3] {
                handle.send(ShadowServiceMessageV1::HeartbeatTick).unwrap();
            }
            pump_online_prefix_until_round(
                &handles,
                &mut events,
                &mut open_rounds,
                3,
                fixed_round + 1,
            )
            .await;
        }
        assert_eq!(open_rounds[3], 2);
        assert!(open_rounds[..3].iter().all(|round| *round >= 73));

        // Reconnect, fix the lagging node's first local slot, and let the
        // healthy quorum open one more round. Exact responses then drive an
        // immediate local heartbeat per repaired round; convergence must
        // outrun the independently paced healthy producers.
        for (authority, handle) in handles.iter().enumerate() {
            for peer in 0..N {
                if peer != authority {
                    handle.peer_connected(peer as AuthorityIndex).unwrap();
                }
            }
        }
        handles[3]
            .send(ShadowServiceMessageV1::HeartbeatTick)
            .unwrap();
        let catch_up_initial_gap = open_rounds[..3]
            .iter()
            .copied()
            .min()
            .unwrap()
            .saturating_sub(open_rounds[3]);
        let producer_running = Arc::new(AtomicBool::new(true));
        let producer_flag = Arc::clone(&producer_running);
        let producer_handles = handles[..3].to_vec();
        let producer = tokio::spawn(async move {
            while producer_flag.load(Ordering::Relaxed) {
                for handle in &producer_handles {
                    handle
                        .send_reliably(ShadowServiceMessageV1::HeartbeatTick)
                        .await
                        .unwrap();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        let sync_requests_before_catch_up = sync_requests;
        pump_autonomous_until_round(
            &handles,
            &mut events,
            &mut open_rounds,
            &mut deliveries,
            &mut application_deliveries,
            &mut committed_frontiers,
            &mut sync_requests,
            &mut projected_vertices,
            &mut projected_decisions,
            &mut max_buffered_authenticated,
            &mut rejections,
            80,
            Duration::from_secs(30),
        )
        .await;
        let inspect_handle = handles[3].clone();
        let inspection_task = tokio::spawn(async move {
            inspect_handle
                .inspect_carrier_sync()
                .await
                .expect("lagging actor stopped before live catch-up inspection")
        });
        timeout(Duration::from_secs(5), async {
            while !inspection_task.is_finished() {
                let observed_minimum = open_rounds.iter().copied().min().unwrap_or_default();
                pump_autonomous_until_round(
                    &handles,
                    &mut events,
                    &mut open_rounds,
                    &mut deliveries,
                    &mut application_deliveries,
                    &mut committed_frontiers,
                    &mut sync_requests,
                    &mut projected_vertices,
                    &mut projected_decisions,
                    &mut max_buffered_authenticated,
                    &mut rejections,
                    observed_minimum,
                    Duration::from_secs(1),
                )
                .await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("live catch-up inspection was starved behind actor events");
        let live_inspection = inspection_task.await.unwrap();
        let live_lagger_round = open_rounds[3].max(live_inspection.open_round);
        let live_healthy_minimum = open_rounds[..3].iter().copied().min().unwrap();
        // A fast run may already have reached and drained the validity-backed
        // target, in which case the actor correctly clears the episode. Treat
        // that stronger state as a zero target gap at the inspected round.
        let live_target = live_inspection.target.unwrap_or(live_lagger_round);
        let live_healthy_gap = live_healthy_minimum.saturating_sub(live_lagger_round);
        let live_target_gap = live_target.saturating_sub(live_lagger_round);
        assert!(
            live_lagger_round.saturating_sub(2) > EXECUTABLE_MODEL_BUFFER_WINDOW_V1,
            "lagger did not repair beyond the normal retention horizon: live={open_rounds:?}, inspection={live_inspection:?}"
        );
        assert!(
            live_healthy_gap < catch_up_initial_gap,
            "lagger gap did not shrink while producers remained live: initial_gap={catch_up_initial_gap}, live={open_rounds:?}, inspection={live_inspection:?}"
        );
        assert!(
            live_target_gap <= live_healthy_gap,
            "validity-backed target escaped beyond the healthy live high-water: live={open_rounds:?}, inspection={live_inspection:?}"
        );

        // A single shrinking observation is not sufficient: repair could
        // still plateau permanently outside the bounded exact-slot window.
        // Keep the producers live and route fairly until the lagger is within
        // one pipeline of both the validity-backed target and the observed
        // healthy minimum. A fully drained episode that already reached and
        // cleared its target is the stronger equivalent outcome.
        let pipeline_depth = carrier_sync_pipeline_depth(N) as RoundNumber;
        let (bounded_inspection, bounded_lagger_round) =
            timeout(Duration::from_secs(5), async {
                loop {
                    let inspect_handle = handles[3].clone();
                    let inspection_task = tokio::spawn(async move {
                        inspect_handle.inspect_carrier_sync().await.expect(
                            "lagging actor stopped before bounded catch-up inspection",
                        )
                    });
                    while !inspection_task.is_finished() {
                        let observed_minimum =
                            open_rounds.iter().copied().min().unwrap_or_default();
                        pump_autonomous_until_round(
                            &handles,
                            &mut events,
                            &mut open_rounds,
                            &mut deliveries,
                            &mut application_deliveries,
                            &mut committed_frontiers,
                            &mut sync_requests,
                            &mut projected_vertices,
                            &mut projected_decisions,
                            &mut max_buffered_authenticated,
                            &mut rejections,
                            observed_minimum,
                            Duration::from_secs(1),
                        )
                        .await;
                        tokio::task::yield_now().await;
                    }
                    let inspection = inspection_task.await.unwrap();
                    let lagger_round = open_rounds[3].max(inspection.open_round);
                    let healthy_minimum = open_rounds[..3].iter().copied().min().unwrap();
                    let healthy_gap = healthy_minimum.saturating_sub(lagger_round);
                    let target_gap = inspection
                        .target
                        .map(|target| target.saturating_sub(lagger_round))
                        .unwrap_or_default();
                    let episode_cleared = inspection.target.is_none()
                        && inspection.outstanding == 0
                        && inspection.desired_responses == 0;
                    if episode_cleared
                        || (healthy_gap <= pipeline_depth && target_gap <= pipeline_depth)
                    {
                        break (inspection, lagger_round);
                    }
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "live exact repair plateaued outside pipeline depth {pipeline_depth}: open={open_rounds:?}, first_inspection={live_inspection:?}"
                )
            });
        producer_running.store(false, Ordering::Relaxed);
        producer.await.unwrap();
        assert!(
            sync_requests > sync_requests_before_catch_up,
            "catch-up must use exact-slot repair"
        );
        // Maintenance timers may keep publishing benign state observations,
        // so quiescence cannot mean an indefinitely empty event channel.
        // Fairly route one event per node for one complete exact-slot budget;
        // every staged network event is delivered before each pass returns.
        for _ in 0..SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1 {
            let observed_minimum = open_rounds.iter().copied().min().unwrap_or_default();
            pump_autonomous_until_round(
                &handles,
                &mut events,
                &mut open_rounds,
                &mut deliveries,
                &mut application_deliveries,
                &mut committed_frontiers,
                &mut sync_requests,
                &mut projected_vertices,
                &mut projected_decisions,
                &mut max_buffered_authenticated,
                &mut rejections,
                observed_minimum,
                Duration::from_secs(1),
            )
            .await;
        }
        let inspect_handle = handles[3].clone();
        let final_inspection_task = tokio::spawn(async move {
            inspect_handle
                .inspect_carrier_sync()
                .await
                .expect("lagging actor stopped before final catch-up inspection")
        });
        timeout(Duration::from_secs(2), async {
            while !final_inspection_task.is_finished() {
                let observed_minimum = open_rounds.iter().copied().min().unwrap_or_default();
                pump_autonomous_until_round(
                    &handles,
                    &mut events,
                    &mut open_rounds,
                    &mut deliveries,
                    &mut application_deliveries,
                    &mut committed_frontiers,
                    &mut sync_requests,
                    &mut projected_vertices,
                    &mut projected_decisions,
                    &mut max_buffered_authenticated,
                    &mut rejections,
                    observed_minimum,
                    Duration::from_secs(1),
                )
                .await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("final catch-up inspection timed out behind actor events");
        let final_inspection = final_inspection_task.await.unwrap();
        assert!(
            final_inspection.open_round >= bounded_lagger_round,
            "short router drain regressed catch-up progress: bounded={bounded_inspection:?}, final={final_inspection:?}"
        );
        assert!(max_buffered_authenticated > 0);
        let buffered_authenticated_capacity = usize::try_from(
            EXECUTABLE_MODEL_BUFFER_WINDOW_V1.saturating_sub(EXECUTABLE_MODEL_ADMISSION_WINDOW_V1),
        )
        .unwrap_or(usize::MAX)
        .saturating_mul(N.saturating_sub(1));
        assert!(
            max_buffered_authenticated <= buffered_authenticated_capacity,
            "pipelined exact repair exceeded the executable model's authenticated retention capacity: observed={max_buffered_authenticated}, capacity={buffered_authenticated_capacity}"
        );
        assert!(
            final_inspection.max_outstanding <= SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1,
            "outstanding exact slots exceeded the global cap: {final_inspection:?}"
        );
        assert!(
            final_inspection.max_desired_responses <= SHADOW_CARRIER_SYNC_SLOT_CAPACITY_V1,
            "coalesced exact responses exceeded the global cap: {final_inspection:?}"
        );
        assert!(
            rejections.is_empty(),
            "valid catch-up produced rejections: {rejections:?}"
        );
        drop(events);
        for handle in &handles {
            handle.shutdown().await.unwrap();
        }
        for task in tasks {
            task.await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn autonomous_wal_restart_serves_the_exact_persisted_heartbeat() {
        let harness = Harness::new();
        let (handle, mut events, task) = harness.start_autonomous(0);
        loop {
            if let ShadowServiceEventV1::Ready { autonomous_clock } = next_event(&mut events).await
            {
                assert!(autonomous_clock);
                break;
            }
        }
        handle.send(ShadowServiceMessageV1::HeartbeatTick).unwrap();
        let original = next_carrier(&mut events, 1).await;
        stop(handle, events, task).await;

        let (restarted, mut restarted_events, restarted_task) = harness.start_autonomous(0);
        let mut replayed = false;
        loop {
            match next_event(&mut restarted_events).await {
                ShadowServiceEventV1::Recovered { batches, .. } => replayed = batches > 0,
                ShadowServiceEventV1::Ready { autonomous_clock } => {
                    assert!(autonomous_clock);
                    break;
                }
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("autonomous WAL restart failed: {error}")
                }
                _ => {}
            }
        }
        assert!(replayed);
        restarted
            .carrier_sync_request(
                1,
                RbcDagShadowCarrierSyncRequest {
                    author: 0,
                    round: 1,
                },
            )
            .unwrap();
        loop {
            if let ShadowServiceEventV1::Network {
                recipient: 1,
                message: NetworkMessage::RbcDagShadowCarrierSyncResponse(response),
            } = next_event(&mut restarted_events).await
            {
                assert_eq!(response.canonical_carrier, original.canonical_carrier);
                assert_eq!(
                    response.authentication_sidecar,
                    original.authentication_sidecar
                );
                break;
            }
        }
        stop(restarted, restarted_events, restarted_task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn autonomous_wal_restart_reconciles_and_replays_exact_application_origin() {
        let harness = Harness::new();
        let application = direct_header(0, 1, 0x7B);
        let (handle, mut events, task) = harness.start_autonomous(0);
        wait_ready(&mut events).await;
        handle.local_header(&application).unwrap();
        let original = next_carrier(&mut events, 1).await;
        stop(handle, events, task).await;

        let (restarted, mut restarted_events, restarted_task) =
            start_starfish_rbc_dag_autonomous_clock_service_v1(
                &harness.paths[0],
                harness.committee.clone(),
                0,
                harness.context,
                ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
                vec![application.clone()],
                Duration::from_secs(60 * 60),
                ShadowWalSyncPolicyV1::EveryBatch,
            )
            .unwrap();
        loop {
            match next_event(&mut restarted_events).await {
                ShadowServiceEventV1::Ready { autonomous_clock } => {
                    assert!(autonomous_clock);
                    break;
                }
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("application WAL restart failed: {error}")
                }
                _ => {}
            }
        }
        restarted.local_header(&application).unwrap();
        restarted
            .carrier_sync_request(
                1,
                RbcDagShadowCarrierSyncRequest {
                    author: 0,
                    round: 1,
                },
            )
            .unwrap();
        loop {
            if let ShadowServiceEventV1::Network {
                recipient: 1,
                message: NetworkMessage::RbcDagShadowCarrierSyncResponse(response),
            } = next_event(&mut restarted_events).await
            {
                assert_eq!(response.canonical_carrier, original.canonical_carrier);
                assert_eq!(
                    response.authentication_sidecar,
                    original.authentication_sidecar
                );
                break;
            }
        }
        stop(restarted, restarted_events, restarted_task).await;

        let (_invalid, invalid_events, invalid_task) =
            start_starfish_rbc_dag_autonomous_clock_service_v1(
                &harness.paths[0],
                harness.committee.clone(),
                0,
                harness.context,
                ShadowAuthorizerV1::MacVector(harness.keyrings[0].clone()),
                Vec::new(),
                Duration::from_secs(60 * 60),
                ShadowWalSyncPolicyV1::EveryBatch,
            )
            .unwrap();
        assert!(
            startup_rejection(invalid_events)
                .await
                .contains("no matching recovered direct header")
        );
        invalid_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn buffered_wal_reports_append_without_durability_and_reopens_after_clean_shutdown() {
        let harness = Harness::new();
        let (handle, mut events, task) = harness.start_autonomous_with_policy(
            0,
            Duration::from_secs(60 * 60),
            ShadowWalSyncPolicyV1::OnShutdown,
        );
        wait_ready(&mut events).await;
        handle.send(ShadowServiceMessageV1::HeartbeatTick).unwrap();

        loop {
            if let ShadowServiceEventV1::WalAppended {
                batches,
                records,
                durable,
            } = next_event(&mut events).await
            {
                assert_eq!(batches, 1);
                assert!(records > 0);
                assert!(!durable);
                break;
            }
        }
        stop(handle, events, task).await;

        let (restarted, mut restarted_events, restarted_task) = harness.start_autonomous(0);
        let mut replayed = 0;
        loop {
            match next_event(&mut restarted_events).await {
                ShadowServiceEventV1::Recovered { batches, .. } => replayed = batches,
                ShadowServiceEventV1::Ready { autonomous_clock } => {
                    assert!(autonomous_clock);
                    break;
                }
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("buffered WAL restart failed: {error}")
                }
                _ => {}
            }
        }
        assert_eq!(replayed, 1);
        stop(restarted, restarted_events, restarted_task).await;
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
                application_header: None,
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
                ShadowServiceEventV1::Ready { .. } => break,
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
    async fn relayed_authenticated_candidate_serves_its_exact_persisted_envelope() {
        let harness = Harness::new();
        let target = round_one_candidate(0, &harness.committee, 0x22);
        let envelope = harness.envelope(&target, 0);
        let (holder, mut events, task) = harness.start(1, Vec::new());
        wait_ready(&mut events).await;
        holder.carrier(0, envelope.clone()).unwrap();
        loop {
            if let ShadowServiceEventV1::Input {
                kind: "carrier",
                outcome: "authenticated",
            } = next_event(&mut events).await
            {
                break;
            }
        }

        holder.carrier_request(2, target.reference()).unwrap();
        loop {
            if let ShadowServiceEventV1::Network {
                recipient: 2,
                message: NetworkMessage::RbcDagShadowCarrierEnvelopeResponse(response),
            } = next_event(&mut events).await
            {
                assert_eq!(response.reference, target.reference());
                assert_eq!(response.canonical_carrier, envelope.canonical_carrier);
                assert_eq!(
                    response.authentication_sidecar,
                    envelope.authentication_sidecar
                );
                break;
            }
        }
        stop(holder, events, task).await;
    }

    #[tokio::test]
    async fn poisoned_application_payload_waits_for_exact_delivery() {
        let harness = Harness::new();
        let (header, payload) = application_header_and_payload(3, 1, 0xC2, &harness.committee);
        let target = round_one_application_candidate(3, header.clone(), &harness.committee, 0xC3);
        let mut envelope = harness.envelope(&target, 3);
        envelope.application_payload = Some(Arc::clone(&payload));
        envelope.authentication_sidecar[3 + 2 * MAC_TAG_SIZE] ^= 1;

        let (receiver, mut events, task) = harness.start(2, Vec::new());
        wait_ready(&mut events).await;
        receiver.carrier(3, envelope).unwrap();
        let mut retained = false;
        let mut rejected = false;
        while !retained || !rejected {
            match next_event(&mut events).await {
                ShadowServiceEventV1::Input {
                    kind: "carrier",
                    outcome: "retained_unauthenticated",
                } => retained = true,
                ShadowServiceEventV1::Rejected { peer: Some(3), .. } => rejected = true,
                ShadowServiceEventV1::AuthorizedApplicationObserved { .. } => {
                    panic!("poisoned receiver MAC must not authorize its payload")
                }
                _ => {}
            }
        }

        for author in [0, 1] {
            let phase = phase_carrier(
                author,
                RbcPhaseStatementV1::Ready {
                    target: target.reference(),
                },
                &harness.committee,
            );
            receiver
                .carrier(author, harness.envelope(&phase, author))
                .unwrap();
        }
        let mut delivered = false;
        loop {
            match next_event(&mut events).await {
                ShadowServiceEventV1::Delivered(identity)
                    if identity.author == 3 && identity.round == 1 =>
                {
                    delivered = true;
                }
                ShadowServiceEventV1::AuthorizedApplicationObserved {
                    carrier,
                    header: observed,
                    payload: Some(observed_payload),
                    authorization_basis: ShadowApplicationAuthorizationBasisV1::Delivered,
                } => {
                    assert!(delivered, "authorization must follow the Delivered effect");
                    assert_eq!(carrier, target.reference());
                    assert_eq!(observed, header);
                    assert!(application_payloads_equal(
                        Some(observed_payload.as_ref()),
                        Some(payload.as_ref())
                    ));
                    break;
                }
                ShadowServiceEventV1::Rejected {
                    peer: Some(peer),
                    error,
                } if peer != 3 => panic!("delivery evidence was rejected: {error}"),
                _ => {}
            }
        }
        stop(receiver, events, task).await;
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
    async fn coalesced_application_wins_the_round_opened_by_carrier_ingress() {
        let harness = Harness::new();
        let (handle, mut events, task) =
            harness.start_autonomous_with_interval(0, Duration::from_millis(600));
        wait_ready(&mut events).await;
        let (carrier_tx, mut carrier_rx) = mpsc::unbounded_channel();
        let event_task = tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                match event {
                    ShadowServiceEventV1::Network {
                        recipient: 1,
                        message: NetworkMessage::RbcDagShadowCarrier(envelope),
                    } => carrier_tx.send(envelope).unwrap(),
                    ShadowServiceEventV1::Rejected { error, .. } => {
                        panic!("coalesced application test rejected input: {error}")
                    }
                    _ => {}
                }
            }
        });

        handle.local_header(&direct_header(0, 1, 0x71)).unwrap();
        let first = timeout(EVENT_TIMEOUT, carrier_rx.recv())
            .await
            .expect("first local carrier timed out")
            .expect("carrier collector stopped");
        let first = CandidateCarrierV1::decode_wire_with_committee(
            &first.canonical_carrier,
            &harness.committee,
            None,
        )
        .unwrap();
        assert_eq!(first.header().carrier_round(), 1);
        tokio::time::sleep(Duration::from_millis(40)).await;

        let first_peer = round_one_candidate(1, &harness.committee, 0x72);
        handle.carrier(1, harness.envelope(&first_peer, 1)).unwrap();
        let inspection = handle.inspect_carrier_sync().await.unwrap();
        assert_eq!(inspection.open_round, 1);

        // Model a full/coalesced notification queue: the producer has
        // published the exact desired application, but its wake is not ahead
        // of the final quorum carrier in the actor FIFO.
        let application = RbcCanonicalHeader::try_new(
            0,
            2,
            (0..N as AuthorityIndex)
                .map(|author| BlockReference::new_test(author, 1))
                .collect(),
            Vec::new(),
            2_073,
            TransactionsCommitment::from_bytes([0x73; 32]),
        )
        .unwrap();
        handle.desired_local_applications.lock().insert(
            application.reference().round,
            ShadowLocalCarrierV1::from_direct_header(&application),
        );
        let quorum_peer = round_one_candidate(2, &harness.committee, 0x74);
        handle
            .carrier(2, harness.envelope(&quorum_peer, 2))
            .unwrap();
        let inspection = handle.inspect_carrier_sync().await.unwrap();
        assert_eq!(inspection.open_round, 2);

        let second = loop {
            let envelope = timeout(EVENT_TIMEOUT, carrier_rx.recv())
                .await
                .expect("second local carrier timed out")
                .expect("carrier collector stopped");
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
        assert_eq!(second.header().application_header(), Some(&application));
        handle.shutdown().await.unwrap();
        task.await.unwrap();
        event_task.await.unwrap();
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
        handle
            .carrier_response(
                1,
                RbcDagShadowCarrierResponse {
                    reference: target.reference(),
                    canonical_carrier: target.canonical_wire_bytes().unwrap(),
                },
            )
            .unwrap();
        loop {
            match next_event(&mut events).await {
                ShadowServiceEventV1::Input {
                    kind: "recovery",
                    outcome: "ignored_already_retained",
                } => break,
                ShadowServiceEventV1::Rejected { error, .. } => {
                    panic!("late exact recovery response was not idempotent: {error}")
                }
                _ => {}
            }
        }
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
    async fn vector_bearing_recovery_authenticates_relay_or_falls_back_without_blame() {
        for poisoned_receiver_entry in [false, true] {
            let harness = Harness::new();
            let (handle, mut events, task) = harness.start(3, Vec::new());
            wait_ready(&mut events).await;
            handle.peer_connected(0).unwrap();
            handle.peer_connected(1).unwrap();
            let target = round_one_candidate(2, &harness.committee, 0x63);
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
            let holder = loop {
                if let ShadowServiceEventV1::Network {
                    recipient,
                    message: NetworkMessage::RbcDagShadowCarrierRequest(reference),
                } = next_event(&mut events).await
                {
                    assert_eq!(reference, target.reference());
                    break recipient;
                }
            };
            assert!(holder == 0 || holder == 1);

            let envelope = harness.envelope(&target, 2);
            let mut authentication_sidecar = envelope.authentication_sidecar;
            if poisoned_receiver_entry {
                authentication_sidecar[3 + 3 * MAC_TAG_SIZE] ^= 1;
            }
            handle
                .carrier_envelope_response(
                    holder,
                    RbcDagShadowCarrierEnvelopeResponse {
                        reference: target.reference(),
                        canonical_carrier: envelope.canonical_carrier,
                        authentication_sidecar,
                    },
                )
                .unwrap();

            let expected_outcome = if poisoned_receiver_entry {
                "accepted_content_only"
            } else {
                "accepted_authenticated"
            };
            let mut accepted = false;
            let mut delivered = false;
            while !accepted || !delivered {
                match next_event(&mut events).await {
                    ShadowServiceEventV1::Input {
                        kind: "recovery",
                        outcome,
                    } if outcome == expected_outcome => accepted = true,
                    ShadowServiceEventV1::Delivered(identity) => {
                        assert_eq!(identity.author, 2);
                        assert_eq!(identity.round, 1);
                        delivered = true;
                    }
                    ShadowServiceEventV1::Rejected { peer, error } => {
                        panic!("vector-bearing recovery assigned blame to {peer:?}: {error}")
                    }
                    _ => {}
                }
            }
            stop(handle, events, task).await;
        }
    }

    #[test]
    fn verified_payload_callback_coalesces_when_notification_queue_is_full() {
        let harness = Harness::new();
        let (header, payload) = application_header_and_payload(0, 1, 0xD1, &harness.committee);
        let (other_header, other_payload) =
            application_header_and_payload(0, 2, 0xD2, &harness.committee);
        let (sender, mut receiver) = mpsc::channel(1);
        let desired_verified_application_payloads = Arc::new(Mutex::new(BTreeMap::new()));
        let invalidated_by_overload = Arc::new(Mutex::new(None));
        let handle = StarfishRbcDagShadowServiceHandleV1 {
            sender,
            mode: ShadowServiceModeV1::DirectMirror,
            max_sidecar_size: 3 + N * MAC_TAG_SIZE,
            own_authority: 0,
            committee_size: N,
            input_capacity: 1,
            desired_topology: Arc::new(Mutex::new(BTreeMap::new())),
            desired_local_applications: Arc::new(Mutex::new(BTreeMap::new())),
            desired_carrier_sync_responses: Arc::new(Mutex::new(BTreeMap::new())),
            desired_verified_application_payloads: Arc::clone(
                &desired_verified_application_payloads,
            ),
            desired_direct_deliveries: Arc::new(Mutex::new(BTreeSet::new())),
            desired_available_applications: Arc::new(Mutex::new(BTreeSet::new())),
            invalidated_by_overload: Arc::clone(&invalidated_by_overload),
        };

        handle.send(ShadowServiceMessageV1::RetryRecovery).unwrap();
        handle
            .verified_application_payload(header.reference(), Arc::clone(&payload))
            .unwrap();
        handle
            .verified_application_payload(header.reference(), Arc::clone(&payload))
            .unwrap();

        assert_eq!(desired_verified_application_payloads.lock().len(), 1);
        assert_eq!(*invalidated_by_overload.lock(), None);
        assert!(matches!(
            receiver.try_recv(),
            Ok(ShadowServiceMessageV1::RetryRecovery)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        handle
            .verified_application_payload(other_header.reference(), Arc::clone(&other_payload))
            .unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Ok(ShadowServiceMessageV1::VerifiedApplicationPayloadsChanged)
        ));
        assert_eq!(desired_verified_application_payloads.lock().len(), 2);
        assert!(matches!(
            handle.verified_application_payload(header.reference(), other_payload),
            Err(ShadowServiceErrorV1::ConflictingApplicationPayload(application))
                if application == header.reference()
        ));
    }

    #[tokio::test]
    async fn bounded_input_reports_overload_but_shutdown_waits_for_capacity() {
        let input_capacity = shadow_input_capacity(N, ShadowServiceModeV1::DirectMirror).unwrap();
        let (sender, mut receiver) = mpsc::channel(input_capacity);
        let handle = StarfishRbcDagShadowServiceHandleV1 {
            sender,
            mode: ShadowServiceModeV1::DirectMirror,
            max_sidecar_size: 3 + N * MAC_TAG_SIZE,
            own_authority: 0,
            committee_size: N,
            input_capacity,
            desired_topology: Arc::new(Mutex::new(BTreeMap::new())),
            desired_local_applications: Arc::new(Mutex::new(BTreeMap::new())),
            desired_carrier_sync_responses: Arc::new(Mutex::new(BTreeMap::new())),
            desired_verified_application_payloads: Arc::new(Mutex::new(BTreeMap::new())),
            desired_direct_deliveries: Arc::new(Mutex::new(BTreeSet::new())),
            desired_available_applications: Arc::new(Mutex::new(BTreeSet::new())),
            invalidated_by_overload: Arc::new(Mutex::new(None)),
        };
        for round in 0..input_capacity {
            handle
                .carrier(
                    1,
                    RbcDagShadowCarrier {
                        canonical_carrier: vec![round as u8],
                        authentication_sidecar: Vec::new(),
                        application_payload: None,
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
                    application_payload: None,
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
            mode: ShadowServiceModeV1::DirectMirror,
            max_sidecar_size: 3 + N * MAC_TAG_SIZE,
            own_authority: 0,
            committee_size: N,
            input_capacity: 1,
            desired_topology: Arc::new(Mutex::new(BTreeMap::new())),
            desired_local_applications: Arc::new(Mutex::new(BTreeMap::new())),
            desired_carrier_sync_responses: Arc::new(Mutex::new(BTreeMap::new())),
            desired_verified_application_payloads: Arc::new(Mutex::new(BTreeMap::new())),
            desired_direct_deliveries: Arc::new(Mutex::new(BTreeSet::new())),
            desired_available_applications: Arc::new(Mutex::new(BTreeSet::new())),
            invalidated_by_overload: Arc::new(Mutex::new(None)),
        };
        assert!(matches!(
            oversized.carrier(
                1,
                RbcDagShadowCarrier {
                    canonical_carrier: vec![0; MAX_CARRIER_CONTENT_SIZE_V1 + 1],
                    authentication_sidecar: Vec::new(),
                    application_payload: None,
                },
            ),
            Err(ShadowServiceErrorV1::InputTooLarge {
                field: "carrier",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn maximum_mirror_burst_fits_before_the_actor_drains() {
        const LARGE_N: usize = 124;
        let input_capacity =
            shadow_input_capacity(LARGE_N, ShadowServiceModeV1::DirectMirror).unwrap();
        assert_eq!(input_capacity, SHADOW_SERVICE_MAX_INPUT_CAPACITY_V1);
        let (sender, _receiver) = mpsc::channel(input_capacity);
        let invalidated = Arc::new(Mutex::new(None));
        let handle = StarfishRbcDagShadowServiceHandleV1 {
            sender,
            mode: ShadowServiceModeV1::DirectMirror,
            max_sidecar_size: 3 + LARGE_N * MAC_TAG_SIZE,
            own_authority: 0,
            committee_size: LARGE_N,
            input_capacity,
            desired_topology: Arc::new(Mutex::new(BTreeMap::new())),
            desired_local_applications: Arc::new(Mutex::new(BTreeMap::new())),
            desired_carrier_sync_responses: Arc::new(Mutex::new(BTreeMap::new())),
            desired_verified_application_payloads: Arc::new(Mutex::new(BTreeMap::new())),
            desired_direct_deliveries: Arc::new(Mutex::new(BTreeSet::new())),
            desired_available_applications: Arc::new(Mutex::new(BTreeSet::new())),
            invalidated_by_overload: Arc::clone(&invalidated),
        };
        for peer in 1..LARGE_N {
            handle
                .carrier(
                    peer as AuthorityIndex,
                    RbcDagShadowCarrier {
                        canonical_carrier: vec![peer as u8],
                        authentication_sidecar: Vec::new(),
                        application_payload: None,
                    },
                )
                .unwrap();
        }
        for _ in 0..SHADOW_SERVICE_CONTROL_RESERVE_V1 {
            handle.send(ShadowServiceMessageV1::RetryRecovery).unwrap();
        }
        assert_eq!(*invalidated.lock(), None);
        assert!(matches!(
            shadow_input_capacity(LARGE_N + 1, ShadowServiceModeV1::DirectMirror),
            Err(ShadowServiceErrorV1::CommitteeBurstTooLarge { .. })
        ));
    }

    #[test]
    fn autonomous_burst_budget_accepts_forty_two_and_rejects_forty_three() {
        let mode = ShadowServiceModeV1::AutonomousClock {
            heartbeat_interval: Duration::from_millis(250),
        };
        assert_eq!(shadow_application_payload_capacity(10), 64);
        assert_eq!(shadow_application_payload_capacity(40), 120);
        assert_eq!(shadow_application_payload_capacity(42), 126);
        assert_eq!(
            shadow_application_submission_grace(10),
            Duration::from_millis(100)
        );
        assert_eq!(
            shadow_application_submission_grace(40),
            Duration::from_millis(25)
        );
        assert_eq!(
            shadow_application_submission_grace(42),
            Duration::from_millis(20)
        );
        assert_eq!(shadow_input_capacity(40, mode).unwrap(), 122);
        assert_eq!(shadow_input_capacity(42, mode).unwrap(), 128);
        assert!(matches!(
            shadow_input_capacity(43, mode),
            Err(ShadowServiceErrorV1::CommitteeBurstTooLarge {
                committee_size: 43,
                required_capacity: 131,
                maximum_capacity: 128,
            })
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
