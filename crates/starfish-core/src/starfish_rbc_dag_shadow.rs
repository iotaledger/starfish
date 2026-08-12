// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Durable, single-owner execution for the embedded-RBC Starfish DAG.
//!
//! Direct-mirror mode remains observational. Autonomous mode owns carrier
//! admission, embedded RBC, and certified projection decisions; the legacy
//! Starfish DAG is still the temporary application-output scaffold until M7.
//! One [`ShadowWalV1`] batch is one reducer transition. Effects are returned
//! only after that complete batch has reached durable storage.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt,
    path::Path,
};

use crate::{
    crypto::{MacKey, MlDsa44Signer, MlDsa65Signer, Signer, TransactionsCommitment},
    starfish_rbc::RbcCanonicalHeader,
    starfish_rbc_dag::{
        AuthenticatedCarrierV1, CandidateCarrierV1, CarrierAuthenticationV1, CarrierAuthorizerV1,
        CarrierHeaderV1Args, ConsensusVertexReference, ConsensusVertexV1, LeaderChoiceV1,
        LocallyAuthenticatedCarrierV1, RbcDagCommitteeContextV1, RbcDagContextV1, RbcDagError,
        RbcPhaseStatementV1, carrier_genesis_reference,
        journal::{IngressProvenanceV1, JournalErrorV1, JournalEventV1, WriteAheadJournalV1},
        model::{
            DeliveryPromiseBasisV1, EXECUTABLE_MODEL_BUFFER_WINDOW_V1, ModelEffect, ModelError,
            ModelInputRecord, ModelTraceEvent, RbcDagModel,
        },
        projection::{
            C1StrongParentWitnessV1, CertifiedProjectionError, CertifiedProjectionModel,
            LeaderSlotV1, ProjectionDecisionV1, PromisedProjectionModel,
        },
        storage::{
            MAX_SHADOW_WAL_RECORD_SIZE_V1, ShadowWalErrorV1, ShadowWalNamespaceV1,
            ShadowWalSummaryV1, ShadowWalSyncPolicyV1, ShadowWalV1,
        },
    },
    store::RbcDagFrontierReceipt,
    types::{
        AuthorityIndex, BlockAuthenticationScheme, BlockDigest, BlockReference, MAX_COMMITTEE_SIZE,
        RoundNumber, Stake, TimestampNs,
    },
};

const RAW_RECORD_MAGIC: &[u8; 4] = b"SRD5";
const RAW_RECORD_VERSION_V1: u8 = 1;
const RAW_RECORD_HEADER_SIZE: usize = 80;

const RECORD_AUTHENTICATED_INGRESS: u8 = 0x01;
const RECORD_CANDIDATE_RETENTION: u8 = 0x02;
const RECORD_CANDIDATE_RECOVERY: u8 = 0x03;
const RECORD_LOCAL_OUTBOUND_CONTENT: u8 = 0x04;
const RECORD_DATA_AVAILABLE: u8 = 0x05;
const RECORD_MODEL_TRACE: u8 = 0x10;
const RECORD_LOCAL_OUTBOUND_SIDECAR: u8 = 0x11;
const RECORD_LOCAL_OUTBOUND_EXPOSE: u8 = 0x12;

const TRACE_ADMISSION_LOCKED: u8 = 0x00;
const TRACE_LOCAL_PHASE_LOCKED: u8 = 0x01;
const TRACE_PHASE_ENTRY_APPLIED: u8 = 0x02;
const TRACE_PHASE_CURSOR_ADVANCED: u8 = 0x03;
const TRACE_LOCAL_CARRIER_FIXED: u8 = 0x04;
const TRACE_DELIVERY_LOCKED: u8 = 0x05;
const TRACE_EFFECT: u8 = 0x06;
const TRACE_CONSENSUS_SLOT_LOCKED: u8 = 0x07;
const TRACE_LEADER_CHOICE_LOCKED: u8 = 0x08;
const TRACE_DELIVERY_PROMISE_LOCKED: u8 = 0x09;

const EFFECT_NEED_CARRIER: u8 = 0x00;
const EFFECT_DELIVERED: u8 = 0x01;
const EFFECT_PREFIX_ADVANCED: u8 = 0x02;
const EFFECT_CARRIER_ROUND_ADVANCED: u8 = 0x03;
const EFFECT_DELIVERY_PROMISED: u8 = 0x04;

const PHASE_ECHO: u8 = 0x00;
const PHASE_READY: u8 = 0x01;
// Phase codes are append-only because they are persisted in the shadow WAL.
const PHASE_VOTE: u8 = 0x02;
const PHASE_ACK: u8 = 0x03;
const PROVENANCE_DIRECT: u8 = 0x00;
const PROVENANCE_RELAYED: u8 = 0x01;

/// Shadow-benchmark-only resource guard for newly arriving, unsolicited
/// values. This is not a protocol-safe pruning rule: asynchronous delivery
/// can delay an honest INIT by more than this many rounds. A production
/// protocol must derive pruning from a certified/committed watermark instead.
/// Exact RBC recovery requests are exempt from this prototype guard.
const SHADOW_BENCHMARK_UNSOLICITED_RETENTION_WINDOW_ROUNDS_V1: RoundNumber = 64;
/// A restart may replay only a bounded committed-frontier suffix into Core.
/// Larger gaps require a future checkpoint-transfer protocol rather than an
/// unbounded startup event burst.
pub(crate) const MAX_AUTHORITATIVE_FRONTIER_RECOVERY_SUFFIX_V1: usize = 64;

/// Local authentication material owned by exactly one shadow core.
///
/// The MAC variant contains the local authority's complete pairwise keyring:
/// it creates full outbound vectors and verifies this receiver's inbound tag.
#[derive(Clone, Debug)]
pub(crate) enum ShadowAuthorizerV1 {
    Ed25519(Signer),
    MlDsa44(MlDsa44Signer),
    MlDsa65(MlDsa65Signer),
    MacVector(Vec<MacKey>),
}

impl ShadowAuthorizerV1 {
    fn scheme(&self) -> BlockAuthenticationScheme {
        match self {
            Self::Ed25519(_) => BlockAuthenticationScheme::Ed25519,
            Self::MlDsa44(_) => BlockAuthenticationScheme::MlDsa44,
            Self::MlDsa65(_) => BlockAuthenticationScheme::MlDsa65,
            Self::MacVector(_) => BlockAuthenticationScheme::MacVector,
        }
    }

    fn authorizer(&self, authority: AuthorityIndex) -> CarrierAuthorizerV1<'_> {
        match self {
            Self::Ed25519(signer) => CarrierAuthorizerV1::Ed25519 { authority, signer },
            Self::MlDsa44(signer) => CarrierAuthorizerV1::MlDsa44 { authority, signer },
            Self::MlDsa65(signer) => CarrierAuthorizerV1::MlDsa65 { authority, signer },
            Self::MacVector(keys) => CarrierAuthorizerV1::MacVector { authority, keys },
        }
    }

    fn inbound_mac_keys(&self) -> &[MacKey] {
        match self {
            Self::MacVector(keys) => keys,
            Self::Ed25519(_) | Self::MlDsa44(_) | Self::MlDsa65(_) => &[],
        }
    }
}

/// Exact, peer-independent bytes retained for first send and retransmission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShadowOutboundEnvelopeV1 {
    reference: BlockReference,
    canonical_carrier_wire: Vec<u8>,
    authentication_sidecar: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LocalOutboundMetadataV1 {
    pub(crate) round: RoundNumber,
    pub(crate) transactions_commitment: TransactionsCommitment,
    pub(crate) creation_time_ns: TimestampNs,
    pub(crate) control_shape: bool,
    pub(crate) application: Option<BlockReference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShadowIngressDispositionV1 {
    Authenticated,
    CandidateRetained,
    IgnoredDuplicateConflictOrStale,
    /// An unsolicited carrier was beyond the bounded future-retention
    /// window. It was discarded before authentication and without WAL/model
    /// mutation; exact current-round synchronization remains available.
    IgnoredFutureOutsideBuffer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShadowIngressOutcomeV1 {
    disposition: ShadowIngressDispositionV1,
    effects: Vec<ModelEffect>,
}

impl ShadowIngressOutcomeV1 {
    pub(crate) fn disposition(&self) -> ShadowIngressDispositionV1 {
        self.disposition
    }

    pub(crate) fn effects(&self) -> &[ModelEffect] {
        &self.effects
    }

    fn new(disposition: ShadowIngressDispositionV1, effects: Vec<ModelEffect>) -> Self {
        Self {
            disposition,
            effects,
        }
    }
}

impl ShadowOutboundEnvelopeV1 {
    pub(crate) fn reference(&self) -> BlockReference {
        self.reference
    }

    pub(crate) fn canonical_carrier_wire(&self) -> &[u8] {
        &self.canonical_carrier_wire
    }

    pub(crate) fn authentication_sidecar(&self) -> &[u8] {
        &self.authentication_sidecar
    }
}

/// Protocol-independent delivery identity used for direct/shadow comparison.
///
/// A block reference is intentionally absent: direct and shadow protocols may
/// commit different headers for the same transaction payload.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ShadowDeliveryIdentityV1 {
    pub(crate) author: AuthorityIndex,
    pub(crate) round: RoundNumber,
    pub(crate) transactions_commitment: TransactionsCommitment,
}

impl ShadowDeliveryIdentityV1 {
    pub(crate) const fn new(
        author: AuthorityIndex,
        round: RoundNumber,
        transactions_commitment: TransactionsCommitment,
    ) -> Self {
        Self {
            author,
            round,
            transactions_commitment,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ShadowDeliverySlotV1 {
    pub(crate) author: AuthorityIndex,
    pub(crate) round: RoundNumber,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ShadowDeliveryComparisonV1 {
    Match,
    Mismatch {
        direct_only: Vec<ShadowDeliveryIdentityV1>,
        shadow_only: Vec<ShadowDeliveryIdentityV1>,
    },
    Ambiguous {
        slots: Vec<ShadowDeliverySlotV1>,
    },
}

/// Cheap, non-consensus physical-round observation for one first-committed
/// application. Unlike the discarded logical-ancestry diagnostic, this is
/// computed once at output and adds no work to projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CommittedApplicationDiagnosticV1 {
    pub(crate) physical_carrier_round_delta: i64,
}

impl CommittedApplicationDiagnosticV1 {
    fn new(anchor: ConsensusVertexReference, enclosing_carrier: BlockReference) -> Self {
        Self {
            physical_carrier_round_delta: i64::from(anchor.carrier().round)
                - i64::from(enclosing_carrier.round),
        }
    }
}

/// Deterministic application output unlocked by one newly committed clean
/// projected anchor. Carrier references remain available for audit while the
/// application headers are already deduplicated and sorted by their carrier
/// position in the exact committed frontier delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommittedFrontierDeltaV1 {
    /// Monotone one-based output position, independent of the possibly
    /// regressing logical round of `anchor`.
    pub(crate) output_sequence: RoundNumber,
    pub(crate) anchor: ConsensusVertexReference,
    pub(crate) frontier: Vec<Option<BlockReference>>,
    pub(crate) carriers: Vec<BlockReference>,
    pub(crate) applications: Vec<RbcCanonicalHeader>,
    /// Diagnostic-only records in one-to-one order with `applications`.
    pub(crate) application_diagnostics: Vec<CommittedApplicationDiagnosticV1>,
}

/// Runtime-only handoff between Core's compact durable receipt and the
/// authoritative carrier WAL. Application references are reconstructed from
/// the CommitData atomically stored under `receipt.carrier_anchor`; a missing
/// CommitData value therefore denotes an exact control-only frontier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RbcDagFrontierRecoveryCursorV1 {
    pub(crate) receipt: RbcDagFrontierReceipt,
    pub(crate) application_references: Vec<BlockReference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectionHolReasonV1 {
    InsufficientLookahead,
    DirectEvidencePending,
    AwaitingIndirectAnchor,
    Ready,
}

impl ProjectionHolReasonV1 {
    pub(crate) const fn metric_label(self) -> &'static str {
        match self {
            Self::InsufficientLookahead => "insufficient_lookahead",
            Self::DirectEvidencePending => "direct_evidence_pending",
            Self::AwaitingIndirectAnchor => "awaiting_indirect_anchor",
            Self::Ready => "ready",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProjectionRuntimeSnapshotV1 {
    pub(crate) pending_candidates: usize,
    pub(crate) highest_projected_round: RoundNumber,
    pub(crate) next_undecided_round: RoundNumber,
    pub(crate) next_undecided_projected_stake: Stake,
    pub(crate) last_committed_round: RoundNumber,
    pub(crate) hol_reason: ProjectionHolReasonV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShadowOpenReportV1 {
    replayed_batches: u64,
    discarded_tail_bytes: u64,
    recovery_effects: Vec<ModelEffect>,
    recovered_committed_frontiers: Vec<CommittedFrontierDeltaV1>,
}

impl ShadowOpenReportV1 {
    pub(crate) fn replayed_batches(&self) -> u64 {
        self.replayed_batches
    }

    pub(crate) fn discarded_tail_bytes(&self) -> u64 {
        self.discarded_tail_bytes
    }

    /// Final outstanding recovery requests only. Historical delivery, clock,
    /// and already-satisfied recovery effects are never reissued on restart.
    pub(crate) fn recovery_effects(&self) -> &[ModelEffect] {
        &self.recovery_effects
    }

    /// Strictly newer authoritative WAL output that Core has not durably
    /// acknowledged yet. Observational opens always return an empty suffix.
    pub(crate) fn recovered_committed_frontiers(&self) -> &[CommittedFrontierDeltaV1] {
        &self.recovered_committed_frontiers
    }

    #[cfg(test)]
    pub(crate) fn with_recovered_committed_frontiers_for_test(
        recovered_committed_frontiers: Vec<CommittedFrontierDeltaV1>,
    ) -> Self {
        Self {
            replayed_batches: 1,
            discarded_tail_bytes: 0,
            recovery_effects: Vec::new(),
            recovered_committed_frontiers,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ShadowCodecErrorV1 {
    UnexpectedEnd,
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidFlags(u16),
    ContextMismatch,
    AuthorityMismatch {
        expected: AuthorityIndex,
        actual: AuthorityIndex,
    },
    AuthenticationSchemeMismatch,
    UnknownRecordKind(u8),
    InvalidRecordLength(usize),
    TrailingBytes(usize),
    InvalidProvenance(u8),
    InvalidPhase(u8),
    InvalidLeaderChoice(u8),
    InvalidDeliveryPromiseBasis(u8),
    InvalidTrace(u8),
    InvalidEffect(u8),
    NonCanonicalHolders,
    LengthOverflow,
}

impl fmt::Display for ShadowCodecErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Starfish-RBC-DAG shadow codec error: {self:?}")
    }
}

impl Error for ShadowCodecErrorV1 {}

#[derive(Debug)]
pub(crate) enum ShadowErrorV1 {
    Wal(ShadowWalErrorV1),
    Codec(ShadowCodecErrorV1),
    Carrier(RbcDagError),
    Model(ModelError),
    Journal(JournalErrorV1),
    ContextMismatch,
    UnknownAuthority(AuthorityIndex),
    NonCanonicalProvenance,
    AuthorizerSchemeMismatch,
    AuthorizerKeyMismatch,
    InvalidAuthorizerKeyringLength {
        expected: usize,
        actual: usize,
    },
    InvalidBatch(&'static str),
    NonCanonicalCarrier,
    NonCanonicalAuthentication,
    TraceMismatch {
        batch_sequence: u64,
    },
    ReplayPolicyViolation {
        batch_sequence: u64,
        reason: &'static str,
    },
    FrontierRecoveryWatermarkLength {
        expected: usize,
        actual: usize,
    },
    FrontierOutputSequenceOverflow(u64),
    FrontierRecoverySequence {
        expected_sequence: RoundNumber,
        actual_sequence: RoundNumber,
    },
    FrontierRecoveryCursorAhead {
        durable_sequence: RoundNumber,
        actor_sequence: RoundNumber,
    },
    FrontierRecoveryCursorMissing(RoundNumber),
    FrontierRecoveryAnchorConflict {
        consensus_round: RoundNumber,
        durable: BlockReference,
        actor: BlockReference,
    },
    FrontierRecoveryApplicationsConflict {
        consensus_round: RoundNumber,
        durable: Vec<BlockReference>,
        actor: Vec<BlockReference>,
    },
    FrontierRecoveryWatermarksConflict {
        consensus_round: RoundNumber,
        durable: Vec<RoundNumber>,
        actor: Vec<RoundNumber>,
    },
    FrontierRecoveryApplicationAuthority {
        application: BlockReference,
        committee_size: usize,
    },
    FrontierRecoverySuffixLimit {
        limit: usize,
        actual: usize,
    },
    UnrequestedRecovery(BlockReference),
    SlotCandidateLimit {
        author: AuthorityIndex,
        round: RoundNumber,
        limit: usize,
    },
    MissingOutboundCandidate(BlockReference),
    MissingDeliveredCandidate(BlockReference),
    PostModelJournal(JournalErrorV1),
    Projection(CertifiedProjectionError),
    Poisoned,
}

impl fmt::Display for ShadowErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wal(error) => write!(formatter, "{error}"),
            Self::Codec(error) => write!(formatter, "{error}"),
            Self::Carrier(error) => write!(formatter, "{error}"),
            Self::Model(error) => write!(formatter, "{error}"),
            Self::Journal(error) => write!(formatter, "{error}"),
            Self::ContextMismatch => formatter.write_str("shadow protocol context mismatch"),
            Self::UnknownAuthority(authority) => {
                write!(formatter, "unknown shadow authority {authority}")
            }
            Self::NonCanonicalProvenance => formatter.write_str(
                "non-canonical shadow ingress provenance: an author's own peer must be direct",
            ),
            Self::AuthorizerSchemeMismatch => {
                formatter.write_str("shadow authorizer scheme mismatch")
            }
            Self::AuthorizerKeyMismatch => formatter.write_str("shadow authorizer key mismatch"),
            Self::InvalidAuthorizerKeyringLength { expected, actual } => write!(
                formatter,
                "invalid shadow authorizer keyring length: expected {expected}, got {actual}"
            ),
            Self::InvalidBatch(reason) => write!(formatter, "invalid shadow WAL batch: {reason}"),
            Self::NonCanonicalCarrier => {
                formatter.write_str("non-canonical shadow carrier encoding")
            }
            Self::NonCanonicalAuthentication => {
                formatter.write_str("non-canonical shadow authentication encoding")
            }
            Self::TraceMismatch { batch_sequence } => write!(
                formatter,
                "shadow trace mismatch in WAL batch {batch_sequence}"
            ),
            Self::ReplayPolicyViolation {
                batch_sequence,
                reason,
            } => write!(
                formatter,
                "shadow replay policy violation in WAL batch {batch_sequence}: {reason}"
            ),
            Self::FrontierRecoveryWatermarkLength { expected, actual } => write!(
                formatter,
                "RBC-DAG frontier recovery cursor watermark length mismatch: expected {expected}, got {actual}"
            ),
            Self::FrontierOutputSequenceOverflow(sequence) => write!(
                formatter,
                "RBC-DAG frontier output sequence {sequence} exceeds the u32 receipt encoding"
            ),
            Self::FrontierRecoverySequence {
                expected_sequence,
                actual_sequence,
            } => write!(
                formatter,
                "RBC-DAG frontier recovery output sequence mismatch: expected {expected_sequence}, got {actual_sequence}"
            ),
            Self::FrontierRecoveryCursorAhead {
                durable_sequence,
                actor_sequence,
            } => write!(
                formatter,
                "RBC-DAG frontier recovery cursor sequence {durable_sequence} is ahead of actor WAL sequence {actor_sequence}"
            ),
            Self::FrontierRecoveryCursorMissing(sequence) => write!(
                formatter,
                "RBC-DAG frontier recovery cursor sequence {sequence} is missing from the actor WAL"
            ),
            Self::FrontierRecoveryAnchorConflict {
                consensus_round,
                durable,
                actor,
            } => write!(
                formatter,
                "RBC-DAG frontier recovery anchor conflict at consensus round {consensus_round}: durable {durable}, actor {actor}"
            ),
            Self::FrontierRecoveryApplicationsConflict {
                consensus_round,
                durable,
                actor,
            } => write!(
                formatter,
                "RBC-DAG frontier recovery application conflict at consensus round {consensus_round}: durable {durable:?}, actor {actor:?}"
            ),
            Self::FrontierRecoveryWatermarksConflict {
                consensus_round,
                durable,
                actor,
            } => write!(
                formatter,
                "RBC-DAG frontier recovery watermark conflict at consensus round {consensus_round}: durable {durable:?}, actor {actor:?}"
            ),
            Self::FrontierRecoveryApplicationAuthority {
                application,
                committee_size,
            } => write!(
                formatter,
                "RBC-DAG frontier recovery application {application} is outside committee size {committee_size}"
            ),
            Self::FrontierRecoverySuffixLimit { limit, actual } => write!(
                formatter,
                "RBC-DAG frontier recovery suffix exceeds the bound {limit}: got {actual}"
            ),
            Self::UnrequestedRecovery(reference) => {
                write!(formatter, "unrequested shadow recovery for {reference}")
            }
            Self::SlotCandidateLimit {
                author,
                round,
                limit,
            } => write!(
                formatter,
                "shadow candidate limit {limit} reached for slot ({author}, {round})"
            ),
            Self::MissingOutboundCandidate(reference) => {
                write!(
                    formatter,
                    "missing persisted outbound shadow candidate {reference}"
                )
            }
            Self::MissingDeliveredCandidate(reference) => {
                write!(formatter, "missing delivered shadow candidate {reference}")
            }
            Self::PostModelJournal(error) => write!(
                formatter,
                "shadow journal validation failed after the unpublished model transition: {error}"
            ),
            Self::Projection(error) => write!(formatter, "{error}"),
            Self::Poisoned => formatter.write_str("shadow core is poisoned"),
        }
    }
}

impl Error for ShadowErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wal(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::Carrier(error) => Some(error),
            Self::Model(error) => Some(error),
            Self::Journal(error) | Self::PostModelJournal(error) => Some(error),
            Self::Projection(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ShadowWalErrorV1> for ShadowErrorV1 {
    fn from(error: ShadowWalErrorV1) -> Self {
        Self::Wal(error)
    }
}

impl From<ShadowCodecErrorV1> for ShadowErrorV1 {
    fn from(error: ShadowCodecErrorV1) -> Self {
        Self::Codec(error)
    }
}

impl From<RbcDagError> for ShadowErrorV1 {
    fn from(error: RbcDagError) -> Self {
        Self::Carrier(error)
    }
}

impl From<ModelError> for ShadowErrorV1 {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<JournalErrorV1> for ShadowErrorV1 {
    fn from(error: JournalErrorV1) -> Self {
        Self::Journal(error)
    }
}

impl From<CertifiedProjectionError> for ShadowErrorV1 {
    fn from(error: CertifiedProjectionError) -> Self {
        Self::Projection(error)
    }
}

#[derive(Clone)]
enum ShadowInputV1 {
    AuthenticatedIngress {
        authenticated: AuthenticatedCarrierV1,
        provenance: IngressProvenanceV1,
    },
    CandidateRetention(CandidateCarrierV1),
    CandidateRecovery(CandidateCarrierV1),
    LocalOutbound(LocallyAuthenticatedCarrierV1),
    DataAvailable(BlockReference),
}

impl ShadowInputV1 {
    fn model_input(&self) -> ModelInputRecord {
        match self {
            Self::AuthenticatedIngress { authenticated, .. } => {
                ModelInputRecord::AuthenticatedIngress(authenticated.clone())
            }
            Self::CandidateRetention(candidate) => {
                ModelInputRecord::CandidateRetained(candidate.clone())
            }
            Self::CandidateRecovery(candidate) => {
                ModelInputRecord::CandidateRecovered(candidate.clone())
            }
            Self::LocalOutbound(authenticated) => {
                ModelInputRecord::LocalCarrierFixed(authenticated.clone())
            }
            Self::DataAvailable(reference) => ModelInputRecord::DataAvailable(*reference),
        }
    }

    fn candidate(&self) -> Option<&CandidateCarrierV1> {
        match self {
            Self::AuthenticatedIngress { authenticated, .. } => Some(authenticated.candidate()),
            Self::CandidateRetention(candidate) | Self::CandidateRecovery(candidate) => {
                Some(candidate)
            }
            Self::LocalOutbound(authenticated) => Some(authenticated.candidate()),
            Self::DataAvailable(_) => None,
        }
    }

    fn is_local(&self) -> bool {
        matches!(self, Self::LocalOutbound(_))
    }
}

struct DecodedRawRecord {
    kind: u8,
    payload: Vec<u8>,
}

/// Synchronous, durable RBC-DAG core.
///
/// This type has one mutable model, journal, and WAL handle and intentionally
/// offers no shared-state wrapper. A caller may move it between threads but
/// must preserve exclusive ownership.
pub(crate) struct StarfishRbcDagShadowV1 {
    committee: RbcDagCommitteeContextV1,
    context: RbcDagContextV1,
    own_authority: AuthorityIndex,
    authorizer: ShadowAuthorizerV1,
    model: RbcDagModel,
    journal: WriteAheadJournalV1,
    wal: ShadowWalV1,
    candidates: BTreeMap<BlockReference, CandidateCarrierV1>,
    application_carriers: BTreeMap<BlockReference, BTreeSet<BlockReference>>,
    /// Every authoritative delivery, including the optimistic ECHO path.
    delivered: BTreeSet<BlockReference>,
    /// The slower fallback values that additionally reached `Q` READYs.
    certified_delivered: BTreeSet<BlockReference>,
    authenticated_slots: BTreeMap<(AuthorityIndex, RoundNumber), BlockReference>,
    ordinarily_retained_slots: BTreeMap<(AuthorityIndex, RoundNumber), BlockReference>,
    slot_candidates: BTreeMap<(AuthorityIndex, RoundNumber), BTreeSet<BlockReference>>,
    requested_recoveries: BTreeMap<BlockReference, Vec<AuthorityIndex>>,
    promised_projection: PromisedProjectionModel,
    pending_promised_references: BTreeSet<BlockReference>,
    pending_promised_projection_candidates: BTreeSet<BlockReference>,
    promised_projection_rejected: BTreeMap<BlockReference, CertifiedProjectionError>,
    projection: CertifiedProjectionModel,
    pending_projection_candidates: BTreeSet<BlockReference>,
    projection_rejected: BTreeMap<BlockReference, CertifiedProjectionError>,
    projected_decisions: BTreeSet<ProjectionDecisionV1>,
    /// Exact derived index for the append-only decision history. Consensus
    /// drive asks this on every newly decidable round; scanning all prior
    /// decisions made a long run quadratic despite the slot being unique.
    projected_decision_slots: BTreeSet<LeaderSlotV1>,
    included_applications: BTreeSet<BlockReference>,
    highest_projected_consensus_round: RoundNumber,
    highest_committed_consensus_round: RoundNumber,
    committed_output_count: u64,
    next_undecided_consensus_round: RoundNumber,
    next_local_consensus_round: RoundNumber,
    pending_projected_vertices: Vec<ConsensusVertexReference>,
    pending_projection_decisions: Vec<ProjectionDecisionV1>,
    pending_committed_frontiers: Vec<CommittedFrontierDeltaV1>,
    vote_qc_fast_path: bool,
    poisoned: bool,
}

enum ShadowFrontierRecoveryPolicyV1 {
    /// Comparison/mirror mode reconstructs state but never republishes
    /// historical authoritative outputs.
    Observational,
    /// Embedded-authority mode reconciles Core's exact durable cursor and
    /// republishes only the bounded, strictly newer actor-WAL suffix.
    Authoritative(Option<RbcDagFrontierRecoveryCursorV1>),
}

impl StarfishRbcDagShadowV1 {
    #[cfg(test)]
    pub(crate) fn open(
        path: impl AsRef<Path>,
        committee: RbcDagCommitteeContextV1,
        own_authority: AuthorityIndex,
        context: RbcDagContextV1,
        authorizer: ShadowAuthorizerV1,
    ) -> Result<(Self, ShadowOpenReportV1), ShadowErrorV1> {
        Self::open_with_wal_sync_policy(
            path,
            committee,
            own_authority,
            context,
            authorizer,
            ShadowWalSyncPolicyV1::EveryBatch,
        )
    }

    pub(crate) fn open_with_wal_sync_policy(
        path: impl AsRef<Path>,
        committee: RbcDagCommitteeContextV1,
        own_authority: AuthorityIndex,
        context: RbcDagContextV1,
        authorizer: ShadowAuthorizerV1,
        wal_sync_policy: ShadowWalSyncPolicyV1,
    ) -> Result<(Self, ShadowOpenReportV1), ShadowErrorV1> {
        Self::open_with_frontier_recovery_policy(
            path,
            committee,
            own_authority,
            context,
            authorizer,
            wal_sync_policy,
            ShadowFrontierRecoveryPolicyV1::Observational,
            false,
        )
    }

    /// Open the embedded-authority runtime and reconcile the carrier WAL's
    /// committed output against Core's exact durable cursor. The report owns
    /// the strictly newer bounded suffix so startup can publish it before its
    /// readiness barrier.
    pub(crate) fn open_authoritative_with_wal_sync_policy(
        path: impl AsRef<Path>,
        committee: RbcDagCommitteeContextV1,
        own_authority: AuthorityIndex,
        context: RbcDagContextV1,
        authorizer: ShadowAuthorizerV1,
        wal_sync_policy: ShadowWalSyncPolicyV1,
        recovery_cursor: Option<RbcDagFrontierRecoveryCursorV1>,
        vote_qc_fast_path: bool,
    ) -> Result<(Self, ShadowOpenReportV1), ShadowErrorV1> {
        Self::open_with_frontier_recovery_policy(
            path,
            committee,
            own_authority,
            context,
            authorizer,
            wal_sync_policy,
            ShadowFrontierRecoveryPolicyV1::Authoritative(recovery_cursor),
            vote_qc_fast_path,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_with_frontier_recovery_policy(
        path: impl AsRef<Path>,
        committee: RbcDagCommitteeContextV1,
        own_authority: AuthorityIndex,
        context: RbcDagContextV1,
        authorizer: ShadowAuthorizerV1,
        wal_sync_policy: ShadowWalSyncPolicyV1,
        frontier_recovery_policy: ShadowFrontierRecoveryPolicyV1,
        vote_qc_fast_path: bool,
    ) -> Result<(Self, ShadowOpenReportV1), ShadowErrorV1> {
        validate_configuration(&committee, own_authority, context, &authorizer)?;
        let committee_size = committee.committee().len();
        let namespace = ShadowWalNamespaceV1::new(context, own_authority);
        let (wal, recovery) = ShadowWalV1::open_with_sync_policy(path, namespace, wal_sync_policy)?;
        let replayed_batches = recovery.batch_count();
        let discarded_tail_bytes = recovery.discarded_tail_bytes();

        let mut model = RbcDagModel::new(committee.committee_arc(), own_authority, context)?;
        model.enable_intrinsic_empty_data_availability();
        let promised_projection =
            PromisedProjectionModel::from_committee_context(committee.clone());
        let projection = CertifiedProjectionModel::from_committee_context(committee.clone());
        let journal = WriteAheadJournalV1::new(context, own_authority);
        let mut core = Self {
            committee,
            context,
            own_authority,
            authorizer,
            model,
            journal,
            wal,
            candidates: BTreeMap::new(),
            application_carriers: BTreeMap::new(),
            delivered: BTreeSet::new(),
            certified_delivered: BTreeSet::new(),
            authenticated_slots: BTreeMap::new(),
            ordinarily_retained_slots: BTreeMap::new(),
            slot_candidates: BTreeMap::new(),
            requested_recoveries: BTreeMap::new(),
            promised_projection,
            pending_promised_references: BTreeSet::new(),
            pending_promised_projection_candidates: BTreeSet::new(),
            promised_projection_rejected: BTreeMap::new(),
            projection,
            pending_projection_candidates: BTreeSet::new(),
            projection_rejected: BTreeMap::new(),
            projected_decisions: BTreeSet::new(),
            projected_decision_slots: BTreeSet::new(),
            included_applications: BTreeSet::new(),
            highest_projected_consensus_round: 0,
            highest_committed_consensus_round: 0,
            committed_output_count: 0,
            next_undecided_consensus_round: 1,
            next_local_consensus_round: 1,
            pending_projected_vertices: Vec::new(),
            pending_projection_decisions: Vec::new(),
            pending_committed_frontiers: Vec::new(),
            vote_qc_fast_path,
            poisoned: false,
        };

        for batch in recovery.batches() {
            let input = core.decode_batch(batch.records())?;
            core.apply_replayed(input, batch.records(), batch.sequence())?;
        }
        // Historical decisions are reconstructed to validate replay, but only
        // an authoritative open may republish the exact Core-unacknowledged
        // committed-frontier suffix.
        core.pending_projection_decisions.clear();
        core.pending_projected_vertices.clear();
        let replayed_frontiers = std::mem::take(&mut core.pending_committed_frontiers);
        let recovered_committed_frontiers = match frontier_recovery_policy {
            ShadowFrontierRecoveryPolicyV1::Observational => Vec::new(),
            ShadowFrontierRecoveryPolicyV1::Authoritative(cursor) => {
                reconcile_authoritative_frontier_suffix(
                    replayed_frontiers,
                    cursor.as_ref(),
                    committee_size,
                )?
            }
        };
        let recovery_effects = core
            .requested_recoveries
            .iter()
            .map(|(target, holders)| ModelEffect::NeedCarrier {
                target: *target,
                holders: holders.clone(),
            })
            .collect();
        Ok((
            core,
            ShadowOpenReportV1 {
                replayed_batches,
                discarded_tail_bytes,
                recovery_effects,
                recovered_committed_frontiers,
            },
        ))
    }

    pub(crate) fn local_carrier_round(&self) -> RoundNumber {
        self.model.local_carrier_round()
    }

    pub(crate) fn can_create_carrier(&self) -> bool {
        self.model.can_create_carrier()
    }

    /// Whether the open local carrier can name an exact admitted quorum from
    /// the immediately preceding physical round. This is a read-only pacing
    /// predicate: the reducer still validates the same parent set again when
    /// the carrier is durably fixed.
    pub(crate) fn local_parent_quorum_ready(&self) -> bool {
        self.model.local_parent_set().is_ok()
    }

    pub(crate) fn pending_phase_backlog_len(&self) -> usize {
        self.model.pending_phase_backlog_len()
    }

    /// Whether the exact phase prefix encodable in the open carrier contains
    /// work for an application-bearing carrier. This lets the prototype send
    /// application-critical ECHO/READY promptly without turning control-only
    /// carrier certification into an unpaced self-sustaining loop.
    pub(crate) fn has_pending_application_phase_work(&self) -> bool {
        self.model.pending_phase_batch().iter().any(|statement| {
            self.candidates
                .get(&statement.target())
                .is_some_and(|candidate| candidate.header().application_header().is_some())
        })
    }

    #[cfg(test)]
    pub(crate) fn admitted_reference(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Option<BlockReference> {
        self.model.admitted_reference(authority, round)
    }

    /// Return the exact authenticated value retained for a slot, including a
    /// future value that is inside the normal 64-round window but not yet
    /// admitted by sequential clock advancement.
    pub(crate) fn authenticated_reference(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Option<BlockReference> {
        self.authenticated_slots.get(&(authority, round)).copied()
    }

    pub(crate) fn current_round_admitted_author_count(&self) -> usize {
        let round = self.local_carrier_round();
        self.committee
            .committee()
            .authorities()
            .filter(|authority| self.model.admitted_reference(*authority, round).is_some())
            .count()
    }

    pub(crate) fn current_round_admitted_stake(&self) -> Stake {
        let round = self.local_carrier_round();
        self.committee
            .committee()
            .authorities()
            .filter(|authority| self.model.admitted_reference(*authority, round).is_some())
            .filter_map(|authority| self.committee.committee().get_stake(authority))
            .fold(0, Stake::saturating_add)
    }

    /// Authenticated slots retained beyond the model's current admission
    /// window. These are bounded by the reducer's future-carrier window and
    /// become admitted only through sequential clock advancement.
    pub(crate) fn buffered_authenticated_carrier_count(&self) -> usize {
        self.authenticated_slots
            .iter()
            .filter(|((authority, round), reference)| {
                self.model.admitted_reference(*authority, *round) != Some(**reference)
            })
            .count()
    }

    pub(crate) fn drain_projection_decisions(&mut self) -> Vec<ProjectionDecisionV1> {
        std::mem::take(&mut self.pending_projection_decisions)
    }

    pub(crate) fn drain_projected_vertices(&mut self) -> Vec<ConsensusVertexReference> {
        std::mem::take(&mut self.pending_projected_vertices)
    }

    pub(crate) fn drain_committed_frontiers(&mut self) -> Vec<CommittedFrontierDeltaV1> {
        std::mem::take(&mut self.pending_committed_frontiers)
    }

    /// Persist the external data-availability predicate for one exact
    /// application-bearing carrier. Control carriers are available by shape
    /// and never require this oracle.
    pub(crate) fn mark_carrier_data_available(
        &mut self,
        reference: BlockReference,
    ) -> Result<Vec<ModelEffect>, ShadowErrorV1> {
        self.ensure_live()?;
        if self.projection.is_data_available(reference) {
            return Ok(Vec::new());
        }
        self.apply_durable(ShadowInputV1::DataAvailable(reference))
    }

    pub(crate) fn application_carriers(&self, application: BlockReference) -> Vec<BlockReference> {
        self.application_carriers
            .get(&application)
            .map(|carriers| carriers.iter().copied().collect())
            .unwrap_or_default()
    }

    pub(crate) fn carrier_data_available(&self, reference: BlockReference) -> bool {
        self.projection.is_data_available(reference)
    }

    pub(crate) fn wal_counts(&self) -> (u64, u64) {
        (self.wal.batch_count(), self.wal.record_count())
    }

    #[cfg(test)]
    pub(crate) fn delivered(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Option<BlockReference> {
        self.model.delivered(authority, round)
    }

    #[cfg(test)]
    pub(crate) fn optimistic_promise_count(&self) -> usize {
        self.slot_candidates
            .values()
            .flat_map(BTreeSet::iter)
            .filter(|reference| {
                self.model.delivery_promise_basis(reference)
                    == Some(DeliveryPromiseBasisV1::OptimisticEcho)
            })
            .count()
    }

    #[cfg(test)]
    pub(crate) fn certified_delivery_count(&self) -> Result<usize, ShadowErrorV1> {
        Ok(self.certified_delivered.len())
    }

    /// Construct, authenticate, durably fix, and expose the next local
    /// carrier. M3 intentionally uses empty ACKs and no consensus vertex.
    pub(crate) fn create_local_carrier(
        &mut self,
        round: RoundNumber,
        transactions_commitment: TransactionsCommitment,
        creation_time_ns: TimestampNs,
    ) -> Result<(ShadowOutboundEnvelopeV1, Vec<ModelEffect>), ShadowErrorV1> {
        self.create_local_carrier_with_application(
            round,
            transactions_commitment,
            None,
            None,
            creation_time_ns,
        )
    }

    fn create_local_carrier_with_application(
        &mut self,
        round: RoundNumber,
        transactions_commitment: TransactionsCommitment,
        application_header: Option<RbcCanonicalHeader>,
        consensus_vertex: Option<ConsensusVertexV1>,
        creation_time_ns: TimestampNs,
    ) -> Result<(ShadowOutboundEnvelopeV1, Vec<ModelEffect>), ShadowErrorV1> {
        self.ensure_live()?;
        let (own_prev, weak_parents) = self.model.local_parent_set()?;
        let candidate = CandidateCarrierV1::try_new_with_committee(
            CarrierHeaderV1Args {
                author: self.own_authority,
                carrier_round: round,
                own_prev,
                weak_parents,
                transactions_commitment,
                application_header,
                data_acknowledgments: Vec::new(),
                phase_batch: self.model.pending_phase_batch(),
                consensus_vertex,
                creation_time_ns,
            },
            &self.committee,
        )?;
        let authenticated = self.context.authenticate_local_with_committee(
            candidate,
            &self.committee,
            self.authorizer.authorizer(self.own_authority),
        )?;
        let envelope = ShadowOutboundEnvelopeV1 {
            reference: authenticated.reference(),
            canonical_carrier_wire: authenticated.candidate().canonical_wire_bytes()?,
            authentication_sidecar: authenticated.authentication().canonical_wire_bytes(),
        };
        let effects = self.apply_durable(ShadowInputV1::LocalOutbound(authenticated))?;
        debug_assert!(
            self.journal
                .snapshot()
                .outbound(envelope.reference())
                .is_some_and(|outbound| outbound.exposed())
        );
        Ok((envelope, effects))
    }

    /// Create the currently open autonomous control slot with no application
    /// payload. The caller supplies only a timestamp: the round is derived
    /// from the durable reducer and the empty commitment is canonical.
    pub(crate) fn create_local_control_heartbeat(
        &mut self,
        creation_time_ns: TimestampNs,
        allow_no_vote: bool,
    ) -> Result<(ShadowOutboundEnvelopeV1, Vec<ModelEffect>), ShadowErrorV1> {
        let round = self.model.local_carrier_round();
        let (own_prev, _) = self.model.local_parent_set()?;
        let consensus_vertex = self.build_local_consensus_vertex(own_prev, allow_no_vote);
        self.create_local_carrier_with_application(
            round,
            TransactionsCommitment::default(),
            None,
            consensus_vertex,
            creation_time_ns,
        )
    }

    /// Assign one exact direct application header to the currently open
    /// independent carrier slot. The complete canonical header is committed
    /// by the V2 carrier and is therefore recoverable from carrier content.
    pub(crate) fn create_local_application_carrier(
        &mut self,
        application_header: RbcCanonicalHeader,
        creation_time_ns: TimestampNs,
        allow_no_vote: bool,
    ) -> Result<(ShadowOutboundEnvelopeV1, Vec<ModelEffect>), ShadowErrorV1> {
        let round = self.model.local_carrier_round();
        let commitment = application_header.transactions_commitment();
        let (own_prev, _) = self.model.local_parent_set()?;
        let consensus_vertex = self.build_local_consensus_vertex(own_prev, allow_no_vote);
        self.create_local_carrier_with_application(
            round,
            commitment,
            Some(application_header),
            consensus_vertex,
            creation_time_ns,
        )
    }

    fn build_local_consensus_vertex(
        &self,
        own_prev: BlockReference,
        allow_no_vote: bool,
    ) -> Option<ConsensusVertexV1> {
        // `allow_no_vote` authorizes the complete C2/C3 fallback, including a
        // late Vote when the scheduled leader exists. The service must bind
        // that authorization to this logical consensus slot, not to a global
        // physical-carrier heartbeat.
        let consensus_round = self.next_local_consensus_round();
        let (strong_parents, leader_choice) = if consensus_round == 1 {
            let strong_parents = self
                .committee
                .committee()
                .authorities()
                .map(|authority| {
                    ConsensusVertexReference::new(carrier_genesis_reference(authority), 0)
                })
                .collect::<Vec<_>>();
            let leader_author = self.committee.committee().elect_leader(0);
            (
                strong_parents,
                LeaderChoiceV1::Vote {
                    leader: ConsensusVertexReference::new(
                        carrier_genesis_reference(leader_author),
                        0,
                    ),
                },
            )
        } else {
            let parent_round = consensus_round - 1;
            let mut by_author = BTreeMap::new();
            for parent in self
                .promised_projection
                .projected_values_at_round(parent_round)
            {
                by_author.entry(parent.author()).or_insert(parent);
            }
            let own_parent = *by_author.get(&self.own_authority)?;
            let stake = by_author
                .keys()
                .filter_map(|authority| self.committee.committee().get_stake(*authority))
                .fold(0, Stake::saturating_add);
            if stake < self.committee.committee().quorum_threshold() {
                return None;
            }
            let leader_author = self.committee.committee().elect_leader(parent_round);
            let leader = by_author.get(&leader_author).copied();
            let (strong_parents, leader_choice) = if consensus_round >= 3 {
                let witness = match leader {
                    Some(leader) => match self
                        .promised_projection
                        .c1_strong_parent_witness(consensus_round, &[own_parent, leader])
                    {
                        Ok(witness) => witness,
                        Err(_) => return None,
                    },
                    None => None,
                };
                match (leader, witness) {
                    (Some(leader), Some(witness)) => {
                        let witness_parents = match &witness {
                            C1StrongParentWitnessV1::Vote {
                                leader: witnessed,
                                parents,
                            } => {
                                debug_assert_eq!(
                                    witnessed.consensus_round(),
                                    consensus_round.saturating_sub(2)
                                );
                                parents
                            }
                            C1StrongParentWitnessV1::DirectSkip { slot, parents } => {
                                debug_assert_eq!(slot.round, consensus_round.saturating_sub(2));
                                parents
                            }
                        };
                        if !witness_parents.contains(&own_parent)
                            || !witness_parents.contains(&leader)
                        {
                            return None;
                        }
                        (witness_parents.clone(), LeaderChoiceV1::Vote { leader })
                    }
                    _ if !allow_no_vote => return None,
                    _ => self.fallback_strong_parents(
                        &by_author,
                        own_parent,
                        leader,
                        leader_author,
                        parent_round,
                    )?,
                }
            } else {
                match leader {
                    Some(leader) => (
                        self.minimal_strong_parent_quorum(&by_author, [own_parent, leader])?,
                        LeaderChoiceV1::Vote { leader },
                    ),
                    None if allow_no_vote => self.fallback_strong_parents(
                        &by_author,
                        own_parent,
                        None,
                        leader_author,
                        parent_round,
                    )?,
                    None => return None,
                }
            };
            debug_assert!(strong_parents.contains(&own_parent));
            (strong_parents, leader_choice)
        };

        let mut delivery_frontier = self
            .promised_projection
            .joined_strong_parent_frontier(&strong_parents)
            .ok()?;
        let own_entry = (own_prev.round != 0).then_some(own_prev);
        // The enclosing carrier is not clean yet, so its immediate physical
        // predecessor may be ahead of today's closed tip. The immutable
        // declaration names that exact predecessor; projection later proves
        // the intervening self-chain closed before accepting this vertex.
        delivery_frontier.get(self.own_authority as usize)?;
        delivery_frontier[self.own_authority as usize] = own_entry;
        Some(ConsensusVertexV1::new(
            consensus_round,
            strong_parents,
            delivery_frontier,
            leader_choice,
        ))
    }

    fn fallback_strong_parents(
        &self,
        by_author: &BTreeMap<AuthorityIndex, ConsensusVertexReference>,
        own_parent: ConsensusVertexReference,
        leader: Option<ConsensusVertexReference>,
        leader_author: AuthorityIndex,
        leader_round: RoundNumber,
    ) -> Option<(Vec<ConsensusVertexReference>, LeaderChoiceV1)> {
        match leader {
            Some(leader) => Some((
                self.minimal_strong_parent_quorum(by_author, [own_parent, leader])?,
                LeaderChoiceV1::Vote { leader },
            )),
            None => Some((
                self.minimal_strong_parent_quorum(by_author, [own_parent])?,
                LeaderChoiceV1::NoVote {
                    leader_author,
                    leader_round,
                },
            )),
        }
    }

    fn minimal_strong_parent_quorum<const N: usize>(
        &self,
        by_author: &BTreeMap<AuthorityIndex, ConsensusVertexReference>,
        required: [ConsensusVertexReference; N],
    ) -> Option<Vec<ConsensusVertexReference>> {
        self.promised_projection
            .frontier_fresh_quorum(by_author.values().copied(), &required)
            .ok()
            .flatten()
    }

    pub(crate) fn next_local_consensus_round(&self) -> RoundNumber {
        self.next_local_consensus_round
    }

    /// Whether the currently open logical slot can be fixed through the
    /// optimistic C1 path using only already-promised projection state. This
    /// is a pure preview of the same builder used for durable carrier
    /// creation; callers must recompute when they actually create.
    pub(crate) fn local_consensus_vertex_c1_ready(&self) -> bool {
        if self.next_local_consensus_round <= 1 {
            return false;
        }
        let Ok((own_prev, _)) = self.model.local_parent_set() else {
            return false;
        };
        self.build_local_consensus_vertex(own_prev, false).is_some()
    }

    pub(crate) fn projected_consensus_stake(&self, round: RoundNumber) -> Stake {
        self.promised_projection.projected_stake_at_round(round)
    }

    pub(crate) fn has_projected_consensus_quorum(&self, round: RoundNumber) -> bool {
        self.projected_consensus_stake(round) >= self.committee.committee().quorum_threshold()
    }

    #[cfg(test)]
    pub(crate) fn inject_projected_consensus_for_test(
        &mut self,
        reference: ConsensusVertexReference,
        strong_parents: Vec<ConsensusVertexReference>,
        leader_choice: LeaderChoiceV1,
    ) {
        self.promised_projection.inject_projected_for_test(
            reference,
            strong_parents,
            leader_choice,
        );
    }

    #[cfg(test)]
    pub(crate) fn set_next_local_consensus_round_for_test(&mut self, round: RoundNumber) {
        self.next_local_consensus_round = round;
    }

    pub(crate) fn projection_runtime_snapshot(&self) -> ProjectionRuntimeSnapshotV1 {
        let decidable_round = self.highest_projected_consensus_round.saturating_sub(2);
        let hol_reason = if self.next_undecided_consensus_round > decidable_round {
            ProjectionHolReasonV1::InsufficientLookahead
        } else {
            let slot = self
                .projection
                .leader_slot(self.next_undecided_consensus_round);
            match self.projection.direct_decision(slot) {
                Err(_) => ProjectionHolReasonV1::DirectEvidencePending,
                Ok(ProjectionDecisionV1::Undecided { .. }) => {
                    ProjectionHolReasonV1::AwaitingIndirectAnchor
                }
                Ok(
                    ProjectionDecisionV1::DirectCommit { .. }
                    | ProjectionDecisionV1::DirectSkip { .. }
                    | ProjectionDecisionV1::IndirectCommit { .. }
                    | ProjectionDecisionV1::IndirectSkip { .. },
                ) => ProjectionHolReasonV1::Ready,
            }
        };
        ProjectionRuntimeSnapshotV1 {
            pending_candidates: self.pending_projection_candidates.len(),
            highest_projected_round: self.highest_projected_consensus_round,
            next_undecided_round: self.next_undecided_consensus_round,
            next_undecided_projected_stake: self
                .projection
                .projected_stake_at_round(self.next_undecided_consensus_round),
            last_committed_round: self.highest_committed_consensus_round,
            hol_reason,
        }
    }

    /// Verify and durably apply an authenticated network envelope for this
    /// exact receiver.
    #[cfg(test)]
    pub(crate) fn receive_authenticated_envelope(
        &mut self,
        canonical_carrier_wire: &[u8],
        authentication_sidecar: &[u8],
        provenance: IngressProvenanceV1,
    ) -> Result<Vec<ModelEffect>, ShadowErrorV1> {
        self.ensure_live()?;
        let candidate = decode_candidate(canonical_carrier_wire, &self.committee, None)?;
        validate_provenance(provenance, candidate.header().author(), &self.committee)?;
        self.receive_decoded_authenticated(candidate, authentication_sidecar, provenance)
    }

    /// Classify provenance from the authenticated transport peer and the
    /// already-decoded carrier author, then verify and apply the envelope.
    /// The candidate bytes are decoded exactly once in this method.
    #[cfg(test)]
    pub(crate) fn receive_authenticated_from_peer(
        &mut self,
        canonical_carrier_wire: &[u8],
        authentication_sidecar: &[u8],
        trusted_peer: AuthorityIndex,
    ) -> Result<Vec<ModelEffect>, ShadowErrorV1> {
        self.ensure_live()?;
        if !self.committee.committee().known_authority(trusted_peer) {
            return Err(ShadowErrorV1::UnknownAuthority(trusted_peer));
        }
        let candidate = decode_candidate(canonical_carrier_wire, &self.committee, None)?;
        let provenance = infer_ingress_provenance(trusted_peer, candidate.header().author());
        self.receive_decoded_authenticated(candidate, authentication_sidecar, provenance)
    }

    /// Verify an envelope when possible and otherwise durably retain its
    /// canonical content as candidate-only input. This is the normal network
    /// ingress API: a poisoned receiver tag must not discard the content that
    /// embedded ECHO/READY evidence can later deliver.
    pub(crate) fn receive_or_retain_from_peer(
        &mut self,
        canonical_carrier_wire: &[u8],
        authentication_sidecar: &[u8],
        trusted_peer: AuthorityIndex,
    ) -> Result<ShadowIngressOutcomeV1, ShadowErrorV1> {
        self.receive_or_retain_from_peer_with_future_window(
            canonical_carrier_wire,
            authentication_sidecar,
            trusted_peer,
            EXECUTABLE_MODEL_BUFFER_WINDOW_V1,
        )
    }

    /// Normal operation retains the full prototype elasticity window. During
    /// exact catch-up the service narrows unsolicited ingress to the admission
    /// horizon so replay responses are not starved behind duplicate future
    /// work; requested exact-slot synchronization uses the normal window and
    /// remains unaffected.
    pub(crate) fn receive_or_retain_from_peer_with_future_window(
        &mut self,
        canonical_carrier_wire: &[u8],
        authentication_sidecar: &[u8],
        trusted_peer: AuthorityIndex,
        future_window: RoundNumber,
    ) -> Result<ShadowIngressOutcomeV1, ShadowErrorV1> {
        self.ensure_live()?;
        if !self.committee.committee().known_authority(trusted_peer) {
            return Err(ShadowErrorV1::UnknownAuthority(trusted_peer));
        }
        let candidate = decode_candidate(canonical_carrier_wire, &self.committee, None)?;
        let provenance = infer_ingress_provenance(trusted_peer, candidate.header().author());
        // A healthy quorum may run ahead of a temporarily descheduled peer,
        // but arbitrary unsolicited future traffic must not consume MAC or
        // signature verification and durable reducer capacity. Exact sync
        // requests recover the receiver's current slot one round at a time.
        if candidate.reference().round
            > self
                .model
                .local_carrier_round()
                .saturating_add(future_window.min(EXECUTABLE_MODEL_BUFFER_WINDOW_V1))
        {
            return Ok(ShadowIngressOutcomeV1::new(
                ShadowIngressDispositionV1::IgnoredFutureOutsideBuffer,
                Vec::new(),
            ));
        }
        // Once a slot has a durably authenticated value, unsolicited replays
        // and conflicts cannot change the shadow state. Reject before public
        // signature/ML-DSA verification to keep this idempotence cheap.
        if self.ignores_unsolicited_authenticated(&candidate) {
            return Ok(ShadowIngressOutcomeV1::new(
                ShadowIngressDispositionV1::IgnoredDuplicateConflictOrStale,
                Vec::new(),
            ));
        }
        match self.authenticate_decoded(candidate.clone(), authentication_sidecar) {
            Ok(authenticated) => {
                let (effects, applied) =
                    self.apply_authenticated_capability(authenticated, provenance)?;
                let disposition = if applied {
                    ShadowIngressDispositionV1::Authenticated
                } else {
                    ShadowIngressDispositionV1::IgnoredDuplicateConflictOrStale
                };
                Ok(ShadowIngressOutcomeV1::new(disposition, effects))
            }
            Err(ShadowErrorV1::Carrier(_)) | Err(ShadowErrorV1::NonCanonicalAuthentication) => {
                let (effects, applied) = self.apply_candidate_retention(candidate)?;
                let disposition = if applied {
                    ShadowIngressDispositionV1::CandidateRetained
                } else {
                    ShadowIngressDispositionV1::IgnoredDuplicateConflictOrStale
                };
                Ok(ShadowIngressOutcomeV1::new(disposition, effects))
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(test)]
    fn receive_decoded_authenticated(
        &mut self,
        candidate: CandidateCarrierV1,
        authentication_sidecar: &[u8],
        provenance: IngressProvenanceV1,
    ) -> Result<Vec<ModelEffect>, ShadowErrorV1> {
        let authenticated = self.authenticate_decoded(candidate, authentication_sidecar)?;
        self.apply_authenticated_capability(authenticated, provenance)
            .map(|(effects, _)| effects)
    }

    fn authenticate_decoded(
        &self,
        candidate: CandidateCarrierV1,
        authentication_sidecar: &[u8],
    ) -> Result<AuthenticatedCarrierV1, ShadowErrorV1> {
        let authentication = decode_authentication(authentication_sidecar, &self.committee)?;
        Ok(self.context.verify_authentication_with_committee(
            candidate,
            authentication,
            self.own_authority,
            &self.committee,
            self.authorizer.inbound_mac_keys(),
        )?)
    }

    fn apply_authenticated_capability(
        &mut self,
        authenticated: AuthenticatedCarrierV1,
        provenance: IngressProvenanceV1,
    ) -> Result<(Vec<ModelEffect>, bool), ShadowErrorV1> {
        let reference = authenticated.reference();
        let slot = carrier_slot(reference);
        if round_is_stale(self.model.local_carrier_round(), reference.round)
            || self.authenticated_slots.contains_key(&slot)
        {
            return Ok((Vec::new(), false));
        }
        self.apply_durable(ShadowInputV1::AuthenticatedIngress {
            authenticated,
            provenance,
        })
        .map(|effects| (effects, true))
    }

    fn ignores_unsolicited_authenticated(&self, candidate: &CandidateCarrierV1) -> bool {
        let reference = candidate.reference();
        round_is_stale(self.model.local_carrier_round(), reference.round)
            || self
                .authenticated_slots
                .contains_key(&carrier_slot(reference))
    }

    fn apply_candidate_retention(
        &mut self,
        candidate: CandidateCarrierV1,
    ) -> Result<(Vec<ModelEffect>, bool), ShadowErrorV1> {
        let reference = candidate.reference();
        let slot = carrier_slot(reference);
        if round_is_stale(self.model.local_carrier_round(), reference.round)
            || self.candidates.contains_key(&reference)
            || self.authenticated_slots.contains_key(&slot)
            || self.ordinarily_retained_slots.contains_key(&slot)
        {
            return Ok((Vec::new(), false));
        }
        self.apply_durable(ShadowInputV1::CandidateRetention(candidate))
            .map(|effects| (effects, true))
    }

    /// Recover content only if it recomputes the exact requested reference.
    pub(crate) fn recover_candidate_for(
        &mut self,
        expected_reference: BlockReference,
        canonical_carrier_wire: &[u8],
    ) -> Result<Vec<ModelEffect>, ShadowErrorV1> {
        self.ensure_live()?;
        let candidate = decode_candidate(
            canonical_carrier_wire,
            &self.committee,
            Some(expected_reference),
        )?;
        self.apply_requested_recovery(candidate)
    }

    /// Recover an exact phase-evidenced carrier through the ordinary
    /// receiver-bound authentication predicate. A valid sidecar variant is
    /// durably recorded as relayed/direct authenticated ingress; an invalid
    /// variant retains the exact requested content through the existing
    /// content-only recovery path. MAC failures assign no blame.
    pub(crate) fn recover_or_admit_from_peer(
        &mut self,
        expected_reference: BlockReference,
        canonical_carrier_wire: &[u8],
        authentication_sidecar: &[u8],
        trusted_peer: AuthorityIndex,
    ) -> Result<ShadowIngressOutcomeV1, ShadowErrorV1> {
        self.ensure_live()?;
        if !self.committee.committee().known_authority(trusted_peer) {
            return Err(ShadowErrorV1::UnknownAuthority(trusted_peer));
        }
        if !self.requested_recoveries.contains_key(&expected_reference) {
            return Err(ShadowErrorV1::UnrequestedRecovery(expected_reference));
        }
        let candidate = decode_candidate(
            canonical_carrier_wire,
            &self.committee,
            Some(expected_reference),
        )?;
        let provenance = infer_ingress_provenance(trusted_peer, candidate.header().author());
        validate_provenance(provenance, candidate.header().author(), &self.committee)?;

        match self.authenticate_decoded(candidate.clone(), authentication_sidecar) {
            Ok(authenticated) => {
                let (effects, applied) =
                    self.apply_authenticated_capability(authenticated, provenance)?;
                if applied {
                    return Ok(ShadowIngressOutcomeV1::new(
                        ShadowIngressDispositionV1::Authenticated,
                        effects,
                    ));
                }
            }
            Err(ShadowErrorV1::Carrier(_)) | Err(ShadowErrorV1::NonCanonicalAuthentication) => {}
            Err(error) => return Err(error),
        }

        let effects = self.apply_requested_recovery(candidate)?;
        Ok(ShadowIngressOutcomeV1::new(
            ShadowIngressDispositionV1::CandidateRetained,
            effects,
        ))
    }

    pub(crate) fn retained_candidate_wire(&self, reference: BlockReference) -> Option<Vec<u8>> {
        self.journal
            .snapshot()
            .retained_carrier(reference)
            .map(<[u8]>::to_vec)
    }

    /// Return one exact, durably retained authentication variant for a
    /// carrier. Locally authored envelopes use the outbound WAL record;
    /// received envelopes use the first authenticated ingress record, whose
    /// provenance and bytes replay identically after restart.
    pub(crate) fn retained_authenticated_envelope(
        &self,
        reference: BlockReference,
    ) -> Option<ShadowOutboundEnvelopeV1> {
        if reference.authority == self.own_authority {
            return self
                .local_outbound_envelope(reference.round)
                .filter(|envelope| envelope.reference() == reference);
        }
        self.journal
            .snapshot()
            .authenticated_ingress()
            .iter()
            .find(|ingress| ingress.reference() == reference)
            .map(|ingress| ShadowOutboundEnvelopeV1 {
                reference,
                canonical_carrier_wire: ingress.canonical_carrier_wire().to_vec(),
                authentication_sidecar: ingress.authentication_sidecar().to_vec(),
            })
    }

    /// Decode canonical carrier bytes without mutating the reducer. Sync
    /// clients use this to bind a response to the requested author and round
    /// before passing it through normal authenticated ingress.
    pub(crate) fn candidate_slot(
        &self,
        canonical_carrier_wire: &[u8],
    ) -> Result<(AuthorityIndex, RoundNumber, BlockReference), ShadowErrorV1> {
        let candidate = decode_candidate(canonical_carrier_wire, &self.committee, None)?;
        Ok((
            candidate.header().author(),
            candidate.header().carrier_round(),
            candidate.reference(),
        ))
    }

    /// Return the exact durably exposed local envelope for one carrier round.
    /// Missing, incomplete, or unexposed slots are never served.
    pub(crate) fn local_outbound_envelope(
        &self,
        round: RoundNumber,
    ) -> Option<ShadowOutboundEnvelopeV1> {
        let snapshot = self.journal.snapshot();
        let reference = snapshot.own_carrier(round)?;
        let outbound = snapshot.outbound(reference)?;
        outbound.exposed().then(|| ShadowOutboundEnvelopeV1 {
            reference: outbound.reference(),
            canonical_carrier_wire: outbound.canonical_carrier_wire().to_vec(),
            authentication_sidecar: outbound.authentication_sidecar().to_vec(),
        })
    }

    /// Return every exposed local carrier in deterministic reference order.
    /// The same full sidecar is returned for every peer.
    pub(crate) fn retransmissions(&self) -> Vec<ShadowOutboundEnvelopeV1> {
        self.journal
            .snapshot()
            .retransmissions()
            .into_iter()
            .map(|outbound| ShadowOutboundEnvelopeV1 {
                reference: outbound.reference(),
                canonical_carrier_wire: outbound.canonical_carrier_wire().to_vec(),
                authentication_sidecar: outbound.authentication_sidecar().to_vec(),
            })
            .collect()
    }

    /// Metadata for every durably exposed local carrier, ordered by its exact
    /// persisted reference. Startup uses this to prove that the shadow WAL and
    /// recovered authoritative local chain overlap on the same application
    /// payload and creation timestamp before accepting new observations.
    pub(crate) fn local_outbound_metadata(
        &self,
    ) -> Result<Vec<LocalOutboundMetadataV1>, ShadowErrorV1> {
        self.journal
            .snapshot()
            .retransmissions()
            .into_iter()
            .map(|outbound| {
                let reference = outbound.reference();
                let candidate = self
                    .candidates
                    .get(&reference)
                    .ok_or(ShadowErrorV1::MissingOutboundCandidate(reference))?;
                Ok(LocalOutboundMetadataV1 {
                    round: candidate.header().carrier_round(),
                    transactions_commitment: candidate.header().transactions_commitment(),
                    creation_time_ns: candidate.header().creation_time_ns(),
                    control_shape: candidate.header().data_acknowledgments().is_empty(),
                    application: candidate
                        .header()
                        .application_header()
                        .map(RbcCanonicalHeader::reference),
                })
            })
            .collect()
    }

    pub(crate) fn delivered_identities(
        &self,
    ) -> Result<Vec<ShadowDeliveryIdentityV1>, ShadowErrorV1> {
        self.delivered
            .iter()
            .map(|reference| self.delivery_identity(*reference))
            .collect()
    }

    pub(crate) fn delivery_identity(
        &self,
        reference: BlockReference,
    ) -> Result<ShadowDeliveryIdentityV1, ShadowErrorV1> {
        let candidate = self
            .candidates
            .get(&reference)
            .ok_or(ShadowErrorV1::MissingDeliveredCandidate(reference))?;
        Ok(ShadowDeliveryIdentityV1::new(
            candidate.header().author(),
            candidate.header().carrier_round(),
            candidate.header().transactions_commitment(),
        ))
    }

    /// Exact application headers whose enclosing carriers reached embedded
    /// RBC delivery. Control-only carrier deliveries are intentionally absent.
    pub(crate) fn delivered_application_headers(
        &self,
    ) -> Result<Vec<(BlockReference, RbcCanonicalHeader)>, ShadowErrorV1> {
        self.delivered
            .iter()
            .filter_map(|carrier_reference| {
                match self.delivered_application_header(*carrier_reference) {
                    Ok(Some(application)) => Some(Ok(application)),
                    Ok(None) => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .collect()
    }

    pub(crate) fn delivered_application_header(
        &self,
        carrier_reference: BlockReference,
    ) -> Result<Option<(BlockReference, RbcCanonicalHeader)>, ShadowErrorV1> {
        let candidate = self
            .candidates
            .get(&carrier_reference)
            .ok_or(ShadowErrorV1::MissingDeliveredCandidate(carrier_reference))?;
        Ok(candidate
            .header()
            .application_header()
            .map(|header| (carrier_reference, header.clone())))
    }

    /// Compare protocol-independent delivery sets. Multiple transaction
    /// commitments for one `(author, round)` slot make the comparison
    /// ambiguous instead of being resolved by arrival or reference order.
    #[cfg(test)]
    pub(crate) fn compare_direct_deliveries<I>(
        &self,
        direct: I,
    ) -> Result<ShadowDeliveryComparisonV1, ShadowErrorV1>
    where
        I: IntoIterator<Item = ShadowDeliveryIdentityV1>,
    {
        let direct: BTreeSet<_> = direct.into_iter().collect();
        let shadow: BTreeSet<_> = self.delivered_identities()?.into_iter().collect();
        let ambiguous = ambiguous_slots(&direct)
            .into_iter()
            .chain(ambiguous_slots(&shadow))
            .collect::<BTreeSet<_>>();
        if !ambiguous.is_empty() {
            return Ok(ShadowDeliveryComparisonV1::Ambiguous {
                slots: ambiguous.into_iter().collect(),
            });
        }
        if direct == shadow {
            return Ok(ShadowDeliveryComparisonV1::Match);
        }
        Ok(ShadowDeliveryComparisonV1::Mismatch {
            direct_only: direct.difference(&shadow).copied().collect(),
            shadow_only: shadow.difference(&direct).copied().collect(),
        })
    }

    pub(crate) fn shutdown(self) -> Result<ShadowWalSummaryV1, ShadowErrorV1> {
        Ok(self.wal.shutdown()?)
    }

    fn drive_certified_projection(&mut self) -> Result<(), ShadowErrorV1> {
        loop {
            let mut advanced = false;
            let candidates = self
                .pending_projection_candidates
                .iter()
                .copied()
                .collect::<Vec<_>>();
            for reference in candidates {
                match self.projection.try_project(reference) {
                    Ok(projected) => {
                        self.pending_projection_candidates.remove(&reference);
                        self.highest_projected_consensus_round = self
                            .highest_projected_consensus_round
                            .max(projected.consensus_round());
                        self.pending_projected_vertices.push(projected);
                        advanced = true;
                    }
                    Err(error) if projection_error_is_pending(&error) => {}
                    Err(error) => {
                        self.pending_projection_candidates.remove(&reference);
                        self.projection_rejected.insert(reference, error);
                    }
                }
            }
            if !advanced {
                break;
            }
        }

        self.drive_ordered_committer(self.highest_projected_consensus_round)
    }

    /// Advance the planning-only projection without emitting vertices,
    /// decisions, anchors, or committed frontiers. A rejected promised value
    /// is isolated here; certified projection continues independently.
    fn drive_promised_projection(&mut self) {
        loop {
            let mut advanced = false;
            let candidates = self
                .pending_promised_projection_candidates
                .iter()
                .copied()
                .collect::<Vec<_>>();
            for reference in candidates {
                match self.promised_projection.try_project(reference) {
                    Ok(_) => {
                        self.pending_promised_projection_candidates
                            .remove(&reference);
                        advanced = true;
                    }
                    Err(error) if projection_error_is_pending(&error) => {}
                    Err(error) => {
                        self.pending_promised_projection_candidates
                            .remove(&reference);
                        self.promised_projection_rejected.insert(reference, error);
                    }
                }
            }
            if !advanced {
                break;
            }
        }
    }

    /// Resolve durable promise effects only once exact canonical content is
    /// locally staged. Missing content remains an explicit replay-derived
    /// pending reference until authenticated ingress or exact recovery stores
    /// it; no placeholder can enter either projection plane or the delivered
    /// application set.
    fn activate_promised_references(&mut self) {
        let available = self
            .pending_promised_references
            .iter()
            .copied()
            .filter(|reference| self.promised_projection.carrier_is_stored(*reference))
            .collect::<Vec<_>>();
        for reference in available {
            self.promised_projection
                .mark_promised(reference)
                .expect("a stored model promise must be valid in the promised plane");
            self.projection
                .mark_delivered(reference)
                .expect("a stored optimistic delivery must be valid in the certified plane");
            self.delivered.insert(reference);
            self.requested_recoveries.remove(&reference);
            self.pending_promised_references.remove(&reference);
        }
    }

    fn drive_ordered_committer(&mut self, highest_round: RoundNumber) -> Result<(), ShadowErrorV1> {
        let decidable_round = highest_round.saturating_sub(2);
        if self.next_undecided_consensus_round > decidable_round {
            return Ok(());
        }

        // Plan from newest to oldest, as the universal Starfish committer
        // does. An indirect decision may use only the first committed leader
        // in this already-decided suffix; a still-undecided intervening slot
        // is a hard barrier. This makes anchor selection independent of which
        // later direct certificate happened to arrive first locally.
        let mut planned = VecDeque::new();
        for round in (self.next_undecided_consensus_round..=decidable_round).rev() {
            let slot = self.projection.leader_slot(round);
            let direct = self.projection.direct_decision(slot)?;
            let decision = match direct {
                ProjectionDecisionV1::Undecided { .. } => {
                    let minimum_anchor_round = round.saturating_add(3);
                    let mut anchor = None;
                    for later in planned.iter().filter(|later| {
                        projection_decision_slot(**later).round >= minimum_anchor_round
                    }) {
                        match later {
                            ProjectionDecisionV1::DirectCommit { leader }
                            | ProjectionDecisionV1::IndirectCommit { leader, .. } => {
                                anchor = Some(*leader);
                                break;
                            }
                            ProjectionDecisionV1::DirectSkip { .. }
                            | ProjectionDecisionV1::IndirectSkip { .. } => {}
                            ProjectionDecisionV1::Undecided { .. } => break,
                        }
                    }
                    let Some(anchor) = anchor else {
                        planned.push_front(direct);
                        continue;
                    };
                    self.projection.indirect_decision(slot, anchor)?
                }
                ProjectionDecisionV1::DirectCommit { .. }
                | ProjectionDecisionV1::DirectSkip { .. } => direct,
                ProjectionDecisionV1::IndirectCommit { .. }
                | ProjectionDecisionV1::IndirectSkip { .. } => {
                    unreachable!("direct decision returned an indirect result")
                }
            };
            planned.push_front(decision);
        }

        // Emit only the longest finalized prefix. Every committed leader,
        // including an indirectly committed one, contributes its frontier at
        // its exact position in that agreed leader order. Later deciding
        // anchors are therefore never applied ahead of older leaders.
        for decision in planned {
            if matches!(decision, ProjectionDecisionV1::Undecided { .. }) {
                break;
            }
            match decision {
                ProjectionDecisionV1::DirectCommit { leader }
                | ProjectionDecisionV1::IndirectCommit { leader, .. } => {
                    self.commit_projected_anchor(leader)?;
                }
                ProjectionDecisionV1::DirectSkip { .. }
                | ProjectionDecisionV1::IndirectSkip { .. } => {}
                ProjectionDecisionV1::Undecided { .. } => unreachable!("handled above"),
            }
            let round = projection_decision_slot(decision).round;
            self.record_projection_decision(decision);
            self.next_undecided_consensus_round = round.saturating_add(1);
        }
        Ok(())
    }

    /// Commit the longest consecutive prefix backed by an exact projected
    /// vote quorum. Two conflicting vote quorums, or a vote quorum and a
    /// negative-choice skip quorum, intersect in honest stake; an honest
    /// logical author fixes exactly one choice. Reliable projected delivery
    /// then makes the certificate eventually visible to every honest node.
    /// This removes the redundant second certificate wave from the optimistic
    /// direct-commit path while leaving skip and indirect recovery unchanged.
    fn drive_vote_quorum_committer(&mut self) -> Result<(), ShadowErrorV1> {
        loop {
            let slot = self
                .projection
                .leader_slot(self.next_undecided_consensus_round);
            let mut certified = Vec::new();
            for leader in self.projection.leader_values(slot) {
                if self.projection.vote_stake(leader)?
                    >= self.committee.committee().quorum_threshold()
                {
                    certified.push(leader);
                }
            }
            if certified.len() > 1 {
                return Err(CertifiedProjectionError::MultipleCertifiedLeaderValues(slot).into());
            }
            let Some(leader) = certified.pop() else {
                return Ok(());
            };
            let decision = ProjectionDecisionV1::DirectCommit { leader };
            self.commit_projected_anchor(leader)?;
            self.record_projection_decision(decision);
            self.next_undecided_consensus_round = slot.round.saturating_add(1);
        }
    }

    fn record_projection_decision(&mut self, decision: ProjectionDecisionV1) {
        if self.projected_decisions.insert(decision) {
            let slot = projection_decision_slot(decision);
            assert!(
                self.projected_decision_slots.insert(slot),
                "one logical leader slot cannot retain conflicting projection decisions"
            );
            self.pending_projection_decisions.push(decision);
        }
    }

    fn commit_projected_anchor(
        &mut self,
        anchor: ConsensusVertexReference,
    ) -> Result<(), ShadowErrorV1> {
        if self.projection.is_committed_anchor(anchor) {
            return Ok(());
        }
        let next_count = self
            .committed_output_count
            .checked_add(1)
            .ok_or(ShadowErrorV1::FrontierOutputSequenceOverflow(u64::MAX))?;
        let output_sequence = RoundNumber::try_from(next_count)
            .map_err(|_| ShadowErrorV1::FrontierOutputSequenceOverflow(next_count))?;
        let frontier = self
            .projection
            .record_committed_anchor(anchor)
            .unwrap_or_else(|error| {
                panic!("committed clean anchor frontiers must have an exact-prefix join: {error}")
            });
        self.highest_committed_consensus_round = self
            .highest_committed_consensus_round
            .max(anchor.consensus_round());
        let carriers = self
            .model
            .apply_frontier(&frontier)
            .expect("projection and reducer closed prefixes must agree");
        let mut applications = Vec::new();
        let mut application_diagnostics = Vec::new();
        for carrier in &carriers {
            let Some(application) = self
                .candidates
                .get(carrier)
                .and_then(|candidate| candidate.header().application_header())
                .cloned()
            else {
                continue;
            };
            if !self.included_applications.insert(application.reference()) {
                continue;
            }
            applications.push(application);
            application_diagnostics.push(CommittedApplicationDiagnosticV1::new(anchor, *carrier));
        }
        self.pending_committed_frontiers
            .push(CommittedFrontierDeltaV1 {
                output_sequence,
                anchor,
                frontier,
                carriers,
                applications,
                application_diagnostics,
            });
        self.committed_output_count = next_count;
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), ShadowErrorV1> {
        if self.poisoned || self.wal.is_poisoned() {
            Err(ShadowErrorV1::Poisoned)
        } else {
            Ok(())
        }
    }

    fn apply_requested_recovery(
        &mut self,
        candidate: CandidateCarrierV1,
    ) -> Result<Vec<ModelEffect>, ShadowErrorV1> {
        let reference = candidate.reference();
        if self.candidates.contains_key(&reference) {
            return Ok(Vec::new());
        }
        if !self.requested_recoveries.contains_key(&reference) {
            return Err(ShadowErrorV1::UnrequestedRecovery(reference));
        }
        let slot = carrier_slot(reference);
        let limit = self
            .committee
            .committee()
            .len()
            .saturating_mul(2)
            .saturating_add(2);
        if self
            .slot_candidates
            .get(&slot)
            .is_some_and(|candidates| candidates.len() >= limit)
        {
            return Err(ShadowErrorV1::SlotCandidateLimit {
                author: reference.authority,
                round: reference.round,
                limit,
            });
        }
        self.apply_durable(ShadowInputV1::CandidateRecovery(candidate))
    }

    fn apply_durable(&mut self, input: ShadowInputV1) -> Result<Vec<ModelEffect>, ShadowErrorV1> {
        let (trace, effects) = self.model.apply_input_unpublished(input.model_input())?;
        let records = match encode_batch(self.context, self.own_authority, &input, &trace) {
            Ok(records) => records,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let journal_events = match journal_transition_events(&self.journal, &input, &trace) {
            Ok(events) => events,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if let Err(error) = self.journal.apply_batch_unpublished(journal_events) {
            self.poisoned = true;
            return Err(ShadowErrorV1::PostModelJournal(error));
        }
        if let Err(error) = self.wal.append_batch(&records) {
            self.poisoned = true;
            return Err(error.into());
        }
        if let Err(error) = self.record_committed_input(&input, &effects) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(effects)
    }

    fn apply_replayed(
        &mut self,
        input: ShadowInputV1,
        records: &[Vec<u8>],
        batch_sequence: u64,
    ) -> Result<Vec<ModelEffect>, ShadowErrorV1> {
        self.validate_replay_policy(&input, batch_sequence)?;
        let recorded_trace = decode_recorded_trace(
            records,
            self.context,
            self.own_authority,
            self.committee.committee().len(),
        )?;
        let (trace, effects) = self.model.apply_input_unpublished(input.model_input())?;
        if trace != recorded_trace {
            return Err(ShadowErrorV1::TraceMismatch { batch_sequence });
        }
        let journal_events = journal_transition_events(&self.journal, &input, &trace)?;
        if let Err(error) = self.journal.apply_batch_unpublished(journal_events) {
            self.poisoned = true;
            return Err(ShadowErrorV1::PostModelJournal(error));
        }
        if let Err(error) = self.record_committed_input(&input, &effects) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(effects)
    }

    fn validate_replay_policy(
        &self,
        input: &ShadowInputV1,
        batch_sequence: u64,
    ) -> Result<(), ShadowErrorV1> {
        let reference = input.candidate().map(CandidateCarrierV1::reference);
        let slot = reference.map(carrier_slot);
        let violation = match input {
            ShadowInputV1::AuthenticatedIngress { .. } => {
                let reference = reference.expect("authenticated ingress has a candidate");
                let slot = slot.expect("authenticated ingress has a slot");
                if round_is_stale(self.model.local_carrier_round(), reference.round) {
                    Some("stale authenticated ingress")
                } else if self.authenticated_slots.contains_key(&slot) {
                    Some("duplicate or conflicting authenticated slot")
                } else {
                    None
                }
            }
            ShadowInputV1::CandidateRetention(_) => {
                let reference = reference.expect("candidate retention has a candidate");
                let slot = slot.expect("candidate retention has a slot");
                if round_is_stale(self.model.local_carrier_round(), reference.round) {
                    Some("stale candidate retention")
                } else if self.candidates.contains_key(&reference)
                    || self.authenticated_slots.contains_key(&slot)
                    || self.ordinarily_retained_slots.contains_key(&slot)
                {
                    Some("duplicate or conflicting ordinary retention")
                } else {
                    None
                }
            }
            ShadowInputV1::CandidateRecovery(_) => {
                let reference = reference.expect("candidate recovery has a candidate");
                let slot = slot.expect("candidate recovery has a slot");
                let limit = self
                    .committee
                    .committee()
                    .len()
                    .saturating_mul(2)
                    .saturating_add(2);
                if self.candidates.contains_key(&reference) {
                    Some("duplicate candidate recovery")
                } else if !self.requested_recoveries.contains_key(&reference) {
                    Some("candidate recovery was not requested")
                } else if self
                    .slot_candidates
                    .get(&slot)
                    .is_some_and(|candidates| candidates.len() >= limit)
                {
                    Some("candidate recovery exceeds the per-slot limit")
                } else {
                    None
                }
            }
            ShadowInputV1::LocalOutbound(_) => None,
            ShadowInputV1::DataAvailable(reference) => {
                (!self.candidates.contains_key(reference)).then_some("unknown available carrier")
            }
        };
        if let Some(reason) = violation {
            return Err(ShadowErrorV1::ReplayPolicyViolation {
                batch_sequence,
                reason,
            });
        }
        Ok(())
    }

    fn record_committed_input(
        &mut self,
        input: &ShadowInputV1,
        effects: &[ModelEffect],
    ) -> Result<(), ShadowErrorV1> {
        if let Some(candidate) = input.candidate().cloned() {
            let reference = candidate.reference();
            let slot = carrier_slot(reference);
            if let Some(vertex) = candidate.header().consensus_vertex() {
                self.pending_promised_projection_candidates
                    .insert(reference);
                self.pending_projection_candidates.insert(reference);
                if input.is_local() {
                    self.next_local_consensus_round = self
                        .next_local_consensus_round
                        .max(vertex.consensus_round().saturating_add(1));
                }
            }
            if let Some(application) = candidate.header().application_header() {
                self.application_carriers
                    .entry(application.reference())
                    .or_default()
                    .insert(reference);
            }
            self.projection
                .stage_carrier(candidate.clone())
                .expect("durably validated carrier must match projection committee");
            self.promised_projection
                .stage_carrier(candidate.clone())
                .expect("durably validated carrier must match promised projection committee");
            // Control carriers have no application materialization boundary,
            // so the exact carrier bytes make them intrinsically available.
            // An embedded application with an empty transaction commitment
            // still needs its canonical header installed in Core before an
            // authoritative frontier may reference it; the typed
            // DataAvailable callback records that separate fact.
            if candidate.header().application_header().is_none()
                && candidate.header().transactions_commitment() == TransactionsCommitment::default()
            {
                self.projection
                    .mark_data_available(reference)
                    .expect("staged control carrier is available");
                self.promised_projection
                    .mark_data_available(reference)
                    .expect("staged control carrier is available to promised projection");
            }
            self.candidates.insert(reference, candidate);
            self.slot_candidates
                .entry(slot)
                .or_default()
                .insert(reference);
            match input {
                ShadowInputV1::AuthenticatedIngress { .. } | ShadowInputV1::LocalOutbound(_) => {
                    self.authenticated_slots.entry(slot).or_insert(reference);
                }
                ShadowInputV1::CandidateRetention(_) => {
                    self.ordinarily_retained_slots
                        .entry(slot)
                        .or_insert(reference);
                }
                ShadowInputV1::CandidateRecovery(_) => {}
                ShadowInputV1::DataAvailable(_) => unreachable!("handled without a candidate"),
            }
            self.requested_recoveries.remove(&reference);
        }
        if let ShadowInputV1::DataAvailable(reference) = input {
            self.projection
                .mark_data_available(*reference)
                .expect("model accepted availability only for a staged carrier");
            self.promised_projection
                .mark_data_available(*reference)
                .expect("model accepted availability only for a promised staged carrier");
        }
        for effect in effects {
            match effect {
                ModelEffect::NeedCarrier { target, holders } => {
                    self.requested_recoveries.insert(*target, holders.clone());
                }
                ModelEffect::Delivered(delivered) => {
                    self.certified_delivered.insert(*delivered);
                    self.delivered.insert(*delivered);
                    self.requested_recoveries.remove(delivered);
                    self.projection
                        .mark_delivered(*delivered)
                        .expect("model delivery must name a staged carrier");
                }
                ModelEffect::DeliveryPromised(reference) => {
                    self.pending_promised_references.insert(*reference);
                }
                ModelEffect::PrefixAdvanced { .. } | ModelEffect::CarrierRoundAdvanced(_) => {}
            }
        }
        self.activate_promised_references();
        self.drive_promised_projection();
        self.drive_certified_projection()?;
        if self.vote_qc_fast_path {
            self.drive_vote_quorum_committer()?;
        }
        Ok(())
    }

    fn decode_batch(&self, records: &[Vec<u8>]) -> Result<ShadowInputV1, ShadowErrorV1> {
        if records.is_empty() {
            return Err(ShadowErrorV1::InvalidBatch("empty transition batch"));
        }
        let decoded = records
            .iter()
            .map(|record| {
                decode_raw_record(record, self.context, self.own_authority)
                    .map_err(ShadowErrorV1::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        match decoded[0].kind {
            RECORD_AUTHENTICATED_INGRESS => {
                ensure_trace_tail(&decoded[1..])?;
                let mut payload = RawDecoder::new(&decoded[0].payload);
                let provenance = decode_provenance(&mut payload)?;
                let carrier_wire = payload.read_sized_bytes()?.to_vec();
                let sidecar_wire = payload.read_sized_bytes()?.to_vec();
                payload.finish()?;
                let candidate = decode_candidate(&carrier_wire, &self.committee, None)?;
                validate_provenance(provenance, candidate.header().author(), &self.committee)?;
                let authentication = decode_authentication(&sidecar_wire, &self.committee)?;
                let authenticated = self.context.verify_authentication_with_committee(
                    candidate,
                    authentication,
                    self.own_authority,
                    &self.committee,
                    self.authorizer.inbound_mac_keys(),
                )?;
                Ok(ShadowInputV1::AuthenticatedIngress {
                    authenticated,
                    provenance,
                })
            }
            RECORD_CANDIDATE_RETENTION | RECORD_CANDIDATE_RECOVERY => {
                ensure_trace_tail(&decoded[1..])?;
                let candidate = decode_candidate(&decoded[0].payload, &self.committee, None)?;
                if decoded[0].kind == RECORD_CANDIDATE_RETENTION {
                    Ok(ShadowInputV1::CandidateRetention(candidate))
                } else {
                    Ok(ShadowInputV1::CandidateRecovery(candidate))
                }
            }
            RECORD_DATA_AVAILABLE => {
                ensure_trace_tail(&decoded[1..])?;
                let mut payload = RawDecoder::new(&decoded[0].payload);
                let reference = payload.read_reference()?;
                payload.finish()?;
                Ok(ShadowInputV1::DataAvailable(reference))
            }
            RECORD_LOCAL_OUTBOUND_CONTENT => {
                if decoded.len() != 4 {
                    return Err(ShadowErrorV1::InvalidBatch(
                        "local transition must contain input, trace, sidecar, and exposure",
                    ));
                }
                let trace_end = decoded.len() - 2;
                ensure_trace_tail(&decoded[1..trace_end])?;
                if decoded[trace_end].kind != RECORD_LOCAL_OUTBOUND_SIDECAR
                    || decoded[trace_end + 1].kind != RECORD_LOCAL_OUTBOUND_EXPOSE
                {
                    return Err(ShadowErrorV1::InvalidBatch(
                        "local sidecar and exposure must follow the trace",
                    ));
                }
                let candidate = decode_candidate(&decoded[0].payload, &self.committee, None)?;
                let mut sidecar = RawDecoder::new(&decoded[trace_end].payload);
                let sidecar_reference = sidecar.read_reference()?;
                let authentication_wire = sidecar.read_sized_bytes()?.to_vec();
                sidecar.finish()?;
                let mut expose = RawDecoder::new(&decoded[trace_end + 1].payload);
                let expose_reference = expose.read_reference()?;
                expose.finish()?;
                if sidecar_reference != candidate.reference()
                    || expose_reference != candidate.reference()
                {
                    return Err(ShadowErrorV1::InvalidBatch(
                        "local sidecar or exposure reference mismatch",
                    ));
                }
                let authentication = decode_authentication(&authentication_wire, &self.committee)?;
                let authenticated = self.context.verify_local_authentication_with_committee(
                    candidate,
                    authentication,
                    &self.committee,
                    self.authorizer.authorizer(self.own_authority),
                )?;
                Ok(ShadowInputV1::LocalOutbound(authenticated))
            }
            _ => Err(ShadowErrorV1::InvalidBatch(
                "first record is not a model input",
            )),
        }
    }
}

fn validate_configuration(
    committee: &RbcDagCommitteeContextV1,
    own_authority: AuthorityIndex,
    context: RbcDagContextV1,
    authorizer: &ShadowAuthorizerV1,
) -> Result<(), ShadowErrorV1> {
    if context.committee_id() != committee.committee_id() {
        return Err(ShadowErrorV1::ContextMismatch);
    }
    if !committee.committee().known_authority(own_authority) {
        return Err(ShadowErrorV1::UnknownAuthority(own_authority));
    }
    if context.authentication_scheme() != authorizer.scheme() {
        return Err(ShadowErrorV1::AuthorizerSchemeMismatch);
    }
    match authorizer {
        ShadowAuthorizerV1::Ed25519(signer) => {
            if committee.committee().get_public_key(own_authority) != Some(&signer.public_key()) {
                return Err(ShadowErrorV1::AuthorizerKeyMismatch);
            }
        }
        ShadowAuthorizerV1::MlDsa44(signer) => {
            if committee
                .committee()
                .get_ml_dsa_44_public_key(own_authority)
                != Some(&signer.public_key())
            {
                return Err(ShadowErrorV1::AuthorizerKeyMismatch);
            }
        }
        ShadowAuthorizerV1::MlDsa65(signer) => {
            if committee
                .committee()
                .get_ml_dsa_65_public_key(own_authority)
                != Some(&signer.public_key())
            {
                return Err(ShadowErrorV1::AuthorizerKeyMismatch);
            }
        }
        ShadowAuthorizerV1::MacVector(keys) => {
            if keys.len() != committee.committee().len() {
                return Err(ShadowErrorV1::InvalidAuthorizerKeyringLength {
                    expected: committee.committee().len(),
                    actual: keys.len(),
                });
            }
        }
    }
    Ok(())
}

fn validate_provenance(
    provenance: IngressProvenanceV1,
    candidate_author: AuthorityIndex,
    committee: &RbcDagCommitteeContextV1,
) -> Result<(), ShadowErrorV1> {
    if let IngressProvenanceV1::Relayed { peer } = provenance {
        if !committee.committee().known_authority(peer) {
            return Err(ShadowErrorV1::UnknownAuthority(peer));
        }
        if peer == candidate_author {
            return Err(ShadowErrorV1::NonCanonicalProvenance);
        }
    }
    Ok(())
}

pub(crate) fn infer_ingress_provenance(
    trusted_peer: AuthorityIndex,
    candidate_author: AuthorityIndex,
) -> IngressProvenanceV1 {
    if trusted_peer == candidate_author {
        IngressProvenanceV1::DirectFromAuthor
    } else {
        IngressProvenanceV1::Relayed { peer: trusted_peer }
    }
}

fn decode_candidate(
    wire: &[u8],
    committee: &RbcDagCommitteeContextV1,
    expected_reference: Option<BlockReference>,
) -> Result<CandidateCarrierV1, ShadowErrorV1> {
    let candidate =
        CandidateCarrierV1::decode_wire_with_committee(wire, committee, expected_reference)?;
    if candidate.canonical_wire_bytes()?.as_slice() != wire {
        return Err(ShadowErrorV1::NonCanonicalCarrier);
    }
    Ok(candidate)
}

fn decode_authentication(
    wire: &[u8],
    committee: &RbcDagCommitteeContextV1,
) -> Result<CarrierAuthenticationV1, ShadowErrorV1> {
    let authentication = CarrierAuthenticationV1::decode_wire_with_committee(wire, committee)?;
    if authentication.canonical_wire_bytes().as_slice() != wire {
        return Err(ShadowErrorV1::NonCanonicalAuthentication);
    }
    Ok(authentication)
}

fn journal_transition_events(
    journal: &WriteAheadJournalV1,
    input: &ShadowInputV1,
    trace: &[ModelTraceEvent],
) -> Result<Vec<JournalEventV1>, ShadowErrorV1> {
    let mut events = Vec::new();
    let context = journal.snapshot().context();
    match input {
        ShadowInputV1::AuthenticatedIngress {
            authenticated,
            provenance,
        } => events.push(JournalEventV1::AuthenticatedIngress {
            context,
            sequence: journal.snapshot().next_ingress_sequence(),
            authenticated: authenticated.clone(),
            provenance: *provenance,
        }),
        ShadowInputV1::CandidateRetention(candidate)
        | ShadowInputV1::CandidateRecovery(candidate) => {
            events.push(JournalEventV1::RetainCandidateContent {
                context,
                candidate: candidate.clone(),
            });
        }
        ShadowInputV1::LocalOutbound(authenticated) => {
            events.push(JournalEventV1::PersistOutboundContent {
                context,
                candidate: authenticated.candidate().clone(),
            });
        }
        ShadowInputV1::DataAvailable(_) => {}
    }

    let local_reference = input.is_local().then(|| {
        input
            .candidate()
            .expect("local input has candidate")
            .reference()
    });
    for entry in trace {
        let event = match entry {
            ModelTraceEvent::AdmissionLocked(target) if Some(*target) == local_reference => {
                // `FixOwnCarrier` is the journal's authority lock for a local
                // value. `LockAdmission` intentionally accepts only network
                // ingress; the exact model trace remains present in the WAL.
                None
            }
            ModelTraceEvent::AdmissionLocked(target) => Some(JournalEventV1::LockAdmission {
                context,
                target: *target,
            }),
            ModelTraceEvent::LocalPhaseLocked(statement) => Some(match statement {
                RbcPhaseStatementV1::Echo { target } => JournalEventV1::LockEcho {
                    context,
                    target: *target,
                },
                RbcPhaseStatementV1::Ready { target } => JournalEventV1::LockReady {
                    context,
                    target: *target,
                },
                RbcPhaseStatementV1::Vote { target } => JournalEventV1::LockVote {
                    context,
                    target: *target,
                },
                RbcPhaseStatementV1::Ack { target } => JournalEventV1::LockAck {
                    context,
                    target: *target,
                },
            }),
            ModelTraceEvent::PhaseBatchEntryApplied {
                outer,
                index,
                sender,
                statement,
            } => Some(JournalEventV1::ApplyPhaseStatement {
                context,
                outer: *outer,
                index: *index,
                sender: *sender,
                statement: *statement,
            }),
            ModelTraceEvent::PhaseBatchCursorAdvanced {
                outer,
                index,
                next_index,
            } => {
                if index.checked_add(1) != Some(*next_index) {
                    return Err(ShadowErrorV1::InvalidBatch(
                        "non-sequential phase cursor trace",
                    ));
                }
                Some(JournalEventV1::AdvancePhaseBatchCursor {
                    context,
                    outer: *outer,
                    index: *index,
                })
            }
            ModelTraceEvent::LocalCarrierFixed(reference) => Some(JournalEventV1::FixOwnCarrier {
                context,
                reference: *reference,
            }),
            ModelTraceEvent::ConsensusSlotLocked {
                consensus_round,
                enclosing_carrier,
            } => Some(JournalEventV1::LockConsensusSlot {
                context,
                consensus_round: *consensus_round,
                enclosing_carrier: *enclosing_carrier,
            }),
            ModelTraceEvent::LeaderChoiceLocked {
                consensus_round,
                choice,
            } => Some(JournalEventV1::LockLeaderChoice {
                context,
                consensus_round: *consensus_round,
                choice: *choice,
            }),
            ModelTraceEvent::DeliveryPromiseLocked { target, basis } => match basis {
                DeliveryPromiseBasisV1::LocalFixed
                | DeliveryPromiseBasisV1::HonestAuthor
                | DeliveryPromiseBasisV1::OptimisticEcho => {
                    Some(JournalEventV1::LockOptimisticDelivery {
                        context,
                        target: *target,
                    })
                }
                DeliveryPromiseBasisV1::Delivered => None,
            },
            ModelTraceEvent::DeliveryLocked(target) => Some(JournalEventV1::LockDelivery {
                context,
                target: *target,
            }),
            ModelTraceEvent::Effect(_) => None,
        };
        if let Some(event) = event {
            events.push(event);
        }
    }

    if let ShadowInputV1::LocalOutbound(authenticated) = input {
        events.push(JournalEventV1::PersistOutboundSidecar {
            context,
            authenticated: authenticated.clone(),
        });
        events.push(JournalEventV1::ExposeOutbound {
            context,
            reference: authenticated.reference(),
        });
    }
    Ok(events)
}

fn encode_batch(
    context: RbcDagContextV1,
    own_authority: AuthorityIndex,
    input: &ShadowInputV1,
    trace: &[ModelTraceEvent],
) -> Result<Vec<Vec<u8>>, ShadowErrorV1> {
    let mut records = Vec::with_capacity(4);
    match input {
        ShadowInputV1::AuthenticatedIngress {
            authenticated,
            provenance,
        } => {
            let mut payload = Vec::new();
            encode_provenance(&mut payload, *provenance);
            push_sized_bytes(
                &mut payload,
                &authenticated.candidate().canonical_wire_bytes()?,
            )?;
            push_sized_bytes(
                &mut payload,
                &authenticated.authentication().canonical_wire_bytes(),
            )?;
            records.push(encode_raw_record(
                context,
                own_authority,
                RECORD_AUTHENTICATED_INGRESS,
                &payload,
            )?);
        }
        ShadowInputV1::CandidateRetention(candidate) => {
            records.push(encode_raw_record(
                context,
                own_authority,
                RECORD_CANDIDATE_RETENTION,
                &candidate.canonical_wire_bytes()?,
            )?);
        }
        ShadowInputV1::CandidateRecovery(candidate) => {
            records.push(encode_raw_record(
                context,
                own_authority,
                RECORD_CANDIDATE_RECOVERY,
                &candidate.canonical_wire_bytes()?,
            )?);
        }
        ShadowInputV1::LocalOutbound(authenticated) => {
            records.push(encode_raw_record(
                context,
                own_authority,
                RECORD_LOCAL_OUTBOUND_CONTENT,
                &authenticated.candidate().canonical_wire_bytes()?,
            )?);
        }
        ShadowInputV1::DataAvailable(reference) => {
            let mut payload = Vec::new();
            push_reference(&mut payload, *reference);
            records.push(encode_raw_record(
                context,
                own_authority,
                RECORD_DATA_AVAILABLE,
                &payload,
            )?);
        }
    }
    records.push(encode_raw_record(
        context,
        own_authority,
        RECORD_MODEL_TRACE,
        &encode_trace_batch(trace)?,
    )?);
    if let ShadowInputV1::LocalOutbound(authenticated) = input {
        let mut sidecar = Vec::new();
        push_reference(&mut sidecar, authenticated.reference());
        push_sized_bytes(
            &mut sidecar,
            &authenticated.authentication().canonical_wire_bytes(),
        )?;
        records.push(encode_raw_record(
            context,
            own_authority,
            RECORD_LOCAL_OUTBOUND_SIDECAR,
            &sidecar,
        )?);
        let mut expose = Vec::new();
        push_reference(&mut expose, authenticated.reference());
        records.push(encode_raw_record(
            context,
            own_authority,
            RECORD_LOCAL_OUTBOUND_EXPOSE,
            &expose,
        )?);
    }
    Ok(records)
}

fn encode_raw_record(
    context: RbcDagContextV1,
    own_authority: AuthorityIndex,
    kind: u8,
    payload: &[u8],
) -> Result<Vec<u8>, ShadowCodecErrorV1> {
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| ShadowCodecErrorV1::LengthOverflow)?;
    let total_len = RAW_RECORD_HEADER_SIZE
        .checked_add(payload.len())
        .ok_or(ShadowCodecErrorV1::LengthOverflow)?;
    if total_len > MAX_SHADOW_WAL_RECORD_SIZE_V1 {
        return Err(ShadowCodecErrorV1::InvalidRecordLength(total_len));
    }
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(RAW_RECORD_MAGIC);
    bytes.push(RAW_RECORD_VERSION_V1);
    bytes.push(kind);
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(context.protocol_instance().as_bytes());
    bytes.extend_from_slice(context.committee_id().as_bytes());
    bytes.extend_from_slice(&own_authority.to_be_bytes());
    bytes.push(authentication_scheme_code(context.authentication_scheme()));
    bytes.push(0);
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    debug_assert_eq!(bytes.len(), RAW_RECORD_HEADER_SIZE);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn decode_raw_record(
    bytes: &[u8],
    context: RbcDagContextV1,
    own_authority: AuthorityIndex,
) -> Result<DecodedRawRecord, ShadowCodecErrorV1> {
    if bytes.len() > MAX_SHADOW_WAL_RECORD_SIZE_V1 {
        return Err(ShadowCodecErrorV1::InvalidRecordLength(bytes.len()));
    }
    let mut decoder = RawDecoder::new(bytes);
    if decoder.take(4)? != RAW_RECORD_MAGIC {
        return Err(ShadowCodecErrorV1::InvalidMagic);
    }
    let version = decoder.read_u8()?;
    if version != RAW_RECORD_VERSION_V1 {
        return Err(ShadowCodecErrorV1::UnsupportedVersion(version));
    }
    let kind = decoder.read_u8()?;
    let flags = decoder.read_u16()?;
    if flags != 0 {
        return Err(ShadowCodecErrorV1::InvalidFlags(flags));
    }
    if decoder.take(32)? != context.protocol_instance().as_bytes()
        || decoder.take(32)? != context.committee_id().as_bytes()
    {
        return Err(ShadowCodecErrorV1::ContextMismatch);
    }
    let actual_authority = decoder.read_u16()?;
    if actual_authority != own_authority {
        return Err(ShadowCodecErrorV1::AuthorityMismatch {
            expected: own_authority,
            actual: actual_authority,
        });
    }
    if decoder.read_u8()? != authentication_scheme_code(context.authentication_scheme()) {
        return Err(ShadowCodecErrorV1::AuthenticationSchemeMismatch);
    }
    if decoder.read_u8()? != 0 {
        return Err(ShadowCodecErrorV1::InvalidFlags(1));
    }
    let payload_len = decoder.read_u32()? as usize;
    if payload_len != decoder.remaining() {
        return Err(ShadowCodecErrorV1::InvalidRecordLength(bytes.len()));
    }
    let payload = decoder.take(payload_len)?.to_vec();
    decoder.finish()?;
    match kind {
        RECORD_AUTHENTICATED_INGRESS
        | RECORD_CANDIDATE_RETENTION
        | RECORD_CANDIDATE_RECOVERY
        | RECORD_LOCAL_OUTBOUND_CONTENT
        | RECORD_DATA_AVAILABLE
        | RECORD_MODEL_TRACE
        | RECORD_LOCAL_OUTBOUND_SIDECAR
        | RECORD_LOCAL_OUTBOUND_EXPOSE => {}
        other => return Err(ShadowCodecErrorV1::UnknownRecordKind(other)),
    }
    Ok(DecodedRawRecord { kind, payload })
}

fn decode_recorded_trace(
    records: &[Vec<u8>],
    context: RbcDagContextV1,
    own_authority: AuthorityIndex,
    committee_size: usize,
) -> Result<Vec<ModelTraceEvent>, ShadowErrorV1> {
    let decoded = records
        .iter()
        .map(|record| decode_raw_record(record, context, own_authority))
        .collect::<Result<Vec<_>, _>>()?;
    let range = match decoded.first().map(|record| record.kind) {
        Some(RECORD_LOCAL_OUTBOUND_CONTENT) => 1..decoded.len().saturating_sub(2),
        Some(
            RECORD_AUTHENTICATED_INGRESS
            | RECORD_CANDIDATE_RETENTION
            | RECORD_CANDIDATE_RECOVERY
            | RECORD_DATA_AVAILABLE,
        ) => 1..decoded.len(),
        _ => return Err(ShadowErrorV1::InvalidBatch("missing model input")),
    };
    let trace_records = &decoded[range];
    ensure_trace_tail(trace_records)?;
    decode_trace_batch(&trace_records[0].payload, committee_size).map_err(ShadowErrorV1::from)
}

fn ensure_trace_tail(records: &[DecodedRawRecord]) -> Result<(), ShadowErrorV1> {
    if matches!(records, [record] if record.kind == RECORD_MODEL_TRACE) {
        Ok(())
    } else {
        Err(ShadowErrorV1::InvalidBatch(
            "each model input must have exactly one ordered trace record",
        ))
    }
}

fn encode_trace_batch(trace: &[ModelTraceEvent]) -> Result<Vec<u8>, ShadowCodecErrorV1> {
    let count = u32::try_from(trace.len()).map_err(|_| ShadowCodecErrorV1::LengthOverflow)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&count.to_be_bytes());
    for entry in trace {
        push_sized_bytes(&mut bytes, &encode_trace(entry)?)?;
    }
    Ok(bytes)
}

fn decode_trace_batch(
    bytes: &[u8],
    committee_size: usize,
) -> Result<Vec<ModelTraceEvent>, ShadowCodecErrorV1> {
    let mut decoder = RawDecoder::new(bytes);
    let count = decoder.read_u32()? as usize;
    if count > decoder.remaining() / 5 {
        return Err(ShadowCodecErrorV1::InvalidRecordLength(bytes.len()));
    }
    let mut trace = Vec::with_capacity(count);
    for _ in 0..count {
        trace.push(decode_trace(decoder.read_sized_bytes()?, committee_size)?);
    }
    decoder.finish()?;
    Ok(trace)
}

fn encode_trace(trace: &ModelTraceEvent) -> Result<Vec<u8>, ShadowCodecErrorV1> {
    let mut bytes = Vec::new();
    match trace {
        ModelTraceEvent::AdmissionLocked(reference) => {
            bytes.push(TRACE_ADMISSION_LOCKED);
            push_reference(&mut bytes, *reference);
        }
        ModelTraceEvent::LocalPhaseLocked(statement) => {
            bytes.push(TRACE_LOCAL_PHASE_LOCKED);
            push_phase(&mut bytes, *statement);
        }
        ModelTraceEvent::PhaseBatchEntryApplied {
            outer,
            index,
            sender,
            statement,
        } => {
            bytes.push(TRACE_PHASE_ENTRY_APPLIED);
            push_reference(&mut bytes, *outer);
            push_usize_as_u32(&mut bytes, *index)?;
            bytes.extend_from_slice(&sender.to_be_bytes());
            push_phase(&mut bytes, *statement);
        }
        ModelTraceEvent::PhaseBatchCursorAdvanced {
            outer,
            index,
            next_index,
        } => {
            bytes.push(TRACE_PHASE_CURSOR_ADVANCED);
            push_reference(&mut bytes, *outer);
            push_usize_as_u32(&mut bytes, *index)?;
            push_usize_as_u32(&mut bytes, *next_index)?;
        }
        ModelTraceEvent::LocalCarrierFixed(reference) => {
            bytes.push(TRACE_LOCAL_CARRIER_FIXED);
            push_reference(&mut bytes, *reference);
        }
        ModelTraceEvent::ConsensusSlotLocked {
            consensus_round,
            enclosing_carrier,
        } => {
            bytes.push(TRACE_CONSENSUS_SLOT_LOCKED);
            bytes.extend_from_slice(&consensus_round.to_be_bytes());
            push_reference(&mut bytes, *enclosing_carrier);
        }
        ModelTraceEvent::LeaderChoiceLocked {
            consensus_round,
            choice,
        } => {
            bytes.push(TRACE_LEADER_CHOICE_LOCKED);
            bytes.extend_from_slice(&consensus_round.to_be_bytes());
            push_leader_choice(&mut bytes, *choice);
        }
        ModelTraceEvent::DeliveryPromiseLocked { target, basis } => {
            bytes.push(TRACE_DELIVERY_PROMISE_LOCKED);
            push_reference(&mut bytes, *target);
            bytes.push(match basis {
                DeliveryPromiseBasisV1::LocalFixed => 0,
                DeliveryPromiseBasisV1::HonestAuthor => 1,
                DeliveryPromiseBasisV1::OptimisticEcho => 2,
                DeliveryPromiseBasisV1::Delivered => 3,
            });
        }
        ModelTraceEvent::DeliveryLocked(reference) => {
            bytes.push(TRACE_DELIVERY_LOCKED);
            push_reference(&mut bytes, *reference);
        }
        ModelTraceEvent::Effect(effect) => {
            bytes.push(TRACE_EFFECT);
            push_effect(&mut bytes, effect)?;
        }
    }
    Ok(bytes)
}

fn decode_trace(
    bytes: &[u8],
    committee_size: usize,
) -> Result<ModelTraceEvent, ShadowCodecErrorV1> {
    let mut decoder = RawDecoder::new(bytes);
    let trace = match decoder.read_u8()? {
        TRACE_ADMISSION_LOCKED => ModelTraceEvent::AdmissionLocked(decoder.read_reference()?),
        TRACE_LOCAL_PHASE_LOCKED => ModelTraceEvent::LocalPhaseLocked(decoder.read_phase()?),
        TRACE_PHASE_ENTRY_APPLIED => ModelTraceEvent::PhaseBatchEntryApplied {
            outer: decoder.read_reference()?,
            index: decoder.read_u32()? as usize,
            sender: decoder.read_u16()?,
            statement: decoder.read_phase()?,
        },
        TRACE_PHASE_CURSOR_ADVANCED => ModelTraceEvent::PhaseBatchCursorAdvanced {
            outer: decoder.read_reference()?,
            index: decoder.read_u32()? as usize,
            next_index: decoder.read_u32()? as usize,
        },
        TRACE_LOCAL_CARRIER_FIXED => ModelTraceEvent::LocalCarrierFixed(decoder.read_reference()?),
        TRACE_CONSENSUS_SLOT_LOCKED => ModelTraceEvent::ConsensusSlotLocked {
            consensus_round: decoder.read_u32()?,
            enclosing_carrier: decoder.read_reference()?,
        },
        TRACE_LEADER_CHOICE_LOCKED => ModelTraceEvent::LeaderChoiceLocked {
            consensus_round: decoder.read_u32()?,
            choice: decoder.read_leader_choice()?,
        },
        TRACE_DELIVERY_PROMISE_LOCKED => ModelTraceEvent::DeliveryPromiseLocked {
            target: decoder.read_reference()?,
            basis: match decoder.read_u8()? {
                0 => DeliveryPromiseBasisV1::LocalFixed,
                1 => DeliveryPromiseBasisV1::HonestAuthor,
                2 => DeliveryPromiseBasisV1::OptimisticEcho,
                3 => DeliveryPromiseBasisV1::Delivered,
                other => return Err(ShadowCodecErrorV1::InvalidDeliveryPromiseBasis(other)),
            },
        },
        TRACE_DELIVERY_LOCKED => ModelTraceEvent::DeliveryLocked(decoder.read_reference()?),
        TRACE_EFFECT => ModelTraceEvent::Effect(decoder.read_effect(committee_size)?),
        other => return Err(ShadowCodecErrorV1::InvalidTrace(other)),
    };
    decoder.finish()?;
    Ok(trace)
}

fn push_effect(bytes: &mut Vec<u8>, effect: &ModelEffect) -> Result<(), ShadowCodecErrorV1> {
    match effect {
        ModelEffect::NeedCarrier { target, holders } => {
            bytes.push(EFFECT_NEED_CARRIER);
            push_reference(bytes, *target);
            let count =
                u16::try_from(holders.len()).map_err(|_| ShadowCodecErrorV1::LengthOverflow)?;
            bytes.extend_from_slice(&count.to_be_bytes());
            for holder in holders {
                bytes.extend_from_slice(&holder.to_be_bytes());
            }
        }
        ModelEffect::Delivered(reference) => {
            bytes.push(EFFECT_DELIVERED);
            push_reference(bytes, *reference);
        }
        ModelEffect::DeliveryPromised(reference) => {
            bytes.push(EFFECT_DELIVERY_PROMISED);
            push_reference(bytes, *reference);
        }
        ModelEffect::PrefixAdvanced { authority, tip } => {
            bytes.push(EFFECT_PREFIX_ADVANCED);
            bytes.extend_from_slice(&authority.to_be_bytes());
            push_reference(bytes, *tip);
        }
        ModelEffect::CarrierRoundAdvanced(round) => {
            bytes.push(EFFECT_CARRIER_ROUND_ADVANCED);
            bytes.extend_from_slice(&round.to_be_bytes());
        }
    }
    Ok(())
}

fn push_phase(bytes: &mut Vec<u8>, statement: RbcPhaseStatementV1) {
    match statement {
        RbcPhaseStatementV1::Echo { target } => {
            bytes.push(PHASE_ECHO);
            push_reference(bytes, target);
        }
        RbcPhaseStatementV1::Ready { target } => {
            bytes.push(PHASE_READY);
            push_reference(bytes, target);
        }
        RbcPhaseStatementV1::Vote { target } => {
            bytes.push(PHASE_VOTE);
            push_reference(bytes, target);
        }
        RbcPhaseStatementV1::Ack { target } => {
            bytes.push(PHASE_ACK);
            push_reference(bytes, target);
        }
    }
}

fn push_consensus_reference(bytes: &mut Vec<u8>, reference: ConsensusVertexReference) {
    push_reference(bytes, reference.carrier());
    bytes.extend_from_slice(&reference.consensus_round().to_be_bytes());
}

fn push_leader_choice(bytes: &mut Vec<u8>, choice: LeaderChoiceV1) {
    match choice {
        LeaderChoiceV1::Vote { leader } => {
            bytes.push(0);
            push_consensus_reference(bytes, leader);
        }
        LeaderChoiceV1::NoVote {
            leader_author,
            leader_round,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&leader_author.to_be_bytes());
            bytes.extend_from_slice(&leader_round.to_be_bytes());
        }
    }
}

fn encode_provenance(bytes: &mut Vec<u8>, provenance: IngressProvenanceV1) {
    match provenance {
        IngressProvenanceV1::DirectFromAuthor => bytes.push(PROVENANCE_DIRECT),
        IngressProvenanceV1::Relayed { peer } => {
            bytes.push(PROVENANCE_RELAYED);
            bytes.extend_from_slice(&peer.to_be_bytes());
        }
    }
}

fn decode_provenance(
    decoder: &mut RawDecoder<'_>,
) -> Result<IngressProvenanceV1, ShadowCodecErrorV1> {
    match decoder.read_u8()? {
        PROVENANCE_DIRECT => Ok(IngressProvenanceV1::DirectFromAuthor),
        PROVENANCE_RELAYED => Ok(IngressProvenanceV1::Relayed {
            peer: decoder.read_u16()?,
        }),
        other => Err(ShadowCodecErrorV1::InvalidProvenance(other)),
    }
}

fn push_reference(bytes: &mut Vec<u8>, reference: BlockReference) {
    bytes.extend_from_slice(&reference.authority.to_be_bytes());
    bytes.extend_from_slice(&reference.round.to_be_bytes());
    bytes.extend_from_slice(reference.digest.as_ref());
}

fn push_sized_bytes(target: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ShadowCodecErrorV1> {
    let len = u32::try_from(bytes.len()).map_err(|_| ShadowCodecErrorV1::LengthOverflow)?;
    target.extend_from_slice(&len.to_be_bytes());
    target.extend_from_slice(bytes);
    Ok(())
}

fn push_usize_as_u32(target: &mut Vec<u8>, value: usize) -> Result<(), ShadowCodecErrorV1> {
    let value = u32::try_from(value).map_err(|_| ShadowCodecErrorV1::LengthOverflow)?;
    target.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn authentication_scheme_code(scheme: BlockAuthenticationScheme) -> u8 {
    match scheme {
        BlockAuthenticationScheme::Ed25519 => 0,
        BlockAuthenticationScheme::MlDsa44 => 1,
        BlockAuthenticationScheme::MlDsa65 => 2,
        BlockAuthenticationScheme::MacVector => 3,
    }
}

fn carrier_slot(reference: BlockReference) -> (AuthorityIndex, RoundNumber) {
    (reference.authority, reference.round)
}

fn round_is_stale(current_round: RoundNumber, candidate_round: RoundNumber) -> bool {
    candidate_round
        < current_round.saturating_sub(SHADOW_BENCHMARK_UNSOLICITED_RETENTION_WINDOW_ROUNDS_V1)
}

#[cfg(test)]
fn ambiguous_slots(
    identities: &BTreeSet<ShadowDeliveryIdentityV1>,
) -> BTreeSet<ShadowDeliverySlotV1> {
    let mut by_slot: BTreeMap<ShadowDeliverySlotV1, BTreeSet<TransactionsCommitment>> =
        BTreeMap::new();
    for identity in identities {
        by_slot
            .entry(ShadowDeliverySlotV1 {
                author: identity.author,
                round: identity.round,
            })
            .or_default()
            .insert(identity.transactions_commitment);
    }
    by_slot
        .into_iter()
        .filter_map(|(slot, commitments)| (commitments.len() > 1).then_some(slot))
        .collect()
}

fn projection_error_is_pending(error: &CertifiedProjectionError) -> bool {
    matches!(
        error,
        CertifiedProjectionError::CarrierNotDelivered(_)
            | CertifiedProjectionError::CarrierDataUnavailable(_)
            | CertifiedProjectionError::CarrierOutsideClosedPrefix(_)
            | CertifiedProjectionError::MissingStrongParent(_)
            | CertifiedProjectionError::FrontierNotClosed { .. }
    )
}

fn projection_decision_slot(decision: ProjectionDecisionV1) -> LeaderSlotV1 {
    match decision {
        ProjectionDecisionV1::DirectCommit { leader }
        | ProjectionDecisionV1::IndirectCommit { leader, .. } => LeaderSlotV1 {
            author: leader.author(),
            round: leader.consensus_round(),
        },
        ProjectionDecisionV1::DirectSkip { slot }
        | ProjectionDecisionV1::IndirectSkip { slot, .. }
        | ProjectionDecisionV1::Undecided { slot } => slot,
    }
}

fn reconcile_authoritative_frontier_suffix(
    replayed: Vec<CommittedFrontierDeltaV1>,
    cursor: Option<&RbcDagFrontierRecoveryCursorV1>,
    committee_size: usize,
) -> Result<Vec<CommittedFrontierDeltaV1>, ShadowErrorV1> {
    if let Some(cursor) = cursor {
        if cursor.receipt.committed_rounds.len() != committee_size {
            return Err(ShadowErrorV1::FrontierRecoveryWatermarkLength {
                expected: committee_size,
                actual: cursor.receipt.committed_rounds.len(),
            });
        }
    }

    let mut committed_rounds = vec![0; committee_size];
    let mut last_sequence: RoundNumber = 0;
    let mut cursor_found = cursor.is_none();
    let mut suffix = Vec::new();
    for delta in replayed {
        let expected_sequence =
            last_sequence
                .checked_add(1)
                .ok_or(ShadowErrorV1::FrontierOutputSequenceOverflow(
                    u64::from(last_sequence) + 1,
                ))?;
        if delta.output_sequence != expected_sequence {
            return Err(ShadowErrorV1::FrontierRecoverySequence {
                expected_sequence,
                actual_sequence: delta.output_sequence,
            });
        }
        last_sequence = delta.output_sequence;
        let consensus_round = delta.anchor.consensus_round();

        let application_references = delta
            .applications
            .iter()
            .map(RbcCanonicalHeader::reference)
            .collect::<Vec<_>>();
        for application in &application_references {
            let Some(watermark) = committed_rounds.get_mut(application.authority as usize) else {
                return Err(ShadowErrorV1::FrontierRecoveryApplicationAuthority {
                    application: *application,
                    committee_size,
                });
            };
            *watermark = (*watermark).max(application.round);
        }

        match cursor {
            Some(cursor) if delta.output_sequence < cursor.receipt.output_sequence => {}
            Some(cursor) if delta.output_sequence == cursor.receipt.output_sequence => {
                if delta.anchor.carrier() != cursor.receipt.carrier_anchor {
                    return Err(ShadowErrorV1::FrontierRecoveryAnchorConflict {
                        consensus_round,
                        durable: cursor.receipt.carrier_anchor,
                        actor: delta.anchor.carrier(),
                    });
                }
                if application_references != cursor.application_references {
                    return Err(ShadowErrorV1::FrontierRecoveryApplicationsConflict {
                        consensus_round,
                        durable: cursor.application_references.clone(),
                        actor: application_references,
                    });
                }
                if committed_rounds != cursor.receipt.committed_rounds {
                    return Err(ShadowErrorV1::FrontierRecoveryWatermarksConflict {
                        consensus_round,
                        durable: cursor.receipt.committed_rounds.clone(),
                        actor: committed_rounds.clone(),
                    });
                }
                cursor_found = true;
            }
            Some(_) => suffix.push(delta),
            None => suffix.push(delta),
        }
    }

    if let Some(cursor) = cursor {
        if !cursor_found {
            if cursor.receipt.output_sequence > last_sequence {
                return Err(ShadowErrorV1::FrontierRecoveryCursorAhead {
                    durable_sequence: cursor.receipt.output_sequence,
                    actor_sequence: last_sequence,
                });
            }
            return Err(ShadowErrorV1::FrontierRecoveryCursorMissing(
                cursor.receipt.output_sequence,
            ));
        }
    }
    if suffix.len() > MAX_AUTHORITATIVE_FRONTIER_RECOVERY_SUFFIX_V1 {
        return Err(ShadowErrorV1::FrontierRecoverySuffixLimit {
            limit: MAX_AUTHORITATIVE_FRONTIER_RECOVERY_SUFFIX_V1,
            actual: suffix.len(),
        });
    }
    Ok(suffix)
}

struct RawDecoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> RawDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ShadowCodecErrorV1> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ShadowCodecErrorV1::LengthOverflow)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(ShadowCodecErrorV1::UnexpectedEnd)?;
        self.position = end;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> Result<u8, ShadowCodecErrorV1> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ShadowCodecErrorV1> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("fixed u16 range"),
        ))
    }

    fn read_u32(&mut self) -> Result<u32, ShadowCodecErrorV1> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("fixed u32 range"),
        ))
    }

    fn read_reference(&mut self) -> Result<BlockReference, ShadowCodecErrorV1> {
        let authority = self.read_u16()?;
        let round = self.read_u32()?;
        let mut digest = [0; 32];
        digest.copy_from_slice(self.take(32)?);
        Ok(BlockReference {
            authority,
            round,
            digest: BlockDigest::from(digest),
        })
    }

    fn read_phase(&mut self) -> Result<RbcPhaseStatementV1, ShadowCodecErrorV1> {
        let phase = self.read_u8()?;
        let target = self.read_reference()?;
        match phase {
            PHASE_ECHO => Ok(RbcPhaseStatementV1::Echo { target }),
            PHASE_READY => Ok(RbcPhaseStatementV1::Ready { target }),
            PHASE_VOTE => Ok(RbcPhaseStatementV1::Vote { target }),
            PHASE_ACK => Ok(RbcPhaseStatementV1::Ack { target }),
            other => Err(ShadowCodecErrorV1::InvalidPhase(other)),
        }
    }

    fn read_consensus_reference(&mut self) -> Result<ConsensusVertexReference, ShadowCodecErrorV1> {
        let carrier = self.read_reference()?;
        let consensus_round = self.read_u32()?;
        Ok(ConsensusVertexReference::new(carrier, consensus_round))
    }

    fn read_leader_choice(&mut self) -> Result<LeaderChoiceV1, ShadowCodecErrorV1> {
        match self.read_u8()? {
            0 => Ok(LeaderChoiceV1::Vote {
                leader: self.read_consensus_reference()?,
            }),
            1 => Ok(LeaderChoiceV1::NoVote {
                leader_author: self.read_u16()?,
                leader_round: self.read_u32()?,
            }),
            other => Err(ShadowCodecErrorV1::InvalidLeaderChoice(other)),
        }
    }

    fn read_effect(&mut self, committee_size: usize) -> Result<ModelEffect, ShadowCodecErrorV1> {
        match self.read_u8()? {
            EFFECT_NEED_CARRIER => {
                let target = self.read_reference()?;
                let count = self.read_u16()? as usize;
                if count > committee_size || count > MAX_COMMITTEE_SIZE as usize {
                    return Err(ShadowCodecErrorV1::NonCanonicalHolders);
                }
                let mut holders = Vec::with_capacity(count);
                let mut previous = None;
                for _ in 0..count {
                    let holder = self.read_u16()?;
                    if holder as usize >= committee_size
                        || previous.is_some_and(|previous| previous >= holder)
                    {
                        return Err(ShadowCodecErrorV1::NonCanonicalHolders);
                    }
                    previous = Some(holder);
                    holders.push(holder);
                }
                Ok(ModelEffect::NeedCarrier { target, holders })
            }
            EFFECT_DELIVERED => Ok(ModelEffect::Delivered(self.read_reference()?)),
            EFFECT_DELIVERY_PROMISED => Ok(ModelEffect::DeliveryPromised(self.read_reference()?)),
            EFFECT_PREFIX_ADVANCED => Ok(ModelEffect::PrefixAdvanced {
                authority: self.read_u16()?,
                tip: self.read_reference()?,
            }),
            EFFECT_CARRIER_ROUND_ADVANCED => {
                Ok(ModelEffect::CarrierRoundAdvanced(self.read_u32()?))
            }
            other => Err(ShadowCodecErrorV1::InvalidEffect(other)),
        }
    }

    fn read_sized_bytes(&mut self) -> Result<&'a [u8], ShadowCodecErrorV1> {
        let length = self.read_u32()? as usize;
        self.take(length)
    }

    fn finish(self) -> Result<(), ShadowCodecErrorV1> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ShadowCodecErrorV1::TrailingBytes(
                self.bytes.len() - self.position,
            ))
        }
    }
}

const _: () = assert!(RAW_RECORD_HEADER_SIZE == 80);

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::OpenOptions, io::Write, sync::Arc};

    use tempfile::TempDir;

    use crate::{
        committee::Committee,
        crypto::{
            MAC_TAG_SIZE, dummy_ml_dsa_44_signer, dummy_ml_dsa_65_signer, dummy_signer,
            mac_keyrings_for_test,
        },
        starfish_rbc_dag::{
            RbcDagProtocolInstanceId, carrier_genesis_reference, journal::RbcSlotKeyV1,
        },
    };

    const N: usize = 4;

    struct TestNetwork {
        committee: RbcDagCommitteeContextV1,
        context: RbcDagContextV1,
        keyrings: Vec<Vec<MacKey>>,
        directories: Vec<TempDir>,
        nodes: Vec<StarfishRbcDagShadowV1>,
    }

    impl TestNetwork {
        fn new() -> Self {
            let committee = Committee::new_test(vec![1; N]);
            let committee = RbcDagCommitteeContextV1::new(Arc::clone(&committee)).unwrap();
            let context = RbcDagContextV1::new_with_committee(
                RbcDagProtocolInstanceId::new([0xE3; 32]).unwrap(),
                &committee,
                BlockAuthenticationScheme::MacVector,
            );
            let keyrings = mac_keyrings_for_test(N);
            let directories = (0..N)
                .map(|_| tempfile::tempdir().unwrap())
                .collect::<Vec<_>>();
            let nodes = (0..N)
                .map(|authority| {
                    StarfishRbcDagShadowV1::open(
                        directories[authority].path().join("shadow.wal"),
                        committee.clone(),
                        authority as AuthorityIndex,
                        context,
                        ShadowAuthorizerV1::MacVector(keyrings[authority].clone()),
                    )
                    .unwrap()
                    .0
                })
                .collect();
            Self {
                committee,
                context,
                keyrings,
                directories,
                nodes,
            }
        }

        fn path(&self, authority: usize) -> std::path::PathBuf {
            self.directories[authority].path().join("shadow.wal")
        }

        fn run_four_phase_rounds_with_one_poisoned_recipient(&mut self) {
            // INIT/ECHO is exposed in round one, the accumulated ECHOs drive
            // VOTE+ACK in round two, ACK convergence drives READY in round
            // three, and the Q-READY certificate is observed in round four.
            // Keep these as distinct physical carrier rounds: collapsing the
            // final transition would fail to exercise the runtime backlog.
            for round in 1..=4 {
                let envelopes = self
                    .nodes
                    .iter_mut()
                    .enumerate()
                    .map(|(authority, node)| {
                        let commitment = TransactionsCommitment::from_bytes(
                            [(round * 16 + authority as u32) as u8; 32],
                        );
                        node.create_local_carrier(round, commitment, u64::from(round) * 1_000)
                            .unwrap()
                            .0
                    })
                    .collect::<Vec<_>>();

                for (sender, envelope) in envelopes.iter().enumerate() {
                    for receiver in 0..N {
                        if receiver == sender {
                            continue;
                        }
                        if round == 1 && sender == 0 && receiver == 2 {
                            let mut poisoned = envelope.authentication_sidecar().to_vec();
                            poisoned[3 + receiver * MAC_TAG_SIZE] ^= 1;
                            let outcome = self.nodes[receiver]
                                .receive_or_retain_from_peer(
                                    envelope.canonical_carrier_wire(),
                                    &poisoned,
                                    sender as AuthorityIndex,
                                )
                                .unwrap();
                            assert_eq!(
                                outcome.disposition(),
                                ShadowIngressDispositionV1::CandidateRetained
                            );
                            assert!(outcome.effects().is_empty());
                        } else {
                            self.nodes[receiver]
                                .receive_authenticated_from_peer(
                                    envelope.canonical_carrier_wire(),
                                    envelope.authentication_sidecar(),
                                    sender as AuthorityIndex,
                                )
                                .unwrap();
                        }
                    }
                }

                for node in &self.nodes {
                    assert_eq!(node.local_carrier_round(), round + 1);
                }
            }
        }
    }

    fn ordered_committer_vertex(
        author: AuthorityIndex,
        consensus_round: RoundNumber,
        variant: u8,
    ) -> ConsensusVertexReference {
        let marker = (consensus_round as u8)
            .wrapping_mul(17)
            .wrapping_add(author as u8)
            .wrapping_add(variant.wrapping_mul(71));
        ConsensusVertexReference::new(
            BlockReference {
                authority: author,
                round: 100 + consensus_round * 2 + RoundNumber::from(variant),
                digest: BlockDigest::from([marker; 32]),
            },
            consensus_round,
        )
    }

    fn quorum_authors_including(
        committee: &RbcDagCommitteeContextV1,
        required: AuthorityIndex,
    ) -> Vec<AuthorityIndex> {
        std::iter::once(required)
            .chain(
                committee
                    .committee()
                    .authorities()
                    .filter(|author| *author != required),
            )
            .take(3)
            .collect()
    }

    fn inject_ordered_committer_fixture(
        node: &mut StarfishRbcDagShadowV1,
        include_early_direct_anchor: bool,
    ) -> [ConsensusVertexReference; 3] {
        let committee = node.committee.clone();
        let leader_author = |round: RoundNumber| committee.committee().elect_leader(round);
        let no_vote = |round: RoundNumber| LeaderChoiceV1::NoVote {
            leader_author: leader_author(round - 1),
            leader_round: round - 1,
        };
        let older = ordered_committer_vertex(leader_author(1), 1, 0);
        node.projection
            .inject_projected_for_test(older, Vec::new(), no_vote(1));

        // Q voters make the round-one leader certifiable, but only one
        // round-three vertex initially carries that certificate. Direct
        // commit is therefore unavailable while indirect commit is possible.
        let round_two = (0..N as AuthorityIndex)
            .map(|author| ordered_committer_vertex(author, 2, 0))
            .collect::<Vec<_>>();
        for (author, reference) in round_two.iter().copied().enumerate() {
            let choice = if author < 3 {
                LeaderChoiceV1::Vote { leader: older }
            } else {
                no_vote(2)
            };
            node.projection
                .inject_projected_for_test(reference, vec![older], choice);
        }

        let round_three = (0..3 as AuthorityIndex)
            .map(|author| ordered_committer_vertex(author, 3, 0))
            .collect::<Vec<_>>();
        let round_three_parents = [
            round_two[..3].to_vec(),
            vec![round_two[0], round_two[1], round_two[3]],
            vec![round_two[1], round_two[2], round_two[3]],
        ];
        for (reference, parents) in round_three.iter().copied().zip(round_three_parents) {
            node.projection
                .inject_projected_for_test(reference, parents, no_vote(3));
        }

        // The first later leader is reachable from the single certificate.
        // It is initially only indirectly committed by the still-later
        // leader, which is the case the old direct-only anchor scan skipped.
        let first_anchor = ordered_committer_vertex(leader_author(4), 4, 0);
        let round_four_authors = quorum_authors_including(&committee, first_anchor.author());
        let mut round_four = Vec::new();
        for author in round_four_authors {
            let reference = if author == first_anchor.author() {
                first_anchor
            } else {
                ordered_committer_vertex(author, 4, 0)
            };
            node.projection
                .inject_projected_for_test(reference, round_three.clone(), no_vote(4));
            round_four.push(reference);
        }

        let round_five = (0..N as AuthorityIndex)
            .map(|author| ordered_committer_vertex(author, 5, 0))
            .collect::<Vec<_>>();
        for (author, reference) in round_five.iter().copied().enumerate() {
            let choice = if author < 3 {
                LeaderChoiceV1::Vote {
                    leader: first_anchor,
                }
            } else {
                no_vote(5)
            };
            node.projection
                .inject_projected_for_test(reference, round_four.clone(), choice);
        }

        let round_six = (0..3 as AuthorityIndex)
            .map(|author| ordered_committer_vertex(author, 6, 0))
            .collect::<Vec<_>>();
        let round_six_parents = [
            round_five[..3].to_vec(),
            vec![round_five[0], round_five[1], round_five[3]],
            vec![round_five[1], round_five[2], round_five[3]],
        ];
        for (reference, parents) in round_six.iter().copied().zip(round_six_parents) {
            node.projection
                .inject_projected_for_test(reference, parents, no_vote(6));
        }
        if include_early_direct_anchor {
            // One Byzantine author supplies a conflicting certifier while the
            // unused fourth author supplies another. Together with author 0,
            // direct evidence for the round-four leader reaches Q.
            for (author, variant) in [(1, 1), (3, 0)] {
                node.projection.inject_projected_for_test(
                    ordered_committer_vertex(author, 6, variant),
                    round_five[..3].to_vec(),
                    no_vote(6),
                );
            }
        }

        let later_anchor = ordered_committer_vertex(leader_author(7), 7, 0);
        let round_seven_authors = quorum_authors_including(&committee, later_anchor.author());
        let mut round_seven = Vec::new();
        for author in round_seven_authors {
            let reference = if author == later_anchor.author() {
                later_anchor
            } else {
                ordered_committer_vertex(author, 7, 0)
            };
            node.projection
                .inject_projected_for_test(reference, round_six.clone(), no_vote(7));
            round_seven.push(reference);
        }
        let round_eight = (0..3 as AuthorityIndex)
            .map(|author| ordered_committer_vertex(author, 8, 0))
            .collect::<Vec<_>>();
        for reference in &round_eight {
            node.projection.inject_projected_for_test(
                *reference,
                round_seven.clone(),
                LeaderChoiceV1::Vote {
                    leader: later_anchor,
                },
            );
        }
        for author in 0..3 as AuthorityIndex {
            node.projection.inject_projected_for_test(
                ordered_committer_vertex(author, 9, 0),
                round_eight.clone(),
                no_vote(9),
            );
        }
        [older, first_anchor, later_anchor]
    }

    #[test]
    fn vote_quorum_commits_before_the_certifier_round_projects() {
        let mut network = TestNetwork::new();
        let node = &mut network.nodes[0];
        assert!(!node.vote_qc_fast_path, "strict finality is the default");
        node.vote_qc_fast_path = true;
        let leader_author = node.committee.committee().elect_leader(1);
        let leader = ordered_committer_vertex(leader_author, 1, 0);
        node.projection.inject_projected_for_test(
            leader,
            Vec::new(),
            LeaderChoiceV1::NoVote {
                leader_author,
                leader_round: 0,
            },
        );
        for author in 0..3 as AuthorityIndex {
            node.projection.inject_projected_for_test(
                ordered_committer_vertex(author, 2, 0),
                vec![leader],
                LeaderChoiceV1::Vote { leader },
            );
        }

        let slot = node.projection.leader_slot(1);
        assert_eq!(
            node.projection.direct_decision(slot).unwrap(),
            ProjectionDecisionV1::Undecided { slot },
            "the legacy two-level rule still waits for round-three certifiers"
        );
        node.drive_vote_quorum_committer().unwrap();
        assert_eq!(
            node.drain_projection_decisions(),
            vec![ProjectionDecisionV1::DirectCommit { leader }]
        );
        assert_eq!(node.drain_committed_frontiers().len(), 1);
        assert_eq!(node.next_undecided_consensus_round, 2);
    }

    #[test]
    fn ordered_committer_is_deterministic_across_direct_anchor_arrival_orders() {
        let mut network = TestNetwork::new();
        let expected = inject_ordered_committer_fixture(&mut network.nodes[0], false);
        assert_eq!(
            inject_ordered_committer_fixture(&mut network.nodes[1], true),
            expected
        );

        network.nodes[0].drive_ordered_committer(9).unwrap();
        network.nodes[1].drive_ordered_committer(9).unwrap();

        let delayed_decisions = network.nodes[0].drain_projection_decisions();
        let eager_decisions = network.nodes[1].drain_projection_decisions();
        assert!(
            delayed_decisions.contains(&ProjectionDecisionV1::IndirectCommit {
                leader: expected[1],
                anchor: expected[2],
            })
        );
        assert!(
            eager_decisions.contains(&ProjectionDecisionV1::DirectCommit {
                leader: expected[1],
            })
        );

        let delayed_output = network.nodes[0].drain_committed_frontiers();
        let eager_output = network.nodes[1].drain_committed_frontiers();
        assert_eq!(delayed_output, eager_output);
        assert_eq!(
            delayed_output
                .iter()
                .map(|delta| delta.anchor)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            delayed_output
                .iter()
                .map(|delta| delta.output_sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn vote_and_ack_trace_codec_preserves_append_only_golden_tags() {
        let target = BlockReference {
            authority: 0x0123,
            round: 0x0405_0607,
            digest: BlockDigest::from([0xA5; 32]),
        };
        let mut vote_golden = vec![
            TRACE_LOCAL_PHASE_LOCKED,
            PHASE_VOTE,
            0x01,
            0x23,
            0x04,
            0x05,
            0x06,
            0x07,
        ];
        vote_golden.extend_from_slice(&[0xA5; 32]);
        let mut ack_golden = vote_golden.clone();
        ack_golden[1] = PHASE_ACK;

        let vote = ModelTraceEvent::LocalPhaseLocked(RbcPhaseStatementV1::Vote { target });
        let ack = ModelTraceEvent::LocalPhaseLocked(RbcPhaseStatementV1::Ack { target });
        assert_eq!(encode_trace(&vote).unwrap(), vote_golden);
        assert_eq!(encode_trace(&ack).unwrap(), ack_golden);
        assert_eq!(decode_trace(&vote_golden, N).unwrap(), vote);
        assert_eq!(decode_trace(&ack_golden, N).unwrap(), ack);

        let batch_payload = encode_trace_batch(&[vote.clone(), ack.clone()]).unwrap();
        let committee = Committee::new_test(vec![1; N]);
        let committee = RbcDagCommitteeContextV1::new(committee).unwrap();
        let context = RbcDagContextV1::new_with_committee(
            RbcDagProtocolInstanceId::new([0xD4; 32]).unwrap(),
            &committee,
            BlockAuthenticationScheme::MacVector,
        );
        let raw = encode_raw_record(context, 0, RECORD_MODEL_TRACE, &batch_payload).unwrap();
        assert_eq!(&raw[..4], b"SRD5");
        let decoded = decode_raw_record(&raw, context, 0).unwrap();
        assert_eq!(decoded.kind, RECORD_MODEL_TRACE);
        assert_eq!(
            decode_trace_batch(&decoded.payload, N).unwrap(),
            vec![vote, ack]
        );
    }

    #[test]
    fn vote_and_ack_local_locks_and_pending_phases_survive_shadow_reopen() {
        let mut network = TestNetwork::new();
        let target = round_one_candidate(0, &network.committee, 0xD5);
        let target_reference = target.reference();
        let authentication = network
            .context
            .authenticate_with_committee(
                &target,
                &network.committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 0,
                    keys: &network.keyrings[0],
                },
            )
            .unwrap();
        network.nodes[3]
            .receive_authenticated_from_peer(
                &target.canonical_wire_bytes().unwrap(),
                &authentication.canonical_wire_bytes(),
                0,
            )
            .unwrap();

        let outer = round_two_phase_carrier(
            1,
            RbcPhaseStatementV1::Echo {
                target: target_reference,
            },
            &network.committee,
        );
        let authentication = network
            .context
            .authenticate_with_committee(
                &outer,
                &network.committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 1,
                    keys: &network.keyrings[1],
                },
            )
            .unwrap();
        network.nodes[3]
            .receive_authenticated_from_peer(
                &outer.canonical_wire_bytes().unwrap(),
                &authentication.canonical_wire_bytes(),
                1,
            )
            .unwrap();

        // Phase statements for a round-one target become eligible only once
        // the local physical clock opens round two. Fix the local round-one
        // carrier and admit one more round-one peer to expose the exact
        // pending VOTE/ACK batch before restart.
        network.nodes[3]
            .create_local_control_heartbeat(10, true)
            .unwrap();
        let peer = round_one_candidate(2, &network.committee, 0xD6);
        let authentication = network
            .context
            .authenticate_with_committee(
                &peer,
                &network.committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 2,
                    keys: &network.keyrings[2],
                },
            )
            .unwrap();
        network.nodes[3]
            .receive_authenticated_from_peer(
                &peer.canonical_wire_bytes().unwrap(),
                &authentication.canonical_wire_bytes(),
                2,
            )
            .unwrap();
        assert_eq!(network.nodes[3].local_carrier_round(), 2);

        let expected = [
            RbcPhaseStatementV1::Vote {
                target: target_reference,
            },
            RbcPhaseStatementV1::Ack {
                target: target_reference,
            },
        ];
        let slot = RbcSlotKeyV1::of(target_reference);
        for phase in expected {
            let pending = network.nodes[3].model.pending_phase_batch();
            assert!(
                pending.contains(&phase),
                "missing {phase:?} from pending phase batch {pending:?}"
            );
        }
        assert_eq!(
            network.nodes[3].journal.snapshot().vote_lock(slot),
            Some(target_reference)
        );
        assert_eq!(
            network.nodes[3].journal.snapshot().ack_lock(slot),
            Some(target_reference)
        );

        let node = network.nodes.swap_remove(3);
        let path = network.path(3);
        node.shutdown().unwrap();
        let (reopened, report) = StarfishRbcDagShadowV1::open(
            path,
            network.committee.clone(),
            3,
            network.context,
            ShadowAuthorizerV1::MacVector(network.keyrings[3].clone()),
        )
        .unwrap();
        assert!(report.replayed_batches() >= 2);
        for phase in expected {
            let pending = reopened.model.pending_phase_batch();
            assert!(
                pending.contains(&phase),
                "reopen lost {phase:?} from pending phase batch {pending:?}"
            );
        }
        assert_eq!(
            reopened.journal.snapshot().vote_lock(slot),
            Some(target_reference)
        );
        assert_eq!(
            reopened.journal.snapshot().ack_lock(slot),
            Some(target_reference)
        );
        reopened.shutdown().unwrap();
    }

    #[test]
    fn four_phase_mac_shadow_delivers_round_one_after_poisoned_tag_is_only_staged() {
        let mut network = TestNetwork::new();
        network.run_four_phase_rounds_with_one_poisoned_recipient();

        for node in &network.nodes {
            for author in 0..N {
                assert!(node.delivered(author as AuthorityIndex, 1).is_some());
            }
        }
        assert!(network.nodes[2].delivered(0, 1).is_some());
        assert_eq!(
            infer_ingress_provenance(1, 1),
            IngressProvenanceV1::DirectFromAuthor
        );
        assert_eq!(
            infer_ingress_provenance(2, 1),
            IngressProvenanceV1::Relayed { peer: 2 }
        );
    }

    #[test]
    fn autonomous_control_heartbeat_derives_the_open_round_and_is_durably_addressable() {
        let mut network = TestNetwork::new();
        let node = &mut network.nodes[0];
        assert_eq!(node.local_carrier_round(), 1);
        assert_eq!(node.current_round_admitted_author_count(), 0);
        assert_eq!(node.current_round_admitted_stake(), 0);
        assert_eq!(node.pending_phase_backlog_len(), 0);
        assert_eq!(node.buffered_authenticated_carrier_count(), 0);
        assert_eq!(node.local_outbound_envelope(1), None);

        let before = node.wal_counts();
        let (heartbeat, effects) = node.create_local_control_heartbeat(123, true).unwrap();
        assert_eq!(
            effects,
            vec![
                ModelEffect::DeliveryPromised(heartbeat.reference()),
                ModelEffect::PrefixAdvanced {
                    authority: 0,
                    tip: heartbeat.reference(),
                },
            ]
        );
        assert_eq!(
            node.model.delivery_promise_basis(&heartbeat.reference()),
            Some(DeliveryPromiseBasisV1::LocalFixed)
        );
        assert_eq!(node.wal_counts().0, before.0 + 1);
        let candidate = decode_candidate(
            heartbeat.canonical_carrier_wire(),
            &network.committee,
            Some(heartbeat.reference()),
        )
        .unwrap();
        assert_eq!(candidate.header().author(), 0);
        assert_eq!(candidate.header().carrier_round(), 1);
        assert_eq!(
            candidate.header().transactions_commitment(),
            TransactionsCommitment::default()
        );
        assert_eq!(candidate.header().creation_time_ns(), 123);
        assert!(candidate.header().data_acknowledgments().is_empty());
        assert!(candidate.header().phase_batch().is_empty());
        let vertex = candidate
            .header()
            .consensus_vertex()
            .expect("first autonomous heartbeat carries the genesis projection");
        assert_eq!(vertex.consensus_round(), 1);
        assert_eq!(
            node.journal.snapshot().consensus_slot(1),
            Some(heartbeat.reference())
        );
        assert_eq!(
            node.journal.snapshot().leader_choice(1),
            Some(vertex.leader_choice())
        );
        assert_eq!(node.local_outbound_envelope(1), Some(heartbeat.clone()));
        assert_eq!(node.local_outbound_envelope(2), None);
        assert_eq!(
            node.candidate_slot(heartbeat.canonical_carrier_wire())
                .unwrap(),
            (0, 1, heartbeat.reference())
        );
        assert_eq!(node.admitted_reference(0, 1), Some(heartbeat.reference()));
        assert_eq!(node.current_round_admitted_author_count(), 1);
        assert_eq!(node.current_round_admitted_stake(), 1);
        assert_eq!(
            node.pending_phase_backlog_len(),
            0,
            "the target author is excluded from ECHO/VOTE/ACK"
        );
        assert_eq!(node.buffered_authenticated_carrier_count(), 0);

        let durable_counts = node.wal_counts();
        assert!(matches!(
            node.create_local_control_heartbeat(124, true),
            Err(ShadowErrorV1::Model(ModelError::LocalCarrierAlreadyFixed(
                1
            )))
        ));
        assert_eq!(node.wal_counts(), durable_counts);

        let mut trailing = heartbeat.canonical_carrier_wire().to_vec();
        trailing.push(0);
        assert!(node.candidate_slot(&trailing).is_err());
    }

    #[test]
    fn optimistic_delivery_projects_before_q_ready_for_the_same_locked_vertex() {
        let mut network = TestNetwork::new();
        let target = round_one_consensus_candidate(
            1,
            &network.committee,
            0x91,
            TransactionsCommitment::from_bytes([0x91; 32]),
        );
        let target_reference = target.reference();
        let vertex_reference = ConsensusVertexReference::new(target_reference, 1);
        let authentication = network
            .context
            .authenticate_with_committee(
                &target,
                &network.committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 1,
                    keys: &network.keyrings[1],
                },
            )
            .unwrap();
        assert!(
            network.nodes[0]
                .receive_authenticated_from_peer(
                    &target.canonical_wire_bytes().unwrap(),
                    &authentication.canonical_wire_bytes(),
                    1,
                )
                .unwrap()
                .is_empty()
        );

        // The target author's ECHO is excluded from the optimistic
        // certificate. Receiving only that statement cannot promise.
        let sender = 1;
        {
            let outer = phase_carrier(
                sender,
                2,
                RbcPhaseStatementV1::Echo {
                    target: target_reference,
                },
                &network.committee,
                0xA0 + sender as u8,
            );
            let authentication = network
                .context
                .authenticate_with_committee(
                    &outer,
                    &network.committee,
                    CarrierAuthorizerV1::MacVector {
                        authority: sender,
                        keys: &network.keyrings[sender as usize],
                    },
                )
                .unwrap();
            network.nodes[0]
                .receive_authenticated_from_peer(
                    &outer.canonical_wire_bytes().unwrap(),
                    &authentication.canonical_wire_bytes(),
                    sender,
                )
                .unwrap();
        }
        assert_eq!(
            network.nodes[0]
                .model
                .delivery_promise_basis(&target_reference),
            None
        );
        assert!(
            !network.nodes[0]
                .promised_projection
                .is_projected(vertex_reference)
        );
        assert!(!network.nodes[0].projection.is_projected(vertex_reference));

        // The receiver's local ECHO plus one other non-author ECHO reaches
        // the N=4 optimistic threshold O=2. This is deliberately earlier
        // than the later Q-READY delivery certificate.
        let sender = 2;
        let outer = phase_carrier(
            sender,
            2,
            RbcPhaseStatementV1::Echo {
                target: target_reference,
            },
            &network.committee,
            0xA2,
        );
        let authentication = network
            .context
            .authenticate_with_committee(
                &outer,
                &network.committee,
                CarrierAuthorizerV1::MacVector {
                    authority: sender,
                    keys: &network.keyrings[sender as usize],
                },
            )
            .unwrap();
        let effects = network.nodes[0]
            .receive_authenticated_from_peer(
                &outer.canonical_wire_bytes().unwrap(),
                &authentication.canonical_wire_bytes(),
                sender,
            )
            .unwrap();
        assert!(effects.contains(&ModelEffect::DeliveryPromised(target_reference)));
        assert_eq!(
            network.nodes[0]
                .model
                .delivery_promise_basis(&target_reference),
            Some(DeliveryPromiseBasisV1::OptimisticEcho)
        );
        assert_eq!(network.nodes[0].promised_projection.promised_tip(1), None);
        assert!(
            !network.nodes[0]
                .promised_projection
                .is_projected(vertex_reference)
        );
        assert!(!network.nodes[0].carrier_data_available(target_reference));

        network.nodes[0]
            .mark_carrier_data_available(target_reference)
            .unwrap();
        assert!(
            network.nodes[0]
                .promised_projection
                .is_projected(vertex_reference)
        );
        assert_eq!(
            network.nodes[0].promised_projection.promised_tip(1),
            Some(target_reference)
        );
        assert!(network.nodes[0].projection.is_projected(vertex_reference));
        assert_eq!(
            network.nodes[0].projection.closed_tip(1),
            Some(target_reference)
        );
        assert_eq!(
            network.nodes[0].drain_projected_vertices(),
            vec![vertex_reference]
        );
        assert!(network.nodes[0].drain_projection_decisions().is_empty());
        assert!(network.nodes[0].drain_committed_frontiers().is_empty());

        // Reopening from typed inputs and trace effects reconstructs the
        // authoritative optimistic delivery and the identical planning view.
        let node = network.nodes.swap_remove(0);
        let path = network.path(0);
        node.shutdown().unwrap();
        let mut node = StarfishRbcDagShadowV1::open(
            path,
            network.committee.clone(),
            0,
            network.context,
            ShadowAuthorizerV1::MacVector(network.keyrings[0].clone()),
        )
        .unwrap()
        .0;
        assert!(node.promised_projection.is_projected(vertex_reference));
        assert!(node.projection.is_projected(vertex_reference));
        assert!(
            !node
                .model
                .lifecycle(&target_reference)
                .unwrap()
                .certified_delivered
        );
        assert!(node.drain_committed_frontiers().is_empty());

        // Two external READYs first trigger the local READY and then produce
        // the final Q-READY delivery. Certified projection catches up to the
        // exact immutable vertex and effective frontier planned earlier.
        for sender in [1, 2] {
            let outer = phase_carrier(
                sender,
                3,
                RbcPhaseStatementV1::Ready {
                    target: target_reference,
                },
                &network.committee,
                0xB0 + sender as u8,
            );
            let authentication = network
                .context
                .authenticate_with_committee(
                    &outer,
                    &network.committee,
                    CarrierAuthorizerV1::MacVector {
                        authority: sender,
                        keys: &network.keyrings[sender as usize],
                    },
                )
                .unwrap();
            node.receive_authenticated_from_peer(
                &outer.canonical_wire_bytes().unwrap(),
                &authentication.canonical_wire_bytes(),
                sender,
            )
            .unwrap();
        }
        assert!(node.model.lifecycle(&target_reference).unwrap().delivered);
        assert!(
            node.model
                .lifecycle(&target_reference)
                .unwrap()
                .certified_delivered
        );
        assert!(node.projection.is_projected(vertex_reference));
        assert_eq!(
            node.promised_projection.projected_vertex(vertex_reference),
            node.projection.projected_vertex(vertex_reference)
        );
        assert_eq!(
            node.promised_projection
                .effective_frontier(vertex_reference),
            node.projection.effective_frontier(vertex_reference)
        );
        for projected in node.drain_projected_vertices() {
            assert!(node.projection.is_projected(projected));
        }
        for delta in node.drain_committed_frontiers() {
            assert!(node.projection.is_projected(delta.anchor));
            assert!(delta.carriers.iter().all(|reference| {
                node.model.lifecycle(reference).is_some_and(|lifecycle| {
                    lifecycle.delivered && lifecycle.data_available && lifecycle.prefix_closed
                })
            }));
        }
    }

    #[test]
    fn promise_for_missing_content_waits_for_exact_recovery_without_panicking() {
        let mut network = TestNetwork::new();
        let target = round_one_consensus_candidate(
            1,
            &network.committee,
            0x92,
            TransactionsCommitment::default(),
        );
        let target_reference = target.reference();
        let vertex_reference = ConsensusVertexReference::new(target_reference, 1);
        let unrelated = round_one_candidate(2, &network.committee, 0x93);

        // This directly exercises the durable-adapter boundary represented by
        // an all-author-ECHO promise whose exact carrier bytes have not yet
        // arrived. The effect is retained, not applied to a placeholder.
        network.nodes[0]
            .record_committed_input(
                &ShadowInputV1::CandidateRetention(unrelated),
                &[ModelEffect::DeliveryPromised(target_reference)],
            )
            .unwrap();
        assert!(
            network.nodes[0]
                .pending_promised_references
                .contains(&target_reference)
        );
        assert!(
            !network.nodes[0]
                .promised_projection
                .is_projected(vertex_reference)
        );

        network.nodes[0]
            .record_committed_input(&ShadowInputV1::CandidateRecovery(target), &[])
            .unwrap();
        assert!(network.nodes[0].pending_promised_references.is_empty());
        assert!(
            network.nodes[0]
                .promised_projection
                .is_projected(vertex_reference)
        );
        assert!(network.nodes[0].projection.is_projected(vertex_reference));
    }

    #[test]
    fn missing_content_echo_evidence_reopens_then_promises_on_exact_recovery() {
        let mut network = TestNetwork::new();
        let target = round_one_consensus_candidate(
            3,
            &network.committee,
            0x94,
            TransactionsCommitment::default(),
        );
        let target_reference = target.reference();
        let vertex_reference = ConsensusVertexReference::new(target_reference, 1);

        // Three remote ECHOs reach Q while exact content is missing. The
        // receiver cannot count its own ECHO without first authenticating the
        // carrier, so the reducer requests recovery but emits no promise.
        for sender in [1, 2, 3] {
            let outer = phase_carrier(
                sender,
                2,
                RbcPhaseStatementV1::Echo {
                    target: target_reference,
                },
                &network.committee,
                0xC0 + sender as u8,
            );
            let authentication = network
                .context
                .authenticate_with_committee(
                    &outer,
                    &network.committee,
                    CarrierAuthorizerV1::MacVector {
                        authority: sender,
                        keys: &network.keyrings[sender as usize],
                    },
                )
                .unwrap();
            network.nodes[0]
                .receive_authenticated_from_peer(
                    &outer.canonical_wire_bytes().unwrap(),
                    &authentication.canonical_wire_bytes(),
                    sender,
                )
                .unwrap();
        }
        assert!(
            network.nodes[0]
                .retained_candidate_wire(target_reference)
                .is_none()
        );
        assert_eq!(
            network.nodes[0]
                .model
                .delivery_promise_basis(&target_reference),
            None
        );

        let node = network.nodes.swap_remove(0);
        let path = network.path(0);
        node.shutdown().unwrap();
        let (mut node, report) = StarfishRbcDagShadowV1::open(
            path,
            network.committee.clone(),
            0,
            network.context,
            ShadowAuthorizerV1::MacVector(network.keyrings[0].clone()),
        )
        .unwrap();
        assert!(report.recovery_effects().iter().any(|effect| {
            matches!(effect, ModelEffect::NeedCarrier { target, .. } if *target == target_reference)
        }));
        assert_eq!(node.model.delivery_promise_basis(&target_reference), None);

        let recovery_effects = node
            .recover_candidate_for(target_reference, &target.canonical_wire_bytes().unwrap())
            .unwrap();
        assert!(node.retained_candidate_wire(target_reference).is_some());
        assert!(
            recovery_effects.contains(&ModelEffect::DeliveryPromised(target_reference)),
            "the persisted ECHO certificate must activate once exact content arrives"
        );
        assert_eq!(
            node.model.delivery_promise_basis(&target_reference),
            Some(DeliveryPromiseBasisV1::OptimisticEcho)
        );
        assert!(node.promised_projection.is_projected(vertex_reference));

        // Later receiver-authenticated ingress may authorize the local ECHO,
        // but it must not duplicate the already durable promise.
        let authentication = network
            .context
            .authenticate_with_committee(
                &target,
                &network.committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 3,
                    keys: &network.keyrings[3],
                },
            )
            .unwrap();
        let effects = node
            .receive_authenticated_from_peer(
                &target.canonical_wire_bytes().unwrap(),
                &authentication.canonical_wire_bytes(),
                3,
            )
            .unwrap();
        assert!(!effects.contains(&ModelEffect::DeliveryPromised(target_reference)));
        assert!(node.promised_projection.is_projected(vertex_reference));
        assert!(node.projection.is_projected(vertex_reference));
        assert!(
            !node
                .model
                .lifecycle(&target_reference)
                .unwrap()
                .certified_delivered
        );
    }

    #[test]
    fn c1_builder_waits_for_the_witness_and_avoids_the_mixed_slow_tail() {
        let committee = Committee::new_test(vec![1; 7]);
        let committee = RbcDagCommitteeContextV1::new(Arc::clone(&committee)).unwrap();
        let context = RbcDagContextV1::new_with_committee(
            RbcDagProtocolInstanceId::new([0xC1; 32]).unwrap(),
            &committee,
            BlockAuthenticationScheme::MacVector,
        );
        let keyrings = mac_keyrings_for_test(7);
        let directory = tempfile::tempdir().unwrap();
        let mut node = StarfishRbcDagShadowV1::open(
            directory.path().join("c1-builder.wal"),
            committee.clone(),
            0,
            context,
            ShadowAuthorizerV1::MacVector(keyrings[0].clone()),
        )
        .unwrap()
        .0;
        let reference = |authority, consensus_round, marker| {
            ConsensusVertexReference::new(
                BlockReference {
                    authority,
                    round: consensus_round + 100,
                    digest: BlockDigest::from([marker; 32]),
                },
                consensus_round,
            )
        };

        let target = reference(committee.committee().elect_leader(2), 2, 0x20);
        node.promised_projection.inject_projected_for_test(
            target,
            Vec::new(),
            LeaderChoiceV1::NoVote {
                leader_author: committee.committee().elect_leader(1),
                leader_round: 1,
            },
        );
        for author in [0, 1, 2, 3, 6] {
            let projected = reference(author, 3, 0x30 + author as u8);
            let choice = if author == 6 {
                LeaderChoiceV1::NoVote {
                    leader_author: target.author(),
                    leader_round: target.consensus_round(),
                }
            } else {
                LeaderChoiceV1::Vote { leader: target }
            };
            node.promised_projection
                .inject_projected_for_test(projected, vec![target], choice);
        }
        node.next_local_consensus_round = 4;
        assert!(
            node.build_local_consensus_vertex(carrier_genesis_reference(0), false)
                .is_none(),
            "a mixed first quorum must not fix a non-certifying C1 vertex"
        );

        let final_voter = reference(4, 3, 0x34);
        node.promised_projection.inject_projected_for_test(
            final_voter,
            vec![target],
            LeaderChoiceV1::Vote { leader: target },
        );
        let vertex = node
            .build_local_consensus_vertex(carrier_genesis_reference(0), false)
            .expect("the exact fifth vote completes C1");
        let authors = vertex
            .strong_parents()
            .iter()
            .map(|parent| parent.author())
            .collect::<Vec<_>>();
        assert_eq!(authors, vec![0, 1, 2, 3, 4]);
        assert_eq!(vertex.strong_parents().len(), 5);
        assert!(!authors.contains(&6));
    }

    #[test]
    fn autonomous_control_heartbeat_advances_sequentially_and_reopens_exact_bytes() {
        let mut network = TestNetwork::new();
        let first = network.nodes[0]
            .create_local_control_heartbeat(1_000, true)
            .unwrap()
            .0;
        for author in [1, 2] {
            let candidate = round_one_candidate(author, &network.committee, 0x70 + author as u8);
            let authentication = network
                .context
                .authenticate_with_committee(
                    &candidate,
                    &network.committee,
                    CarrierAuthorizerV1::MacVector {
                        authority: author,
                        keys: &network.keyrings[author as usize],
                    },
                )
                .unwrap();
            network.nodes[0]
                .receive_authenticated_from_peer(
                    &candidate.canonical_wire_bytes().unwrap(),
                    &authentication.canonical_wire_bytes(),
                    author,
                )
                .unwrap();
        }
        assert_eq!(network.nodes[0].local_carrier_round(), 2);
        assert!(network.nodes[0].can_create_carrier());
        assert_eq!(network.nodes[0].current_round_admitted_author_count(), 0);

        let second = network.nodes[0]
            .create_local_control_heartbeat(2_000, true)
            .unwrap()
            .0;
        let second_candidate = decode_candidate(
            second.canonical_carrier_wire(),
            &network.committee,
            Some(second.reference()),
        )
        .unwrap();
        assert_eq!(second_candidate.header().carrier_round(), 2);
        assert_eq!(second_candidate.header().own_prev(), first.reference());
        assert_eq!(
            second_candidate.header().transactions_commitment(),
            TransactionsCommitment::default()
        );
        assert_eq!(
            network.nodes[0].local_outbound_envelope(1),
            Some(first.clone())
        );
        assert_eq!(
            network.nodes[0].local_outbound_envelope(2),
            Some(second.clone())
        );

        let node = network.nodes.swap_remove(0);
        let path = network.path(0);
        node.shutdown().unwrap();
        let (restarted, report) = StarfishRbcDagShadowV1::open(
            path,
            network.committee.clone(),
            0,
            network.context,
            ShadowAuthorizerV1::MacVector(network.keyrings[0].clone()),
        )
        .unwrap();
        assert!(report.replayed_batches() >= 4);
        assert_eq!(restarted.local_carrier_round(), 2);
        assert!(!restarted.can_create_carrier());
        assert_eq!(restarted.local_outbound_envelope(1), Some(first));
        assert_eq!(restarted.local_outbound_envelope(2), Some(second));
        let first_reference = restarted
            .local_outbound_envelope(1)
            .expect("round one survived restart")
            .reference();
        assert_eq!(
            restarted.journal.snapshot().consensus_slot(1),
            Some(first_reference)
        );
        assert!(restarted.journal.snapshot().leader_choice(1).is_some());
    }

    #[test]
    fn empty_application_waits_for_explicit_core_materialization() {
        let mut network = TestNetwork::new();
        let application_header = RbcCanonicalHeader::try_new(
            0,
            1,
            network
                .committee
                .committee()
                .authorities()
                .map(carrier_genesis_reference)
                .collect(),
            Vec::new(),
            899,
            TransactionsCommitment::default(),
        )
        .unwrap();
        let reference = network.nodes[0]
            .create_local_application_carrier(application_header, 999, true)
            .unwrap()
            .0
            .reference();

        assert!(
            network.nodes[0]
                .model
                .lifecycle(&reference)
                .unwrap()
                .data_available,
            "the empty payload is intrinsically available to the RBC reducer"
        );
        assert!(
            !network.nodes[0].projection.is_data_available(reference),
            "authoritative projection must still wait for the Core header"
        );

        network.nodes[0]
            .mark_carrier_data_available(reference)
            .unwrap();
        assert!(network.nodes[0].projection.is_data_available(reference));
        assert!(
            network.nodes[0]
                .promised_projection
                .is_data_available(reference)
        );
    }

    #[test]
    fn application_data_availability_record_reopens_from_the_wal() {
        let mut network = TestNetwork::new();
        let commitment = TransactionsCommitment::from_bytes([0xDA; 32]);
        let application_header = RbcCanonicalHeader::try_new(
            0,
            1,
            network
                .committee
                .committee()
                .authorities()
                .map(carrier_genesis_reference)
                .collect(),
            Vec::new(),
            900,
            commitment,
        )
        .unwrap();
        let reference = network.nodes[0]
            .create_local_application_carrier(application_header, 1_000, true)
            .unwrap()
            .0
            .reference();
        assert!(!network.nodes[0].carrier_data_available(reference));
        assert_eq!(network.nodes[0].projection.closed_tip(0), None);

        for sender in [1, 2] {
            let outer = round_two_phase_carrier(
                sender,
                RbcPhaseStatementV1::Ready { target: reference },
                &network.committee,
            );
            let authentication = network
                .context
                .authenticate_with_committee(
                    &outer,
                    &network.committee,
                    CarrierAuthorizerV1::MacVector {
                        authority: sender,
                        keys: &network.keyrings[sender as usize],
                    },
                )
                .unwrap();
            network.nodes[0]
                .receive_authenticated_from_peer(
                    &outer.canonical_wire_bytes().unwrap(),
                    &authentication.canonical_wire_bytes(),
                    sender,
                )
                .unwrap();
        }

        let vertex = ConsensusVertexReference::new(reference, 1);
        let lifecycle = network.nodes[0].model.lifecycle(&reference).unwrap();
        assert!(lifecycle.delivered);
        assert!(!lifecycle.prefix_closed);
        assert_eq!(network.nodes[0].projection.closed_tip(0), None);
        assert!(matches!(
            network.nodes[0].projection.try_project(reference),
            Err(CertifiedProjectionError::CarrierDataUnavailable(actual)) if actual == reference
        ));

        let effects = network.nodes[0]
            .mark_carrier_data_available(reference)
            .unwrap();
        assert!(effects.iter().any(
            |effect| matches!(effect, ModelEffect::PrefixAdvanced { tip, .. } if *tip == reference)
        ));
        assert!(network.nodes[0].carrier_data_available(reference));
        assert!(
            network.nodes[0]
                .model
                .lifecycle(&reference)
                .unwrap()
                .prefix_closed
        );
        assert_eq!(network.nodes[0].projection.closed_tip(0), Some(reference));
        assert!(network.nodes[0].projection.is_projected(vertex));

        let node = network.nodes.swap_remove(0);
        let path = network.path(0);
        node.shutdown().unwrap();
        let (restarted, report) = StarfishRbcDagShadowV1::open(
            path,
            network.committee.clone(),
            0,
            network.context,
            ShadowAuthorizerV1::MacVector(network.keyrings[0].clone()),
        )
        .unwrap();

        assert_eq!(report.replayed_batches(), 4);
        assert!(restarted.carrier_data_available(reference));
        assert!(restarted.model.lifecycle(&reference).unwrap().prefix_closed);
        assert_eq!(restarted.projection.closed_tip(0), Some(reference));
        assert!(restarted.projection.is_projected(vertex));
        assert!(restarted.retained_candidate_wire(reference).is_some());
    }

    #[test]
    fn authenticated_replays_and_slot_conflicts_do_not_grow_durable_state() {
        let mut network = TestNetwork::new();
        let first = round_one_candidate(1, &network.committee, 0x71);
        let first_authentication = network
            .context
            .authenticate_with_committee(
                &first,
                &network.committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 1,
                    keys: &network.keyrings[1],
                },
            )
            .unwrap();
        let wire = first.canonical_wire_bytes().unwrap();
        let sidecar = first_authentication.canonical_wire_bytes();
        let accepted = network.nodes[0]
            .receive_or_retain_from_peer(&wire, &sidecar, 1)
            .unwrap();
        assert_eq!(
            accepted.disposition(),
            ShadowIngressDispositionV1::Authenticated
        );
        let counts = network.nodes[0].wal_counts();

        let replay = network.nodes[0]
            .receive_or_retain_from_peer(&wire, &sidecar, 1)
            .unwrap();
        assert_eq!(
            replay.disposition(),
            ShadowIngressDispositionV1::IgnoredDuplicateConflictOrStale
        );
        assert_eq!(network.nodes[0].wal_counts(), counts);

        let conflicting = round_one_candidate(1, &network.committee, 0x72);
        let conflicting_authentication = network
            .context
            .authenticate_with_committee(
                &conflicting,
                &network.committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 1,
                    keys: &network.keyrings[1],
                },
            )
            .unwrap();
        let conflict = network.nodes[0]
            .receive_or_retain_from_peer(
                &conflicting.canonical_wire_bytes().unwrap(),
                &conflicting_authentication.canonical_wire_bytes(),
                1,
            )
            .unwrap();
        assert_eq!(
            conflict.disposition(),
            ShadowIngressDispositionV1::IgnoredDuplicateConflictOrStale
        );
        assert_eq!(network.nodes[0].wal_counts(), counts);

        // The classified runtime path cheaply ignores an occupied slot, but
        // the explicitly strict API must retain its advertised verification
        // contract even when the candidate cannot affect state.
        let mut invalid_conflict_sidecar = conflicting_authentication.canonical_wire_bytes();
        invalid_conflict_sidecar[3] ^= 1;
        assert!(matches!(
            network.nodes[0].receive_authenticated_from_peer(
                &conflicting.canonical_wire_bytes().unwrap(),
                &invalid_conflict_sidecar,
                1,
            ),
            Err(ShadowErrorV1::Carrier(_))
        ));
        assert_eq!(network.nodes[0].wal_counts(), counts);

        let node = network.nodes.swap_remove(0);
        let path = network.path(0);
        node.shutdown().unwrap();
        let (mut restarted, _) = StarfishRbcDagShadowV1::open(
            path,
            network.committee.clone(),
            0,
            network.context,
            ShadowAuthorizerV1::MacVector(network.keyrings[0].clone()),
        )
        .unwrap();
        assert_eq!(restarted.wal_counts(), counts);
        let replay_after_restart = restarted
            .receive_or_retain_from_peer(&wire, &sidecar, 1)
            .unwrap();
        assert_eq!(
            replay_after_restart.disposition(),
            ShadowIngressDispositionV1::IgnoredDuplicateConflictOrStale
        );
        assert_eq!(restarted.wal_counts(), counts);
    }

    #[test]
    fn unsolicited_stale_window_has_a_fixed_round_bound() {
        assert!(!round_is_stale(64, 0));
        assert!(!round_is_stale(65, 1));
        assert!(round_is_stale(66, 1));
        assert!(!round_is_stale(66, 2));
    }

    #[test]
    fn ignored_far_future_ingress_skips_authentication_and_durable_state() {
        let mut network = TestNetwork::new();
        let author = 1;
        let previous = |authority: AuthorityIndex| BlockReference {
            authority,
            round: 65,
            digest: BlockDigest::from([0x90 + authority as u8; 32]),
        };
        let candidate = CandidateCarrierV1::try_new_with_committee(
            CarrierHeaderV1Args {
                author,
                carrier_round: 66,
                own_prev: previous(author),
                weak_parents: [0, 2].into_iter().map(previous).collect(),
                transactions_commitment: TransactionsCommitment::default(),
                application_header: None,
                data_acknowledgments: Vec::new(),
                phase_batch: Vec::new(),
                consensus_vertex: None,
                creation_time_ns: 1,
            },
            &network.committee,
        )
        .unwrap();
        let outcome = network.nodes[0]
            .receive_or_retain_from_peer(
                &candidate.canonical_wire_bytes().unwrap(),
                // The far-future prefilter must run before parsing or
                // verifying the authentication sidecar.
                b"not-an-authentication-sidecar",
                author,
            )
            .unwrap();
        assert_eq!(
            outcome.disposition(),
            ShadowIngressDispositionV1::IgnoredFutureOutsideBuffer
        );
        assert!(outcome.effects().is_empty());
        assert_eq!(network.nodes[0].wal_counts(), (0, 0));
        network.nodes[0]
            .create_local_control_heartbeat(2, true)
            .expect("a preflight rejection must leave the actor live");
        assert_eq!(network.nodes[0].wal_counts().0, 1);
    }

    #[test]
    fn caller_supplied_relay_provenance_must_be_canonical_for_the_author() {
        let mut network = TestNetwork::new();
        let candidate = round_one_candidate(1, &network.committee, 0x80);
        let authentication = network
            .context
            .authenticate_with_committee(
                &candidate,
                &network.committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 1,
                    keys: &network.keyrings[1],
                },
            )
            .unwrap();
        assert!(matches!(
            network.nodes[0].receive_authenticated_envelope(
                &candidate.canonical_wire_bytes().unwrap(),
                &authentication.canonical_wire_bytes(),
                IngressProvenanceV1::Relayed { peer: 1 },
            ),
            Err(ShadowErrorV1::NonCanonicalProvenance)
        ));
        assert_eq!(network.nodes[0].wal_counts(), (0, 0));
    }

    #[test]
    fn relayed_authenticated_envelope_reopens_with_exact_provenance_and_bytes() {
        let mut network = TestNetwork::new();
        let candidate = round_one_candidate(1, &network.committee, 0x80);
        let authentication = network
            .context
            .authenticate_with_committee(
                &candidate,
                &network.committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 1,
                    keys: &network.keyrings[1],
                },
            )
            .unwrap();
        let wire = candidate.canonical_wire_bytes().unwrap();
        let sidecar = authentication.canonical_wire_bytes();
        network.nodes[0]
            .receive_authenticated_from_peer(&wire, &sidecar, 2)
            .unwrap();
        assert_eq!(
            network.nodes[0].admitted_reference(1, 1),
            Some(candidate.reference())
        );
        assert_eq!(
            network.nodes[0].journal.snapshot().authenticated_ingress()[0].provenance(),
            IngressProvenanceV1::Relayed { peer: 2 }
        );
        let retained = network.nodes[0]
            .retained_authenticated_envelope(candidate.reference())
            .unwrap();
        assert_eq!(retained.canonical_carrier_wire(), wire);
        assert_eq!(retained.authentication_sidecar(), sidecar);

        let node = network.nodes.swap_remove(0);
        let path = network.path(0);
        node.shutdown().unwrap();
        let (reopened, report) = StarfishRbcDagShadowV1::open(
            path,
            network.committee.clone(),
            0,
            network.context,
            ShadowAuthorizerV1::MacVector(network.keyrings[0].clone()),
        )
        .unwrap();
        assert_eq!(report.replayed_batches(), 1);
        assert_eq!(
            reopened.authenticated_reference(1, 1),
            Some(candidate.reference())
        );
        assert_eq!(
            reopened.admitted_reference(1, 1),
            Some(candidate.reference())
        );
        assert_eq!(
            reopened.journal.snapshot().authenticated_ingress()[0].provenance(),
            IngressProvenanceV1::Relayed { peer: 2 }
        );
        let retained = reopened
            .retained_authenticated_envelope(candidate.reference())
            .unwrap();
        assert_eq!(retained.canonical_carrier_wire(), wire);
        assert_eq!(retained.authentication_sidecar(), sidecar);
        reopened.shutdown().unwrap();
    }

    #[test]
    fn replay_rejects_a_duplicate_authenticated_slot_even_with_an_exact_trace() {
        let mut network = TestNetwork::new();
        let candidate = round_one_candidate(1, &network.committee, 0x81);
        let authentication = network
            .context
            .authenticate_with_committee(
                &candidate,
                &network.committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 1,
                    keys: &network.keyrings[1],
                },
            )
            .unwrap();
        network.nodes[0]
            .receive_authenticated_from_peer(
                &candidate.canonical_wire_bytes().unwrap(),
                &authentication.canonical_wire_bytes(),
                1,
            )
            .unwrap();

        let node = network.nodes.swap_remove(0);
        let path = network.path(0);
        node.shutdown().unwrap();
        let namespace = ShadowWalNamespaceV1::new(network.context, 0);
        let (mut wal, recovery) = ShadowWalV1::open(&path, namespace).unwrap();
        let duplicate = recovery.batches()[0].records().to_vec();
        wal.append_batch(&duplicate).unwrap();
        wal.shutdown().unwrap();

        let result = StarfishRbcDagShadowV1::open(
            path,
            network.committee.clone(),
            0,
            network.context,
            ShadowAuthorizerV1::MacVector(network.keyrings[0].clone()),
        );
        assert!(matches!(
            result,
            Err(ShadowErrorV1::ReplayPolicyViolation {
                batch_sequence: 1,
                reason: "duplicate or conflicting authenticated slot",
            })
        ));
    }

    #[test]
    fn replay_rejects_candidate_recovery_that_was_never_requested() {
        let mut network = TestNetwork::new();
        let target = round_one_candidate(3, &network.committee, 0x82);
        let outer = round_two_phase_carrier(
            1,
            RbcPhaseStatementV1::Echo {
                target: target.reference(),
            },
            &network.committee,
        );
        let authentication = network
            .context
            .authenticate_with_committee(
                &outer,
                &network.committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 1,
                    keys: &network.keyrings[1],
                },
            )
            .unwrap();
        network.nodes[0]
            .receive_authenticated_from_peer(
                &outer.canonical_wire_bytes().unwrap(),
                &authentication.canonical_wire_bytes(),
                1,
            )
            .unwrap();
        assert!(
            !network.nodes[0]
                .requested_recoveries
                .contains_key(&target.reference())
        );

        // The reducer accepts content after any phase evidence allocated the
        // candidate. The shadow's durable grammar is deliberately stricter:
        // network recovery is legal only after a surfaced NeedCarrier.
        let forged_input = ShadowInputV1::CandidateRecovery(target);
        let plan = network.nodes[0]
            .model
            .plan_input(forged_input.model_input())
            .unwrap();
        let forged_batch = encode_batch(network.context, 0, &forged_input, plan.trace()).unwrap();

        let node = network.nodes.swap_remove(0);
        let path = network.path(0);
        node.shutdown().unwrap();
        let namespace = ShadowWalNamespaceV1::new(network.context, 0);
        let (mut wal, _) = ShadowWalV1::open(&path, namespace).unwrap();
        wal.append_batch(&forged_batch).unwrap();
        wal.shutdown().unwrap();

        let result = StarfishRbcDagShadowV1::open(
            path,
            network.committee.clone(),
            0,
            network.context,
            ShadowAuthorizerV1::MacVector(network.keyrings[0].clone()),
        );
        assert!(matches!(
            result,
            Err(ShadowErrorV1::ReplayPolicyViolation {
                batch_sequence: 1,
                reason: "candidate recovery was not requested",
            })
        ));
    }

    #[test]
    fn wal_restart_past_round_one_discards_torn_tail_and_retransmits_exact_bytes() {
        let mut network = TestNetwork::new();
        network.run_four_phase_rounds_with_one_poisoned_recipient();

        let node = network.nodes.swap_remove(0);
        let path = network.path(0);
        let before = node.retransmissions();
        assert_eq!(before.len(), 4);
        let retained = node.retained_candidate_wire(before[0].reference()).unwrap();
        assert_eq!(retained, before[0].canonical_carrier_wire());
        node.shutdown().unwrap();

        let namespace = ShadowWalNamespaceV1::new(network.context, 0);
        let (wal, recovery) = ShadowWalV1::open(&path, namespace).unwrap();
        let first = recovery.batches().first().unwrap().records();
        let kinds = first
            .iter()
            .map(|record| decode_raw_record(record, network.context, 0).unwrap().kind)
            .collect::<Vec<_>>();
        assert_eq!(kinds[0], RECORD_LOCAL_OUTBOUND_CONTENT);
        assert_eq!(kinds[kinds.len() - 2], RECORD_LOCAL_OUTBOUND_SIDECAR);
        assert_eq!(kinds[kinds.len() - 1], RECORD_LOCAL_OUTBOUND_EXPOSE);
        assert!(
            kinds[1..kinds.len() - 2]
                .iter()
                .all(|kind| *kind == RECORD_MODEL_TRACE)
        );
        wal.shutdown().unwrap();

        let torn = b"uncommitted-tail";
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(torn).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let (restarted, report) = StarfishRbcDagShadowV1::open(
            &path,
            network.committee.clone(),
            0,
            network.context,
            ShadowAuthorizerV1::MacVector(network.keyrings[0].clone()),
        )
        .unwrap();
        assert_eq!(report.discarded_tail_bytes(), torn.len() as u64);
        assert!(report.replayed_batches() > 3);
        assert_eq!(restarted.local_carrier_round(), 5);
        assert_eq!(restarted.retransmissions(), before);
        assert!(report.recovery_effects().is_empty());
        for author in 0..N {
            assert!(restarted.delivered(author as AuthorityIndex, 1).is_some());
        }
    }

    #[test]
    fn every_authentication_scheme_reopens_with_the_exact_persisted_sidecar() {
        let committee = Committee::new_test(vec![1; N]);
        let committee = RbcDagCommitteeContextV1::new(committee).unwrap();
        let keyrings = mac_keyrings_for_test(N);
        let directory = tempfile::tempdir().unwrap();

        for (index, scheme) in [
            BlockAuthenticationScheme::Ed25519,
            BlockAuthenticationScheme::MlDsa44,
            BlockAuthenticationScheme::MlDsa65,
            BlockAuthenticationScheme::MacVector,
        ]
        .into_iter()
        .enumerate()
        {
            let context = RbcDagContextV1::new_with_committee(
                RbcDagProtocolInstanceId::new([0xA0 + index as u8; 32]).unwrap(),
                &committee,
                scheme,
            );
            let authorizer = match scheme {
                BlockAuthenticationScheme::Ed25519 => ShadowAuthorizerV1::Ed25519(dummy_signer()),
                BlockAuthenticationScheme::MlDsa44 => {
                    ShadowAuthorizerV1::MlDsa44(dummy_ml_dsa_44_signer())
                }
                BlockAuthenticationScheme::MlDsa65 => {
                    ShadowAuthorizerV1::MlDsa65(dummy_ml_dsa_65_signer())
                }
                BlockAuthenticationScheme::MacVector => {
                    ShadowAuthorizerV1::MacVector(keyrings[0].clone())
                }
            };
            let path = directory.path().join(format!("scheme-{index}.wal"));
            let (mut core, _) = StarfishRbcDagShadowV1::open(
                &path,
                committee.clone(),
                0,
                context,
                authorizer.clone(),
            )
            .unwrap();
            let envelope = core
                .create_local_carrier(
                    1,
                    TransactionsCommitment::from_bytes([0xE0 + index as u8; 32]),
                    10,
                )
                .unwrap()
                .0;
            core.shutdown().unwrap();

            let (restarted, report) =
                StarfishRbcDagShadowV1::open(&path, committee.clone(), 0, context, authorizer)
                    .unwrap();
            assert!(report.replayed_batches() > 0);
            assert_eq!(restarted.retransmissions(), vec![envelope]);
            restarted.shutdown().unwrap();
        }
    }

    #[test]
    fn reopening_rejects_a_wrong_local_signer_before_replaying_the_wal() {
        let committee = Committee::new_test(vec![1; N]);
        let committee = RbcDagCommitteeContextV1::new(committee).unwrap();
        let context = RbcDagContextV1::new_with_committee(
            RbcDagProtocolInstanceId::new([0xAF; 32]).unwrap(),
            &committee,
            BlockAuthenticationScheme::Ed25519,
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wrong-reopen-signer.wal");
        let (mut core, _) = StarfishRbcDagShadowV1::open(
            &path,
            committee.clone(),
            0,
            context,
            ShadowAuthorizerV1::Ed25519(dummy_signer()),
        )
        .unwrap();
        core.create_local_carrier(1, TransactionsCommitment::from_bytes([0xEF; 32]), 10)
            .unwrap();
        core.shutdown().unwrap();

        let wrong_signer = Signer::new_for_test(1).pop().unwrap();
        let result = StarfishRbcDagShadowV1::open(
            path,
            committee,
            0,
            context,
            ShadowAuthorizerV1::Ed25519(wrong_signer),
        );
        assert!(matches!(result, Err(ShadowErrorV1::AuthorizerKeyMismatch)));
    }

    #[test]
    fn replay_rejects_a_validly_framed_corrupt_trace() {
        let committee = Committee::new_test(vec![1; N]);
        let committee = RbcDagCommitteeContextV1::new(Arc::clone(&committee)).unwrap();
        let context = RbcDagContextV1::new_with_committee(
            RbcDagProtocolInstanceId::new([0xF4; 32]).unwrap(),
            &committee,
            BlockAuthenticationScheme::MacVector,
        );
        let keyrings = mac_keyrings_for_test(N);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corrupt-trace.wal");
        let candidate = round_one_candidate(1, &committee, 0x91);
        let input = encode_raw_record(
            context,
            0,
            RECORD_CANDIDATE_RETENTION,
            &candidate.canonical_wire_bytes().unwrap(),
        )
        .unwrap();
        let fabricated_trace = encode_raw_record(
            context,
            0,
            RECORD_MODEL_TRACE,
            &encode_trace_batch(&[ModelTraceEvent::Effect(ModelEffect::CarrierRoundAdvanced(
                99,
            ))])
            .unwrap(),
        )
        .unwrap();
        let (mut wal, _) = ShadowWalV1::open(&path, ShadowWalNamespaceV1::new(context, 0)).unwrap();
        wal.append_batch(&[input, fabricated_trace]).unwrap();
        wal.shutdown().unwrap();

        let result = StarfishRbcDagShadowV1::open(
            &path,
            committee,
            0,
            context,
            ShadowAuthorizerV1::MacVector(keyrings[0].clone()),
        );
        assert!(matches!(
            result,
            Err(ShadowErrorV1::TraceMismatch { batch_sequence: 0 })
        ));
    }

    #[test]
    fn direct_shadow_comparison_reports_match_mismatch_and_ambiguity_without_references() {
        let mut network = TestNetwork::new();
        network.run_four_phase_rounds_with_one_poisoned_recipient();
        let node = &network.nodes[0];
        let direct = node.delivered_identities().unwrap();
        assert_eq!(
            node.compare_direct_deliveries(direct.clone()).unwrap(),
            ShadowDeliveryComparisonV1::Match
        );

        let mut mismatch = direct.clone();
        mismatch[0].transactions_commitment = TransactionsCommitment::from_bytes([0xAB; 32]);
        assert!(matches!(
            node.compare_direct_deliveries(mismatch).unwrap(),
            ShadowDeliveryComparisonV1::Mismatch { .. }
        ));

        let mut ambiguous = direct.clone();
        let mut conflicting = direct[0];
        conflicting.transactions_commitment = TransactionsCommitment::from_bytes([0xCD; 32]);
        ambiguous.push(conflicting);
        assert_eq!(
            node.compare_direct_deliveries(ambiguous).unwrap(),
            ShadowDeliveryComparisonV1::Ambiguous {
                slots: vec![ShadowDeliverySlotV1 {
                    author: direct[0].author,
                    round: direct[0].round,
                }],
            }
        );
    }

    #[test]
    fn recovery_api_binds_requested_reference_before_model_transition() {
        let mut network = TestNetwork::new();
        let candidate = round_one_candidate(1, &network.committee, 0xA1);
        let mut wrong = candidate.reference();
        wrong.digest = BlockDigest::from([0xFF; 32]);
        assert!(matches!(
            network.nodes[0]
                .recover_candidate_for(wrong, &candidate.canonical_wire_bytes().unwrap()),
            Err(ShadowErrorV1::Carrier(
                RbcDagError::ReferenceMismatch { .. }
            ))
        ));
    }

    #[test]
    fn recovered_content_is_durable_only_after_embedded_phase_evidence() {
        let mut network = TestNetwork::new();
        let target = round_one_candidate(3, &network.committee, 0xB1);
        for sender in 1..N {
            let outer = round_two_phase_carrier(
                sender as AuthorityIndex,
                RbcPhaseStatementV1::Echo {
                    target: target.reference(),
                },
                &network.committee,
            );
            let authentication = network
                .context
                .authenticate_with_committee(
                    &outer,
                    &network.committee,
                    CarrierAuthorizerV1::MacVector {
                        authority: sender as AuthorityIndex,
                        keys: &network.keyrings[sender],
                    },
                )
                .unwrap();
            network.nodes[0]
                .receive_authenticated_from_peer(
                    &outer.canonical_wire_bytes().unwrap(),
                    &authentication.canonical_wire_bytes(),
                    sender as AuthorityIndex,
                )
                .unwrap();
        }
        assert!(
            network.nodes[0]
                .retained_candidate_wire(target.reference())
                .is_none()
        );
        network.nodes[0]
            .recover_candidate_for(target.reference(), &target.canonical_wire_bytes().unwrap())
            .unwrap();
        assert_eq!(
            network.nodes[0]
                .retained_candidate_wire(target.reference())
                .unwrap(),
            target.canonical_wire_bytes().unwrap()
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
                creation_time_ns: 1,
            },
            committee,
        )
        .unwrap()
    }

    fn round_one_consensus_candidate(
        author: AuthorityIndex,
        committee: &RbcDagCommitteeContextV1,
        marker: u8,
        transactions_commitment: TransactionsCommitment,
    ) -> CandidateCarrierV1 {
        let weak_parents = committee
            .committee()
            .authorities()
            .filter(|authority| *authority != author)
            .take(2)
            .map(carrier_genesis_reference)
            .collect();
        let strong_parents = committee
            .committee()
            .authorities()
            .map(|authority| ConsensusVertexReference::new(carrier_genesis_reference(authority), 0))
            .collect();
        let leader_author = committee.committee().elect_leader(0);
        CandidateCarrierV1::try_new_with_committee(
            CarrierHeaderV1Args {
                author,
                carrier_round: 1,
                own_prev: carrier_genesis_reference(author),
                weak_parents,
                transactions_commitment,
                application_header: None,
                data_acknowledgments: Vec::new(),
                phase_batch: Vec::new(),
                consensus_vertex: Some(ConsensusVertexV1::new(
                    1,
                    strong_parents,
                    vec![None; committee.committee().len()],
                    LeaderChoiceV1::Vote {
                        leader: ConsensusVertexReference::new(
                            carrier_genesis_reference(leader_author),
                            0,
                        ),
                    },
                )),
                creation_time_ns: u64::from(marker),
            },
            committee,
        )
        .unwrap()
    }

    fn phase_carrier(
        author: AuthorityIndex,
        round: RoundNumber,
        statement: RbcPhaseStatementV1,
        committee: &RbcDagCommitteeContextV1,
        marker: u8,
    ) -> CandidateCarrierV1 {
        assert!(round > 1);
        let previous = |authority: AuthorityIndex| BlockReference {
            authority,
            round: round - 1,
            digest: BlockDigest::from([marker.wrapping_add(authority as u8); 32]),
        };
        let weak_parents = committee
            .committee()
            .authorities()
            .filter(|authority| *authority != author)
            .take(2)
            .map(previous)
            .collect();
        CandidateCarrierV1::try_new_with_committee(
            CarrierHeaderV1Args {
                author,
                carrier_round: round,
                own_prev: previous(author),
                weak_parents,
                transactions_commitment: TransactionsCommitment::from_bytes([marker; 32]),
                application_header: None,
                data_acknowledgments: Vec::new(),
                phase_batch: vec![statement],
                consensus_vertex: None,
                creation_time_ns: u64::from(round),
            },
            committee,
        )
        .unwrap()
    }

    fn round_two_phase_carrier(
        author: AuthorityIndex,
        statement: RbcPhaseStatementV1,
        committee: &RbcDagCommitteeContextV1,
    ) -> CandidateCarrierV1 {
        let previous = |authority: AuthorityIndex| BlockReference {
            authority,
            round: 1,
            digest: BlockDigest::from([0xC0 + authority as u8; 32]),
        };
        let weak_parents = committee
            .committee()
            .authorities()
            .filter(|authority| *authority != author)
            .take(2)
            .map(previous)
            .collect();
        CandidateCarrierV1::try_new_with_committee(
            CarrierHeaderV1Args {
                author,
                carrier_round: 2,
                own_prev: previous(author),
                weak_parents,
                transactions_commitment: TransactionsCommitment::from_bytes(
                    [0xD0 + author as u8; 32],
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

    fn recovery_application(
        authority: AuthorityIndex,
        round: RoundNumber,
        marker: u8,
    ) -> RbcCanonicalHeader {
        RbcCanonicalHeader::try_new(
            authority,
            round,
            (0..N as AuthorityIndex)
                .map(carrier_genesis_reference)
                .collect(),
            Vec::new(),
            u64::from(marker),
            TransactionsCommitment::from_bytes([marker; 32]),
        )
        .unwrap()
    }

    fn recovery_delta(
        output_sequence: RoundNumber,
        consensus_round: RoundNumber,
        applications: Vec<RbcCanonicalHeader>,
    ) -> CommittedFrontierDeltaV1 {
        let carrier = BlockReference::new_test(
            (consensus_round as usize % N) as AuthorityIndex,
            consensus_round.saturating_add(100),
        );
        let application_diagnostics = applications
            .iter()
            .map(|_| CommittedApplicationDiagnosticV1 {
                physical_carrier_round_delta: 0,
            })
            .collect();
        CommittedFrontierDeltaV1 {
            output_sequence,
            anchor: ConsensusVertexReference::new(carrier, consensus_round),
            frontier: vec![None; N],
            carriers: Vec::new(),
            applications,
            application_diagnostics,
        }
    }

    fn recovery_cursor(
        delta: &CommittedFrontierDeltaV1,
        committed_rounds: Vec<RoundNumber>,
    ) -> RbcDagFrontierRecoveryCursorV1 {
        RbcDagFrontierRecoveryCursorV1 {
            receipt: RbcDagFrontierReceipt {
                carrier_anchor: delta.anchor.carrier(),
                output_sequence: delta.output_sequence,
                committed_rounds,
            },
            application_references: delta
                .applications
                .iter()
                .map(RbcCanonicalHeader::reference)
                .collect(),
        }
    }

    #[test]
    fn authoritative_frontier_recovery_replays_only_the_exact_newer_suffix() {
        let first_application = recovery_application(1, 5, 0xA1);
        let last_application = recovery_application(2, 7, 0xA2);
        // Logical anchor rounds may regress while the output sequence remains
        // contiguous and monotone.
        let first = recovery_delta(1, 8, vec![first_application]);
        let control_only = recovery_delta(2, 3, Vec::new());
        let last = recovery_delta(3, 7, vec![last_application]);
        let history = vec![first.clone(), control_only.clone(), last.clone()];

        assert_eq!(
            reconcile_authoritative_frontier_suffix(history.clone(), None, N).unwrap(),
            history
        );

        let after_first = reconcile_authoritative_frontier_suffix(
            history.clone(),
            Some(&recovery_cursor(&first, vec![0, 5, 0, 0])),
            N,
        )
        .unwrap();
        assert_eq!(after_first, vec![control_only.clone(), last.clone()]);

        let after_control = reconcile_authoritative_frontier_suffix(
            history,
            Some(&recovery_cursor(&control_only, vec![0, 5, 0, 0])),
            N,
        )
        .unwrap();
        assert_eq!(after_control, vec![last]);
    }

    #[test]
    fn authoritative_frontier_recovery_rejects_unreconciled_cursors() {
        let application = recovery_application(1, 5, 0xB1);
        let first = recovery_delta(1, 8, vec![application]);
        let last = recovery_delta(2, 3, Vec::new());
        let history = vec![first.clone(), last.clone()];

        let mut conflict = recovery_cursor(&first, vec![0, 5, 0, 0]);
        conflict.receipt.carrier_anchor = BlockReference::new_test(0, 999);
        assert!(matches!(
            reconcile_authoritative_frontier_suffix(history.clone(), Some(&conflict), N),
            Err(ShadowErrorV1::FrontierRecoveryAnchorConflict { .. })
        ));

        let mut conflict = recovery_cursor(&first, vec![0, 5, 0, 0]);
        conflict.application_references.clear();
        assert!(matches!(
            reconcile_authoritative_frontier_suffix(history.clone(), Some(&conflict), N),
            Err(ShadowErrorV1::FrontierRecoveryApplicationsConflict { .. })
        ));

        let conflict = recovery_cursor(&first, vec![0, 4, 0, 0]);
        assert!(matches!(
            reconcile_authoritative_frontier_suffix(history.clone(), Some(&conflict), N),
            Err(ShadowErrorV1::FrontierRecoveryWatermarksConflict { .. })
        ));

        let missing = RbcDagFrontierRecoveryCursorV1 {
            receipt: RbcDagFrontierReceipt {
                carrier_anchor: BlockReference::new_test(2, 103),
                output_sequence: 3,
                committed_rounds: vec![0, 5, 0, 0],
            },
            application_references: Vec::new(),
        };
        assert!(matches!(
            reconcile_authoritative_frontier_suffix(history.clone(), Some(&missing), N),
            Err(ShadowErrorV1::FrontierRecoveryCursorAhead {
                durable_sequence: 3,
                actor_sequence: 2
            })
        ));

        let ahead = RbcDagFrontierRecoveryCursorV1 {
            receipt: RbcDagFrontierReceipt {
                carrier_anchor: BlockReference::new_test(0, 104),
                output_sequence: 4,
                committed_rounds: vec![0, 5, 0, 0],
            },
            application_references: Vec::new(),
        };
        assert!(matches!(
            reconcile_authoritative_frontier_suffix(history, Some(&ahead), N),
            Err(ShadowErrorV1::FrontierRecoveryCursorAhead {
                durable_sequence: 4,
                actor_sequence: 2
            })
        ));
    }

    #[test]
    fn authoritative_frontier_recovery_suffix_is_bounded() {
        let history = (1..=MAX_AUTHORITATIVE_FRONTIER_RECOVERY_SUFFIX_V1 + 1)
            .map(|sequence| {
                recovery_delta(sequence as RoundNumber, sequence as RoundNumber, Vec::new())
            })
            .collect();
        assert!(matches!(
            reconcile_authoritative_frontier_suffix(history, None, N),
            Err(ShadowErrorV1::FrontierRecoverySuffixLimit { limit, actual })
                if limit == MAX_AUTHORITATIVE_FRONTIER_RECOVERY_SUFFIX_V1
                    && actual == MAX_AUTHORITATIVE_FRONTIER_RECOVERY_SUFFIX_V1 + 1
        ));
    }
}
