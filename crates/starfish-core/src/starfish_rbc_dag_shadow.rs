// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Durable, single-owner shadow execution for the embedded-RBC Starfish DAG.
//!
//! This adapter is deliberately non-authoritative: it consumes the same
//! carrier bytes as the live protocol, persists its own deterministic input
//! and trace log, and reports comparison results without influencing the live
//! protocol. One [`ShadowWalV1`] batch is one reducer transition. Effects are
//! returned only after that complete batch has reached durable storage.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::Path,
};

use crate::{
    crypto::{MacKey, MlDsa44Signer, MlDsa65Signer, Signer, TransactionsCommitment},
    starfish_rbc_dag::{
        AuthenticatedCarrierV1, CandidateCarrierV1, CarrierAuthenticationV1, CarrierAuthorizerV1,
        CarrierHeaderV1Args, LocallyAuthenticatedCarrierV1, RbcDagCommitteeContextV1,
        RbcDagContextV1, RbcDagError, RbcPhaseStatementV1,
        journal::{
            IngressProvenanceV1, JournalErrorV1, JournalEventV1, ValidatedJournalBatchV1,
            WriteAheadJournalV1,
        },
        model::{ModelEffect, ModelError, ModelInputRecord, ModelTraceEvent, RbcDagModel},
        storage::{
            MAX_SHADOW_WAL_RECORD_SIZE_V1, ShadowWalErrorV1, ShadowWalNamespaceV1,
            ShadowWalSummaryV1, ShadowWalV1,
        },
    },
    types::{
        AuthorityIndex, BlockAuthenticationScheme, BlockDigest, BlockReference, MAX_COMMITTEE_SIZE,
        RoundNumber, TimestampNs,
    },
};

const RAW_RECORD_MAGIC: &[u8; 4] = b"SRD3";
const RAW_RECORD_VERSION_V1: u8 = 1;
const RAW_RECORD_HEADER_SIZE: usize = 80;

const RECORD_AUTHENTICATED_INGRESS: u8 = 0x01;
const RECORD_CANDIDATE_RETENTION: u8 = 0x02;
const RECORD_CANDIDATE_RECOVERY: u8 = 0x03;
const RECORD_LOCAL_OUTBOUND_CONTENT: u8 = 0x04;
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

const EFFECT_NEED_CARRIER: u8 = 0x00;
const EFFECT_DELIVERED: u8 = 0x01;
const EFFECT_PREFIX_ADVANCED: u8 = 0x02;
const EFFECT_CARRIER_ROUND_ADVANCED: u8 = 0x03;

const PHASE_ECHO: u8 = 0x00;
const PHASE_READY: u8 = 0x01;
const PROVENANCE_DIRECT: u8 = 0x00;
const PROVENANCE_RELAYED: u8 = 0x01;

/// Shadow-benchmark-only resource guard for newly arriving, unsolicited
/// values. This is not a protocol-safe pruning rule: asynchronous delivery
/// can delay an honest INIT by more than this many rounds. A production
/// protocol must derive pruning from a certified/committed watermark instead.
/// Exact RBC recovery requests are exempt from this prototype guard.
const SHADOW_BENCHMARK_UNSOLICITED_RETENTION_WINDOW_ROUNDS_V1: RoundNumber = 64;

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
pub(crate) enum ShadowIngressDispositionV1 {
    Authenticated,
    CandidateRetained,
    IgnoredDuplicateConflictOrStale,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShadowOpenReportV1 {
    replayed_batches: u64,
    discarded_tail_bytes: u64,
    recovery_effects: Vec<ModelEffect>,
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
    UnrequestedRecovery(BlockReference),
    SlotCandidateLimit {
        author: AuthorityIndex,
        round: RoundNumber,
        limit: usize,
    },
    MissingOutboundCandidate(BlockReference),
    MissingDeliveredCandidate(BlockReference),
    PostDurabilityCommit(ModelError),
    PostDurabilityJournal(JournalErrorV1),
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
            Self::PostDurabilityCommit(error) => write!(
                formatter,
                "shadow model commit failed after WAL durability: {error}"
            ),
            Self::PostDurabilityJournal(error) => write!(
                formatter,
                "shadow journal commit failed after WAL durability: {error}"
            ),
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
            Self::Model(error) | Self::PostDurabilityCommit(error) => Some(error),
            Self::Journal(error) | Self::PostDurabilityJournal(error) => Some(error),
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

#[derive(Clone)]
enum ShadowInputV1 {
    AuthenticatedIngress {
        authenticated: AuthenticatedCarrierV1,
        provenance: IngressProvenanceV1,
    },
    CandidateRetention(CandidateCarrierV1),
    CandidateRecovery(CandidateCarrierV1),
    LocalOutbound(LocallyAuthenticatedCarrierV1),
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
        }
    }

    fn candidate(&self) -> &CandidateCarrierV1 {
        match self {
            Self::AuthenticatedIngress { authenticated, .. } => authenticated.candidate(),
            Self::CandidateRetention(candidate) | Self::CandidateRecovery(candidate) => candidate,
            Self::LocalOutbound(authenticated) => authenticated.candidate(),
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

/// Synchronous, non-authoritative shadow core.
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
    delivered: BTreeSet<BlockReference>,
    authenticated_slots: BTreeMap<(AuthorityIndex, RoundNumber), BlockReference>,
    ordinarily_retained_slots: BTreeMap<(AuthorityIndex, RoundNumber), BlockReference>,
    slot_candidates: BTreeMap<(AuthorityIndex, RoundNumber), BTreeSet<BlockReference>>,
    requested_recoveries: BTreeMap<BlockReference, Vec<AuthorityIndex>>,
    poisoned: bool,
}

impl StarfishRbcDagShadowV1 {
    pub(crate) fn open(
        path: impl AsRef<Path>,
        committee: RbcDagCommitteeContextV1,
        own_authority: AuthorityIndex,
        context: RbcDagContextV1,
        authorizer: ShadowAuthorizerV1,
    ) -> Result<(Self, ShadowOpenReportV1), ShadowErrorV1> {
        validate_configuration(&committee, own_authority, context, &authorizer)?;
        let namespace = ShadowWalNamespaceV1::new(context, own_authority);
        let (wal, recovery) = ShadowWalV1::open(path, namespace)?;
        let replayed_batches = recovery.batch_count();
        let discarded_tail_bytes = recovery.discarded_tail_bytes();

        let model = RbcDagModel::new(committee.committee_arc(), own_authority, context)?;
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
            delivered: BTreeSet::new(),
            authenticated_slots: BTreeMap::new(),
            ordinarily_retained_slots: BTreeMap::new(),
            slot_candidates: BTreeMap::new(),
            requested_recoveries: BTreeMap::new(),
            poisoned: false,
        };

        for batch in recovery.batches() {
            let input = core.decode_batch(batch.records())?;
            core.apply_replayed(input, batch.records(), batch.sequence())?;
        }
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
            },
        ))
    }

    pub(crate) fn local_carrier_round(&self) -> RoundNumber {
        self.model.local_carrier_round()
    }

    pub(crate) fn can_create_carrier(&self) -> bool {
        self.model.can_create_carrier()
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

    /// Construct, authenticate, durably fix, and expose the next local
    /// carrier. M3 intentionally uses empty ACKs and no consensus vertex.
    pub(crate) fn create_local_carrier(
        &mut self,
        round: RoundNumber,
        transactions_commitment: TransactionsCommitment,
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
                data_acknowledgments: Vec::new(),
                phase_batch: self.model.pending_phase_batch(),
                consensus_vertex: None,
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
        self.ensure_live()?;
        if !self.committee.committee().known_authority(trusted_peer) {
            return Err(ShadowErrorV1::UnknownAuthority(trusted_peer));
        }
        let candidate = decode_candidate(canonical_carrier_wire, &self.committee, None)?;
        let provenance = infer_ingress_provenance(trusted_peer, candidate.header().author());
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

    pub(crate) fn retained_candidate_wire(&self, reference: BlockReference) -> Option<Vec<u8>> {
        self.journal
            .snapshot()
            .retained_carrier(reference)
            .map(<[u8]>::to_vec)
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
    ) -> Result<Vec<(RoundNumber, TransactionsCommitment, TimestampNs)>, ShadowErrorV1> {
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
                Ok((
                    candidate.header().carrier_round(),
                    candidate.header().transactions_commitment(),
                    candidate.header().creation_time_ns(),
                ))
            })
            .collect()
    }

    pub(crate) fn delivered_identities(
        &self,
    ) -> Result<Vec<ShadowDeliveryIdentityV1>, ShadowErrorV1> {
        self.delivered
            .iter()
            .map(|reference| {
                let candidate = self
                    .candidates
                    .get(reference)
                    .ok_or(ShadowErrorV1::MissingDeliveredCandidate(*reference))?;
                Ok(ShadowDeliveryIdentityV1::new(
                    candidate.header().author(),
                    candidate.header().carrier_round(),
                    candidate.header().transactions_commitment(),
                ))
            })
            .collect()
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
        let plan = self.model.plan_input(input.model_input())?;
        let records = encode_batch(self.context, self.own_authority, &input, plan.trace())?;
        let journal_batch = validate_journal_transition(&self.journal, &input, plan.trace())?;
        self.wal.append_batch(&records)?;
        let effects = match self.model.commit_plan(plan) {
            Ok(effects) => effects,
            Err(error) => {
                self.poisoned = true;
                return Err(ShadowErrorV1::PostDurabilityCommit(error));
            }
        };
        if let Err(error) = self.journal.commit_validated_batch(journal_batch) {
            self.poisoned = true;
            return Err(ShadowErrorV1::PostDurabilityJournal(error));
        }
        self.record_committed_input(&input, &effects);
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
        let plan = self.model.plan_input(input.model_input())?;
        if plan.trace() != recorded_trace {
            return Err(ShadowErrorV1::TraceMismatch { batch_sequence });
        }
        let journal_batch = validate_journal_transition(&self.journal, &input, plan.trace())?;
        let effects = self.model.commit_plan(plan)?;
        if let Err(error) = self.journal.commit_validated_batch(journal_batch) {
            self.poisoned = true;
            return Err(ShadowErrorV1::PostDurabilityJournal(error));
        }
        self.record_committed_input(&input, &effects);
        Ok(effects)
    }

    fn validate_replay_policy(
        &self,
        input: &ShadowInputV1,
        batch_sequence: u64,
    ) -> Result<(), ShadowErrorV1> {
        let reference = input.candidate().reference();
        let slot = carrier_slot(reference);
        let violation = match input {
            ShadowInputV1::AuthenticatedIngress { .. } => {
                if round_is_stale(self.model.local_carrier_round(), reference.round) {
                    Some("stale authenticated ingress")
                } else if self.authenticated_slots.contains_key(&slot) {
                    Some("duplicate or conflicting authenticated slot")
                } else {
                    None
                }
            }
            ShadowInputV1::CandidateRetention(_) => {
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
        };
        if let Some(reason) = violation {
            return Err(ShadowErrorV1::ReplayPolicyViolation {
                batch_sequence,
                reason,
            });
        }
        Ok(())
    }

    fn record_committed_input(&mut self, input: &ShadowInputV1, effects: &[ModelEffect]) {
        let candidate = input.candidate().clone();
        let reference = candidate.reference();
        let slot = carrier_slot(reference);
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
        }
        self.requested_recoveries.remove(&reference);
        for effect in effects {
            match effect {
                ModelEffect::NeedCarrier { target, holders } => {
                    self.requested_recoveries.insert(*target, holders.clone());
                }
                ModelEffect::Delivered(delivered) => {
                    self.delivered.insert(*delivered);
                    self.requested_recoveries.remove(delivered);
                }
                ModelEffect::PrefixAdvanced { .. } | ModelEffect::CarrierRoundAdvanced(_) => {}
            }
        }
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

fn validate_journal_transition(
    journal: &WriteAheadJournalV1,
    input: &ShadowInputV1,
    trace: &[ModelTraceEvent],
) -> Result<ValidatedJournalBatchV1, ShadowErrorV1> {
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
    }

    let local_reference = input.is_local().then(|| input.candidate().reference());
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
    journal.validate_batch(events).map_err(Into::into)
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
            RECORD_AUTHENTICATED_INGRESS | RECORD_CANDIDATE_RETENTION | RECORD_CANDIDATE_RECOVERY,
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
            other => Err(ShadowCodecErrorV1::InvalidPhase(other)),
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
        starfish_rbc_dag::{RbcDagProtocolInstanceId, carrier_genesis_reference},
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

        fn run_three_rounds_with_one_poisoned_recipient(&mut self) {
            for round in 1..=3 {
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

    #[test]
    fn three_round_mac_shadow_delivers_round_one_after_poisoned_tag_is_only_staged() {
        let mut network = TestNetwork::new();
        network.run_three_rounds_with_one_poisoned_recipient();

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
        network.run_three_rounds_with_one_poisoned_recipient();

        let node = network.nodes.swap_remove(0);
        let path = network.path(0);
        let before = node.retransmissions();
        assert_eq!(before.len(), 3);
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
        assert_eq!(restarted.local_carrier_round(), 4);
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
        network.run_three_rounds_with_one_poisoned_recipient();
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
                data_acknowledgments: Vec::new(),
                phase_batch: Vec::new(),
                consensus_vertex: None,
                creation_time_ns: 1,
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
                data_acknowledgments: Vec::new(),
                phase_batch: vec![statement],
                consensus_vertex: None,
                creation_time_ns: 2,
            },
            committee,
        )
        .unwrap()
    }
}
