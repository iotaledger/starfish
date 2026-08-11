// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Crash/restart model for proof-critical Starfish-RBC-DAG state.
//!
//! This module is intentionally a deterministic write-ahead-log reducer. It
//! does not perform I/O and it does not duplicate carrier or authentication
//! decoding. Callers validate canonical bytes before journaling them; the
//! reducer pins the exact byte strings and rejects any later alternative.

use std::{collections::BTreeMap, error::Error, fmt};

use crate::types::{AuthorityIndex, BlockReference, RoundNumber};

use super::{
    AuthenticatedCarrierV1, CandidateCarrierV1, LeaderChoiceV1, LocallyAuthenticatedCarrierV1,
    RbcDagContextV1, RbcPhaseStatementV1,
};

/// A Bracha slot is identified independently of the candidate digest.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RbcSlotKeyV1 {
    pub author: AuthorityIndex,
    pub carrier_round: RoundNumber,
}

impl RbcSlotKeyV1 {
    pub const fn new(author: AuthorityIndex, carrier_round: RoundNumber) -> Self {
        Self {
            author,
            carrier_round,
        }
    }

    pub const fn of(reference: BlockReference) -> Self {
        Self::new(reference.authority, reference.round)
    }
}

/// Provenance retained for an authenticated ingress record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressProvenanceV1 {
    DirectFromAuthor,
    Relayed { peer: AuthorityIndex },
}

/// One authenticated arrival in its locally observed order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedIngressRecordV1 {
    sequence: u64,
    reference: BlockReference,
    provenance: IngressProvenanceV1,
    canonical_carrier_wire: Vec<u8>,
    authentication_sidecar: Vec<u8>,
}

impl AuthenticatedIngressRecordV1 {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn reference(&self) -> BlockReference {
        self.reference
    }

    pub fn provenance(&self) -> IngressProvenanceV1 {
        self.provenance
    }

    pub fn canonical_carrier_wire(&self) -> &[u8] {
        &self.canonical_carrier_wire
    }

    pub fn authentication_sidecar(&self) -> &[u8] {
        &self.authentication_sidecar
    }
}

/// Exact local carrier bytes retained for first send and retransmission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableOutboundCarrierV1 {
    reference: BlockReference,
    canonical_carrier_wire: Vec<u8>,
    authentication_sidecar: Vec<u8>,
    exposed: bool,
}

impl DurableOutboundCarrierV1 {
    pub fn reference(&self) -> BlockReference {
        self.reference
    }

    pub fn canonical_carrier_wire(&self) -> &[u8] {
        &self.canonical_carrier_wire
    }

    pub fn authentication_sidecar(&self) -> &[u8] {
        &self.authentication_sidecar
    }

    pub fn exposed(&self) -> bool {
        self.exposed
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PhaseKindV1 {
    Echo,
    Ready,
}

/// Durable result of processing one entry in an enclosing phase batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppliedPhaseOutcomeV1 {
    Counted,
    IgnoredReplay,
    IgnoredEquivocation,
}

impl PhaseKindV1 {
    const fn of(statement: RbcPhaseStatementV1) -> Self {
        match statement {
            RbcPhaseStatementV1::Echo { .. } => Self::Echo,
            RbcPhaseStatementV1::Ready { .. } => Self::Ready,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SenderPhaseKeyV1 {
    slot: RbcSlotKeyV1,
    sender: AuthorityIndex,
    phase: PhaseKindV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AppliedPhaseEntryV1 {
    sender: AuthorityIndex,
    statement: RbcPhaseStatementV1,
    outcome: AppliedPhaseOutcomeV1,
}

/// One durable write-ahead event.
///
/// The context is repeated in every event so that copied records from another
/// protocol instance, committee, or authentication run fail closed on replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalEventV1 {
    AuthenticatedIngress {
        context: RbcDagContextV1,
        sequence: u64,
        authenticated: AuthenticatedCarrierV1,
        provenance: IngressProvenanceV1,
    },
    /// Canonical content retained through header recovery. This is content
    /// availability for READY/delivery, not authenticated admission for ECHO.
    RetainCandidateContent {
        context: RbcDagContextV1,
        candidate: CandidateCarrierV1,
    },
    FixOwnCarrier {
        context: RbcDagContextV1,
        reference: BlockReference,
    },
    LockEcho {
        context: RbcDagContextV1,
        target: BlockReference,
    },
    LockAdmission {
        context: RbcDagContextV1,
        target: BlockReference,
    },
    LockReady {
        context: RbcDagContextV1,
        target: BlockReference,
    },
    LockDelivery {
        context: RbcDagContextV1,
        target: BlockReference,
    },
    LockConsensusSlot {
        context: RbcDagContextV1,
        consensus_round: RoundNumber,
        enclosing_carrier: BlockReference,
    },
    LockLeaderChoice {
        context: RbcDagContextV1,
        consensus_round: RoundNumber,
        choice: LeaderChoiceV1,
    },
    PersistOutboundContent {
        context: RbcDagContextV1,
        candidate: CandidateCarrierV1,
    },
    PersistOutboundSidecar {
        context: RbcDagContextV1,
        authenticated: LocallyAuthenticatedCarrierV1,
    },
    ExposeOutbound {
        context: RbcDagContextV1,
        reference: BlockReference,
    },
    ApplyPhaseStatement {
        context: RbcDagContextV1,
        outer: BlockReference,
        index: usize,
        sender: AuthorityIndex,
        statement: RbcPhaseStatementV1,
    },
    AdvancePhaseBatchCursor {
        context: RbcDagContextV1,
        outer: BlockReference,
        index: usize,
    },
}

impl JournalEventV1 {
    fn context(&self) -> RbcDagContextV1 {
        match self {
            Self::AuthenticatedIngress { context, .. }
            | Self::RetainCandidateContent { context, .. }
            | Self::FixOwnCarrier { context, .. }
            | Self::LockEcho { context, .. }
            | Self::LockAdmission { context, .. }
            | Self::LockReady { context, .. }
            | Self::LockDelivery { context, .. }
            | Self::LockConsensusSlot { context, .. }
            | Self::LockLeaderChoice { context, .. }
            | Self::PersistOutboundContent { context, .. }
            | Self::PersistOutboundSidecar { context, .. }
            | Self::ExposeOutbound { context, .. }
            | Self::ApplyPhaseStatement { context, .. }
            | Self::AdvancePhaseBatchCursor { context, .. } => *context,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PartialOutboundCarrierV1 {
    reference: BlockReference,
    candidate: CandidateCarrierV1,
    canonical_carrier_wire: Vec<u8>,
    authentication_sidecar: Option<Vec<u8>>,
    exposed: bool,
}

impl PartialOutboundCarrierV1 {
    fn new(candidate: CandidateCarrierV1, canonical_carrier_wire: Vec<u8>) -> Self {
        Self {
            reference: candidate.reference(),
            candidate,
            canonical_carrier_wire,
            authentication_sidecar: None,
            exposed: false,
        }
    }

    fn complete(&self) -> Option<DurableOutboundCarrierV1> {
        Some(DurableOutboundCarrierV1 {
            reference: self.reference,
            canonical_carrier_wire: self.canonical_carrier_wire.clone(),
            authentication_sidecar: self.authentication_sidecar.clone()?,
            exposed: self.exposed,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetainedCarrierV1 {
    candidate: CandidateCarrierV1,
    canonical_carrier_wire: Vec<u8>,
}

/// State reconstructed exclusively from the durable event sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalSnapshotV1 {
    context: RbcDagContextV1,
    own_authority: AuthorityIndex,
    ingress: Vec<AuthenticatedIngressRecordV1>,
    retained_carriers: BTreeMap<BlockReference, RetainedCarrierV1>,
    own_carriers: BTreeMap<RoundNumber, BlockReference>,
    admission_locks: BTreeMap<RbcSlotKeyV1, BlockReference>,
    echo_locks: BTreeMap<RbcSlotKeyV1, BlockReference>,
    ready_locks: BTreeMap<RbcSlotKeyV1, BlockReference>,
    delivery_locks: BTreeMap<RbcSlotKeyV1, BlockReference>,
    consensus_slots: BTreeMap<RoundNumber, BlockReference>,
    leader_choices: BTreeMap<RoundNumber, LeaderChoiceV1>,
    outbound: BTreeMap<BlockReference, PartialOutboundCarrierV1>,
    applied_phase_entries: BTreeMap<(BlockReference, usize), AppliedPhaseEntryV1>,
    sender_phase_locks: BTreeMap<SenderPhaseKeyV1, BlockReference>,
    phase_batch_cursors: BTreeMap<BlockReference, usize>,
}

impl JournalSnapshotV1 {
    fn new(context: RbcDagContextV1, own_authority: AuthorityIndex) -> Self {
        Self {
            context,
            own_authority,
            ingress: Vec::new(),
            retained_carriers: BTreeMap::new(),
            own_carriers: BTreeMap::new(),
            admission_locks: BTreeMap::new(),
            echo_locks: BTreeMap::new(),
            ready_locks: BTreeMap::new(),
            delivery_locks: BTreeMap::new(),
            consensus_slots: BTreeMap::new(),
            leader_choices: BTreeMap::new(),
            outbound: BTreeMap::new(),
            applied_phase_entries: BTreeMap::new(),
            sender_phase_locks: BTreeMap::new(),
            phase_batch_cursors: BTreeMap::new(),
        }
    }

    pub fn context(&self) -> RbcDagContextV1 {
        self.context
    }

    pub fn own_authority(&self) -> AuthorityIndex {
        self.own_authority
    }

    pub fn authenticated_ingress(&self) -> &[AuthenticatedIngressRecordV1] {
        &self.ingress
    }

    pub fn next_ingress_sequence(&self) -> u64 {
        self.ingress.len() as u64
    }

    pub fn retained_carrier(&self, reference: BlockReference) -> Option<&[u8]> {
        self.retained_carriers
            .get(&reference)
            .map(|retained| retained.canonical_carrier_wire.as_slice())
    }

    pub fn own_carrier(&self, round: RoundNumber) -> Option<BlockReference> {
        self.own_carriers.get(&round).copied()
    }

    pub fn admission_lock(&self, slot: RbcSlotKeyV1) -> Option<BlockReference> {
        self.admission_locks.get(&slot).copied()
    }

    pub fn echo_lock(&self, slot: RbcSlotKeyV1) -> Option<BlockReference> {
        self.echo_locks.get(&slot).copied()
    }

    pub fn ready_lock(&self, slot: RbcSlotKeyV1) -> Option<BlockReference> {
        self.ready_locks.get(&slot).copied()
    }

    pub fn delivery_lock(&self, slot: RbcSlotKeyV1) -> Option<BlockReference> {
        self.delivery_locks.get(&slot).copied()
    }

    pub fn consensus_slot(&self, round: RoundNumber) -> Option<BlockReference> {
        self.consensus_slots.get(&round).copied()
    }

    pub fn leader_choice(&self, round: RoundNumber) -> Option<LeaderChoiceV1> {
        self.leader_choices.get(&round).copied()
    }

    pub fn phase_batch_cursor(&self, outer: BlockReference) -> usize {
        self.phase_batch_cursors.get(&outer).copied().unwrap_or(0)
    }

    pub fn phase_statement_applied(&self, outer: BlockReference, index: usize) -> bool {
        self.applied_phase_entries.contains_key(&(outer, index))
    }

    pub fn phase_statement_outcome(
        &self,
        outer: BlockReference,
        index: usize,
    ) -> Option<AppliedPhaseOutcomeV1> {
        self.applied_phase_entries
            .get(&(outer, index))
            .map(|entry| entry.outcome)
    }

    pub fn outbound(&self, reference: BlockReference) -> Option<DurableOutboundCarrierV1> {
        self.outbound
            .get(&reference)
            .and_then(PartialOutboundCarrierV1::complete)
    }

    /// Byte-identical records that a restart must retransmit.
    pub fn retransmissions(&self) -> Vec<DurableOutboundCarrierV1> {
        self.outbound
            .values()
            .filter_map(PartialOutboundCarrierV1::complete)
            .filter(DurableOutboundCarrierV1::exposed)
            .collect()
    }

    fn apply(&mut self, event: &JournalEventV1) -> Result<(), JournalErrorV1> {
        if event.context() != self.context {
            return Err(JournalErrorV1::ContextMismatch);
        }

        match event {
            JournalEventV1::AuthenticatedIngress {
                sequence,
                authenticated,
                provenance,
                ..
            } => self.apply_ingress(*sequence, authenticated, *provenance),
            JournalEventV1::RetainCandidateContent { candidate, .. } => {
                self.retain_carrier_content(candidate).map(|_| ())
            }
            JournalEventV1::FixOwnCarrier { reference, .. } => self.fix_own_carrier(*reference),
            JournalEventV1::LockAdmission { target, .. } => self.lock_admission(*target),
            JournalEventV1::LockEcho { target, .. } => self.lock_echo(*target),
            JournalEventV1::LockReady { target, .. } => self.lock_ready(*target),
            JournalEventV1::LockDelivery { target, .. } => {
                self.ensure_retained(*target)?;
                if self.ready_lock(RbcSlotKeyV1::of(*target)) != Some(*target) {
                    return Err(JournalErrorV1::DeliveryWithoutMatchingReady(*target));
                }
                Self::lock_candidate(&mut self.delivery_locks, *target, LockKindV1::Delivery)
            }
            JournalEventV1::LockConsensusSlot {
                consensus_round,
                enclosing_carrier,
                ..
            } => self.lock_consensus_slot(*consensus_round, *enclosing_carrier),
            JournalEventV1::LockLeaderChoice {
                consensus_round,
                choice,
                ..
            } => self.lock_leader_choice(*consensus_round, *choice),
            JournalEventV1::PersistOutboundContent { candidate, .. } => {
                self.persist_outbound_content(candidate)
            }
            JournalEventV1::PersistOutboundSidecar { authenticated, .. } => {
                self.persist_outbound_sidecar(authenticated)
            }
            JournalEventV1::ExposeOutbound { reference, .. } => self.expose_outbound(*reference),
            JournalEventV1::ApplyPhaseStatement {
                outer,
                index,
                sender,
                statement,
                ..
            } => self.apply_phase_statement(*outer, *index, *sender, *statement),
            JournalEventV1::AdvancePhaseBatchCursor { outer, index, .. } => {
                self.advance_phase_cursor(*outer, *index)
            }
        }
    }

    fn apply_ingress(
        &mut self,
        sequence: u64,
        authenticated: &AuthenticatedCarrierV1,
        provenance: IngressProvenanceV1,
    ) -> Result<(), JournalErrorV1> {
        let expected = self.next_ingress_sequence();
        if sequence != expected {
            return Err(JournalErrorV1::IngressSequence {
                expected,
                actual: sequence,
            });
        }
        if authenticated.context() != self.context {
            return Err(JournalErrorV1::AuthenticatedIngressContextMismatch);
        }
        if authenticated.receiver() != self.own_authority {
            return Err(JournalErrorV1::AuthenticatedIngressReceiverMismatch {
                expected: self.own_authority,
                actual: authenticated.receiver(),
            });
        }
        let reference = authenticated.reference();
        let canonical_carrier_wire = self.retain_carrier_content(authenticated.candidate())?;
        let authentication_sidecar = authenticated.authentication().canonical_wire_bytes();
        self.ingress.push(AuthenticatedIngressRecordV1 {
            sequence,
            reference,
            provenance,
            canonical_carrier_wire,
            authentication_sidecar,
        });
        Ok(())
    }

    fn fix_own_carrier(&mut self, reference: BlockReference) -> Result<(), JournalErrorV1> {
        if reference.authority != self.own_authority {
            return Err(JournalErrorV1::OwnCarrierAuthorMismatch {
                expected: self.own_authority,
                actual: reference.authority,
            });
        }
        if reference.round == 0 {
            return Err(JournalErrorV1::EncodedGenesisCarrier);
        }
        if !self.outbound.contains_key(&reference) {
            return Err(JournalErrorV1::OutboundContentNotPersisted(reference));
        }
        Self::lock_exact(
            &mut self.own_carriers,
            reference.round,
            reference,
            JournalErrorV1::ConflictingOwnCarrier(reference.round),
        )
    }

    fn lock_echo(&mut self, target: BlockReference) -> Result<(), JournalErrorV1> {
        self.ensure_retained(target)?;
        let admitted = self.admission_lock(RbcSlotKeyV1::of(target)) == Some(target);
        let fixed_locally = self.own_carrier(target.round) == Some(target);
        if !admitted && !fixed_locally {
            return Err(JournalErrorV1::EchoWithoutAdmission(target));
        }
        Self::lock_candidate(&mut self.echo_locks, target, LockKindV1::Echo)
    }

    fn lock_admission(&mut self, target: BlockReference) -> Result<(), JournalErrorV1> {
        let authenticated_ingress = self
            .ingress
            .iter()
            .any(|ingress| ingress.reference == target);
        if !authenticated_ingress {
            return Err(JournalErrorV1::AdmissionWithoutAuthenticatedIngress(target));
        }
        Self::lock_candidate(&mut self.admission_locks, target, LockKindV1::Admission)
    }

    fn lock_ready(&mut self, target: BlockReference) -> Result<(), JournalErrorV1> {
        self.ensure_retained(target)?;
        Self::lock_candidate(&mut self.ready_locks, target, LockKindV1::Ready)
    }

    fn ensure_retained(&self, reference: BlockReference) -> Result<(), JournalErrorV1> {
        if self.retained_carriers.contains_key(&reference) {
            Ok(())
        } else {
            Err(JournalErrorV1::CarrierContentNotRetained(reference))
        }
    }

    fn retain_carrier_content(
        &mut self,
        candidate: &CandidateCarrierV1,
    ) -> Result<Vec<u8>, JournalErrorV1> {
        if candidate.committee_id() != self.context.committee_id() {
            return Err(JournalErrorV1::CandidateCommitteeMismatch);
        }
        let reference = candidate.reference();
        let canonical_carrier_wire = candidate
            .canonical_wire_bytes()
            .map_err(|_| JournalErrorV1::CanonicalCarrierEncoding(reference))?;
        match self.retained_carriers.get(&reference) {
            Some(existing)
                if existing.candidate != *candidate
                    || existing.canonical_carrier_wire != canonical_carrier_wire =>
            {
                Err(JournalErrorV1::ConflictingRetainedContent(reference))
            }
            Some(existing) => Ok(existing.canonical_carrier_wire.clone()),
            None => {
                self.retained_carriers.insert(
                    reference,
                    RetainedCarrierV1 {
                        candidate: candidate.clone(),
                        canonical_carrier_wire: canonical_carrier_wire.clone(),
                    },
                );
                Ok(canonical_carrier_wire)
            }
        }
    }

    fn lock_candidate(
        locks: &mut BTreeMap<RbcSlotKeyV1, BlockReference>,
        target: BlockReference,
        kind: LockKindV1,
    ) -> Result<(), JournalErrorV1> {
        let slot = RbcSlotKeyV1::of(target);
        Self::lock_exact(
            locks,
            slot,
            target,
            JournalErrorV1::ConflictingPhaseLock { kind, slot },
        )
    }

    fn lock_consensus_slot(
        &mut self,
        consensus_round: RoundNumber,
        enclosing_carrier: BlockReference,
    ) -> Result<(), JournalErrorV1> {
        if consensus_round == 0 {
            return Err(JournalErrorV1::EncodedGenesisConsensusVertex);
        }
        if enclosing_carrier.authority != self.own_authority
            || !self
                .own_carriers
                .values()
                .any(|reference| *reference == enclosing_carrier)
        {
            return Err(JournalErrorV1::ConsensusCarrierNotFixed(enclosing_carrier));
        }
        let matching_vertex = self
            .outbound
            .get(&enclosing_carrier)
            .and_then(|outbound| outbound.candidate.header().consensus_vertex())
            .is_some_and(|vertex| vertex.consensus_round() == consensus_round);
        if !matching_vertex {
            return Err(JournalErrorV1::ConsensusVertexMismatch {
                consensus_round,
                enclosing_carrier,
            });
        }
        Self::lock_exact(
            &mut self.consensus_slots,
            consensus_round,
            enclosing_carrier,
            JournalErrorV1::ConflictingConsensusSlot(consensus_round),
        )
    }

    fn lock_leader_choice(
        &mut self,
        consensus_round: RoundNumber,
        choice: LeaderChoiceV1,
    ) -> Result<(), JournalErrorV1> {
        let Some(enclosing_carrier) = self.consensus_slot(consensus_round) else {
            return Err(JournalErrorV1::LeaderChoiceWithoutConsensusSlot(
                consensus_round,
            ));
        };
        let matching_choice = self
            .outbound
            .get(&enclosing_carrier)
            .and_then(|outbound| outbound.candidate.header().consensus_vertex())
            .is_some_and(|vertex| {
                vertex.consensus_round() == consensus_round && vertex.leader_choice() == choice
            });
        if !matching_choice {
            return Err(JournalErrorV1::LeaderChoiceCandidateMismatch(
                consensus_round,
            ));
        }
        Self::lock_exact(
            &mut self.leader_choices,
            consensus_round,
            choice,
            JournalErrorV1::ConflictingLeaderChoice(consensus_round),
        )
    }

    fn persist_outbound_content(
        &mut self,
        candidate: &CandidateCarrierV1,
    ) -> Result<(), JournalErrorV1> {
        let reference = candidate.reference();
        if reference.authority != self.own_authority {
            return Err(JournalErrorV1::OwnCarrierAuthorMismatch {
                expected: self.own_authority,
                actual: reference.authority,
            });
        }
        if reference.round == 0 {
            return Err(JournalErrorV1::EncodedGenesisCarrier);
        }
        if self
            .own_carrier(reference.round)
            .is_some_and(|fixed| fixed != reference)
        {
            return Err(JournalErrorV1::ConflictingOwnCarrier(reference.round));
        }
        let canonical_carrier_wire = self.retain_carrier_content(candidate)?;
        match self.outbound.get(&reference) {
            Some(existing)
                if existing.candidate != *candidate
                    || existing.canonical_carrier_wire != canonical_carrier_wire =>
            {
                Err(JournalErrorV1::ConflictingOutboundContent(reference))
            }
            Some(_) => Ok(()),
            None => {
                self.outbound.insert(
                    reference,
                    PartialOutboundCarrierV1::new(candidate.clone(), canonical_carrier_wire),
                );
                Ok(())
            }
        }
    }

    fn persist_outbound_sidecar(
        &mut self,
        authenticated: &LocallyAuthenticatedCarrierV1,
    ) -> Result<(), JournalErrorV1> {
        if authenticated.context() != self.context {
            return Err(JournalErrorV1::OutboundAuthenticationContextMismatch);
        }
        let reference = authenticated.reference();
        if reference.authority != self.own_authority {
            return Err(JournalErrorV1::OwnCarrierAuthorMismatch {
                expected: self.own_authority,
                actual: reference.authority,
            });
        }
        if self.own_carrier(reference.round) != Some(reference) {
            return Err(JournalErrorV1::OwnCarrierNotFixed(reference));
        }
        let Some(outbound) = self.outbound.get_mut(&reference) else {
            return Err(JournalErrorV1::OutboundContentNotPersisted(reference));
        };
        if outbound.candidate != *authenticated.candidate() {
            return Err(JournalErrorV1::OutboundAuthenticationCandidateMismatch(
                reference,
            ));
        }
        let authentication_sidecar = authenticated.authentication().canonical_wire_bytes();
        match &outbound.authentication_sidecar {
            Some(existing) if *existing != authentication_sidecar => {
                Err(JournalErrorV1::ConflictingOutboundSidecar(reference))
            }
            Some(_) => Ok(()),
            None => {
                outbound.authentication_sidecar = Some(authentication_sidecar);
                Ok(())
            }
        }
    }

    fn expose_outbound(&mut self, reference: BlockReference) -> Result<(), JournalErrorV1> {
        if self.own_carrier(reference.round) != Some(reference) {
            return Err(JournalErrorV1::OwnCarrierNotFixed(reference));
        }
        let Some(outbound) = self.outbound.get(&reference) else {
            return Err(JournalErrorV1::OutboundContentNotPersisted(reference));
        };
        if outbound.authentication_sidecar.is_none() {
            return Err(JournalErrorV1::OutboundSidecarNotPersisted(reference));
        }
        let candidate = outbound.candidate.clone();
        if self.echo_lock(RbcSlotKeyV1::of(reference)) != Some(reference) {
            return Err(JournalErrorV1::OutboundEchoNotLocked(reference));
        }
        for statement in candidate.header().phase_batch() {
            let target = statement.target();
            let lock = match statement {
                RbcPhaseStatementV1::Echo { .. } => self.echo_lock(RbcSlotKeyV1::of(target)),
                RbcPhaseStatementV1::Ready { .. } => self.ready_lock(RbcSlotKeyV1::of(target)),
            };
            if lock != Some(target) {
                return Err(JournalErrorV1::OutboundPhaseNotLocked(*statement));
            }
        }
        if let Some(vertex) = candidate.header().consensus_vertex() {
            let consensus_round = vertex.consensus_round();
            if self.consensus_slot(consensus_round) != Some(reference) {
                return Err(JournalErrorV1::OutboundConsensusSlotNotLocked {
                    consensus_round,
                    reference,
                });
            }
            if self.leader_choice(consensus_round) != Some(vertex.leader_choice()) {
                return Err(JournalErrorV1::OutboundLeaderChoiceNotLocked(
                    consensus_round,
                ));
            }
        }
        self.outbound
            .get_mut(&reference)
            .expect("outbound remains retained")
            .exposed = true;
        Ok(())
    }

    fn apply_phase_statement(
        &mut self,
        outer: BlockReference,
        index: usize,
        sender: AuthorityIndex,
        statement: RbcPhaseStatementV1,
    ) -> Result<(), JournalErrorV1> {
        if sender != outer.authority {
            return Err(JournalErrorV1::PhaseSenderMismatch {
                outer_author: outer.authority,
                sender,
            });
        }
        let target = statement.target();
        if target.round >= outer.round {
            return Err(JournalErrorV1::PhaseTargetNotOlder { outer, target });
        }
        let Some(retained_outer) = self.retained_carriers.get(&outer) else {
            return Err(JournalErrorV1::OuterCarrierContentNotRetained(outer));
        };
        if retained_outer
            .candidate
            .header()
            .phase_batch()
            .get(index)
            .copied()
            != Some(statement)
        {
            return Err(JournalErrorV1::PhaseBatchEntryMismatch { outer, index });
        }
        let outer_slot = RbcSlotKeyV1::of(outer);
        let authorized = self.own_carrier(outer.round) == Some(outer)
            || self.admission_lock(outer_slot) == Some(outer)
            || self.delivery_lock(outer_slot) == Some(outer);
        if !authorized {
            return Err(JournalErrorV1::OuterCarrierNotAdmittedOrDelivered(outer));
        }

        let cursor = self.phase_batch_cursor(outer);
        if index > cursor {
            return Err(JournalErrorV1::PhaseBatchIndexGap {
                outer,
                expected: cursor,
                actual: index,
            });
        }
        if let Some(existing) = self.applied_phase_entries.get(&(outer, index)) {
            return if existing.sender == sender && existing.statement == statement {
                Ok(())
            } else {
                Err(JournalErrorV1::ConflictingPhaseBatchEntry { outer, index })
            };
        }
        if index < cursor {
            return Err(JournalErrorV1::MissingAppliedPhaseEntry { outer, index });
        }

        if sender == self.own_authority {
            if self.own_carrier(outer.round) != Some(outer) {
                return Err(JournalErrorV1::OwnOuterCarrierNotFixed(outer));
            }
            let lock = match statement {
                RbcPhaseStatementV1::Echo { .. } => self.echo_lock(RbcSlotKeyV1::of(target)),
                RbcPhaseStatementV1::Ready { .. } => self.ready_lock(RbcSlotKeyV1::of(target)),
            };
            if lock != Some(target) {
                return Err(JournalErrorV1::OwnPhaseWithoutDurableLock(statement));
            }
        }

        let sender_key = SenderPhaseKeyV1 {
            slot: RbcSlotKeyV1::of(target),
            sender,
            phase: PhaseKindV1::of(statement),
        };
        let outcome = match self.sender_phase_locks.get(&sender_key) {
            Some(existing) if *existing != target => AppliedPhaseOutcomeV1::IgnoredEquivocation,
            Some(_) => AppliedPhaseOutcomeV1::IgnoredReplay,
            None => {
                self.sender_phase_locks.insert(sender_key, target);
                AppliedPhaseOutcomeV1::Counted
            }
        };
        self.applied_phase_entries.insert(
            (outer, index),
            AppliedPhaseEntryV1 {
                sender,
                statement,
                outcome,
            },
        );
        Ok(())
    }

    fn advance_phase_cursor(
        &mut self,
        outer: BlockReference,
        index: usize,
    ) -> Result<(), JournalErrorV1> {
        let cursor = self.phase_batch_cursor(outer);
        if index < cursor {
            return if self.applied_phase_entries.contains_key(&(outer, index)) {
                Ok(())
            } else {
                Err(JournalErrorV1::MissingAppliedPhaseEntry { outer, index })
            };
        }
        if index > cursor {
            return Err(JournalErrorV1::PhaseBatchIndexGap {
                outer,
                expected: cursor,
                actual: index,
            });
        }
        if !self.applied_phase_entries.contains_key(&(outer, index)) {
            return Err(JournalErrorV1::PhaseCursorBeforeApplication { outer, index });
        }
        self.phase_batch_cursors.insert(outer, cursor + 1);
        Ok(())
    }

    fn lock_exact<K, V>(
        map: &mut BTreeMap<K, V>,
        key: K,
        value: V,
        conflict: JournalErrorV1,
    ) -> Result<(), JournalErrorV1>
    where
        K: Ord,
        V: Eq,
    {
        match map.get(&key) {
            Some(existing) if *existing != value => Err(conflict),
            Some(_) => Ok(()),
            None => {
                map.insert(key, value);
                Ok(())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockKindV1 {
    Admission,
    Echo,
    Ready,
    Delivery,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalErrorV1 {
    ContextMismatch,
    IngressSequence {
        expected: u64,
        actual: u64,
    },
    AuthenticatedIngressContextMismatch,
    AuthenticatedIngressReceiverMismatch {
        expected: AuthorityIndex,
        actual: AuthorityIndex,
    },
    CandidateCommitteeMismatch,
    CanonicalCarrierEncoding(BlockReference),
    CarrierContentNotRetained(BlockReference),
    ConflictingRetainedContent(BlockReference),
    AdmissionWithoutAuthenticatedIngress(BlockReference),
    EchoWithoutAdmission(BlockReference),
    OwnCarrierAuthorMismatch {
        expected: AuthorityIndex,
        actual: AuthorityIndex,
    },
    EncodedGenesisCarrier,
    ConflictingOwnCarrier(RoundNumber),
    ConflictingPhaseLock {
        kind: LockKindV1,
        slot: RbcSlotKeyV1,
    },
    DeliveryWithoutMatchingReady(BlockReference),
    EncodedGenesisConsensusVertex,
    ConsensusCarrierNotFixed(BlockReference),
    ConsensusVertexMismatch {
        consensus_round: RoundNumber,
        enclosing_carrier: BlockReference,
    },
    ConflictingConsensusSlot(RoundNumber),
    LeaderChoiceWithoutConsensusSlot(RoundNumber),
    LeaderChoiceCandidateMismatch(RoundNumber),
    ConflictingLeaderChoice(RoundNumber),
    OwnCarrierNotFixed(BlockReference),
    ConflictingOutboundContent(BlockReference),
    OutboundContentNotPersisted(BlockReference),
    ConflictingOutboundSidecar(BlockReference),
    OutboundSidecarNotPersisted(BlockReference),
    OutboundAuthenticationContextMismatch,
    OutboundAuthenticationCandidateMismatch(BlockReference),
    OutboundEchoNotLocked(BlockReference),
    OutboundPhaseNotLocked(RbcPhaseStatementV1),
    OutboundConsensusSlotNotLocked {
        consensus_round: RoundNumber,
        reference: BlockReference,
    },
    OutboundLeaderChoiceNotLocked(RoundNumber),
    PhaseSenderMismatch {
        outer_author: AuthorityIndex,
        sender: AuthorityIndex,
    },
    PhaseTargetNotOlder {
        outer: BlockReference,
        target: BlockReference,
    },
    OuterCarrierContentNotRetained(BlockReference),
    OuterCarrierNotAdmittedOrDelivered(BlockReference),
    OwnOuterCarrierNotFixed(BlockReference),
    PhaseBatchEntryMismatch {
        outer: BlockReference,
        index: usize,
    },
    PhaseBatchIndexGap {
        outer: BlockReference,
        expected: usize,
        actual: usize,
    },
    ConflictingPhaseBatchEntry {
        outer: BlockReference,
        index: usize,
    },
    MissingAppliedPhaseEntry {
        outer: BlockReference,
        index: usize,
    },
    OwnPhaseWithoutDurableLock(RbcPhaseStatementV1),
    PhaseCursorBeforeApplication {
        outer: BlockReference,
        index: usize,
    },
}

impl fmt::Display for JournalErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Starfish-RBC-DAG journal error: {self:?}")
    }
}

impl Error for JournalErrorV1 {}

/// A deterministic write-ahead journal with a volatile replayed snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteAheadJournalV1 {
    context: RbcDagContextV1,
    own_authority: AuthorityIndex,
    durable_events: Vec<JournalEventV1>,
    snapshot: JournalSnapshotV1,
}

impl WriteAheadJournalV1 {
    pub fn new(context: RbcDagContextV1, own_authority: AuthorityIndex) -> Self {
        Self {
            context,
            own_authority,
            durable_events: Vec::new(),
            snapshot: JournalSnapshotV1::new(context, own_authority),
        }
    }

    /// Validate against a cloned snapshot, then atomically make the event
    /// durable and visible. A real backend maps this boundary to its durable
    /// transaction commit.
    pub fn append(&mut self, event: JournalEventV1) -> Result<(), JournalErrorV1> {
        let mut next = self.snapshot.clone();
        next.apply(&event)?;
        self.durable_events.push(event);
        self.snapshot = next;
        Ok(())
    }

    pub fn record_authenticated_ingress(
        &mut self,
        authenticated: AuthenticatedCarrierV1,
        provenance: IngressProvenanceV1,
    ) -> Result<u64, JournalErrorV1> {
        let sequence = self.snapshot.next_ingress_sequence();
        self.append(JournalEventV1::AuthenticatedIngress {
            context: self.context,
            sequence,
            authenticated,
            provenance,
        })?;
        Ok(sequence)
    }

    pub fn durable_events(&self) -> &[JournalEventV1] {
        &self.durable_events
    }

    pub fn snapshot(&self) -> &JournalSnapshotV1 {
        &self.snapshot
    }

    /// Rebuild volatile state in exact durable order.
    pub fn restart(&self) -> Result<Self, JournalErrorV1> {
        Self::from_durable_events(
            self.context,
            self.own_authority,
            self.durable_events.clone(),
        )
    }

    pub fn from_durable_events(
        context: RbcDagContextV1,
        own_authority: AuthorityIndex,
        durable_events: Vec<JournalEventV1>,
    ) -> Result<Self, JournalErrorV1> {
        let mut snapshot = JournalSnapshotV1::new(context, own_authority);
        for event in &durable_events {
            snapshot.apply(event)?;
        }
        Ok(Self {
            context,
            own_authority,
            durable_events,
            snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        committee::Committee,
        crypto::{TransactionsCommitment, mac_keyrings_for_test},
        starfish_rbc_dag::{
            CarrierAuthenticationV1, CarrierAuthorizerV1, CarrierHeaderV1Args,
            ConsensusVertexReference, ConsensusVertexV1, RbcDagProtocolInstanceId,
            carrier_genesis_reference,
        },
        types::{BlockAuthenticationScheme, BlockDigest},
    };

    fn committee() -> std::sync::Arc<Committee> {
        Committee::new_test(vec![1; 4])
    }

    fn context(marker: u8) -> RbcDagContextV1 {
        let committee = committee();
        RbcDagContextV1::new(
            RbcDagProtocolInstanceId::new([marker; 32]).unwrap(),
            &committee,
            BlockAuthenticationScheme::MacVector,
        )
        .unwrap()
    }

    fn reference(authority: AuthorityIndex, round: RoundNumber, marker: u8) -> BlockReference {
        BlockReference {
            authority,
            round,
            digest: BlockDigest::from([marker; 32]),
        }
    }

    fn journal() -> WriteAheadJournalV1 {
        WriteAheadJournalV1::new(context(0xA1), 1)
    }

    fn fix_event(journal: &WriteAheadJournalV1, reference: BlockReference) -> JournalEventV1 {
        JournalEventV1::FixOwnCarrier {
            context: journal.context,
            reference,
        }
    }

    fn candidate(
        author: AuthorityIndex,
        round: RoundNumber,
        marker: u8,
        phase_batch: Vec<RbcPhaseStatementV1>,
        consensus_vertex: Option<ConsensusVertexV1>,
    ) -> CandidateCarrierV1 {
        let committee = committee();
        let previous_round = round - 1;
        let parent = |authority| {
            if previous_round == 0 {
                carrier_genesis_reference(authority)
            } else {
                reference(authority, previous_round, 0x40 + authority as u8)
            }
        };
        let mut parent_stake = committee.get_stake(author).unwrap();
        let mut weak_parents = Vec::new();
        for authority in committee
            .authorities()
            .filter(|authority| *authority != author)
        {
            if parent_stake >= committee.quorum_threshold() {
                break;
            }
            parent_stake += committee.get_stake(authority).unwrap();
            weak_parents.push(parent(authority));
        }
        CandidateCarrierV1::try_new(
            CarrierHeaderV1Args {
                author,
                carrier_round: round,
                own_prev: parent(author),
                weak_parents,
                transactions_commitment: TransactionsCommitment::from_bytes([marker; 32]),
                data_acknowledgments: Vec::new(),
                phase_batch,
                consensus_vertex,
                creation_time_ns: u64::from(marker),
            },
            &committee,
        )
        .unwrap()
    }

    fn consensus_vertex(
        enclosing_author: AuthorityIndex,
        consensus_round: RoundNumber,
    ) -> ConsensusVertexV1 {
        let committee = committee();
        let parent_round = consensus_round - 1;
        let parent = |authority| {
            let carrier = if parent_round == 0 {
                carrier_genesis_reference(authority)
            } else {
                reference(authority, parent_round, 0xD0 + authority as u8)
            };
            ConsensusVertexReference::new(carrier, parent_round)
        };
        let strong_parents: Vec<_> = committee.authorities().map(parent).collect();
        assert!(
            strong_parents
                .iter()
                .any(|parent| parent.author() == enclosing_author)
        );
        let leader = parent(committee.elect_leader(parent_round));
        ConsensusVertexV1::new(
            consensus_round,
            strong_parents,
            vec![None; committee.len()],
            LeaderChoiceV1::Vote { leader },
        )
    }

    fn outbound_content_event(
        journal: &WriteAheadJournalV1,
        candidate: &CandidateCarrierV1,
    ) -> JournalEventV1 {
        JournalEventV1::PersistOutboundContent {
            context: journal.context,
            candidate: candidate.clone(),
        }
    }

    fn persist_and_fix(journal: &mut WriteAheadJournalV1, candidate: &CandidateCarrierV1) {
        journal
            .append(outbound_content_event(journal, candidate))
            .unwrap();
        journal
            .append(fix_event(journal, candidate.reference()))
            .unwrap();
    }

    fn retain_candidate(journal: &mut WriteAheadJournalV1, candidate: &CandidateCarrierV1) {
        journal
            .append(JournalEventV1::RetainCandidateContent {
                context: journal.context,
                candidate: candidate.clone(),
            })
            .unwrap();
    }

    fn authentication_with_marker(
        candidate: &CandidateCarrierV1,
        context_marker: u8,
    ) -> CarrierAuthenticationV1 {
        let committee = committee();
        let context = context(context_marker);
        let keyrings = mac_keyrings_for_test(committee.len());
        let author = candidate.header().author() as usize;
        context
            .authenticate(
                candidate,
                &committee,
                CarrierAuthorizerV1::MacVector {
                    authority: author as AuthorityIndex,
                    keys: &keyrings[author],
                },
            )
            .unwrap()
    }

    fn locally_authenticated_with_marker(
        candidate: &CandidateCarrierV1,
        context_marker: u8,
    ) -> LocallyAuthenticatedCarrierV1 {
        let committee = committee();
        let context = context(context_marker);
        let keyrings = mac_keyrings_for_test(committee.len());
        let author = candidate.header().author() as usize;
        context
            .authenticate_local(
                candidate.clone(),
                &committee,
                CarrierAuthorizerV1::MacVector {
                    authority: author as AuthorityIndex,
                    keys: &keyrings[author],
                },
            )
            .unwrap()
    }

    fn locally_authenticated(candidate: &CandidateCarrierV1) -> LocallyAuthenticatedCarrierV1 {
        locally_authenticated_with_marker(candidate, 0xA1)
    }

    fn authenticated_with_marker(
        candidate: &CandidateCarrierV1,
        receiver: AuthorityIndex,
        context_marker: u8,
    ) -> AuthenticatedCarrierV1 {
        let committee = committee();
        let context = context(context_marker);
        let keyrings = mac_keyrings_for_test(committee.len());
        context
            .verify_authentication(
                candidate.clone(),
                authentication_with_marker(candidate, context_marker),
                receiver,
                &committee,
                &keyrings[receiver as usize],
            )
            .unwrap()
    }

    fn authenticated(
        candidate: &CandidateCarrierV1,
        receiver: AuthorityIndex,
    ) -> AuthenticatedCarrierV1 {
        authenticated_with_marker(candidate, receiver, 0xA1)
    }

    fn authenticate_candidate(journal: &mut WriteAheadJournalV1, candidate: &CandidateCarrierV1) {
        journal
            .record_authenticated_ingress(
                authenticated(candidate, journal.own_authority),
                IngressProvenanceV1::DirectFromAuthor,
            )
            .unwrap();
    }

    fn admit_candidate(journal: &mut WriteAheadJournalV1, candidate: &CandidateCarrierV1) {
        authenticate_candidate(journal, candidate);
        journal
            .append(JournalEventV1::LockAdmission {
                context: journal.context,
                target: candidate.reference(),
            })
            .unwrap();
    }

    fn prepare_outbound_for_exposure(
        journal: &mut WriteAheadJournalV1,
        candidate: &CandidateCarrierV1,
    ) {
        let reference = candidate.reference();
        persist_and_fix(journal, candidate);
        journal
            .append(JournalEventV1::LockEcho {
                context: journal.context,
                target: reference,
            })
            .unwrap();
        journal
            .append(JournalEventV1::PersistOutboundSidecar {
                context: journal.context,
                authenticated: locally_authenticated(candidate),
            })
            .unwrap();
    }

    fn assert_before_after<F>(journal: &WriteAheadJournalV1, event: JournalEventV1, assertion: F)
    where
        F: Fn(&JournalSnapshotV1) -> bool,
    {
        let before = journal.restart().unwrap();
        assert!(!assertion(before.snapshot()));

        let mut after = journal.clone();
        after.append(event).unwrap();
        let after = after.restart().unwrap();
        assert!(assertion(after.snapshot()));
    }

    #[test]
    fn authenticated_ingress_sequence_and_bytes_survive_restart_in_order() {
        let mut journal = journal();
        let first_candidate = candidate(0, 1, 0x10, Vec::new(), None);
        let second_candidate = candidate(2, 1, 0x20, Vec::new(), None);
        let first = first_candidate.reference();
        let second = second_candidate.reference();
        let first_authenticated = authenticated(&first_candidate, 1);
        let second_authenticated = authenticated(&second_candidate, 1);
        let first_wire = first_candidate.canonical_wire_bytes().unwrap();
        let second_sidecar = second_authenticated.authentication().canonical_wire_bytes();
        assert_eq!(
            journal
                .record_authenticated_ingress(
                    first_authenticated,
                    IngressProvenanceV1::DirectFromAuthor,
                )
                .unwrap(),
            0
        );
        assert_eq!(
            journal
                .record_authenticated_ingress(
                    second_authenticated,
                    IngressProvenanceV1::Relayed { peer: 3 },
                )
                .unwrap(),
            1
        );

        let restarted = journal.restart().unwrap().restart().unwrap();
        let ingress = restarted.snapshot().authenticated_ingress();
        assert_eq!(
            ingress
                .iter()
                .map(|entry| entry.sequence())
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(ingress[0].reference(), first);
        assert_eq!(ingress[1].reference(), second);
        assert_eq!(ingress[0].canonical_carrier_wire(), first_wire);
        assert_eq!(ingress[1].authentication_sidecar(), second_sidecar);

        let mut corrupt = journal.durable_events().to_vec();
        if let JournalEventV1::AuthenticatedIngress { sequence, .. } = &mut corrupt[1] {
            *sequence = 2;
        }
        assert!(matches!(
            WriteAheadJournalV1::from_durable_events(context(0xA1), 1, corrupt),
            Err(JournalErrorV1::IngressSequence {
                expected: 1,
                actual: 2
            })
        ));
    }

    #[test]
    fn crash_boundaries_preserve_each_slot_global_lock() {
        let own_candidate = candidate(1, 1, 0x11, Vec::new(), None);
        let target_candidate = candidate(2, 1, 0x21, Vec::new(), None);
        let own = own_candidate.reference();
        let target = target_candidate.reference();
        let slot = RbcSlotKeyV1::of(target);
        let mut content_base = journal();
        content_base
            .append(outbound_content_event(&content_base, &own_candidate))
            .unwrap();
        assert_before_after(&content_base, fix_event(&content_base, own), |state| {
            state.own_carrier(1) == Some(own)
        });

        let mut base = content_base;
        base.append(fix_event(&base, own)).unwrap();
        authenticate_candidate(&mut base, &target_candidate);
        let admission = JournalEventV1::LockAdmission {
            context: base.context,
            target,
        };
        assert_before_after(&base, admission.clone(), |state| {
            state.admission_lock(slot) == Some(target)
        });
        base.append(admission).unwrap();

        let echo = JournalEventV1::LockEcho {
            context: base.context,
            target,
        };
        assert_before_after(&base, echo, |state| state.echo_lock(slot) == Some(target));

        let mut ready_base = base.clone();
        let ready = JournalEventV1::LockReady {
            context: base.context,
            target,
        };
        assert_before_after(&ready_base, ready.clone(), |state| {
            state.ready_lock(slot) == Some(target)
        });
        ready_base.append(ready).unwrap();

        let delivery = JournalEventV1::LockDelivery {
            context: base.context,
            target,
        };
        assert_before_after(&ready_base, delivery, |state| {
            state.delivery_lock(slot) == Some(target)
        });
    }

    #[test]
    fn crash_boundaries_preserve_consensus_and_leader_choice_locks() {
        let mut journal = journal();
        let vertex = consensus_vertex(1, 1);
        let expected_choice = vertex.leader_choice();
        let own_candidate = candidate(1, 2, 0x32, Vec::new(), Some(vertex));
        let own = own_candidate.reference();
        persist_and_fix(&mut journal, &own_candidate);
        let consensus = JournalEventV1::LockConsensusSlot {
            context: journal.context,
            consensus_round: 1,
            enclosing_carrier: own,
        };
        assert_before_after(&journal, consensus.clone(), |state| {
            state.consensus_slot(1) == Some(own)
        });

        journal.append(consensus).unwrap();
        let choice = JournalEventV1::LockLeaderChoice {
            context: journal.context,
            consensus_round: 1,
            choice: expected_choice,
        };
        assert_before_after(&journal, choice, |state| {
            state.leader_choice(1) == Some(expected_choice)
        });
    }

    #[test]
    fn outbound_content_sidecar_and_exposure_are_separate_crash_boundaries() {
        let mut journal = journal();
        let own_candidate = candidate(1, 1, 0x41, Vec::new(), None);
        let own = own_candidate.reference();
        let expected_wire = own_candidate.canonical_wire_bytes().unwrap();
        let own_authenticated = locally_authenticated(&own_candidate);
        let expected_sidecar = own_authenticated.authentication().canonical_wire_bytes();

        let content = JournalEventV1::PersistOutboundContent {
            context: journal.context,
            candidate: own_candidate,
        };
        assert_before_after(&journal, content.clone(), |state| {
            state.outbound.contains_key(&own)
        });
        assert!(journal.snapshot().retransmissions().is_empty());
        journal.append(content).unwrap();

        let fix = fix_event(&journal, own);
        assert_before_after(&journal, fix.clone(), |state| {
            state.own_carrier(1) == Some(own)
        });
        journal.append(fix).unwrap();
        journal
            .append(JournalEventV1::LockEcho {
                context: journal.context,
                target: own,
            })
            .unwrap();

        let sidecar = JournalEventV1::PersistOutboundSidecar {
            context: journal.context,
            authenticated: own_authenticated,
        };
        assert_before_after(&journal, sidecar.clone(), |state| {
            state.outbound(own).is_some()
        });
        journal.append(sidecar).unwrap();
        assert!(journal.snapshot().retransmissions().is_empty());

        let expose = JournalEventV1::ExposeOutbound {
            context: journal.context,
            reference: own,
        };
        assert_before_after(&journal, expose.clone(), |state| {
            state
                .outbound(own)
                .is_some_and(|outbound| outbound.exposed())
        });
        journal.append(expose).unwrap();

        let before = journal.snapshot().retransmissions();
        let after = journal.restart().unwrap().snapshot().retransmissions();
        assert_eq!(after, before);
        assert_eq!(after[0].canonical_carrier_wire(), expected_wire);
        assert_eq!(after[0].authentication_sidecar(), expected_sidecar);
    }

    #[test]
    fn outbound_cannot_be_exposed_before_both_exact_records_are_durable() {
        let mut journal = journal();
        let own_candidate = candidate(1, 1, 0x51, Vec::new(), None);
        let own = own_candidate.reference();
        let context = journal.context;
        let expose = || JournalEventV1::ExposeOutbound {
            context,
            reference: own,
        };
        assert_eq!(
            journal.append(expose()).unwrap_err(),
            JournalErrorV1::OwnCarrierNotFixed(own)
        );
        journal
            .append(JournalEventV1::PersistOutboundContent {
                context: journal.context,
                candidate: own_candidate,
            })
            .unwrap();
        journal.append(fix_event(&journal, own)).unwrap();
        journal
            .append(JournalEventV1::LockEcho {
                context: journal.context,
                target: own,
            })
            .unwrap();
        assert_eq!(
            journal.append(expose()).unwrap_err(),
            JournalErrorV1::OutboundSidecarNotPersisted(own)
        );
    }

    #[test]
    fn phase_application_is_durable_before_the_cursor_advances() {
        let mut journal = journal();
        let statement = RbcPhaseStatementV1::Echo {
            target: reference(0, 1, 0x60),
        };
        let outer_candidate = candidate(2, 3, 0x62, vec![statement], None);
        let outer = outer_candidate.reference();
        admit_candidate(&mut journal, &outer_candidate);
        let apply = JournalEventV1::ApplyPhaseStatement {
            context: journal.context,
            outer,
            index: 0,
            sender: 2,
            statement,
        };
        assert_before_after(&journal, apply.clone(), |state| {
            state.phase_statement_applied(outer, 0) && state.phase_batch_cursor(outer) == 0
        });
        journal.append(apply.clone()).unwrap();

        let advance = JournalEventV1::AdvancePhaseBatchCursor {
            context: journal.context,
            outer,
            index: 0,
        };
        assert_before_after(&journal, advance, |state| {
            state.phase_batch_cursor(outer) == 1
        });

        let restarted = journal.restart().unwrap();
        let mut retried = restarted.clone();
        retried.append(apply).unwrap();
        retried
            .append(JournalEventV1::AdvancePhaseBatchCursor {
                context: journal.context,
                outer,
                index: 0,
            })
            .unwrap();
        assert_eq!(retried.snapshot().phase_batch_cursor(outer), 1);
    }

    #[test]
    fn only_admitted_conflict_processes_until_the_other_is_delivered() {
        let mut journal = journal();
        let first_statement = RbcPhaseStatementV1::Echo {
            target: reference(0, 1, 0x63),
        };
        let second_statement = RbcPhaseStatementV1::Echo {
            target: reference(3, 1, 0x64),
        };
        let first_candidate = candidate(2, 2, 0x65, vec![first_statement], None);
        let second_candidate = candidate(2, 2, 0x66, vec![second_statement], None);
        let first = first_candidate.reference();
        let second = second_candidate.reference();
        authenticate_candidate(&mut journal, &first_candidate);
        authenticate_candidate(&mut journal, &second_candidate);
        journal
            .append(JournalEventV1::LockAdmission {
                context: journal.context,
                target: first,
            })
            .unwrap();
        assert!(matches!(
            journal.append(JournalEventV1::LockAdmission {
                context: journal.context,
                target: second,
            }),
            Err(JournalErrorV1::ConflictingPhaseLock {
                kind: LockKindV1::Admission,
                ..
            })
        ));
        journal
            .append(JournalEventV1::ApplyPhaseStatement {
                context: journal.context,
                outer: first,
                index: 0,
                sender: 2,
                statement: first_statement,
            })
            .unwrap();
        assert_eq!(
            journal
                .append(JournalEventV1::ApplyPhaseStatement {
                    context: journal.context,
                    outer: second,
                    index: 0,
                    sender: 2,
                    statement: second_statement,
                })
                .unwrap_err(),
            JournalErrorV1::OuterCarrierNotAdmittedOrDelivered(second)
        );

        journal
            .append(JournalEventV1::LockReady {
                context: journal.context,
                target: second,
            })
            .unwrap();
        journal
            .append(JournalEventV1::LockDelivery {
                context: journal.context,
                target: second,
            })
            .unwrap();
        journal
            .append(JournalEventV1::ApplyPhaseStatement {
                context: journal.context,
                outer: second,
                index: 0,
                sender: 2,
                statement: second_statement,
            })
            .unwrap();
        journal
            .append(JournalEventV1::AdvancePhaseBatchCursor {
                context: journal.context,
                outer: second,
                index: 0,
            })
            .unwrap();
        assert_eq!(journal.snapshot().phase_batch_cursor(second), 1);
    }

    #[test]
    fn cursor_cannot_skip_or_advance_before_idempotent_application() {
        let mut journal = journal();
        let statement = RbcPhaseStatementV1::Ready {
            target: reference(0, 1, 0x70),
        };
        let second_statement = RbcPhaseStatementV1::Ready {
            target: reference(3, 1, 0x71),
        };
        let outer_candidate = candidate(2, 3, 0x72, vec![statement, second_statement], None);
        let outer = outer_candidate.reference();
        admit_candidate(&mut journal, &outer_candidate);
        assert!(matches!(
            journal.append(JournalEventV1::AdvancePhaseBatchCursor {
                context: journal.context,
                outer,
                index: 0,
            }),
            Err(JournalErrorV1::PhaseCursorBeforeApplication { .. })
        ));
        assert!(matches!(
            journal.append(JournalEventV1::ApplyPhaseStatement {
                context: journal.context,
                outer,
                index: 1,
                sender: 2,
                statement: second_statement,
            }),
            Err(JournalErrorV1::PhaseBatchIndexGap {
                expected: 0,
                actual: 1,
                ..
            })
        ));
    }

    #[test]
    fn own_embedded_phase_requires_lock_to_precede_it_in_the_log() {
        let mut journal = journal();
        let target_candidate = candidate(0, 1, 0x80, Vec::new(), None);
        let target = target_candidate.reference();
        let statement = RbcPhaseStatementV1::Echo { target };
        let outer_candidate = candidate(1, 2, 0x81, vec![statement], None);
        let outer = outer_candidate.reference();
        admit_candidate(&mut journal, &target_candidate);
        persist_and_fix(&mut journal, &outer_candidate);
        let apply = JournalEventV1::ApplyPhaseStatement {
            context: journal.context,
            outer,
            index: 0,
            sender: 1,
            statement,
        };
        assert_eq!(
            journal.append(apply.clone()).unwrap_err(),
            JournalErrorV1::OwnPhaseWithoutDurableLock(statement)
        );
        journal
            .append(JournalEventV1::LockEcho {
                context: journal.context,
                target,
            })
            .unwrap();
        journal.append(apply).unwrap();

        let mut reversed = journal.durable_events().to_vec();
        let last = reversed.len() - 1;
        reversed.swap(last - 1, last);
        assert_eq!(
            WriteAheadJournalV1::from_durable_events(journal.context, 1, reversed).unwrap_err(),
            JournalErrorV1::OwnPhaseWithoutDurableLock(statement)
        );
    }

    #[test]
    fn conflicting_local_carrier_and_phase_choices_are_rejected() {
        let mut journal = journal();
        let first_candidate = candidate(1, 1, 0x91, Vec::new(), None);
        let second_candidate = candidate(1, 1, 0x92, Vec::new(), None);
        let first_carrier = first_candidate.reference();
        let second_carrier = second_candidate.reference();
        journal
            .append(outbound_content_event(&journal, &first_candidate))
            .unwrap();
        journal
            .append(outbound_content_event(&journal, &second_candidate))
            .unwrap();
        journal.append(fix_event(&journal, first_carrier)).unwrap();
        assert_eq!(
            journal
                .append(fix_event(&journal, second_carrier))
                .unwrap_err(),
            JournalErrorV1::ConflictingOwnCarrier(1)
        );

        let first_target_candidate = candidate(0, 1, 0x93, Vec::new(), None);
        let second_target_candidate = candidate(0, 1, 0x94, Vec::new(), None);
        let first_target = first_target_candidate.reference();
        let second_target = second_target_candidate.reference();
        retain_candidate(&mut journal, &first_target_candidate);
        retain_candidate(&mut journal, &second_target_candidate);
        journal
            .append(JournalEventV1::LockReady {
                context: journal.context,
                target: first_target,
            })
            .unwrap();
        assert!(matches!(
            journal.append(JournalEventV1::LockReady {
                context: journal.context,
                target: second_target,
            }),
            Err(JournalErrorV1::ConflictingPhaseLock {
                kind: LockKindV1::Ready,
                ..
            })
        ));
    }

    #[test]
    fn conflicting_remote_phase_is_durably_ignored_and_does_not_stall_cursor() {
        let mut journal = journal();
        let first = reference(0, 1, 0xA0);
        let second = reference(0, 1, 0xA1);
        let first_statement = RbcPhaseStatementV1::Ready { target: first };
        let second_statement = RbcPhaseStatementV1::Ready { target: second };
        let outer_one_candidate = candidate(2, 2, 0xA2, vec![first_statement], None);
        let outer_two_candidate = candidate(2, 3, 0xA3, vec![second_statement], None);
        let outer_one = outer_one_candidate.reference();
        let outer_two = outer_two_candidate.reference();
        admit_candidate(&mut journal, &outer_one_candidate);
        admit_candidate(&mut journal, &outer_two_candidate);
        journal
            .append(JournalEventV1::ApplyPhaseStatement {
                context: journal.context,
                outer: outer_one,
                index: 0,
                sender: 2,
                statement: first_statement,
            })
            .unwrap();
        journal
            .append(JournalEventV1::AdvancePhaseBatchCursor {
                context: journal.context,
                outer: outer_one,
                index: 0,
            })
            .unwrap();
        journal
            .append(JournalEventV1::ApplyPhaseStatement {
                context: journal.context,
                outer: outer_two,
                index: 0,
                sender: 2,
                statement: second_statement,
            })
            .unwrap();
        assert_eq!(
            journal.snapshot().phase_statement_outcome(outer_two, 0),
            Some(AppliedPhaseOutcomeV1::IgnoredEquivocation)
        );
        journal
            .append(JournalEventV1::AdvancePhaseBatchCursor {
                context: journal.context,
                outer: outer_two,
                index: 0,
            })
            .unwrap();
        assert_eq!(journal.snapshot().phase_batch_cursor(outer_two), 1);
        assert_eq!(
            journal
                .restart()
                .unwrap()
                .snapshot()
                .phase_statement_outcome(outer_two, 0),
            Some(AppliedPhaseOutcomeV1::IgnoredEquivocation)
        );
    }

    #[test]
    fn replay_is_idempotent_and_foreign_namespace_fails_closed() {
        let mut journal = journal();
        let own_candidate = candidate(1, 1, 0xB1, Vec::new(), None);
        let own = own_candidate.reference();
        persist_and_fix(&mut journal, &own_candidate);
        journal
            .append(JournalEventV1::LockEcho {
                context: journal.context,
                target: own,
            })
            .unwrap();
        let once = journal.restart().unwrap();
        let twice = once.restart().unwrap();
        assert_eq!(once.snapshot(), twice.snapshot());
        assert_eq!(once.durable_events(), twice.durable_events());

        let foreign = JournalEventV1::LockReady {
            context: context(0xB2),
            target: own,
        };
        assert!(matches!(
            journal.append(foreign),
            Err(JournalErrorV1::ContextMismatch)
        ));
    }

    #[test]
    fn recovered_content_is_durable_before_ready_but_does_not_authorize_echo() {
        let mut journal = journal();
        let target_candidate = candidate(0, 1, 0xB3, Vec::new(), None);
        let target = target_candidate.reference();
        let ready = JournalEventV1::LockReady {
            context: journal.context,
            target,
        };
        assert_eq!(
            journal.append(ready.clone()).unwrap_err(),
            JournalErrorV1::CarrierContentNotRetained(target)
        );

        let retain = JournalEventV1::RetainCandidateContent {
            context: journal.context,
            candidate: target_candidate.clone(),
        };
        let expected_wire = target_candidate.canonical_wire_bytes().unwrap();
        assert_before_after(&journal, retain.clone(), |state| {
            state.retained_carrier(target) == Some(expected_wire.as_slice())
        });
        journal.append(retain).unwrap();
        assert_before_after(&journal, ready.clone(), |state| {
            state.ready_lock(RbcSlotKeyV1::of(target)) == Some(target)
        });
        journal.append(ready).unwrap();

        let echo = JournalEventV1::LockEcho {
            context: journal.context,
            target,
        };
        assert_eq!(
            journal.append(echo.clone()).unwrap_err(),
            JournalErrorV1::EchoWithoutAdmission(target)
        );
        admit_candidate(&mut journal, &target_candidate);
        journal.append(echo).unwrap();
    }

    #[test]
    fn own_fix_and_echo_cannot_precede_exact_typed_content() {
        let mut journal = journal();
        let own_candidate = candidate(1, 1, 0xB4, Vec::new(), None);
        let own = own_candidate.reference();
        assert_eq!(
            journal.append(fix_event(&journal, own)).unwrap_err(),
            JournalErrorV1::OutboundContentNotPersisted(own)
        );

        let content = outbound_content_event(&journal, &own_candidate);
        let expected_wire = own_candidate.canonical_wire_bytes().unwrap();
        assert_before_after(&journal, content.clone(), |state| {
            state.retained_carrier(own) == Some(expected_wire.as_slice())
                && state.own_carrier(1).is_none()
        });
        journal.append(content).unwrap();
        let echo = JournalEventV1::LockEcho {
            context: journal.context,
            target: own,
        };
        assert_eq!(
            journal.append(echo.clone()).unwrap_err(),
            JournalErrorV1::EchoWithoutAdmission(own)
        );
        journal.append(fix_event(&journal, own)).unwrap();
        journal.append(echo).unwrap();
    }

    #[test]
    fn outbound_exposure_waits_for_every_embedded_phase_lock() {
        let mut journal = journal();
        let echo_target_candidate = candidate(0, 1, 0xB5, Vec::new(), None);
        let ready_target_candidate = candidate(2, 1, 0xB6, Vec::new(), None);
        let echo = RbcPhaseStatementV1::Echo {
            target: echo_target_candidate.reference(),
        };
        let ready = RbcPhaseStatementV1::Ready {
            target: ready_target_candidate.reference(),
        };
        let own_candidate = candidate(1, 2, 0xB7, vec![echo, ready], None);
        let own = own_candidate.reference();
        admit_candidate(&mut journal, &echo_target_candidate);
        retain_candidate(&mut journal, &ready_target_candidate);
        prepare_outbound_for_exposure(&mut journal, &own_candidate);
        let expose = JournalEventV1::ExposeOutbound {
            context: journal.context,
            reference: own,
        };

        assert_eq!(
            journal.append(expose.clone()).unwrap_err(),
            JournalErrorV1::OutboundPhaseNotLocked(echo)
        );
        journal
            .append(JournalEventV1::LockEcho {
                context: journal.context,
                target: echo.target(),
            })
            .unwrap();
        assert_eq!(
            journal.append(expose.clone()).unwrap_err(),
            JournalErrorV1::OutboundPhaseNotLocked(ready)
        );
        journal
            .append(JournalEventV1::LockReady {
                context: journal.context,
                target: ready.target(),
            })
            .unwrap();
        journal.append(expose).unwrap();
    }

    #[test]
    fn outbound_exposure_waits_for_matching_consensus_and_leader_locks() {
        let mut journal = journal();
        let vertex = consensus_vertex(1, 1);
        let choice = vertex.leader_choice();
        let own_candidate = candidate(1, 2, 0xB8, Vec::new(), Some(vertex));
        let own = own_candidate.reference();
        prepare_outbound_for_exposure(&mut journal, &own_candidate);
        let expose = JournalEventV1::ExposeOutbound {
            context: journal.context,
            reference: own,
        };
        assert_eq!(
            journal.append(expose.clone()).unwrap_err(),
            JournalErrorV1::OutboundConsensusSlotNotLocked {
                consensus_round: 1,
                reference: own,
            }
        );
        journal
            .append(JournalEventV1::LockConsensusSlot {
                context: journal.context,
                consensus_round: 1,
                enclosing_carrier: own,
            })
            .unwrap();
        assert_eq!(
            journal.append(expose.clone()).unwrap_err(),
            JournalErrorV1::OutboundLeaderChoiceNotLocked(1)
        );
        journal
            .append(JournalEventV1::LockLeaderChoice {
                context: journal.context,
                consensus_round: 1,
                choice,
            })
            .unwrap();
        journal.append(expose).unwrap();
    }

    #[test]
    fn mismatched_consensus_or_leader_lock_cannot_poison_a_slot() {
        let mut no_vertex_journal = journal();
        let no_vertex = candidate(1, 2, 0xB9, Vec::new(), None);
        prepare_outbound_for_exposure(&mut no_vertex_journal, &no_vertex);
        assert!(matches!(
            no_vertex_journal.append(JournalEventV1::LockConsensusSlot {
                context: no_vertex_journal.context,
                consensus_round: 1,
                enclosing_carrier: no_vertex.reference(),
            }),
            Err(JournalErrorV1::ConsensusVertexMismatch { .. })
        ));

        let mut journal = journal();
        let vertex = consensus_vertex(1, 1);
        let choice = vertex.leader_choice();
        let own_candidate = candidate(1, 2, 0xBA, Vec::new(), Some(vertex));
        prepare_outbound_for_exposure(&mut journal, &own_candidate);
        assert_eq!(
            journal
                .append(JournalEventV1::LockLeaderChoice {
                    context: journal.context,
                    consensus_round: 1,
                    choice,
                })
                .unwrap_err(),
            JournalErrorV1::LeaderChoiceWithoutConsensusSlot(1)
        );
        assert!(matches!(
            journal.append(JournalEventV1::LockConsensusSlot {
                context: journal.context,
                consensus_round: 2,
                enclosing_carrier: own_candidate.reference(),
            }),
            Err(JournalErrorV1::ConsensusVertexMismatch { .. })
        ));
        journal
            .append(JournalEventV1::LockConsensusSlot {
                context: journal.context,
                consensus_round: 1,
                enclosing_carrier: own_candidate.reference(),
            })
            .unwrap();
        let wrong_choice = LeaderChoiceV1::NoVote {
            leader_author: 3,
            leader_round: 0,
        };
        assert_eq!(
            journal
                .append(JournalEventV1::LockLeaderChoice {
                    context: journal.context,
                    consensus_round: 1,
                    choice: wrong_choice,
                })
                .unwrap_err(),
            JournalErrorV1::LeaderChoiceCandidateMismatch(1)
        );
        journal
            .append(JournalEventV1::LockLeaderChoice {
                context: journal.context,
                consensus_round: 1,
                choice,
            })
            .unwrap();
    }

    #[test]
    fn authenticated_ingress_capability_is_context_and_receiver_bound() {
        let candidate = candidate(0, 1, 0xBB, Vec::new(), None);
        let mut journal = journal();
        assert!(matches!(
            journal.append(JournalEventV1::AuthenticatedIngress {
                context: journal.context,
                sequence: 0,
                authenticated: authenticated(&candidate, 2),
                provenance: IngressProvenanceV1::Relayed { peer: 3 },
            }),
            Err(JournalErrorV1::AuthenticatedIngressReceiverMismatch {
                expected: 1,
                actual: 2,
            })
        ));
        assert_eq!(journal.snapshot().next_ingress_sequence(), 0);
        assert_eq!(
            journal
                .append(JournalEventV1::AuthenticatedIngress {
                    context: journal.context,
                    sequence: 0,
                    authenticated: authenticated_with_marker(&candidate, 1, 0xBC),
                    provenance: IngressProvenanceV1::DirectFromAuthor,
                })
                .unwrap_err(),
            JournalErrorV1::AuthenticatedIngressContextMismatch
        );
        assert_eq!(journal.snapshot().next_ingress_sequence(), 0);
    }

    #[test]
    fn typed_outbound_content_rederives_bytes_and_rejects_foreign_context_sidecar() {
        let mut journal = journal();
        let own_candidate = candidate(1, 1, 0xC1, Vec::new(), None);
        let own = own_candidate.reference();
        let expected_wire = own_candidate.canonical_wire_bytes().unwrap();
        journal
            .append(JournalEventV1::PersistOutboundContent {
                context: journal.context,
                candidate: own_candidate.clone(),
            })
            .unwrap();
        assert_eq!(
            journal.snapshot().retained_carrier(own),
            Some(expected_wire.as_slice())
        );
        journal.append(fix_event(&journal, own)).unwrap();
        journal
            .append(JournalEventV1::PersistOutboundSidecar {
                context: journal.context,
                authenticated: locally_authenticated(&own_candidate),
            })
            .unwrap();
        assert_eq!(
            journal
                .append(JournalEventV1::PersistOutboundSidecar {
                    context: journal.context,
                    authenticated: locally_authenticated_with_marker(&own_candidate, 0xC2),
                })
                .unwrap_err(),
            JournalErrorV1::OutboundAuthenticationContextMismatch
        );
    }
}
