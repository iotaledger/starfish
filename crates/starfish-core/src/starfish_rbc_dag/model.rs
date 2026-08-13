// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Deterministic, in-memory model for the embedded-RBC carrier DAG.
//!
//! This reducer intentionally has no networking, storage, timers, or consensus
//! integration. Authentication is represented by a capability supplied by the
//! caller after the outer authenticator has been checked. This keeps the
//! important authority boundary explicit: canonical but unauthenticated
//! content may help header recovery, while only the first authenticated value
//! in a carrier slot is optimistically admitted and allowed to ECHO.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt,
    sync::Arc,
};

use crate::{
    committee::Committee,
    types::{AuthorityIndex, BlockReference, RoundNumber, Stake},
};

use super::{
    AuthenticatedCarrierV1, CandidateCarrierV1, LocallyAuthenticatedCarrierV1,
    MAX_PHASE_STATEMENTS_V1, RbcDagCommitteeId, RbcDagContextV1, RbcPhaseStatementV1,
    carrier_genesis_reference,
};

/// Executable-model runahead bound. This is deliberately a model parameter,
/// not a production protocol constant; the runtime value remains a proof and
/// benchmarking decision.
pub const EXECUTABLE_MODEL_ADMISSION_WINDOW_V1: RoundNumber = 2;
pub const EXECUTABLE_MODEL_BUFFER_WINDOW_V1: RoundNumber = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IngressAuthentication {
    Authenticated,
    CandidateOnly,
}

/// Observable effects of one deterministic reducer transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelEffect {
    /// A threshold is latched, but the exact canonical carrier is absent.
    NeedCarrier {
        target: BlockReference,
        holders: Vec<AuthorityIndex>,
    },
    /// The local Bracha instance delivered this exact carrier value.
    Delivered(BlockReference),
    /// One exact author prefix advanced by one carrier.
    PrefixAdvanced {
        authority: AuthorityIndex,
        tip: BlockReference,
    },
    /// The sequential fast clock opened the next local carrier round.
    CarrierRoundAdvanced(RoundNumber),
}

/// Snapshot of the lifecycle predicates for one exact carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierLifecycle {
    pub authenticated: bool,
    pub admitted: bool,
    pub phase_batch_processed: bool,
    pub delivered: bool,
    pub data_available: bool,
    pub prefix_closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelError {
    InvalidCommittee,
    CommitteeMismatch {
        expected: RbcDagCommitteeId,
        actual: RbcDagCommitteeId,
    },
    ContextMismatch,
    AuthenticationReceiverMismatch {
        expected: AuthorityIndex,
        actual: AuthorityIndex,
    },
    UnknownAuthority(AuthorityIndex),
    LocalAuthorMismatch {
        expected: AuthorityIndex,
        actual: AuthorityIndex,
    },
    LocalCarrierRequiresStart(BlockReference),
    LocalRoundNotOpen(RoundNumber),
    UnexpectedLocalRound {
        expected: RoundNumber,
        actual: RoundNumber,
    },
    LocalCarrierAlreadyFixed(RoundNumber),
    FutureCarrierOutsideBuffer {
        current: RoundNumber,
        maximum: RoundNumber,
        actual: RoundNumber,
    },
    WrongLocalPredecessor {
        expected: BlockReference,
        actual: BlockReference,
    },
    LocalWeakParentNotAdmitted(BlockReference),
    LocalPhaseBatchMismatch,
    ConflictingCarrierContent(BlockReference),
    UnexpectedRecovery(BlockReference),
    MissingCarrier(BlockReference),
    FrontierLength {
        expected: usize,
        actual: usize,
    },
    FrontierAuthority {
        index: AuthorityIndex,
        reference: BlockReference,
    },
    FrontierNotClosed(BlockReference),
    FrontierRegression {
        authority: AuthorityIndex,
        previous: Option<BlockReference>,
        proposed: Option<BlockReference>,
    },
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Starfish-RBC-DAG model error: {self:?}")
    }
}

impl Error for ModelError {}

#[derive(Clone)]
struct CarrierRecord {
    carrier: CandidateCarrierV1,
    authenticated: bool,
    admitted: bool,
    phase_batch_cursor: usize,
    delivered: bool,
    data_available: bool,
    prefix_closed: bool,
}

impl CarrierRecord {
    fn new(carrier: CandidateCarrierV1) -> Self {
        Self {
            carrier,
            authenticated: false,
            admitted: false,
            phase_batch_cursor: 0,
            delivered: false,
            data_available: false,
            prefix_closed: false,
        }
    }

    fn lifecycle(&self) -> CarrierLifecycle {
        CarrierLifecycle {
            authenticated: self.authenticated,
            admitted: self.admitted,
            phase_batch_processed: self.phase_batch_cursor
                == self.carrier.header().phase_batch().len(),
            delivered: self.delivered,
            data_available: self.data_available,
            prefix_closed: self.prefix_closed,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RbcCandidateState {
    echoes: BTreeSet<AuthorityIndex>,
    readies: BTreeSet<AuthorityIndex>,
    echo_quorum_observed: bool,
    ready_validity_observed: bool,
    ready_quorum_observed: bool,
    requested_holders: BTreeSet<AuthorityIndex>,
}

impl RbcCandidateState {
    fn holders(&self) -> BTreeSet<AuthorityIndex> {
        self.echoes.union(&self.readies).copied().collect()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RbcSlotState {
    echoed: Option<BlockReference>,
    readied: Option<BlockReference>,
    delivered: Option<BlockReference>,
    echo_by_sender: BTreeMap<AuthorityIndex, BlockReference>,
    ready_by_sender: BTreeMap<AuthorityIndex, BlockReference>,
    candidates: BTreeMap<BlockReference, RbcCandidateState>,
}

#[derive(Clone, Copy)]
enum RbcAction {
    NeedCarrier,
    SendReady,
    Deliver,
    None,
}

/// Pure local state machine used by the milestone-two simulations.
#[derive(Clone)]
pub struct RbcDagModel {
    committee: Arc<Committee>,
    committee_id: RbcDagCommitteeId,
    context: RbcDagContextV1,
    own_authority: AuthorityIndex,
    local_carrier_round: RoundNumber,
    own_fixed: BTreeMap<RoundNumber, BlockReference>,
    carriers: BTreeMap<BlockReference, CarrierRecord>,
    authenticated_by_slot: BTreeMap<(RoundNumber, AuthorityIndex), BlockReference>,
    admitted_by_slot: BTreeMap<(RoundNumber, AuthorityIndex), BlockReference>,
    rbc_slots: BTreeMap<(RoundNumber, AuthorityIndex), RbcSlotState>,
    pending_phases: VecDeque<RbcPhaseStatementV1>,
    pending_phase_set: BTreeSet<RbcPhaseStatementV1>,
    pending_delivered_batch_replays: VecDeque<BlockReference>,
    prefix_tips: Vec<BlockReference>,
    included_frontier: Vec<Option<BlockReference>>,
    included: BTreeSet<BlockReference>,
}

impl RbcDagModel {
    pub fn new(
        committee: Arc<Committee>,
        own_authority: AuthorityIndex,
        context: RbcDagContextV1,
    ) -> Result<Self, ModelError> {
        if !committee.known_authority(own_authority) {
            return Err(ModelError::UnknownAuthority(own_authority));
        }
        let committee_id =
            RbcDagCommitteeId::derive(&committee).map_err(|_| ModelError::InvalidCommittee)?;
        if context.committee_id() != committee_id {
            return Err(ModelError::ContextMismatch);
        }
        let prefix_tips = committee
            .authorities()
            .map(carrier_genesis_reference)
            .collect();
        Ok(Self {
            included_frontier: vec![None; committee.len()],
            committee,
            committee_id,
            context,
            own_authority,
            local_carrier_round: 1,
            own_fixed: BTreeMap::new(),
            carriers: BTreeMap::new(),
            authenticated_by_slot: BTreeMap::new(),
            admitted_by_slot: BTreeMap::new(),
            rbc_slots: BTreeMap::new(),
            pending_phases: VecDeque::new(),
            pending_phase_set: BTreeSet::new(),
            pending_delivered_batch_replays: VecDeque::new(),
            prefix_tips,
            included: BTreeSet::new(),
        })
    }

    pub fn own_authority(&self) -> AuthorityIndex {
        self.own_authority
    }

    pub fn context(&self) -> RbcDagContextV1 {
        self.context
    }

    /// Current sequential local carrier slot. If `can_create_carrier` is
    /// false, the local carrier is fixed and waits for exact-round quorum.
    pub fn local_carrier_round(&self) -> RoundNumber {
        self.local_carrier_round
    }

    pub fn can_create_carrier(&self) -> bool {
        !self.own_fixed.contains_key(&self.local_carrier_round)
    }

    pub fn pending_phase_batch(&self) -> Vec<RbcPhaseStatementV1> {
        let limit = self
            .committee
            .len()
            .saturating_mul(4)
            .min(MAX_PHASE_STATEMENTS_V1);
        self.pending_phases
            .iter()
            .filter(|statement| statement.target().round < self.local_carrier_round)
            .take(limit)
            .copied()
            .collect()
    }

    pub fn pending_phase_backlog_len(&self) -> usize {
        self.pending_phases.len()
    }

    /// Return the exact predecessor and one deterministic quorum of admitted
    /// weak parents for the next honest carrier.
    pub fn local_parent_set(&self) -> Result<(BlockReference, Vec<BlockReference>), ModelError> {
        if !self.can_create_carrier() {
            return Err(ModelError::LocalCarrierAlreadyFixed(
                self.local_carrier_round,
            ));
        }
        let parent_round = self.local_carrier_round - 1;
        let own_prev = if parent_round == 0 {
            carrier_genesis_reference(self.own_authority)
        } else {
            *self
                .own_fixed
                .get(&parent_round)
                .ok_or(ModelError::LocalRoundNotOpen(self.local_carrier_round))?
        };

        let mut stake = self.authority_stake(self.own_authority);
        let mut weak_parents = Vec::new();
        for authority in self.committee.authorities() {
            if authority == self.own_authority {
                continue;
            }
            let parent = if parent_round == 0 {
                carrier_genesis_reference(authority)
            } else {
                let Some(parent) = self
                    .admitted_by_slot
                    .get(&(parent_round, authority))
                    .copied()
                else {
                    continue;
                };
                parent
            };
            weak_parents.push(parent);
            stake = stake.saturating_add(self.authority_stake(authority));
            if stake >= self.committee.quorum_threshold() {
                break;
            }
        }
        if stake < self.committee.quorum_threshold() {
            return Err(ModelError::LocalRoundNotOpen(self.local_carrier_round));
        }
        Ok((own_prev, weak_parents))
    }

    /// Fix a locally authored carrier. Its phase batch must be the exact
    /// bounded FIFO prefix returned by [`Self::pending_phase_batch`]; newly
    /// generated ECHO is left for a later carrier.
    pub fn start_local_carrier(
        &mut self,
        authenticated: LocallyAuthenticatedCarrierV1,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        self.ensure_locally_authenticated(&authenticated)?;
        let carrier = authenticated.candidate().clone();
        self.ensure_committee(&carrier)?;
        let header = carrier.header();
        if header.author() != self.own_authority {
            return Err(ModelError::LocalAuthorMismatch {
                expected: self.own_authority,
                actual: header.author(),
            });
        }
        if header.carrier_round() != self.local_carrier_round {
            return Err(ModelError::UnexpectedLocalRound {
                expected: self.local_carrier_round,
                actual: header.carrier_round(),
            });
        }
        if !self.can_create_carrier() {
            return Err(ModelError::LocalCarrierAlreadyFixed(
                self.local_carrier_round,
            ));
        }
        let (expected_prev, _) = self.local_parent_set()?;
        if header.own_prev() != expected_prev {
            return Err(ModelError::WrongLocalPredecessor {
                expected: expected_prev,
                actual: header.own_prev(),
            });
        }
        if header.carrier_round() > 1 {
            for parent in header.weak_parents() {
                if self.admitted_by_slot.get(&(parent.round, parent.authority)) != Some(parent) {
                    return Err(ModelError::LocalWeakParentNotAdmitted(*parent));
                }
            }
        }
        let expected_phase_batch = self.pending_phase_batch();
        if header.phase_batch() != expected_phase_batch {
            return Err(ModelError::LocalPhaseBatchMismatch);
        }

        let round = header.carrier_round();
        let selected_phase_indices: BTreeSet<_> = self
            .pending_phases
            .iter()
            .enumerate()
            .filter(|(_, statement)| statement.target().round < round)
            .take(expected_phase_batch.len())
            .map(|(index, _)| index)
            .collect();
        let reference = carrier.reference();
        // Preflight all fallible ingress checks before the proof-critical
        // write order. The exact local carrier must be fixed before its local
        // ECHO is authorized or any embedded phase statement is exposed.
        self.preflight_receive(&carrier)?;
        self.own_fixed.insert(round, reference);
        for statement in &expected_phase_batch {
            self.pending_phase_set.remove(statement);
        }
        self.pending_phases = self
            .pending_phases
            .drain(..)
            .enumerate()
            .filter_map(|(index, statement)| {
                (!selected_phase_indices.contains(&index)).then_some(statement)
            })
            .collect();
        let mut effects =
            self.apply_received_carrier(carrier, IngressAuthentication::Authenticated);
        self.maybe_advance_fast_clock(&mut effects);
        Ok(effects)
    }

    /// Stage canonical content without granting optimistic admission or ECHO.
    pub fn stage_candidate(
        &mut self,
        carrier: CandidateCarrierV1,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        self.receive_carrier(carrier, IngressAuthentication::CandidateOnly)
    }

    /// Admit a carrier only through the opaque capability produced by the
    /// codec's context- and receiver-bound authenticator verifier.
    pub fn receive_authenticated(
        &mut self,
        authenticated: AuthenticatedCarrierV1,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        self.ensure_authenticated(&authenticated)?;
        if authenticated.candidate().header().author() == self.own_authority {
            return Err(ModelError::LocalCarrierRequiresStart(
                authenticated.candidate().reference(),
            ));
        }
        self.receive_carrier(
            authenticated.candidate().clone(),
            IngressAuthentication::Authenticated,
        )
    }

    fn receive_carrier(
        &mut self,
        carrier: CandidateCarrierV1,
        authentication: IngressAuthentication,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        self.preflight_receive(&carrier)?;
        Ok(self.apply_received_carrier(carrier, authentication))
    }

    fn preflight_receive(&self, carrier: &CandidateCarrierV1) -> Result<(), ModelError> {
        self.ensure_committee(carrier)?;
        let reference = carrier.reference();
        let maximum = self
            .local_carrier_round
            .saturating_add(EXECUTABLE_MODEL_BUFFER_WINDOW_V1);
        if reference.round > maximum {
            return Err(ModelError::FutureCarrierOutsideBuffer {
                current: self.local_carrier_round,
                maximum,
                actual: reference.round,
            });
        }
        let author = carrier.header().author();
        if !self.committee.known_authority(author) {
            return Err(ModelError::UnknownAuthority(author));
        }
        match self.carriers.get(&reference) {
            Some(existing) if &existing.carrier != carrier => {
                return Err(ModelError::ConflictingCarrierContent(reference));
            }
            Some(_) | None => {}
        }
        Ok(())
    }

    fn apply_received_carrier(
        &mut self,
        carrier: CandidateCarrierV1,
        authentication: IngressAuthentication,
    ) -> Vec<ModelEffect> {
        let reference = carrier.reference();
        self.carriers
            .entry(reference)
            .or_insert_with(|| CarrierRecord::new(carrier));

        let mut effects = Vec::new();
        // Canonical content can satisfy a previously latched recovery even if
        // the receiver-specific authenticator is invalid.
        self.drive_rbc(reference, &mut effects);

        if authentication == IngressAuthentication::Authenticated {
            self.carriers
                .get_mut(&reference)
                .expect("carrier was staged")
                .authenticated = true;
            let slot_key = (reference.round, reference.authority);
            let selected = match self.authenticated_by_slot.get(&slot_key) {
                Some(existing) => *existing == reference,
                None => {
                    self.authenticated_by_slot.insert(slot_key, reference);
                    true
                }
            };
            if selected && self.in_admission_window(reference.round) {
                self.promote_authenticated(reference, &mut effects);
            }
        }
        self.maybe_advance_fast_clock(&mut effects);
        self.drain_delivered_phase_batches(&mut effects);
        effects
    }

    /// Accept an exact recovered carrier only after authenticated phase
    /// evidence allocated its candidate.
    pub fn recover_carrier(
        &mut self,
        carrier: CandidateCarrierV1,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        self.ensure_committee(&carrier)?;
        let reference = carrier.reference();
        let key = (reference.round, reference.authority);
        let expected = self
            .rbc_slots
            .get(&key)
            .is_some_and(|slot| slot.candidates.contains_key(&reference));
        if !expected {
            return Err(ModelError::UnexpectedRecovery(reference));
        }
        self.receive_carrier(carrier, IngressAuthentication::CandidateOnly)
    }

    /// Record transaction-data availability established by the external
    /// Reed-Solomon/reconstruction layer after it verifies this carrier's
    /// commitment. Milestone two intentionally treats that layer as a trusted
    /// oracle; it does not infer this predicate from unauthenticated ACKs.
    pub fn mark_data_available(
        &mut self,
        reference: BlockReference,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        self.carriers
            .get_mut(&reference)
            .ok_or(ModelError::MissingCarrier(reference))?
            .data_available = true;
        let mut effects = Vec::new();
        self.drive_prefix(reference.authority, &mut effects);
        Ok(effects)
    }

    pub fn lifecycle(&self, reference: &BlockReference) -> Option<CarrierLifecycle> {
        self.carriers.get(reference).map(CarrierRecord::lifecycle)
    }

    pub fn delivered(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Option<BlockReference> {
        self.rbc_slots
            .get(&(round, authority))
            .and_then(|slot| slot.delivered)
    }

    pub fn prefix_tip(&self, authority: AuthorityIndex) -> Option<BlockReference> {
        let tip = *self.prefix_tips.get(authority as usize)?;
        (tip.round > 0).then_some(tip)
    }

    pub fn admitted_reference(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Option<BlockReference> {
        self.admitted_by_slot.get(&(round, authority)).copied()
    }

    /// Include the exact closed-prefix delta named by a committed frontier.
    /// The output order is `(round, author, digest)` through `BlockReference`'s
    /// canonical ordering.
    pub fn apply_frontier(
        &mut self,
        frontier: &[Option<BlockReference>],
    ) -> Result<Vec<BlockReference>, ModelError> {
        if frontier.len() != self.committee.len() {
            return Err(ModelError::FrontierLength {
                expected: self.committee.len(),
                actual: frontier.len(),
            });
        }
        let mut delta = BTreeSet::new();
        for (index, proposed) in frontier.iter().copied().enumerate() {
            let authority = index as AuthorityIndex;
            if let Some(reference) = proposed {
                if reference.authority != authority || reference.round == 0 {
                    return Err(ModelError::FrontierAuthority {
                        index: authority,
                        reference,
                    });
                }
                if !self
                    .carriers
                    .get(&reference)
                    .is_some_and(|record| record.prefix_closed)
                {
                    return Err(ModelError::FrontierNotClosed(reference));
                }
            }
            let previous = self.included_frontier[index];
            self.collect_frontier_extension(authority, previous, proposed, &mut delta)?;
        }
        self.included_frontier.clone_from_slice(frontier);
        self.included.extend(delta.iter().copied());
        Ok(delta.into_iter().collect())
    }

    fn collect_frontier_extension(
        &self,
        authority: AuthorityIndex,
        previous: Option<BlockReference>,
        proposed: Option<BlockReference>,
        delta: &mut BTreeSet<BlockReference>,
    ) -> Result<(), ModelError> {
        let Some(mut cursor) = proposed else {
            if previous.is_some() {
                return Err(ModelError::FrontierRegression {
                    authority,
                    previous,
                    proposed,
                });
            }
            return Ok(());
        };
        if Some(cursor) == previous {
            return Ok(());
        }
        loop {
            if Some(cursor) == previous {
                return Ok(());
            }
            if cursor.round == 0 {
                if previous.is_none() && cursor == carrier_genesis_reference(authority) {
                    return Ok(());
                }
                return Err(ModelError::FrontierRegression {
                    authority,
                    previous,
                    proposed,
                });
            }
            let record = self
                .carriers
                .get(&cursor)
                .ok_or(ModelError::FrontierNotClosed(cursor))?;
            if !record.prefix_closed {
                return Err(ModelError::FrontierNotClosed(cursor));
            }
            delta.insert(cursor);
            cursor = record.carrier.header().own_prev();
        }
    }

    fn authority_stake(&self, authority: AuthorityIndex) -> Stake {
        self.committee.get_stake(authority).unwrap_or(0)
    }

    fn ensure_committee(&self, carrier: &CandidateCarrierV1) -> Result<(), ModelError> {
        let actual = carrier.committee_id();
        if actual != self.committee_id {
            return Err(ModelError::CommitteeMismatch {
                expected: self.committee_id,
                actual,
            });
        }
        Ok(())
    }

    fn ensure_authenticated(
        &self,
        authenticated: &AuthenticatedCarrierV1,
    ) -> Result<(), ModelError> {
        if authenticated.context() != self.context {
            return Err(ModelError::ContextMismatch);
        }
        if authenticated.receiver() != self.own_authority {
            return Err(ModelError::AuthenticationReceiverMismatch {
                expected: self.own_authority,
                actual: authenticated.receiver(),
            });
        }
        self.ensure_committee(authenticated.candidate())
    }

    fn ensure_locally_authenticated(
        &self,
        authenticated: &LocallyAuthenticatedCarrierV1,
    ) -> Result<(), ModelError> {
        if authenticated.context() != self.context {
            return Err(ModelError::ContextMismatch);
        }
        self.ensure_committee(authenticated.candidate())
    }

    fn voters_stake(&self, voters: &BTreeSet<AuthorityIndex>) -> Stake {
        voters.iter().fold(0, |stake, authority| {
            stake.saturating_add(self.authority_stake(*authority))
        })
    }

    fn rbc_slot_mut(&mut self, reference: BlockReference) -> &mut RbcSlotState {
        self.rbc_slots
            .entry((reference.round, reference.authority))
            .or_default()
    }

    fn authorize_local_echo(&mut self, reference: BlockReference, effects: &mut Vec<ModelEffect>) {
        let own = self.own_authority;
        let slot = self.rbc_slot_mut(reference);
        if slot.echoed.is_some() {
            return;
        }
        slot.echoed = Some(reference);
        slot.echo_by_sender.insert(own, reference);
        slot.candidates
            .entry(reference)
            .or_default()
            .echoes
            .insert(own);
        self.queue_local_phase(RbcPhaseStatementV1::Echo { target: reference });
        self.drive_rbc(reference, effects);
    }

    fn queue_local_phase(&mut self, statement: RbcPhaseStatementV1) {
        if self.pending_phase_set.insert(statement) {
            self.pending_phases.push_back(statement);
        }
    }

    fn process_phase_batch(&mut self, outer: BlockReference, effects: &mut Vec<ModelEffect>) {
        self.process_phase_batch_steps(outer, usize::MAX, effects);
        self.drain_delivered_phase_batches(effects);
    }

    fn drain_delivered_phase_batches(&mut self, effects: &mut Vec<ModelEffect>) {
        while let Some(outer) = self.pending_delivered_batch_replays.pop_front() {
            self.process_phase_batch_steps(outer, usize::MAX, effects);
        }
    }

    fn process_phase_batch_steps(
        &mut self,
        outer: BlockReference,
        maximum_steps: usize,
        effects: &mut Vec<ModelEffect>,
    ) {
        let mut processed = 0;
        loop {
            if processed == maximum_steps {
                return;
            }
            let Some((sender, statement)) = self.carriers.get(&outer).and_then(|record| {
                record
                    .carrier
                    .header()
                    .phase_batch()
                    .get(record.phase_batch_cursor)
                    .copied()
                    .map(|statement| (record.carrier.header().author(), statement))
            }) else {
                return;
            };
            // Applying the statement is idempotent. Advance the persisted
            // cursor only afterwards, so a crash between the two replays the
            // same statement rather than skipping the unprocessed tail.
            self.record_phase(sender, statement, effects);
            self.carriers
                .get_mut(&outer)
                .expect("the outer carrier remains pinned")
                .phase_batch_cursor += 1;
            processed += 1;
        }
    }

    fn record_phase(
        &mut self,
        sender: AuthorityIndex,
        statement: RbcPhaseStatementV1,
        effects: &mut Vec<ModelEffect>,
    ) {
        if !self.committee.known_authority(sender) {
            return;
        }
        let target = statement.target();
        if sender == self.own_authority {
            let authorized = self
                .rbc_slots
                .get(&(target.round, target.authority))
                .is_some_and(|slot| match statement {
                    RbcPhaseStatementV1::Echo { .. } => slot.echoed == Some(target),
                    RbcPhaseStatementV1::Ready { .. } => slot.readied == Some(target),
                });
            if !authorized {
                // An own-authored embedded statement is replay, not fresh
                // authority. The corresponding persisted local lock must
                // already exist before it may reconstruct sender evidence.
                return;
            }
        }
        let slot = self.rbc_slot_mut(target);
        let senders = match statement {
            RbcPhaseStatementV1::Echo { .. } => &mut slot.echo_by_sender,
            RbcPhaseStatementV1::Ready { .. } => &mut slot.ready_by_sender,
        };
        match senders.get(&sender) {
            Some(existing) if *existing != target => return,
            Some(_) => return,
            None => {
                senders.insert(sender, target);
            }
        }
        let candidate = slot.candidates.entry(target).or_default();
        match statement {
            RbcPhaseStatementV1::Echo { .. } => {
                candidate.echoes.insert(sender);
            }
            RbcPhaseStatementV1::Ready { .. } => {
                candidate.readies.insert(sender);
            }
        }
        self.drive_rbc(target, effects);
    }

    fn drive_rbc(&mut self, target: BlockReference, effects: &mut Vec<ModelEffect>) {
        let slot_key = (target.round, target.authority);
        if !self
            .rbc_slots
            .get(&slot_key)
            .is_some_and(|slot| slot.candidates.contains_key(&target))
        {
            // Merely staging canonical content is not authenticated RBC
            // evidence. Candidate state is allocated only by a locally
            // authorized ECHO or an embedded ECHO/READY statement.
            return;
        }
        loop {
            let header_available = self.carriers.contains_key(&target);
            let q = self.committee.quorum_threshold();
            let v = self.committee.validity_threshold();
            let action = {
                let echo_stake;
                let ready_stake;
                {
                    let slot = self.rbc_slot_mut(target);
                    let candidate = slot.candidates.entry(target).or_default();
                    echo_stake = candidate.echoes.clone();
                    ready_stake = candidate.readies.clone();
                }
                let echo_stake = self.voters_stake(&echo_stake);
                let ready_stake = self.voters_stake(&ready_stake);
                let slot = self.rbc_slot_mut(target);
                let candidate = slot.candidates.entry(target).or_default();
                candidate.echo_quorum_observed |= echo_stake >= q;
                candidate.ready_validity_observed |= ready_stake >= v;
                candidate.ready_quorum_observed |= ready_stake >= q;
                let ready_trigger =
                    candidate.echo_quorum_observed || candidate.ready_validity_observed;
                let needs_header = !header_available
                    && ((slot.readied.is_none() && ready_trigger)
                        || (slot.delivered.is_none() && candidate.ready_quorum_observed));
                if needs_header {
                    let holders = candidate.holders();
                    if holders != candidate.requested_holders {
                        candidate.requested_holders = holders;
                        RbcAction::NeedCarrier
                    } else {
                        RbcAction::None
                    }
                } else if header_available && slot.readied.is_none() && ready_trigger {
                    RbcAction::SendReady
                } else if header_available
                    && slot.delivered.is_none()
                    && candidate.ready_quorum_observed
                {
                    RbcAction::Deliver
                } else {
                    RbcAction::None
                }
            };

            match action {
                RbcAction::NeedCarrier => {
                    let holders = self
                        .rbc_slots
                        .get(&(target.round, target.authority))
                        .and_then(|slot| slot.candidates.get(&target))
                        .map(RbcCandidateState::holders)
                        .unwrap_or_default()
                        .into_iter()
                        .collect();
                    effects.push(ModelEffect::NeedCarrier { target, holders });
                    break;
                }
                RbcAction::SendReady => {
                    let own = self.own_authority;
                    let slot = self.rbc_slot_mut(target);
                    slot.readied = Some(target);
                    slot.ready_by_sender.insert(own, target);
                    slot.candidates
                        .entry(target)
                        .or_default()
                        .readies
                        .insert(own);
                    self.queue_local_phase(RbcPhaseStatementV1::Ready { target });
                }
                RbcAction::Deliver => {
                    self.rbc_slot_mut(target).delivered = Some(target);
                    let record = self
                        .carriers
                        .get_mut(&target)
                        .expect("delivery requires exact canonical carrier content");
                    record.delivered = true;
                    effects.push(ModelEffect::Delivered(target));
                    self.pending_delivered_batch_replays.push_back(target);
                    self.drive_prefix(target.authority, effects);
                }
                RbcAction::None => break,
            }
        }
    }

    fn maybe_advance_fast_clock(&mut self, effects: &mut Vec<ModelEffect>) {
        let round = self.local_carrier_round;
        if !self.own_fixed.contains_key(&round) {
            return;
        }
        let admitted: BTreeSet<_> = self
            .admitted_by_slot
            .keys()
            .filter_map(|(candidate_round, authority)| {
                (*candidate_round == round).then_some(*authority)
            })
            .collect();
        if self.voters_stake(&admitted) < self.committee.quorum_threshold() {
            return;
        }
        self.local_carrier_round = round.saturating_add(1);
        effects.push(ModelEffect::CarrierRoundAdvanced(self.local_carrier_round));
        self.promote_buffered_window(effects);
    }

    fn in_admission_window(&self, round: RoundNumber) -> bool {
        round
            <= self
                .local_carrier_round
                .saturating_add(EXECUTABLE_MODEL_ADMISSION_WINDOW_V1)
    }

    fn promote_authenticated(&mut self, reference: BlockReference, effects: &mut Vec<ModelEffect>) {
        let slot_key = (reference.round, reference.authority);
        if self.authenticated_by_slot.get(&slot_key) != Some(&reference)
            || self
                .carriers
                .get(&reference)
                .is_none_or(|record| record.admitted)
        {
            return;
        }
        self.admitted_by_slot.insert(slot_key, reference);
        self.carriers
            .get_mut(&reference)
            .expect("an authenticated carrier remains staged")
            .admitted = true;
        self.authorize_local_echo(reference, effects);
        self.process_phase_batch(reference, effects);
    }

    fn promote_buffered_window(&mut self, effects: &mut Vec<ModelEffect>) {
        let eligible: Vec<_> = self
            .authenticated_by_slot
            .values()
            .copied()
            .filter(|reference| self.in_admission_window(reference.round))
            .collect();
        for reference in eligible {
            self.promote_authenticated(reference, effects);
        }
    }

    fn drive_prefix(&mut self, authority: AuthorityIndex, effects: &mut Vec<ModelEffect>) {
        loop {
            let Some(current_tip) = self.prefix_tips.get(authority as usize).copied() else {
                return;
            };
            let Some(next_round) = current_tip.round.checked_add(1) else {
                return;
            };
            let Some(next) = self.delivered(authority, next_round) else {
                return;
            };
            let can_close = self.carriers.get(&next).is_some_and(|record| {
                record.delivered
                    && record.data_available
                    && record.carrier.header().own_prev() == current_tip
            });
            if !can_close {
                return;
            }
            self.carriers
                .get_mut(&next)
                .expect("delivered carrier exists")
                .prefix_closed = true;
            self.prefix_tips[authority as usize] = next;
            effects.push(ModelEffect::PrefixAdvanced {
                authority,
                tip: next,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{TransactionsCommitment, mac_keyrings_for_test},
        starfish_rbc_dag::{CarrierHeaderV1Args, RbcDagError},
        types::{BlockAuthenticationScheme, BlockReference},
    };

    fn committee(n: usize) -> Arc<Committee> {
        Committee::new_test(vec![1; n])
    }

    fn context(committee: &Committee) -> RbcDagContextV1 {
        RbcDagContextV1::new(
            super::super::RbcDagProtocolInstanceId::new([0xD1; 32]).unwrap(),
            committee,
            BlockAuthenticationScheme::MacVector,
        )
        .unwrap()
    }

    fn model(committee: Arc<Committee>, authority: AuthorityIndex) -> RbcDagModel {
        let context = context(&committee);
        RbcDagModel::new(committee, authority, context).unwrap()
    }

    fn authenticate_for(
        committee: &Committee,
        carrier: &CandidateCarrierV1,
        receiver: AuthorityIndex,
    ) -> AuthenticatedCarrierV1 {
        let context = context(committee);
        let keyrings = mac_keyrings_for_test(committee.len());
        let author = carrier.header().author() as usize;
        let authentication = context
            .authenticate(
                carrier,
                committee,
                super::super::CarrierAuthorizerV1::MacVector {
                    authority: author as AuthorityIndex,
                    keys: &keyrings[author],
                },
            )
            .unwrap();
        context
            .verify_authentication(
                carrier.clone(),
                authentication,
                receiver,
                committee,
                &keyrings[receiver as usize],
            )
            .unwrap()
    }

    fn authenticate_local(
        committee: &Committee,
        carrier: &CandidateCarrierV1,
    ) -> LocallyAuthenticatedCarrierV1 {
        let context = context(committee);
        let keyrings = mac_keyrings_for_test(committee.len());
        let author = carrier.header().author() as usize;
        context
            .authenticate_local(
                carrier.clone(),
                committee,
                super::super::CarrierAuthorizerV1::MacVector {
                    authority: author as AuthorityIndex,
                    keys: &keyrings[author],
                },
            )
            .unwrap()
    }

    fn admit(
        model: &mut RbcDagModel,
        carrier: CandidateCarrierV1,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        let authenticated = authenticate_for(&model.committee, &carrier, model.own_authority);
        model.receive_authenticated(authenticated)
    }

    fn candidate(
        committee: &Committee,
        author: AuthorityIndex,
        round: RoundNumber,
        own_prev: BlockReference,
        weak_parents: Vec<BlockReference>,
        phase_batch: Vec<RbcPhaseStatementV1>,
        marker: u64,
    ) -> Result<CandidateCarrierV1, RbcDagError> {
        CandidateCarrierV1::try_new(
            CarrierHeaderV1Args {
                author,
                carrier_round: round,
                own_prev,
                weak_parents,
                transactions_commitment: TransactionsCommitment::default(),
                data_acknowledgments: Vec::new(),
                phase_batch,
                consensus_vertex: None,
                creation_time_ns: marker,
            },
            committee,
        )
    }

    fn genesis_parents(
        committee: &Committee,
        author: AuthorityIndex,
    ) -> (BlockReference, Vec<BlockReference>) {
        let own = carrier_genesis_reference(author);
        let mut stake = committee.get_stake(author).unwrap();
        let mut weak = Vec::new();
        for other in committee.authorities() {
            if other == author {
                continue;
            }
            weak.push(carrier_genesis_reference(other));
            stake += committee.get_stake(other).unwrap();
            if stake >= committee.quorum_threshold() {
                break;
            }
        }
        (own, weak)
    }

    fn build_local(model: &mut RbcDagModel, marker: u64) -> CandidateCarrierV1 {
        let (own_prev, weak_parents) = model.local_parent_set().unwrap();
        let carrier = candidate(
            &model.committee,
            model.own_authority,
            model.local_carrier_round,
            own_prev,
            weak_parents,
            model.pending_phase_batch(),
            marker,
        )
        .unwrap();
        let authenticated = authenticate_local(&model.committee, &carrier);
        model.start_local_carrier(authenticated).unwrap();
        carrier
    }

    fn run_honest_round(models: &mut [RbcDagModel], round: RoundNumber) -> Vec<CandidateCarrierV1> {
        let carriers: Vec<_> = models
            .iter_mut()
            .enumerate()
            .map(|(index, model)| build_local(model, u64::from(round) * 100 + index as u64))
            .collect();
        for carrier in &carriers {
            for model in models.iter_mut() {
                if model.own_authority != carrier.header().author() {
                    let authenticated =
                        authenticate_for(&model.committee, carrier, model.own_authority);
                    model.receive_authenticated(authenticated).unwrap();
                }
                model.mark_data_available(carrier.reference()).unwrap();
            }
        }
        assert!(
            models
                .iter()
                .all(|model| model.local_carrier_round() == round + 1)
        );
        carriers
    }

    fn all_honest_progress(n: usize) {
        let committee = committee(n);
        let mut models: Vec<_> = committee
            .authorities()
            .map(|authority| model(Arc::clone(&committee), authority))
            .collect();
        let mut rounds = Vec::new();
        for round in 1..=6 {
            rounds.push(run_honest_round(&mut models, round));
        }
        for model in &models {
            for carriers in rounds.iter().take(4) {
                for carrier in carriers {
                    assert_eq!(
                        model
                            .delivered(carrier.header().author(), carrier.header().carrier_round()),
                        Some(carrier.reference())
                    );
                    assert!(model.lifecycle(&carrier.reference()).unwrap().prefix_closed);
                }
            }
        }
    }

    #[test]
    fn four_node_heartbeat_only_run_delivers_every_mature_carrier() {
        all_honest_progress(4);
    }

    #[test]
    fn seven_node_heartbeat_only_run_delivers_every_mature_carrier() {
        all_honest_progress(7);
    }

    #[test]
    fn phase_backlog_exposes_only_a_bounded_fifo_prefix() {
        let committee = committee(4);
        let mut model = model(committee, 0);
        model.local_carrier_round = 4;
        let mut queued = Vec::new();
        for round in 1..=3 {
            for author in 0..4 {
                let target = BlockReference::new_test(author, round);
                queued.push(RbcPhaseStatementV1::Echo { target });
                queued.push(RbcPhaseStatementV1::Ready { target });
            }
        }
        for statement in &queued {
            model.queue_local_phase(*statement);
        }

        assert_eq!(model.pending_phase_backlog_len(), 24);
        assert_eq!(model.pending_phase_batch(), queued[..16]);
    }

    #[test]
    fn local_carrier_must_drain_the_exact_bounded_phase_prefix() {
        let committee = committee(4);
        let mut models: Vec<_> = (0..4)
            .map(|authority| model(Arc::clone(&committee), authority))
            .collect();
        run_honest_round(&mut models, 1);

        let model = &mut models[0];
        let expected = model.pending_phase_batch();
        assert!(!expected.is_empty());
        let (own_prev, weak_parents) = model.local_parent_set().unwrap();
        let omitted = candidate(
            &committee,
            model.own_authority,
            model.local_carrier_round,
            own_prev,
            weak_parents.clone(),
            Vec::new(),
            0xA1,
        )
        .unwrap();
        let omitted_authentication = authenticate_local(&committee, &omitted);
        assert_eq!(
            model.start_local_carrier(omitted_authentication),
            Err(ModelError::LocalPhaseBatchMismatch)
        );
        assert!(model.can_create_carrier());

        let exact = candidate(
            &committee,
            model.own_authority,
            model.local_carrier_round,
            own_prev,
            weak_parents,
            expected,
            0xA2,
        )
        .unwrap();
        let exact_authentication = authenticate_local(&committee, &exact);
        model.start_local_carrier(exact_authentication).unwrap();
        assert_eq!(model.own_fixed.get(&2), Some(&exact.reference()));
    }

    fn record_phase(
        model: &mut RbcDagModel,
        sender: AuthorityIndex,
        statement: RbcPhaseStatementV1,
    ) -> Vec<ModelEffect> {
        let mut effects = Vec::new();
        model.record_phase(sender, statement, &mut effects);
        model.drain_delivered_phase_batches(&mut effects);
        effects
    }

    fn force_deliver(model: &mut RbcDagModel, carrier: CandidateCarrierV1) {
        let target = carrier.reference();
        model.stage_candidate(carrier).unwrap();
        let senders: Vec<_> = model
            .committee
            .authorities()
            .filter(|sender| *sender != model.own_authority)
            .take(model.committee.quorum_threshold() as usize)
            .collect();
        for sender in senders {
            record_phase(model, sender, RbcPhaseStatementV1::Ready { target });
        }
        assert_eq!(
            model.delivered(target.authority, target.round),
            Some(target)
        );
    }

    #[test]
    fn threshold_before_header_requests_then_recovers_exact_carrier() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 1).unwrap();
        let target = carrier.reference();

        assert!(record_phase(&mut model, 0, RbcPhaseStatementV1::Echo { target }).is_empty());
        assert!(record_phase(&mut model, 1, RbcPhaseStatementV1::Echo { target }).is_empty());
        assert!(matches!(
            record_phase(
                &mut model,
                2,
                RbcPhaseStatementV1::Echo { target }
            )
            .as_slice(),
            [ModelEffect::NeedCarrier { target: requested, holders }]
                if *requested == target && holders == &[0, 1, 2]
        ));

        model.recover_carrier(carrier).unwrap();
        assert!(
            model
                .pending_phases
                .contains(&RbcPhaseStatementV1::Ready { target })
        );
        let lifecycle = model.lifecycle(&target).unwrap();
        assert!(!lifecycle.authenticated);
        assert!(!lifecycle.admitted);
    }

    #[test]
    fn staged_content_without_phase_evidence_cannot_authorize_recovery() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 2).unwrap();
        let reference = carrier.reference();

        model.stage_candidate(carrier.clone()).unwrap();
        assert!(model.lifecycle(&reference).is_some());
        assert!(model.rbc_slots.is_empty());
        assert_eq!(
            model.recover_carrier(carrier),
            Err(ModelError::UnexpectedRecovery(reference))
        );
        assert!(model.rbc_slots.is_empty());
    }

    #[test]
    fn ready_threshold_before_content_recovers_then_delivers() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 3).unwrap();
        let target = carrier.reference();

        assert!(record_phase(&mut model, 0, RbcPhaseStatementV1::Ready { target }).is_empty());
        assert!(matches!(
            record_phase(
                &mut model,
                1,
                RbcPhaseStatementV1::Ready { target }
            )
            .as_slice(),
            [ModelEffect::NeedCarrier { target: requested, holders }]
                if *requested == target && holders == &[0, 1]
        ));
        assert_eq!(model.delivered(0, 1), None);
        assert!(model.lifecycle(&target).is_none());

        let effects = model.recover_carrier(carrier).unwrap();
        assert!(effects.contains(&ModelEffect::Delivered(target)));
        assert_eq!(model.delivered(0, 1), Some(target));
        assert!(
            model
                .pending_phases
                .contains(&RbcPhaseStatementV1::Ready { target })
        );
    }

    #[test]
    fn cross_committee_candidate_is_rejected_before_state_mutation() {
        let local_committee = committee(4);
        let foreign_committee = Committee::new_test(vec![2; 4]);
        let mut model = model(Arc::clone(&local_committee), 3);
        let (own_prev, weak) = genesis_parents(&foreign_committee, 0);
        let foreign = candidate(&foreign_committee, 0, 1, own_prev, weak, Vec::new(), 9).unwrap();
        let reference = foreign.reference();

        assert!(matches!(
            model.stage_candidate(foreign),
            Err(ModelError::CommitteeMismatch { .. })
        ));
        assert!(model.lifecycle(&reference).is_none());
        assert!(model.admitted_reference(0, 1).is_none());
        assert!(model.rbc_slots.is_empty());
    }

    #[test]
    fn authenticated_capability_is_bound_to_context_and_receiver() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 10).unwrap();
        let reference = carrier.reference();

        let wrong_receiver = authenticate_for(&committee, &carrier, 2);
        assert_eq!(
            model.receive_authenticated(wrong_receiver),
            Err(ModelError::AuthenticationReceiverMismatch {
                expected: 3,
                actual: 2,
            })
        );

        let other_context = RbcDagContextV1::new(
            super::super::RbcDagProtocolInstanceId::new([0xD2; 32]).unwrap(),
            &committee,
            BlockAuthenticationScheme::MacVector,
        )
        .unwrap();
        let keyrings = mac_keyrings_for_test(committee.len());
        let authentication = other_context
            .authenticate(
                &carrier,
                &committee,
                super::super::CarrierAuthorizerV1::MacVector {
                    authority: 0,
                    keys: &keyrings[0],
                },
            )
            .unwrap();
        let wrong_context = other_context
            .verify_authentication(carrier, authentication, 3, &committee, &keyrings[3])
            .unwrap();
        assert_eq!(
            model.receive_authenticated(wrong_context),
            Err(ModelError::ContextMismatch)
        );
        assert!(model.lifecycle(&reference).is_none());
        assert!(model.rbc_slots.is_empty());
    }

    #[test]
    fn locally_authored_carrier_can_only_enter_through_atomic_start() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 0);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 11).unwrap();
        let reference = carrier.reference();
        let authenticated = authenticate_for(&committee, &carrier, 0);

        assert_eq!(
            model.receive_authenticated(authenticated),
            Err(ModelError::LocalCarrierRequiresStart(reference))
        );
        assert!(model.lifecycle(&reference).is_none());
        assert!(model.own_fixed.is_empty());
        assert!(model.rbc_slots.is_empty());
    }

    #[test]
    fn own_embedded_phase_requires_the_persisted_local_lock() {
        let committee = committee(4);
        let mut model = model(committee, 3);
        let target = BlockReference::new_test(0, 1);

        assert!(record_phase(&mut model, 3, RbcPhaseStatementV1::Echo { target }).is_empty());
        assert!(record_phase(&mut model, 3, RbcPhaseStatementV1::Ready { target }).is_empty());
        assert!(model.rbc_slots.is_empty());
    }

    #[test]
    fn phase_replay_and_equivocation_count_each_sender_once() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let first = BlockReference::new_test(0, 1);
        let conflicting = BlockReference::new_test(0, 1);
        let mut conflicting = conflicting;
        conflicting.digest = crate::types::BlockDigest::from([0x77; 32]);

        for _ in 0..3 {
            assert!(
                record_phase(&mut model, 0, RbcPhaseStatementV1::Echo { target: first }).is_empty()
            );
        }
        assert!(
            record_phase(
                &mut model,
                0,
                RbcPhaseStatementV1::Echo {
                    target: conflicting
                }
            )
            .is_empty()
        );
        assert!(
            record_phase(&mut model, 1, RbcPhaseStatementV1::Echo { target: first }).is_empty()
        );
        assert!(matches!(
            record_phase(
                &mut model,
                2,
                RbcPhaseStatementV1::Echo { target: first }
            )
            .as_slice(),
            [ModelEffect::NeedCarrier { target, .. }] if *target == first
        ));
        let slot = model.rbc_slots.get(&(1, 0)).unwrap();
        assert_eq!(slot.echo_by_sender.len(), 3);
        assert_eq!(slot.echo_by_sender[&0], first);
        assert!(!slot.candidates.contains_key(&conflicting));

        record_phase(&mut model, 0, RbcPhaseStatementV1::Ready { target: first });
        record_phase(
            &mut model,
            0,
            RbcPhaseStatementV1::Ready {
                target: conflicting,
            },
        );
        let slot = model.rbc_slots.get(&(1, 0)).unwrap();
        assert_eq!(slot.ready_by_sender[&0], first);
        assert!(!slot.candidates.contains_key(&conflicting));
    }

    #[test]
    fn split_initial_values_converge_on_one_delivery() {
        let committee = committee(4);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let first = candidate(&committee, 0, 1, own_prev, weak.clone(), Vec::new(), 11).unwrap();
        let conflicting = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 12).unwrap();
        let first_ref = first.reference();
        let conflicting_ref = conflicting.reference();
        let mut models: Vec<_> = committee
            .authorities()
            .map(|authority| model(Arc::clone(&committee), authority))
            .collect();

        for (index, model) in models.iter_mut().enumerate() {
            let (admitted, staged) = if index == 3 {
                (conflicting.clone(), first.clone())
            } else {
                (first.clone(), conflicting.clone())
            };
            if model.own_authority == admitted.header().author() {
                // The dealer is Byzantine in this trace. Its local behavior is
                // outside the honest local-start API, so retain both bytes and
                // drive its receive-side RBC state only from phase evidence.
                model.stage_candidate(admitted).unwrap();
                model.stage_candidate(staged).unwrap();
            } else {
                admit(model, admitted).unwrap();
                model.stage_candidate(staged).unwrap();
            }
        }

        // Authorities 0, 1, and 2 ECHO the first value; authority 3 ECHOs the
        // conflicting value. The first value reaches Q and READY amplification
        // carries the receiver that saw the split INIT to the same delivery.
        for model in &mut models {
            for sender in 0..3 {
                record_phase(
                    model,
                    sender,
                    RbcPhaseStatementV1::Echo { target: first_ref },
                );
            }
            record_phase(
                model,
                3,
                RbcPhaseStatementV1::Echo {
                    target: conflicting_ref,
                },
            );
        }
        for model in &mut models {
            for sender in 0..3 {
                record_phase(
                    model,
                    sender,
                    RbcPhaseStatementV1::Ready { target: first_ref },
                );
            }
        }
        assert!(
            models
                .iter()
                .all(|model| model.delivered(0, 1) == Some(first_ref))
        );
        assert!(
            models
                .iter()
                .all(|model| model.delivered(0, 1) != Some(conflicting_ref))
        );
    }

    #[test]
    fn typed_outer_carriers_enforce_split_value_phase_locks_end_to_end() {
        let committee = committee(4);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let first = candidate(&committee, 0, 1, own_prev, weak.clone(), Vec::new(), 21).unwrap();
        let conflicting = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 22).unwrap();
        let first_ref = first.reference();
        let conflicting_ref = conflicting.reference();
        let mut receiver = model(Arc::clone(&committee), 3);

        admit(&mut receiver, first).unwrap();
        admit(&mut receiver, conflicting).unwrap();
        assert_eq!(receiver.admitted_reference(0, 1), Some(first_ref));

        let outer = |author: AuthorityIndex,
                     round: RoundNumber,
                     phase_batch: Vec<RbcPhaseStatementV1>,
                     marker: u64| {
            let own_prev = BlockReference::new_test(author, round - 1);
            let weak_parents = (0..4)
                .filter(|other| *other != author)
                .take(2)
                .map(|other| BlockReference::new_test(other, round - 1))
                .collect();
            candidate(
                &committee,
                author,
                round,
                own_prev,
                weak_parents,
                phase_batch,
                marker,
            )
            .unwrap()
        };

        for author in 0..3 {
            let carrier = outer(
                author,
                2,
                vec![RbcPhaseStatementV1::Echo { target: first_ref }],
                200 + u64::from(author),
            );
            admit(&mut receiver, carrier).unwrap();
        }
        for author in 0..3 {
            let mut phase_batch = Vec::new();
            if author == 0 {
                phase_batch.push(RbcPhaseStatementV1::Echo {
                    target: conflicting_ref,
                });
            }
            phase_batch.push(RbcPhaseStatementV1::Ready { target: first_ref });
            let carrier = outer(author, 3, phase_batch, 300 + u64::from(author));
            admit(&mut receiver, carrier).unwrap();
        }

        assert_eq!(receiver.delivered(0, 1), Some(first_ref));
        assert_ne!(receiver.delivered(0, 1), Some(conflicting_ref));
        let slot = receiver.rbc_slots.get(&(1, 0)).unwrap();
        assert_eq!(slot.echo_by_sender.get(&0), Some(&first_ref));
        assert!(!slot.candidates.contains_key(&conflicting_ref));
    }

    #[test]
    fn non_equivocating_phase_reordering_has_the_same_result() {
        let committee = committee(4);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 15).unwrap();
        let target = carrier.reference();
        let mut left = model(Arc::clone(&committee), 3);
        let mut right = model(Arc::clone(&committee), 3);
        left.stage_candidate(carrier.clone()).unwrap();
        right.stage_candidate(carrier).unwrap();

        for sender in [0, 1, 2] {
            record_phase(&mut left, sender, RbcPhaseStatementV1::Echo { target });
        }
        for sender in [2, 0, 1] {
            record_phase(&mut right, sender, RbcPhaseStatementV1::Echo { target });
        }
        for sender in [0, 1, 2] {
            record_phase(&mut left, sender, RbcPhaseStatementV1::Ready { target });
        }
        for sender in [1, 2, 0] {
            record_phase(&mut right, sender, RbcPhaseStatementV1::Ready { target });
        }
        assert_eq!(left.delivered(0, 1), Some(target));
        assert_eq!(right.delivered(0, 1), Some(target));
        assert_eq!(left.pending_phase_batch(), right.pending_phase_batch());
    }

    #[test]
    fn delivered_candidate_replays_batch_even_without_admission() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let target = BlockReference::new_test(1, 1);
        let own_prev = BlockReference::new_test(0, 1);
        let weak = vec![
            BlockReference::new_test(1, 1),
            BlockReference::new_test(2, 1),
        ];
        let outer = candidate(
            &committee,
            0,
            2,
            own_prev,
            weak,
            vec![RbcPhaseStatementV1::Echo { target }],
            2,
        )
        .unwrap();
        let outer_ref = outer.reference();
        model.stage_candidate(outer.clone()).unwrap();
        assert!(
            !model
                .rbc_slots
                .get(&(target.round, target.authority))
                .is_some_and(|slot| slot.echo_by_sender.contains_key(&0))
        );

        force_deliver(&mut model, outer);
        assert_eq!(
            model.rbc_slots[&(target.round, target.authority)].echo_by_sender[&0],
            target
        );
        let lifecycle = model.lifecycle(&outer_ref).unwrap();
        assert!(!lifecycle.admitted);
        assert!(lifecycle.delivered);
        assert!(lifecycle.phase_batch_processed);
    }

    #[test]
    fn replay_after_crash_before_batch_cursor_does_not_skip_the_tail() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let own_prev = BlockReference::new_test(0, 1);
        let weak = vec![
            BlockReference::new_test(1, 1),
            BlockReference::new_test(2, 1),
        ];
        let first = BlockReference::new_test(1, 1);
        let second = BlockReference::new_test(2, 1);
        let outer = candidate(
            &committee,
            0,
            2,
            own_prev,
            weak,
            vec![
                RbcPhaseStatementV1::Echo { target: first },
                RbcPhaseStatementV1::Ready { target: second },
            ],
            0xCA,
        )
        .unwrap();
        let outer_ref = outer.reference();
        model.stage_candidate(outer).unwrap();

        let mut uninterrupted = model.clone();
        uninterrupted.process_phase_batch(outer_ref, &mut Vec::new());

        // Model a crash after the first idempotent statement was persisted but
        // before the outer batch cursor was advanced.
        let mut restarted = model;
        restarted.record_phase(
            0,
            RbcPhaseStatementV1::Echo { target: first },
            &mut Vec::new(),
        );
        restarted.process_phase_batch(outer_ref, &mut Vec::new());

        assert_eq!(restarted.rbc_slots, uninterrupted.rbc_slots);
        assert_eq!(restarted.pending_phases, uninterrupted.pending_phases);
        assert!(
            restarted
                .lifecycle(&outer_ref)
                .unwrap()
                .phase_batch_processed
        );
    }

    #[test]
    fn deeply_chained_delivered_batches_use_an_explicit_work_queue() {
        const DEPTH: RoundNumber = 2_048;

        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let mut previous = None;
        let mut references = Vec::with_capacity(DEPTH as usize);
        for round in 1..=DEPTH {
            let own_prev = previous.unwrap_or_else(|| carrier_genesis_reference(0));
            let parent = |authority| {
                if round == 1 {
                    carrier_genesis_reference(authority)
                } else {
                    BlockReference::new_test(authority, round - 1)
                }
            };
            let phase_batch = previous
                .map(|target| vec![RbcPhaseStatementV1::Ready { target }])
                .unwrap_or_default();
            let carrier = candidate(
                &committee,
                0,
                round,
                own_prev,
                vec![parent(1), parent(2)],
                phase_batch,
                u64::from(round),
            )
            .unwrap();
            let reference = carrier.reference();
            model
                .carriers
                .insert(reference, CarrierRecord::new(carrier));
            let mut candidate_state = RbcCandidateState::default();
            candidate_state.readies.extend([1, 2]);
            let mut slot = RbcSlotState::default();
            slot.ready_by_sender
                .extend([(1, reference), (2, reference)]);
            slot.candidates.insert(reference, candidate_state);
            model.rbc_slots.insert((round, 0), slot);
            references.push(reference);
            previous = Some(reference);
        }

        model
            .pending_delivered_batch_replays
            .push_back(*references.last().unwrap());
        let mut effects = Vec::new();
        model.drain_delivered_phase_batches(&mut effects);

        assert!(model.pending_delivered_batch_replays.is_empty());
        assert_eq!(model.delivered(0, 1), Some(references[0]));
        assert_eq!(
            model.delivered(0, DEPTH - 1),
            Some(references[DEPTH as usize - 2])
        );
        assert!(model.delivered(0, DEPTH).is_none());
    }

    #[test]
    fn quorum_of_future_carriers_cannot_jump_the_sequential_clock() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 0);
        let mut future_references = Vec::new();
        for author in 1..4 {
            let own_prev = BlockReference::new_test(author, 4);
            let weak = (0..4)
                .filter(|other| *other != author)
                .take(2)
                .map(|other| BlockReference::new_test(other, 4))
                .collect();
            let future = candidate(
                &committee,
                author,
                5,
                own_prev,
                weak,
                Vec::new(),
                u64::from(author),
            )
            .unwrap();
            future_references.push(future.reference());
            admit(&mut model, future).unwrap();
        }
        assert_eq!(model.local_carrier_round(), 1);
        assert!(model.can_create_carrier());
        for reference in future_references {
            let lifecycle = model.lifecycle(&reference).unwrap();
            assert!(lifecycle.authenticated);
            assert!(!lifecycle.admitted);
            assert!(
                !model
                    .rbc_slots
                    .contains_key(&(reference.round, reference.authority))
            );
        }
    }

    #[test]
    fn carrier_beyond_the_bounded_future_buffer_is_rejected_without_state() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 0);
        let carrier = candidate(
            &committee,
            1,
            6,
            BlockReference::new_test(1, 5),
            vec![
                BlockReference::new_test(0, 5),
                BlockReference::new_test(2, 5),
            ],
            Vec::new(),
            60,
        )
        .unwrap();
        let reference = carrier.reference();
        let authenticated = authenticate_for(&committee, &carrier, 0);

        assert_eq!(
            model.receive_authenticated(authenticated),
            Err(ModelError::FutureCarrierOutsideBuffer {
                current: 1,
                maximum: 5,
                actual: 6,
            })
        );
        assert!(model.lifecycle(&reference).is_none());
        assert!(model.authenticated_by_slot.is_empty());
        assert!(model.rbc_slots.is_empty());
    }

    #[test]
    fn buffered_authenticated_carrier_is_promoted_when_window_opens() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 0);
        let future = candidate(
            &committee,
            1,
            4,
            BlockReference::new_test(1, 3),
            vec![
                BlockReference::new_test(0, 3),
                BlockReference::new_test(2, 3),
            ],
            Vec::new(),
            40,
        )
        .unwrap();
        let future_ref = future.reference();
        admit(&mut model, future).unwrap();
        assert!(model.lifecycle(&future_ref).unwrap().authenticated);
        assert!(!model.lifecycle(&future_ref).unwrap().admitted);

        build_local(&mut model, 1);
        for author in [1, 2] {
            let (own_prev, weak) = genesis_parents(&committee, author);
            let round_one = candidate(
                &committee,
                author,
                1,
                own_prev,
                weak,
                Vec::new(),
                u64::from(author),
            )
            .unwrap();
            admit(&mut model, round_one).unwrap();
        }

        assert_eq!(model.local_carrier_round(), 2);
        assert!(model.lifecycle(&future_ref).unwrap().admitted);
        assert_eq!(model.admitted_reference(1, 4), Some(future_ref));

        let future_echo = RbcPhaseStatementV1::Echo { target: future_ref };
        for round in 2..=4 {
            assert_eq!(model.local_carrier_round(), round);
            assert!(!model.pending_phase_batch().contains(&future_echo));
            build_local(&mut model, 100 + u64::from(round));
            assert!(model.pending_phases.contains(&future_echo));
            for author in [2, 3] {
                let own_prev = BlockReference::new_test(author, round - 1);
                let weak = (0..4)
                    .filter(|other| *other != author)
                    .take(2)
                    .map(|other| BlockReference::new_test(other, round - 1))
                    .collect();
                let remote = candidate(
                    &committee,
                    author,
                    round,
                    own_prev,
                    weak,
                    Vec::new(),
                    u64::from(round) * 10 + u64::from(author),
                )
                .unwrap();
                admit(&mut model, remote).unwrap();
            }
            assert_eq!(model.local_carrier_round(), round + 1);
        }

        assert!(model.pending_phase_batch().contains(&future_echo));
        let round_five = build_local(&mut model, 500);
        assert!(round_five.header().phase_batch().contains(&future_echo));
        assert!(!model.pending_phases.contains(&future_echo));
    }

    #[test]
    fn poisoned_recipient_still_delivers_without_optimistic_admission() {
        let committee = committee(4);
        let mut models: Vec<_> = committee
            .authorities()
            .map(|authority| model(Arc::clone(&committee), authority))
            .collect();
        let round_one: Vec<_> = models
            .iter_mut()
            .enumerate()
            .map(|(index, model)| build_local(model, index as u64))
            .collect();
        let poisoned = round_one[0].reference();
        for carrier in &round_one {
            for model in &mut models {
                if model.own_authority == carrier.header().author() {
                    continue;
                }
                if carrier.reference() == poisoned && model.own_authority == 3 {
                    model.stage_candidate(carrier.clone()).unwrap();
                } else {
                    admit(model, carrier.clone()).unwrap();
                }
            }
        }
        assert_ne!(models[3].admitted_reference(0, 1), Some(poisoned));
        for round in 2..=4 {
            run_honest_round(&mut models, round);
        }
        for model in &models {
            assert_eq!(model.delivered(0, 1), Some(poisoned));
        }
        let poisoned_lifecycle = models[3].lifecycle(&poisoned).unwrap();
        assert!(!poisoned_lifecycle.admitted);
        assert!(poisoned_lifecycle.delivered);
    }

    #[test]
    fn missing_weak_parent_body_does_not_trigger_fetch_or_block_delivery() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let (g0, weak0) = genesis_parents(&committee, 0);
        let round_one = candidate(&committee, 0, 1, g0, weak0, Vec::new(), 1).unwrap();
        let round_one_ref = round_one.reference();
        force_deliver(&mut model, round_one);
        model.mark_data_available(round_one_ref).unwrap();

        let missing = BlockReference::new_test(1, 1);
        let round_two = candidate(
            &committee,
            0,
            2,
            round_one_ref,
            vec![missing, BlockReference::new_test(2, 1)],
            Vec::new(),
            2,
        )
        .unwrap();
        let round_two_ref = round_two.reference();
        let effects = admit(&mut model, round_two.clone()).unwrap();
        assert!(!effects.iter().any(
            |effect| matches!(effect, ModelEffect::NeedCarrier { target, .. } if *target == missing)
        ));
        force_deliver(&mut model, round_two);
        model.mark_data_available(round_two_ref).unwrap();
        assert_eq!(model.prefix_tip(0), Some(round_two_ref));
    }

    #[test]
    fn f_missing_weak_parent_bodies_do_not_block_seven_node_delivery() {
        let committee = committee(7);
        let mut model = model(Arc::clone(&committee), 6);
        let (genesis, weak) = genesis_parents(&committee, 0);
        let first = candidate(&committee, 0, 1, genesis, weak, Vec::new(), 1).unwrap();
        let first_ref = first.reference();
        force_deliver(&mut model, first);
        model.mark_data_available(first_ref).unwrap();

        let mut known = Vec::new();
        for author in [3, 4] {
            let (own_prev, weak) = genesis_parents(&committee, author);
            let carrier = candidate(
                &committee,
                author,
                1,
                own_prev,
                weak,
                Vec::new(),
                u64::from(author),
            )
            .unwrap();
            known.push(carrier.reference());
            model.stage_candidate(carrier).unwrap();
        }
        let missing = [
            BlockReference::new_test(1, 1),
            BlockReference::new_test(2, 1),
        ];
        let second = candidate(
            &committee,
            0,
            2,
            first_ref,
            vec![missing[0], missing[1], known[0], known[1]],
            Vec::new(),
            2,
        )
        .unwrap();
        let second_ref = second.reference();
        let effects = admit(&mut model, second.clone()).unwrap();
        assert!(effects.iter().all(
            |effect| !matches!(effect, ModelEffect::NeedCarrier { target, .. } if missing.contains(target))
        ));
        assert!(
            missing
                .iter()
                .all(|reference| model.lifecycle(reference).is_none())
        );

        force_deliver(&mut model, second);
        model.mark_data_available(second_ref).unwrap();
        assert_eq!(model.prefix_tip(0), Some(second_ref));
    }

    #[test]
    fn prefix_rejects_fork_above_closed_tip() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let (genesis, weak) = genesis_parents(&committee, 0);
        let first = candidate(&committee, 0, 1, genesis, weak, Vec::new(), 1).unwrap();
        let first_ref = first.reference();
        force_deliver(&mut model, first);
        model.mark_data_available(first_ref).unwrap();

        let mut unavailable_fork = first_ref;
        unavailable_fork.digest = crate::types::BlockDigest::from([0x88; 32]);
        let fork = candidate(
            &committee,
            0,
            2,
            unavailable_fork,
            vec![
                BlockReference::new_test(1, 1),
                BlockReference::new_test(2, 1),
            ],
            Vec::new(),
            2,
        )
        .unwrap();
        let fork_ref = fork.reference();
        force_deliver(&mut model, fork);
        model.mark_data_available(fork_ref).unwrap();
        assert_eq!(model.prefix_tip(0), Some(first_ref));
        assert!(!model.lifecycle(&fork_ref).unwrap().prefix_closed);
    }

    #[test]
    fn delayed_data_availability_closes_the_whole_waiting_prefix() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let (genesis, weak) = genesis_parents(&committee, 0);
        let first = candidate(&committee, 0, 1, genesis, weak, Vec::new(), 1).unwrap();
        let first_ref = first.reference();
        force_deliver(&mut model, first);
        model.mark_data_available(first_ref).unwrap();
        let second = candidate(
            &committee,
            0,
            2,
            first_ref,
            vec![
                BlockReference::new_test(1, 1),
                BlockReference::new_test(2, 1),
            ],
            Vec::new(),
            2,
        )
        .unwrap();
        let second_ref = second.reference();
        force_deliver(&mut model, second);
        let third = candidate(
            &committee,
            0,
            3,
            second_ref,
            vec![
                BlockReference::new_test(1, 2),
                BlockReference::new_test(2, 2),
            ],
            Vec::new(),
            3,
        )
        .unwrap();
        let third_ref = third.reference();
        force_deliver(&mut model, third);
        model.mark_data_available(third_ref).unwrap();
        assert_eq!(model.prefix_tip(0), Some(first_ref));

        let effects = model.mark_data_available(second_ref).unwrap();
        assert_eq!(model.prefix_tip(0), Some(third_ref));
        assert_eq!(
            effects
                .iter()
                .filter(|effect| matches!(effect, ModelEffect::PrefixAdvanced { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn equal_frontiers_produce_identical_ordered_deltas() {
        let committee = committee(4);
        let mut left = model(Arc::clone(&committee), 3);
        let mut right = model(Arc::clone(&committee), 3);
        let carriers: Vec<_> = committee
            .authorities()
            .map(|author| {
                let (own_prev, weak) = genesis_parents(&committee, author);
                candidate(
                    &committee,
                    author,
                    1,
                    own_prev,
                    weak,
                    Vec::new(),
                    u64::from(author),
                )
                .unwrap()
            })
            .collect();
        for carrier in &carriers {
            force_deliver(&mut left, carrier.clone());
            left.mark_data_available(carrier.reference()).unwrap();
        }
        for carrier in carriers.iter().rev() {
            force_deliver(&mut right, carrier.clone());
            right.mark_data_available(carrier.reference()).unwrap();
        }
        let frontier: Vec<_> = carriers
            .iter()
            .map(|carrier| Some(carrier.reference()))
            .collect();
        let left_delta = left.apply_frontier(&frontier).unwrap();
        let right_delta = right.apply_frontier(&frontier).unwrap();
        assert_eq!(left_delta, right_delta);
        assert!(left_delta.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(left.apply_frontier(&frontier).unwrap().is_empty());
    }
}
