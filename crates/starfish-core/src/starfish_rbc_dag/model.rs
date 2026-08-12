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
    crypto::{Blake3Hasher, TransactionsCommitment},
    types::{AuthorityIndex, BlockReference, RoundNumber, Stake},
};

use super::{
    AuthenticatedCarrierV1, CandidateCarrierV1, LeaderChoiceV1, LocallyAuthenticatedCarrierV1,
    MAX_PHASE_STATEMENTS_V1, RbcDagCommitteeId, RbcDagContextV1, RbcPhaseStatementV1,
    carrier_genesis_reference,
};

/// Executable-model runahead bounds. Admission stays close to the exact local
/// clock, while the wider authenticated-retention window lets a temporarily
/// descheduled validator catch up without forcing the healthy quorum to pace
/// itself to the slowest peer. These remain prototype resource parameters,
/// not production protocol constants.
pub const EXECUTABLE_MODEL_ADMISSION_WINDOW_V1: RoundNumber = 2;
pub const EXECUTABLE_MODEL_BUFFER_WINDOW_V1: RoundNumber = 64;

const MODEL_LINEAGE_DERIVE_CONTEXT: &str = "starfish-rbc-dag-model-lineage-v1";
type ModelLineage = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IngressAuthentication {
    Authenticated,
    CandidateOnly,
}

/// Safety basis for the optimistic RBC fast-delivery latch.
///
/// The first three predicates are authoritative delivery rules: the sender is
/// known honest, or the author-excluding optimistic ECHO threshold proves the
/// value unique and forces the VOTE/ACK/READY fallback to terminate on it.
/// `Delivered` records the slower `Q`-READY path when no fast predicate fired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryPromiseBasisV1 {
    LocalFixed,
    /// The target author has stake greater than the maximum Byzantine stake,
    /// so a receiver-authenticated author value cannot equivocate.
    HonestAuthor,
    /// The author-excluding optimistic ECHO threshold `O = M + b` was met.
    OptimisticEcho,
    Delivered,
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
    /// This exact value satisfied an authoritative optimistic-delivery
    /// predicate. The slower `Delivered` effect still records `Q`-READY
    /// certification independently. Projection additionally requires DA and
    /// an exact closed carrier prefix.
    DeliveryPromised(BlockReference),
    /// One exact author prefix advanced by one carrier.
    PrefixAdvanced {
        authority: AuthorityIndex,
        tip: BlockReference,
    },
    /// The sequential fast clock opened the next local carrier round.
    CarrierRoundAdvanced(RoundNumber),
}

/// One proof-critical or externally observable step of a reducer transition.
///
/// The order is part of the runtime contract. A caller may plan a transition
/// on a clone, persist these entries in order, and only then install the
/// planned model with [`RbcDagModel::commit_plan`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelTraceEvent {
    /// The first authenticated value selected for a remote carrier slot.
    AdmissionLocked(BlockReference),
    /// A locally generated ECHO, VOTE, ACK, or READY became slot-global and
    /// immutable for its phase.
    LocalPhaseLocked(RbcPhaseStatementV1),
    /// One exact entry of an enclosing carrier's authenticated phase log is
    /// about to be applied. Any lock enabled by that entry follows this event.
    PhaseBatchEntryApplied {
        outer: BlockReference,
        index: usize,
        sender: AuthorityIndex,
        statement: RbcPhaseStatementV1,
    },
    /// The entry at `index` was applied and the durable cursor may advance to
    /// `next_index`. This always follows the matching application event.
    PhaseBatchCursorAdvanced {
        outer: BlockReference,
        index: usize,
        next_index: usize,
    },
    /// The local author fixed one exact carrier before authorizing its ECHO.
    LocalCarrierFixed(BlockReference),
    /// The optional consensus vertex became the author's immutable value for
    /// its logical consensus round. This follows fixing the enclosing carrier
    /// and precedes any outbound exposure.
    ConsensusSlotLocked {
        consensus_round: RoundNumber,
        enclosing_carrier: BlockReference,
    },
    /// The local Vote/NoVote choice embedded in the fixed consensus vertex
    /// became immutable before the carrier can be exposed.
    LeaderChoiceLocked {
        consensus_round: RoundNumber,
        choice: LeaderChoiceV1,
    },
    /// One safety-preserving promise predicate became true.
    /// This lock is emitted at most once for an exact carrier and immediately
    /// precedes its `DeliveryPromised` effect.
    DeliveryPromiseLocked {
        target: BlockReference,
        basis: DeliveryPromiseBasisV1,
    },
    /// Bracha delivery became slot-global and immutable.
    DeliveryLocked(BlockReference),
    /// Existing non-durable output retained in its exact reducer order.
    Effect(ModelEffect),
}

/// Ordered typed input from which the executable model can be reconstructed.
///
/// `CandidateRetained` is ordinary candidate-only retention. The stricter
/// `CandidateRecovered` variant additionally requires prior phase evidence,
/// matching [`RbcDagModel::recover_carrier`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelInputRecord {
    CandidateRetained(CandidateCarrierV1),
    CandidateRecovered(CandidateCarrierV1),
    AuthenticatedIngress(AuthenticatedCarrierV1),
    LocalCarrierFixed(LocallyAuthenticatedCarrierV1),
    DataAvailable(BlockReference),
}

#[derive(Default)]
struct TransitionLog {
    trace: Vec<ModelTraceEvent>,
}

impl TransitionLog {
    fn proof(&mut self, event: ModelTraceEvent) {
        self.trace.push(event);
    }

    fn effect(&mut self, effect: ModelEffect) {
        self.trace.push(ModelTraceEvent::Effect(effect));
    }

    fn effects(&self) -> Vec<ModelEffect> {
        self.trace
            .iter()
            .filter_map(|entry| match entry {
                ModelTraceEvent::Effect(effect) => Some(effect.clone()),
                _ => None,
            })
            .collect()
    }
}

/// A transition evaluated against an immutable model revision.
///
/// Fields are deliberately private: the only way to install the planned state
/// is [`RbcDagModel::commit_plan`], which rejects a stale or foreign base.
#[derive(Clone)]
pub struct ModelTransitionPlan {
    base_revision: u64,
    base_lineage: ModelLineage,
    base_context: RbcDagContextV1,
    base_authority: AuthorityIndex,
    input: ModelInputRecord,
    trace: Vec<ModelTraceEvent>,
    next_model: RbcDagModel,
}

impl ModelTransitionPlan {
    /// The typed reducer input must be durably recorded before the ordered
    /// proof trace is persisted and this plan is committed.
    pub fn input(&self) -> &ModelInputRecord {
        &self.input
    }

    pub fn trace(&self) -> &[ModelTraceEvent] {
        &self.trace
    }

    pub fn effects(&self) -> Vec<ModelEffect> {
        self.trace
            .iter()
            .filter_map(|entry| match entry {
                ModelTraceEvent::Effect(effect) => Some(effect.clone()),
                _ => None,
            })
            .collect()
    }
}

/// Snapshot of the lifecycle predicates for one exact carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierLifecycle {
    pub authenticated: bool,
    pub admitted: bool,
    pub phase_batch_processed: bool,
    pub delivered: bool,
    pub certified_delivered: bool,
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
    RevisionOverflow,
    StaleTransitionPlan {
        expected_revision: u64,
        actual_revision: u64,
    },
    ForeignTransitionPlan,
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
    certified_delivered: bool,
    data_available: bool,
    prefix_closed: bool,
}

impl CarrierRecord {
    fn new(carrier: CandidateCarrierV1, data_available: bool) -> Self {
        Self {
            carrier,
            authenticated: false,
            admitted: false,
            phase_batch_cursor: 0,
            delivered: false,
            certified_delivered: false,
            data_available,
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
            certified_delivered: self.certified_delivered,
            data_available: self.data_available,
            prefix_closed: self.prefix_closed,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RbcCandidateState {
    echoes: BTreeSet<AuthorityIndex>,
    votes: BTreeSet<AuthorityIndex>,
    acks: BTreeSet<AuthorityIndex>,
    readies: BTreeSet<AuthorityIndex>,
    requested_holders: BTreeSet<AuthorityIndex>,
}

impl RbcCandidateState {
    fn holders(&self) -> BTreeSet<AuthorityIndex> {
        self.echoes
            .iter()
            .chain(&self.votes)
            .chain(&self.acks)
            .chain(&self.readies)
            .copied()
            .collect()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RbcSlotState {
    echoed: Option<BlockReference>,
    voted: Option<BlockReference>,
    acked: Option<BlockReference>,
    readied: Option<BlockReference>,
    delivered: Option<BlockReference>,
    certified_delivered: Option<BlockReference>,
    echo_by_sender: BTreeMap<AuthorityIndex, BlockReference>,
    vote_by_sender: BTreeMap<AuthorityIndex, BlockReference>,
    ack_by_sender: BTreeMap<AuthorityIndex, BlockReference>,
    ready_by_sender: BTreeMap<AuthorityIndex, BlockReference>,
    candidates: BTreeMap<BlockReference, RbcCandidateState>,
}

#[derive(Clone, Copy)]
enum RbcAction {
    NeedCarrier,
    SendVote,
    SendAck,
    SendReady,
    CertifyDelivery,
    None,
}

/// Exact integer thresholds for one target-author slot.
///
/// `fault = floor((W - 1) / 3)` is the greatest integer Byzantine stake
/// strictly below one third. ECHO, VOTE, and ACK exclude the target author.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RbcThresholds {
    fault: Stake,
    ready_validity: Stake,
    ready_quorum: Stake,
    optimistic: Option<OptimisticThresholds>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OptimisticThresholds {
    vote_from_echo: Stake,
    converge: Stake,
    promise_from_echo: Stake,
}

/// Pure local state machine used by the milestone-two simulations.
#[derive(Clone)]
pub struct RbcDagModel {
    committee: Arc<Committee>,
    total_committee_stake: Stake,
    committee_id: RbcDagCommitteeId,
    context: RbcDagContextV1,
    own_authority: AuthorityIndex,
    intrinsic_empty_data_available: bool,
    revision: u64,
    lineage: ModelLineage,
    local_carrier_round: RoundNumber,
    own_fixed: BTreeMap<RoundNumber, BlockReference>,
    carriers: BTreeMap<BlockReference, CarrierRecord>,
    authenticated_by_slot: BTreeMap<(RoundNumber, AuthorityIndex), BlockReference>,
    admitted_by_slot: BTreeMap<(RoundNumber, AuthorityIndex), BlockReference>,
    rbc_slots: BTreeMap<(RoundNumber, AuthorityIndex), RbcSlotState>,
    pending_phases: VecDeque<RbcPhaseStatementV1>,
    pending_phase_set: BTreeSet<RbcPhaseStatementV1>,
    pending_delivered_batch_replays: VecDeque<BlockReference>,
    delivery_promises: BTreeMap<BlockReference, DeliveryPromiseBasisV1>,
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
        let total_committee_stake =
            committee.authorities().try_fold(0u64, |total, authority| {
                total
                    .checked_add(
                        committee
                            .get_stake(authority)
                            .ok_or(ModelError::UnknownAuthority(authority))?,
                    )
                    .ok_or(ModelError::InvalidCommittee)
            })?;
        let prefix_tips = committee
            .authorities()
            .map(carrier_genesis_reference)
            .collect();
        Ok(Self {
            included_frontier: vec![None; committee.len()],
            committee,
            total_committee_stake,
            committee_id,
            context,
            own_authority,
            intrinsic_empty_data_available: false,
            revision: 0,
            lineage: [0; 32],
            local_carrier_round: 1,
            own_fixed: BTreeMap::new(),
            carriers: BTreeMap::new(),
            authenticated_by_slot: BTreeMap::new(),
            admitted_by_slot: BTreeMap::new(),
            rbc_slots: BTreeMap::new(),
            pending_phases: VecDeque::new(),
            pending_phase_set: BTreeSet::new(),
            pending_delivered_batch_replays: VecDeque::new(),
            delivery_promises: BTreeMap::new(),
            prefix_tips,
            included: BTreeSet::new(),
        })
    }

    /// Enable the runtime rule that a carrier with the canonical empty
    /// transaction commitment needs no external reconstruction oracle. The
    /// generic M2 model leaves this disabled so tests can control DA
    /// independently of carrier contents.
    pub fn enable_intrinsic_empty_data_availability(&mut self) {
        assert!(
            self.carriers.is_empty(),
            "intrinsic availability mode must be fixed before ingress"
        );
        self.intrinsic_empty_data_available = true;
    }

    pub fn own_authority(&self) -> AuthorityIndex {
        self.own_authority
    }

    pub fn context(&self) -> RbcDagContextV1 {
        self.context
    }

    /// Monotonic reducer revision used to reject a plan computed from stale
    /// state. It is advanced once per successfully applied typed input record.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Evaluate one typed input against a clone without changing live state.
    /// A durable adapter records [`ModelTransitionPlan::input`] first, then
    /// [`ModelTransitionPlan::trace`] in order, and commits only after both
    /// writes are durable.
    pub fn plan_input(&self, input: ModelInputRecord) -> Result<ModelTransitionPlan, ModelError> {
        let mut next_model = self.clone();
        let log = next_model.apply_input_traced(input.clone())?;
        Ok(ModelTransitionPlan {
            base_revision: self.revision,
            base_lineage: self.lineage,
            base_context: self.context,
            base_authority: self.own_authority,
            input,
            trace: log.trace,
            next_model,
        })
    }

    /// Atomically install a previously planned state after its ordered trace
    /// has been durably recorded by the caller.
    pub fn commit_plan(
        &mut self,
        plan: ModelTransitionPlan,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        if self.context != plan.base_context || self.own_authority != plan.base_authority {
            return Err(ModelError::ForeignTransitionPlan);
        }
        if self.revision != plan.base_revision {
            return Err(ModelError::StaleTransitionPlan {
                expected_revision: plan.base_revision,
                actual_revision: self.revision,
            });
        }
        if self.lineage != plan.base_lineage {
            return Err(ModelError::ForeignTransitionPlan);
        }
        let effects = plan.effects();
        *self = plan.next_model;
        Ok(effects)
    }

    /// Apply one typed record immediately. Runtime adapters that need
    /// write-ahead durability should use [`Self::plan_input`] and
    /// [`Self::commit_plan`] instead.
    pub fn apply_input(&mut self, input: ModelInputRecord) -> Result<Vec<ModelEffect>, ModelError> {
        self.apply_input_traced(input).map(|log| log.effects())
    }

    /// Apply a transition before any of its effects are externally exposed.
    /// The durable actor uses this fail-stop path to avoid cloning the entire
    /// retained reducer history for every carrier. If persistence of the
    /// returned trace fails, the caller must poison and terminate the actor;
    /// it must never publish the returned effects.
    pub(crate) fn apply_input_unpublished(
        &mut self,
        input: ModelInputRecord,
    ) -> Result<(Vec<ModelTraceEvent>, Vec<ModelEffect>), ModelError> {
        let log = self.apply_input_traced(input)?;
        let effects = log.effects();
        Ok((log.trace, effects))
    }

    /// Deterministically reconstruct a model by replaying the original typed
    /// inputs in their recorded order. No round or lock is synthesized.
    pub fn replay_from_records<I>(
        committee: Arc<Committee>,
        own_authority: AuthorityIndex,
        context: RbcDagContextV1,
        records: I,
    ) -> Result<(Self, Vec<ModelTraceEvent>), ModelError>
    where
        I: IntoIterator<Item = ModelInputRecord>,
    {
        let mut model = Self::new(committee, own_authority, context)?;
        let mut trace = Vec::new();
        for record in records {
            trace.extend(model.apply_input_traced(record)?.trace);
        }
        Ok((model, trace))
    }

    fn apply_input_traced(&mut self, input: ModelInputRecord) -> Result<TransitionLog, ModelError> {
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(ModelError::RevisionOverflow)?;
        let next_lineage = self.input_lineage(&input);
        let mut log = TransitionLog::default();
        match input {
            ModelInputRecord::CandidateRetained(carrier) => {
                self.receive_carrier_traced(
                    carrier,
                    IngressAuthentication::CandidateOnly,
                    &mut log,
                )?;
            }
            ModelInputRecord::CandidateRecovered(carrier) => {
                self.recover_carrier_traced(carrier, &mut log)?;
            }
            ModelInputRecord::AuthenticatedIngress(authenticated) => {
                self.receive_authenticated_traced(authenticated, &mut log)?;
            }
            ModelInputRecord::LocalCarrierFixed(authenticated) => {
                self.start_local_carrier_traced(authenticated, &mut log)?;
            }
            ModelInputRecord::DataAvailable(reference) => {
                self.mark_data_available_traced(reference, &mut log)?;
            }
        }
        self.lineage = next_lineage;
        self.revision = next_revision;
        Ok(log)
    }

    fn input_lineage(&self, input: &ModelInputRecord) -> ModelLineage {
        let (kind, reference) = match input {
            ModelInputRecord::CandidateRetained(carrier) => (0, carrier.reference()),
            ModelInputRecord::CandidateRecovered(carrier) => (1, carrier.reference()),
            ModelInputRecord::AuthenticatedIngress(carrier) => (2, carrier.reference()),
            ModelInputRecord::LocalCarrierFixed(carrier) => (3, carrier.reference()),
            ModelInputRecord::DataAvailable(reference) => (4, *reference),
        };
        let mut hasher = Blake3Hasher::new_derive_key(MODEL_LINEAGE_DERIVE_CONTEXT);
        hasher.update(&self.lineage);
        hasher.update(&[kind]);
        update_lineage_reference(&mut hasher, reference);
        hasher.finalize().into()
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
            .saturating_mul(6)
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
    /// generated phase statements are left for a later carrier.
    pub fn start_local_carrier(
        &mut self,
        authenticated: LocallyAuthenticatedCarrierV1,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        self.apply_input(ModelInputRecord::LocalCarrierFixed(authenticated))
    }

    fn start_local_carrier_traced(
        &mut self,
        authenticated: LocallyAuthenticatedCarrierV1,
        log: &mut TransitionLog,
    ) -> Result<(), ModelError> {
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
        // write order. The exact local carrier must be fixed before any local
        // phase statement is authorized or any embedded statement is exposed.
        self.preflight_receive(&carrier)?;
        self.own_fixed.insert(round, reference);
        log.proof(ModelTraceEvent::LocalCarrierFixed(reference));
        if let Some(vertex) = header.consensus_vertex() {
            log.proof(ModelTraceEvent::ConsensusSlotLocked {
                consensus_round: vertex.consensus_round(),
                enclosing_carrier: reference,
            });
            log.proof(ModelTraceEvent::LeaderChoiceLocked {
                consensus_round: vertex.consensus_round(),
                choice: vertex.leader_choice(),
            });
        }
        self.lock_delivery_promise(reference, DeliveryPromiseBasisV1::LocalFixed, log);
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
        self.apply_received_carrier(carrier, IngressAuthentication::Authenticated, log);
        self.maybe_advance_fast_clock(log);
        Ok(())
    }

    /// Stage canonical content without granting optimistic admission or ECHO.
    pub fn stage_candidate(
        &mut self,
        carrier: CandidateCarrierV1,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        self.apply_input(ModelInputRecord::CandidateRetained(carrier))
    }

    /// Admit a carrier only through the opaque capability produced by the
    /// codec's context- and receiver-bound authenticator verifier.
    pub fn receive_authenticated(
        &mut self,
        authenticated: AuthenticatedCarrierV1,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        self.apply_input(ModelInputRecord::AuthenticatedIngress(authenticated))
    }

    fn receive_authenticated_traced(
        &mut self,
        authenticated: AuthenticatedCarrierV1,
        log: &mut TransitionLog,
    ) -> Result<(), ModelError> {
        self.ensure_authenticated(&authenticated)?;
        if authenticated.candidate().header().author() == self.own_authority {
            return Err(ModelError::LocalCarrierRequiresStart(
                authenticated.candidate().reference(),
            ));
        }
        self.receive_carrier_traced(
            authenticated.candidate().clone(),
            IngressAuthentication::Authenticated,
            log,
        )
    }

    fn receive_carrier_traced(
        &mut self,
        carrier: CandidateCarrierV1,
        authentication: IngressAuthentication,
        log: &mut TransitionLog,
    ) -> Result<(), ModelError> {
        self.preflight_receive(&carrier)?;
        self.apply_received_carrier(carrier, authentication, log);
        Ok(())
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
        log: &mut TransitionLog,
    ) {
        let reference = carrier.reference();
        let intrinsic_data_available = self.intrinsic_empty_data_available
            && carrier.header().transactions_commitment() == TransactionsCommitment::default();
        self.carriers
            .entry(reference)
            .or_insert_with(|| CarrierRecord::new(carrier, intrinsic_data_available));

        // Canonical content can satisfy a previously latched recovery even if
        // the receiver-specific authenticator is invalid.
        self.drive_rbc(reference, log);

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
            if selected && self.target_author_is_honest(reference.authority) {
                // This capability authenticates the exact target-author bytes
                // to this receiver. If the author's stake exceeds F, the
                // fault model itself rules out author equivocation.
                self.lock_delivery_promise(reference, DeliveryPromiseBasisV1::HonestAuthor, log);
            }
            if selected && self.in_admission_window(reference.round) {
                self.promote_authenticated(reference, log);
            }
        }
        // A locally fixed promise is persisted before the carrier is inserted
        // above. Activate every already-locked fast-delivery predicate only
        // after exact content exists, and defer phase-batch replay until the
        // current reducer input finishes.
        self.activate_delivery_promise(reference, log);
        self.maybe_advance_fast_clock(log);
        self.drain_delivered_phase_batches(log);
    }

    /// Accept an exact recovered carrier only after authenticated phase
    /// evidence allocated its candidate.
    pub fn recover_carrier(
        &mut self,
        carrier: CandidateCarrierV1,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        self.apply_input(ModelInputRecord::CandidateRecovered(carrier))
    }

    fn recover_carrier_traced(
        &mut self,
        carrier: CandidateCarrierV1,
        log: &mut TransitionLog,
    ) -> Result<(), ModelError> {
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
        self.receive_carrier_traced(carrier, IngressAuthentication::CandidateOnly, log)
    }

    /// Record transaction-data availability established by the external
    /// Reed-Solomon/reconstruction layer after it verifies this carrier's
    /// commitment. Milestone two intentionally treats that layer as a trusted
    /// oracle; it does not infer this predicate from unauthenticated ACKs.
    pub fn mark_data_available(
        &mut self,
        reference: BlockReference,
    ) -> Result<Vec<ModelEffect>, ModelError> {
        self.apply_input(ModelInputRecord::DataAvailable(reference))
    }

    fn mark_data_available_traced(
        &mut self,
        reference: BlockReference,
        log: &mut TransitionLog,
    ) -> Result<(), ModelError> {
        self.carriers
            .get_mut(&reference)
            .ok_or(ModelError::MissingCarrier(reference))?
            .data_available = true;
        self.drive_prefix(reference.authority, log);
        Ok(())
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

    /// Return the exact value that reached the fallback `Q`-READY
    /// certificate, independently of an earlier optimistic delivery.
    pub fn certified_delivered(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Option<BlockReference> {
        self.rbc_slots
            .get(&(round, authority))
            .and_then(|slot| slot.certified_delivered)
    }

    pub fn certified_delivery_count(&self) -> usize {
        self.rbc_slots
            .values()
            .filter(|slot| slot.certified_delivered.is_some())
            .count()
    }

    /// Return the first durable fast-delivery basis for this exact carrier.
    pub fn delivery_promise_basis(
        &self,
        reference: &BlockReference,
    ) -> Option<DeliveryPromiseBasisV1> {
        self.delivery_promises.get(reference).copied()
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
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(ModelError::RevisionOverflow)?;
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
        self.advance_frontier_lineage(frontier);
        self.revision = next_revision;
        Ok(delta.into_iter().collect())
    }

    fn advance_frontier_lineage(&mut self, frontier: &[Option<BlockReference>]) {
        let mut hasher = Blake3Hasher::new_derive_key(MODEL_LINEAGE_DERIVE_CONTEXT);
        hasher.update(&self.lineage);
        hasher.update(&[5]);
        hasher.update(&(frontier.len() as u64).to_be_bytes());
        for reference in frontier {
            match reference {
                Some(reference) => {
                    hasher.update(&[1]);
                    update_lineage_reference(&mut hasher, *reference);
                }
                None => {
                    hasher.update(&[0]);
                }
            }
        }
        self.lineage = hasher.finalize().into();
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

    fn voters_stake_excluding(
        &self,
        voters: &BTreeSet<AuthorityIndex>,
        excluded: AuthorityIndex,
    ) -> Stake {
        voters.iter().fold(0, |stake, authority| {
            if *authority == excluded {
                stake
            } else {
                stake.saturating_add(self.authority_stake(*authority))
            }
        })
    }

    fn rbc_thresholds(&self, target_author: AuthorityIndex) -> Option<RbcThresholds> {
        let author_stake = self.committee.get_stake(target_author)?;
        let fault = self.total_committee_stake.checked_sub(1)? / 3;
        let ready_validity = fault.checked_add(1)?;
        let ready_quorum = self.total_committee_stake.checked_sub(fault)?;
        let optimistic = if author_stake <= fault {
            let non_author_stake = self.total_committee_stake.checked_sub(author_stake)?;
            let residual_fault = fault.checked_sub(author_stake)?;
            let vote_from_echo = non_author_stake.checked_div(2)?.checked_add(1)?;
            // floor((U + b) / 2) without overflowing the intermediate sum.
            let converge = (non_author_stake / 2)
                .checked_add(residual_fault / 2)?
                .checked_add((non_author_stake % 2 + residual_fault % 2) / 2)?
                .checked_add(1)?;
            let promise_from_echo = vote_from_echo.checked_add(residual_fault)?;
            Some(OptimisticThresholds {
                vote_from_echo,
                converge,
                promise_from_echo,
            })
        } else {
            None
        };
        Some(RbcThresholds {
            fault,
            ready_validity,
            ready_quorum,
            optimistic,
        })
    }

    fn target_author_is_honest(&self, target_author: AuthorityIndex) -> bool {
        self.rbc_thresholds(target_author)
            .is_some_and(|thresholds| thresholds.optimistic.is_none())
    }

    fn rbc_slot_mut(&mut self, reference: BlockReference) -> &mut RbcSlotState {
        self.rbc_slots
            .entry((reference.round, reference.authority))
            .or_default()
    }

    fn authorize_local_echo(&mut self, reference: BlockReference, log: &mut TransitionLog) {
        let own = self.own_authority;
        if own == reference.authority {
            // The target author is excluded from ECHO/VOTE/ACK. A locally
            // fixed high-stake author instead seeds READY: its stake is at
            // least F+1, so every correct receiver can safely amplify it.
            if self.target_author_is_honest(reference.authority) {
                self.authorize_local_ready(reference, log);
            }
            return;
        }
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
        let statement = RbcPhaseStatementV1::Echo { target: reference };
        log.proof(ModelTraceEvent::LocalPhaseLocked(statement));
        self.queue_local_phase(statement);
        self.drive_rbc(reference, log);
    }

    fn authorize_local_ready(&mut self, reference: BlockReference, log: &mut TransitionLog) {
        let own = self.own_authority;
        let slot = self.rbc_slot_mut(reference);
        if slot.readied.is_some() {
            return;
        }
        slot.readied = Some(reference);
        slot.ready_by_sender.insert(own, reference);
        slot.candidates
            .entry(reference)
            .or_default()
            .readies
            .insert(own);
        let statement = RbcPhaseStatementV1::Ready { target: reference };
        log.proof(ModelTraceEvent::LocalPhaseLocked(statement));
        self.queue_local_phase(statement);
        self.drive_rbc(reference, log);
    }

    fn queue_local_phase(&mut self, statement: RbcPhaseStatementV1) {
        if self.pending_phase_set.insert(statement) {
            self.pending_phases.push_back(statement);
        }
    }

    fn process_phase_batch(&mut self, outer: BlockReference, log: &mut TransitionLog) {
        self.process_phase_batch_steps(outer, usize::MAX, log);
        self.drain_delivered_phase_batches(log);
    }

    fn drain_delivered_phase_batches(&mut self, log: &mut TransitionLog) {
        while let Some(outer) = self.pending_delivered_batch_replays.pop_front() {
            self.process_phase_batch_steps(outer, usize::MAX, log);
        }
    }

    fn process_phase_batch_steps(
        &mut self,
        outer: BlockReference,
        maximum_steps: usize,
        log: &mut TransitionLog,
    ) {
        let mut processed = 0;
        loop {
            if processed == maximum_steps {
                return;
            }
            let Some((index, sender, statement)) = self.carriers.get(&outer).and_then(|record| {
                let index = record.phase_batch_cursor;
                record
                    .carrier
                    .header()
                    .phase_batch()
                    .get(index)
                    .copied()
                    .map(|statement| (index, record.carrier.header().author(), statement))
            }) else {
                return;
            };
            // Applying the statement is idempotent. Advance the persisted
            // cursor only afterwards, so a crash between the two replays the
            // same statement rather than skipping the unprocessed tail.
            log.proof(ModelTraceEvent::PhaseBatchEntryApplied {
                outer,
                index,
                sender,
                statement,
            });
            self.record_phase(sender, statement, log);
            let next_index = {
                let record = self
                    .carriers
                    .get_mut(&outer)
                    .expect("the outer carrier remains pinned");
                record.phase_batch_cursor += 1;
                record.phase_batch_cursor
            };
            log.proof(ModelTraceEvent::PhaseBatchCursorAdvanced {
                outer,
                index,
                next_index,
            });
            processed += 1;
        }
    }

    fn record_phase(
        &mut self,
        sender: AuthorityIndex,
        statement: RbcPhaseStatementV1,
        log: &mut TransitionLog,
    ) {
        if !self.committee.known_authority(sender) {
            return;
        }
        let target = statement.target();
        if !self.committee.known_authority(target.authority) || target.round == 0 {
            return;
        }
        if sender == target.authority
            && matches!(
                statement,
                RbcPhaseStatementV1::Echo { .. }
                    | RbcPhaseStatementV1::Vote { .. }
                    | RbcPhaseStatementV1::Ack { .. }
            )
        {
            // The broadcaster may equivocate. Its stake is deliberately
            // excluded from every optimistic certificate phase.
            return;
        }
        if sender == self.own_authority {
            let authorized = self
                .rbc_slots
                .get(&(target.round, target.authority))
                .is_some_and(|slot| match statement {
                    RbcPhaseStatementV1::Echo { .. } => slot.echoed == Some(target),
                    RbcPhaseStatementV1::Vote { .. } => slot.voted == Some(target),
                    RbcPhaseStatementV1::Ack { .. } => slot.acked == Some(target),
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
            RbcPhaseStatementV1::Vote { .. } => &mut slot.vote_by_sender,
            RbcPhaseStatementV1::Ack { .. } => &mut slot.ack_by_sender,
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
            RbcPhaseStatementV1::Vote { .. } => {
                candidate.votes.insert(sender);
            }
            RbcPhaseStatementV1::Ack { .. } => {
                candidate.acks.insert(sender);
            }
            RbcPhaseStatementV1::Ready { .. } => {
                candidate.readies.insert(sender);
            }
        }
        self.drive_rbc(target, log);
    }

    fn lock_delivery_promise(
        &mut self,
        target: BlockReference,
        basis: DeliveryPromiseBasisV1,
        log: &mut TransitionLog,
    ) {
        if self.delivery_promises.contains_key(&target) {
            return;
        }
        if self
            .rbc_slots
            .get(&(target.round, target.authority))
            .and_then(|slot| slot.delivered)
            .is_some_and(|delivered| delivered != target)
        {
            // Integrity is enforced locally even though the optimistic and
            // fallback quorum proofs already rule out conflicting honest
            // deliveries.
            return;
        }
        self.delivery_promises.insert(target, basis);
        log.proof(ModelTraceEvent::DeliveryPromiseLocked { target, basis });
        log.effect(ModelEffect::DeliveryPromised(target));
        self.activate_delivery_promise(target, log);
    }

    fn activate_delivery_promise(&mut self, target: BlockReference, log: &mut TransitionLog) {
        let Some(basis) = self.delivery_promises.get(&target).copied() else {
            return;
        };
        if basis == DeliveryPromiseBasisV1::Delivered || !self.carriers.contains_key(&target) {
            return;
        }
        let slot = self.rbc_slot_mut(target);
        match slot.delivered {
            Some(existing) if existing != target => return,
            Some(_) => return,
            None => slot.delivered = Some(target),
        }
        self.carriers
            .get_mut(&target)
            .expect("fast delivery requires exact canonical carrier content")
            .delivered = true;
        self.pending_delivered_batch_replays.push_back(target);
        self.drive_prefix(target.authority, log);
    }

    fn drive_rbc(&mut self, target: BlockReference, log: &mut TransitionLog) {
        let slot_key = (target.round, target.authority);
        if !self
            .rbc_slots
            .get(&slot_key)
            .is_some_and(|slot| slot.candidates.contains_key(&target))
        {
            // Merely staging canonical content is not authenticated RBC
            // evidence. Candidate state is allocated only by a locally
            // authorized phase or an embedded phase statement.
            return;
        }
        let Some(thresholds) = self.rbc_thresholds(target.authority) else {
            return;
        };
        loop {
            let header_available = self.carriers.contains_key(&target);
            let (echo_stake, vote_stake, ack_stake, ready_stake) = {
                let candidate = self
                    .rbc_slots
                    .get(&slot_key)
                    .and_then(|slot| slot.candidates.get(&target))
                    .expect("the candidate remains allocated");
                (
                    self.voters_stake_excluding(&candidate.echoes, target.authority),
                    self.voters_stake_excluding(&candidate.votes, target.authority),
                    self.voters_stake_excluding(&candidate.acks, target.authority),
                    self.voters_stake(&candidate.readies),
                )
            };
            let (vote_trigger, ack_trigger, optimistic_ready_trigger, promise_trigger) = thresholds
                .optimistic
                .map_or((false, false, false, false), |optimistic| {
                    (
                        echo_stake >= optimistic.vote_from_echo,
                        echo_stake >= optimistic.converge || vote_stake >= optimistic.converge,
                        ack_stake >= optimistic.converge,
                        echo_stake >= optimistic.promise_from_echo,
                    )
                });
            let ready_trigger =
                optimistic_ready_trigger || ready_stake >= thresholds.ready_validity;
            let deliver_trigger = ready_stake >= thresholds.ready_quorum;
            let promise_missing = !self.delivery_promises.contains_key(&target);

            // A promise names exact canonical content, never a digest learned
            // only from phase evidence.
            if header_available && promise_missing && promise_trigger {
                self.lock_delivery_promise(target, DeliveryPromiseBasisV1::OptimisticEcho, log);
            }
            let can_send_optimistic_phase = self.own_authority != target.authority;
            let action = {
                let slot = self.rbc_slot_mut(target);
                let candidate = slot.candidates.entry(target).or_default();
                let needs_header = !header_available
                    && ((slot.voted.is_none() && can_send_optimistic_phase && vote_trigger)
                        || (slot.acked.is_none() && can_send_optimistic_phase && ack_trigger)
                        || (slot.readied.is_none() && ready_trigger)
                        || (slot.certified_delivered.is_none() && deliver_trigger)
                        || (promise_missing && promise_trigger));
                if needs_header {
                    let holders = candidate.holders();
                    if holders != candidate.requested_holders {
                        candidate.requested_holders = holders;
                        RbcAction::NeedCarrier
                    } else {
                        RbcAction::None
                    }
                } else if header_available
                    && slot.voted.is_none()
                    && can_send_optimistic_phase
                    && vote_trigger
                {
                    RbcAction::SendVote
                } else if header_available
                    && slot.acked.is_none()
                    && can_send_optimistic_phase
                    && ack_trigger
                {
                    RbcAction::SendAck
                } else if header_available && slot.readied.is_none() && ready_trigger {
                    RbcAction::SendReady
                } else if header_available && slot.certified_delivered.is_none() && deliver_trigger
                {
                    RbcAction::CertifyDelivery
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
                    log.effect(ModelEffect::NeedCarrier { target, holders });
                    break;
                }
                RbcAction::SendVote => {
                    let own = self.own_authority;
                    let slot = self.rbc_slot_mut(target);
                    slot.voted = Some(target);
                    slot.vote_by_sender.insert(own, target);
                    slot.candidates.entry(target).or_default().votes.insert(own);
                    let statement = RbcPhaseStatementV1::Vote { target };
                    log.proof(ModelTraceEvent::LocalPhaseLocked(statement));
                    self.queue_local_phase(statement);
                }
                RbcAction::SendAck => {
                    let own = self.own_authority;
                    let slot = self.rbc_slot_mut(target);
                    slot.acked = Some(target);
                    slot.ack_by_sender.insert(own, target);
                    slot.candidates.entry(target).or_default().acks.insert(own);
                    let statement = RbcPhaseStatementV1::Ack { target };
                    log.proof(ModelTraceEvent::LocalPhaseLocked(statement));
                    self.queue_local_phase(statement);
                }
                RbcAction::SendReady => {
                    self.authorize_local_ready(target, log);
                }
                RbcAction::CertifyDelivery => {
                    let slot = self.rbc_slot_mut(target);
                    if slot.delivered.is_some_and(|delivered| delivered != target) {
                        break;
                    }
                    slot.delivered = Some(target);
                    slot.certified_delivered = Some(target);
                    let record = self
                        .carriers
                        .get_mut(&target)
                        .expect("delivery requires exact canonical carrier content");
                    record.delivered = true;
                    record.certified_delivered = true;
                    log.proof(ModelTraceEvent::DeliveryLocked(target));
                    self.lock_delivery_promise(target, DeliveryPromiseBasisV1::Delivered, log);
                    log.effect(ModelEffect::Delivered(target));
                    self.pending_delivered_batch_replays.push_back(target);
                    self.drive_prefix(target.authority, log);
                }
                RbcAction::None => break,
            }
        }
    }

    fn maybe_advance_fast_clock(&mut self, log: &mut TransitionLog) {
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
        log.effect(ModelEffect::CarrierRoundAdvanced(self.local_carrier_round));
        self.promote_buffered_window(log);
    }

    fn in_admission_window(&self, round: RoundNumber) -> bool {
        round
            <= self
                .local_carrier_round
                .saturating_add(EXECUTABLE_MODEL_ADMISSION_WINDOW_V1)
    }

    fn promote_authenticated(&mut self, reference: BlockReference, log: &mut TransitionLog) {
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
        log.proof(ModelTraceEvent::AdmissionLocked(reference));
        self.authorize_local_echo(reference, log);
        self.process_phase_batch(reference, log);
    }

    fn promote_buffered_window(&mut self, log: &mut TransitionLog) {
        let eligible: Vec<_> = self
            .authenticated_by_slot
            .values()
            .copied()
            .filter(|reference| self.in_admission_window(reference.round))
            .collect();
        for reference in eligible {
            self.promote_authenticated(reference, log);
        }
    }

    fn drive_prefix(&mut self, authority: AuthorityIndex, log: &mut TransitionLog) {
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
            log.effect(ModelEffect::PrefixAdvanced {
                authority,
                tip: next,
            });
        }
    }
}

fn update_lineage_reference(hasher: &mut Blake3Hasher, reference: BlockReference) {
    hasher.update(&reference.authority.to_be_bytes());
    hasher.update(&reference.round.to_be_bytes());
    hasher.update(reference.digest.as_array());
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
                application_header: None,
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
        // ECHO, VOTE/ACK, and READY are embedded in later carriers. Seven
        // carrier rounds make the first four rounds mature end-to-end.
        for round in 1..=7 {
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
    fn planned_authenticated_ingress_locks_admission_before_echo() {
        let committee = committee(4);
        let model = model(Arc::clone(&committee), 3);
        let (own_prev, weak_parents) = genesis_parents(&committee, 0);
        let carrier =
            candidate(&committee, 0, 1, own_prev, weak_parents, Vec::new(), 0xD0).unwrap();
        let target = carrier.reference();
        let authenticated = authenticate_for(&committee, &carrier, 3);
        let plan = model
            .plan_input(ModelInputRecord::AuthenticatedIngress(authenticated))
            .unwrap();

        let admission = plan
            .trace()
            .iter()
            .position(|event| *event == ModelTraceEvent::AdmissionLocked(target))
            .unwrap();
        let echo = plan
            .trace()
            .iter()
            .position(|event| {
                *event == ModelTraceEvent::LocalPhaseLocked(RbcPhaseStatementV1::Echo { target })
            })
            .unwrap();
        assert!(admission < echo);
        assert_eq!(model.revision(), 0);
        assert!(model.lifecycle(&target).is_none());
    }

    #[test]
    fn phase_application_precedes_ready_and_ready_precedes_delivery() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let (own_prev, weak_parents) = genesis_parents(&committee, 0);
        let target_carrier =
            candidate(&committee, 0, 1, own_prev, weak_parents, Vec::new(), 0xD1).unwrap();
        let target = target_carrier.reference();
        model.stage_candidate(target_carrier).unwrap();
        // One remote READY is below V. The enclosing carrier supplies the
        // second; the resulting local READY is then the third vote and delivers.
        let mut setup = TransitionLog::default();
        model.record_phase(0, RbcPhaseStatementV1::Ready { target }, &mut setup);

        let outer = candidate(
            &committee,
            1,
            2,
            BlockReference::new_test(1, 1),
            vec![
                BlockReference::new_test(0, 1),
                BlockReference::new_test(2, 1),
            ],
            vec![RbcPhaseStatementV1::Ready { target }],
            0xD2,
        )
        .unwrap();
        let outer_reference = outer.reference();
        let authenticated = authenticate_for(&committee, &outer, 3);
        let plan = model
            .plan_input(ModelInputRecord::AuthenticatedIngress(authenticated))
            .unwrap();
        let trace = plan.trace();

        let applied = trace
            .iter()
            .position(|event| {
                matches!(
                    event,
                    ModelTraceEvent::PhaseBatchEntryApplied {
                        outer,
                        index: 0,
                        sender: 1,
                        statement: RbcPhaseStatementV1::Ready { target: actual },
                    } if *outer == outer_reference && *actual == target
                )
            })
            .unwrap();
        let ready = trace
            .iter()
            .position(|event| {
                *event == ModelTraceEvent::LocalPhaseLocked(RbcPhaseStatementV1::Ready { target })
            })
            .unwrap();
        let delivery = trace
            .iter()
            .position(|event| *event == ModelTraceEvent::DeliveryLocked(target))
            .unwrap();
        let cursor = trace
            .iter()
            .position(|event| {
                matches!(
                    event,
                    ModelTraceEvent::PhaseBatchCursorAdvanced {
                        outer,
                        index: 0,
                        next_index: 1,
                    } if *outer == outer_reference
                )
            })
            .unwrap();
        assert!(applied < ready);
        assert!(ready < delivery);
        assert!(delivery < cursor);
    }

    #[test]
    fn delivery_lock_precedes_replay_of_the_delivered_carrier_batch() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let replay_target = BlockReference::new_test(2, 1);
        let target_carrier = candidate(
            &committee,
            0,
            2,
            BlockReference::new_test(0, 1),
            vec![
                BlockReference::new_test(1, 1),
                BlockReference::new_test(2, 1),
            ],
            vec![RbcPhaseStatementV1::Echo {
                target: replay_target,
            }],
            0xD3,
        )
        .unwrap();
        let target = target_carrier.reference();
        model.stage_candidate(target_carrier).unwrap();
        let mut setup = TransitionLog::default();
        model.record_phase(0, RbcPhaseStatementV1::Ready { target }, &mut setup);

        let outer = candidate(
            &committee,
            1,
            3,
            BlockReference::new_test(1, 2),
            vec![
                BlockReference::new_test(0, 2),
                BlockReference::new_test(2, 2),
            ],
            vec![RbcPhaseStatementV1::Ready { target }],
            0xD4,
        )
        .unwrap();
        let authenticated = authenticate_for(&committee, &outer, 3);
        let plan = model
            .plan_input(ModelInputRecord::AuthenticatedIngress(authenticated))
            .unwrap();
        let trace = plan.trace();
        let delivery = trace
            .iter()
            .position(|event| *event == ModelTraceEvent::DeliveryLocked(target))
            .unwrap();
        let replay = trace
            .iter()
            .position(|event| {
                matches!(
                    event,
                    ModelTraceEvent::PhaseBatchEntryApplied {
                        outer,
                        index: 0,
                        sender: 0,
                        statement: RbcPhaseStatementV1::Echo { target: actual },
                    } if *outer == target && *actual == replay_target
                )
            })
            .unwrap();
        assert!(delivery < replay);
    }

    #[test]
    fn planned_transition_is_rollback_safe_and_rejects_stale_or_divergent_commits() {
        let committee = committee(4);
        let mut live = model(Arc::clone(&committee), 3);
        let (own_prev, weak_parents) = genesis_parents(&committee, 0);
        let carrier =
            candidate(&committee, 0, 1, own_prev, weak_parents, Vec::new(), 0xD5).unwrap();
        let reference = carrier.reference();
        let authenticated = authenticate_for(&committee, &carrier, 3);
        let plan = live
            .plan_input(ModelInputRecord::AuthenticatedIngress(
                authenticated.clone(),
            ))
            .unwrap();

        // Planning and dropping a clone cannot expose any live transition.
        assert_eq!(live.revision(), 0);
        assert!(live.lifecycle(&reference).is_none());
        let mut committed = live.clone();
        committed.commit_plan(plan.clone()).unwrap();
        assert_eq!(committed.revision(), 1);
        assert!(committed.lifecycle(&reference).unwrap().admitted);
        assert!(live.lifecycle(&reference).is_none());

        // Any intervening successful input invalidates the old base revision.
        live.stage_candidate(carrier).unwrap();
        assert_eq!(live.revision(), 1);
        assert_eq!(
            live.commit_plan(plan),
            Err(ModelError::StaleTransitionPlan {
                expected_revision: 0,
                actual_revision: 1,
            })
        );
        let lifecycle = live.lifecycle(&reference).unwrap();
        assert!(!lifecycle.authenticated);
        assert!(!lifecycle.admitted);

        // Equal revision numbers do not make independently evolved clones
        // interchangeable: their private lineages bind a plan to its exact
        // base state.
        let divergent_plan = committed
            .plan_input(ModelInputRecord::DataAvailable(reference))
            .unwrap();
        assert_eq!(
            live.commit_plan(divergent_plan),
            Err(ModelError::ForeignTransitionPlan)
        );
        let lifecycle = live.lifecycle(&reference).unwrap();
        assert!(!lifecycle.authenticated);
        assert!(!lifecycle.data_available);
    }

    #[test]
    fn ordered_typed_replay_reconstructs_rounds_and_local_locks() {
        let committee = committee(4);
        let context = context(&committee);
        let mut live = RbcDagModel::new(Arc::clone(&committee), 3, context).unwrap();
        let mut records = Vec::new();
        let mut references = Vec::new();

        let (own_prev, weak_parents) = live.local_parent_set().unwrap();
        let local_one = candidate(
            &committee,
            3,
            1,
            own_prev,
            weak_parents,
            live.pending_phase_batch(),
            0xE0,
        )
        .unwrap();
        let local_one_record =
            ModelInputRecord::LocalCarrierFixed(authenticate_local(&committee, &local_one));
        live.apply_input(local_one_record.clone()).unwrap();
        records.push(local_one_record);
        references.push(local_one.reference());

        let mut round_one = BTreeMap::new();
        for (author, marker) in [(0, 0xE1), (1, 0xE2)] {
            let (own_prev, weak_parents) = genesis_parents(&committee, author);
            let carrier = candidate(
                &committee,
                author,
                1,
                own_prev,
                weak_parents,
                Vec::new(),
                marker,
            )
            .unwrap();
            if author == 0 {
                let retained = ModelInputRecord::CandidateRetained(carrier.clone());
                live.apply_input(retained.clone()).unwrap();
                records.push(retained);
            }
            let ingress =
                ModelInputRecord::AuthenticatedIngress(authenticate_for(&committee, &carrier, 3));
            live.apply_input(ingress.clone()).unwrap();
            records.push(ingress);
            references.push(carrier.reference());
            round_one.insert(author, carrier);
        }
        assert_eq!(live.local_carrier_round(), 2);

        let (own_prev, weak_parents) = live.local_parent_set().unwrap();
        let local_two = candidate(
            &committee,
            3,
            2,
            own_prev,
            weak_parents,
            live.pending_phase_batch(),
            0xE3,
        )
        .unwrap();
        let local_two_record =
            ModelInputRecord::LocalCarrierFixed(authenticate_local(&committee, &local_two));
        live.apply_input(local_two_record.clone()).unwrap();
        records.push(local_two_record);
        references.push(local_two.reference());

        for (author, marker, other) in [(0, 0xE4, 1), (1, 0xE5, 0)] {
            let carrier = candidate(
                &committee,
                author,
                2,
                round_one[&author].reference(),
                vec![round_one[&other].reference(), local_one.reference()],
                Vec::new(),
                marker,
            )
            .unwrap();
            let ingress =
                ModelInputRecord::AuthenticatedIngress(authenticate_for(&committee, &carrier, 3));
            live.apply_input(ingress.clone()).unwrap();
            records.push(ingress);
            references.push(carrier.reference());
        }
        assert_eq!(live.local_carrier_round(), 3);

        let (replayed, trace) =
            RbcDagModel::replay_from_records(Arc::clone(&committee), 3, context, records.clone())
                .unwrap();
        assert!(!trace.is_empty());
        assert_eq!(replayed.revision(), records.len() as u64);
        assert_eq!(replayed.lineage, live.lineage);
        assert_eq!(replayed.local_carrier_round, live.local_carrier_round);
        assert_eq!(replayed.own_fixed, live.own_fixed);
        assert_eq!(replayed.authenticated_by_slot, live.authenticated_by_slot);
        assert_eq!(replayed.admitted_by_slot, live.admitted_by_slot);
        assert_eq!(replayed.rbc_slots, live.rbc_slots);
        assert_eq!(replayed.delivery_promises, live.delivery_promises);
        assert_eq!(replayed.pending_phases, live.pending_phases);
        assert_eq!(replayed.pending_phase_set, live.pending_phase_set);
        for reference in references {
            assert_eq!(replayed.lifecycle(&reference), live.lifecycle(&reference));
        }

        // Recovery is sequential: retaining only the round-two local record
        // cannot synthesize round one or jump the local carrier clock.
        assert!(matches!(
            RbcDagModel::replay_from_records(committee, 3, context, [records[4].clone()],),
            Err(ModelError::UnexpectedLocalRound {
                expected: 1,
                actual: 2,
            })
        ));
    }

    #[test]
    fn phase_backlog_exposes_only_a_bounded_fifo_prefix() {
        let committee = committee(4);
        let mut model = model(committee, 0);
        model.local_carrier_round = 4;
        let mut queued = Vec::new();
        for round in 1..=2 {
            for author in 0..4 {
                let target = BlockReference::new_test(author, round);
                queued.push(RbcPhaseStatementV1::Echo { target });
                queued.push(RbcPhaseStatementV1::Vote { target });
                queued.push(RbcPhaseStatementV1::Ack { target });
                queued.push(RbcPhaseStatementV1::Ready { target });
            }
        }
        for statement in &queued {
            model.queue_local_phase(*statement);
        }

        assert_eq!(model.pending_phase_backlog_len(), 32);
        assert_eq!(model.pending_phase_batch(), queued[..24]);
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
        let mut log = TransitionLog::default();
        model.record_phase(sender, statement, &mut log);
        model.drain_delivered_phase_batches(&mut log);
        log.effects()
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
    fn local_fix_fast_delivers_exact_content_once_without_q_ready_certificate() {
        let committee = committee(4);
        let model = model(Arc::clone(&committee), 3);
        let (own_prev, weak_parents) = model.local_parent_set().unwrap();
        let carrier = candidate(
            &committee,
            3,
            1,
            own_prev,
            weak_parents,
            model.pending_phase_batch(),
            0xF0,
        )
        .unwrap();
        let target = carrier.reference();
        let plan = model
            .plan_input(ModelInputRecord::LocalCarrierFixed(authenticate_local(
                &committee, &carrier,
            )))
            .unwrap();

        let fixed = plan
            .trace()
            .iter()
            .position(|event| *event == ModelTraceEvent::LocalCarrierFixed(target))
            .unwrap();
        let promised = plan
            .trace()
            .iter()
            .position(|event| {
                *event
                    == ModelTraceEvent::DeliveryPromiseLocked {
                        target,
                        basis: DeliveryPromiseBasisV1::LocalFixed,
                    }
            })
            .unwrap();
        assert!(fixed < promised);
        assert_eq!(
            plan.effects()
                .iter()
                .filter(|effect| **effect == ModelEffect::DeliveryPromised(target))
                .count(),
            1
        );

        let mut committed = model;
        committed.commit_plan(plan).unwrap();
        assert_eq!(
            committed.delivery_promise_basis(&target),
            Some(DeliveryPromiseBasisV1::LocalFixed)
        );
        assert_eq!(committed.delivered(3, 1), Some(target));
        assert_eq!(committed.certified_delivered(3, 1), None);
        assert!(committed.lifecycle(&target).unwrap().delivered);
        assert!(!committed.lifecycle(&target).unwrap().certified_delivered);
        assert!(!committed.lifecycle(&target).unwrap().prefix_closed);
    }

    #[test]
    fn weighted_thresholds_follow_the_target_author_formula() {
        let cases = [
            (vec![1, 1, 1, 1], 0, (1, 2, 3, Some((2, 2, 2)))),
            (vec![1, 1, 1, 1, 1, 1, 1], 0, (2, 3, 5, Some((4, 4, 5)))),
            (vec![2, 1, 1, 1, 1, 1], 0, (2, 3, 5, Some((3, 3, 3)))),
            (vec![1, 2, 2, 2], 0, (2, 3, 5, Some((4, 4, 5)))),
            (vec![3, 1, 1, 1], 0, (1, 2, 5, None)),
        ];

        for (stakes, target_author, (fault, validity, quorum, optimistic)) in cases {
            let committee = Committee::new_test(stakes);
            let model = model(committee, target_author);
            let thresholds = model.rbc_thresholds(target_author).unwrap();
            assert_eq!(thresholds.fault, fault);
            assert_eq!(thresholds.ready_validity, validity);
            assert_eq!(thresholds.ready_quorum, quorum);
            assert_eq!(
                thresholds.optimistic.map(|thresholds| (
                    thresholds.vote_from_echo,
                    thresholds.converge,
                    thresholds.promise_from_echo,
                )),
                optimistic
            );
        }
    }

    #[test]
    fn exhaustive_weighted_echo_subsets_promise_exactly_at_o() {
        for stakes in [
            vec![1, 1, 1, 1, 1, 1, 1],
            vec![2, 1, 1, 1, 1, 1],
            vec![1, 2, 1, 2, 1],
            vec![2, 3, 1, 1, 1, 1, 1],
        ] {
            let committee = Committee::new_test(stakes);
            let template = model(Arc::clone(&committee), 0);
            let threshold = template
                .rbc_thresholds(0)
                .unwrap()
                .optimistic
                .unwrap()
                .promise_from_echo;
            let (own_prev, weak) = genesis_parents(&committee, 0);
            let carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 0x1A0).unwrap();
            let target = carrier.reference();
            let non_authors: Vec<_> = committee
                .authorities()
                .filter(|sender| *sender != 0)
                .collect();

            for mask in 0usize..(1usize << non_authors.len()) {
                for reverse in [false, true] {
                    let mut model = model(Arc::clone(&committee), 0);
                    model.stage_candidate(carrier.clone()).unwrap();
                    // The author is never counted, even if it embeds an ECHO.
                    record_phase(&mut model, 0, RbcPhaseStatementV1::Echo { target });
                    let mut selected: Vec<_> = non_authors
                        .iter()
                        .enumerate()
                        .filter_map(|(index, sender)| ((mask >> index) & 1 == 1).then_some(*sender))
                        .collect();
                    if reverse {
                        selected.reverse();
                    }
                    let mut observed_stake = 0;
                    for sender in selected {
                        observed_stake += committee.get_stake(sender).unwrap();
                        record_phase(&mut model, sender, RbcPhaseStatementV1::Echo { target });
                        assert_eq!(
                            model.delivery_promise_basis(&target).is_some(),
                            observed_stake >= threshold
                        );
                    }
                    assert_eq!(
                        model.delivery_promise_basis(&target),
                        (observed_stake >= threshold)
                            .then_some(DeliveryPromiseBasisV1::OptimisticEcho)
                    );
                }
            }
        }
    }

    #[test]
    fn exhaustive_weighted_optimistic_certificates_intersect_honestly() {
        for stakes in [
            vec![1, 1, 1, 1, 1, 1, 1],
            vec![2, 1, 1, 1, 1, 1],
            vec![1, 2, 1, 2, 1],
            vec![2, 3, 1, 1, 1, 1, 1],
        ] {
            let committee = Committee::new_test(stakes);
            let model = model(Arc::clone(&committee), 0);
            let thresholds = model.rbc_thresholds(0).unwrap();
            let optimistic = thresholds.optimistic.unwrap();
            let author_stake = committee.get_stake(0).unwrap();
            let residual_fault = thresholds.fault - author_stake;
            let non_authors: Vec<_> = committee
                .authorities()
                .filter(|sender| *sender != 0)
                .collect();
            let subset_stake = |mask: usize| {
                non_authors
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| (mask >> index) & 1 == 1)
                    .map(|(_, sender)| committee.get_stake(*sender).unwrap())
                    .sum::<Stake>()
            };
            let limit = 1usize << non_authors.len();
            let certificates: Vec<_> = (0..limit)
                .filter(|mask| subset_stake(*mask) >= optimistic.promise_from_echo)
                .collect();
            let byzantine_sets: Vec<_> = (0..limit)
                .filter(|mask| subset_stake(*mask) <= residual_fault)
                .collect();

            for first in &certificates {
                for second in &certificates {
                    for byzantine in &byzantine_sets {
                        // Every pair of selective O certificates shares a
                        // non-author sender outside the remaining Byzantine
                        // budget. That honest ECHO lock forbids two values.
                        assert_ne!(first & second & !byzantine, 0);
                    }
                }
            }
        }
    }

    #[test]
    fn weighted_four_phase_rules_and_q_ready_delivery_are_exact() {
        let committee = committee(7);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 0x1A1).unwrap();
        let target = carrier.reference();

        let mut from_echo = model(Arc::clone(&committee), 6);
        from_echo.stage_candidate(carrier.clone()).unwrap();
        for sender in 1..=3 {
            record_phase(&mut from_echo, sender, RbcPhaseStatementV1::Echo { target });
        }
        assert!(from_echo.rbc_slots[&(1, 0)].voted.is_none());
        assert!(from_echo.rbc_slots[&(1, 0)].acked.is_none());
        record_phase(&mut from_echo, 4, RbcPhaseStatementV1::Echo { target });
        assert_eq!(from_echo.rbc_slots[&(1, 0)].voted, Some(target));
        assert_eq!(from_echo.rbc_slots[&(1, 0)].acked, Some(target));
        assert_eq!(from_echo.delivery_promise_basis(&target), None);
        record_phase(&mut from_echo, 5, RbcPhaseStatementV1::Echo { target });
        assert_eq!(
            from_echo.delivery_promise_basis(&target),
            Some(DeliveryPromiseBasisV1::OptimisticEcho)
        );

        let mut from_vote = model(Arc::clone(&committee), 6);
        from_vote.stage_candidate(carrier.clone()).unwrap();
        for sender in 1..=3 {
            record_phase(&mut from_vote, sender, RbcPhaseStatementV1::Vote { target });
        }
        assert!(from_vote.rbc_slots[&(1, 0)].acked.is_none());
        record_phase(&mut from_vote, 4, RbcPhaseStatementV1::Vote { target });
        assert_eq!(from_vote.rbc_slots[&(1, 0)].acked, Some(target));

        let mut from_ack = model(Arc::clone(&committee), 6);
        from_ack.stage_candidate(carrier.clone()).unwrap();
        for sender in 1..=3 {
            record_phase(&mut from_ack, sender, RbcPhaseStatementV1::Ack { target });
        }
        assert!(from_ack.rbc_slots[&(1, 0)].readied.is_none());
        record_phase(&mut from_ack, 4, RbcPhaseStatementV1::Ack { target });
        assert_eq!(from_ack.rbc_slots[&(1, 0)].readied, Some(target));

        let mut from_ready = model(Arc::clone(&committee), 0);
        from_ready.stage_candidate(carrier).unwrap();
        for sender in 1..=2 {
            record_phase(
                &mut from_ready,
                sender,
                RbcPhaseStatementV1::Ready { target },
            );
        }
        assert!(from_ready.rbc_slots[&(1, 0)].readied.is_none());
        assert_eq!(from_ready.delivered(0, 1), None);
        record_phase(&mut from_ready, 3, RbcPhaseStatementV1::Ready { target });
        assert_eq!(from_ready.rbc_slots[&(1, 0)].readied, Some(target));
        // Three remote READYs plus the local READY have stake four, below Q=5.
        assert_eq!(from_ready.delivered(0, 1), None);
        record_phase(&mut from_ready, 4, RbcPhaseStatementV1::Ready { target });
        assert_eq!(from_ready.delivered(0, 1), Some(target));
    }

    #[test]
    fn missing_content_blocks_every_phase_and_requests_all_phase_holders() {
        let committee = committee(7);
        let mut model = model(Arc::clone(&committee), 6);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 0x1A2).unwrap();
        let target = carrier.reference();

        for sender in 1..=4 {
            record_phase(&mut model, sender, RbcPhaseStatementV1::Echo { target });
        }
        record_phase(&mut model, 5, RbcPhaseStatementV1::Vote { target });
        record_phase(&mut model, 5, RbcPhaseStatementV1::Ack { target });
        let effects = record_phase(&mut model, 0, RbcPhaseStatementV1::Ready { target });
        assert!(matches!(
            effects.as_slice(),
            [ModelEffect::NeedCarrier { target: requested, holders }]
                if *requested == target && holders == &[0, 1, 2, 3, 4, 5]
        ));
        let slot = &model.rbc_slots[&(1, 0)];
        assert!(slot.voted.is_none());
        assert!(slot.acked.is_none());
        assert!(slot.readied.is_none());
        assert!(slot.delivered.is_none());
        assert_eq!(model.delivery_promise_basis(&target), None);

        model.recover_carrier(carrier).unwrap();
        let slot = &model.rbc_slots[&(1, 0)];
        assert_eq!(slot.voted, Some(target));
        assert_eq!(slot.acked, Some(target));
    }

    #[test]
    fn high_stake_honest_author_promises_on_auth_and_seeds_ready_locally() {
        let committee = Committee::new_test(vec![3, 1, 1, 1]);
        let mut author = model(Arc::clone(&committee), 0);
        let (own_prev, weak) = author.local_parent_set().unwrap();
        let carrier = candidate(
            &committee,
            0,
            1,
            own_prev,
            weak,
            author.pending_phase_batch(),
            0x1A3,
        )
        .unwrap();
        let target = carrier.reference();
        let effects = author
            .start_local_carrier(authenticate_local(&committee, &carrier))
            .unwrap();
        assert_eq!(effects, vec![ModelEffect::DeliveryPromised(target)]);
        assert_eq!(
            author.delivery_promise_basis(&target),
            Some(DeliveryPromiseBasisV1::LocalFixed)
        );
        assert_eq!(author.rbc_slots[&(1, 0)].readied, Some(target));
        assert!(
            author
                .pending_phases
                .contains(&RbcPhaseStatementV1::Ready { target })
        );

        let mut receiver = model(Arc::clone(&committee), 3);
        receiver.stage_candidate(carrier.clone()).unwrap();
        assert_eq!(receiver.delivery_promise_basis(&target), None);
        let effects = receiver
            .receive_authenticated(authenticate_for(&committee, &carrier, 3))
            .unwrap();
        assert_eq!(effects, vec![ModelEffect::DeliveryPromised(target)]);
        assert_eq!(
            receiver.delivery_promise_basis(&target),
            Some(DeliveryPromiseBasisV1::HonestAuthor)
        );
        assert!(receiver.rbc_slots[&(1, 0)].readied.is_none());
        assert_eq!(receiver.delivered(0, 1), Some(target));
        assert_eq!(receiver.certified_delivered(0, 1), None);

        record_phase(&mut receiver, 0, RbcPhaseStatementV1::Ready { target });
        assert_eq!(receiver.rbc_slots[&(1, 0)].readied, Some(target));
        assert_eq!(receiver.delivered(0, 1), Some(target));
        assert_eq!(receiver.certified_delivered(0, 1), None);
        record_phase(&mut receiver, 1, RbcPhaseStatementV1::Ready { target });
        assert_eq!(receiver.delivered(0, 1), Some(target));
        assert_eq!(receiver.certified_delivered(0, 1), Some(target));

        // Even a test-only forged second author capability cannot bypass the
        // receiver's exact authenticated slot lock.
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let conflicting = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 0x1A4).unwrap();
        let conflicting_ref = conflicting.reference();
        receiver
            .receive_authenticated(authenticate_for(&committee, &conflicting, 3))
            .unwrap();
        assert_eq!(receiver.delivery_promise_basis(&conflicting_ref), None);
    }

    #[test]
    fn raw_q_that_counts_the_target_author_is_not_an_optimistic_promise() {
        let committee = committee(7);
        let mut model = model(Arc::clone(&committee), 0);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 0xF1).unwrap();
        let target = carrier.reference();
        model.stage_candidate(carrier).unwrap();

        // W=7, F=2, a=1 gives O=5. A raw Q=5 that includes the
        // equivocating target author contains only four admissible ECHOs.
        assert!(record_phase(&mut model, 0, RbcPhaseStatementV1::Echo { target }).is_empty());
        for sender in 1..=4 {
            assert!(
                record_phase(&mut model, sender, RbcPhaseStatementV1::Echo { target }).is_empty()
            );
        }
        assert_eq!(model.delivery_promise_basis(&target), None);
        assert_eq!(model.delivered(0, 1), None);

        let effects = record_phase(&mut model, 5, RbcPhaseStatementV1::Echo { target });
        assert_eq!(effects, vec![ModelEffect::DeliveryPromised(target)]);
        assert_eq!(
            model.delivery_promise_basis(&target),
            Some(DeliveryPromiseBasisV1::OptimisticEcho)
        );
        assert_eq!(model.delivered(0, 1), Some(target));
        assert_eq!(model.certified_delivered(0, 1), None);

        // Exact replay and a conflicting later ECHO are both idempotent and
        // cannot emit a second promise.
        assert!(record_phase(&mut model, 5, RbcPhaseStatementV1::Echo { target }).is_empty());
        let mut conflicting = target;
        conflicting.digest = crate::types::BlockDigest::from([0xF2; 32]);
        assert!(
            record_phase(
                &mut model,
                5,
                RbcPhaseStatementV1::Echo {
                    target: conflicting,
                },
            )
            .is_empty()
        );
        assert_eq!(model.delivery_promises.len(), 1);
    }

    #[test]
    fn selective_and_equivocating_echoes_cannot_promise_two_values() {
        let committee = committee(7);
        let mut model = model(Arc::clone(&committee), 0);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let first = candidate(&committee, 0, 1, own_prev, weak.clone(), Vec::new(), 0xF3).unwrap();
        let conflicting = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 0xF4).unwrap();
        let first_ref = first.reference();
        let conflicting_ref = conflicting.reference();

        model.stage_candidate(first).unwrap();
        model.stage_candidate(conflicting).unwrap();
        for sender in 1..=4 {
            record_phase(
                &mut model,
                sender,
                RbcPhaseStatementV1::Echo { target: first_ref },
            );
        }
        for sender in 5..=6 {
            record_phase(
                &mut model,
                sender,
                RbcPhaseStatementV1::Echo {
                    target: conflicting_ref,
                },
            );
        }
        // Sender 1 equivocates after locking the first value. The second
        // statement is ignored slot-globally for ECHO.
        record_phase(
            &mut model,
            1,
            RbcPhaseStatementV1::Echo {
                target: conflicting_ref,
            },
        );

        assert_eq!(
            model.rbc_slots.get(&(1, 0)).unwrap().candidates[&first_ref]
                .echoes
                .len(),
            4
        );
        assert_eq!(
            model.rbc_slots[&(1, 0)].candidates[&conflicting_ref]
                .echoes
                .len(),
            2
        );
        assert_eq!(model.delivery_promise_basis(&first_ref), None);
        assert_eq!(model.delivery_promise_basis(&conflicting_ref), None);
        assert!(model.delivery_promises.is_empty());
    }

    #[test]
    fn delivered_fallback_promises_before_the_delivered_effect() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 0xF5).unwrap();
        let target = carrier.reference();
        model.stage_candidate(carrier).unwrap();

        assert!(record_phase(&mut model, 0, RbcPhaseStatementV1::Ready { target }).is_empty());
        let effects = record_phase(&mut model, 1, RbcPhaseStatementV1::Ready { target });
        assert_eq!(
            effects,
            vec![
                ModelEffect::DeliveryPromised(target),
                ModelEffect::Delivered(target),
            ]
        );
        assert_eq!(
            model.delivery_promise_basis(&target),
            Some(DeliveryPromiseBasisV1::Delivered)
        );
    }

    #[test]
    fn promised_effects_and_locks_replay_deterministically_from_typed_inputs() {
        let committee = committee(4);
        let context = context(&committee);
        let mut live = RbcDagModel::new(Arc::clone(&committee), 3, context).unwrap();
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let target_carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 0xF6).unwrap();
        let target = target_carrier.reference();
        let mut records = vec![ModelInputRecord::AuthenticatedIngress(authenticate_for(
            &committee,
            &target_carrier,
            3,
        ))];

        for author in 0..3 {
            let outer = candidate(
                &committee,
                author,
                2,
                BlockReference::new_test(author, 1),
                committee
                    .authorities()
                    .filter(|other| *other != author)
                    .take(2)
                    .map(|other| BlockReference::new_test(other, 1))
                    .collect(),
                vec![RbcPhaseStatementV1::Echo { target }],
                0xF7 + u64::from(author),
            )
            .unwrap();
            records.push(ModelInputRecord::AuthenticatedIngress(authenticate_for(
                &committee, &outer, 3,
            )));
        }

        let mut live_trace = Vec::new();
        for record in records.iter().cloned() {
            let plan = live.plan_input(record).unwrap();
            live_trace.extend_from_slice(plan.trace());
            live.commit_plan(plan).unwrap();
        }
        let (replayed, replay_trace) =
            RbcDagModel::replay_from_records(committee, 3, context, records).unwrap();

        assert_eq!(replay_trace, live_trace);
        assert_eq!(replayed.delivery_promises, live.delivery_promises);
        assert_eq!(
            replay_trace
                .iter()
                .filter(|event| {
                    **event == ModelTraceEvent::Effect(ModelEffect::DeliveryPromised(target))
                })
                .count(),
            1
        );
        assert_eq!(
            replayed.delivery_promise_basis(&target),
            Some(DeliveryPromiseBasisV1::OptimisticEcho)
        );
        assert_eq!(replayed.delivered(0, 1), Some(target));
        assert_eq!(replayed.certified_delivered(0, 1), None);
    }

    #[test]
    fn threshold_before_header_requests_then_recovers_exact_carrier() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 3);
        let (own_prev, weak) = genesis_parents(&committee, 0);
        let carrier = candidate(&committee, 0, 1, own_prev, weak, Vec::new(), 1).unwrap();
        let target = carrier.reference();

        assert!(record_phase(&mut model, 1, RbcPhaseStatementV1::Echo { target }).is_empty());
        assert!(matches!(
            record_phase(
                &mut model,
                2,
                RbcPhaseStatementV1::Echo { target }
            )
            .as_slice(),
            [ModelEffect::NeedCarrier { target: requested, holders }]
                if *requested == target && holders == &[1, 2]
        ));

        let effects = model.recover_carrier(carrier).unwrap();
        assert_eq!(effects, vec![ModelEffect::DeliveryPromised(target)]);
        assert!(
            model
                .pending_phases
                .contains(&RbcPhaseStatementV1::Vote { target })
        );
        assert!(
            model
                .pending_phases
                .contains(&RbcPhaseStatementV1::Ack { target })
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
        assert!(record_phase(&mut model, 3, RbcPhaseStatementV1::Vote { target }).is_empty());
        assert!(record_phase(&mut model, 3, RbcPhaseStatementV1::Ack { target }).is_empty());
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
        assert_eq!(slot.echo_by_sender.len(), 2);
        assert_eq!(slot.echo_by_sender[&1], first);
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

        for statement in [
            RbcPhaseStatementV1::Vote { target: first },
            RbcPhaseStatementV1::Ack { target: first },
        ] {
            record_phase(&mut model, 1, statement);
            let conflicting_statement = match statement {
                RbcPhaseStatementV1::Vote { .. } => RbcPhaseStatementV1::Vote {
                    target: conflicting,
                },
                RbcPhaseStatementV1::Ack { .. } => RbcPhaseStatementV1::Ack {
                    target: conflicting,
                },
                _ => unreachable!(),
            };
            record_phase(&mut model, 1, conflicting_statement);
        }
        let slot = model.rbc_slots.get(&(1, 0)).unwrap();
        assert_eq!(slot.vote_by_sender[&1], first);
        assert_eq!(slot.ack_by_sender[&1], first);
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
        assert_eq!(slot.echo_by_sender.get(&0), None);
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
        uninterrupted.process_phase_batch(outer_ref, &mut TransitionLog::default());

        // Model a crash after the first idempotent statement was persisted but
        // before the outer batch cursor was advanced.
        let mut restarted = model;
        restarted.record_phase(
            0,
            RbcPhaseStatementV1::Echo { target: first },
            &mut TransitionLog::default(),
        );
        restarted.process_phase_batch(outer_ref, &mut TransitionLog::default());

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
                .insert(reference, CarrierRecord::new(carrier, false));
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
        model.drain_delivered_phase_batches(&mut TransitionLog::default());

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
            66,
            BlockReference::new_test(1, 65),
            vec![
                BlockReference::new_test(0, 65),
                BlockReference::new_test(2, 65),
            ],
            Vec::new(),
            660,
        )
        .unwrap();
        let reference = carrier.reference();
        let authenticated = authenticate_for(&committee, &carrier, 0);

        assert_eq!(
            model.receive_authenticated(authenticated),
            Err(ModelError::FutureCarrierOutsideBuffer {
                current: 1,
                maximum: 65,
                actual: 66,
            })
        );
        assert!(model.lifecycle(&reference).is_none());
        assert!(model.authenticated_by_slot.is_empty());
        assert!(model.rbc_slots.is_empty());
    }

    #[test]
    fn carrier_at_the_future_buffer_boundary_is_retained_but_cannot_advance() {
        let committee = committee(4);
        let mut model = model(Arc::clone(&committee), 0);
        let carrier = candidate(
            &committee,
            1,
            65,
            BlockReference::new_test(1, 64),
            vec![
                BlockReference::new_test(0, 64),
                BlockReference::new_test(2, 64),
            ],
            Vec::new(),
            650,
        )
        .unwrap();
        let reference = carrier.reference();

        assert!(
            model
                .receive_authenticated(authenticate_for(&committee, &carrier, 0))
                .unwrap()
                .is_empty()
        );
        assert_eq!(model.local_carrier_round(), 1);
        assert_eq!(
            model.lifecycle(&reference),
            Some(CarrierLifecycle {
                authenticated: true,
                admitted: false,
                phase_batch_processed: true,
                delivered: false,
                certified_delivered: false,
                data_available: false,
                prefix_closed: false,
            })
        );
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
