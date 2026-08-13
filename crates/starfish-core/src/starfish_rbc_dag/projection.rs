// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Pure executable model of the certified Starfish projection.
//!
//! This module deliberately has no network, storage, pacemaker, or production
//! consensus integration. It models the boundary at which an RBC-delivered,
//! data-available carrier may contribute its optional consensus vertex, and it
//! evaluates the explicit vote/no-vote evidence committed by those vertices.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::Arc,
};

use crate::{
    committee::Committee,
    types::{AuthorityIndex, BlockReference, RoundNumber, Stake},
};

use super::{
    CandidateCarrierV1, ConsensusVertexReference, ConsensusVertexV1, LeaderChoiceV1,
    RbcDagCommitteeContextV1, RbcDagProjectionError, carrier_genesis_reference,
};

/// An indexed exact carrier-prefix frontier. `None` is the authority's virtual
/// genesis prefix; `Some` always identifies an exact carrier value.
pub type DeliveryFrontierV1 = Vec<Option<BlockReference>>;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LeaderSlotV1 {
    pub author: AuthorityIndex,
    pub round: RoundNumber,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProjectionDecisionV1 {
    DirectCommit {
        leader: ConsensusVertexReference,
    },
    DirectSkip {
        slot: LeaderSlotV1,
    },
    IndirectCommit {
        leader: ConsensusVertexReference,
        anchor: ConsensusVertexReference,
    },
    IndirectSkip {
        slot: LeaderSlotV1,
        anchor: ConsensusVertexReference,
    },
    Undecided {
        slot: LeaderSlotV1,
    },
}

/// Immutable level-two evidence that allows an honest author to create the
/// next consensus vertex through the optimistic C1 pacemaker condition.
///
/// Every returned reference is from consensus round `c - 1` and there is at
/// most one reference per author. A vote witness contains quorum stake voting
/// for one exact leader at `c - 2`, plus any caller-required own/leader parent
/// that is not already in that proof. A skip witness is the deterministic
/// union of the per-candidate negative-choice quorums required by the
/// direct-skip evaluator and those same required parents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum C1StrongParentWitnessV1 {
    Vote {
        leader: ConsensusVertexReference,
        parents: Vec<ConsensusVertexReference>,
    },
    DirectSkip {
        slot: LeaderSlotV1,
        parents: Vec<ConsensusVertexReference>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertifiedProjectionError {
    CommitteeMismatch,
    UnknownCarrier(BlockReference),
    ConflictingDeliveredCarrierSlot {
        existing: BlockReference,
        conflicting: BlockReference,
    },
    MissingConsensusVertex(BlockReference),
    InvalidProjectionShape(RbcDagProjectionError),
    CarrierNotDelivered(BlockReference),
    CarrierDataUnavailable(BlockReference),
    CarrierOutsideClosedPrefix(BlockReference),
    MissingStrongParent(ConsensusVertexReference),
    InvalidGenesisStrongParent(ConsensusVertexReference),
    OwnFrontierDoesNotNamePreviousCarrier {
        expected: Option<BlockReference>,
        actual: Option<BlockReference>,
    },
    FrontierNotClosed {
        authority: AuthorityIndex,
        reference: BlockReference,
    },
    ParentFrontierFork {
        authority: AuthorityIndex,
        left: Option<BlockReference>,
        right: Option<BlockReference>,
    },
    FrontierDoesNotDominateParent {
        authority: AuthorityIndex,
        required: Option<BlockReference>,
        actual: Option<BlockReference>,
    },
    StakeOverflow,
    InvalidLeaderSlot(LeaderSlotV1),
    MultipleCertifiedLeaderValues(LeaderSlotV1),
    ConflictingDirectDecision(LeaderSlotV1),
    AnchorTooEarly {
        slot: LeaderSlotV1,
        anchor: ConsensusVertexReference,
    },
}

impl fmt::Display for CertifiedProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "certified projection error: {self:?}")
    }
}

impl Error for CertifiedProjectionError {}

#[derive(Clone, Debug)]
struct CarrierState {
    candidate: CandidateCarrierV1,
    delivered: bool,
    data_available: bool,
}

#[derive(Clone, Debug)]
struct ProjectedVertex {
    vertex: ConsensusVertexV1,
    effective_frontier: DeliveryFrontierV1,
}

/// Stateful, deterministic model of the clean certified projection.
///
/// Staging and cleaning a carrier never projects its optional vertex
/// automatically. Callers explicitly invoke [`Self::try_project`] so tests can
/// observe malformed or unavailable optional metadata without changing carrier
/// admission state.
#[derive(Clone)]
pub struct CertifiedProjectionModel {
    committee: Arc<Committee>,
    committee_context: RbcDagCommitteeContextV1,
    carriers: BTreeMap<BlockReference, CarrierState>,
    delivered_slots: BTreeMap<(AuthorityIndex, RoundNumber), BlockReference>,
    closed_prefixes: Vec<Vec<BlockReference>>,
    vertices: BTreeMap<ConsensusVertexReference, ProjectedVertex>,
    vertices_by_round: BTreeMap<RoundNumber, BTreeSet<ConsensusVertexReference>>,
    consensus_slots: BTreeMap<(AuthorityIndex, RoundNumber), BTreeSet<ConsensusVertexReference>>,
    committed_frontier: DeliveryFrontierV1,
    committed_anchors: BTreeSet<ConsensusVertexReference>,
}

impl CertifiedProjectionModel {
    /// Convenience constructor that validates and hashes the committee once.
    /// Runtime code that already owns the reusable capability should call
    /// [`Self::from_committee_context`].
    pub fn new(committee: Arc<Committee>) -> Result<Self, CertifiedProjectionError> {
        let committee = RbcDagCommitteeContextV1::new(committee)
            .map_err(|_| CertifiedProjectionError::CommitteeMismatch)?;
        Ok(Self::from_committee_context(committee))
    }

    pub fn from_committee_context(committee: RbcDagCommitteeContextV1) -> Self {
        let committee_size = committee.committee().len();
        let committee_arc = committee.committee_arc();
        Self {
            committee: committee_arc,
            committee_context: committee,
            carriers: BTreeMap::new(),
            delivered_slots: BTreeMap::new(),
            closed_prefixes: vec![Vec::new(); committee_size],
            vertices: BTreeMap::new(),
            vertices_by_round: BTreeMap::new(),
            consensus_slots: BTreeMap::new(),
            committed_frontier: vec![None; committee_size],
            committed_anchors: BTreeSet::new(),
        }
    }

    /// Retain a canonical carrier independently of optional-vertex validity.
    pub fn stage_carrier(
        &mut self,
        candidate: CandidateCarrierV1,
    ) -> Result<(), CertifiedProjectionError> {
        if candidate.committee_id() != self.committee_context.committee_id() {
            return Err(CertifiedProjectionError::CommitteeMismatch);
        }
        self.carriers
            .entry(candidate.reference())
            .or_insert(CarrierState {
                candidate,
                delivered: false,
                data_available: false,
            });
        Ok(())
    }

    /// Record exact RBC delivery. A second delivered value in one physical
    /// author/round slot is rejected rather than resolved by arrival order.
    pub fn mark_delivered(
        &mut self,
        reference: BlockReference,
    ) -> Result<(), CertifiedProjectionError> {
        let state = self
            .carriers
            .get(&reference)
            .ok_or(CertifiedProjectionError::UnknownCarrier(reference))?;
        let slot = (
            state.candidate.header().author(),
            state.candidate.header().carrier_round(),
        );
        if let Some(existing) = self.delivered_slots.get(&slot) {
            if *existing != reference {
                return Err(CertifiedProjectionError::ConflictingDeliveredCarrierSlot {
                    existing: *existing,
                    conflicting: reference,
                });
            }
        }
        self.delivered_slots.insert(slot, reference);
        self.carriers
            .get_mut(&reference)
            .expect("carrier checked above")
            .delivered = true;
        self.advance_closed_prefix(slot.0);
        Ok(())
    }

    pub fn mark_data_available(
        &mut self,
        reference: BlockReference,
    ) -> Result<(), CertifiedProjectionError> {
        let authority = self
            .carriers
            .get(&reference)
            .ok_or(CertifiedProjectionError::UnknownCarrier(reference))?
            .candidate
            .header()
            .author();
        self.carriers
            .get_mut(&reference)
            .expect("carrier checked above")
            .data_available = true;
        self.advance_closed_prefix(authority);
        Ok(())
    }

    pub(crate) fn is_data_available(&self, reference: BlockReference) -> bool {
        self.carriers
            .get(&reference)
            .is_some_and(|state| state.data_available)
    }

    pub fn carrier_is_stored(&self, reference: BlockReference) -> bool {
        self.carriers.contains_key(&reference)
    }

    pub fn closed_tip(&self, authority: AuthorityIndex) -> Option<BlockReference> {
        self.closed_prefixes
            .get(authority as usize)
            .and_then(|prefix| prefix.last())
            .copied()
    }

    pub fn is_projected(&self, reference: ConsensusVertexReference) -> bool {
        self.vertices.contains_key(&reference)
    }

    /// Deterministic clean values at one logical consensus round. Byzantine
    /// equivocations remain visible as distinct exact references.
    pub fn projected_values_at_round(&self, round: RoundNumber) -> Vec<ConsensusVertexReference> {
        self.vertices_at_round(round)
            .map(|(reference, _)| reference)
            .collect()
    }

    pub fn projected_vertex(
        &self,
        reference: ConsensusVertexReference,
    ) -> Option<&ConsensusVertexV1> {
        self.vertices
            .get(&reference)
            .map(|projected| &projected.vertex)
    }

    pub fn is_committed_anchor(&self, reference: ConsensusVertexReference) -> bool {
        self.committed_anchors.contains(&reference)
    }

    /// Whether the current committed prefix already contains every carrier
    /// named by `frontier`. This is used when a later anchor first resolves an
    /// older slot: an intermediate leader can subsequently be decided as a
    /// logical commit even though its entire payload frontier was already
    /// output by that later anchor.
    pub fn committed_frontier_dominates(&self, frontier: &[Option<BlockReference>]) -> bool {
        frontier.len() == self.committed_frontier.len()
            && frontier
                .iter()
                .copied()
                .zip(self.committed_frontier.iter().copied())
                .all(|(older, committed)| self.is_exact_extension(older, committed))
    }

    /// Current exact closed carrier-prefix frontier in authority order.
    pub fn closed_frontier(&self) -> DeliveryFrontierV1 {
        self.committee
            .authorities()
            .map(|authority| self.closed_tip(authority))
            .collect()
    }

    pub fn projected_vertex_count(&self) -> usize {
        self.vertices.len()
    }

    pub(crate) fn projected_stake_at_round(&self, round: RoundNumber) -> Stake {
        self.vertices_at_round(round)
            .map(|(reference, _)| reference.author())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter_map(|authority| self.committee.get_stake(authority))
            .fold(0, Stake::saturating_add)
    }

    pub fn slot_values(
        &self,
        author: AuthorityIndex,
        round: RoundNumber,
    ) -> Vec<ConsensusVertexReference> {
        self.consensus_slots
            .get(&(author, round))
            .map(|values| values.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn effective_frontier(
        &self,
        reference: ConsensusVertexReference,
    ) -> Option<&[Option<BlockReference>]> {
        self.vertices
            .get(&reference)
            .map(|projected| projected.effective_frontier.as_slice())
    }

    pub fn leader_choice(&self, reference: ConsensusVertexReference) -> Option<LeaderChoiceV1> {
        self.vertices
            .get(&reference)
            .map(|projected| projected.vertex.leader_choice())
    }

    /// Return the exact C1 witness for creating consensus round `c`.
    ///
    /// Exact-vote witnesses consider every projected equivocation, then select
    /// one deterministic matching value per author. Direct-skip witnesses use
    /// one deterministic representative per author so their per-candidate
    /// negative quorums have one compatible immutable union. Returning `None`
    /// means C1 is not ready and the caller must wait or use a separately
    /// justified C2/C3 fallback.
    pub(crate) fn c1_strong_parent_witness(
        &self,
        consensus_round: RoundNumber,
        required_parents: &[ConsensusVertexReference],
    ) -> Result<Option<C1StrongParentWitnessV1>, CertifiedProjectionError> {
        if consensus_round < 3 {
            return Ok(None);
        }
        let voting_round = consensus_round - 1;
        let slot = self.leader_slot(consensus_round - 2);
        let representatives = self.deterministic_round_values(voting_round);

        let mut votes = BTreeMap::<
            ConsensusVertexReference,
            BTreeMap<AuthorityIndex, ConsensusVertexReference>,
        >::new();
        for (reference, _) in self.vertices_at_round(voting_round) {
            if let Some(LeaderChoiceV1::Vote { leader }) = self.leader_choice(reference) {
                votes
                    .entry(leader)
                    .or_default()
                    .entry(reference.author())
                    .or_insert(reference);
            }
        }
        let mut vote_witnesses = Vec::new();
        for (leader, voters) in votes {
            if let Some(parents) =
                self.frontier_fresh_quorum(voters.into_values(), required_parents)?
            {
                vote_witnesses.push((leader, parents));
            }
        }
        if vote_witnesses.len() > 1 {
            return Err(CertifiedProjectionError::MultipleCertifiedLeaderValues(
                slot,
            ));
        }
        if let Some((leader, parents)) = vote_witnesses.pop() {
            return Ok(Some(C1StrongParentWitnessV1::Vote { leader, parents }));
        }

        let candidates = self.slot_values(slot.author, slot.round);
        let mut union = BTreeMap::new();
        if candidates.is_empty() {
            let Some(parents) =
                self.frontier_fresh_quorum(representatives.values().copied(), required_parents)?
            else {
                return Ok(None);
            };
            for reference in parents {
                union.insert(reference.author(), reference);
            }
        } else {
            for candidate in candidates {
                let negative = representatives.values().copied().filter(|reference| {
                    self.leader_choice(*reference)
                        .is_some_and(|choice| match choice {
                            LeaderChoiceV1::Vote { leader } => leader != candidate,
                            LeaderChoiceV1::NoVote { .. } => true,
                        })
                });
                let Some(parents) = self.lexicographic_quorum(negative)? else {
                    return Ok(None);
                };
                for reference in parents {
                    union.insert(reference.author(), reference);
                }
            }
            if !self.extend_with_required_parents(&mut union, required_parents) {
                return Ok(None);
            }
        }
        Ok(Some(C1StrongParentWitnessV1::DirectSkip {
            slot,
            parents: union.into_values().collect(),
        }))
    }

    /// Componentwise join of the exact effective frontiers inherited through
    /// one immutable strong-parent set. Callers extend only their own
    /// component from this base; copying the globally freshest closed
    /// frontier would make every consensus vertex wait for unrelated
    /// all-author delivery tails.
    pub(crate) fn joined_strong_parent_frontier(
        &self,
        strong_parents: &[ConsensusVertexReference],
    ) -> Result<DeliveryFrontierV1, CertifiedProjectionError> {
        let mut parent_frontiers = Vec::with_capacity(strong_parents.len());
        for parent in strong_parents {
            if parent.consensus_round() == 0 {
                if parent.carrier() != carrier_genesis_reference(parent.author()) {
                    return Err(CertifiedProjectionError::InvalidGenesisStrongParent(
                        *parent,
                    ));
                }
                parent_frontiers.push(vec![None; self.committee.len()]);
                continue;
            }
            let projected = self
                .vertices
                .get(parent)
                .ok_or(CertifiedProjectionError::MissingStrongParent(*parent))?;
            parent_frontiers.push(projected.effective_frontier.clone());
        }
        self.join_frontiers(&parent_frontiers)
    }

    /// Project one optional consensus vertex if every stateful eligibility
    /// condition holds. Failure leaves the enclosing carrier untouched.
    pub fn try_project(
        &mut self,
        carrier_reference: BlockReference,
    ) -> Result<ConsensusVertexReference, CertifiedProjectionError> {
        let state = self
            .carriers
            .get(&carrier_reference)
            .ok_or(CertifiedProjectionError::UnknownCarrier(carrier_reference))?;
        let vertex = state.candidate.header().consensus_vertex().cloned().ok_or(
            CertifiedProjectionError::MissingConsensusVertex(carrier_reference),
        )?;
        let vertex_reference =
            ConsensusVertexReference::new(carrier_reference, vertex.consensus_round());
        if self.vertices.contains_key(&vertex_reference) {
            return Ok(vertex_reference);
        }

        state
            .candidate
            .validate_consensus_vertex_with_committee(&self.committee_context)
            .map_err(CertifiedProjectionError::InvalidProjectionShape)?;
        if !state.delivered {
            return Err(CertifiedProjectionError::CarrierNotDelivered(
                carrier_reference,
            ));
        }
        if !state.data_available {
            return Err(CertifiedProjectionError::CarrierDataUnavailable(
                carrier_reference,
            ));
        }
        if !self.is_on_closed_prefix(carrier_reference) {
            return Err(CertifiedProjectionError::CarrierOutsideClosedPrefix(
                carrier_reference,
            ));
        }

        let author = carrier_reference.authority;
        let own_previous = state.candidate.header().own_prev();
        let expected_author_frontier = (own_previous.round != 0).then_some(own_previous);
        let actual_author_frontier = vertex.delivery_frontier()[author as usize];
        if actual_author_frontier != expected_author_frontier {
            return Err(
                CertifiedProjectionError::OwnFrontierDoesNotNamePreviousCarrier {
                    expected: expected_author_frontier,
                    actual: actual_author_frontier,
                },
            );
        }

        self.ensure_frontier_closed(vertex.delivery_frontier())?;

        let mut parent_frontiers = Vec::with_capacity(vertex.strong_parents().len());
        for parent in vertex.strong_parents() {
            if parent.consensus_round() == 0 {
                if parent.carrier() != carrier_genesis_reference(parent.author()) {
                    return Err(CertifiedProjectionError::InvalidGenesisStrongParent(
                        *parent,
                    ));
                }
                parent_frontiers.push(vec![None; self.committee.len()]);
                continue;
            }
            let projected = self
                .vertices
                .get(parent)
                .ok_or(CertifiedProjectionError::MissingStrongParent(*parent))?;
            parent_frontiers.push(projected.effective_frontier.clone());
        }
        let parent_join = self.join_frontiers(&parent_frontiers)?;
        self.ensure_dominates_parent(vertex.delivery_frontier(), &parent_join)?;

        let mut effective_frontier = vertex.delivery_frontier().to_vec();
        effective_frontier[author as usize] = Some(carrier_reference);
        self.vertices.insert(
            vertex_reference,
            ProjectedVertex {
                vertex,
                effective_frontier,
            },
        );
        self.vertices_by_round
            .entry(vertex_reference.consensus_round())
            .or_default()
            .insert(vertex_reference);
        self.consensus_slots
            .entry((author, vertex_reference.consensus_round()))
            .or_default()
            .insert(vertex_reference);
        Ok(vertex_reference)
    }

    /// The scheduled leader slot for a consensus round.
    pub fn leader_slot(&self, round: RoundNumber) -> LeaderSlotV1 {
        LeaderSlotV1 {
            author: self.committee.elect_leader(round),
            round,
        }
    }

    /// Stake of distinct projected voter authors that explicitly vote for this
    /// exact leader value. Equivocations by one author count once.
    pub fn vote_stake(
        &self,
        leader: ConsensusVertexReference,
    ) -> Result<Stake, CertifiedProjectionError> {
        let slot = LeaderSlotV1 {
            author: leader.author(),
            round: leader.consensus_round(),
        };
        self.validate_leader_slot(slot)?;
        self.stake_of_authors(self.voter_authors(
            slot,
            |choice| matches!(choice, LeaderChoiceV1::Vote { leader: voted } if voted == leader),
        ))
    }

    /// Evaluate the explicit direct Starfish patterns over clean projected
    /// vertices only.
    pub fn direct_decision(
        &self,
        slot: LeaderSlotV1,
    ) -> Result<ProjectionDecisionV1, CertifiedProjectionError> {
        self.validate_leader_slot(slot)?;
        let candidates = self.slot_values(slot.author, slot.round);
        let mut committed = Vec::new();
        for candidate in &candidates {
            let certifier_authors = self.certifier_authors(*candidate);
            if self.stake_of_authors(certifier_authors)? >= self.committee.quorum_threshold() {
                committed.push(*candidate);
            }
        }
        if committed.len() > 1 {
            return Err(CertifiedProjectionError::MultipleCertifiedLeaderValues(
                slot,
            ));
        }

        let all_choice_authors = self.voter_authors(slot, |_| true);
        let enough_choices =
            self.stake_of_authors(all_choice_authors)? >= self.committee.quorum_threshold();
        let skip = enough_choices
            && candidates.iter().all(|candidate| {
                self.stake_of_authors(self.voter_authors(slot, |choice| match choice {
                    LeaderChoiceV1::Vote { leader } => leader != *candidate,
                    LeaderChoiceV1::NoVote { .. } => true,
                }))
                .is_ok_and(|stake| stake >= self.committee.quorum_threshold())
            });

        match (committed.pop(), skip) {
            (Some(_), true) => Err(CertifiedProjectionError::ConflictingDirectDecision(slot)),
            (Some(leader), false) => Ok(ProjectionDecisionV1::DirectCommit { leader }),
            (None, true) => Ok(ProjectionDecisionV1::DirectSkip { slot }),
            (None, false) => Ok(ProjectionDecisionV1::Undecided { slot }),
        }
    }

    /// Record an externally selected committed anchor and return the monotone
    /// componentwise join of every committed anchor frontier. Consecutive
    /// Starfish leaders need not be ancestors of one another, so their exact
    /// frontiers may advance different authority components concurrently.
    /// Logical anchor membership is therefore independent of whether this
    /// particular anchor advances the accumulated output frontier.
    pub fn record_committed_anchor(
        &mut self,
        anchor: ConsensusVertexReference,
    ) -> Result<DeliveryFrontierV1, CertifiedProjectionError> {
        let projected = self
            .vertices
            .get(&anchor)
            .ok_or(CertifiedProjectionError::MissingStrongParent(anchor))?;
        let frontier = projected.effective_frontier.clone();
        let accumulated = self.committed_frontier.clone();
        let joined = self.join_frontiers(&[accumulated, frontier])?;
        self.committed_frontier.clone_from(&joined);
        self.committed_anchors.insert(anchor);
        Ok(joined)
    }

    /// Decide an older leader from a later projected anchor selected by the
    /// ordered committer. A reachable certifying-round vertex with a QC yields
    /// commit; absence yields skip.
    ///
    /// The anchor's frontier is deliberately not required to have been
    /// applied yet. The committer first derives the finalized leader sequence
    /// from newest to oldest, then applies committed frontiers in the opposite
    /// (oldest-to-newest) order.
    pub fn indirect_decision(
        &self,
        slot: LeaderSlotV1,
        anchor: ConsensusVertexReference,
    ) -> Result<ProjectionDecisionV1, CertifiedProjectionError> {
        self.validate_leader_slot(slot)?;
        if !self.vertices.contains_key(&anchor) {
            return Err(CertifiedProjectionError::MissingStrongParent(anchor));
        }
        let minimum_anchor_round = slot.round.saturating_add(3);
        if anchor.consensus_round() < minimum_anchor_round {
            return Err(CertifiedProjectionError::AnchorTooEarly { slot, anchor });
        }
        let certifying_round = slot.round.saturating_add(2);
        let reachable = self.reachable_at_round(anchor, certifying_round);
        let mut certified = Vec::new();
        for candidate in self.slot_values(slot.author, slot.round) {
            if reachable
                .iter()
                .any(|certifier| self.is_certificate(*certifier, candidate))
            {
                certified.push(candidate);
            }
        }
        if certified.len() > 1 {
            return Err(CertifiedProjectionError::MultipleCertifiedLeaderValues(
                slot,
            ));
        }
        Ok(match certified.pop() {
            Some(leader) => ProjectionDecisionV1::IndirectCommit { leader, anchor },
            None => ProjectionDecisionV1::IndirectSkip { slot, anchor },
        })
    }

    fn advance_closed_prefix(&mut self, authority: AuthorityIndex) {
        let index = authority as usize;
        loop {
            let next_round = self.closed_prefixes[index].len() as RoundNumber + 1;
            let Some(reference) = self.delivered_slots.get(&(authority, next_round)).copied()
            else {
                break;
            };
            let Some(state) = self.carriers.get(&reference) else {
                break;
            };
            if !state.delivered || !state.data_available {
                break;
            }
            let expected_previous = self.closed_prefixes[index]
                .last()
                .copied()
                .unwrap_or_else(|| carrier_genesis_reference(authority));
            if state.candidate.header().own_prev() != expected_previous {
                break;
            }
            self.closed_prefixes[index].push(reference);
        }
    }

    fn is_on_closed_prefix(&self, reference: BlockReference) -> bool {
        self.closed_tip(reference.authority)
            .is_some_and(|tip| self.is_exact_extension(Some(reference), Some(tip)))
    }

    fn ensure_frontier_closed(
        &self,
        frontier: &[Option<BlockReference>],
    ) -> Result<(), CertifiedProjectionError> {
        for (index, entry) in frontier.iter().copied().enumerate() {
            let Some(reference) = entry else {
                continue;
            };
            let authority = index as AuthorityIndex;
            let closed_tip = self.closed_tip(authority);
            if !self.is_exact_extension(Some(reference), closed_tip) {
                return Err(CertifiedProjectionError::FrontierNotClosed {
                    authority,
                    reference,
                });
            }
        }
        Ok(())
    }

    fn join_frontiers(
        &self,
        frontiers: &[DeliveryFrontierV1],
    ) -> Result<DeliveryFrontierV1, CertifiedProjectionError> {
        let mut joined = vec![None; self.committee.len()];
        for frontier in frontiers {
            for (index, right) in frontier.iter().copied().enumerate() {
                let left = joined[index];
                if self.is_exact_extension(left, right) {
                    joined[index] = right;
                } else if !self.is_exact_extension(right, left) {
                    return Err(CertifiedProjectionError::ParentFrontierFork {
                        authority: index as AuthorityIndex,
                        left,
                        right,
                    });
                }
            }
        }
        Ok(joined)
    }

    fn ensure_dominates_parent(
        &self,
        frontier: &[Option<BlockReference>],
        required: &[Option<BlockReference>],
    ) -> Result<(), CertifiedProjectionError> {
        for (index, (required, actual)) in required
            .iter()
            .copied()
            .zip(frontier.iter().copied())
            .enumerate()
        {
            if !self.is_exact_extension(required, actual) {
                return Err(CertifiedProjectionError::FrontierDoesNotDominateParent {
                    authority: index as AuthorityIndex,
                    required,
                    actual,
                });
            }
        }
        Ok(())
    }

    /// True iff `descendant` is the same exact prefix tip as `base`, or an
    /// exact self-chain extension whose intermediate carrier headers are known.
    fn is_exact_extension(
        &self,
        base: Option<BlockReference>,
        descendant: Option<BlockReference>,
    ) -> bool {
        self.exact_extension_on_closed_prefix(base, descendant)
            .unwrap_or_else(|| self.is_exact_extension_by_chain(base, descendant))
    }

    /// Resolve comparisons whose answer is already encoded by the exact
    /// per-author closed prefix. Returning `None` preserves the historical
    /// header-chain walk for staged forks and incomplete/non-closed tails.
    fn exact_extension_on_closed_prefix(
        &self,
        base: Option<BlockReference>,
        descendant: Option<BlockReference>,
    ) -> Option<bool> {
        let Some(descendant) = descendant else {
            return Some(base.is_none());
        };
        if base.is_some_and(|base| base.authority != descendant.authority) {
            return Some(false);
        }
        let base_round = base.map_or(0, |reference| reference.round);
        if descendant.round < base_round {
            return Some(false);
        }
        if base == Some(descendant) {
            return Some(true);
        }
        if descendant.round == base_round {
            return Some(match base {
                Some(_) => false,
                None => descendant == carrier_genesis_reference(descendant.authority),
            });
        }
        if !self.is_exact_closed_prefix_reference(descendant) {
            return None;
        }
        match base {
            None => Some(true),
            Some(base) if self.is_exact_closed_prefix_reference(base) => Some(true),
            Some(_) => None,
        }
    }

    fn is_exact_closed_prefix_reference(&self, reference: BlockReference) -> bool {
        if reference.round == 0 {
            return reference == carrier_genesis_reference(reference.authority);
        }
        self.closed_prefixes
            .get(reference.authority as usize)
            .and_then(|prefix| prefix.get((reference.round - 1) as usize))
            .is_some_and(|closed| *closed == reference)
    }

    fn is_exact_extension_by_chain(
        &self,
        base: Option<BlockReference>,
        descendant: Option<BlockReference>,
    ) -> bool {
        let Some(mut cursor) = descendant else {
            return base.is_none();
        };
        let authority = cursor.authority;
        if base.is_some_and(|base| base.authority != authority) {
            return false;
        }
        let base_round = base.map_or(0, |reference| reference.round);
        if cursor.round < base_round {
            return false;
        }
        while cursor.round > base_round {
            let Some(state) = self.carriers.get(&cursor) else {
                return false;
            };
            if state.candidate.header().author() != authority
                || state.candidate.reference() != cursor
            {
                return false;
            }
            cursor = state.candidate.header().own_prev();
        }
        match base {
            Some(reference) => cursor == reference,
            None => cursor == carrier_genesis_reference(authority),
        }
    }

    fn validate_leader_slot(&self, slot: LeaderSlotV1) -> Result<(), CertifiedProjectionError> {
        if slot.round == 0 || self.committee.elect_leader(slot.round) != slot.author {
            return Err(CertifiedProjectionError::InvalidLeaderSlot(slot));
        }
        Ok(())
    }

    fn vertices_at_round(
        &self,
        round: RoundNumber,
    ) -> impl Iterator<Item = (ConsensusVertexReference, &ProjectedVertex)> {
        self.vertices_by_round
            .get(&round)
            .into_iter()
            .flatten()
            .filter_map(|reference| {
                self.vertices
                    .get(reference)
                    .map(|projected| (*reference, projected))
            })
    }

    fn deterministic_round_values(
        &self,
        round: RoundNumber,
    ) -> BTreeMap<AuthorityIndex, ConsensusVertexReference> {
        let mut by_author = BTreeMap::new();
        for (reference, _) in self.vertices_at_round(round) {
            by_author.entry(reference.author()).or_insert(reference);
        }
        by_author
    }

    fn lexicographic_quorum(
        &self,
        references: impl Iterator<Item = ConsensusVertexReference>,
    ) -> Result<Option<Vec<ConsensusVertexReference>>, CertifiedProjectionError> {
        let mut stake = 0u64;
        let mut selected = Vec::new();
        for reference in references {
            let author_stake = self
                .committee
                .get_stake(reference.author())
                .ok_or(CertifiedProjectionError::StakeOverflow)?;
            stake = stake
                .checked_add(author_stake)
                .ok_or(CertifiedProjectionError::StakeOverflow)?;
            selected.push(reference);
            if stake >= self.committee.quorum_threshold() {
                return Ok(Some(selected));
            }
        }
        Ok(None)
    }

    /// Choose quorum evidence that maximizes new exact-prefix coverage without
    /// increasing the parent budget of the former canonical-prefix selector.
    ///
    /// The baseline is the lexicographic quorum unioned with every required
    /// parent. The greedy candidate set may use at most that many references.
    /// Each choice must leave enough remaining slots to complete weighted
    /// quorum stake; if freshness selection cannot do so, the known-valid
    /// baseline is returned. Required references count toward proof stake only
    /// when they are exact members of `references`.
    pub(crate) fn frontier_fresh_quorum(
        &self,
        references: impl IntoIterator<Item = ConsensusVertexReference>,
        required: &[ConsensusVertexReference],
    ) -> Result<Option<Vec<ConsensusVertexReference>>, CertifiedProjectionError> {
        let mut candidates = BTreeMap::<AuthorityIndex, ConsensusVertexReference>::new();
        for reference in references {
            candidates
                .entry(reference.author())
                .and_modify(|existing| *existing = (*existing).min(reference))
                .or_insert(reference);
        }

        let Some(baseline_proof) = self.lexicographic_quorum(candidates.values().copied())? else {
            return Ok(None);
        };
        let mut baseline = baseline_proof
            .into_iter()
            .map(|reference| (reference.author(), reference))
            .collect::<BTreeMap<_, _>>();
        if !self.extend_with_required_parents(&mut baseline, required) {
            return Ok(None);
        }
        let parent_budget = baseline.len();

        let mut selected = BTreeMap::new();
        if !self.extend_with_required_parents(&mut selected, required) {
            return Ok(None);
        }
        let mut proof_stake = selected
            .iter()
            .filter(|(author, reference)| candidates.get(author) == Some(reference))
            .try_fold(0u64, |stake, (author, _)| {
                stake
                    .checked_add(
                        self.committee
                            .get_stake(*author)
                            .ok_or(CertifiedProjectionError::StakeOverflow)?,
                    )
                    .ok_or(CertifiedProjectionError::StakeOverflow)
            })?;
        let quorum = self.committee.quorum_threshold();
        let tie_origin: RoundNumber = candidates
            .values()
            .next()
            .map_or(0, |reference| reference.consensus_round())
            % u32::try_from(self.committee.len())
                .unwrap_or(u32::MAX)
                .max(1);

        while proof_stake < quorum && selected.len() < parent_budget {
            let selected_references = selected.values().copied().collect::<Vec<_>>();
            let base = match self.joined_strong_parent_frontier(&selected_references) {
                Ok(base) => base,
                Err(_) => return Ok(Some(baseline.into_values().collect())),
            };
            let remaining_slots = parent_budget.saturating_sub(selected.len() + 1);
            let mut best = None;
            for (author, reference) in &candidates {
                if selected.contains_key(author) {
                    continue;
                }
                let Some(projected) = self.vertices.get(reference) else {
                    continue;
                };
                if self
                    .join_frontiers(&[base.clone(), projected.effective_frontier.clone()])
                    .is_err()
                {
                    continue;
                }
                let author_stake = self
                    .committee
                    .get_stake(*author)
                    .ok_or(CertifiedProjectionError::StakeOverflow)?;
                let candidate_stake = proof_stake
                    .checked_add(author_stake)
                    .ok_or(CertifiedProjectionError::StakeOverflow)?;
                let mut remaining_stakes: Vec<Stake> = candidates
                    .keys()
                    .filter(|candidate_author| {
                        **candidate_author != *author && !selected.contains_key(*candidate_author)
                    })
                    .map(|candidate_author| {
                        self.committee
                            .get_stake(*candidate_author)
                            .ok_or(CertifiedProjectionError::StakeOverflow)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                remaining_stakes.sort_unstable_by(|left: &Stake, right: &Stake| right.cmp(left));
                let maximum_completion = remaining_stakes
                    .into_iter()
                    .take(remaining_slots)
                    .try_fold(candidate_stake, |stake: Stake, next: Stake| {
                        stake
                            .checked_add(next)
                            .ok_or(CertifiedProjectionError::StakeOverflow)
                    })?;
                if maximum_completion < quorum {
                    continue;
                }

                let (advanced_components, round_advance) = base
                    .iter()
                    .zip(&projected.effective_frontier)
                    .fold((0usize, 0u64), |(components, advance), (base, tip)| {
                        let base_round = base.map_or(0, |reference| reference.round);
                        let tip_round = tip.map_or(0, |reference| reference.round);
                        let delta = tip_round.saturating_sub(base_round);
                        (
                            components.saturating_add(usize::from(delta != 0)),
                            advance.saturating_add(u64::from(delta)),
                        )
                    });
                let committee_size = u32::try_from(self.committee.len())
                    .unwrap_or(u32::MAX)
                    .max(1);
                let rotating_rank =
                    u32::from(*author).wrapping_add(committee_size - tie_origin) % committee_size;
                let score = (
                    advanced_components,
                    round_advance,
                    Reverse(rotating_rank),
                    Reverse(*reference),
                );
                if best
                    .as_ref()
                    .is_none_or(|(best_score, _, _)| score > *best_score)
                {
                    best = Some((score, *author, *reference));
                }
            }
            let Some((_, author, reference)) = best else {
                return Ok(Some(baseline.into_values().collect()));
            };
            selected.insert(author, reference);
            proof_stake = proof_stake
                .checked_add(
                    self.committee
                        .get_stake(author)
                        .ok_or(CertifiedProjectionError::StakeOverflow)?,
                )
                .ok_or(CertifiedProjectionError::StakeOverflow)?;
        }

        if proof_stake < quorum {
            return Ok(Some(baseline.into_values().collect()));
        }
        Ok(Some(selected.into_values().collect()))
    }

    fn extend_with_required_parents(
        &self,
        selected: &mut BTreeMap<AuthorityIndex, ConsensusVertexReference>,
        required: &[ConsensusVertexReference],
    ) -> bool {
        for reference in required {
            if selected
                .insert(reference.author(), *reference)
                .is_some_and(|existing| existing != *reference)
            {
                return false;
            }
        }
        true
    }

    fn voter_authors(
        &self,
        slot: LeaderSlotV1,
        predicate: impl Fn(LeaderChoiceV1) -> bool,
    ) -> BTreeSet<AuthorityIndex> {
        self.vertices_at_round(slot.round.saturating_add(1))
            .filter_map(|(reference, projected)| {
                let choice = projected.vertex.leader_choice();
                let belongs_to_slot = match choice {
                    LeaderChoiceV1::Vote { leader } => {
                        leader.author() == slot.author && leader.consensus_round() == slot.round
                    }
                    LeaderChoiceV1::NoVote {
                        leader_author,
                        leader_round,
                    } => leader_author == slot.author && leader_round == slot.round,
                };
                (belongs_to_slot && predicate(choice)).then_some(reference.author())
            })
            .collect()
    }

    fn certifier_authors(&self, leader: ConsensusVertexReference) -> BTreeSet<AuthorityIndex> {
        self.vertices_at_round(leader.consensus_round().saturating_add(2))
            .filter_map(|(reference, _)| {
                self.is_certificate(reference, leader)
                    .then_some(reference.author())
            })
            .collect()
    }

    fn is_certificate(
        &self,
        certifier: ConsensusVertexReference,
        leader: ConsensusVertexReference,
    ) -> bool {
        let Some(projected) = self.vertices.get(&certifier) else {
            return false;
        };
        let voter_authors: BTreeSet<_> = projected
            .vertex
            .strong_parents()
            .iter()
            .filter_map(|parent| {
                self.vertices.get(parent).and_then(|voter| {
                    matches!(
                        voter.vertex.leader_choice(),
                        LeaderChoiceV1::Vote { leader: voted } if voted == leader
                    )
                    .then_some(parent.author())
                })
            })
            .collect();
        self.stake_of_authors(voter_authors)
            .is_ok_and(|stake| stake >= self.committee.quorum_threshold())
    }

    fn stake_of_authors(
        &self,
        authors: BTreeSet<AuthorityIndex>,
    ) -> Result<Stake, CertifiedProjectionError> {
        authors.into_iter().try_fold(0u64, |stake, author| {
            let author_stake = self
                .committee
                .get_stake(author)
                .ok_or(CertifiedProjectionError::StakeOverflow)?;
            stake
                .checked_add(author_stake)
                .ok_or(CertifiedProjectionError::StakeOverflow)
        })
    }

    fn reachable_at_round(
        &self,
        anchor: ConsensusVertexReference,
        target_round: RoundNumber,
    ) -> BTreeSet<ConsensusVertexReference> {
        let mut result = BTreeSet::new();
        let mut pending = vec![anchor];
        let mut seen = BTreeSet::new();
        while let Some(reference) = pending.pop() {
            if !seen.insert(reference) || reference.consensus_round() < target_round {
                continue;
            }
            if reference.consensus_round() == target_round {
                result.insert(reference);
                continue;
            }
            if let Some(projected) = self.vertices.get(&reference) {
                pending.extend(projected.vertex.strong_parents().iter().copied());
            }
        }
        result
    }

    #[cfg(test)]
    pub(crate) fn inject_projected_for_test(
        &mut self,
        reference: ConsensusVertexReference,
        strong_parents: Vec<ConsensusVertexReference>,
        leader_choice: LeaderChoiceV1,
    ) {
        let vertex = ConsensusVertexV1::new(
            reference.consensus_round(),
            strong_parents,
            vec![None; self.committee.len()],
            leader_choice,
        );
        self.vertices.insert(
            reference,
            ProjectedVertex {
                vertex,
                effective_frontier: vec![None; self.committee.len()],
            },
        );
        self.vertices_by_round
            .entry(reference.consensus_round())
            .or_default()
            .insert(reference);
        self.consensus_slots
            .entry((reference.author(), reference.consensus_round()))
            .or_default()
            .insert(reference);
    }
}

/// Independent planning-only projection over promised, data-available carrier
/// prefixes.
///
/// This wrapper deliberately exposes no decision, committed-anchor, or
/// committed-frontier API. Its inner model reuses the exact carrier-chain,
/// strong-parent, and frontier validation of the certified projection, but
/// interprets that private plane's delivery latch as `DeliveryPromised`.
/// Consequently its contiguous prefixes and projected vertices can run ahead
/// of certification without becoming output authority.
#[derive(Clone)]
pub(crate) struct PromisedProjectionModel {
    inner: CertifiedProjectionModel,
}

impl PromisedProjectionModel {
    pub(crate) fn from_committee_context(committee: RbcDagCommitteeContextV1) -> Self {
        Self {
            inner: CertifiedProjectionModel::from_committee_context(committee),
        }
    }

    pub(crate) fn stage_carrier(
        &mut self,
        candidate: CandidateCarrierV1,
    ) -> Result<(), CertifiedProjectionError> {
        self.inner.stage_carrier(candidate)
    }

    /// Mark one exact carrier promised. This advances only the planner's
    /// private contiguous prefix once local DA is also established.
    pub(crate) fn mark_promised(
        &mut self,
        reference: BlockReference,
    ) -> Result<(), CertifiedProjectionError> {
        self.inner.mark_delivered(reference)
    }

    pub(crate) fn mark_data_available(
        &mut self,
        reference: BlockReference,
    ) -> Result<(), CertifiedProjectionError> {
        self.inner.mark_data_available(reference)
    }

    #[cfg(test)]
    pub(crate) fn is_data_available(&self, reference: BlockReference) -> bool {
        self.inner.is_data_available(reference)
    }

    pub(crate) fn carrier_is_stored(&self, reference: BlockReference) -> bool {
        self.inner.carrier_is_stored(reference)
    }

    #[cfg(test)]
    pub(crate) fn promised_tip(&self, authority: AuthorityIndex) -> Option<BlockReference> {
        self.inner.closed_tip(authority)
    }

    #[cfg(test)]
    pub(crate) fn is_projected(&self, reference: ConsensusVertexReference) -> bool {
        self.inner.is_projected(reference)
    }

    #[cfg(test)]
    pub(crate) fn projected_vertex(
        &self,
        reference: ConsensusVertexReference,
    ) -> Option<&ConsensusVertexV1> {
        self.inner.projected_vertex(reference)
    }

    #[cfg(test)]
    pub(crate) fn effective_frontier(
        &self,
        reference: ConsensusVertexReference,
    ) -> Option<&[Option<BlockReference>]> {
        self.inner.effective_frontier(reference)
    }

    pub(crate) fn projected_values_at_round(
        &self,
        round: RoundNumber,
    ) -> Vec<ConsensusVertexReference> {
        self.inner.projected_values_at_round(round)
    }

    pub(crate) fn projected_stake_at_round(&self, round: RoundNumber) -> Stake {
        self.inner.projected_stake_at_round(round)
    }

    pub(crate) fn c1_strong_parent_witness(
        &self,
        consensus_round: RoundNumber,
        required_parents: &[ConsensusVertexReference],
    ) -> Result<Option<C1StrongParentWitnessV1>, CertifiedProjectionError> {
        self.inner
            .c1_strong_parent_witness(consensus_round, required_parents)
    }

    pub(crate) fn frontier_fresh_quorum(
        &self,
        references: impl IntoIterator<Item = ConsensusVertexReference>,
        required: &[ConsensusVertexReference],
    ) -> Result<Option<Vec<ConsensusVertexReference>>, CertifiedProjectionError> {
        self.inner.frontier_fresh_quorum(references, required)
    }

    pub(crate) fn joined_strong_parent_frontier(
        &self,
        strong_parents: &[ConsensusVertexReference],
    ) -> Result<DeliveryFrontierV1, CertifiedProjectionError> {
        self.inner.joined_strong_parent_frontier(strong_parents)
    }

    pub(crate) fn try_project(
        &mut self,
        carrier_reference: BlockReference,
    ) -> Result<ConsensusVertexReference, CertifiedProjectionError> {
        self.inner.try_project(carrier_reference)
    }

    #[cfg(test)]
    pub(crate) fn inject_projected_for_test(
        &mut self,
        reference: ConsensusVertexReference,
        strong_parents: Vec<ConsensusVertexReference>,
        leader_choice: LeaderChoiceV1,
    ) {
        self.inner
            .inject_projected_for_test(reference, strong_parents, leader_choice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::TransactionsCommitment,
        starfish_rbc_dag::{CarrierHeaderV1Args, LeaderChoiceV1},
        types::BlockDigest,
    };

    fn reference(authority: AuthorityIndex, round: RoundNumber, marker: u8) -> BlockReference {
        BlockReference {
            authority,
            round,
            digest: BlockDigest::from([marker; 32]),
        }
    }

    fn consensus_reference(
        authority: AuthorityIndex,
        round: RoundNumber,
        marker: u8,
    ) -> ConsensusVertexReference {
        ConsensusVertexReference::new(reference(authority, round + 20, marker), round)
    }

    fn previous_carriers(committee: &Committee, round: RoundNumber) -> Vec<BlockReference> {
        committee
            .authorities()
            .map(|authority| {
                if round == 0 {
                    carrier_genesis_reference(authority)
                } else {
                    reference(authority, round, authority as u8 + 0x80)
                }
            })
            .collect()
    }

    fn candidate(
        committee: &Committee,
        author: AuthorityIndex,
        carrier_round: RoundNumber,
        previous: &[BlockReference],
        vertex: Option<ConsensusVertexV1>,
        marker: u8,
    ) -> CandidateCarrierV1 {
        let weak_parents = previous
            .iter()
            .copied()
            .filter(|parent| parent.authority != author)
            .collect();
        CandidateCarrierV1::try_new(
            CarrierHeaderV1Args {
                author,
                carrier_round,
                own_prev: previous[author as usize],
                weak_parents,
                transactions_commitment: TransactionsCommitment::from_bytes([marker; 32]),
                application_header: None,
                data_acknowledgments: Vec::new(),
                phase_batch: Vec::new(),
                consensus_vertex: vertex,
                creation_time_ns: marker as u64,
            },
            committee,
        )
        .unwrap()
    }

    fn clean(
        model: &mut CertifiedProjectionModel,
        candidate: CandidateCarrierV1,
    ) -> BlockReference {
        let reference = candidate.reference();
        model.stage_carrier(candidate).unwrap();
        model.mark_delivered(reference).unwrap();
        model.mark_data_available(reference).unwrap();
        reference
    }

    fn close_author_history(
        model: &mut CertifiedProjectionModel,
        author: AuthorityIndex,
        rounds: RoundNumber,
    ) -> Vec<BlockReference> {
        let mut result = Vec::with_capacity(rounds as usize);
        let mut own_previous = carrier_genesis_reference(author);
        for round in 1..=rounds {
            let previous = model
                .committee
                .authorities()
                .map(|authority| {
                    if authority == author {
                        own_previous
                    } else if round == 1 {
                        carrier_genesis_reference(authority)
                    } else {
                        reference(
                            authority,
                            round - 1,
                            (authority as u8).wrapping_mul(31).wrapping_add(round as u8),
                        )
                    }
                })
                .collect::<Vec<_>>();
            let carrier = candidate(
                &model.committee,
                author,
                round,
                &previous,
                None,
                (author as u8).wrapping_mul(53).wrapping_add(round as u8),
            );
            own_previous = clean(model, carrier);
            result.push(own_previous);
        }
        result
    }

    fn assert_exact_extension_matches_chain_oracle(
        model: &CertifiedProjectionModel,
        base: Option<BlockReference>,
        descendant: Option<BlockReference>,
    ) {
        assert_eq!(
            model.is_exact_extension(base, descendant),
            model.is_exact_extension_by_chain(base, descendant),
            "base={base:?}, descendant={descendant:?}",
        );
    }

    fn first_consensus_round(
        model: &mut CertifiedProjectionModel,
    ) -> (Vec<BlockReference>, Vec<ConsensusVertexReference>) {
        let previous = previous_carriers(&model.committee, 0);
        let strong_parents: Vec<_> = model
            .committee
            .authorities()
            .map(|authority| ConsensusVertexReference::new(carrier_genesis_reference(authority), 0))
            .collect();
        let leader = strong_parents[0];
        let mut carriers = Vec::new();
        let mut vertices = Vec::new();
        let authors: Vec<_> = model.committee.authorities().collect();
        for author in authors {
            let vertex = ConsensusVertexV1::new(
                1,
                strong_parents.clone(),
                vec![None; model.committee.len()],
                LeaderChoiceV1::Vote { leader },
            );
            let carrier = candidate(
                &model.committee,
                author,
                1,
                &previous,
                Some(vertex),
                0x10 + author as u8,
            );
            let carrier_reference = clean(model, carrier);
            let vertex_reference = model.try_project(carrier_reference).unwrap();
            carriers.push(carrier_reference);
            vertices.push(vertex_reference);
        }
        (carriers, vertices)
    }

    fn second_round_candidate(
        model: &CertifiedProjectionModel,
        author: AuthorityIndex,
        previous: &[BlockReference],
        parents: Vec<ConsensusVertexReference>,
        frontier: DeliveryFrontierV1,
        marker: u8,
    ) -> CandidateCarrierV1 {
        let leader = parents
            .iter()
            .find(|parent| parent.author() == model.committee.elect_leader(1))
            .copied()
            .unwrap();
        candidate(
            &model.committee,
            author,
            2,
            previous,
            Some(ConsensusVertexV1::new(
                2,
                parents,
                frontier,
                LeaderChoiceV1::Vote { leader },
            )),
            marker,
        )
    }

    #[test]
    fn effective_frontier_includes_every_enclosing_strong_parent() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(Arc::clone(&committee)).unwrap();
        let (carriers, parents) = first_consensus_round(&mut model);

        let child = second_round_candidate(
            &model,
            0,
            &carriers,
            parents,
            carriers.iter().copied().map(Some).collect(),
            0x30,
        );
        let child_carrier = clean(&mut model, child);
        let child_vertex = model.try_project(child_carrier).unwrap();
        let effective = model.effective_frontier(child_vertex).unwrap();
        assert_eq!(effective[0], Some(child_carrier));
        let expected: Vec<_> = carriers[1..].iter().copied().map(Some).collect();
        assert_eq!(&effective[1..], expected.as_slice());
    }

    #[test]
    fn closed_prefix_exact_extension_fast_path_matches_chain_oracle() {
        const LAST_ROUND: RoundNumber = 512;

        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(committee).unwrap();
        let closed = close_author_history(&mut model, 0, LAST_ROUND);
        let genesis = carrier_genesis_reference(0);
        let closed_samples = [closed[0], closed[16], closed[255], closed[511]];

        assert_eq!(
            model.exact_extension_on_closed_prefix(None, Some(closed[511])),
            Some(true)
        );
        assert_eq!(
            model.exact_extension_on_closed_prefix(Some(closed[16]), Some(closed[511])),
            Some(true)
        );
        for base in [None, Some(genesis)]
            .into_iter()
            .chain(closed_samples.into_iter().map(Some))
        {
            for descendant in [None, Some(genesis)]
                .into_iter()
                .chain(closed_samples.into_iter().map(Some))
            {
                assert_exact_extension_matches_chain_oracle(&model, base, descendant);
            }
        }

        let same_round_fork = reference(0, LAST_ROUND, 0xF1);
        let cross_author = reference(1, LAST_ROUND, 0xF2);
        let missing_descendant = reference(0, LAST_ROUND + 4, 0xF3);
        let invalid_genesis = reference(0, 0, 0xF4);
        for (base, descendant) in [
            (Some(closed[511]), Some(same_round_fork)),
            (Some(closed[16]), Some(same_round_fork)),
            (Some(closed[16]), Some(cross_author)),
            (Some(closed[511]), Some(missing_descendant)),
            (None, Some(invalid_genesis)),
            (Some(closed[511]), None),
            (None, None),
        ] {
            assert_exact_extension_matches_chain_oracle(&model, base, descendant);
        }

        // A fully staged non-closed tail remains an exact known extension and
        // therefore exercises the historical chain-walk fallback.
        let staged_previous = model
            .committee
            .authorities()
            .map(|authority| {
                if authority == 0 {
                    closed[511]
                } else {
                    reference(authority, LAST_ROUND, 0xA0 + authority as u8)
                }
            })
            .collect::<Vec<_>>();
        let staged = candidate(
            &model.committee,
            0,
            LAST_ROUND + 1,
            &staged_previous,
            None,
            0xF5,
        );
        let staged_reference = staged.reference();
        model.stage_carrier(staged).unwrap();
        let mut staged_child_previous = staged_previous;
        staged_child_previous[0] = staged_reference;
        for (authority, previous) in staged_child_previous.iter_mut().enumerate().skip(1) {
            *previous = reference(
                authority as AuthorityIndex,
                LAST_ROUND + 1,
                0xB0 + authority as u8,
            );
        }
        let staged_child = candidate(
            &model.committee,
            0,
            LAST_ROUND + 2,
            &staged_child_previous,
            None,
            0xF6,
        );
        let staged_child_reference = staged_child.reference();
        model.stage_carrier(staged_child).unwrap();
        assert_eq!(
            model
                .exact_extension_on_closed_prefix(Some(closed[511]), Some(staged_child_reference),),
            None
        );
        assert_exact_extension_matches_chain_oracle(
            &model,
            Some(closed[511]),
            Some(staged_child_reference),
        );
        assert!(model.is_exact_extension(Some(closed[511]), Some(staged_child_reference)));

        // A staged descendant whose intermediate own-prev is absent also
        // falls back, then rejects exactly as the prior implementation did.
        let missing_previous = reference(0, LAST_ROUND + 2, 0xF7);
        let missing_chain_previous = model
            .committee
            .authorities()
            .map(|authority| {
                if authority == 0 {
                    missing_previous
                } else {
                    reference(authority, LAST_ROUND + 2, 0xC0 + authority as u8)
                }
            })
            .collect::<Vec<_>>();
        let missing_chain = candidate(
            &model.committee,
            0,
            LAST_ROUND + 3,
            &missing_chain_previous,
            None,
            0xF8,
        );
        let missing_chain_reference = missing_chain.reference();
        model.stage_carrier(missing_chain).unwrap();
        assert_exact_extension_matches_chain_oracle(
            &model,
            Some(closed[511]),
            Some(missing_chain_reference),
        );
        assert!(!model.is_exact_extension(Some(closed[511]), Some(missing_chain_reference)));
    }

    #[test]
    fn closed_prefix_fast_path_preserves_join_dominance_and_committed_frontiers() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(committee).unwrap();
        let histories = (0..4)
            .map(|authority| close_author_history(&mut model, authority, 32))
            .collect::<Vec<_>>();
        let first = vec![
            Some(histories[0][7]),
            None,
            Some(histories[2][11]),
            Some(histories[3][3]),
        ];
        let second = vec![
            Some(histories[0][15]),
            Some(histories[1][5]),
            Some(histories[2][2]),
            None,
        ];
        let joined = vec![
            Some(histories[0][15]),
            Some(histories[1][5]),
            Some(histories[2][11]),
            Some(histories[3][3]),
        ];

        assert_eq!(
            model
                .join_frontiers(&[first.clone(), second.clone()])
                .unwrap(),
            joined
        );
        model.ensure_dominates_parent(&joined, &first).unwrap();
        model.ensure_dominates_parent(&joined, &second).unwrap();
        assert!(matches!(
            model.ensure_dominates_parent(&first, &second),
            Err(CertifiedProjectionError::FrontierDoesNotDominateParent { authority: 0, .. })
        ));

        let first_anchor = consensus_reference(0, 40, 0xD1);
        let second_anchor = consensus_reference(1, 41, 0xD2);
        for anchor in [first_anchor, second_anchor] {
            model.inject_projected_for_test(
                anchor,
                Vec::new(),
                LeaderChoiceV1::NoVote {
                    leader_author: 0,
                    leader_round: 39,
                },
            );
        }
        model
            .vertices
            .get_mut(&first_anchor)
            .unwrap()
            .effective_frontier
            .clone_from(&first);
        model
            .vertices
            .get_mut(&second_anchor)
            .unwrap()
            .effective_frontier
            .clone_from(&second);
        assert_eq!(
            model
                .joined_strong_parent_frontier(&[first_anchor, second_anchor])
                .unwrap(),
            joined
        );
        assert_eq!(model.record_committed_anchor(first_anchor).unwrap(), first);
        assert_eq!(
            model.record_committed_anchor(second_anchor).unwrap(),
            joined
        );
        assert!(model.committed_frontier_dominates(&first));
        assert!(model.committed_frontier_dominates(&second));
        assert!(model.committed_frontier_dominates(&joined));

        let fork = Some(reference(2, histories[2][11].round, 0xD3));
        let mut forked = joined.clone();
        forked[2] = fork;
        assert!(matches!(
            model.join_frontiers(&[joined.clone(), forked.clone()]),
            Err(CertifiedProjectionError::ParentFrontierFork { authority: 2, .. })
        ));
        assert!(!model.committed_frontier_dominates(&forked));
        let mut beyond_commit = joined;
        beyond_commit[3] = Some(histories[3][31]);
        assert!(!model.committed_frontier_dominates(&beyond_commit));
    }

    #[test]
    fn omission_and_same_round_fork_do_not_pass_frontier_checks() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut omission_model = CertifiedProjectionModel::new(Arc::clone(&committee)).unwrap();
        let (carriers, parents) = first_consensus_round(&mut omission_model);
        let mut omitted = carriers.iter().copied().map(Some).collect::<Vec<_>>();
        omitted[2] = None;
        let child = second_round_candidate(&omission_model, 0, &carriers, parents, omitted, 0x31);
        let child_reference = clean(&mut omission_model, child);
        assert!(matches!(
            omission_model.try_project(child_reference),
            Err(CertifiedProjectionError::FrontierDoesNotDominateParent { authority: 2, .. })
        ));
        assert!(omission_model.carrier_is_stored(child_reference));

        let mut fork_model = CertifiedProjectionModel::new(committee).unwrap();
        let (carriers, parents) = first_consensus_round(&mut fork_model);
        let mut forked = carriers.iter().copied().map(Some).collect::<Vec<_>>();
        forked[2] = Some(reference(2, 1, 0xEE));
        let child = second_round_candidate(&fork_model, 0, &carriers, parents, forked, 0x32);
        let child_reference = clean(&mut fork_model, child);
        assert!(matches!(
            fork_model.try_project(child_reference),
            Err(CertifiedProjectionError::FrontierNotClosed { authority: 2, .. })
        ));
    }

    #[test]
    fn exact_strong_parent_lookup_and_parent_fork_are_enforced() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut exact_model = CertifiedProjectionModel::new(Arc::clone(&committee)).unwrap();
        let (carriers, mut parents) = first_consensus_round(&mut exact_model);
        parents[2] = ConsensusVertexReference::new(reference(2, 1, 0xEF), 1);
        let child = second_round_candidate(
            &exact_model,
            0,
            &carriers,
            parents,
            carriers.iter().copied().map(Some).collect(),
            0x33,
        );
        let child_reference = clean(&mut exact_model, child);
        assert!(matches!(
            exact_model.try_project(child_reference),
            Err(CertifiedProjectionError::MissingStrongParent(parent))
                if parent.author() == 2
        ));

        let mut fork_model = CertifiedProjectionModel::new(committee).unwrap();
        let genesis = previous_carriers(&fork_model.committee, 0);
        let base = candidate(&fork_model.committee, 0, 1, &genesis, None, 0x34);
        let base_reference = clean(&mut fork_model, base);
        let parent_references: Vec<_> = (0..3)
            .map(|authority| consensus_reference(authority, 1, 0x40 + authority as u8))
            .collect();
        for parent in &parent_references {
            fork_model.inject_projected_for_test(
                *parent,
                Vec::new(),
                LeaderChoiceV1::NoVote {
                    leader_author: 0,
                    leader_round: 0,
                },
            );
        }
        fork_model
            .vertices
            .get_mut(&parent_references[0])
            .unwrap()
            .effective_frontier[3] = Some(reference(3, 1, 0xA1));
        fork_model
            .vertices
            .get_mut(&parent_references[1])
            .unwrap()
            .effective_frontier[3] = Some(reference(3, 1, 0xA2));
        let previous = vec![
            base_reference,
            reference(1, 1, 0xB1),
            reference(2, 1, 0xB2),
            reference(3, 1, 0xB3),
        ];
        let child = second_round_candidate(
            &fork_model,
            0,
            &previous,
            parent_references,
            vec![Some(base_reference), None, None, None],
            0x35,
        );
        let child_reference = clean(&mut fork_model, child);
        assert!(matches!(
            fork_model.try_project(child_reference),
            Err(CertifiedProjectionError::ParentFrontierFork { authority: 3, .. })
        ));
    }

    #[test]
    fn concurrent_committed_anchor_frontiers_accumulate_by_exact_component_join() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(committee).unwrap();
        let (carriers, parents) = first_consensus_round(&mut model);
        let anchor = second_round_candidate(
            &model,
            0,
            &carriers,
            parents.clone(),
            carriers.iter().copied().map(Some).collect(),
            0x36,
        );
        let anchor_carrier = clean(&mut model, anchor);
        let anchor_vertex = model.try_project(anchor_carrier).unwrap();
        model.record_committed_anchor(anchor_vertex).unwrap();
        assert!(
            model.committed_frontier_dominates(
                &carriers.iter().copied().map(Some).collect::<Vec<_>>()
            )
        );

        let regressing = second_round_candidate(
            &model,
            2,
            &carriers,
            parents,
            carriers.iter().copied().map(Some).collect(),
            0x37,
        );
        let regressing_carrier = clean(&mut model, regressing);
        let regressing_vertex = model.try_project(regressing_carrier).unwrap();
        assert!(model.is_projected(regressing_vertex));
        let accumulated = model.record_committed_anchor(regressing_vertex).unwrap();
        assert_eq!(
            accumulated,
            vec![
                Some(anchor_carrier),
                Some(carriers[1]),
                Some(regressing_carrier),
                Some(carriers[3]),
            ]
        );
        assert!(model.is_committed_anchor(anchor_vertex));
        assert!(model.is_committed_anchor(regressing_vertex));
        assert!(
            model.committed_frontier_dominates(model.effective_frontier(anchor_vertex).unwrap())
        );
        assert!(
            model
                .committed_frontier_dominates(model.effective_frontier(regressing_vertex).unwrap())
        );
    }

    #[test]
    fn conflicting_consensus_values_in_one_slot_remain_visible() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(committee).unwrap();
        let (carriers, _) = first_consensus_round(&mut model);
        let genesis_parents: Vec<_> = model
            .committee
            .authorities()
            .map(|authority| ConsensusVertexReference::new(carrier_genesis_reference(authority), 0))
            .collect();
        let conflicting = candidate(
            &model.committee,
            0,
            2,
            &carriers,
            Some(ConsensusVertexV1::new(
                1,
                genesis_parents.clone(),
                carriers.iter().copied().map(Some).collect(),
                LeaderChoiceV1::Vote {
                    leader: genesis_parents[0],
                },
            )),
            0x38,
        );
        let conflicting_carrier = clean(&mut model, conflicting);
        model.try_project(conflicting_carrier).unwrap();

        let values = model.slot_values(0, 1);
        assert_eq!(values.len(), 2);
        assert_ne!(values[0], values[1]);
    }

    #[test]
    fn objective_vote_and_no_vote_shapes_are_both_projectable() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(Arc::clone(&committee)).unwrap();
        let previous = previous_carriers(&committee, 0);
        let genesis: Vec<_> = committee
            .authorities()
            .map(|authority| ConsensusVertexReference::new(carrier_genesis_reference(authority), 0))
            .collect();
        let vote = candidate(
            &committee,
            1,
            1,
            &previous,
            Some(ConsensusVertexV1::new(
                1,
                vec![genesis[0], genesis[1], genesis[2]],
                vec![None; 4],
                LeaderChoiceV1::Vote { leader: genesis[0] },
            )),
            0x39,
        );
        let vote_carrier = clean(&mut model, vote);
        let vote_reference = model.try_project(vote_carrier).unwrap();
        let no_vote = candidate(
            &committee,
            3,
            1,
            &previous,
            Some(ConsensusVertexV1::new(
                1,
                vec![genesis[1], genesis[2], genesis[3]],
                vec![None; 4],
                LeaderChoiceV1::NoVote {
                    leader_author: 0,
                    leader_round: 0,
                },
            )),
            0x3A,
        );
        let no_vote_carrier = clean(&mut model, no_vote);
        let no_vote_reference = model.try_project(no_vote_carrier).unwrap();

        assert_eq!(
            model.leader_choice(vote_reference),
            Some(LeaderChoiceV1::Vote { leader: genesis[0] })
        );
        assert!(matches!(
            model.leader_choice(no_vote_reference),
            Some(LeaderChoiceV1::NoVote {
                leader_author: 0,
                leader_round: 0
            })
        ));
    }

    #[test]
    fn dirty_or_malformed_optional_vertex_never_enters_projection() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(Arc::clone(&committee)).unwrap();
        let previous = previous_carriers(&committee, 0);
        let genesis: Vec<_> = committee
            .authorities()
            .map(|authority| ConsensusVertexReference::new(carrier_genesis_reference(authority), 0))
            .collect();
        let dirty = candidate(
            &committee,
            0,
            1,
            &previous,
            Some(ConsensusVertexV1::new(
                1,
                vec![genesis[0], genesis[1], genesis[2]],
                vec![None; 4],
                LeaderChoiceV1::Vote { leader: genesis[0] },
            )),
            0x3B,
        );
        let dirty_carrier = dirty.reference();
        model.stage_carrier(dirty).unwrap();
        assert_eq!(
            model.try_project(dirty_carrier),
            Err(CertifiedProjectionError::CarrierNotDelivered(dirty_carrier))
        );
        assert!(model.carrier_is_stored(dirty_carrier));
        assert!(model.slot_values(0, 1).is_empty());

        let malformed = candidate(
            &committee,
            1,
            1,
            &previous,
            Some(ConsensusVertexV1::new(
                1,
                vec![genesis[1]],
                vec![None; 4],
                LeaderChoiceV1::NoVote {
                    leader_author: 0,
                    leader_round: 0,
                },
            )),
            0x3C,
        );
        let malformed_carrier = clean(&mut model, malformed);
        assert!(matches!(
            model.try_project(malformed_carrier),
            Err(CertifiedProjectionError::InvalidProjectionShape(
                RbcDagProjectionError::InvalidStrongParentThreshold
            ))
        ));
        assert!(model.carrier_is_stored(malformed_carrier));
        assert!(model.slot_values(1, 1).is_empty());
    }

    #[test]
    fn missing_weak_parent_bodies_do_not_block_consensus_projection() {
        let committee = Committee::new_test(vec![1; 7]);
        let mut model = CertifiedProjectionModel::new(Arc::clone(&committee)).unwrap();
        let genesis = previous_carriers(&committee, 0);
        let base = candidate(&committee, 0, 1, &genesis, None, 0x3D);
        let base_reference = clean(&mut model, base);

        let mut previous = previous_carriers(&committee, 1);
        previous[0] = base_reference;
        let missing: Vec<_> = previous[1..=2].to_vec();
        let strong_parents: Vec<_> = committee
            .authorities()
            .map(|authority| ConsensusVertexReference::new(carrier_genesis_reference(authority), 0))
            .collect();
        let leader = strong_parents
            .iter()
            .find(|parent| parent.author() == committee.elect_leader(0))
            .copied()
            .unwrap();
        let mut frontier = vec![None; committee.len()];
        frontier[0] = Some(base_reference);
        let outer = candidate(
            &committee,
            0,
            2,
            &previous,
            Some(ConsensusVertexV1::new(
                1,
                strong_parents,
                frontier,
                LeaderChoiceV1::Vote { leader },
            )),
            0x3E,
        );
        let outer_reference = clean(&mut model, outer);

        assert!(
            missing
                .iter()
                .all(|reference| !model.carrier_is_stored(*reference))
        );
        assert!(model.try_project(outer_reference).is_ok());
    }

    fn project_complete_round(
        model: &mut CertifiedProjectionModel,
        consensus_round: RoundNumber,
        previous_carriers: &[BlockReference],
        parent_sets: &[Vec<ConsensusVertexReference>],
        choices: &[LeaderChoiceV1],
        marker_base: u8,
    ) -> (Vec<BlockReference>, Vec<ConsensusVertexReference>) {
        assert_eq!(parent_sets.len(), model.committee.len());
        assert_eq!(choices.len(), model.committee.len());
        let carrier_round = previous_carriers[0].round + 1;
        let frontier: DeliveryFrontierV1 = previous_carriers.iter().copied().map(Some).collect();
        let mut carriers = Vec::with_capacity(model.committee.len());
        let mut vertices = Vec::with_capacity(model.committee.len());
        for author in 0..model.committee.len() as AuthorityIndex {
            let carrier = candidate(
                &model.committee,
                author,
                carrier_round,
                previous_carriers,
                Some(ConsensusVertexV1::new(
                    consensus_round,
                    parent_sets[author as usize].clone(),
                    frontier.clone(),
                    choices[author as usize],
                )),
                marker_base + author as u8,
            );
            let carrier_reference = clean(model, carrier);
            let vertex_reference = model.try_project(carrier_reference).unwrap();
            carriers.push(carrier_reference);
            vertices.push(vertex_reference);
        }
        (carriers, vertices)
    }

    #[test]
    fn direct_commit_uses_clean_projected_voters_and_certifiers() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(committee).unwrap();
        let (round_one_carriers, round_one_vertices) = first_consensus_round(&mut model);
        let slot = model.leader_slot(1);
        let leader = round_one_vertices[slot.author as usize];

        let voter_parents = vec![round_one_vertices.clone(); 4];
        let voter_choices = vec![LeaderChoiceV1::Vote { leader }; 4];
        let (round_two_carriers, round_two_vertices) = project_complete_round(
            &mut model,
            2,
            &round_one_carriers,
            &voter_parents,
            &voter_choices,
            0x50,
        );
        assert_eq!(model.vote_stake(leader).unwrap(), 4);

        let round_two_leader = round_two_vertices[model.committee.elect_leader(2) as usize];
        let certifier_parents = vec![round_two_vertices; 4];
        let certifier_choices = vec![
            LeaderChoiceV1::Vote {
                leader: round_two_leader,
            };
            4
        ];
        project_complete_round(
            &mut model,
            3,
            &round_two_carriers,
            &certifier_parents,
            &certifier_choices,
            0x60,
        );

        assert_eq!(
            model.direct_decision(slot).unwrap(),
            ProjectionDecisionV1::DirectCommit { leader }
        );
    }

    #[test]
    fn c1_waits_for_an_exact_vote_quorum_and_returns_only_its_witness() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(committee).unwrap();
        let (round_one_carriers, round_one_vertices) = first_consensus_round(&mut model);
        let slot = model.leader_slot(1);
        let leader = round_one_vertices[slot.author as usize];
        let frontier = round_one_carriers
            .iter()
            .copied()
            .map(Some)
            .collect::<Vec<_>>();

        let choices = [
            LeaderChoiceV1::Vote { leader },
            LeaderChoiceV1::Vote { leader },
            LeaderChoiceV1::Vote { leader },
            LeaderChoiceV1::NoVote {
                leader_author: slot.author,
                leader_round: slot.round,
            },
        ];
        let mut projected = BTreeMap::new();
        for author in [0, 1, 3] {
            let parents = if author == 3 {
                round_one_vertices
                    .iter()
                    .copied()
                    .filter(|parent| parent.author() != slot.author)
                    .collect()
            } else {
                round_one_vertices.clone()
            };
            let carrier = candidate(
                &model.committee,
                author,
                2,
                &round_one_carriers,
                Some(ConsensusVertexV1::new(
                    2,
                    parents,
                    frontier.clone(),
                    choices[author as usize],
                )),
                0xD0 + author as u8,
            );
            let carrier = clean(&mut model, carrier);
            projected.insert(author, model.try_project(carrier).unwrap());
        }
        assert_eq!(model.c1_strong_parent_witness(3, &[]).unwrap(), None);

        let author = 2;
        let carrier = candidate(
            &model.committee,
            author,
            2,
            &round_one_carriers,
            Some(ConsensusVertexV1::new(
                2,
                round_one_vertices,
                frontier,
                choices[author as usize],
            )),
            0xD0 + author as u8,
        );
        let carrier = clean(&mut model, carrier);
        projected.insert(author, model.try_project(carrier).unwrap());

        let witness = model
            .c1_strong_parent_witness(3, &[])
            .unwrap()
            .expect("the third exact vote completes C1");
        assert_eq!(
            witness,
            C1StrongParentWitnessV1::Vote {
                leader,
                parents: [0, 1, 2]
                    .into_iter()
                    .map(|author| projected[&author])
                    .collect(),
            }
        );
        let C1StrongParentWitnessV1::Vote { parents, .. } = witness else {
            panic!("the exact vote quorum must return a vote witness");
        };
        assert!(!parents.iter().any(|parent| parent.author() == 3));
    }

    #[test]
    fn c1_exact_vote_witness_is_not_hidden_by_a_smaller_byzantine_equivocation() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(committee).unwrap();
        let (_, round_one_vertices) = first_consensus_round(&mut model);
        let slot = model.leader_slot(1);
        let leader = round_one_vertices[slot.author as usize];
        let no_vote = LeaderChoiceV1::NoVote {
            leader_author: slot.author,
            leader_round: slot.round,
        };

        let byzantine_no_vote = consensus_reference(0, 2, 0x10);
        let byzantine_vote = consensus_reference(0, 2, 0xF0);
        assert!(byzantine_no_vote < byzantine_vote);
        model.inject_projected_for_test(byzantine_no_vote, Vec::new(), no_vote);
        model.inject_projected_for_test(
            byzantine_vote,
            Vec::new(),
            LeaderChoiceV1::Vote { leader },
        );

        let voter_one = consensus_reference(1, 2, 0x21);
        let voter_two = consensus_reference(2, 2, 0x22);
        let non_voter = consensus_reference(3, 2, 0x23);
        for voter in [voter_one, voter_two] {
            model.inject_projected_for_test(voter, Vec::new(), LeaderChoiceV1::Vote { leader });
        }
        model.inject_projected_for_test(non_voter, Vec::new(), no_vote);

        assert_eq!(
            model.c1_strong_parent_witness(3, &[]).unwrap(),
            Some(C1StrongParentWitnessV1::Vote {
                leader,
                parents: vec![byzantine_vote, voter_one, voter_two],
            })
        );
    }

    #[test]
    fn joined_parent_frontier_omits_unrelated_fresh_closed_tips() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(committee).unwrap();
        let (carriers, vertices) = first_consensus_round(&mut model);
        assert_eq!(
            model.closed_frontier(),
            carriers.iter().copied().map(Some).collect::<Vec<_>>()
        );

        let joined = model.joined_strong_parent_frontier(&vertices[..3]).unwrap();
        assert_eq!(
            joined,
            vec![
                Some(carriers[0]),
                Some(carriers[1]),
                Some(carriers[2]),
                None
            ]
        );
    }

    #[test]
    fn frontier_fresh_quorum_preserves_weighted_stake_and_parent_budget() {
        let committee = Committee::new_test(vec![4, 3, 2, 1, 1]);
        let mut model = CertifiedProjectionModel::new(Arc::clone(&committee)).unwrap();
        let previous = previous_carriers(&committee, 0);
        let mut vertices = Vec::new();
        for author in committee.authorities() {
            let carrier = candidate(&committee, author, 1, &previous, None, 0x70 + author as u8);
            let carrier_reference = carrier.reference();
            model.stage_carrier(carrier).unwrap();
            let vertex = ConsensusVertexReference::new(carrier_reference, 1);
            model.inject_projected_for_test(
                vertex,
                Vec::new(),
                LeaderChoiceV1::NoVote {
                    leader_author: 0,
                    leader_round: 0,
                },
            );
            model.vertices.get_mut(&vertex).unwrap().effective_frontier[author as usize] =
                Some(carrier_reference);
            vertices.push(vertex);
        }

        // The previous lexicographic proof used authors 0, 1, and 2; adding
        // required author 4 gave a four-parent hard budget.
        let selected = model
            .frontier_fresh_quorum(vertices.iter().copied(), &[vertices[4]])
            .unwrap()
            .unwrap();
        let selected_stake = selected
            .iter()
            .map(|reference| committee.get_stake(reference.author()).unwrap())
            .sum::<Stake>();
        assert!(selected_stake >= committee.quorum_threshold());
        assert!(selected.contains(&vertices[4]));
        assert!(selected.len() <= 4);
        assert_eq!(
            selected
                .iter()
                .map(|reference| reference.author())
                .collect::<BTreeSet<_>>()
                .len(),
            selected.len(),
            "one equivocating author must never contribute stake twice"
        );
    }

    fn simulated_parent_frontier_inclusion_lags(frontier_fresh: bool) -> Vec<Vec<RoundNumber>> {
        const N: usize = 10;
        const ROUNDS: RoundNumber = 30;

        let committee = Committee::new_test(vec![1; N]);
        let mut model = CertifiedProjectionModel::new(Arc::clone(&committee)).unwrap();
        let mut previous = previous_carriers(&committee, 0);
        let mut vertices_by_round = vec![Vec::new(); ROUNDS as usize + 1];

        for round in 1..=ROUNDS {
            let mut carriers = Vec::with_capacity(N);
            for author in committee.authorities() {
                let marker = ((round as usize * 17 + author as usize) % 251) as u8;
                let carrier = candidate(&committee, author, round, &previous, None, marker);
                let reference = carrier.reference();
                model.stage_carrier(carrier).unwrap();
                carriers.push(reference);
            }

            let mut round_vertices = Vec::with_capacity(N);
            for author in committee.authorities() {
                let mut effective_frontier = vec![None; N];
                if round > 1 {
                    let parent_values = &vertices_by_round[round as usize - 1];
                    let leader = parent_values[committee.elect_leader(round - 1) as usize];
                    let own = parent_values[author as usize];
                    let required = [own, leader];
                    let strong_parents = if frontier_fresh {
                        model
                            .frontier_fresh_quorum(parent_values.iter().copied(), &required)
                            .unwrap()
                            .unwrap()
                    } else {
                        let mut selected = BTreeMap::new();
                        if round >= 3 {
                            let mut proof_stake = 0;
                            for parent in parent_values {
                                selected.insert(parent.author(), *parent);
                                proof_stake += committee.get_stake(parent.author()).unwrap();
                                if proof_stake >= committee.quorum_threshold() {
                                    break;
                                }
                            }
                            for parent in required {
                                selected.insert(parent.author(), parent);
                            }
                        } else {
                            for parent in required {
                                selected.insert(parent.author(), parent);
                            }
                            let mut stake = selected
                                .keys()
                                .map(|authority| committee.get_stake(*authority).unwrap())
                                .sum::<Stake>();
                            for parent in parent_values {
                                if stake >= committee.quorum_threshold() {
                                    break;
                                }
                                if selected.insert(parent.author(), *parent).is_none() {
                                    stake += committee.get_stake(parent.author()).unwrap();
                                }
                            }
                        }
                        selected.into_values().collect()
                    };
                    effective_frontier = model
                        .joined_strong_parent_frontier(&strong_parents)
                        .unwrap();
                }
                effective_frontier[author as usize] = Some(carriers[author as usize]);
                let vertex = ConsensusVertexReference::new(carriers[author as usize], round);
                model.inject_projected_for_test(
                    vertex,
                    Vec::new(),
                    LeaderChoiceV1::NoVote {
                        leader_author: committee.elect_leader(round.saturating_sub(1)),
                        leader_round: round.saturating_sub(1),
                    },
                );
                model.vertices.get_mut(&vertex).unwrap().effective_frontier = effective_frontier;
                round_vertices.push(vertex);
            }
            vertices_by_round[round as usize] = round_vertices;
            previous = carriers;
        }

        let mut lags = vec![Vec::new(); N];
        // Leave a complete leader rotation at the tail so the intentionally
        // biased baseline also has time to include every high-index author.
        for application_round in 3..=ROUNDS - 12 {
            for author in committee.authorities() {
                let first_anchor = (application_round..=ROUNDS - 2)
                    .find(|anchor_round| {
                        let leader = vertices_by_round[*anchor_round as usize]
                            [committee.elect_leader(*anchor_round) as usize];
                        model.effective_frontier(leader).unwrap()[author as usize]
                            .is_some_and(|tip| tip.round >= application_round)
                    })
                    .expect("every healthy application prefix must reach a committed leader");
                lags[author as usize].push(first_anchor - application_round);
            }
        }
        lags
    }

    #[test]
    fn frontier_fresh_quorums_remove_lexicographic_author_inclusion_tail() {
        let lexicographic = simulated_parent_frontier_inclusion_lags(false);
        let low_author_average = lexicographic[..7]
            .iter()
            .flatten()
            .copied()
            .map(u64::from)
            .sum::<u64>() as f64
            / lexicographic[..7].iter().map(Vec::len).sum::<usize>() as f64;
        let high_author_average = lexicographic[7..]
            .iter()
            .flatten()
            .copied()
            .map(u64::from)
            .sum::<u64>() as f64
            / lexicographic[7..].iter().map(Vec::len).sum::<usize>() as f64;
        assert!(
            high_author_average > low_author_average + 2.0,
            "the regression fixture must expose the former 0..6/7..9 tail"
        );

        let fresh = simulated_parent_frontier_inclusion_lags(true);
        let maximum_lag = fresh.iter().flatten().copied().max().unwrap();
        assert!(
            maximum_lag <= 2,
            "a healthy n=10 frontier should enter a leader within two logical rounds, got {fresh:?}"
        );
        let per_author_average = fresh
            .iter()
            .map(|lags| lags.iter().copied().map(u64::from).sum::<u64>() as f64 / lags.len() as f64)
            .collect::<Vec<_>>();
        let minimum = per_author_average.iter().copied().reduce(f64::min).unwrap();
        let maximum = per_author_average.iter().copied().reduce(f64::max).unwrap();
        assert!(
            maximum - minimum < 1.0,
            "author skew remains: {per_author_average:?}"
        );
    }

    #[test]
    fn direct_skip_uses_clean_projected_explicit_negative_choices() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(committee).unwrap();
        let (round_one_carriers, round_one_vertices) = first_consensus_round(&mut model);
        let slot = model.leader_slot(1);
        let leader = round_one_vertices[slot.author as usize];
        let negative_parents = vec![
            round_one_vertices[0],
            round_one_vertices[2],
            round_one_vertices[3],
        ];
        let voter_parents = vec![
            negative_parents.clone(),
            vec![
                round_one_vertices[0],
                round_one_vertices[1],
                round_one_vertices[2],
            ],
            negative_parents.clone(),
            negative_parents,
        ];
        let no_vote = LeaderChoiceV1::NoVote {
            leader_author: slot.author,
            leader_round: slot.round,
        };
        let voter_choices = vec![no_vote, LeaderChoiceV1::Vote { leader }, no_vote, no_vote];
        let (_, voters) = project_complete_round(
            &mut model,
            2,
            &round_one_carriers,
            &voter_parents,
            &voter_choices,
            0x70,
        );

        assert_eq!(
            model.direct_decision(slot).unwrap(),
            ProjectionDecisionV1::DirectSkip { slot }
        );
        assert_eq!(
            model.c1_strong_parent_witness(3, &[]).unwrap(),
            Some(C1StrongParentWitnessV1::DirectSkip {
                slot,
                parents: [voters[0], voters[2], voters[3]].to_vec(),
            })
        );
    }

    fn indirect_graph(
        include_certificate: bool,
    ) -> (
        CertifiedProjectionModel,
        LeaderSlotV1,
        ConsensusVertexReference,
        ConsensusVertexReference,
    ) {
        let committee = Committee::new_test(vec![1; 4]);
        let mut model = CertifiedProjectionModel::new(committee).unwrap();
        let (round_one_carriers, round_one_vertices) = first_consensus_round(&mut model);
        let slot = model.leader_slot(1);
        let leader = round_one_vertices[slot.author as usize];

        let voter_parent_sets = vec![
            vec![
                round_one_vertices[0],
                round_one_vertices[1],
                round_one_vertices[2],
            ],
            vec![
                round_one_vertices[0],
                round_one_vertices[1],
                round_one_vertices[2],
            ],
            vec![
                round_one_vertices[0],
                round_one_vertices[1],
                round_one_vertices[2],
            ],
            vec![
                round_one_vertices[0],
                round_one_vertices[2],
                round_one_vertices[3],
            ],
        ];
        let no_vote_round_one = LeaderChoiceV1::NoVote {
            leader_author: slot.author,
            leader_round: slot.round,
        };
        let voter_choices = vec![
            LeaderChoiceV1::Vote { leader },
            LeaderChoiceV1::Vote { leader },
            LeaderChoiceV1::Vote { leader },
            no_vote_round_one,
        ];
        let (round_two_carriers, round_two_vertices) = project_complete_round(
            &mut model,
            2,
            &round_one_carriers,
            &voter_parent_sets,
            &voter_choices,
            0x80,
        );

        let certifier_parent_sets = vec![
            vec![
                round_two_vertices[0],
                round_two_vertices[1],
                round_two_vertices[2],
            ],
            vec![
                round_two_vertices[0],
                round_two_vertices[1],
                round_two_vertices[3],
            ],
            vec![
                round_two_vertices[0],
                round_two_vertices[2],
                round_two_vertices[3],
            ],
            vec![
                round_two_vertices[1],
                round_two_vertices[2],
                round_two_vertices[3],
            ],
        ];
        let round_two_leader = round_two_vertices[model.committee.elect_leader(2) as usize];
        let no_vote_round_two = LeaderChoiceV1::NoVote {
            leader_author: model.committee.elect_leader(2),
            leader_round: 2,
        };
        let certifier_choices = vec![
            LeaderChoiceV1::Vote {
                leader: round_two_leader,
            },
            no_vote_round_two,
            LeaderChoiceV1::Vote {
                leader: round_two_leader,
            },
            LeaderChoiceV1::Vote {
                leader: round_two_leader,
            },
        ];
        let (round_three_carriers, round_three_vertices) = project_complete_round(
            &mut model,
            3,
            &round_two_carriers,
            &certifier_parent_sets,
            &certifier_choices,
            0x90,
        );
        assert_eq!(
            model.direct_decision(slot).unwrap(),
            ProjectionDecisionV1::Undecided { slot }
        );

        let (anchor_author, anchor_parents, anchor_choice) = if include_certificate {
            (
                0,
                round_three_vertices[..3].to_vec(),
                LeaderChoiceV1::NoVote {
                    leader_author: model.committee.elect_leader(3),
                    leader_round: 3,
                },
            )
        } else {
            (
                3,
                round_three_vertices[1..].to_vec(),
                LeaderChoiceV1::Vote {
                    leader: round_three_vertices[3],
                },
            )
        };
        let anchor_carrier = candidate(
            &model.committee,
            anchor_author,
            4,
            &round_three_carriers,
            Some(ConsensusVertexV1::new(
                4,
                anchor_parents,
                round_three_carriers.iter().copied().map(Some).collect(),
                anchor_choice,
            )),
            if include_certificate { 0xA0 } else { 0xA1 },
        );
        let anchor_carrier = clean(&mut model, anchor_carrier);
        let anchor = model.try_project(anchor_carrier).unwrap();
        (model, slot, leader, anchor)
    }

    #[test]
    fn later_selected_anchor_drives_indirect_commit_or_skip_before_frontier_application() {
        let (commit_model, slot, leader, commit_anchor) = indirect_graph(true);
        assert_eq!(
            commit_model.indirect_decision(slot, commit_anchor).unwrap(),
            ProjectionDecisionV1::IndirectCommit {
                leader,
                anchor: commit_anchor,
            }
        );

        let (skip_model, slot, _, skip_anchor) = indirect_graph(false);
        assert_eq!(
            skip_model.indirect_decision(slot, skip_anchor).unwrap(),
            ProjectionDecisionV1::IndirectSkip {
                slot,
                anchor: skip_anchor,
            }
        );
    }

    #[test]
    fn already_dominated_anchor_identity_remains_usable_for_indirect_decision() {
        let (mut model, slot, leader, anchor) = indirect_graph(true);
        let anchor_frontier = model.effective_frontier(anchor).unwrap().to_vec();
        let anchor_previous = model
            .carriers
            .get(&anchor.carrier())
            .unwrap()
            .candidate
            .header()
            .own_prev();
        let previous = model
            .committee
            .authorities()
            .map(|authority| {
                if authority == anchor.author() {
                    anchor_previous
                } else {
                    model.closed_tip(authority).unwrap()
                }
            })
            .collect::<Vec<_>>();
        let extension = candidate(&model.committee, 1, 4, &previous, None, 0xB0);
        let extension = clean(&mut model, extension);

        let dominating = consensus_reference(1, 5, 0xB1);
        model.inject_projected_for_test(
            dominating,
            Vec::new(),
            LeaderChoiceV1::NoVote {
                leader_author: model.committee.elect_leader(4),
                leader_round: 4,
            },
        );
        let mut dominating_frontier = anchor_frontier;
        dominating_frontier[1] = Some(extension);
        model
            .vertices
            .get_mut(&dominating)
            .unwrap()
            .effective_frontier
            .clone_from(&dominating_frontier);
        assert_eq!(
            model.record_committed_anchor(dominating).unwrap(),
            dominating_frontier
        );
        assert_eq!(
            model.record_committed_anchor(anchor).unwrap(),
            dominating_frontier
        );
        assert!(model.is_committed_anchor(anchor));
        assert_eq!(
            model.indirect_decision(slot, anchor).unwrap(),
            ProjectionDecisionV1::IndirectCommit { leader, anchor }
        );
    }
}
