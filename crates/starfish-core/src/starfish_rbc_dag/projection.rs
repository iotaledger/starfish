// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Pure executable model of the certified Starfish projection.
//!
//! This module deliberately has no network, storage, pacemaker, or production
//! consensus integration. It models the boundary at which an RBC-delivered,
//! data-available carrier may contribute its optional consensus vertex, and it
//! evaluates the explicit vote/no-vote evidence committed by those vertices.

use std::{
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    FrontierRegressesCommitted {
        authority: AuthorityIndex,
        committed: Option<BlockReference>,
        actual: Option<BlockReference>,
    },
    StakeOverflow,
    InvalidLeaderSlot(LeaderSlotV1),
    MultipleCertifiedLeaderValues(LeaderSlotV1),
    ConflictingDirectDecision(LeaderSlotV1),
    AnchorNotCommitted(ConsensusVertexReference),
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

    /// Record an externally selected committed anchor while enforcing exact
    /// componentwise frontier monotonicity. The runtime committer remains out
    /// of scope for this model.
    pub fn record_committed_anchor(
        &mut self,
        anchor: ConsensusVertexReference,
    ) -> Result<(), CertifiedProjectionError> {
        let projected = self
            .vertices
            .get(&anchor)
            .ok_or(CertifiedProjectionError::MissingStrongParent(anchor))?;
        let frontier = projected.effective_frontier.clone();
        self.ensure_dominates_committed(&frontier)?;
        self.committed_frontier = frontier;
        self.committed_anchors.insert(anchor);
        Ok(())
    }

    /// Decide an older leader from a later committed anchor. A reachable
    /// certifying-round vertex with a QC yields commit; absence yields skip.
    pub fn indirect_decision(
        &self,
        slot: LeaderSlotV1,
        anchor: ConsensusVertexReference,
    ) -> Result<ProjectionDecisionV1, CertifiedProjectionError> {
        self.validate_leader_slot(slot)?;
        if !self.committed_anchors.contains(&anchor) {
            return Err(CertifiedProjectionError::AnchorNotCommitted(anchor));
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

    fn ensure_dominates_committed(
        &self,
        frontier: &[Option<BlockReference>],
    ) -> Result<(), CertifiedProjectionError> {
        for (index, (committed, actual)) in self
            .committed_frontier
            .iter()
            .copied()
            .zip(frontier.iter().copied())
            .enumerate()
        {
            if !self.is_exact_extension(committed, actual) {
                return Err(CertifiedProjectionError::FrontierRegressesCommitted {
                    authority: index as AuthorityIndex,
                    committed,
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
        self.vertices
            .iter()
            .filter(move |(reference, _)| reference.consensus_round() == round)
            .map(|(reference, projected)| (*reference, projected))
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
    fn inject_projected_for_test(
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
        self.consensus_slots
            .entry((reference.author(), reference.consensus_round()))
            .or_default()
            .insert(reference);
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
    fn late_vertex_remains_visible_but_cannot_become_a_regressing_anchor() {
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
        assert!(matches!(
            model.record_committed_anchor(regressing_vertex),
            Err(CertifiedProjectionError::FrontierRegressesCommitted { authority: 0, .. })
        ));
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
        project_complete_round(
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
        model.record_committed_anchor(anchor).unwrap();
        (model, slot, leader, anchor)
    }

    #[test]
    fn later_committed_anchor_drives_indirect_commit_or_skip() {
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
}
