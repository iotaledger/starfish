// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Canonical carrier types for the experimental embedded-RBC Starfish DAG.
//!
//! This module is deliberately independent from the implemented direct-message
//! `starfish_rbc` protocol. An opt-in persisted shadow adapter consumes these
//! types without influencing consensus; authoritative integration remains a
//! later milestone.

pub mod journal;
pub mod model;
pub mod projection;
pub mod storage;

use std::{
    collections::{BTreeSet, HashSet},
    error::Error,
    fmt,
    sync::Arc,
};

use crate::{
    committee::Committee,
    crypto::{
        Blake3Hasher, MAC_TAG_SIZE, ML_DSA_44_SIGNATURE_SIZE, ML_DSA_65_SIGNATURE_SIZE, MacKey,
        MacTag, MlDsa44SignatureBytes, MlDsa44Signer, MlDsa65SignatureBytes, MlDsa65Signer,
        SIGNATURE_SIZE, SignatureBytes, Signer, TransactionsCommitment,
    },
    types::{
        AuthorityIndex, BlockAuthenticationScheme, BlockDigest, BlockReference, MAX_COMMITTEE_SIZE,
        RoundNumber, TimestampNs,
    },
};

pub const CARRIER_FORMAT_VERSION_V1: u8 = 1;
pub const CARRIER_WIRE_FORMAT_VERSION_V1: u8 = 0x81;
pub const MAX_CARRIER_CONTENT_SIZE_V1: usize = 4 * 1024 * 1024;
pub const MAX_PHASE_STATEMENTS_V1: usize = 2_048;

const CONTENT_FORMAT_FIELD: u8 = 0x00;
const AUTHOR_FIELD: u8 = 0x01;
const CARRIER_ROUND_FIELD: u8 = 0x02;
const OWN_PREV_FIELD: u8 = 0x03;
const WEAK_PARENTS_FIELD: u8 = 0x04;
const TRANSACTIONS_COMMITMENT_FIELD: u8 = 0x05;
const ACKNOWLEDGMENTS_FIELD: u8 = 0x06;
const PHASE_BATCH_FIELD: u8 = 0x07;
const CONSENSUS_VERTEX_FIELD: u8 = 0x08;
const CREATION_TIME_FIELD: u8 = 0x09;
const CONSENSUS_ROUND_FIELD: u8 = 0x01;
const STRONG_PARENTS_FIELD: u8 = 0x02;
const DELIVERY_FRONTIER_FIELD: u8 = 0x03;
const LEADER_CHOICE_FIELD: u8 = 0x04;

const OPTION_NONE: u8 = 0;
const OPTION_SOME: u8 = 1;
const PHASE_ECHO: u8 = 0;
const PHASE_READY: u8 = 1;
const LEADER_NONE: u8 = 0;
const LEADER_VOTE: u8 = 1;
const LEADER_NO_VOTE: u8 = 2;
const BLOCK_REFERENCE_SIZE: usize = 2 + 4 + 32;
const PROTOCOL_INSTANCE_SIZE: usize = 32;
const COMMITTEE_ID_SIZE: usize = 32;
const AUTHENTICATION_DOMAIN: &[u8; 19] = b"STARFISH_RBC_DAG_V1";
const COMMITTEE_ID_DERIVE_CONTEXT: &str = "STARFISH_RBC_DAG_V1_COMMITTEE_ID";
const CARRIER_AUTHENTICATION_KIND: u8 = 0;
const AUTHENTICATION_BASE_SIZE: usize = 123;
const AUTHENTICATION_MAC_SIZE: usize = AUTHENTICATION_BASE_SIZE + 2;

#[cfg(test)]
std::thread_local! {
    static COMMITTEE_ID_DERIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RbcPhaseStatementV1 {
    Echo { target: BlockReference },
    Ready { target: BlockReference },
}

impl RbcPhaseStatementV1 {
    pub fn target(self) -> BlockReference {
        match self {
            Self::Echo { target } | Self::Ready { target } => target,
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Echo { .. } => PHASE_ECHO,
            Self::Ready { .. } => PHASE_READY,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConsensusVertexReference {
    carrier: BlockReference,
    consensus_round: RoundNumber,
}

impl ConsensusVertexReference {
    pub const fn new(carrier: BlockReference, consensus_round: RoundNumber) -> Self {
        Self {
            carrier,
            consensus_round,
        }
    }

    pub const fn carrier(self) -> BlockReference {
        self.carrier
    }

    pub const fn consensus_round(self) -> RoundNumber {
        self.consensus_round
    }

    pub const fn author(self) -> AuthorityIndex {
        self.carrier.authority
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LeaderChoiceV1 {
    Vote {
        leader: ConsensusVertexReference,
    },
    NoVote {
        leader_author: AuthorityIndex,
        leader_round: RoundNumber,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsensusVertexV1 {
    consensus_round: RoundNumber,
    strong_parents: Vec<ConsensusVertexReference>,
    delivery_frontier: Vec<Option<BlockReference>>,
    leader_choice: LeaderChoiceV1,
}

impl ConsensusVertexV1 {
    pub fn new(
        consensus_round: RoundNumber,
        strong_parents: Vec<ConsensusVertexReference>,
        delivery_frontier: Vec<Option<BlockReference>>,
        leader_choice: LeaderChoiceV1,
    ) -> Self {
        Self {
            consensus_round,
            strong_parents,
            delivery_frontier,
            leader_choice,
        }
    }

    pub fn consensus_round(&self) -> RoundNumber {
        self.consensus_round
    }

    pub fn strong_parents(&self) -> &[ConsensusVertexReference] {
        &self.strong_parents
    }

    pub fn delivery_frontier(&self) -> &[Option<BlockReference>] {
        &self.delivery_frontier
    }

    pub fn leader_choice(&self) -> LeaderChoiceV1 {
        self.leader_choice
    }

    /// Validate the context-free certified-projection shape of this optional
    /// vertex. Callers intentionally invoke this separately from carrier
    /// candidacy: failure excludes only the optional vertex.
    pub fn validate_projection_shape(
        &self,
        enclosing_author: AuthorityIndex,
        committee: &Committee,
    ) -> Result<(), RbcDagProjectionError> {
        if self.consensus_round == 0 {
            return Err(RbcDagProjectionError::GenesisVertexEncoded);
        }
        if !committee.known_authority(enclosing_author) {
            return Err(RbcDagProjectionError::UnknownAuthority(enclosing_author));
        }
        if self.strong_parents.len() > committee.len() {
            return Err(RbcDagProjectionError::InvalidStrongParentCount(
                self.strong_parents.len(),
            ));
        }

        let parent_round = self.consensus_round - 1;
        let mut previous_authority = None;
        let mut parent_stake = 0u64;
        let mut includes_own_previous = false;
        for parent in &self.strong_parents {
            let authority = parent.author();
            if !committee.known_authority(authority) {
                return Err(RbcDagProjectionError::UnknownAuthority(authority));
            }
            if previous_authority.is_some_and(|previous| previous >= authority) {
                return Err(RbcDagProjectionError::StrongParentsNotOrdered);
            }
            previous_authority = Some(authority);
            if parent.consensus_round != parent_round {
                return Err(RbcDagProjectionError::InvalidStrongParent(*parent));
            }
            if parent_round == 0 && parent.carrier != carrier_genesis_reference(authority) {
                return Err(RbcDagProjectionError::InvalidStrongParent(*parent));
            }
            includes_own_previous |= authority == enclosing_author;
            parent_stake = parent_stake
                .checked_add(
                    committee
                        .get_stake(authority)
                        .ok_or(RbcDagProjectionError::UnknownAuthority(authority))?,
                )
                .ok_or(RbcDagProjectionError::StakeOverflow)?;
        }
        if parent_stake < committee.quorum_threshold() {
            return Err(RbcDagProjectionError::InvalidStrongParentThreshold);
        }
        if !includes_own_previous {
            return Err(RbcDagProjectionError::MissingOwnStrongParent);
        }

        if self.delivery_frontier.len() != committee.len() {
            return Err(RbcDagProjectionError::InvalidFrontierLength {
                expected: committee.len(),
                actual: self.delivery_frontier.len(),
            });
        }
        for (authority, entry) in self.delivery_frontier.iter().enumerate() {
            if let Some(reference) = entry {
                if reference.authority as usize != authority || reference.round == 0 {
                    return Err(RbcDagProjectionError::InvalidFrontierEntry {
                        authority: authority as AuthorityIndex,
                        reference: *reference,
                    });
                }
            }
        }

        let expected_leader = committee.elect_leader(parent_round);
        match self.leader_choice {
            LeaderChoiceV1::Vote { leader } => {
                if leader.consensus_round != parent_round
                    || leader.author() != expected_leader
                    || !self.strong_parents.contains(&leader)
                {
                    return Err(RbcDagProjectionError::InvalidLeaderVote(leader));
                }
            }
            LeaderChoiceV1::NoVote {
                leader_author,
                leader_round,
            } => {
                if leader_author != expected_leader
                    || leader_round != parent_round
                    || self
                        .strong_parents
                        .iter()
                        .any(|parent| parent.author() == expected_leader)
                {
                    return Err(RbcDagProjectionError::InvalidNoVote {
                        leader_author,
                        leader_round,
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RbcDagProjectionError {
    CommitteeMismatch,
    GenesisVertexEncoded,
    UnknownAuthority(AuthorityIndex),
    InvalidStrongParentCount(usize),
    StrongParentsNotOrdered,
    InvalidStrongParent(ConsensusVertexReference),
    StakeOverflow,
    InvalidStrongParentThreshold,
    MissingOwnStrongParent,
    InvalidFrontierLength {
        expected: usize,
        actual: usize,
    },
    InvalidFrontierEntry {
        authority: AuthorityIndex,
        reference: BlockReference,
    },
    InvalidLeaderVote(ConsensusVertexReference),
    InvalidNoVote {
        leader_author: AuthorityIndex,
        leader_round: RoundNumber,
    },
}

impl fmt::Display for RbcDagProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Starfish-RBC-DAG projection error: {self:?}")
    }
}

impl Error for RbcDagProjectionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarrierHeaderV1 {
    author: AuthorityIndex,
    carrier_round: RoundNumber,
    own_prev: BlockReference,
    weak_parents: Vec<BlockReference>,
    transactions_commitment: TransactionsCommitment,
    data_acknowledgments: Vec<BlockReference>,
    phase_batch: Vec<RbcPhaseStatementV1>,
    consensus_vertex: Option<ConsensusVertexV1>,
    creation_time_ns: TimestampNs,
}

#[derive(Clone, Debug)]
pub struct CarrierHeaderV1Args {
    pub author: AuthorityIndex,
    pub carrier_round: RoundNumber,
    pub own_prev: BlockReference,
    pub weak_parents: Vec<BlockReference>,
    pub transactions_commitment: TransactionsCommitment,
    pub data_acknowledgments: Vec<BlockReference>,
    pub phase_batch: Vec<RbcPhaseStatementV1>,
    pub consensus_vertex: Option<ConsensusVertexV1>,
    pub creation_time_ns: TimestampNs,
}

impl CarrierHeaderV1 {
    fn from_args(args: CarrierHeaderV1Args) -> Self {
        Self {
            author: args.author,
            carrier_round: args.carrier_round,
            own_prev: args.own_prev,
            weak_parents: args.weak_parents,
            transactions_commitment: args.transactions_commitment,
            data_acknowledgments: args.data_acknowledgments,
            phase_batch: args.phase_batch,
            consensus_vertex: args.consensus_vertex,
            creation_time_ns: args.creation_time_ns,
        }
    }
}

impl CarrierHeaderV1 {
    pub fn author(&self) -> AuthorityIndex {
        self.author
    }

    pub fn carrier_round(&self) -> RoundNumber {
        self.carrier_round
    }

    pub fn own_prev(&self) -> BlockReference {
        self.own_prev
    }

    pub fn weak_parents(&self) -> &[BlockReference] {
        &self.weak_parents
    }

    pub fn transactions_commitment(&self) -> TransactionsCommitment {
        self.transactions_commitment
    }

    pub fn data_acknowledgments(&self) -> &[BlockReference] {
        &self.data_acknowledgments
    }

    pub fn phase_batch(&self) -> &[RbcPhaseStatementV1] {
        &self.phase_batch
    }

    pub fn consensus_vertex(&self) -> Option<&ConsensusVertexV1> {
        self.consensus_vertex.as_ref()
    }

    pub fn creation_time_ns(&self) -> TimestampNs {
        self.creation_time_ns
    }

    /// Exact expanded canonical content bytes committed by the carrier
    /// reference. Authentication is deliberately absent.
    fn canonical_content_bytes(&self) -> Result<Vec<u8>, RbcDagError> {
        encode_header(self, AckEncoding::Expanded)
    }

    /// Canonical wire bytes. The acknowledgment log is represented by its
    /// unique maximal physical-parent suffix and the remaining exact log.
    fn canonical_wire_bytes(&self) -> Result<Vec<u8>, RbcDagError> {
        encode_header(self, AckEncoding::Compressed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateCarrierV1 {
    header: Arc<CarrierHeaderV1>,
    reference: BlockReference,
    committee_id: RbcDagCommitteeId,
}

impl CandidateCarrierV1 {
    /// Convenience constructor for tests and one-shot callers.
    ///
    /// Runtime code should build one [`RbcDagCommitteeContextV1`] and call
    /// [`Self::try_new_with_committee`] so the committee's complete public-key
    /// transcript is not rehashed for every carrier.
    pub fn try_new(args: CarrierHeaderV1Args, committee: &Committee) -> Result<Self, RbcDagError> {
        Self::try_from_header_internal(CarrierHeaderV1::from_args(args), committee, None, None)
    }

    pub fn try_new_with_committee(
        args: CarrierHeaderV1Args,
        committee: &RbcDagCommitteeContextV1,
    ) -> Result<Self, RbcDagError> {
        Self::try_from_header_internal(
            CarrierHeaderV1::from_args(args),
            committee.committee(),
            Some(committee.committee_id()),
            None,
        )
    }

    /// Convenience constructor for tests and one-shot callers. Runtime code
    /// should prefer [`Self::try_from_header_with_committee`].
    pub fn try_from_header(
        header: CarrierHeaderV1,
        committee: &Committee,
        expected_reference: Option<BlockReference>,
    ) -> Result<Self, RbcDagError> {
        Self::try_from_header_internal(header, committee, None, expected_reference)
    }

    pub fn try_from_header_with_committee(
        header: CarrierHeaderV1,
        committee: &RbcDagCommitteeContextV1,
        expected_reference: Option<BlockReference>,
    ) -> Result<Self, RbcDagError> {
        Self::try_from_header_internal(
            header,
            committee.committee(),
            Some(committee.committee_id()),
            expected_reference,
        )
    }

    fn try_from_header_internal(
        mut header: CarrierHeaderV1,
        committee: &Committee,
        cached_committee_id: Option<RbcDagCommitteeId>,
        expected_reference: Option<BlockReference>,
    ) -> Result<Self, RbcDagError> {
        normalize_acknowledgments(&mut header)?;
        validate_outer_header(&header, committee, cached_committee_id.is_some())?;
        let reference = carrier_reference(&header)?;
        if let Some(expected) = expected_reference {
            if expected != reference {
                return Err(RbcDagError::ReferenceMismatch {
                    expected,
                    actual: reference,
                });
            }
        }
        let committee_id = match cached_committee_id {
            Some(committee_id) => committee_id,
            None => RbcDagCommitteeId::derive(committee)?,
        };
        Ok(Self {
            header: Arc::new(header),
            reference,
            committee_id,
        })
    }

    pub fn decode_content(
        bytes: &[u8],
        committee: &Committee,
        expected_reference: Option<BlockReference>,
    ) -> Result<Self, RbcDagError> {
        let header = decode_header(bytes, AckEncoding::Expanded)?;
        let candidate =
            Self::try_from_header_internal(header, committee, None, expected_reference)?;
        if candidate.canonical_content_bytes()?.as_slice() != bytes {
            return Err(RbcDagError::NonCanonicalAcknowledgments);
        }
        Ok(candidate)
    }

    pub fn decode_content_with_committee(
        bytes: &[u8],
        committee: &RbcDagCommitteeContextV1,
        expected_reference: Option<BlockReference>,
    ) -> Result<Self, RbcDagError> {
        let header = decode_header(bytes, AckEncoding::Expanded)?;
        let candidate = Self::try_from_header_internal(
            header,
            committee.committee(),
            Some(committee.committee_id()),
            expected_reference,
        )?;
        if candidate.canonical_content_bytes()?.as_slice() != bytes {
            return Err(RbcDagError::NonCanonicalAcknowledgments);
        }
        Ok(candidate)
    }

    pub fn decode_wire(
        bytes: &[u8],
        committee: &Committee,
        expected_reference: Option<BlockReference>,
    ) -> Result<Self, RbcDagError> {
        let header = decode_header(bytes, AckEncoding::Compressed)?;
        Self::try_from_header_internal(header, committee, None, expected_reference)
    }

    pub fn decode_wire_with_committee(
        bytes: &[u8],
        committee: &RbcDagCommitteeContextV1,
        expected_reference: Option<BlockReference>,
    ) -> Result<Self, RbcDagError> {
        let header = decode_header(bytes, AckEncoding::Compressed)?;
        Self::try_from_header_internal(
            header,
            committee.committee(),
            Some(committee.committee_id()),
            expected_reference,
        )
    }

    pub fn header(&self) -> &CarrierHeaderV1 {
        &self.header
    }

    pub fn reference(&self) -> BlockReference {
        self.reference
    }

    pub fn committee_id(&self) -> RbcDagCommitteeId {
        self.committee_id
    }

    pub fn canonical_content_bytes(&self) -> Result<Vec<u8>, RbcDagError> {
        self.header.canonical_content_bytes()
    }

    pub fn canonical_wire_bytes(&self) -> Result<Vec<u8>, RbcDagError> {
        self.header.canonical_wire_bytes()
    }

    pub fn validate_consensus_vertex(
        &self,
        committee: &Committee,
    ) -> Result<Option<&ConsensusVertexV1>, RbcDagProjectionError> {
        let committee_id = RbcDagCommitteeId::derive(committee)
            .map_err(|_| RbcDagProjectionError::CommitteeMismatch)?;
        self.validate_consensus_vertex_with_validated_committee(committee, committee_id)
    }

    pub fn validate_consensus_vertex_with_committee(
        &self,
        committee: &RbcDagCommitteeContextV1,
    ) -> Result<Option<&ConsensusVertexV1>, RbcDagProjectionError> {
        self.validate_consensus_vertex_with_validated_committee(
            committee.committee(),
            committee.committee_id(),
        )
    }

    fn validate_consensus_vertex_with_validated_committee(
        &self,
        committee: &Committee,
        committee_id: RbcDagCommitteeId,
    ) -> Result<Option<&ConsensusVertexV1>, RbcDagProjectionError> {
        if committee_id != self.committee_id {
            return Err(RbcDagProjectionError::CommitteeMismatch);
        }
        let Some(vertex) = self.header.consensus_vertex() else {
            return Ok(None);
        };
        vertex.validate_projection_shape(self.header.author(), committee)?;
        Ok(Some(vertex))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct FlatMacVector {
    bytes: Box<[u8]>,
}

impl FlatMacVector {
    pub fn from_tags(tags: &[MacTag]) -> Result<Self, RbcDagError> {
        if tags.len() > MAX_COMMITTEE_SIZE as usize {
            return Err(RbcDagError::InvalidMacVectorLength {
                expected: MAX_COMMITTEE_SIZE as usize * MAC_TAG_SIZE,
                actual: tags.len().saturating_mul(MAC_TAG_SIZE),
            });
        }
        let mut bytes = Vec::with_capacity(tags.len() * MAC_TAG_SIZE);
        for tag in tags {
            bytes.extend_from_slice(tag.as_ref());
        }
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
        })
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, RbcDagError> {
        if !bytes.chunks_exact(MAC_TAG_SIZE).remainder().is_empty()
            || bytes.len() > MAX_COMMITTEE_SIZE as usize * MAC_TAG_SIZE
        {
            return Err(RbcDagError::InvalidFlatMacVectorLength(bytes.len()));
        }
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len() / MAC_TAG_SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn tag(&self, authority: AuthorityIndex) -> Option<MacTag> {
        let start = authority as usize * MAC_TAG_SIZE;
        let end = start.checked_add(MAC_TAG_SIZE)?;
        let mut bytes = [0; MAC_TAG_SIZE];
        bytes.copy_from_slice(self.bytes.get(start..end)?);
        Some(MacTag::from_bytes(bytes))
    }
}

impl fmt::Debug for FlatMacVector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlatMacVector")
            .field("tag_count", &self.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CarrierAuthenticationV1 {
    Ed25519(SignatureBytes),
    MlDsa44(MlDsa44SignatureBytes),
    MlDsa65(MlDsa65SignatureBytes),
    MacVector(FlatMacVector),
}

impl CarrierAuthenticationV1 {
    pub fn scheme(&self) -> BlockAuthenticationScheme {
        match self {
            Self::Ed25519(_) => BlockAuthenticationScheme::Ed25519,
            Self::MlDsa44(_) => BlockAuthenticationScheme::MlDsa44,
            Self::MlDsa65(_) => BlockAuthenticationScheme::MlDsa65,
            Self::MacVector(_) => BlockAuthenticationScheme::MacVector,
        }
    }

    /// Versioned sidecar wire bytes. `FlatMacVector` itself remains the raw
    /// concatenation of tags; the envelope supplies version and scheme.
    pub fn canonical_wire_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(CONTENT_FORMAT_FIELD);
        bytes.push(CARRIER_FORMAT_VERSION_V1);
        bytes.push(authentication_scheme_code(self.scheme()));
        match self {
            Self::Ed25519(signature) => bytes.extend_from_slice(signature.as_ref()),
            Self::MlDsa44(signature) => bytes.extend_from_slice(signature.as_ref()),
            Self::MlDsa65(signature) => bytes.extend_from_slice(signature.as_ref()),
            Self::MacVector(vector) => bytes.extend_from_slice(vector.as_bytes()),
        }
        bytes
    }

    /// Convenience decoder for one-shot callers. Runtime code should prefer
    /// [`Self::decode_wire_with_committee`].
    pub fn decode_wire(bytes: &[u8], committee: &Committee) -> Result<Self, RbcDagError> {
        validate_committee(committee)?;
        Self::decode_wire_with_validated_committee(bytes, committee)
    }

    pub fn decode_wire_with_committee(
        bytes: &[u8],
        committee: &RbcDagCommitteeContextV1,
    ) -> Result<Self, RbcDagError> {
        Self::decode_wire_with_validated_committee(bytes, committee.committee())
    }

    fn decode_wire_with_validated_committee(
        bytes: &[u8],
        committee: &Committee,
    ) -> Result<Self, RbcDagError> {
        let mut decoder = Decoder::new(bytes);
        decoder.expect_marker(CONTENT_FORMAT_FIELD)?;
        let version = decoder.read_u8()?;
        if version != CARRIER_FORMAT_VERSION_V1 {
            return Err(RbcDagError::UnsupportedVersion(version));
        }
        let scheme = decode_authentication_scheme(decoder.read_u8()?)?;
        let authentication = match scheme {
            BlockAuthenticationScheme::Ed25519 => Self::Ed25519(SignatureBytes::from_bytes(
                decoder.read_array::<SIGNATURE_SIZE>()?,
            )),
            BlockAuthenticationScheme::MlDsa44 => Self::MlDsa44(MlDsa44SignatureBytes::from_bytes(
                decoder.read_array::<ML_DSA_44_SIGNATURE_SIZE>()?,
            )),
            BlockAuthenticationScheme::MlDsa65 => Self::MlDsa65(MlDsa65SignatureBytes::from_bytes(
                decoder.read_array::<ML_DSA_65_SIGNATURE_SIZE>()?,
            )),
            BlockAuthenticationScheme::MacVector => {
                let expected = committee
                    .len()
                    .checked_mul(MAC_TAG_SIZE)
                    .ok_or(RbcDagError::InvalidCommittee("MAC vector length overflow"))?;
                let vector = FlatMacVector::from_bytes(decoder.take(expected)?.to_vec())?;
                Self::MacVector(vector)
            }
        };
        decoder.finish()?;
        Ok(authentication)
    }
}

pub enum CarrierAuthorizerV1<'a> {
    Ed25519 {
        authority: AuthorityIndex,
        signer: &'a Signer,
    },
    MlDsa44 {
        authority: AuthorityIndex,
        signer: &'a MlDsa44Signer,
    },
    MlDsa65 {
        authority: AuthorityIndex,
        signer: &'a MlDsa65Signer,
    },
    MacVector {
        authority: AuthorityIndex,
        keys: &'a [MacKey],
    },
}

impl CarrierAuthorizerV1<'_> {
    fn scheme(&self) -> BlockAuthenticationScheme {
        match self {
            Self::Ed25519 { .. } => BlockAuthenticationScheme::Ed25519,
            Self::MlDsa44 { .. } => BlockAuthenticationScheme::MlDsa44,
            Self::MlDsa65 { .. } => BlockAuthenticationScheme::MlDsa65,
            Self::MacVector { .. } => BlockAuthenticationScheme::MacVector,
        }
    }

    fn authority(&self) -> AuthorityIndex {
        match self {
            Self::Ed25519 { authority, .. }
            | Self::MlDsa44 { authority, .. }
            | Self::MlDsa65 { authority, .. }
            | Self::MacVector { authority, .. } => *authority,
        }
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RbcDagProtocolInstanceId([u8; PROTOCOL_INSTANCE_SIZE]);

impl RbcDagProtocolInstanceId {
    pub fn new(bytes: [u8; PROTOCOL_INSTANCE_SIZE]) -> Result<Self, RbcDagError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RbcDagError::ZeroProtocolInstance);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; PROTOCOL_INSTANCE_SIZE] {
        &self.0
    }
}

impl fmt::Debug for RbcDagProtocolInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RbcDagInstance({})", hex::encode(&self.0[..4]))
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RbcDagCommitteeId([u8; COMMITTEE_ID_SIZE]);

impl RbcDagCommitteeId {
    pub fn derive(committee: &Committee) -> Result<Self, RbcDagError> {
        validate_committee(committee)?;
        #[cfg(test)]
        COMMITTEE_ID_DERIVATIONS.with(|count| count.set(count.get().saturating_add(1)));
        let committee_size = u16::try_from(committee.len())
            .map_err(|_| RbcDagError::InvalidCommittee("committee too large"))?;
        let info_length = u16::try_from(committee.info_length())
            .map_err(|_| RbcDagError::InvalidCommittee("information length too large"))?;
        let mut hasher = Blake3Hasher::new_derive_key(COMMITTEE_ID_DERIVE_CONTEXT);
        hasher.update(&committee_size.to_be_bytes());
        hasher.update(&committee.validity_threshold().to_be_bytes());
        hasher.update(&committee.quorum_threshold().to_be_bytes());
        hasher.update(&info_length.to_be_bytes());
        hasher.update(&committee.optimistic_fast_threshold().to_be_bytes());
        hasher.update(&committee.optimistic_vote_threshold().to_be_bytes());
        hasher.update(&committee.optimistic_ready_threshold().to_be_bytes());
        for authority in committee.authorities() {
            let stake = committee
                .get_stake(authority)
                .ok_or(RbcDagError::UnknownAuthority(authority))?;
            let public_key = committee
                .get_public_key(authority)
                .ok_or(RbcDagError::UnknownAuthority(authority))?;
            let bls_public_key = committee
                .get_bls_public_key(authority)
                .ok_or(RbcDagError::UnknownAuthority(authority))?;
            let ml_dsa_44_public_key = committee
                .get_ml_dsa_44_public_key(authority)
                .ok_or(RbcDagError::UnknownAuthority(authority))?;
            let ml_dsa_65_public_key = committee
                .get_ml_dsa_65_public_key(authority)
                .ok_or(RbcDagError::UnknownAuthority(authority))?;
            hasher.update(&authority.to_be_bytes());
            hasher.update(&stake.to_be_bytes());
            hasher.update(&public_key.to_bytes());
            hasher.update(&bls_public_key.to_bytes());
            hasher.update(&ml_dsa_44_public_key.to_bytes());
            hasher.update(&ml_dsa_65_public_key.to_bytes());
        }
        Ok(Self(hasher.finalize().into()))
    }

    pub fn as_bytes(&self) -> &[u8; COMMITTEE_ID_SIZE] {
        &self.0
    }
}

impl fmt::Debug for RbcDagCommitteeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RbcDagCommittee({})", hex::encode(&self.0[..4]))
    }
}

/// Validated, reusable committee capability for the Starfish-RBC-DAG hot
/// path.
///
/// Construction validates the committee and hashes its complete key
/// transcript exactly once. Candidate decoding, authentication, and
/// projection APIs that accept this capability perform only constant-time ID
/// comparisons before using the retained committee.
#[derive(Clone)]
pub struct RbcDagCommitteeContextV1 {
    committee: Arc<Committee>,
    committee_id: RbcDagCommitteeId,
}

impl RbcDagCommitteeContextV1 {
    pub fn new(committee: Arc<Committee>) -> Result<Self, RbcDagError> {
        let committee_id = RbcDagCommitteeId::derive(&committee)?;
        Ok(Self {
            committee,
            committee_id,
        })
    }

    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    pub fn committee_arc(&self) -> Arc<Committee> {
        Arc::clone(&self.committee)
    }

    pub fn committee_id(&self) -> RbcDagCommitteeId {
        self.committee_id
    }
}

impl fmt::Debug for RbcDagCommitteeContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RbcDagCommitteeContextV1")
            .field("committee_id", &self.committee_id)
            .field("committee_size", &self.committee.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RbcDagContextV1 {
    protocol_instance: RbcDagProtocolInstanceId,
    committee_id: RbcDagCommitteeId,
    authentication_scheme: BlockAuthenticationScheme,
}

impl RbcDagContextV1 {
    /// Convenience constructor for one-shot callers. Runtime code should
    /// prefer [`Self::new_with_committee`].
    pub fn new(
        protocol_instance: RbcDagProtocolInstanceId,
        committee: &Committee,
        authentication_scheme: BlockAuthenticationScheme,
    ) -> Result<Self, RbcDagError> {
        Ok(Self {
            protocol_instance,
            committee_id: RbcDagCommitteeId::derive(committee)?,
            authentication_scheme,
        })
    }

    pub fn new_with_committee(
        protocol_instance: RbcDagProtocolInstanceId,
        committee: &RbcDagCommitteeContextV1,
        authentication_scheme: BlockAuthenticationScheme,
    ) -> Self {
        Self {
            protocol_instance,
            committee_id: committee.committee_id(),
            authentication_scheme,
        }
    }

    pub fn protocol_instance(&self) -> RbcDagProtocolInstanceId {
        self.protocol_instance
    }

    pub fn committee_id(&self) -> RbcDagCommitteeId {
        self.committee_id
    }

    pub fn authentication_scheme(&self) -> BlockAuthenticationScheme {
        self.authentication_scheme
    }

    /// Convenience authorizer for one-shot callers. Runtime code should
    /// prefer [`Self::authenticate_with_committee`].
    pub fn authenticate(
        &self,
        candidate: &CandidateCarrierV1,
        committee: &Committee,
        authorizer: CarrierAuthorizerV1<'_>,
    ) -> Result<CarrierAuthenticationV1, RbcDagError> {
        let committee_id = RbcDagCommitteeId::derive(committee)?;
        self.authenticate_with_validated_committee(candidate, committee, committee_id, authorizer)
    }

    pub fn authenticate_with_committee(
        &self,
        candidate: &CandidateCarrierV1,
        committee: &RbcDagCommitteeContextV1,
        authorizer: CarrierAuthorizerV1<'_>,
    ) -> Result<CarrierAuthenticationV1, RbcDagError> {
        self.authenticate_with_validated_committee(
            candidate,
            committee.committee(),
            committee.committee_id(),
            authorizer,
        )
    }

    fn authenticate_with_validated_committee(
        &self,
        candidate: &CandidateCarrierV1,
        committee: &Committee,
        committee_id: RbcDagCommitteeId,
        authorizer: CarrierAuthorizerV1<'_>,
    ) -> Result<CarrierAuthenticationV1, RbcDagError> {
        self.ensure_committee_id(committee_id)?;
        self.ensure_candidate(candidate)?;
        if authorizer.scheme() != self.authentication_scheme {
            return Err(RbcDagError::AuthenticationSchemeMismatch);
        }
        let reference = candidate.reference;
        if authorizer.authority() != reference.authority {
            return Err(RbcDagError::AuthorizerAuthorityMismatch {
                expected: reference.authority,
                actual: authorizer.authority(),
            });
        }
        match authorizer {
            CarrierAuthorizerV1::Ed25519 { signer, .. } => {
                let expected = committee
                    .get_public_key(reference.authority)
                    .ok_or(RbcDagError::UnknownAuthority(reference.authority))?;
                if &signer.public_key() != expected {
                    return Err(RbcDagError::AuthorizerKeyMismatch);
                }
                Ok(CarrierAuthenticationV1::Ed25519(signer.sign_digest(
                    &self.public_authentication_digest(reference),
                )))
            }
            CarrierAuthorizerV1::MlDsa44 { signer, .. } => {
                let expected = committee
                    .get_ml_dsa_44_public_key(reference.authority)
                    .ok_or(RbcDagError::UnknownAuthority(reference.authority))?;
                if &signer.public_key() != expected {
                    return Err(RbcDagError::AuthorizerKeyMismatch);
                }
                let digest = BlockDigest::from(self.public_authentication_digest(reference));
                Ok(CarrierAuthenticationV1::MlDsa44(
                    signer.sign_digest(&digest),
                ))
            }
            CarrierAuthorizerV1::MlDsa65 { signer, .. } => {
                let expected = committee
                    .get_ml_dsa_65_public_key(reference.authority)
                    .ok_or(RbcDagError::UnknownAuthority(reference.authority))?;
                if &signer.public_key() != expected {
                    return Err(RbcDagError::AuthorizerKeyMismatch);
                }
                let digest = BlockDigest::from(self.public_authentication_digest(reference));
                Ok(CarrierAuthenticationV1::MlDsa65(
                    signer.sign_digest(&digest),
                ))
            }
            CarrierAuthorizerV1::MacVector { keys, .. } => {
                if keys.len() != committee.len() {
                    return Err(RbcDagError::InvalidKeyringLength {
                        expected: committee.len(),
                        actual: keys.len(),
                    });
                }
                let tags = committee
                    .authorities()
                    .map(|recipient| {
                        keys[recipient as usize].compute_rbc_tag(
                            &self.mac_authentication_statement(reference, recipient),
                        )
                    })
                    .collect::<Vec<_>>();
                Ok(CarrierAuthenticationV1::MacVector(
                    FlatMacVector::from_tags(&tags)?,
                ))
            }
        }
    }

    /// Generate the exact authentication sidecar for a locally authored
    /// carrier and bind it to the candidate and protocol context.
    ///
    /// The returned capability has private fields so persistence and network
    /// adapters cannot substitute a freely constructed, same-scheme sidecar
    /// for the one produced by the configured authorizer.
    ///
    /// Convenience local authorizer for one-shot callers. Runtime code should
    /// prefer [`Self::authenticate_local_with_committee`].
    pub fn authenticate_local(
        &self,
        candidate: CandidateCarrierV1,
        committee: &Committee,
        authorizer: CarrierAuthorizerV1<'_>,
    ) -> Result<LocallyAuthenticatedCarrierV1, RbcDagError> {
        let authentication = self.authenticate(&candidate, committee, authorizer)?;
        Ok(LocallyAuthenticatedCarrierV1 {
            candidate,
            authentication,
            context: *self,
        })
    }

    pub fn authenticate_local_with_committee(
        &self,
        candidate: CandidateCarrierV1,
        committee: &RbcDagCommitteeContextV1,
        authorizer: CarrierAuthorizerV1<'_>,
    ) -> Result<LocallyAuthenticatedCarrierV1, RbcDagError> {
        let authentication = self.authenticate_with_committee(&candidate, committee, authorizer)?;
        Ok(LocallyAuthenticatedCarrierV1 {
            candidate,
            authentication,
            context: *self,
        })
    }

    /// Recover the opaque local-authentication capability from an exact
    /// persisted sidecar without regenerating it.
    ///
    /// Signature modes verify the persisted public proof and the configured
    /// local signer's public key. MAC mode verifies every ordered vector entry
    /// with the configured outbound keyring; checking only this node's entry
    /// would not prove that the locally exposed full vector was generated
    /// correctly.
    ///
    /// Convenience recovery verifier for one-shot callers. Runtime code
    /// should prefer [`Self::verify_local_authentication_with_committee`].
    pub fn verify_local_authentication(
        &self,
        candidate: CandidateCarrierV1,
        authentication: CarrierAuthenticationV1,
        committee: &Committee,
        authorizer: CarrierAuthorizerV1<'_>,
    ) -> Result<LocallyAuthenticatedCarrierV1, RbcDagError> {
        let committee_id = RbcDagCommitteeId::derive(committee)?;
        self.verify_local_authentication_with_validated_committee(
            candidate,
            authentication,
            committee,
            committee_id,
            authorizer,
        )
    }

    pub fn verify_local_authentication_with_committee(
        &self,
        candidate: CandidateCarrierV1,
        authentication: CarrierAuthenticationV1,
        committee: &RbcDagCommitteeContextV1,
        authorizer: CarrierAuthorizerV1<'_>,
    ) -> Result<LocallyAuthenticatedCarrierV1, RbcDagError> {
        self.verify_local_authentication_with_validated_committee(
            candidate,
            authentication,
            committee.committee(),
            committee.committee_id(),
            authorizer,
        )
    }

    fn verify_local_authentication_with_validated_committee(
        &self,
        candidate: CandidateCarrierV1,
        authentication: CarrierAuthenticationV1,
        committee: &Committee,
        committee_id: RbcDagCommitteeId,
        authorizer: CarrierAuthorizerV1<'_>,
    ) -> Result<LocallyAuthenticatedCarrierV1, RbcDagError> {
        self.ensure_committee_id(committee_id)?;
        self.ensure_candidate(&candidate)?;
        if authentication.scheme() != self.authentication_scheme
            || authorizer.scheme() != self.authentication_scheme
        {
            return Err(RbcDagError::AuthenticationSchemeMismatch);
        }
        let reference = candidate.reference;
        if authorizer.authority() != reference.authority {
            return Err(RbcDagError::AuthorizerAuthorityMismatch {
                expected: reference.authority,
                actual: authorizer.authority(),
            });
        }

        match (authorizer, &authentication) {
            (
                CarrierAuthorizerV1::Ed25519 { signer, .. },
                CarrierAuthenticationV1::Ed25519(signature),
            ) => {
                let expected = committee
                    .get_public_key(reference.authority)
                    .ok_or(RbcDagError::UnknownAuthority(reference.authority))?;
                if &signer.public_key() != expected {
                    return Err(RbcDagError::AuthorizerKeyMismatch);
                }
                expected
                    .verify_digest_signature(
                        &self.public_authentication_digest(reference),
                        signature,
                    )
                    .map_err(|_| RbcDagError::InvalidAuthentication)?;
            }
            (
                CarrierAuthorizerV1::MlDsa44 { signer, .. },
                CarrierAuthenticationV1::MlDsa44(signature),
            ) => {
                let expected = committee
                    .get_ml_dsa_44_public_key(reference.authority)
                    .ok_or(RbcDagError::UnknownAuthority(reference.authority))?;
                if &signer.public_key() != expected {
                    return Err(RbcDagError::AuthorizerKeyMismatch);
                }
                let digest = BlockDigest::from(self.public_authentication_digest(reference));
                expected
                    .verify_digest_signature(&digest, signature)
                    .map_err(|_| RbcDagError::InvalidAuthentication)?;
            }
            (
                CarrierAuthorizerV1::MlDsa65 { signer, .. },
                CarrierAuthenticationV1::MlDsa65(signature),
            ) => {
                let expected = committee
                    .get_ml_dsa_65_public_key(reference.authority)
                    .ok_or(RbcDagError::UnknownAuthority(reference.authority))?;
                if &signer.public_key() != expected {
                    return Err(RbcDagError::AuthorizerKeyMismatch);
                }
                let digest = BlockDigest::from(self.public_authentication_digest(reference));
                expected
                    .verify_digest_signature(&digest, signature)
                    .map_err(|_| RbcDagError::InvalidAuthentication)?;
            }
            (
                CarrierAuthorizerV1::MacVector { keys, .. },
                CarrierAuthenticationV1::MacVector(vector),
            ) => {
                let expected_length = committee.len() * MAC_TAG_SIZE;
                if vector.as_bytes().len() != expected_length {
                    return Err(RbcDagError::InvalidMacVectorLength {
                        expected: expected_length,
                        actual: vector.as_bytes().len(),
                    });
                }
                if keys.len() != committee.len() {
                    return Err(RbcDagError::InvalidKeyringLength {
                        expected: committee.len(),
                        actual: keys.len(),
                    });
                }
                for recipient in committee.authorities() {
                    let expected = keys[recipient as usize]
                        .compute_rbc_tag(&self.mac_authentication_statement(reference, recipient));
                    let actual = vector
                        .tag(recipient)
                        .ok_or(RbcDagError::InvalidAuthentication)?;
                    if actual != expected {
                        return Err(RbcDagError::InvalidAuthentication);
                    }
                }
            }
            _ => return Err(RbcDagError::AuthenticationSchemeMismatch),
        }

        Ok(LocallyAuthenticatedCarrierV1 {
            candidate,
            authentication,
            context: *self,
        })
    }

    /// Convenience inbound verifier for one-shot callers. Runtime code should
    /// prefer [`Self::verify_authentication_with_committee`].
    pub fn verify_authentication(
        &self,
        candidate: CandidateCarrierV1,
        authentication: CarrierAuthenticationV1,
        receiver: AuthorityIndex,
        committee: &Committee,
        mac_keys: &[MacKey],
    ) -> Result<AuthenticatedCarrierV1, RbcDagError> {
        let committee_id = RbcDagCommitteeId::derive(committee)?;
        self.verify_authentication_with_validated_committee(
            candidate,
            authentication,
            receiver,
            committee,
            committee_id,
            mac_keys,
        )
    }

    pub fn verify_authentication_with_committee(
        &self,
        candidate: CandidateCarrierV1,
        authentication: CarrierAuthenticationV1,
        receiver: AuthorityIndex,
        committee: &RbcDagCommitteeContextV1,
        mac_keys: &[MacKey],
    ) -> Result<AuthenticatedCarrierV1, RbcDagError> {
        self.verify_authentication_with_validated_committee(
            candidate,
            authentication,
            receiver,
            committee.committee(),
            committee.committee_id(),
            mac_keys,
        )
    }

    fn verify_authentication_with_validated_committee(
        &self,
        candidate: CandidateCarrierV1,
        authentication: CarrierAuthenticationV1,
        receiver: AuthorityIndex,
        committee: &Committee,
        committee_id: RbcDagCommitteeId,
        mac_keys: &[MacKey],
    ) -> Result<AuthenticatedCarrierV1, RbcDagError> {
        self.ensure_committee_id(committee_id)?;
        self.ensure_candidate(&candidate)?;
        if !committee.known_authority(receiver) {
            return Err(RbcDagError::UnknownAuthority(receiver));
        }
        if authentication.scheme() != self.authentication_scheme {
            return Err(RbcDagError::AuthenticationSchemeMismatch);
        }
        let reference = candidate.reference;
        match &authentication {
            CarrierAuthenticationV1::Ed25519(signature) => {
                let public_key = committee
                    .get_public_key(reference.authority)
                    .ok_or(RbcDagError::UnknownAuthority(reference.authority))?;
                public_key
                    .verify_digest_signature(
                        &self.public_authentication_digest(reference),
                        signature,
                    )
                    .map_err(|_| RbcDagError::InvalidAuthentication)?;
            }
            CarrierAuthenticationV1::MlDsa44(signature) => {
                let public_key = committee
                    .get_ml_dsa_44_public_key(reference.authority)
                    .ok_or(RbcDagError::UnknownAuthority(reference.authority))?;
                let digest = BlockDigest::from(self.public_authentication_digest(reference));
                public_key
                    .verify_digest_signature(&digest, signature)
                    .map_err(|_| RbcDagError::InvalidAuthentication)?;
            }
            CarrierAuthenticationV1::MlDsa65(signature) => {
                let public_key = committee
                    .get_ml_dsa_65_public_key(reference.authority)
                    .ok_or(RbcDagError::UnknownAuthority(reference.authority))?;
                let digest = BlockDigest::from(self.public_authentication_digest(reference));
                public_key
                    .verify_digest_signature(&digest, signature)
                    .map_err(|_| RbcDagError::InvalidAuthentication)?;
            }
            CarrierAuthenticationV1::MacVector(vector) => {
                let expected_length = committee.len() * MAC_TAG_SIZE;
                if vector.as_bytes().len() != expected_length {
                    return Err(RbcDagError::InvalidMacVectorLength {
                        expected: expected_length,
                        actual: vector.as_bytes().len(),
                    });
                }
                if mac_keys.len() != committee.len() {
                    return Err(RbcDagError::InvalidKeyringLength {
                        expected: committee.len(),
                        actual: mac_keys.len(),
                    });
                }
                let key = mac_keys
                    .get(reference.authority as usize)
                    .ok_or(RbcDagError::UnknownAuthority(reference.authority))?;
                let expected =
                    key.compute_rbc_tag(&self.mac_authentication_statement(reference, receiver));
                let actual = vector
                    .tag(receiver)
                    .ok_or(RbcDagError::InvalidAuthentication)?;
                if actual != expected {
                    return Err(RbcDagError::InvalidAuthentication);
                }
            }
        }
        Ok(AuthenticatedCarrierV1 {
            candidate,
            authentication,
            context: *self,
            receiver,
        })
    }

    pub fn public_authentication_statement(
        &self,
        reference: BlockReference,
    ) -> [u8; AUTHENTICATION_BASE_SIZE] {
        encode_authentication_base(self, reference)
    }

    pub fn mac_authentication_statement(
        &self,
        reference: BlockReference,
        recipient: AuthorityIndex,
    ) -> [u8; AUTHENTICATION_MAC_SIZE] {
        let mut statement = [0; AUTHENTICATION_MAC_SIZE];
        statement[..AUTHENTICATION_BASE_SIZE]
            .copy_from_slice(&encode_authentication_base(self, reference));
        statement[AUTHENTICATION_BASE_SIZE..].copy_from_slice(&recipient.to_be_bytes());
        statement
    }

    pub fn public_authentication_digest(&self, reference: BlockReference) -> [u8; 32] {
        blake3::hash(&self.public_authentication_statement(reference)).into()
    }

    fn ensure_committee_id(&self, actual: RbcDagCommitteeId) -> Result<(), RbcDagError> {
        if actual != self.committee_id {
            return Err(RbcDagError::CommitteeIdMismatch);
        }
        Ok(())
    }

    fn ensure_candidate(&self, candidate: &CandidateCarrierV1) -> Result<(), RbcDagError> {
        if candidate.committee_id != self.committee_id {
            return Err(RbcDagError::CandidateCommitteeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedCarrierV1 {
    candidate: CandidateCarrierV1,
    authentication: CarrierAuthenticationV1,
    context: RbcDagContextV1,
    receiver: AuthorityIndex,
}

/// Opaque proof that the configured local authorizer generated a carrier's
/// exact sidecar. This is distinct from [`AuthenticatedCarrierV1`], which
/// proves that one receiver verified an inbound sidecar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocallyAuthenticatedCarrierV1 {
    candidate: CandidateCarrierV1,
    authentication: CarrierAuthenticationV1,
    context: RbcDagContextV1,
}

impl LocallyAuthenticatedCarrierV1 {
    pub fn candidate(&self) -> &CandidateCarrierV1 {
        &self.candidate
    }

    pub fn reference(&self) -> BlockReference {
        self.candidate.reference()
    }

    pub fn authentication(&self) -> &CarrierAuthenticationV1 {
        &self.authentication
    }

    pub fn context(&self) -> RbcDagContextV1 {
        self.context
    }

    pub fn into_parts(self) -> (CandidateCarrierV1, CarrierAuthenticationV1, RbcDagContextV1) {
        (self.candidate, self.authentication, self.context)
    }
}

impl AuthenticatedCarrierV1 {
    pub fn candidate(&self) -> &CandidateCarrierV1 {
        &self.candidate
    }

    pub fn header(&self) -> &CarrierHeaderV1 {
        self.candidate.header()
    }

    pub fn reference(&self) -> BlockReference {
        self.candidate.reference()
    }

    pub fn authentication(&self) -> &CarrierAuthenticationV1 {
        &self.authentication
    }

    pub fn context(&self) -> RbcDagContextV1 {
        self.context
    }

    pub fn receiver(&self) -> AuthorityIndex {
        self.receiver
    }

    pub fn into_parts(
        self,
    ) -> (
        CandidateCarrierV1,
        CarrierAuthenticationV1,
        RbcDagContextV1,
        AuthorityIndex,
    ) {
        (
            self.candidate,
            self.authentication,
            self.context,
            self.receiver,
        )
    }
}

fn authentication_scheme_code(authentication_scheme: BlockAuthenticationScheme) -> u8 {
    match authentication_scheme {
        BlockAuthenticationScheme::Ed25519 => 0,
        BlockAuthenticationScheme::MlDsa44 => 1,
        BlockAuthenticationScheme::MlDsa65 => 2,
        BlockAuthenticationScheme::MacVector => 3,
    }
}

fn decode_authentication_scheme(code: u8) -> Result<BlockAuthenticationScheme, RbcDagError> {
    match code {
        0 => Ok(BlockAuthenticationScheme::Ed25519),
        1 => Ok(BlockAuthenticationScheme::MlDsa44),
        2 => Ok(BlockAuthenticationScheme::MlDsa65),
        3 => Ok(BlockAuthenticationScheme::MacVector),
        other => Err(RbcDagError::InvalidAuthenticationScheme(other)),
    }
}

fn encode_authentication_base(
    context: &RbcDagContextV1,
    reference: BlockReference,
) -> [u8; AUTHENTICATION_BASE_SIZE] {
    let mut statement = [0; AUTHENTICATION_BASE_SIZE];
    statement[..19].copy_from_slice(AUTHENTICATION_DOMAIN);
    statement[19] = CARRIER_AUTHENTICATION_KIND;
    statement[20] = authentication_scheme_code(context.authentication_scheme);
    statement[21..53].copy_from_slice(&context.protocol_instance.0);
    statement[53..85].copy_from_slice(&context.committee_id.0);
    statement[85..87].copy_from_slice(&reference.authority.to_be_bytes());
    statement[87..91].copy_from_slice(&reference.round.to_be_bytes());
    statement[91..123].copy_from_slice(reference.digest.as_ref());
    statement
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RbcDagError {
    UnexpectedEnd,
    TrailingBytes(usize),
    UnsupportedVersion(u8),
    InvalidMarker {
        expected: u8,
        actual: u8,
    },
    InvalidOption(u8),
    InvalidPhase(u8),
    InvalidLeaderChoice(u8),
    VectorTooLong {
        field: &'static str,
        count: usize,
    },
    ContentTooLarge(usize),
    NonCanonicalAcknowledgments,
    InvalidCommittee(&'static str),
    UnknownAuthority(AuthorityIndex),
    GenesisCarrier,
    InvalidOwnPrevious,
    InvalidWeakParent(BlockReference),
    WeakParentsNotOrdered,
    InvalidCarrierThreshold,
    InvalidAcknowledgment(BlockReference),
    DuplicateAcknowledgment(BlockReference),
    InvalidPhaseTarget(BlockReference),
    DuplicatePhaseStatement(RbcPhaseStatementV1),
    InvalidConsensusRound,
    ZeroProtocolInstance,
    CommitteeIdMismatch,
    CandidateCommitteeMismatch,
    AuthenticationSchemeMismatch,
    InvalidAuthenticationScheme(u8),
    AuthorizerAuthorityMismatch {
        expected: AuthorityIndex,
        actual: AuthorityIndex,
    },
    AuthorizerKeyMismatch,
    InvalidAuthentication,
    InvalidFlatMacVectorLength(usize),
    InvalidMacVectorLength {
        expected: usize,
        actual: usize,
    },
    InvalidKeyringLength {
        expected: usize,
        actual: usize,
    },
    ReferenceMismatch {
        expected: BlockReference,
        actual: BlockReference,
    },
}

impl fmt::Display for RbcDagError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Starfish-RBC-DAG error: {self:?}")
    }
}

impl Error for RbcDagError {}

fn validate_outer_header(
    header: &CarrierHeaderV1,
    committee: &Committee,
    committee_is_validated: bool,
) -> Result<(), RbcDagError> {
    if !committee_is_validated {
        validate_committee(committee)?;
    }
    if header.carrier_round == 0 {
        return Err(RbcDagError::GenesisCarrier);
    }
    if !committee.known_authority(header.author) {
        return Err(RbcDagError::UnknownAuthority(header.author));
    }
    if header.own_prev.authority != header.author
        || header.own_prev.round.checked_add(1) != Some(header.carrier_round)
        || (header.carrier_round == 1
            && header.own_prev != carrier_genesis_reference(header.author))
    {
        return Err(RbcDagError::InvalidOwnPrevious);
    }

    if header.weak_parents.len() >= committee.len()
        || header.weak_parents.len() > MAX_COMMITTEE_SIZE as usize - 1
    {
        return Err(RbcDagError::VectorTooLong {
            field: "weak parents",
            count: header.weak_parents.len(),
        });
    }
    let mut previous_authority = None;
    let mut parent_stake = committee
        .get_stake(header.author)
        .ok_or(RbcDagError::UnknownAuthority(header.author))?;
    for parent in &header.weak_parents {
        if !committee.known_authority(parent.authority) {
            return Err(RbcDagError::UnknownAuthority(parent.authority));
        }
        if parent.authority == header.author
            || parent.round.checked_add(1) != Some(header.carrier_round)
            || (header.carrier_round == 1 && *parent != carrier_genesis_reference(parent.authority))
        {
            return Err(RbcDagError::InvalidWeakParent(*parent));
        }
        if previous_authority.is_some_and(|previous| previous >= parent.authority) {
            return Err(RbcDagError::WeakParentsNotOrdered);
        }
        previous_authority = Some(parent.authority);
        parent_stake = parent_stake
            .checked_add(
                committee
                    .get_stake(parent.authority)
                    .ok_or(RbcDagError::UnknownAuthority(parent.authority))?,
            )
            .ok_or(RbcDagError::InvalidCommittee("stake overflow"))?;
    }
    if parent_stake < committee.quorum_threshold() {
        return Err(RbcDagError::InvalidCarrierThreshold);
    }

    if header.data_acknowledgments.len() > u16::MAX as usize {
        return Err(RbcDagError::VectorTooLong {
            field: "acknowledgments",
            count: header.data_acknowledgments.len(),
        });
    }
    let mut acknowledgments = BTreeSet::new();
    for acknowledgment in &header.data_acknowledgments {
        if !committee.known_authority(acknowledgment.authority)
            || acknowledgment.round == 0
            || acknowledgment.round > header.carrier_round
        {
            return Err(RbcDagError::InvalidAcknowledgment(*acknowledgment));
        }
        if !acknowledgments.insert(*acknowledgment) {
            return Err(RbcDagError::DuplicateAcknowledgment(*acknowledgment));
        }
    }

    let phase_limit = usize::min(MAX_PHASE_STATEMENTS_V1, committee.len().saturating_mul(4));
    if header.phase_batch.len() > phase_limit {
        return Err(RbcDagError::VectorTooLong {
            field: "phase statements",
            count: header.phase_batch.len(),
        });
    }
    let mut phase_statements = HashSet::new();
    for statement in &header.phase_batch {
        let target = statement.target();
        if !committee.known_authority(target.authority)
            || target.round == 0
            || target.round >= header.carrier_round
        {
            return Err(RbcDagError::InvalidPhaseTarget(target));
        }
        if !phase_statements.insert((statement.code(), target.authority, target.round)) {
            return Err(RbcDagError::DuplicatePhaseStatement(*statement));
        }
    }

    if let Some(vertex) = &header.consensus_vertex {
        if vertex.consensus_round == 0 {
            return Err(RbcDagError::InvalidConsensusRound);
        }
        for (field, count) in [
            ("strong parents", vertex.strong_parents.len()),
            ("delivery frontier", vertex.delivery_frontier.len()),
        ] {
            if count > MAX_COMMITTEE_SIZE as usize {
                return Err(RbcDagError::VectorTooLong { field, count });
            }
        }
    }

    let content_size = header.canonical_content_bytes()?.len();
    if content_size > MAX_CARRIER_CONTENT_SIZE_V1 {
        return Err(RbcDagError::ContentTooLarge(content_size));
    }
    // Candidacy guarantees that the same logical carrier has a canonical
    // transport representation as well as an identity representation.
    header.canonical_wire_bytes()?;
    Ok(())
}

fn carrier_reference(header: &CarrierHeaderV1) -> Result<BlockReference, RbcDagError> {
    let bytes = header.canonical_content_bytes()?;
    Ok(BlockReference {
        round: header.carrier_round,
        authority: header.author,
        digest: BlockDigest::from(*blake3::hash(&bytes).as_bytes()),
    })
}

/// Fixed virtual carrier-genesis reference for one authority.
pub fn carrier_genesis_reference(authority: AuthorityIndex) -> BlockReference {
    let digest = BlockDigest::new_without_transactions(authority, 0, &[], &[], 0, None, None);
    BlockReference {
        round: 0,
        authority,
        digest,
    }
}

#[derive(Clone, Copy)]
enum AckEncoding {
    Expanded,
    Compressed,
}

fn encode_header(
    header: &CarrierHeaderV1,
    acknowledgment_encoding: AckEncoding,
) -> Result<Vec<u8>, RbcDagError> {
    let mut bytes = Vec::new();
    bytes.push(CONTENT_FORMAT_FIELD);
    bytes.push(match acknowledgment_encoding {
        AckEncoding::Expanded => CARRIER_FORMAT_VERSION_V1,
        AckEncoding::Compressed => CARRIER_WIRE_FORMAT_VERSION_V1,
    });
    bytes.push(AUTHOR_FIELD);
    bytes.extend_from_slice(&header.author.to_be_bytes());
    bytes.push(CARRIER_ROUND_FIELD);
    bytes.extend_from_slice(&header.carrier_round.to_be_bytes());
    bytes.push(OWN_PREV_FIELD);
    encode_reference(&mut bytes, header.own_prev);
    bytes.push(WEAK_PARENTS_FIELD);
    encode_count(&mut bytes, "weak parents", header.weak_parents.len())?;
    for parent in &header.weak_parents {
        encode_reference(&mut bytes, *parent);
    }
    bytes.push(TRANSACTIONS_COMMITMENT_FIELD);
    bytes.extend_from_slice(header.transactions_commitment.as_ref());
    bytes.push(ACKNOWLEDGMENTS_FIELD);
    match acknowledgment_encoding {
        AckEncoding::Expanded => {
            encode_count(
                &mut bytes,
                "acknowledgments",
                header.data_acknowledgments.len(),
            )?;
            for acknowledgment in &header.data_acknowledgments {
                encode_reference(&mut bytes, *acknowledgment);
            }
        }
        AckEncoding::Compressed => {
            let (intersection, extras) = compressed_acknowledgments(header)?;
            bytes.extend_from_slice(&intersection.to_be_bytes());
            encode_count(&mut bytes, "extra acknowledgments", extras.len())?;
            for acknowledgment in &extras {
                encode_reference(&mut bytes, *acknowledgment);
            }
        }
    }
    bytes.push(PHASE_BATCH_FIELD);
    encode_count(&mut bytes, "phase statements", header.phase_batch.len())?;
    for statement in &header.phase_batch {
        bytes.push(statement.code());
        encode_reference(&mut bytes, statement.target());
    }
    bytes.push(CONSENSUS_VERTEX_FIELD);
    match &header.consensus_vertex {
        None => bytes.push(OPTION_NONE),
        Some(vertex) => {
            bytes.push(OPTION_SOME);
            encode_consensus_vertex(&mut bytes, vertex)?;
        }
    }
    bytes.push(CREATION_TIME_FIELD);
    bytes.extend_from_slice(&header.creation_time_ns.to_be_bytes());
    if bytes.len() > MAX_CARRIER_CONTENT_SIZE_V1 {
        return Err(RbcDagError::ContentTooLarge(bytes.len()));
    }
    Ok(bytes)
}

fn encode_consensus_vertex(
    bytes: &mut Vec<u8>,
    vertex: &ConsensusVertexV1,
) -> Result<(), RbcDagError> {
    bytes.push(CONSENSUS_ROUND_FIELD);
    bytes.extend_from_slice(&vertex.consensus_round.to_be_bytes());
    bytes.push(STRONG_PARENTS_FIELD);
    encode_count(bytes, "strong parents", vertex.strong_parents.len())?;
    for parent in &vertex.strong_parents {
        encode_consensus_reference(bytes, *parent);
    }
    bytes.push(DELIVERY_FRONTIER_FIELD);
    encode_count(bytes, "delivery frontier", vertex.delivery_frontier.len())?;
    for entry in &vertex.delivery_frontier {
        match entry {
            None => bytes.push(OPTION_NONE),
            Some(reference) => {
                bytes.push(OPTION_SOME);
                encode_reference(bytes, *reference);
            }
        }
    }
    bytes.push(LEADER_CHOICE_FIELD);
    match vertex.leader_choice {
        LeaderChoiceV1::Vote { leader } => {
            bytes.push(LEADER_VOTE);
            encode_consensus_reference(bytes, leader);
        }
        LeaderChoiceV1::NoVote {
            leader_author,
            leader_round,
        } => {
            bytes.push(LEADER_NO_VOTE);
            bytes.extend_from_slice(&leader_author.to_be_bytes());
            bytes.extend_from_slice(&leader_round.to_be_bytes());
        }
    }
    Ok(())
}

fn encode_count(bytes: &mut Vec<u8>, field: &'static str, count: usize) -> Result<(), RbcDagError> {
    let count = u16::try_from(count).map_err(|_| RbcDagError::VectorTooLong { field, count })?;
    bytes.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn encode_reference(bytes: &mut Vec<u8>, reference: BlockReference) {
    bytes.extend_from_slice(&reference.authority.to_be_bytes());
    bytes.extend_from_slice(&reference.round.to_be_bytes());
    bytes.extend_from_slice(reference.digest.as_ref());
}

fn encode_consensus_reference(bytes: &mut Vec<u8>, reference: ConsensusVertexReference) {
    encode_reference(bytes, reference.carrier);
    bytes.extend_from_slice(&reference.consensus_round.to_be_bytes());
}

fn physical_parents(header: &CarrierHeaderV1) -> Vec<BlockReference> {
    let mut parents = Vec::with_capacity(header.weak_parents.len() + 1);
    parents.push(header.own_prev);
    parents.extend_from_slice(&header.weak_parents);
    parents
}

fn compressed_acknowledgments(
    header: &CarrierHeaderV1,
) -> Result<(u16, Vec<BlockReference>), RbcDagError> {
    let parents = physical_parents(header);
    let acknowledged: BTreeSet<_> = header.data_acknowledgments.iter().copied().collect();
    let mut intersection = parents.len();
    while intersection > 0 && acknowledged.contains(&parents[intersection - 1]) {
        intersection -= 1;
    }
    let shared: BTreeSet<_> = parents[intersection..].iter().copied().collect();
    let extras = header
        .data_acknowledgments
        .iter()
        .copied()
        .filter(|reference| !shared.contains(reference))
        .collect();
    let intersection = u16::try_from(intersection).map_err(|_| RbcDagError::VectorTooLong {
        field: "physical parents",
        count: parents.len(),
    })?;
    Ok((intersection, extras))
}

fn normalize_acknowledgments(header: &mut CarrierHeaderV1) -> Result<(), RbcDagError> {
    let mut seen = BTreeSet::new();
    for acknowledgment in &header.data_acknowledgments {
        if !seen.insert(*acknowledgment) {
            return Err(RbcDagError::DuplicateAcknowledgment(*acknowledgment));
        }
    }
    let parents = physical_parents(header);
    let (intersection, extras) = compressed_acknowledgments(header)?;
    let mut normalized = parents[intersection as usize..].to_vec();
    normalized.extend(extras);
    header.data_acknowledgments = normalized;
    Ok(())
}

fn decode_header(
    bytes: &[u8],
    acknowledgment_encoding: AckEncoding,
) -> Result<CarrierHeaderV1, RbcDagError> {
    if bytes.len() > MAX_CARRIER_CONTENT_SIZE_V1 {
        return Err(RbcDagError::ContentTooLarge(bytes.len()));
    }
    let mut decoder = Decoder::new(bytes);
    decoder.expect_marker(CONTENT_FORMAT_FIELD)?;
    let version = decoder.read_u8()?;
    let expected_version = match acknowledgment_encoding {
        AckEncoding::Expanded => CARRIER_FORMAT_VERSION_V1,
        AckEncoding::Compressed => CARRIER_WIRE_FORMAT_VERSION_V1,
    };
    if version != expected_version {
        return Err(RbcDagError::UnsupportedVersion(version));
    }
    decoder.expect_marker(AUTHOR_FIELD)?;
    let author = decoder.read_u16()?;
    decoder.expect_marker(CARRIER_ROUND_FIELD)?;
    let carrier_round = decoder.read_u32()?;
    decoder.expect_marker(OWN_PREV_FIELD)?;
    let own_prev = decoder.read_reference()?;
    decoder.expect_marker(WEAK_PARENTS_FIELD)?;
    let weak_count = decoder.read_count("weak parents", MAX_COMMITTEE_SIZE as usize - 1)?;
    let weak_parents = decoder.read_references(weak_count)?;
    decoder.expect_marker(TRANSACTIONS_COMMITMENT_FIELD)?;
    let transactions_commitment = TransactionsCommitment::from_bytes(decoder.read_array()?);
    decoder.expect_marker(ACKNOWLEDGMENTS_FIELD)?;
    let data_acknowledgments = match acknowledgment_encoding {
        AckEncoding::Expanded => {
            let count = decoder.read_count("acknowledgments", u16::MAX as usize)?;
            decoder.read_references(count)?
        }
        AckEncoding::Compressed => {
            let intersection = decoder.read_u16()? as usize;
            let extra_count = decoder.read_count("extra acknowledgments", u16::MAX as usize)?;
            let extras = decoder.read_references(extra_count)?;
            let mut parents = Vec::with_capacity(weak_parents.len() + 1);
            parents.push(own_prev);
            parents.extend_from_slice(&weak_parents);
            if intersection > parents.len() {
                return Err(RbcDagError::NonCanonicalAcknowledgments);
            }
            let mut acknowledgments = parents[intersection..].to_vec();
            acknowledgments.extend_from_slice(&extras);
            let provisional = CarrierHeaderV1 {
                author,
                carrier_round,
                own_prev,
                weak_parents: weak_parents.clone(),
                transactions_commitment,
                data_acknowledgments: acknowledgments.clone(),
                phase_batch: Vec::new(),
                consensus_vertex: None,
                creation_time_ns: 0,
            };
            let (canonical_intersection, canonical_extras) =
                compressed_acknowledgments(&provisional)?;
            if canonical_intersection as usize != intersection || canonical_extras != extras {
                return Err(RbcDagError::NonCanonicalAcknowledgments);
            }
            acknowledgments
        }
    };
    decoder.expect_marker(PHASE_BATCH_FIELD)?;
    let phase_count = decoder.read_count("phase statements", MAX_PHASE_STATEMENTS_V1)?;
    let mut phase_batch = Vec::with_capacity(phase_count);
    for _ in 0..phase_count {
        let code = decoder.read_u8()?;
        let target = decoder.read_reference()?;
        phase_batch.push(match code {
            PHASE_ECHO => RbcPhaseStatementV1::Echo { target },
            PHASE_READY => RbcPhaseStatementV1::Ready { target },
            other => return Err(RbcDagError::InvalidPhase(other)),
        });
    }
    decoder.expect_marker(CONSENSUS_VERTEX_FIELD)?;
    let consensus_vertex = match decoder.read_u8()? {
        OPTION_NONE => None,
        OPTION_SOME => Some(decoder.read_consensus_vertex()?),
        other => return Err(RbcDagError::InvalidOption(other)),
    };
    decoder.expect_marker(CREATION_TIME_FIELD)?;
    let creation_time_ns = decoder.read_u64()?;
    decoder.finish()?;
    Ok(CarrierHeaderV1 {
        author,
        carrier_round,
        own_prev,
        weak_parents,
        transactions_commitment,
        data_acknowledgments,
        phase_batch,
        consensus_vertex,
        creation_time_ns,
    })
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RbcDagError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RbcDagError::UnexpectedEnd)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(RbcDagError::UnexpectedEnd)?;
        self.position = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], RbcDagError> {
        let mut value = [0; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, RbcDagError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, RbcDagError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, RbcDagError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, RbcDagError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn expect_marker(&mut self, expected: u8) -> Result<(), RbcDagError> {
        let actual = self.read_u8()?;
        if actual != expected {
            return Err(RbcDagError::InvalidMarker { expected, actual });
        }
        Ok(())
    }

    fn read_count(&mut self, field: &'static str, maximum: usize) -> Result<usize, RbcDagError> {
        let count = self.read_u16()? as usize;
        if count > maximum {
            return Err(RbcDagError::VectorTooLong { field, count });
        }
        Ok(count)
    }

    fn read_reference(&mut self) -> Result<BlockReference, RbcDagError> {
        let authority = self.read_u16()?;
        let round = self.read_u32()?;
        let digest = BlockDigest::from(self.read_array()?);
        Ok(BlockReference {
            round,
            authority,
            digest,
        })
    }

    fn read_references(&mut self, count: usize) -> Result<Vec<BlockReference>, RbcDagError> {
        let byte_count = count
            .checked_mul(BLOCK_REFERENCE_SIZE)
            .ok_or(RbcDagError::UnexpectedEnd)?;
        if self.bytes.len().saturating_sub(self.position) < byte_count {
            return Err(RbcDagError::UnexpectedEnd);
        }
        let mut references = Vec::with_capacity(count);
        for _ in 0..count {
            references.push(self.read_reference()?);
        }
        Ok(references)
    }

    fn read_consensus_reference(&mut self) -> Result<ConsensusVertexReference, RbcDagError> {
        Ok(ConsensusVertexReference::new(
            self.read_reference()?,
            self.read_u32()?,
        ))
    }

    fn read_consensus_vertex(&mut self) -> Result<ConsensusVertexV1, RbcDagError> {
        self.expect_marker(CONSENSUS_ROUND_FIELD)?;
        let consensus_round = self.read_u32()?;
        self.expect_marker(STRONG_PARENTS_FIELD)?;
        let parent_count = self.read_count("strong parents", MAX_COMMITTEE_SIZE as usize)?;
        let mut strong_parents = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            strong_parents.push(self.read_consensus_reference()?);
        }
        self.expect_marker(DELIVERY_FRONTIER_FIELD)?;
        let frontier_count = self.read_count("delivery frontier", MAX_COMMITTEE_SIZE as usize)?;
        let mut delivery_frontier = Vec::with_capacity(frontier_count);
        for _ in 0..frontier_count {
            delivery_frontier.push(match self.read_u8()? {
                OPTION_NONE => None,
                OPTION_SOME => Some(self.read_reference()?),
                other => return Err(RbcDagError::InvalidOption(other)),
            });
        }
        self.expect_marker(LEADER_CHOICE_FIELD)?;
        let leader_choice = match self.read_u8()? {
            LEADER_NONE => return Err(RbcDagError::InvalidLeaderChoice(LEADER_NONE)),
            LEADER_VOTE => LeaderChoiceV1::Vote {
                leader: self.read_consensus_reference()?,
            },
            LEADER_NO_VOTE => LeaderChoiceV1::NoVote {
                leader_author: self.read_u16()?,
                leader_round: self.read_u32()?,
            },
            other => return Err(RbcDagError::InvalidLeaderChoice(other)),
        };
        Ok(ConsensusVertexV1::new(
            consensus_round,
            strong_parents,
            delivery_frontier,
            leader_choice,
        ))
    }

    fn finish(self) -> Result<(), RbcDagError> {
        if self.position != self.bytes.len() {
            return Err(RbcDagError::TrailingBytes(self.bytes.len() - self.position));
        }
        Ok(())
    }
}

fn validate_committee(committee: &Committee) -> Result<(), RbcDagError> {
    if committee.is_empty() || committee.len() > MAX_COMMITTEE_SIZE as usize {
        return Err(RbcDagError::InvalidCommittee("invalid committee size"));
    }
    let mut total_stake = 0u64;
    for authority in committee.authorities() {
        let stake = committee
            .get_stake(authority)
            .ok_or(RbcDagError::UnknownAuthority(authority))?;
        if stake == 0 {
            return Err(RbcDagError::InvalidCommittee("zero stake"));
        }
        total_stake = total_stake
            .checked_add(stake)
            .ok_or(RbcDagError::InvalidCommittee("stake overflow"))?;
    }
    let expected_validity = total_stake / 3 + 1;
    let expected_quorum = total_stake
        .checked_mul(2)
        .ok_or(RbcDagError::InvalidCommittee("stake overflow"))?
        / 3
        + 1;
    if committee.validity_threshold() != expected_validity
        || committee.quorum_threshold() != expected_quorum
    {
        return Err(RbcDagError::InvalidCommittee("threshold mismatch"));
    }
    let committee_size = committee.len();
    let fault_count = (committee_size - 1) / 3;
    let expected_info_length = match committee_size % 3 {
        0 => fault_count + 3,
        1 => fault_count + 1,
        _ => fault_count + 2,
    };
    if committee.info_length() != expected_info_length {
        return Err(RbcDagError::InvalidCommittee("information length mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        dummy_ml_dsa_44_signer, dummy_ml_dsa_65_signer, dummy_signer, mac_keyrings_for_test,
    };

    fn reference(authority: AuthorityIndex, round: RoundNumber, marker: u8) -> BlockReference {
        BlockReference {
            authority,
            round,
            digest: BlockDigest::from([marker; 32]),
        }
    }

    fn quorum_others(committee: &Committee, author: AuthorityIndex) -> Vec<AuthorityIndex> {
        let mut stake = committee.get_stake(author).unwrap();
        let mut others = Vec::new();
        for authority in committee.authorities().filter(|other| *other != author) {
            if stake >= committee.quorum_threshold() {
                break;
            }
            stake += committee.get_stake(authority).unwrap();
            others.push(authority);
        }
        others.sort_unstable();
        others
    }

    fn args(
        committee: &Committee,
        author: AuthorityIndex,
        carrier_round: RoundNumber,
    ) -> CarrierHeaderV1Args {
        let previous = carrier_round - 1;
        let parent = |authority| {
            if previous == 0 {
                carrier_genesis_reference(authority)
            } else {
                reference(authority, previous, 0x40 + authority as u8)
            }
        };
        CarrierHeaderV1Args {
            author,
            carrier_round,
            own_prev: parent(author),
            weak_parents: quorum_others(committee, author)
                .into_iter()
                .map(parent)
                .collect(),
            transactions_commitment: TransactionsCommitment::from_bytes([0x55; 32]),
            data_acknowledgments: Vec::new(),
            phase_batch: Vec::new(),
            consensus_vertex: None,
            creation_time_ns: 0x0102_0304_0506_0708,
        }
    }

    fn full_args(committee: &Committee) -> CarrierHeaderV1Args {
        let mut args = args(committee, 3, 2);
        let phase_target = reference(2, 1, 0x72);
        args.data_acknowledgments = vec![*args.weak_parents.last().unwrap(), reference(2, 1, 0x61)];
        args.phase_batch = vec![
            RbcPhaseStatementV1::Echo {
                target: phase_target,
            },
            RbcPhaseStatementV1::Ready {
                target: phase_target,
            },
        ];
        let strong_parents = [0, 1, 3]
            .into_iter()
            .map(|authority| ConsensusVertexReference::new(carrier_genesis_reference(authority), 0))
            .collect();
        args.consensus_vertex = Some(ConsensusVertexV1::new(
            1,
            strong_parents,
            vec![None; committee.len()],
            LeaderChoiceV1::Vote {
                leader: ConsensusVertexReference::new(carrier_genesis_reference(0), 0),
            },
        ));
        args
    }

    fn full_candidate(committee: &Committee) -> CandidateCarrierV1 {
        CandidateCarrierV1::try_new(full_args(committee), committee).unwrap()
    }

    #[test]
    fn canonical_content_and_reference_have_frozen_golden_bytes() {
        let committee = Committee::new_test(vec![1; 4]);
        let candidate = full_candidate(&committee);
        let bytes = candidate.canonical_content_bytes().unwrap();
        assert_eq!(
            bytes[0..2],
            [CONTENT_FORMAT_FIELD, CARRIER_FORMAT_VERSION_V1]
        );
        assert_eq!(
            candidate.reference().digest.as_ref(),
            blake3::hash(&bytes).as_bytes()
        );
        let mut expected = vec![0x00, 0x01, 0x01];
        expected.extend_from_slice(&3u16.to_be_bytes());
        expected.push(0x02);
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.push(0x03);
        encode_reference(&mut expected, reference(3, 1, 0x43));
        expected.extend_from_slice(&[0x04, 0x00, 0x02]);
        encode_reference(&mut expected, reference(0, 1, 0x40));
        encode_reference(&mut expected, reference(1, 1, 0x41));
        expected.push(0x05);
        expected.extend_from_slice(&[0x55; 32]);
        expected.extend_from_slice(&[0x06, 0x00, 0x02]);
        encode_reference(&mut expected, reference(1, 1, 0x41));
        encode_reference(&mut expected, reference(2, 1, 0x61));
        expected.extend_from_slice(&[0x07, 0x00, 0x02]);
        for phase in [0x00, 0x01] {
            expected.push(phase);
            encode_reference(&mut expected, reference(2, 1, 0x72));
        }
        expected.extend_from_slice(&[0x08, 0x01, 0x01]);
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(&[0x02, 0x00, 0x03]);
        for authority in [0, 1, 3] {
            encode_reference(&mut expected, carrier_genesis_reference(authority));
            expected.extend_from_slice(&0u32.to_be_bytes());
        }
        expected.extend_from_slice(&[0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
        expected.extend_from_slice(&[0x04, 0x01]);
        encode_reference(&mut expected, carrier_genesis_reference(0));
        expected.extend_from_slice(&0u32.to_be_bytes());
        expected.push(0x09);
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(bytes, expected);
        assert_eq!(
            hex::encode(candidate.reference().digest.as_ref()),
            "797b7ffa348c94889c36ea4a0c02070963efe6b7326aaed057f47e825867012f"
        );
    }

    #[test]
    fn every_canonical_carrier_field_is_bound_to_the_reference() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut base = full_args(&committee);
        base.data_acknowledgments.push(reference(0, 1, 0x62));
        let base_candidate = CandidateCarrierV1::try_new(base.clone(), &committee).unwrap();
        let base_reference = base_candidate.reference();
        let mut mutations = Vec::new();

        let mut changed = base.clone();
        changed.author = 2;
        changed.own_prev = reference(2, 1, 0x42);
        mutations.push(("author", changed));

        let mut changed = base.clone();
        changed.carrier_round = 3;
        changed.own_prev = reference(3, 2, 0x43);
        changed.weak_parents = vec![reference(0, 2, 0x40), reference(1, 2, 0x41)];
        mutations.push(("carrier round", changed));

        let mut changed = base.clone();
        changed.own_prev.digest = BlockDigest::from([0x91; 32]);
        mutations.push(("own predecessor", changed));

        let mut changed = base.clone();
        changed.weak_parents[0].digest = BlockDigest::from([0x92; 32]);
        mutations.push(("weak parent", changed));

        let mut changed = base.clone();
        changed.weak_parents.push(reference(2, 1, 0x42));
        mutations.push(("weak parent count", changed));

        let mut changed = base.clone();
        changed.transactions_commitment = TransactionsCommitment::from_bytes([0x93; 32]);
        mutations.push(("transaction commitment", changed));

        let mut changed = base.clone();
        changed.data_acknowledgments[1].digest = BlockDigest::from([0x94; 32]);
        mutations.push(("acknowledgment", changed));

        let mut changed = base.clone();
        changed.data_acknowledgments.push(reference(3, 1, 0x95));
        mutations.push(("acknowledgment count", changed));

        let mut changed = base.clone();
        changed.data_acknowledgments.swap(1, 2);
        mutations.push(("acknowledgment order", changed));

        let mut changed = base.clone();
        changed.phase_batch[0] = RbcPhaseStatementV1::Ready {
            target: reference(1, 1, 0x96),
        };
        mutations.push(("phase kind", changed));

        let mut changed = base.clone();
        changed.phase_batch[0] = RbcPhaseStatementV1::Echo {
            target: reference(2, 1, 0x97),
        };
        mutations.push(("phase target", changed));

        let mut changed = base.clone();
        changed.phase_batch.swap(0, 1);
        mutations.push(("phase order", changed));

        let mut changed = base.clone();
        changed.phase_batch.pop();
        mutations.push(("phase count", changed));

        let mut changed = base.clone();
        changed.consensus_vertex = None;
        mutations.push(("consensus presence", changed));

        let mut changed = base.clone();
        changed.consensus_vertex.as_mut().unwrap().consensus_round = 2;
        mutations.push(("consensus round", changed));

        let mut changed = base.clone();
        changed.consensus_vertex.as_mut().unwrap().strong_parents[0]
            .carrier
            .digest = BlockDigest::from([0x98; 32]);
        mutations.push(("strong parent carrier", changed));

        let mut changed = base.clone();
        changed.consensus_vertex.as_mut().unwrap().strong_parents[0].consensus_round = 1;
        mutations.push(("strong parent consensus round", changed));

        let mut changed = base.clone();
        changed
            .consensus_vertex
            .as_mut()
            .unwrap()
            .strong_parents
            .insert(
                2,
                ConsensusVertexReference::new(carrier_genesis_reference(2), 0),
            );
        mutations.push(("strong parent count", changed));

        let mut changed = base.clone();
        changed.consensus_vertex.as_mut().unwrap().delivery_frontier[0] =
            Some(reference(0, 1, 0x99));
        mutations.push(("frontier entry", changed));

        let mut changed = base.clone();
        changed
            .consensus_vertex
            .as_mut()
            .unwrap()
            .delivery_frontier
            .pop();
        mutations.push(("frontier count", changed));

        let mut changed = base.clone();
        changed.consensus_vertex.as_mut().unwrap().leader_choice = LeaderChoiceV1::NoVote {
            leader_author: 0,
            leader_round: 0,
        };
        mutations.push(("leader choice", changed));

        let mut changed = base;
        changed.creation_time_ns ^= 1;
        mutations.push(("creation time", changed));

        for (field, changed) in mutations {
            let candidate = CandidateCarrierV1::try_new(changed, &committee)
                .unwrap_or_else(|error| panic!("{field} mutation must remain encodable: {error}"));
            assert_ne!(candidate.reference(), base_reference, "unbound {field}");
            let bytes = candidate.canonical_content_bytes().unwrap();
            assert!(matches!(
                CandidateCarrierV1::decode_content(&bytes, &committee, Some(base_reference)),
                Err(RbcDagError::ReferenceMismatch { .. })
            ));
        }
    }

    #[test]
    fn content_and_compressed_wire_round_trip_to_same_reference() {
        let committee = Committee::new_test(vec![1; 4]);
        let candidate = full_candidate(&committee);
        let content = candidate.canonical_content_bytes().unwrap();
        let wire = candidate.canonical_wire_bytes().unwrap();
        assert_eq!(content[1], CARRIER_FORMAT_VERSION_V1);
        assert_eq!(wire[1], CARRIER_WIRE_FORMAT_VERSION_V1);
        assert!(wire.len() < content.len());
        assert_eq!(
            CandidateCarrierV1::decode_content(&content, &committee, Some(candidate.reference()))
                .unwrap(),
            candidate
        );
        assert!(matches!(
            CandidateCarrierV1::decode_content(&wire, &committee, None),
            Err(RbcDagError::UnsupportedVersion(
                CARRIER_WIRE_FORMAT_VERSION_V1
            ))
        ));
        assert!(matches!(
            CandidateCarrierV1::decode_wire(&content, &committee, None),
            Err(RbcDagError::UnsupportedVersion(CARRIER_FORMAT_VERSION_V1))
        ));
        assert_eq!(
            CandidateCarrierV1::decode_wire(&wire, &committee, Some(candidate.reference()))
                .unwrap(),
            candidate
        );
        for end in 0..content.len() {
            assert!(CandidateCarrierV1::decode_content(&content[..end], &committee, None).is_err());
        }
        for end in 0..wire.len() {
            assert!(CandidateCarrierV1::decode_wire(&wire[..end], &committee, None).is_err());
        }
        let mut trailing = wire;
        trailing.push(0);
        assert!(matches!(
            CandidateCarrierV1::decode_wire(&trailing, &committee, None),
            Err(RbcDagError::TrailingBytes(1))
        ));
    }

    #[test]
    fn acknowledgment_compression_normalizes_and_rejects_duplicates() {
        let committee = Committee::new_test(vec![1; 4]);
        let base = args(&committee, 3, 2);
        let shared = *base.weak_parents.last().unwrap();
        let extra = reference(2, 1, 0x91);

        let mut reordered = base.clone();
        reordered.data_acknowledgments = vec![extra, shared];
        let candidate = CandidateCarrierV1::try_new(reordered, &committee).unwrap();
        assert_eq!(candidate.header().data_acknowledgments(), &[shared, extra]);

        for acknowledgments in [vec![shared, shared], vec![extra, shared, shared]] {
            let mut duplicate = base.clone();
            duplicate.data_acknowledgments = acknowledgments;
            assert!(matches!(
                CandidateCarrierV1::try_new(duplicate, &committee),
                Err(RbcDagError::DuplicateAcknowledgment(reference)) if reference == shared
            ));
        }
    }

    #[test]
    fn acknowledgment_validation_handles_many_shared_hash_prefixes() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut carrier = args(&committee, 3, 2);
        carrier.data_acknowledgments = (0..8_192u64)
            .map(|counter| {
                let mut digest = [0xA5; 32];
                digest[24..].copy_from_slice(&counter.to_be_bytes());
                BlockReference {
                    authority: 2,
                    round: 1,
                    digest: BlockDigest::from(digest),
                }
            })
            .collect();

        let candidate = CandidateCarrierV1::try_new(carrier, &committee).unwrap();
        assert_eq!(candidate.header().data_acknowledgments().len(), 8_192);
        assert!(candidate.canonical_content_bytes().unwrap().len() < MAX_CARRIER_CONTENT_SIZE_V1);
    }

    #[test]
    fn phase_slot_conflict_is_rejected_even_when_digests_differ() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut args = args(&committee, 3, 2);
        args.phase_batch = vec![
            RbcPhaseStatementV1::Echo {
                target: reference(0, 1, 0x01),
            },
            RbcPhaseStatementV1::Echo {
                target: reference(0, 1, 0x02),
            },
        ];
        assert!(matches!(
            CandidateCarrierV1::try_new(args, &committee),
            Err(RbcDagError::DuplicatePhaseStatement(_))
        ));
    }

    #[test]
    fn malformed_optional_vertex_does_not_invalidate_outer_candidate() {
        let committee = Committee::new_test(vec![1; 4]);
        let mut args = args(&committee, 3, 1);
        args.consensus_vertex = Some(ConsensusVertexV1::new(
            1,
            Vec::new(),
            Vec::new(),
            LeaderChoiceV1::NoVote {
                leader_author: 0,
                leader_round: 0,
            },
        ));
        let candidate = CandidateCarrierV1::try_new(args, &committee).unwrap();
        assert!(matches!(
            candidate.validate_consensus_vertex(&committee),
            Err(RbcDagProjectionError::InvalidStrongParentThreshold)
        ));
    }

    #[test]
    fn valid_projection_shape_checks_quorum_frontier_and_choice() {
        let committee = Committee::new_test(vec![1; 4]);
        let candidate = full_candidate(&committee);
        assert!(
            candidate
                .validate_consensus_vertex(&committee)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn auth_statement_has_frozen_layout() {
        let committee = Committee::new_test(vec![1; 4]);
        let candidate = full_candidate(&committee);
        let instance = RbcDagProtocolInstanceId::new([0xA5; 32]).unwrap();
        let context =
            RbcDagContextV1::new(instance, &committee, BlockAuthenticationScheme::MlDsa65).unwrap();
        let base = context.public_authentication_statement(candidate.reference());
        assert_eq!(
            hex::encode(context.committee_id().as_bytes()),
            "acfb1f9c45727a7366b83e468926bfa9f577cf308078792da0b415d05ae3df62"
        );
        assert_eq!(
            hex::encode(base),
            concat!(
                "53544152464953485f5242435f4441475f56310002",
                "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
                "acfb1f9c45727a7366b83e468926bfa9f577cf308078792da0b415d05ae3df62",
                "000300000002",
                "797b7ffa348c94889c36ea4a0c02070963efe6b7326aaed057f47e825867012f"
            )
        );
        assert_eq!(
            hex::encode(context.public_authentication_digest(candidate.reference())),
            "26a0866c9c6938c9158495f23fd22b281db6371461b6aad109ad41329e5fa5c8"
        );
        assert_eq!(&base[..19], AUTHENTICATION_DOMAIN);
        assert_eq!(base[19], CARRIER_AUTHENTICATION_KIND);
        assert_eq!(base[20], 2);
        assert_eq!(&base[21..53], &[0xA5; 32]);
        assert_eq!(&base[53..85], context.committee_id().as_bytes());
        assert_eq!(&base[85..87], &3u16.to_be_bytes());
        assert_eq!(&base[87..91], &2u32.to_be_bytes());
        assert_eq!(&base[91..], candidate.reference().digest.as_ref());
        let public_digest = blake3::hash(&base);
        for (field, offset) in [
            ("domain", 0),
            ("kind", 19),
            ("scheme", 20),
            ("instance", 21),
            ("committee", 53),
            ("author", 85),
            ("round", 87),
            ("content digest", 91),
        ] {
            let mut changed = base;
            changed[offset] ^= 1;
            assert_ne!(
                blake3::hash(&changed),
                public_digest,
                "{field} must be bound by the public authenticator"
            );
        }

        let mac_context =
            RbcDagContextV1::new(instance, &committee, BlockAuthenticationScheme::MacVector)
                .unwrap();
        let keyrings = mac_keyrings_for_test(committee.len());
        let mac_statement = mac_context.mac_authentication_statement(candidate.reference(), 2);
        assert_eq!(
            hex::encode(mac_statement),
            concat!(
                "53544152464953485f5242435f4441475f56310003",
                "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
                "acfb1f9c45727a7366b83e468926bfa9f577cf308078792da0b415d05ae3df62",
                "000300000002",
                "797b7ffa348c94889c36ea4a0c02070963efe6b7326aaed057f47e825867012f",
                "0002"
            )
        );
        let key = &keyrings[3][2];
        let tag = key.compute_rbc_tag(&mac_statement);
        assert_eq!(
            hex::encode(tag.as_ref()),
            "118209f3c2c3025918ae7f60fe5a04a94e639cd06d910d89c483035c014fff02"
        );
        for (field, offset) in [
            ("domain", 0),
            ("kind", 19),
            ("scheme", 20),
            ("instance", 21),
            ("committee", 53),
            ("author", 85),
            ("round", 87),
            ("content digest", 91),
            ("recipient", 123),
        ] {
            let mut changed = mac_statement;
            changed[offset] ^= 1;
            assert_ne!(
                key.compute_rbc_tag(&changed),
                tag,
                "{field} must be bound by the MAC"
            );
        }
    }

    #[test]
    fn authorizer_is_bound_to_the_claimed_author_and_committee_key() {
        let committee = Committee::new_test(vec![1; 4]);
        let candidate = full_candidate(&committee);
        let context = RbcDagContextV1::new(
            RbcDagProtocolInstanceId::new([0xA5; 32]).unwrap(),
            &committee,
            BlockAuthenticationScheme::Ed25519,
        )
        .unwrap();
        let committee_signer = dummy_signer();

        assert!(matches!(
            context.authenticate(
                &candidate,
                &committee,
                CarrierAuthorizerV1::Ed25519 {
                    authority: 2,
                    signer: &committee_signer,
                },
            ),
            Err(RbcDagError::AuthorizerAuthorityMismatch {
                expected: 3,
                actual: 2,
            })
        ));

        let other_signers = Signer::new_for_test(1);
        assert!(matches!(
            context.authenticate(
                &candidate,
                &committee,
                CarrierAuthorizerV1::Ed25519 {
                    authority: 3,
                    signer: &other_signers[0],
                },
            ),
            Err(RbcDagError::AuthorizerKeyMismatch)
        ));
    }

    #[test]
    fn every_authentication_scheme_round_trips_and_keeps_content_identity() {
        let committee = Committee::new_test(vec![1; 4]);
        let candidate = full_candidate(&committee);
        let instance = RbcDagProtocolInstanceId::new([0xA5; 32]).unwrap();
        let keyrings = mac_keyrings_for_test(committee.len());
        let ed_signer = dummy_signer();
        let ml44_signer = dummy_ml_dsa_44_signer();
        let ml65_signer = dummy_ml_dsa_65_signer();

        for (scheme, authorizer) in [
            (
                BlockAuthenticationScheme::Ed25519,
                CarrierAuthorizerV1::Ed25519 {
                    authority: 3,
                    signer: &ed_signer,
                },
            ),
            (
                BlockAuthenticationScheme::MlDsa44,
                CarrierAuthorizerV1::MlDsa44 {
                    authority: 3,
                    signer: &ml44_signer,
                },
            ),
            (
                BlockAuthenticationScheme::MlDsa65,
                CarrierAuthorizerV1::MlDsa65 {
                    authority: 3,
                    signer: &ml65_signer,
                },
            ),
            (
                BlockAuthenticationScheme::MacVector,
                CarrierAuthorizerV1::MacVector {
                    authority: 3,
                    keys: &keyrings[3],
                },
            ),
        ] {
            let context = RbcDagContextV1::new(instance, &committee, scheme).unwrap();
            let authentication = context
                .authenticate(&candidate, &committee, authorizer)
                .unwrap();
            let wire = authentication.canonical_wire_bytes();
            let payload_len = match scheme {
                BlockAuthenticationScheme::Ed25519 => SIGNATURE_SIZE,
                BlockAuthenticationScheme::MlDsa44 => ML_DSA_44_SIGNATURE_SIZE,
                BlockAuthenticationScheme::MlDsa65 => ML_DSA_65_SIGNATURE_SIZE,
                BlockAuthenticationScheme::MacVector => committee.len() * MAC_TAG_SIZE,
            };
            assert_eq!(
                &wire[..3],
                &[
                    CONTENT_FORMAT_FIELD,
                    CARRIER_FORMAT_VERSION_V1,
                    authentication_scheme_code(scheme),
                ]
            );
            assert_eq!(wire.len(), 3 + payload_len);
            let decoded = CarrierAuthenticationV1::decode_wire(&wire, &committee).unwrap();
            assert_eq!(decoded, authentication);
            let authenticated = context
                .verify_authentication(candidate.clone(), decoded, 1, &committee, &keyrings[1])
                .unwrap();
            assert_eq!(authenticated.reference(), candidate.reference());
            assert_eq!(authenticated.receiver(), 1);
            assert_eq!(authenticated.context(), context);
        }
    }

    #[test]
    fn mac_verifies_only_local_entry_and_context() {
        let committee = Committee::new_test(vec![1; 4]);
        let candidate = full_candidate(&committee);
        let keyrings = mac_keyrings_for_test(committee.len());
        let instance = RbcDagProtocolInstanceId::new([0xA5; 32]).unwrap();
        let context =
            RbcDagContextV1::new(instance, &committee, BlockAuthenticationScheme::MacVector)
                .unwrap();
        let authentication = context
            .authenticate(
                &candidate,
                &committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 3,
                    keys: &keyrings[3],
                },
            )
            .unwrap();
        let CarrierAuthenticationV1::MacVector(vector) = authentication else {
            unreachable!()
        };
        let mut poisoned_other = vector.as_bytes().to_vec();
        poisoned_other[2 * MAC_TAG_SIZE] ^= 0xFF;
        let poisoned_other =
            CarrierAuthenticationV1::MacVector(FlatMacVector::from_bytes(poisoned_other).unwrap());
        assert!(
            context
                .verify_authentication(
                    candidate.clone(),
                    poisoned_other.clone(),
                    1,
                    &committee,
                    &keyrings[1],
                )
                .is_ok()
        );
        assert!(matches!(
            context.verify_authentication(
                candidate.clone(),
                poisoned_other,
                2,
                &committee,
                &keyrings[2],
            ),
            Err(RbcDagError::InvalidAuthentication)
        ));

        let other_context = RbcDagContextV1::new(
            RbcDagProtocolInstanceId::new([0xB6; 32]).unwrap(),
            &committee,
            BlockAuthenticationScheme::MacVector,
        )
        .unwrap();
        let original = context
            .authenticate(
                &candidate,
                &committee,
                CarrierAuthorizerV1::MacVector {
                    authority: 3,
                    keys: &keyrings[3],
                },
            )
            .unwrap();
        assert!(matches!(
            other_context.verify_authentication(candidate, original, 1, &committee, &keyrings[1],),
            Err(RbcDagError::InvalidAuthentication)
        ));
    }

    #[test]
    fn candidate_and_capability_are_committee_bound() {
        let committee = Committee::new_test(vec![1; 4]);
        let other_committee = Committee::new_test(vec![1, 1, 1, 2]);
        let candidate = full_candidate(&committee);
        let context = RbcDagContextV1::new(
            RbcDagProtocolInstanceId::new([0xA5; 32]).unwrap(),
            &other_committee,
            BlockAuthenticationScheme::Ed25519,
        )
        .unwrap();
        assert!(matches!(
            context.authenticate(
                &candidate,
                &other_committee,
                CarrierAuthorizerV1::Ed25519 {
                    authority: 3,
                    signer: &dummy_signer(),
                },
            ),
            Err(RbcDagError::CandidateCommitteeMismatch)
        ));
        assert!(matches!(
            candidate.validate_consensus_vertex(&other_committee),
            Err(RbcDagProjectionError::CommitteeMismatch)
        ));
    }

    #[test]
    fn cached_committee_context_hashes_the_key_transcript_once_across_hot_paths() {
        COMMITTEE_ID_DERIVATIONS.with(|count| count.set(0));

        let committee = Committee::new_test(vec![1; 4]);
        let committee_context = RbcDagCommitteeContextV1::new(Arc::clone(&committee)).unwrap();
        assert_eq!(COMMITTEE_ID_DERIVATIONS.with(std::cell::Cell::get), 1);

        let candidate =
            CandidateCarrierV1::try_new_with_committee(full_args(&committee), &committee_context)
                .unwrap();
        let content = candidate.canonical_content_bytes().unwrap();
        let wire = candidate.canonical_wire_bytes().unwrap();
        let decoded_content = CandidateCarrierV1::decode_content_with_committee(
            &content,
            &committee_context,
            Some(candidate.reference()),
        )
        .unwrap();
        let decoded_wire = CandidateCarrierV1::decode_wire_with_committee(
            &wire,
            &committee_context,
            Some(candidate.reference()),
        )
        .unwrap();
        assert_eq!(decoded_content, candidate);
        assert_eq!(decoded_wire, candidate);

        let context = RbcDagContextV1::new_with_committee(
            RbcDagProtocolInstanceId::new([0xA5; 32]).unwrap(),
            &committee_context,
            BlockAuthenticationScheme::MacVector,
        );
        let keyrings = mac_keyrings_for_test(committee.len());
        let authentication = context
            .authenticate_with_committee(
                &candidate,
                &committee_context,
                CarrierAuthorizerV1::MacVector {
                    authority: candidate.header().author(),
                    keys: &keyrings[candidate.header().author() as usize],
                },
            )
            .unwrap();
        let authentication_wire = authentication.canonical_wire_bytes();
        let decoded_authentication = CarrierAuthenticationV1::decode_wire_with_committee(
            &authentication_wire,
            &committee_context,
        )
        .unwrap();
        context
            .verify_authentication_with_committee(
                candidate.clone(),
                decoded_authentication,
                1,
                &committee_context,
                &keyrings[1],
            )
            .unwrap();
        context
            .verify_local_authentication_with_committee(
                candidate.clone(),
                authentication,
                &committee_context,
                CarrierAuthorizerV1::MacVector {
                    authority: candidate.header().author(),
                    keys: &keyrings[candidate.header().author() as usize],
                },
            )
            .unwrap();
        context
            .authenticate_local_with_committee(
                candidate.clone(),
                &committee_context,
                CarrierAuthorizerV1::MacVector {
                    authority: candidate.header().author(),
                    keys: &keyrings[candidate.header().author() as usize],
                },
            )
            .unwrap();
        candidate
            .validate_consensus_vertex_with_committee(&committee_context)
            .unwrap();

        let mut projection =
            projection::CertifiedProjectionModel::from_committee_context(committee_context.clone());
        projection.stage_carrier(candidate.clone()).unwrap();
        assert!(matches!(
            projection.try_project(candidate.reference()),
            Err(projection::CertifiedProjectionError::CarrierNotDelivered(reference))
                if reference == candidate.reference()
        ));

        assert_eq!(COMMITTEE_ID_DERIVATIONS.with(std::cell::Cell::get), 1);
    }

    #[test]
    fn cached_committee_context_rejects_cross_committee_hot_path_use() {
        let committee = Committee::new_test(vec![1; 4]);
        let other_committee = Committee::new_test(vec![1, 1, 1, 2]);
        let committee_context = RbcDagCommitteeContextV1::new(Arc::clone(&committee)).unwrap();
        let other_context = RbcDagCommitteeContextV1::new(Arc::clone(&other_committee)).unwrap();
        let candidate =
            CandidateCarrierV1::try_new_with_committee(full_args(&committee), &committee_context)
                .unwrap();
        let protocol_context = RbcDagContextV1::new_with_committee(
            RbcDagProtocolInstanceId::new([0xB7; 32]).unwrap(),
            &committee_context,
            BlockAuthenticationScheme::MacVector,
        );
        let keyrings = mac_keyrings_for_test(committee.len());
        let authentication = protocol_context
            .authenticate_with_committee(
                &candidate,
                &committee_context,
                CarrierAuthorizerV1::MacVector {
                    authority: candidate.header().author(),
                    keys: &keyrings[candidate.header().author() as usize],
                },
            )
            .unwrap();

        assert!(matches!(
            protocol_context.authenticate_with_committee(
                &candidate,
                &other_context,
                CarrierAuthorizerV1::MacVector {
                    authority: candidate.header().author(),
                    keys: &keyrings[candidate.header().author() as usize],
                },
            ),
            Err(RbcDagError::CommitteeIdMismatch)
        ));
        assert!(matches!(
            protocol_context.verify_authentication_with_committee(
                candidate.clone(),
                authentication.clone(),
                1,
                &other_context,
                &keyrings[1],
            ),
            Err(RbcDagError::CommitteeIdMismatch)
        ));
        assert!(matches!(
            protocol_context.verify_local_authentication_with_committee(
                candidate.clone(),
                authentication,
                &other_context,
                CarrierAuthorizerV1::MacVector {
                    authority: candidate.header().author(),
                    keys: &keyrings[candidate.header().author() as usize],
                },
            ),
            Err(RbcDagError::CommitteeIdMismatch)
        ));
        assert!(matches!(
            candidate.validate_consensus_vertex_with_committee(&other_context),
            Err(RbcDagProjectionError::CommitteeMismatch)
        ));

        let mut projection =
            projection::CertifiedProjectionModel::from_committee_context(other_context);
        assert_eq!(
            projection.stage_carrier(candidate),
            Err(projection::CertifiedProjectionError::CommitteeMismatch)
        );
    }

    #[test]
    fn persisted_ml_dsa_sidecar_recovers_exact_local_capability_and_rejects_tampering() {
        let committee = Committee::new_test(vec![1; 4]);
        let committee_context = RbcDagCommitteeContextV1::new(Arc::clone(&committee)).unwrap();
        let candidate =
            CandidateCarrierV1::try_new_with_committee(full_args(&committee), &committee_context)
                .unwrap();
        let instance = RbcDagProtocolInstanceId::new([0xC8; 32]).unwrap();
        let context = RbcDagContextV1::new_with_committee(
            instance,
            &committee_context,
            BlockAuthenticationScheme::MlDsa65,
        );
        let signer = dummy_ml_dsa_65_signer();
        let authentication = context
            .authenticate_with_committee(
                &candidate,
                &committee_context,
                CarrierAuthorizerV1::MlDsa65 {
                    authority: candidate.header().author(),
                    signer: &signer,
                },
            )
            .unwrap();
        let persisted_wire = authentication.canonical_wire_bytes();
        let persisted_authentication = CarrierAuthenticationV1::decode_wire_with_committee(
            &persisted_wire,
            &committee_context,
        )
        .unwrap();
        let recovered = context
            .verify_local_authentication_with_committee(
                candidate.clone(),
                persisted_authentication,
                &committee_context,
                CarrierAuthorizerV1::MlDsa65 {
                    authority: candidate.header().author(),
                    signer: &signer,
                },
            )
            .unwrap();
        assert_eq!(recovered.authentication(), &authentication);
        assert_eq!(
            recovered.authentication().canonical_wire_bytes(),
            persisted_wire
        );

        let CarrierAuthenticationV1::MlDsa65(signature) = &authentication else {
            unreachable!()
        };
        let mut tampered_bytes = [0; ML_DSA_65_SIGNATURE_SIZE];
        tampered_bytes.copy_from_slice(signature.as_ref());
        tampered_bytes[0] ^= 1;
        let tampered =
            CarrierAuthenticationV1::MlDsa65(MlDsa65SignatureBytes::from_bytes(tampered_bytes));
        assert!(matches!(
            context.verify_local_authentication_with_committee(
                candidate.clone(),
                tampered,
                &committee_context,
                CarrierAuthorizerV1::MlDsa65 {
                    authority: candidate.header().author(),
                    signer: &signer,
                },
            ),
            Err(RbcDagError::InvalidAuthentication)
        ));
        assert!(matches!(
            context.verify_local_authentication_with_committee(
                candidate.clone(),
                authentication.clone(),
                &committee_context,
                CarrierAuthorizerV1::MlDsa65 {
                    authority: 2,
                    signer: &signer,
                },
            ),
            Err(RbcDagError::AuthorizerAuthorityMismatch {
                expected: 3,
                actual: 2,
            })
        ));

        let wrong_context = RbcDagContextV1::new_with_committee(
            RbcDagProtocolInstanceId::new([0xC9; 32]).unwrap(),
            &committee_context,
            BlockAuthenticationScheme::MlDsa65,
        );
        assert!(matches!(
            wrong_context.verify_local_authentication_with_committee(
                candidate,
                authentication,
                &committee_context,
                CarrierAuthorizerV1::MlDsa65 {
                    authority: 3,
                    signer: &signer,
                },
            ),
            Err(RbcDagError::InvalidAuthentication)
        ));
    }

    #[test]
    fn persisted_local_mac_recovery_verifies_every_vector_entry_and_length() {
        let committee = Committee::new_test(vec![1; 4]);
        let committee_context = RbcDagCommitteeContextV1::new(Arc::clone(&committee)).unwrap();
        let candidate =
            CandidateCarrierV1::try_new_with_committee(full_args(&committee), &committee_context)
                .unwrap();
        let context = RbcDagContextV1::new_with_committee(
            RbcDagProtocolInstanceId::new([0xD9; 32]).unwrap(),
            &committee_context,
            BlockAuthenticationScheme::MacVector,
        );
        let keyrings = mac_keyrings_for_test(committee.len());
        let author = candidate.header().author() as usize;
        let authentication = context
            .authenticate_with_committee(
                &candidate,
                &committee_context,
                CarrierAuthorizerV1::MacVector {
                    authority: author as AuthorityIndex,
                    keys: &keyrings[author],
                },
            )
            .unwrap();
        context
            .verify_local_authentication_with_committee(
                candidate.clone(),
                authentication.clone(),
                &committee_context,
                CarrierAuthorizerV1::MacVector {
                    authority: author as AuthorityIndex,
                    keys: &keyrings[author],
                },
            )
            .unwrap();

        let CarrierAuthenticationV1::MacVector(vector) = &authentication else {
            unreachable!()
        };
        let mut poisoned_bytes = vector.as_bytes().to_vec();
        poisoned_bytes[2 * MAC_TAG_SIZE] ^= 1;
        let poisoned =
            CarrierAuthenticationV1::MacVector(FlatMacVector::from_bytes(poisoned_bytes).unwrap());
        context
            .verify_authentication_with_committee(
                candidate.clone(),
                poisoned.clone(),
                1,
                &committee_context,
                &keyrings[1],
            )
            .expect("a different recipient's entry remains valid");
        assert!(matches!(
            context.verify_local_authentication_with_committee(
                candidate.clone(),
                poisoned,
                &committee_context,
                CarrierAuthorizerV1::MacVector {
                    authority: author as AuthorityIndex,
                    keys: &keyrings[author],
                },
            ),
            Err(RbcDagError::InvalidAuthentication)
        ));

        let short = CarrierAuthenticationV1::MacVector(
            FlatMacVector::from_bytes(
                vector.as_bytes()[..vector.as_bytes().len() - MAC_TAG_SIZE].to_vec(),
            )
            .unwrap(),
        );
        assert!(matches!(
            context.verify_local_authentication_with_committee(
                candidate,
                short,
                &committee_context,
                CarrierAuthorizerV1::MacVector {
                    authority: author as AuthorityIndex,
                    keys: &keyrings[author],
                },
            ),
            Err(RbcDagError::InvalidMacVectorLength { .. })
        ));
    }

    #[test]
    fn sidecar_wire_has_frozen_flat_mac_shape() {
        let committee = Committee::new_test(vec![1; 4]);
        let tags = (0..4)
            .map(|index| MacTag::from_bytes([index; MAC_TAG_SIZE]))
            .collect::<Vec<_>>();
        let authentication =
            CarrierAuthenticationV1::MacVector(FlatMacVector::from_tags(&tags).unwrap());
        let wire = authentication.canonical_wire_bytes();
        assert_eq!(&wire[..3], &[0x00, 0x01, 0x03]);
        assert_eq!(wire.len(), 3 + committee.len() * MAC_TAG_SIZE);
        assert_eq!(
            hex::encode(wire),
            concat!(
                "000103",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0101010101010101010101010101010101010101010101010101010101010101",
                "0202020202020202020202020202020202020202020202020202020202020202",
                "0303030303030303030303030303030303030303030303030303030303030303"
            )
        );

        let mut trailing = authentication.canonical_wire_bytes();
        trailing.push(0xFF);
        assert!(matches!(
            CarrierAuthenticationV1::decode_wire(&trailing, &committee),
            Err(RbcDagError::TrailingBytes(1))
        ));
        let mut truncated = authentication.canonical_wire_bytes();
        truncated.pop();
        assert!(matches!(
            CarrierAuthenticationV1::decode_wire(&truncated, &committee),
            Err(RbcDagError::UnexpectedEnd)
        ));
    }
}
