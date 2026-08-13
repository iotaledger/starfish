// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Synchronous reliable-broadcast kernel for Starfish-RBC.
//!
//! Networking and DAG admission remain outside the kernel: the service adapter
//! supplies content-validated headers and expands typed multicast effects into
//! recipient-specific messages.

use std::{collections::BTreeMap, error::Error, fmt, sync::Arc};

use ahash::{AHashMap, AHashSet};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    committee::{Committee, QuorumThreshold, StakeAggregator, ValidityThreshold},
    crypto::{
        Blake3Hasher, MacKey, MacTag, MlDsa44SignatureBytes, MlDsa65SignatureBytes, SignatureBytes,
        TransactionsCommitment,
    },
    types::{
        AckFields, AuthorityIndex, AuthoritySet, BlockAuthentication, BlockAuthenticationScheme,
        BlockDigest, BlockHeader, BlockReference, MAX_COMMITTEE_SIZE, RoundNumber, Stake,
        StarfishRbcFieldsV3, StarfishRbcReferenceKindV3, StarfishRbcReferenceV3, TimestampNs,
        TransactionData, VerifiedBlock, compress_acknowledgments, expand_acknowledgments,
    },
};

const PROTOCOL_DOMAIN: &[u8; 15] = b"STARFISH_RBC_V1";
const COMMITTEE_ID_DERIVE_CONTEXT: &str = "STARFISH_RBC_V1_COMMITTEE_ID";
const INITIAL_KIND: u8 = 0x00;
const ECHO_KIND: u8 = 0x01;
const READY_KIND: u8 = 0x02;

const PROTOCOL_INSTANCE_SIZE: usize = 32;
const COMMITTEE_ID_SIZE: usize = 32;
const BLOCK_REFERENCE_SIZE: usize = 2 + 4 + 32;
const BASE_STATEMENT_SIZE: usize = PROTOCOL_DOMAIN.len()
    + 1
    + 1
    + PROTOCOL_INSTANCE_SIZE
    + COMMITTEE_ID_SIZE
    + BLOCK_REFERENCE_SIZE;
const MAC_STATEMENT_SIZE: usize = BASE_STATEMENT_SIZE + 2 + 2;
const RBC_BLOCK_REFERENCE_SIZE: usize = 2 + 4 + 32;
const RBC_HEADER_FIXED_CONTENT_SIZE: usize = 1 + 2 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 8 + 1 + 32;
const MAX_RBC_HEADER_CONTENT_SIZE: usize = 4 * 1024 * 1024;
const MAX_RBC_REFERENCES_PER_FIELD: usize = u16::MAX as usize;
const MAX_RBC_FUTURE_ROUNDS: RoundNumber = 100;

mod bounded_references {
    use std::{fmt, marker::PhantomData};

    use serde::de::{Error as _, SeqAccess, Visitor};

    use super::*;

    pub(super) fn serialize<S>(
        references: &[BlockReference],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        references.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<BlockReference>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ReferencesVisitor(PhantomData<BlockReference>);

        impl<'de> Visitor<'de> for ReferencesVisitor {
            type Value = Vec<BlockReference>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "at most {MAX_RBC_REFERENCES_PER_FIELD} Starfish-RBC references"
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let size_hint = sequence.size_hint().unwrap_or(0);
                if size_hint > MAX_RBC_REFERENCES_PER_FIELD {
                    return Err(A::Error::custom(format!(
                        "RBC reference count {size_hint} exceeds {MAX_RBC_REFERENCES_PER_FIELD}"
                    )));
                }
                let mut references = Vec::with_capacity(size_hint);
                while let Some(reference) = sequence.next_element()? {
                    if references.len() == MAX_RBC_REFERENCES_PER_FIELD {
                        return Err(A::Error::custom(format!(
                            "RBC reference count exceeds {MAX_RBC_REFERENCES_PER_FIELD}"
                        )));
                    }
                    references.push(reference);
                }
                Ok(references)
            }
        }

        deserializer.deserialize_seq(ReferencesVisitor(PhantomData))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct RbcAckFields {
    intersection: Option<u8>,
    #[serde(with = "bounded_references")]
    extra_references: Vec<BlockReference>,
}

impl RbcAckFields {
    fn from_logical(
        block_references: &[BlockReference],
        acknowledgment_references: &[BlockReference],
    ) -> Self {
        let (intersection, extra_references) =
            compress_acknowledgments(block_references, acknowledgment_references);
        Self {
            intersection,
            extra_references,
        }
    }

    fn logical(&self, block_references: &[BlockReference]) -> Vec<BlockReference> {
        expand_acknowledgments(block_references, self.intersection, &self.extra_references)
    }

    fn is_canonical(&self, block_references: &[BlockReference]) -> bool {
        if self
            .intersection
            .is_some_and(|start| start as usize > block_references.len())
        {
            return false;
        }
        let logical = self.logical(block_references);
        let (intersection, extra_references) = compress_acknowledgments(block_references, &logical);
        self.intersection == intersection && self.extra_references == extra_references
    }
}

/// Authentication-free, canonical Starfish-RBC header content.
///
/// Acknowledgments stay canonically compressed on wire, but the digest hashes
/// their expanded logical vector with an explicit boundary from parents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RbcCanonicalHeader {
    reference: BlockReference,
    #[serde(with = "bounded_references")]
    block_references: Vec<BlockReference>,
    acknowledgments: RbcAckFields,
    meta_creation_time_ns: TimestampNs,
    transactions_commitment: TransactionsCommitment,
    #[serde(default)]
    starfish_rbc_v3: Option<StarfishRbcFieldsV3>,
}

impl RbcCanonicalHeader {
    pub(crate) fn try_new(
        authority: AuthorityIndex,
        round: RoundNumber,
        block_references: Vec<BlockReference>,
        acknowledgment_references: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        transactions_commitment: TransactionsCommitment,
    ) -> Result<Self, RbcError> {
        Self::try_new_with_fields(
            authority,
            round,
            block_references,
            acknowledgment_references,
            meta_creation_time_ns,
            transactions_commitment,
            None,
        )
    }

    pub(crate) fn try_new_single_dag(
        authority: AuthorityIndex,
        round: RoundNumber,
        block_references: Vec<BlockReference>,
        acknowledgment_references: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        transactions_commitment: TransactionsCommitment,
        starfish_rbc_v3: StarfishRbcFieldsV3,
    ) -> Result<Self, RbcError> {
        Self::try_new_with_fields(
            authority,
            round,
            block_references,
            acknowledgment_references,
            meta_creation_time_ns,
            transactions_commitment,
            Some(starfish_rbc_v3),
        )
    }

    fn try_new_with_fields(
        authority: AuthorityIndex,
        round: RoundNumber,
        block_references: Vec<BlockReference>,
        acknowledgment_references: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        transactions_commitment: TransactionsCommitment,
        starfish_rbc_v3: Option<StarfishRbcFieldsV3>,
    ) -> Result<Self, RbcError> {
        for (field, count) in [
            ("parent", block_references.len()),
            ("acknowledgment", acknowledgment_references.len()),
        ] {
            if count > MAX_RBC_REFERENCES_PER_FIELD {
                return Err(RbcError::TooManyHeaderReferences {
                    field,
                    count,
                    maximum: MAX_RBC_REFERENCES_PER_FIELD,
                });
            }
        }
        let mut parent_set = AHashSet::new();
        for parent in &block_references {
            if !parent_set.insert(*parent) {
                return Err(RbcError::DuplicateParent(*parent));
            }
        }
        let mut acknowledgment_set = AHashSet::new();
        for acknowledgment in &acknowledgment_references {
            if !acknowledgment_set.insert(*acknowledgment) {
                return Err(RbcError::DuplicateAcknowledgment(*acknowledgment));
            }
        }

        let acknowledgments =
            RbcAckFields::from_logical(&block_references, &acknowledgment_references);
        let logical_acknowledgments = acknowledgments.logical(&block_references);
        let digest = match starfish_rbc_v3.as_ref() {
            Some(rbc) => BlockDigest::new_starfish_rbc_single_dag_header(
                authority,
                round,
                &block_references,
                &logical_acknowledgments,
                meta_creation_time_ns,
                transactions_commitment,
                rbc,
            ),
            None => BlockDigest::new_starfish_rbc_header(
                authority,
                round,
                &block_references,
                &logical_acknowledgments,
                meta_creation_time_ns,
                transactions_commitment,
            ),
        };
        let reference = BlockReference {
            authority,
            round,
            digest,
        };
        let header = Self {
            reference,
            block_references,
            acknowledgments,
            meta_creation_time_ns,
            transactions_commitment,
            starfish_rbc_v3,
        };
        if header.encoded_content_size(logical_acknowledgments.len())? > MAX_RBC_HEADER_CONTENT_SIZE
        {
            return Err(RbcError::HeaderContentTooLarge);
        }
        Ok(header)
    }

    pub(crate) fn from_block_header(header: &BlockHeader) -> Result<Self, RbcError> {
        if header.strong_vote.is_some()
            || header.bls.is_some()
            || header.sailfish.is_some()
            || header.unprovable_certificate.is_some()
        {
            return Err(RbcError::ForbiddenHeaderExtensions);
        }
        let Some(acknowledgments) = header.ack.as_ref() else {
            return Err(RbcError::MissingAcknowledgments);
        };
        let Some(transactions_commitment) = header.transactions_commitment else {
            return Err(RbcError::MissingTransactionsCommitment);
        };
        let parent_count = header.block_references.len();
        let extra_acknowledgment_count = acknowledgments.extra_references.len();
        for (field, count) in [
            ("parent", parent_count),
            ("acknowledgment", extra_acknowledgment_count),
        ] {
            if count > MAX_RBC_REFERENCES_PER_FIELD {
                return Err(RbcError::TooManyHeaderReferences {
                    field,
                    count,
                    maximum: MAX_RBC_REFERENCES_PER_FIELD,
                });
            }
        }
        let intersection_start = match acknowledgments.intersection {
            Some(start) if start as usize <= parent_count => start as usize,
            Some(_) => return Err(RbcError::NonCanonicalAcknowledgments),
            None => parent_count,
        };
        let logical_acknowledgment_count = parent_count
            .checked_sub(intersection_start)
            .and_then(|count| count.checked_add(extra_acknowledgment_count))
            .ok_or(RbcError::HeaderContentTooLarge)?;
        if logical_acknowledgment_count > MAX_RBC_REFERENCES_PER_FIELD {
            return Err(RbcError::TooManyHeaderReferences {
                field: "acknowledgment",
                count: logical_acknowledgment_count,
                maximum: MAX_RBC_REFERENCES_PER_FIELD,
            });
        }
        let reference_count = parent_count
            .checked_add(logical_acknowledgment_count)
            .and_then(|count| {
                count.checked_add(
                    header
                        .starfish_rbc_v3
                        .as_ref()
                        .map_or(0, |rbc| rbc.references().len()),
                )
            })
            .ok_or(RbcError::HeaderContentTooLarge)?;
        let encoded_size = RBC_BLOCK_REFERENCE_SIZE
            .checked_mul(reference_count)
            .and_then(|size| size.checked_add(RBC_HEADER_FIXED_CONTENT_SIZE))
            .ok_or(RbcError::HeaderContentTooLarge)?;
        if encoded_size > MAX_RBC_HEADER_CONTENT_SIZE {
            return Err(RbcError::HeaderContentTooLarge);
        }
        Ok(Self {
            reference: header.reference,
            block_references: header.block_references.clone(),
            acknowledgments: RbcAckFields {
                intersection: acknowledgments.intersection,
                extra_references: acknowledgments.extra_references.clone(),
            },
            meta_creation_time_ns: header.meta_creation_time_ns,
            transactions_commitment,
            starfish_rbc_v3: header.starfish_rbc_v3.clone(),
        })
    }

    pub fn reference(&self) -> BlockReference {
        self.reference
    }

    pub fn block_references(&self) -> &[BlockReference] {
        &self.block_references
    }

    pub fn acknowledgment_references(&self) -> Vec<BlockReference> {
        self.acknowledgments.logical(&self.block_references)
    }

    pub(crate) fn acknowledgment_fields(&self) -> AckFields {
        AckFields {
            intersection: self.acknowledgments.intersection,
            extra_references: self.acknowledgments.extra_references.clone(),
        }
    }

    pub fn meta_creation_time_ns(&self) -> TimestampNs {
        self.meta_creation_time_ns
    }

    pub fn transactions_commitment(&self) -> TransactionsCommitment {
        self.transactions_commitment
    }

    pub fn starfish_rbc_v3(&self) -> Option<&StarfishRbcFieldsV3> {
        self.starfish_rbc_v3.as_ref()
    }

    /// Validate canonical header content against an already validated static
    /// committee without deriving the committee identifier.
    ///
    /// This is the shared structural boundary for RBC INIT/recovery and for a
    /// later normal block-batch payload carrier. Global committee invariants
    /// are checked once when the RBC context is created; this per-header path
    /// touches only authorities referenced by the header.
    pub(crate) fn validate_for_committee(&self, committee: &Committee) -> Result<(), RbcError> {
        let block_ref = self.reference;
        if block_ref.round == 0 {
            return Err(RbcError::GenesisSlot);
        }
        if !committee.known_authority(block_ref.authority) {
            return Err(RbcError::UnknownAuthority(block_ref.authority));
        }
        if !self.acknowledgments.is_canonical(&self.block_references) {
            return Err(RbcError::NonCanonicalAcknowledgments);
        }

        let acknowledgments = self.acknowledgment_references();
        for (field, count) in [
            ("parent", self.block_references.len()),
            ("acknowledgment", acknowledgments.len()),
        ] {
            if count > MAX_RBC_REFERENCES_PER_FIELD {
                return Err(RbcError::TooManyHeaderReferences {
                    field,
                    count,
                    maximum: MAX_RBC_REFERENCES_PER_FIELD,
                });
            }
        }
        if self.encoded_content_size(acknowledgments.len())? > MAX_RBC_HEADER_CONTENT_SIZE {
            return Err(RbcError::HeaderContentTooLarge);
        }

        let mut parent_set = AHashSet::new();
        let mut previous_round_parents = StakeAggregator::<QuorumThreshold>::new();
        for parent in &self.block_references {
            if !committee.known_authority(parent.authority) {
                return Err(RbcError::UnknownAuthority(parent.authority));
            }
            if parent.round >= block_ref.round {
                return Err(RbcError::ParentNotPast(*parent));
            }
            if !parent_set.insert(*parent) {
                return Err(RbcError::DuplicateParent(*parent));
            }
            if parent.round + 1 == block_ref.round {
                previous_round_parents.add(parent.authority, committee);
            }
        }
        if !previous_round_parents.is_quorum(committee) {
            return Err(RbcError::InvalidThresholdClock);
        }

        let mut acknowledgment_set = AHashSet::new();
        for acknowledgment in &acknowledgments {
            if !committee.known_authority(acknowledgment.authority) {
                return Err(RbcError::UnknownAuthority(acknowledgment.authority));
            }
            if acknowledgment.round > block_ref.round {
                return Err(RbcError::AcknowledgmentFromFuture(*acknowledgment));
            }
            if !acknowledgment_set.insert(*acknowledgment) {
                return Err(RbcError::DuplicateAcknowledgment(*acknowledgment));
            }
        }

        if self
            .starfish_rbc_v3
            .as_ref()
            .is_some_and(|rbc| !rbc.validate_for_block(committee, block_ref.round))
        {
            return Err(RbcError::InvalidSingleDagEvidence);
        }
        let expected_digest = match self.starfish_rbc_v3.as_ref() {
            Some(rbc) => BlockDigest::new_starfish_rbc_single_dag_header(
                block_ref.authority,
                block_ref.round,
                &self.block_references,
                &acknowledgments,
                self.meta_creation_time_ns,
                self.transactions_commitment,
                rbc,
            ),
            None => BlockDigest::new_starfish_rbc_header(
                block_ref.authority,
                block_ref.round,
                &self.block_references,
                &acknowledgments,
                self.meta_creation_time_ns,
                self.transactions_commitment,
            ),
        };
        if expected_digest != block_ref.digest {
            return Err(RbcError::HeaderDigestMismatch {
                expected: expected_digest,
                actual: block_ref.digest,
            });
        }
        Ok(())
    }

    /// Convert canonical content into the existing header-only carrier. RBC
    /// authorization remains external, so the compatibility header contains
    /// no signature or MAC sidecar.
    pub(crate) fn to_authentication_free_block(&self) -> VerifiedBlock {
        VerifiedBlock::from_parts(
            BlockHeader {
                reference: self.reference,
                block_references: self.block_references.clone(),
                meta_creation_time_ns: self.meta_creation_time_ns,
                authentication: BlockAuthentication::None,
                transactions_commitment: Some(self.transactions_commitment),
                ack: Some(self.acknowledgment_fields()),
                strong_vote: None,
                bls: None,
                sailfish: None,
                unprovable_certificate: None,
                starfish_rbc_v3: self.starfish_rbc_v3.clone(),
                serialized: None,
            },
            None,
        )
    }

    fn encoded_content_size(&self, acknowledgment_count: usize) -> Result<usize, RbcError> {
        let reference_count = self
            .block_references
            .len()
            .checked_add(acknowledgment_count)
            .and_then(|count| {
                count.checked_add(
                    self.starfish_rbc_v3
                        .as_ref()
                        .map_or(0, |rbc| rbc.references().len()),
                )
            })
            .ok_or(RbcError::HeaderContentTooLarge)?;
        RBC_BLOCK_REFERENCE_SIZE
            .checked_mul(reference_count)
            .and_then(|size| size.checked_add(RBC_HEADER_FIXED_CONTENT_SIZE))
            .ok_or(RbcError::HeaderContentTooLarge)
    }
}

/// An intrinsically validated header retained by `Arc` for as long as the RBC
/// state may advertise this validator as a holder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PinnedRbcHeader {
    header: Arc<RbcCanonicalHeader>,
    committee_id: RbcCommitteeId,
}

impl PinnedRbcHeader {
    fn validate_with_committee_id(
        header: RbcCanonicalHeader,
        committee: &Committee,
        committee_id: RbcCommitteeId,
    ) -> Result<Self, RbcError> {
        header.validate_for_committee(committee)?;
        Ok(Self {
            header: Arc::new(header),
            committee_id,
        })
    }

    #[cfg(test)]
    fn validate(header: RbcCanonicalHeader, committee: &Committee) -> Result<Self, RbcError> {
        validate_committee(committee)?;
        let committee_id = RbcCommitteeId::derive(committee)?;
        Self::validate_with_committee_id(header, committee, committee_id)
    }

    pub(crate) fn reference(&self) -> BlockReference {
        self.header.reference
    }

    pub(crate) fn header(&self) -> &RbcCanonicalHeader {
        &self.header
    }

    fn ensure_committee(&self, expected: RbcCommitteeId) -> Result<(), RbcError> {
        if self.committee_id != expected {
            return Err(RbcError::PinnedHeaderCommitteeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RbcInitialProof {
    Ed25519(SignatureBytes),
    MlDsa44(MlDsa44SignatureBytes),
    MlDsa65(MlDsa65SignatureBytes),
    Mac(MacTag),
}

/// Direct-author Starfish-RBC header proposal carried on the wire.
///
/// The proof is a sidecar over the canonical header reference. It is not part
/// of the content-addressed header identity.
#[derive(Clone, Serialize, Deserialize)]
pub struct RbcHeaderProposal {
    header: RbcCanonicalHeader,
    proof: RbcInitialProof,
    transaction_data: Option<Arc<TransactionData>>,
}

impl RbcHeaderProposal {
    #[cfg(test)]
    pub(crate) fn new(header: RbcCanonicalHeader, proof: RbcInitialProof) -> Self {
        Self {
            header,
            proof,
            transaction_data: None,
        }
    }

    pub(crate) fn with_transaction_data(
        header: RbcCanonicalHeader,
        proof: RbcInitialProof,
        transaction_data: Option<Arc<TransactionData>>,
    ) -> Self {
        Self {
            header,
            proof,
            transaction_data,
        }
    }

    pub fn header(&self) -> &RbcCanonicalHeader {
        &self.header
    }

    pub fn proof(&self) -> &RbcInitialProof {
        &self.proof
    }

    #[cfg(test)]
    pub(crate) fn transaction_data(&self) -> Option<&TransactionData> {
        self.transaction_data.as_deref()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        RbcCanonicalHeader,
        RbcInitialProof,
        Option<Arc<TransactionData>>,
    ) {
        (self.header, self.proof, self.transaction_data)
    }
}

impl fmt::Debug for RbcHeaderProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RbcHeaderProposal")
            .field("header", &self.header)
            .field("proof", &self.proof)
            .field(
                "transaction_count",
                &self
                    .transaction_data
                    .as_ref()
                    .map(|data| data.number_transactions()),
            )
            .finish()
    }
}

impl RbcInitialProof {
    #[allow(dead_code)]
    pub(crate) fn from_block_authentication(
        authentication: &BlockAuthentication,
    ) -> Result<Self, RbcError> {
        match authentication {
            BlockAuthentication::Ed25519(signature) => Ok(Self::Ed25519(*signature)),
            BlockAuthentication::MlDsa44(signature) => Ok(Self::MlDsa44(signature.clone())),
            BlockAuthentication::MlDsa65(signature) => Ok(Self::MlDsa65(signature.clone())),
            BlockAuthentication::MacTag(tag) => Ok(Self::Mac(*tag)),
            BlockAuthentication::None | BlockAuthentication::MacVector(_) => {
                Err(RbcError::InvalidInitialProof)
            }
        }
    }
}

/// Capability proving that the pinned header had a valid local-construction
/// path or a direct-author initial proof. Only this type can authorize ECHO.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct EchoEligibleHeader {
    header: PinnedRbcHeader,
    context: RbcContext,
    recipient: AuthorityIndex,
}

#[derive(Debug)]
#[must_use]
pub(crate) struct RbcLocalInitial {
    header: PinnedRbcHeader,
    effects: Vec<RbcEffect>,
    context: RbcContext,
    author: AuthorityIndex,
}

impl RbcLocalInitial {
    pub(crate) fn header(&self) -> &RbcCanonicalHeader {
        self.header.header()
    }

    pub(crate) fn into_parts(self) -> (PinnedRbcHeader, Vec<RbcEffect>) {
        (self.header, self.effects)
    }
}

#[derive(Debug)]
#[must_use]
pub(crate) enum RbcInitialHeaderOutcome {
    Authenticated {
        effects: Vec<RbcEffect>,
    },
    StagedUnauthenticated {
        effects: Vec<RbcEffect>,
        error: RbcError,
    },
}

#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct RbcProtocolInstanceId([u8; PROTOCOL_INSTANCE_SIZE]);

impl RbcProtocolInstanceId {
    pub(crate) fn new(bytes: [u8; PROTOCOL_INSTANCE_SIZE]) -> Result<Self, RbcError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RbcError::ZeroProtocolInstance);
        }
        Ok(Self(bytes))
    }
}

impl<'de> Deserialize<'de> for RbcProtocolInstanceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; PROTOCOL_INSTANCE_SIZE]>::deserialize(deserializer)?;
        Self::new(bytes).map_err(de::Error::custom)
    }
}

impl fmt::Debug for RbcProtocolInstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RbcInstance({})", hex::encode(&self.0[..4]))
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct RbcCommitteeId([u8; COMMITTEE_ID_SIZE]);

impl RbcCommitteeId {
    fn derive(committee: &Committee) -> Result<Self, RbcError> {
        if committee.len() > MAX_COMMITTEE_SIZE as usize {
            return Err(RbcError::CommitteeTooLarge(committee.len()));
        }
        let committee_size = u16::try_from(committee.len())
            .map_err(|_| RbcError::CommitteeTooLarge(committee.len()))?;
        let info_length = u16::try_from(committee.info_length())
            .map_err(|_| RbcError::InvalidInfoLength(committee.info_length()))?;

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
                .ok_or(RbcError::UnknownAuthority(authority))?;
            let public_key = committee
                .get_public_key(authority)
                .ok_or(RbcError::UnknownAuthority(authority))?;
            let bls_public_key = committee
                .get_bls_public_key(authority)
                .ok_or(RbcError::UnknownAuthority(authority))?;
            let ml_dsa_44_public_key = committee
                .get_ml_dsa_44_public_key(authority)
                .ok_or(RbcError::UnknownAuthority(authority))?;
            let ml_dsa_65_public_key = committee
                .get_ml_dsa_65_public_key(authority)
                .ok_or(RbcError::UnknownAuthority(authority))?;

            hasher.update(&authority.to_be_bytes());
            hasher.update(&stake.to_be_bytes());
            hasher.update(&public_key.to_bytes());
            hasher.update(&bls_public_key.to_bytes());
            hasher.update(&ml_dsa_44_public_key.to_bytes());
            hasher.update(&ml_dsa_65_public_key.to_bytes());
        }

        Ok(Self(hasher.finalize().into()))
    }
}

impl fmt::Debug for RbcCommitteeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RbcCommittee({})", hex::encode(&self.0[..4]))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RbcContext {
    protocol_instance: RbcProtocolInstanceId,
    committee_id: RbcCommitteeId,
    initial_authentication: BlockAuthenticationScheme,
}

impl RbcContext {
    fn new(
        protocol_instance: RbcProtocolInstanceId,
        committee: &Committee,
        initial_authentication: BlockAuthenticationScheme,
    ) -> Result<Self, RbcError> {
        validate_committee(committee)?;
        Ok(Self {
            protocol_instance,
            committee_id: RbcCommitteeId::derive(committee)?,
            initial_authentication,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum RbcPhase {
    Echo,
    Ready,
}

impl RbcPhase {
    fn statement_kind(self) -> u8 {
        match self {
            Self::Echo => ECHO_KIND,
            Self::Ready => READY_KIND,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RbcPhaseMessage {
    block_ref: BlockReference,
    sender: AuthorityIndex,
    recipient: AuthorityIndex,
    phase: RbcPhase,
    tag: MacTag,
}

impl RbcPhaseMessage {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        block_ref: BlockReference,
        sender: AuthorityIndex,
        recipient: AuthorityIndex,
        phase: RbcPhase,
        tag: MacTag,
    ) -> Self {
        Self {
            block_ref,
            sender,
            recipient,
            phase,
            tag,
        }
    }

    pub fn block_ref(&self) -> BlockReference {
        self.block_ref
    }

    pub fn sender(&self) -> AuthorityIndex {
        self.sender
    }

    pub fn recipient(&self) -> AuthorityIndex {
        self.recipient
    }

    pub fn phase(&self) -> RbcPhase {
        self.phase
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RbcEffect {
    /// The network adapter must specialize this intent for each recipient by
    /// calling `make_phase_message`; no tagged message may be cloned.
    MulticastPhase {
        phase: RbcPhase,
        block_ref: BlockReference,
    },
    NeedHeader {
        block_ref: BlockReference,
        holders: AuthoritySet,
    },
    Deliver(PinnedRbcHeader),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RbcError {
    EmptyCommittee,
    CommitteeTooLarge(usize),
    InvalidInfoLength(usize),
    InvalidCommitteeStake(AuthorityIndex),
    TotalStakeOverflow,
    InvalidValidityThreshold {
        expected: Stake,
        actual: Stake,
    },
    InvalidQuorumThreshold {
        expected: Stake,
        actual: Stake,
    },
    InvalidDerivedInfoLength {
        expected: usize,
        actual: usize,
    },
    ZeroProtocolInstance,
    InvalidKeyringLength {
        expected: usize,
        actual: usize,
    },
    UnknownAuthority(AuthorityIndex),
    GenesisSlot,
    FutureRound {
        round: RoundNumber,
        maximum: RoundNumber,
    },
    StaleRound {
        round: RoundNumber,
        minimum: RoundNumber,
    },
    RoundRegression {
        current: RoundNumber,
        proposed: RoundNumber,
    },
    #[allow(dead_code)]
    RetainedRoundRegression {
        current: RoundNumber,
        proposed: RoundNumber,
    },
    #[allow(dead_code)]
    RetainedRoundAheadOfLocal {
        local: RoundNumber,
        proposed: RoundNumber,
    },
    MissingAcknowledgments,
    NonCanonicalAcknowledgments,
    MissingTransactionsCommitment,
    ForbiddenHeaderExtensions,
    TooManyHeaderReferences {
        field: &'static str,
        count: usize,
        maximum: usize,
    },
    HeaderContentTooLarge,
    ParentNotPast(BlockReference),
    DuplicateParent(BlockReference),
    AcknowledgmentFromFuture(BlockReference),
    DuplicateAcknowledgment(BlockReference),
    InvalidThresholdClock,
    InvalidSingleDagEvidence,
    HeaderDigestMismatch {
        expected: BlockDigest,
        actual: BlockDigest,
    },
    PinnedHeaderCommitteeMismatch,
    EchoCapabilityContextMismatch,
    LocalInitialContextMismatch,
    LocalInitialNotSelected(BlockReference),
    ConflictingHeaderContent(BlockReference),
    ConflictingInitialHeader {
        existing: BlockReference,
        received: BlockReference,
    },
    UnexpectedRecoveredHeader(BlockReference),
    HeaderUnavailable(BlockReference),
    WrongRecipient {
        expected: AuthorityIndex,
        actual: AuthorityIndex,
    },
    SenderPeerMismatch {
        sender: AuthorityIndex,
        peer: AuthorityIndex,
    },
    PhaseNotAuthorized {
        phase: RbcPhase,
        block_ref: BlockReference,
    },
    LoopbackPhase,
    InvalidPhaseTag,
    InvalidInitialTag,
    InvalidInitialProof,
    InitialProofSchemeMismatch,
    InitialSignatureRequiresSignatureAuthentication,
    InitialMacRequiresMacAuthentication,
    InitialAuthorMismatch {
        expected: AuthorityIndex,
        actual: AuthorityIndex,
    },
}

impl fmt::Display for RbcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommittee => f.write_str("Starfish-RBC committee is empty"),
            Self::CommitteeTooLarge(size) => {
                write!(f, "Starfish-RBC committee is too large: {size}")
            }
            Self::InvalidInfoLength(length) => {
                write!(
                    f,
                    "Starfish-RBC information length is out of range: {length}"
                )
            }
            Self::InvalidCommitteeStake(authority) => {
                write!(f, "Starfish-RBC authority {authority} has invalid stake")
            }
            Self::TotalStakeOverflow => f.write_str("Starfish-RBC total stake overflow"),
            Self::InvalidValidityThreshold { expected, actual } => write!(
                f,
                "Starfish-RBC validity threshold mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidQuorumThreshold { expected, actual } => write!(
                f,
                "Starfish-RBC quorum threshold mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidDerivedInfoLength { expected, actual } => write!(
                f,
                "Starfish-RBC information length mismatch: expected {expected}, got {actual}"
            ),
            Self::ZeroProtocolInstance => {
                f.write_str("Starfish-RBC protocol instance must not be all zeroes")
            }
            Self::InvalidKeyringLength { expected, actual } => write!(
                f,
                "Starfish-RBC keyring length mismatch: expected {expected}, got {actual}"
            ),
            Self::UnknownAuthority(authority) => {
                write!(f, "unknown Starfish-RBC authority {authority}")
            }
            Self::GenesisSlot => f.write_str("Starfish-RBC does not certify genesis slots"),
            Self::FutureRound { round, maximum } => write!(
                f,
                "Starfish-RBC round {round} exceeds admission maximum {maximum}"
            ),
            Self::StaleRound { round, minimum } => write!(
                f,
                "Starfish-RBC round {round} is below admission minimum {minimum}"
            ),
            Self::RoundRegression { current, proposed } => write!(
                f,
                "Starfish-RBC local round cannot regress from {current} to {proposed}"
            ),
            Self::RetainedRoundRegression { current, proposed } => write!(
                f,
                "Starfish-RBC retained-round floor cannot regress from {current} to {proposed}"
            ),
            Self::RetainedRoundAheadOfLocal { local, proposed } => write!(
                f,
                "Starfish-RBC retained-round floor {proposed} exceeds local round {local}"
            ),
            Self::MissingAcknowledgments => {
                f.write_str("Starfish-RBC header is missing acknowledgment fields")
            }
            Self::NonCanonicalAcknowledgments => {
                f.write_str("Starfish-RBC acknowledgment encoding is not canonical")
            }
            Self::MissingTransactionsCommitment => {
                f.write_str("Starfish-RBC header is missing its transaction commitment")
            }
            Self::ForbiddenHeaderExtensions => {
                f.write_str("Starfish-RBC header carries a forbidden protocol extension")
            }
            Self::TooManyHeaderReferences {
                field,
                count,
                maximum,
            } => write!(
                f,
                "Starfish-RBC {field} reference count {count} exceeds limit {maximum}"
            ),
            Self::HeaderContentTooLarge => f.write_str("Starfish-RBC header content is too large"),
            Self::ParentNotPast(parent) => {
                write!(f, "Starfish-RBC parent {parent} is not from a past round")
            }
            Self::DuplicateParent(parent) => {
                write!(f, "Starfish-RBC parent {parent} is duplicated")
            }
            Self::AcknowledgmentFromFuture(acknowledgment) => write!(
                f,
                "Starfish-RBC acknowledgment {acknowledgment} is from a future round"
            ),
            Self::DuplicateAcknowledgment(acknowledgment) => write!(
                f,
                "Starfish-RBC acknowledgment {acknowledgment} is duplicated"
            ),
            Self::InvalidThresholdClock => {
                f.write_str("Starfish-RBC header does not reference previous-round quorum stake")
            }
            Self::InvalidSingleDagEvidence => {
                f.write_str("Starfish-RBC V3 block carries non-canonical reference evidence")
            }
            Self::HeaderDigestMismatch { expected, actual } => write!(
                f,
                "Starfish-RBC header digest mismatch: expected {expected}, got {actual}"
            ),
            Self::PinnedHeaderCommitteeMismatch => {
                f.write_str("Starfish-RBC pinned header belongs to a different committee")
            }
            Self::EchoCapabilityContextMismatch => f.write_str(
                "Starfish-RBC ECHO capability belongs to a different context or recipient",
            ),
            Self::LocalInitialContextMismatch => {
                f.write_str("Starfish-RBC local initial handle belongs to a different kernel")
            }
            Self::LocalInitialNotSelected(block_ref) => write!(
                f,
                "Starfish-RBC local initial header {block_ref} is not the selected pinned proposal"
            ),
            Self::ConflictingHeaderContent(block_ref) => write!(
                f,
                "Starfish-RBC received conflicting pinned content for {block_ref}"
            ),
            Self::ConflictingInitialHeader { existing, received } => write!(
                f,
                "Starfish-RBC slot already staged initial header {existing}, not {received}"
            ),
            Self::UnexpectedRecoveredHeader(block_ref) => write!(
                f,
                "Starfish-RBC recovered header {block_ref} has no retained candidate"
            ),
            Self::HeaderUnavailable(block_ref) => {
                write!(
                    f,
                    "Starfish-RBC header {block_ref} is not locally available"
                )
            }
            Self::WrongRecipient { expected, actual } => write!(
                f,
                "Starfish-RBC message recipient mismatch: expected {expected}, got {actual}"
            ),
            Self::SenderPeerMismatch { sender, peer } => write!(
                f,
                "Starfish-RBC message sender {sender} does not match direct peer {peer}"
            ),
            Self::PhaseNotAuthorized { phase, block_ref } => write!(
                f,
                "Starfish-RBC {phase:?} was not authorized for {block_ref}"
            ),
            Self::LoopbackPhase => {
                f.write_str("Starfish-RBC loopback phase messages are not accepted")
            }
            Self::InvalidPhaseTag => f.write_str("Starfish-RBC phase MAC verification failed"),
            Self::InvalidInitialTag => f.write_str("Starfish-RBC initial MAC verification failed"),
            Self::InvalidInitialProof => {
                f.write_str("Starfish-RBC initial proof verification failed")
            }
            Self::InitialProofSchemeMismatch => {
                f.write_str("Starfish-RBC initial proof has the wrong authentication scheme")
            }
            Self::InitialSignatureRequiresSignatureAuthentication => f.write_str(
                "Starfish-RBC initial signature digest requires a signature authentication mode",
            ),
            Self::InitialMacRequiresMacAuthentication => {
                f.write_str("Starfish-RBC initial MAC requires MAC authentication mode")
            }
            Self::InitialAuthorMismatch { expected, actual } => write!(
                f,
                "Starfish-RBC initial author mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl Error for RbcError {}

struct CandidateState {
    header: Option<PinnedRbcHeader>,
    echoes: StakeAggregator<QuorumThreshold>,
    readies: StakeAggregator<ValidityThreshold>,
    echo_quorum_observed: bool,
    ready_validity_observed: bool,
    ready_quorum_observed: bool,
    header_request_holders: AuthoritySet,
}

impl CandidateState {
    fn new() -> Self {
        Self {
            header: None,
            echoes: StakeAggregator::new(),
            readies: StakeAggregator::new(),
            echo_quorum_observed: false,
            ready_validity_observed: false,
            ready_quorum_observed: false,
            header_request_holders: AuthoritySet::default(),
        }
    }

    fn latch_thresholds(&mut self, validity_threshold: Stake, quorum_threshold: Stake) {
        self.echo_quorum_observed |= self.echoes.get_stake() >= quorum_threshold;
        self.ready_validity_observed |= self.readies.get_stake() >= validity_threshold;
        self.ready_quorum_observed |= self.readies.get_stake() >= quorum_threshold;
    }

    fn holders(&self) -> AuthoritySet {
        self.echoes.votes | self.readies.votes
    }
}

struct SlotState {
    echoed: Option<BlockReference>,
    readied: Option<BlockReference>,
    delivered: Option<BlockReference>,
    initial_candidate: Option<BlockReference>,
    echo_by_sender: AHashMap<AuthorityIndex, BlockReference>,
    ready_by_sender: AHashMap<AuthorityIndex, BlockReference>,
    candidates: AHashMap<BlockReference, CandidateState>,
}

impl Default for SlotState {
    fn default() -> Self {
        Self {
            echoed: None,
            readied: None,
            delivered: None,
            initial_candidate: None,
            echo_by_sender: AHashMap::new(),
            ready_by_sender: AHashMap::new(),
            candidates: AHashMap::new(),
        }
    }
}

impl SlotState {
    fn record_phase_sender(
        &mut self,
        phase: RbcPhase,
        sender: AuthorityIndex,
        block_ref: BlockReference,
    ) -> bool {
        let seen = match phase {
            RbcPhase::Echo => &mut self.echo_by_sender,
            RbcPhase::Ready => &mut self.ready_by_sender,
        };
        match seen.get(&sender) {
            Some(existing) => *existing == block_ref,
            None => {
                seen.insert(sender, block_ref);
                true
            }
        }
    }
}

enum ProgressAction {
    NeedHeader(AuthoritySet),
    SendReady,
    Deliver,
    None,
}

pub(crate) struct StarfishRbcKernel {
    committee: Arc<Committee>,
    own_authority: AuthorityIndex,
    context: RbcContext,
    mac_keys: Arc<Vec<MacKey>>,
    local_round: RoundNumber,
    minimum_new_slot_round: RoundNumber,
    /// Testbed-only optimistic path. A quorum of locked ECHOs proves a unique
    /// value, but without a portable proof it does not prove that every honest
    /// node can assemble the same quorum under selective Byzantine
    /// withholding. Keep disabled for the asynchronous RBC contract.
    echo_qc_fast_path: bool,
    slots: BTreeMap<RoundNumber, AHashMap<AuthorityIndex, SlotState>>,
}

impl StarfishRbcKernel {
    #[allow(dead_code)]
    pub(crate) fn new(
        committee: Arc<Committee>,
        own_authority: AuthorityIndex,
        protocol_instance: RbcProtocolInstanceId,
        initial_authentication: BlockAuthenticationScheme,
        mac_keys: Arc<Vec<MacKey>>,
        local_round: RoundNumber,
    ) -> Result<Self, RbcError> {
        Self::new_with_echo_qc_fast_path(
            committee,
            own_authority,
            protocol_instance,
            initial_authentication,
            mac_keys,
            local_round,
            false,
        )
    }

    pub(crate) fn new_with_echo_qc_fast_path(
        committee: Arc<Committee>,
        own_authority: AuthorityIndex,
        protocol_instance: RbcProtocolInstanceId,
        initial_authentication: BlockAuthenticationScheme,
        mac_keys: Arc<Vec<MacKey>>,
        local_round: RoundNumber,
        echo_qc_fast_path: bool,
    ) -> Result<Self, RbcError> {
        let context = RbcContext::new(protocol_instance, &committee, initial_authentication)?;
        if !committee.known_authority(own_authority) {
            return Err(RbcError::UnknownAuthority(own_authority));
        }
        if mac_keys.len() != committee.len() {
            return Err(RbcError::InvalidKeyringLength {
                expected: committee.len(),
                actual: mac_keys.len(),
            });
        }
        Ok(Self {
            committee,
            own_authority,
            context,
            mac_keys,
            local_round,
            minimum_new_slot_round: 1,
            echo_qc_fast_path,
            slots: BTreeMap::new(),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn context(&self) -> RbcContext {
        self.context
    }

    pub(crate) fn maximum_admissible_round(&self) -> RoundNumber {
        self.local_round.saturating_add(MAX_RBC_FUTURE_ROUNDS)
    }

    pub(crate) fn advance_local_round(&mut self, round: RoundNumber) -> Result<(), RbcError> {
        if round < self.local_round {
            return Err(RbcError::RoundRegression {
                current: self.local_round,
                proposed: round,
            });
        }
        self.local_round = round;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn minimum_new_slot_round(&self) -> RoundNumber {
        self.minimum_new_slot_round
    }

    /// Reject allocation of previously unseen slots below a monotonic safe
    /// watermark. Advancing the DAG round is not sufficient evidence for this
    /// call: the integration layer may advance it only when its recovery model
    /// proves that no newly observed slot below `round` is still required.
    /// Existing slots remain active so late evidence can complete totality.
    #[allow(dead_code)]
    pub(crate) fn close_new_slots_before(&mut self, round: RoundNumber) -> Result<(), RbcError> {
        if round < self.minimum_new_slot_round {
            return Err(RbcError::RetainedRoundRegression {
                current: self.minimum_new_slot_round,
                proposed: round,
            });
        }
        let local_boundary = RoundNumber::max(self.local_round, 1);
        if round > local_boundary {
            return Err(RbcError::RetainedRoundAheadOfLocal {
                local: self.local_round,
                proposed: round,
            });
        }
        self.minimum_new_slot_round = round;
        Ok(())
    }

    pub(crate) fn validate_header_content(
        &self,
        header: RbcCanonicalHeader,
    ) -> Result<PinnedRbcHeader, RbcError> {
        self.validate_block_ref(&header.reference())?;
        PinnedRbcHeader::validate_with_committee_id(
            header,
            &self.committee,
            self.context.committee_id,
        )
    }

    fn direct_initial_header(
        &self,
        direct_peer: AuthorityIndex,
        header: PinnedRbcHeader,
        proof: &RbcInitialProof,
    ) -> Result<EchoEligibleHeader, RbcError> {
        header.ensure_committee(self.context.committee_id)?;
        let block_ref = header.reference();
        self.validate_block_ref(&block_ref)?;
        if direct_peer != block_ref.authority {
            return Err(RbcError::InitialAuthorMismatch {
                expected: block_ref.authority,
                actual: direct_peer,
            });
        }
        if direct_peer == self.own_authority {
            return Err(RbcError::LoopbackPhase);
        }

        match (self.context.initial_authentication, proof) {
            (BlockAuthenticationScheme::Ed25519, RbcInitialProof::Ed25519(signature)) => {
                let digest = self.initial_signature_digest(block_ref)?;
                let public_key = self
                    .committee
                    .get_public_key(block_ref.authority)
                    .ok_or(RbcError::UnknownAuthority(block_ref.authority))?;
                public_key
                    .verify_digest_signature(&digest, signature)
                    .map_err(|_| RbcError::InvalidInitialProof)?;
            }
            (BlockAuthenticationScheme::MlDsa44, RbcInitialProof::MlDsa44(signature)) => {
                let digest = BlockDigest::from(self.initial_signature_digest(block_ref)?);
                let public_key = self
                    .committee
                    .get_ml_dsa_44_public_key(block_ref.authority)
                    .ok_or(RbcError::UnknownAuthority(block_ref.authority))?;
                public_key
                    .verify_digest_signature(&digest, signature)
                    .map_err(|_| RbcError::InvalidInitialProof)?;
            }
            (BlockAuthenticationScheme::MlDsa65, RbcInitialProof::MlDsa65(signature)) => {
                let digest = BlockDigest::from(self.initial_signature_digest(block_ref)?);
                let public_key = self
                    .committee
                    .get_ml_dsa_65_public_key(block_ref.authority)
                    .ok_or(RbcError::UnknownAuthority(block_ref.authority))?;
                public_key
                    .verify_digest_signature(&digest, signature)
                    .map_err(|_| RbcError::InvalidInitialProof)?;
            }
            (BlockAuthenticationScheme::MacVector, RbcInitialProof::Mac(tag)) => {
                self.verify_initial_mac_tag(direct_peer, block_ref, tag)?;
            }
            _ => return Err(RbcError::InitialProofSchemeMismatch),
        }
        Ok(EchoEligibleHeader {
            header,
            context: self.context,
            recipient: self.own_authority,
        })
    }

    fn local_initial_header(
        &self,
        header: PinnedRbcHeader,
    ) -> Result<EchoEligibleHeader, RbcError> {
        header.ensure_committee(self.context.committee_id)?;
        let block_ref = header.reference();
        self.validate_block_ref(&block_ref)?;
        if block_ref.authority != self.own_authority {
            return Err(RbcError::InitialAuthorMismatch {
                expected: self.own_authority,
                actual: block_ref.authority,
            });
        }
        Ok(EchoEligibleHeader {
            header,
            context: self.context,
            recipient: self.own_authority,
        })
    }

    /// Atomically construct, validate, select, pin, and ECHO a local-author
    /// proposal before exposing it for authentication or dissemination. The
    /// caller supplies no author or digest and cannot obtain two conflicting
    /// local handles for one slot.
    pub(crate) fn start_local_initial_header(
        &mut self,
        round: RoundNumber,
        block_references: Vec<BlockReference>,
        acknowledgment_references: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        transactions_commitment: TransactionsCommitment,
    ) -> Result<RbcLocalInitial, RbcError> {
        self.start_local_initial_header_with_fields(
            round,
            block_references,
            acknowledgment_references,
            meta_creation_time_ns,
            transactions_commitment,
            None,
        )
    }

    pub(crate) fn start_local_initial_header_with_fields(
        &mut self,
        round: RoundNumber,
        block_references: Vec<BlockReference>,
        acknowledgment_references: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        transactions_commitment: TransactionsCommitment,
        starfish_rbc_v3: Option<StarfishRbcFieldsV3>,
    ) -> Result<RbcLocalInitial, RbcError> {
        let canonical = match starfish_rbc_v3 {
            Some(rbc) => RbcCanonicalHeader::try_new_single_dag(
                self.own_authority,
                round,
                block_references,
                acknowledgment_references,
                meta_creation_time_ns,
                transactions_commitment,
                rbc,
            ),
            None => RbcCanonicalHeader::try_new(
                self.own_authority,
                round,
                block_references,
                acknowledgment_references,
                meta_creation_time_ns,
                transactions_commitment,
            ),
        }?;
        let pinned = self.validate_header_content(canonical)?;
        let eligible = self.local_initial_header(pinned.clone())?;
        let effects = self.accept_initial_header(eligible)?;
        Ok(RbcLocalInitial {
            header: pinned,
            effects,
            context: self.context,
            author: self.own_authority,
        })
    }

    fn accept_initial_header(
        &mut self,
        eligible: EchoEligibleHeader,
    ) -> Result<Vec<RbcEffect>, RbcError> {
        if eligible.context != self.context || eligible.recipient != self.own_authority {
            return Err(RbcError::EchoCapabilityContextMismatch);
        }
        eligible
            .header
            .ensure_committee(self.context.committee_id)?;
        let block_ref = eligible.header.reference();
        self.record_initial_candidate(block_ref)?;
        let mut effects = self.note_header_available(eligible.header)?;
        effects.extend(self.authorize_echo(block_ref)?);
        Ok(effects)
    }

    /// Validate and stage a directly received proposal before checking its
    /// receiver-specific proof. Invalid authentication therefore cannot make
    /// the adapter accidentally discard content needed by later READY
    /// recovery. The outcome preserves any effects unblocked by staging.
    pub(crate) fn accept_direct_initial_header(
        &mut self,
        direct_peer: AuthorityIndex,
        header: RbcCanonicalHeader,
        proof: &RbcInitialProof,
    ) -> Result<RbcInitialHeaderOutcome, RbcError> {
        let pinned = self.validate_header_content(header)?;
        let block_ref = pinned.reference();
        if direct_peer != block_ref.authority {
            return Err(RbcError::InitialAuthorMismatch {
                expected: block_ref.authority,
                actual: direct_peer,
            });
        }
        if direct_peer == self.own_authority {
            return Err(RbcError::LoopbackPhase);
        }
        self.record_initial_candidate(block_ref)?;
        let mut effects = self.note_header_available(pinned.clone())?;
        match self.direct_initial_header(direct_peer, pinned, proof) {
            Ok(eligible) => {
                effects.extend(self.accept_initial_header(eligible)?);
                Ok(RbcInitialHeaderOutcome::Authenticated { effects })
            }
            Err(error) => Ok(RbcInitialHeaderOutcome::StagedUnauthenticated { effects, error }),
        }
    }

    pub(crate) fn accept_recovered_header(
        &mut self,
        header: RbcCanonicalHeader,
    ) -> Result<Vec<RbcEffect>, RbcError> {
        let pinned = self.validate_header_content(header)?;
        let block_ref = pinned.reference();
        self.validate_block_ref(&block_ref)?;
        if self.candidate(&block_ref).is_none() {
            return Err(RbcError::UnexpectedRecoveredHeader(block_ref));
        }
        self.note_header_available(pinned)
    }

    /// Record a pinned, deterministically content-validated header. This does
    /// not authorize ECHO and does not imply initial authentication. External
    /// ingress uses `accept_recovered_header` or an echo-eligible capability.
    fn note_header_available(
        &mut self,
        header: PinnedRbcHeader,
    ) -> Result<Vec<RbcEffect>, RbcError> {
        header.ensure_committee(self.context.committee_id)?;
        let block_ref = header.reference();
        self.validate_block_ref(&block_ref)?;
        let candidate = self.candidate_mut(block_ref);
        if candidate
            .header
            .as_ref()
            .is_some_and(|existing| existing != &header)
        {
            return Err(RbcError::ConflictingHeaderContent(block_ref));
        }
        candidate.header = Some(header);
        Ok(self.drive(block_ref))
    }

    /// Complete the one local ECHO transition after the typed capability gate.
    /// This lower-level method remains module-private so call ordering cannot
    /// substitute for a direct-author proof or local-creation capability.
    fn authorize_echo(&mut self, block_ref: BlockReference) -> Result<Vec<RbcEffect>, RbcError> {
        self.validate_block_ref(&block_ref)?;
        let header_available = self
            .candidate(&block_ref)
            .is_some_and(|candidate| candidate.header.is_some());
        if !header_available {
            return Err(RbcError::HeaderUnavailable(block_ref));
        }

        let own_authority = self.own_authority;
        let committee = Arc::clone(&self.committee);
        let slot = self.slot_mut(block_ref);
        if slot.echoed.is_some() {
            return Ok(Vec::new());
        }
        slot.echoed = Some(block_ref);
        let recorded = slot.record_phase_sender(RbcPhase::Echo, own_authority, block_ref);
        debug_assert!(recorded, "local ECHO guard and sender record diverged");
        slot.candidates
            .entry(block_ref)
            .or_insert_with(CandidateState::new)
            .echoes
            .add(own_authority, &committee);

        let mut effects = vec![RbcEffect::MulticastPhase {
            phase: RbcPhase::Echo,
            block_ref,
        }];
        effects.extend(self.drive(block_ref));
        Ok(effects)
    }

    pub(crate) fn handle_phase(
        &mut self,
        direct_peer: AuthorityIndex,
        message: RbcPhaseMessage,
    ) -> Result<Vec<RbcEffect>, RbcError> {
        self.verify_phase_message(direct_peer, &message)?;
        let committee = Arc::clone(&self.committee);
        let slot = self.slot_mut(message.block_ref);
        if !slot.record_phase_sender(message.phase, message.sender, message.block_ref) {
            return Ok(Vec::new());
        }
        let candidate = slot
            .candidates
            .entry(message.block_ref)
            .or_insert_with(CandidateState::new);
        match message.phase {
            RbcPhase::Echo => {
                candidate.echoes.add(message.sender, &committee);
            }
            RbcPhase::Ready => {
                candidate.readies.add(message.sender, &committee);
            }
        }
        Ok(self.drive(message.block_ref))
    }

    /// Apply a statement authenticated by the ordinary V3 block that carries
    /// it. The carrying block author is the RBC sender; no standalone phase
    /// MAC or second network message exists in this path.
    pub(crate) fn handle_embedded_reference(
        &mut self,
        authenticated_sender: AuthorityIndex,
        evidence: StarfishRbcReferenceV3,
    ) -> Result<Vec<RbcEffect>, RbcError> {
        if !self.committee.known_authority(authenticated_sender) {
            return Err(RbcError::UnknownAuthority(authenticated_sender));
        }
        let block_ref = evidence.reference();
        self.validate_block_ref(&block_ref)?;
        let phase = match evidence.kind() {
            StarfishRbcReferenceKindV3::Echo => RbcPhase::Echo,
            StarfishRbcReferenceKindV3::Ready => RbcPhase::Ready,
        };
        let committee = Arc::clone(&self.committee);
        let slot = self.slot_mut(block_ref);
        if !slot.record_phase_sender(phase, authenticated_sender, block_ref) {
            return Ok(Vec::new());
        }
        let candidate = slot
            .candidates
            .entry(block_ref)
            .or_insert_with(CandidateState::new);
        match phase {
            RbcPhase::Echo => {
                candidate.echoes.add(authenticated_sender, &committee);
            }
            RbcPhase::Ready => {
                candidate.readies.add(authenticated_sender, &committee);
            }
        }
        Ok(self.drive(block_ref))
    }

    /// Materialize one recipient-specific message for an untagged multicast
    /// effect. The network adapter calls this once per non-local recipient.
    pub(crate) fn make_phase_message(
        &self,
        phase: RbcPhase,
        block_ref: BlockReference,
        recipient: AuthorityIndex,
    ) -> Result<RbcPhaseMessage, RbcError> {
        self.validate_block_ref(&block_ref)?;
        let authorized = self.slot(&block_ref).is_some_and(|slot| {
            let phase_authorized = match phase {
                RbcPhase::Echo => slot.echoed == Some(block_ref),
                RbcPhase::Ready => slot.readied == Some(block_ref),
            };
            phase_authorized
                && slot
                    .candidates
                    .get(&block_ref)
                    .is_some_and(|candidate| candidate.header.is_some())
        });
        if !authorized {
            return Err(RbcError::PhaseNotAuthorized { phase, block_ref });
        }
        if !self.committee.known_authority(recipient) {
            return Err(RbcError::UnknownAuthority(recipient));
        }
        if recipient == self.own_authority {
            return Err(RbcError::LoopbackPhase);
        }
        let statement = encode_mac_statement(
            &self.context,
            phase.statement_kind(),
            &block_ref,
            self.own_authority,
            recipient,
        );
        let tag = self.mac_keys[recipient as usize].compute_rbc_tag(&statement);
        Ok(RbcPhaseMessage {
            block_ref,
            sender: self.own_authority,
            recipient,
            phase,
            tag,
        })
    }

    fn ensure_local_initial(&self, local: &RbcLocalInitial) -> Result<BlockReference, RbcError> {
        if local.context != self.context || local.author != self.own_authority {
            return Err(RbcError::LocalInitialContextMismatch);
        }
        local.header.ensure_committee(self.context.committee_id)?;
        let block_ref = local.header.reference();
        let selected = self.slot(&block_ref).is_some_and(|slot| {
            slot.initial_candidate == Some(block_ref)
                && slot.echoed == Some(block_ref)
                && slot
                    .candidates
                    .get(&block_ref)
                    .and_then(|candidate| candidate.header.as_ref())
                    == Some(&local.header)
        });
        if !selected {
            return Err(RbcError::LocalInitialNotSelected(block_ref));
        }
        Ok(block_ref)
    }

    pub(crate) fn make_local_initial_signature_digest(
        &self,
        local: &RbcLocalInitial,
    ) -> Result<[u8; 32], RbcError> {
        let block_ref = self.ensure_local_initial(local)?;
        self.initial_signature_digest(block_ref)
    }

    /// Produce the common 32-byte digest signed by Ed25519 or ML-DSA for an
    /// initial Starfish-RBC header proposal.
    fn initial_signature_digest(&self, block_ref: BlockReference) -> Result<[u8; 32], RbcError> {
        if self.context.initial_authentication == BlockAuthenticationScheme::MacVector {
            return Err(RbcError::InitialSignatureRequiresSignatureAuthentication);
        }
        self.validate_block_ref(&block_ref)?;
        let statement = encode_base_statement(&self.context, INITIAL_KIND, &block_ref);
        Ok(blake3::hash(&statement).into())
    }

    /// Produce one receiver-specific initial MAC. The local author calls this
    /// separately for every non-local recipient.
    pub(crate) fn make_local_initial_mac_tag(
        &self,
        local: &RbcLocalInitial,
        recipient: AuthorityIndex,
    ) -> Result<MacTag, RbcError> {
        let block_ref = self.ensure_local_initial(local)?;
        self.make_initial_mac_tag_for_reference(block_ref, recipient)
    }

    fn make_initial_mac_tag_for_reference(
        &self,
        block_ref: BlockReference,
        recipient: AuthorityIndex,
    ) -> Result<MacTag, RbcError> {
        if self.context.initial_authentication != BlockAuthenticationScheme::MacVector {
            return Err(RbcError::InitialMacRequiresMacAuthentication);
        }
        self.validate_block_ref(&block_ref)?;
        if block_ref.authority != self.own_authority {
            return Err(RbcError::InitialAuthorMismatch {
                expected: block_ref.authority,
                actual: self.own_authority,
            });
        }
        if !self.committee.known_authority(recipient) {
            return Err(RbcError::UnknownAuthority(recipient));
        }
        if recipient == self.own_authority {
            return Err(RbcError::LoopbackPhase);
        }
        let statement = encode_mac_statement(
            &self.context,
            INITIAL_KIND,
            &block_ref,
            self.own_authority,
            recipient,
        );
        Ok(self.mac_keys[recipient as usize].compute_rbc_tag(&statement))
    }

    /// Verify the local receiver's initial MAC from the direct block author.
    pub(crate) fn verify_initial_mac_tag(
        &self,
        direct_peer: AuthorityIndex,
        block_ref: BlockReference,
        tag: &MacTag,
    ) -> Result<(), RbcError> {
        if self.context.initial_authentication != BlockAuthenticationScheme::MacVector {
            return Err(RbcError::InitialMacRequiresMacAuthentication);
        }
        self.validate_block_ref(&block_ref)?;
        if direct_peer != block_ref.authority {
            return Err(RbcError::InitialAuthorMismatch {
                expected: block_ref.authority,
                actual: direct_peer,
            });
        }
        if direct_peer == self.own_authority {
            return Err(RbcError::LoopbackPhase);
        }
        let statement = encode_mac_statement(
            &self.context,
            INITIAL_KIND,
            &block_ref,
            direct_peer,
            self.own_authority,
        );
        let expected = self.mac_keys[direct_peer as usize].compute_rbc_tag(&statement);
        if expected != *tag {
            return Err(RbcError::InvalidInitialTag);
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn header_holders(&self, block_ref: &BlockReference) -> AuthoritySet {
        self.candidate(block_ref)
            .map(CandidateState::holders)
            .unwrap_or_default()
    }

    /// Return the retained, content-validated header for a candidate.
    ///
    /// The service uses this accessor to answer recovery requests. Returning
    /// the pin (rather than a detached header clone) preserves the invariant
    /// that an honest ECHO/READY sender keeps the advertised content alive.
    pub(crate) fn pinned_header(
        &self,
        block_ref: BlockReference,
    ) -> Result<Option<PinnedRbcHeader>, RbcError> {
        self.validate_block_ref(&block_ref)?;
        Ok(self
            .candidate(&block_ref)
            .and_then(|candidate| candidate.header.clone()))
    }

    /// Recreate the current fetch effect for a durable retry timer. The first
    /// `NeedHeader` effect is only a wake-up; recovery must retry until the
    /// content-validated header becomes locally pinned.
    pub(crate) fn retry_header_request(
        &self,
        block_ref: BlockReference,
    ) -> Result<Option<RbcEffect>, RbcError> {
        self.validate_block_ref(&block_ref)?;
        let Some(slot) = self.slot(&block_ref) else {
            return Ok(None);
        };
        let Some(candidate) = slot.candidates.get(&block_ref) else {
            return Ok(None);
        };
        let ready_trigger = candidate.echo_quorum_observed || candidate.ready_validity_observed;
        let blocked_on_header = candidate.header.is_none()
            && ((slot.readied.is_none() && ready_trigger)
                || (slot.delivered.is_none() && candidate.ready_quorum_observed));
        Ok(blocked_on_header.then(|| RbcEffect::NeedHeader {
            block_ref,
            holders: candidate.holders(),
        }))
    }

    fn verify_phase_message(
        &self,
        direct_peer: AuthorityIndex,
        message: &RbcPhaseMessage,
    ) -> Result<(), RbcError> {
        self.validate_block_ref(&message.block_ref)?;
        if !self.committee.known_authority(direct_peer) {
            return Err(RbcError::UnknownAuthority(direct_peer));
        }
        if !self.committee.known_authority(message.sender) {
            return Err(RbcError::UnknownAuthority(message.sender));
        }
        if !self.committee.known_authority(message.recipient) {
            return Err(RbcError::UnknownAuthority(message.recipient));
        }
        if message.recipient != self.own_authority {
            return Err(RbcError::WrongRecipient {
                expected: self.own_authority,
                actual: message.recipient,
            });
        }
        if message.sender != direct_peer {
            return Err(RbcError::SenderPeerMismatch {
                sender: message.sender,
                peer: direct_peer,
            });
        }
        if message.sender == message.recipient {
            return Err(RbcError::LoopbackPhase);
        }
        let statement = encode_mac_statement(
            &self.context,
            message.phase.statement_kind(),
            &message.block_ref,
            message.sender,
            message.recipient,
        );
        let expected = self.mac_keys[message.sender as usize].compute_rbc_tag(&statement);
        if expected != message.tag {
            return Err(RbcError::InvalidPhaseTag);
        }
        Ok(())
    }

    fn validate_block_ref(&self, block_ref: &BlockReference) -> Result<(), RbcError> {
        if block_ref.round == 0 {
            return Err(RbcError::GenesisSlot);
        }
        if !self.committee.known_authority(block_ref.authority) {
            return Err(RbcError::UnknownAuthority(block_ref.authority));
        }
        let maximum_round = self.maximum_admissible_round();
        if block_ref.round > maximum_round {
            return Err(RbcError::FutureRound {
                round: block_ref.round,
                maximum: maximum_round,
            });
        }
        if block_ref.round < self.minimum_new_slot_round && self.slot(block_ref).is_none() {
            return Err(RbcError::StaleRound {
                round: block_ref.round,
                minimum: self.minimum_new_slot_round,
            });
        }
        Ok(())
    }

    fn record_initial_candidate(&mut self, block_ref: BlockReference) -> Result<(), RbcError> {
        self.validate_block_ref(&block_ref)?;
        let slot = self.slot_mut(block_ref);
        match slot.initial_candidate {
            Some(existing) if existing != block_ref => Err(RbcError::ConflictingInitialHeader {
                existing,
                received: block_ref,
            }),
            Some(_) => Ok(()),
            None => {
                slot.initial_candidate = Some(block_ref);
                Ok(())
            }
        }
    }

    fn slot_mut(&mut self, block_ref: BlockReference) -> &mut SlotState {
        self.slots
            .entry(block_ref.round)
            .or_default()
            .entry(block_ref.authority)
            .or_default()
    }

    fn slot(&self, block_ref: &BlockReference) -> Option<&SlotState> {
        self.slots
            .get(&block_ref.round)
            .and_then(|round| round.get(&block_ref.authority))
    }

    fn candidate_mut(&mut self, block_ref: BlockReference) -> &mut CandidateState {
        self.slot_mut(block_ref)
            .candidates
            .entry(block_ref)
            .or_insert_with(CandidateState::new)
    }

    fn candidate(&self, block_ref: &BlockReference) -> Option<&CandidateState> {
        self.slot(block_ref)
            .and_then(|slot| slot.candidates.get(block_ref))
    }

    fn drive(&mut self, block_ref: BlockReference) -> Vec<RbcEffect> {
        let validity_threshold = self.committee.validity_threshold();
        let quorum_threshold = self.committee.quorum_threshold();
        let echo_qc_fast_path = self.echo_qc_fast_path;
        let mut effects = Vec::new();

        loop {
            let action = {
                let slot = self.slot_mut(block_ref);
                let can_send_ready = slot.readied.is_none();
                let can_deliver = slot.delivered.is_none();
                let candidate = slot
                    .candidates
                    .entry(block_ref)
                    .or_insert_with(CandidateState::new);
                candidate.latch_thresholds(validity_threshold, quorum_threshold);

                let ready_trigger =
                    candidate.echo_quorum_observed || candidate.ready_validity_observed;
                let blocked_on_header = candidate.header.is_none()
                    && ((can_send_ready && ready_trigger)
                        || (can_deliver && candidate.ready_quorum_observed));
                let holders = candidate.holders();
                if blocked_on_header && holders != candidate.header_request_holders {
                    candidate.header_request_holders = holders;
                    ProgressAction::NeedHeader(holders)
                } else if candidate.header.is_some() && can_send_ready && ready_trigger {
                    ProgressAction::SendReady
                } else if candidate.header.is_some()
                    && can_deliver
                    && (candidate.ready_quorum_observed
                        || (echo_qc_fast_path && candidate.echo_quorum_observed))
                {
                    ProgressAction::Deliver
                } else {
                    ProgressAction::None
                }
            };

            match action {
                ProgressAction::NeedHeader(holders) => {
                    effects.push(RbcEffect::NeedHeader { block_ref, holders });
                    break;
                }
                ProgressAction::SendReady => {
                    let own_authority = self.own_authority;
                    let committee = Arc::clone(&self.committee);
                    let slot = self.slot_mut(block_ref);
                    if slot.readied.is_none() {
                        slot.readied = Some(block_ref);
                        let recorded =
                            slot.record_phase_sender(RbcPhase::Ready, own_authority, block_ref);
                        debug_assert!(recorded, "local READY guard and sender record diverged");
                        slot.candidates
                            .entry(block_ref)
                            .or_insert_with(CandidateState::new)
                            .readies
                            .add(own_authority, &committee);
                        effects.push(RbcEffect::MulticastPhase {
                            phase: RbcPhase::Ready,
                            block_ref,
                        });
                    }
                }
                ProgressAction::Deliver => {
                    let slot = self.slot_mut(block_ref);
                    if slot.delivered.is_none() {
                        slot.delivered = Some(block_ref);
                        let header = slot
                            .candidates
                            .get(&block_ref)
                            .and_then(|candidate| candidate.header.clone())
                            .expect("delivery requires a pinned Starfish-RBC header");
                        effects.push(RbcEffect::Deliver(header));
                    }
                }
                ProgressAction::None => break,
            }
        }

        effects
    }
}

fn validate_committee(committee: &Committee) -> Result<(), RbcError> {
    if committee.is_empty() {
        return Err(RbcError::EmptyCommittee);
    }
    if committee.len() > MAX_COMMITTEE_SIZE as usize {
        return Err(RbcError::CommitteeTooLarge(committee.len()));
    }
    let mut total_stake = 0u64;
    for authority in committee.authorities() {
        let stake = committee
            .get_stake(authority)
            .ok_or(RbcError::UnknownAuthority(authority))?;
        if stake == 0 {
            return Err(RbcError::InvalidCommitteeStake(authority));
        }
        total_stake = total_stake
            .checked_add(stake)
            .ok_or(RbcError::TotalStakeOverflow)?;
    }
    let expected_validity = total_stake / 3 + 1;
    let expected_quorum = total_stake
        .checked_mul(2)
        .ok_or(RbcError::TotalStakeOverflow)?
        / 3
        + 1;
    if committee.validity_threshold() != expected_validity {
        return Err(RbcError::InvalidValidityThreshold {
            expected: expected_validity,
            actual: committee.validity_threshold(),
        });
    }
    if committee.quorum_threshold() != expected_quorum {
        return Err(RbcError::InvalidQuorumThreshold {
            expected: expected_quorum,
            actual: committee.quorum_threshold(),
        });
    }
    let committee_size = committee.len();
    let f = (committee_size - 1) / 3;
    let expected_info_length = match committee_size % 3 {
        0 => f + 3,
        1 => f + 1,
        _ => f + 2,
    };
    if committee.info_length() != expected_info_length {
        return Err(RbcError::InvalidDerivedInfoLength {
            expected: expected_info_length,
            actual: committee.info_length(),
        });
    }
    Ok(())
}

fn authentication_code(authentication: BlockAuthenticationScheme) -> u8 {
    match authentication {
        BlockAuthenticationScheme::Ed25519 => 0x00,
        BlockAuthenticationScheme::MlDsa44 => 0x01,
        BlockAuthenticationScheme::MlDsa65 => 0x02,
        BlockAuthenticationScheme::MacVector => 0x03,
    }
}

fn encode_base_statement(
    context: &RbcContext,
    kind: u8,
    block_ref: &BlockReference,
) -> [u8; BASE_STATEMENT_SIZE] {
    let mut statement = [0u8; BASE_STATEMENT_SIZE];
    statement[..15].copy_from_slice(PROTOCOL_DOMAIN);
    statement[15] = kind;
    statement[16] = authentication_code(context.initial_authentication);
    statement[17..49].copy_from_slice(&context.protocol_instance.0);
    statement[49..81].copy_from_slice(&context.committee_id.0);
    statement[81..83].copy_from_slice(&block_ref.authority.to_be_bytes());
    statement[83..87].copy_from_slice(&block_ref.round.to_be_bytes());
    statement[87..119].copy_from_slice(block_ref.digest.as_ref());
    statement
}

fn encode_mac_statement(
    context: &RbcContext,
    kind: u8,
    block_ref: &BlockReference,
    sender: AuthorityIndex,
    recipient: AuthorityIndex,
) -> [u8; MAC_STATEMENT_SIZE] {
    let mut statement = [0u8; MAC_STATEMENT_SIZE];
    statement[..BASE_STATEMENT_SIZE]
        .copy_from_slice(&encode_base_statement(context, kind, block_ref));
    statement[119..121].copy_from_slice(&sender.to_be_bytes());
    statement[121..123].copy_from_slice(&recipient.to_be_bytes());
    statement
}

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, VecDeque};

    use super::*;
    use crate::{
        crypto::{
            dummy_ml_dsa_44_signer, dummy_ml_dsa_65_signer, dummy_signer, mac_keyrings_for_test,
        },
        types::{BlockDigest, BlockReference},
    };

    const TEST_INSTANCE_BYTE: u8 = 0xA5;
    type DeliveryTrace = Vec<Vec<BlockReference>>;
    type RecoveryTrace = Vec<(AuthorityIndex, AuthorityIndex, BlockReference)>;

    fn block(authority: AuthorityIndex, round: RoundNumber, marker: u8) -> BlockReference {
        BlockReference {
            authority,
            round,
            digest: BlockDigest::from([marker; 32]),
        }
    }

    fn pinned_header_for_context(
        context: RbcContext,
        block_ref: BlockReference,
    ) -> PinnedRbcHeader {
        PinnedRbcHeader {
            header: Arc::new(RbcCanonicalHeader {
                reference: block_ref,
                block_references: Vec::new(),
                acknowledgments: RbcAckFields {
                    intersection: Some(0),
                    extra_references: Vec::new(),
                },
                meta_creation_time_ns: 0,
                transactions_commitment: TransactionsCommitment::default(),
                starfish_rbc_v3: None,
            }),
            committee_id: context.committee_id,
        }
    }

    fn pinned_header(committee: &Committee, block_ref: BlockReference) -> PinnedRbcHeader {
        pinned_header_for_context(
            RbcContext::new(
                instance(TEST_INSTANCE_BYTE),
                committee,
                BlockAuthenticationScheme::Ed25519,
            )
            .unwrap(),
            block_ref,
        )
    }

    #[test]
    fn embedded_block_references_drive_rbc_without_phase_messages() {
        let committee = Committee::new_for_benchmarks(4);
        let keyrings = mac_keyrings_for_test(committee.len());
        let mut receiver = StarfishRbcKernel::new(
            committee.clone(),
            0,
            instance(TEST_INSTANCE_BYTE),
            BlockAuthenticationScheme::MacVector,
            Arc::new(keyrings[0].clone()),
            1,
        )
        .unwrap();
        let target = block(3, 1, 0x71);
        receiver
            .note_header_available(pinned_header_for_context(receiver.context, target))
            .unwrap();
        receiver.authorize_echo(target).unwrap();

        let echo = StarfishRbcReferenceV3::new(StarfishRbcReferenceKindV3::Echo, target);
        assert!(
            receiver
                .handle_embedded_reference(1, echo)
                .unwrap()
                .is_empty()
        );
        let effects = receiver.handle_embedded_reference(2, echo).unwrap();
        assert!(effects.iter().any(|effect| matches!(
            effect,
            RbcEffect::MulticastPhase {
                phase: RbcPhase::Ready,
                block_ref,
            } if *block_ref == target
        )));
        assert!(
            !effects
                .iter()
                .any(|effect| matches!(effect, RbcEffect::Deliver(_)))
        );

        let ready = StarfishRbcReferenceV3::new(StarfishRbcReferenceKindV3::Ready, target);
        assert!(
            receiver
                .handle_embedded_reference(1, ready)
                .unwrap()
                .is_empty()
        );
        let effects = receiver.handle_embedded_reference(2, ready).unwrap();
        assert!(effects.iter().any(|effect| matches!(
            effect,
            RbcEffect::Deliver(header) if header.reference() == target
        )));
    }

    #[test]
    fn flagged_echo_qc_fast_path_delivers_unique_header_without_ready_quorum() {
        let committee = Committee::new_for_benchmarks(4);
        let keyrings = mac_keyrings_for_test(committee.len());
        let mut receiver = StarfishRbcKernel::new_with_echo_qc_fast_path(
            committee,
            0,
            instance(TEST_INSTANCE_BYTE),
            BlockAuthenticationScheme::MacVector,
            Arc::new(keyrings[0].clone()),
            1,
            true,
        )
        .unwrap();
        let target = block(3, 1, 0x72);
        receiver
            .note_header_available(pinned_header_for_context(receiver.context, target))
            .unwrap();
        receiver.authorize_echo(target).unwrap();

        let echo = StarfishRbcReferenceV3::new(StarfishRbcReferenceKindV3::Echo, target);
        assert!(
            receiver
                .handle_embedded_reference(1, echo)
                .unwrap()
                .is_empty()
        );
        let effects = receiver.handle_embedded_reference(2, echo).unwrap();

        assert!(effects.iter().any(|effect| matches!(
            effect,
            RbcEffect::MulticastPhase {
                phase: RbcPhase::Ready,
                block_ref,
            } if *block_ref == target
        )));
        assert!(effects.iter().any(|effect| matches!(
            effect,
            RbcEffect::Deliver(header) if header.reference() == target
        )));
    }

    fn valid_canonical_header(
        authority: AuthorityIndex,
        round: RoundNumber,
        marker: u8,
    ) -> RbcCanonicalHeader {
        let parents = (0..3)
            .map(|parent_authority| {
                block(
                    parent_authority,
                    round - 1,
                    marker.wrapping_add(parent_authority as u8),
                )
            })
            .collect();
        RbcCanonicalHeader::try_new(
            authority,
            round,
            parents,
            Vec::new(),
            0x0102_0304_0506_0708,
            TransactionsCommitment::default(),
        )
        .unwrap()
    }

    fn block_header_from_canonical(
        header: &RbcCanonicalHeader,
        authentication: BlockAuthentication,
    ) -> BlockHeader {
        BlockHeader {
            reference: header.reference,
            block_references: header.block_references.clone(),
            meta_creation_time_ns: header.meta_creation_time_ns,
            authentication,
            transactions_commitment: Some(header.transactions_commitment),
            ack: Some(header.acknowledgment_fields()),
            strong_vote: None,
            bls: None,
            sailfish: None,
            unprovable_certificate: None,
            starfish_rbc_v3: None,
            serialized: None,
        }
    }

    fn instance(marker: u8) -> RbcProtocolInstanceId {
        RbcProtocolInstanceId::new([marker; 32]).unwrap()
    }

    fn kernel(
        committee: Arc<Committee>,
        keyrings: &[Vec<MacKey>],
        own_authority: AuthorityIndex,
        authentication: BlockAuthenticationScheme,
    ) -> StarfishRbcKernel {
        kernel_with_instance(
            committee,
            keyrings,
            own_authority,
            authentication,
            TEST_INSTANCE_BYTE,
        )
    }

    fn kernel_with_instance(
        committee: Arc<Committee>,
        keyrings: &[Vec<MacKey>],
        own_authority: AuthorityIndex,
        authentication: BlockAuthenticationScheme,
        instance_byte: u8,
    ) -> StarfishRbcKernel {
        StarfishRbcKernel::new(
            committee,
            own_authority,
            instance(instance_byte),
            authentication,
            Arc::new(keyrings[own_authority as usize].clone()),
            0,
        )
        .unwrap()
    }

    fn phase_message(
        committee: Arc<Committee>,
        keyrings: &[Vec<MacKey>],
        sender: AuthorityIndex,
        recipient: AuthorityIndex,
        phase: RbcPhase,
        block_ref: BlockReference,
    ) -> RbcPhaseMessage {
        let context = RbcContext::new(
            instance(TEST_INSTANCE_BYTE),
            committee.as_ref(),
            BlockAuthenticationScheme::Ed25519,
        )
        .unwrap();
        let statement = encode_mac_statement(
            &context,
            phase.statement_kind(),
            &block_ref,
            sender,
            recipient,
        );
        RbcPhaseMessage {
            block_ref,
            sender,
            recipient,
            phase,
            tag: keyrings[sender as usize][recipient as usize].compute_rbc_tag(&statement),
        }
    }

    fn authorize_echo(kernel: &mut StarfishRbcKernel, block_ref: BlockReference) {
        let header = pinned_header_for_context(kernel.context(), block_ref);
        kernel.note_header_available(header).unwrap();
        assert!(matches!(
            kernel.authorize_echo(block_ref).unwrap().as_slice(),
            [RbcEffect::MulticastPhase {
                phase: RbcPhase::Echo,
                ..
            }]
        ));
    }

    fn holder_vec(holders: AuthoritySet) -> Vec<AuthorityIndex> {
        holders.present().collect()
    }

    fn pump_phase_effects(
        kernels: &mut [StarfishRbcKernel],
        initial_effects: Vec<(AuthorityIndex, Vec<RbcEffect>)>,
        header_stores: &mut [AHashMap<BlockReference, RbcCanonicalHeader>],
    ) -> (DeliveryTrace, RecoveryTrace) {
        let mut queue: VecDeque<_> = initial_effects
            .into_iter()
            .flat_map(|(authority, effects)| {
                effects.into_iter().map(move |effect| (authority, effect))
            })
            .collect();
        let mut deliveries = vec![Vec::new(); kernels.len()];
        let mut recoveries = Vec::new();

        while let Some((owner, effect)) = queue.pop_front() {
            match effect {
                RbcEffect::MulticastPhase { phase, block_ref } => {
                    let messages: Vec<_> = (0..kernels.len())
                        .filter(|recipient| *recipient != owner as usize)
                        .map(|recipient| {
                            let recipient = recipient as AuthorityIndex;
                            (
                                recipient,
                                kernels[owner as usize]
                                    .make_phase_message(phase, block_ref, recipient)
                                    .unwrap(),
                            )
                        })
                        .collect();
                    for (recipient, message) in messages {
                        let effects = kernels[recipient as usize]
                            .handle_phase(owner, message)
                            .unwrap();
                        queue.extend(effects.into_iter().map(|effect| (recipient, effect)));
                    }
                }
                RbcEffect::NeedHeader { block_ref, holders } => {
                    let (source, header) = holders
                        .present()
                        .find_map(|source| {
                            header_stores[source as usize]
                                .get(&block_ref)
                                .cloned()
                                .map(|header| (source, header))
                        })
                        .expect("a test RBC holder must retain the canonical header");
                    let effects = kernels[owner as usize]
                        .accept_recovered_header(header.clone())
                        .unwrap();
                    header_stores[owner as usize].insert(block_ref, header);
                    recoveries.push((owner, source, block_ref));
                    queue.extend(effects.into_iter().map(|effect| (owner, effect)));
                }
                RbcEffect::Deliver(header) => {
                    assert_eq!(
                        header_stores[owner as usize].get(&header.reference()),
                        Some(header.header())
                    );
                    deliveries[owner as usize].push(header.reference());
                }
            }
        }
        (deliveries, recoveries)
    }

    #[test]
    fn canonical_statement_layout_is_fixed_width_and_big_endian() {
        let context = RbcContext {
            protocol_instance: RbcProtocolInstanceId([0x11; 32]),
            committee_id: RbcCommitteeId([0x22; 32]),
            initial_authentication: BlockAuthenticationScheme::MlDsa65,
        };
        let block_ref = BlockReference {
            authority: 0x0102,
            round: 0x0304_0506,
            digest: BlockDigest::from([0x33; 32]),
        };
        let statement = encode_mac_statement(&context, ECHO_KIND, &block_ref, 0x0708, 0x090A);

        assert_eq!(statement.len(), 123);
        assert_eq!(&statement[..15], PROTOCOL_DOMAIN);
        assert_eq!(statement[15], ECHO_KIND);
        assert_eq!(statement[16], 0x02);
        assert_eq!(&statement[17..49], &[0x11; 32]);
        assert_eq!(&statement[49..81], &[0x22; 32]);
        assert_eq!(&statement[81..83], &[0x01, 0x02]);
        assert_eq!(&statement[83..87], &[0x03, 0x04, 0x05, 0x06]);
        assert_eq!(&statement[87..119], &[0x33; 32]);
        assert_eq!(&statement[119..121], &[0x07, 0x08]);
        assert_eq!(&statement[121..123], &[0x09, 0x0A]);
    }

    #[test]
    fn canonical_header_digest_has_a_frozen_tagged_encoding() {
        let parent = block(0x0708, 0x090A_0B0C, 0x11);
        let acknowledgment = block(0x0D0E, 0x0F10_1112, 0x22);
        let timestamp: TimestampNs = 0x1314_1516_1718_191A;
        let commitment = TransactionsCommitment::default();

        let mut encoded = Vec::new();
        encoded.extend_from_slice(&[0x01]);
        encoded.extend_from_slice(&0x0102u16.to_be_bytes());
        encoded.extend_from_slice(&[0x02]);
        encoded.extend_from_slice(&0x0304_0506u32.to_be_bytes());
        encoded.extend_from_slice(&[0x03]);
        encoded.extend_from_slice(&1u32.to_be_bytes());
        encoded.extend_from_slice(&parent.authority.to_be_bytes());
        encoded.extend_from_slice(&parent.round.to_be_bytes());
        encoded.extend_from_slice(parent.digest.as_ref());
        encoded.extend_from_slice(&[0x04]);
        encoded.extend_from_slice(&1u32.to_be_bytes());
        encoded.extend_from_slice(&acknowledgment.authority.to_be_bytes());
        encoded.extend_from_slice(&acknowledgment.round.to_be_bytes());
        encoded.extend_from_slice(acknowledgment.digest.as_ref());
        encoded.extend_from_slice(&[0x05]);
        encoded.extend_from_slice(&timestamp.to_be_bytes());
        encoded.extend_from_slice(&[0x06]);
        encoded.extend_from_slice(commitment.as_ref());

        assert_eq!(
            hex::encode(&encoded),
            concat!(
                "010102020304050603000000010708090a0b0c",
                "11111111111111111111111111111111",
                "11111111111111111111111111111111",
                "04000000010d0e0f101112",
                "22222222222222222222222222222222",
                "22222222222222222222222222222222",
                "051314",
                "15161718191a060000000000000000000000000000000000000000000000000000",
                "000000000000"
            )
        );
        let digest = BlockDigest::new_starfish_rbc_header(
            0x0102,
            0x0304_0506,
            &[parent],
            &[acknowledgment],
            timestamp,
            commitment,
        );
        assert_eq!(digest.as_ref(), blake3::hash(&encoded).as_bytes());
        assert_eq!(
            hex::encode(digest.as_ref()),
            "3a0ef697511a95ddf97c73e72aad2cb2313839063f7249fe0f967f2d8ff3ad22"
        );
    }

    #[test]
    fn canonical_digest_separates_the_legacy_parent_ack_boundary() {
        let references: Vec<_> = (0..4)
            .map(|authority| block(authority, 7, 0x30 + authority as u8))
            .collect();
        let commitment = TransactionsCommitment::default();
        let legacy_first = BlockDigest::new(
            0,
            8,
            &references[..3],
            &references[3..],
            42,
            Some(commitment),
            None,
        );
        let legacy_second = BlockDigest::new(0, 8, &references, &[], 42, Some(commitment), None);
        assert_eq!(legacy_first, legacy_second);

        let canonical_first = BlockDigest::new_starfish_rbc_header(
            0,
            8,
            &references[..3],
            &references[3..],
            42,
            commitment,
        );
        let canonical_second =
            BlockDigest::new_starfish_rbc_header(0, 8, &references, &[], 42, commitment);
        assert_ne!(canonical_first, canonical_second);
    }

    #[test]
    fn canonical_digest_binds_every_content_field_and_order() {
        let first = block(0, 4, 0x41);
        let second = block(1, 4, 0x42);
        let commitment = TransactionsCommitment::default();
        let other_commitment = TransactionsCommitment::new_from_transactions(&Vec::new());
        let digest =
            BlockDigest::new_starfish_rbc_header(2, 5, &[first, second], &[first], 7, commitment);

        for changed in [
            BlockDigest::new_starfish_rbc_header(3, 5, &[first, second], &[first], 7, commitment),
            BlockDigest::new_starfish_rbc_header(2, 6, &[first, second], &[first], 7, commitment),
            BlockDigest::new_starfish_rbc_header(2, 5, &[second, first], &[first], 7, commitment),
            BlockDigest::new_starfish_rbc_header(2, 5, &[first, second], &[second], 7, commitment),
            BlockDigest::new_starfish_rbc_header(2, 5, &[first, second], &[first], 8, commitment),
            BlockDigest::new_starfish_rbc_header(
                2,
                5,
                &[first, second],
                &[first],
                7,
                other_commitment,
            ),
        ] {
            assert_ne!(digest, changed);
        }
    }

    #[test]
    fn canonical_header_validation_is_authentication_independent_and_pins_content() {
        let committee = Committee::new_test(vec![1; 4]);
        let canonical = valid_canonical_header(3, 5, 0x51);
        let without_authentication =
            block_header_from_canonical(&canonical, BlockAuthentication::None);
        let with_authentication = block_header_from_canonical(
            &canonical,
            BlockAuthentication::Ed25519(SignatureBytes::default()),
        );

        let extracted_without =
            RbcCanonicalHeader::from_block_header(&without_authentication).unwrap();
        let extracted_with = RbcCanonicalHeader::from_block_header(&with_authentication).unwrap();
        assert_eq!(extracted_without, canonical);
        assert_eq!(extracted_with, canonical);
        canonical.validate_for_committee(&committee).unwrap();

        let carrier = canonical.to_authentication_free_block();
        assert_eq!(carrier.reference(), &canonical.reference());
        assert_eq!(carrier.authentication(), &BlockAuthentication::None);
        assert!(!carrier.has_transaction_data());
        assert_eq!(
            RbcCanonicalHeader::from_block_header(carrier.header()).unwrap(),
            canonical
        );

        let pinned = PinnedRbcHeader::validate(canonical.clone(), &committee).unwrap();
        let retained = pinned.clone();
        assert_eq!(pinned.reference(), canonical.reference());
        assert!(Arc::ptr_eq(&pinned.header, &retained.header));
        assert_eq!(pinned.header(), &canonical);
    }

    #[test]
    fn block_header_conversion_rejects_missing_fields_and_extensions() {
        let canonical = valid_canonical_header(3, 5, 0x52);
        let mut header = block_header_from_canonical(&canonical, BlockAuthentication::None);
        header.ack = None;
        assert_eq!(
            RbcCanonicalHeader::from_block_header(&header),
            Err(RbcError::MissingAcknowledgments)
        );

        let mut header = block_header_from_canonical(&canonical, BlockAuthentication::None);
        header.transactions_commitment = None;
        assert_eq!(
            RbcCanonicalHeader::from_block_header(&header),
            Err(RbcError::MissingTransactionsCommitment)
        );

        let mut header = block_header_from_canonical(&canonical, BlockAuthentication::None);
        header.strong_vote = Some(AuthoritySet::default());
        assert_eq!(
            RbcCanonicalHeader::from_block_header(&header),
            Err(RbcError::ForbiddenHeaderExtensions)
        );

        let mut header = block_header_from_canonical(&canonical, BlockAuthentication::None);
        header.block_references = vec![block(0, 4, 0x51); MAX_RBC_REFERENCES_PER_FIELD + 1];
        assert!(matches!(
            RbcCanonicalHeader::from_block_header(&header),
            Err(RbcError::TooManyHeaderReferences {
                field: "parent",
                ..
            })
        ));

        let mut header = block_header_from_canonical(&canonical, BlockAuthentication::None);
        header.ack = Some(AckFields {
            intersection: None,
            extra_references: vec![block(0, 4, 0x51); MAX_RBC_REFERENCES_PER_FIELD + 1],
        });
        assert!(matches!(
            RbcCanonicalHeader::from_block_header(&header),
            Err(RbcError::TooManyHeaderReferences {
                field: "acknowledgment",
                ..
            })
        ));

        let mut header = block_header_from_canonical(&canonical, BlockAuthentication::None);
        header.block_references = vec![block(0, 4, 0x51); MAX_RBC_REFERENCES_PER_FIELD];
        header.ack = Some(AckFields {
            intersection: Some(0),
            extra_references: vec![block(1, 4, 0x52)],
        });
        assert!(matches!(
            RbcCanonicalHeader::from_block_header(&header),
            Err(RbcError::TooManyHeaderReferences {
                field: "acknowledgment",
                ..
            })
        ));
    }

    #[test]
    fn acknowledgment_compression_is_canonical_and_preserves_u8_boundary() {
        let committee = Committee::new_test(vec![1; 4]);
        let canonical = valid_canonical_header(3, 5, 0x53);
        assert!(PinnedRbcHeader::validate(canonical.clone(), &committee).is_ok());

        let mut legacy_alias = canonical.clone();
        legacy_alias.acknowledgments.intersection = None;
        legacy_alias.acknowledgments.extra_references.clear();
        assert_eq!(
            PinnedRbcHeader::validate(legacy_alias, &committee),
            Err(RbcError::NonCanonicalAcknowledgments)
        );

        let mut out_of_range = canonical;
        out_of_range.acknowledgments.intersection = Some(4);
        assert_eq!(
            PinnedRbcHeader::validate(out_of_range, &committee),
            Err(RbcError::NonCanonicalAcknowledgments)
        );

        let references = |count: usize| {
            (0..count)
                .map(|index| {
                    let mut digest = [0; 32];
                    digest[..4].copy_from_slice(&(index as u32).to_be_bytes());
                    BlockReference {
                        authority: index as AuthorityIndex % 4,
                        round: 4,
                        digest: BlockDigest::from(digest),
                    }
                })
                .collect::<Vec<_>>()
        };
        let parents_255 = references(255);
        let parents_256 = references(256);
        assert_eq!(
            RbcAckFields::from_logical(&parents_255, &[]).intersection,
            Some(255)
        );
        assert_eq!(
            RbcAckFields::from_logical(&parents_256, &[]),
            RbcAckFields {
                intersection: None,
                extra_references: Vec::new(),
            }
        );
    }

    #[test]
    fn canonical_header_wire_keeps_starfish_acknowledgment_compression() {
        #[derive(Serialize)]
        struct ExpandedHeader<'a> {
            reference: BlockReference,
            block_references: &'a [BlockReference],
            acknowledgments: &'a [BlockReference],
            meta_creation_time_ns: TimestampNs,
            transactions_commitment: TransactionsCommitment,
        }

        let parents: Vec<_> = (0..100)
            .map(|index| {
                let mut digest = [0; 32];
                digest[..4].copy_from_slice(&(index as u32).to_be_bytes());
                BlockReference {
                    authority: index % 4,
                    round: 4,
                    digest: BlockDigest::from(digest),
                }
            })
            .collect();
        let logical_acknowledgments = parents[50..].to_vec();
        let header = RbcCanonicalHeader::try_new(
            3,
            5,
            parents,
            logical_acknowledgments.clone(),
            7,
            TransactionsCommitment::default(),
        )
        .unwrap();
        assert_eq!(header.acknowledgments.intersection, Some(50));
        assert!(header.acknowledgments.extra_references.is_empty());

        let compressed_size = bincode::serialize(&header).unwrap().len();
        let expanded_size = bincode::serialize(&ExpandedHeader {
            reference: header.reference,
            block_references: &header.block_references,
            acknowledgments: &logical_acknowledgments,
            meta_creation_time_ns: header.meta_creation_time_ns,
            transactions_commitment: header.transactions_commitment,
        })
        .unwrap()
        .len();
        assert!(compressed_size < expanded_size);
    }

    #[test]
    fn canonical_header_validation_rejects_duplicate_and_invalid_references() {
        let committee = Committee::new_test(vec![1; 4]);
        let valid = valid_canonical_header(3, 5, 0x54);

        let same_round_ack = RbcCanonicalHeader::try_new(
            3,
            5,
            valid.block_references.clone(),
            vec![block(2, 5, 0x59)],
            valid.meta_creation_time_ns,
            valid.transactions_commitment,
        )
        .unwrap();
        assert!(PinnedRbcHeader::validate(same_round_ack, &committee).is_ok());

        let mut duplicate_parent = valid.clone();
        duplicate_parent
            .block_references
            .push(duplicate_parent.block_references[0]);
        duplicate_parent.reference.digest = BlockDigest::new_starfish_rbc_header(
            duplicate_parent.reference.authority,
            duplicate_parent.reference.round,
            &duplicate_parent.block_references,
            &duplicate_parent.acknowledgment_references(),
            duplicate_parent.meta_creation_time_ns,
            duplicate_parent.transactions_commitment,
        );
        assert!(matches!(
            PinnedRbcHeader::validate(duplicate_parent, &committee),
            Err(RbcError::DuplicateParent(_))
        ));

        let duplicate_ack = block(3, 5, 0x55);
        assert!(matches!(
            RbcCanonicalHeader::try_new(
                3,
                5,
                valid.block_references.clone(),
                vec![duplicate_ack, duplicate_ack],
                valid.meta_creation_time_ns,
                valid.transactions_commitment,
            ),
            Err(RbcError::DuplicateAcknowledgment(_))
        ));

        let shared_parent = valid.block_references[2];
        let extra = block(3, 5, 0x5A);
        let normalized = RbcCanonicalHeader::try_new(
            3,
            5,
            valid.block_references.clone(),
            vec![extra, shared_parent],
            valid.meta_creation_time_ns,
            valid.transactions_commitment,
        );
        assert_eq!(
            normalized.unwrap().acknowledgment_references(),
            vec![shared_parent, extra]
        );

        let future_ack = block(3, 6, 0x56);
        let future_ack_header = RbcCanonicalHeader::try_new(
            3,
            5,
            valid.block_references.clone(),
            vec![future_ack],
            valid.meta_creation_time_ns,
            valid.transactions_commitment,
        )
        .unwrap();
        assert!(matches!(
            PinnedRbcHeader::validate(future_ack_header, &committee),
            Err(RbcError::AcknowledgmentFromFuture(_))
        ));

        let unknown_ack_header = RbcCanonicalHeader::try_new(
            3,
            5,
            valid.block_references.clone(),
            vec![block(4, 5, 0x5B)],
            valid.meta_creation_time_ns,
            valid.transactions_commitment,
        )
        .unwrap();
        assert_eq!(
            PinnedRbcHeader::validate(unknown_ack_header, &committee),
            Err(RbcError::UnknownAuthority(4))
        );

        let mut unknown_parent = valid.clone();
        unknown_parent.block_references[0].authority = 4;
        unknown_parent.reference.digest = BlockDigest::new_starfish_rbc_header(
            unknown_parent.reference.authority,
            unknown_parent.reference.round,
            &unknown_parent.block_references,
            &unknown_parent.acknowledgment_references(),
            unknown_parent.meta_creation_time_ns,
            unknown_parent.transactions_commitment,
        );
        assert_eq!(
            PinnedRbcHeader::validate(unknown_parent, &committee),
            Err(RbcError::UnknownAuthority(4))
        );

        let mut same_round_parent = valid.clone();
        same_round_parent.block_references[0].round = same_round_parent.reference.round;
        same_round_parent.reference.digest = BlockDigest::new_starfish_rbc_header(
            same_round_parent.reference.authority,
            same_round_parent.reference.round,
            &same_round_parent.block_references,
            &same_round_parent.acknowledgment_references(),
            same_round_parent.meta_creation_time_ns,
            same_round_parent.transactions_commitment,
        );
        assert!(matches!(
            PinnedRbcHeader::validate(same_round_parent, &committee),
            Err(RbcError::ParentNotPast(_))
        ));

        let insufficient_parents = RbcCanonicalHeader::try_new(
            3,
            5,
            valid.block_references[..2].to_vec(),
            Vec::new(),
            valid.meta_creation_time_ns,
            valid.transactions_commitment,
        )
        .unwrap();
        assert_eq!(
            PinnedRbcHeader::validate(insufficient_parents, &committee),
            Err(RbcError::InvalidThresholdClock)
        );

        let mut wrong_digest = valid;
        wrong_digest.reference.digest = BlockDigest::from([0xFF; 32]);
        assert!(matches!(
            PinnedRbcHeader::validate(wrong_digest, &committee),
            Err(RbcError::HeaderDigestMismatch { .. })
        ));

        let keyrings = mac_keyrings_for_test(4);
        let kernel = kernel(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::Ed25519,
        );
        let mut genesis = valid_canonical_header(0, 5, 0x5C);
        genesis.reference.round = 0;
        assert_eq!(
            kernel.validate_header_content(genesis),
            Err(RbcError::GenesisSlot)
        );
    }

    #[test]
    fn future_round_admission_advances_monotonically() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let mut kernel = kernel(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::Ed25519,
        );
        let too_far = block(0, MAX_RBC_FUTURE_ROUNDS + 1, 0x57);
        assert!(matches!(
            kernel.handle_phase(
                1,
                phase_message(
                    Arc::clone(&kernel.committee),
                    &keyrings,
                    1,
                    0,
                    RbcPhase::Echo,
                    too_far,
                ),
            ),
            Err(RbcError::FutureRound { .. })
        ));
        assert!(kernel.slots.is_empty());

        kernel.advance_local_round(1).unwrap();
        assert_eq!(kernel.maximum_admissible_round(), MAX_RBC_FUTURE_ROUNDS + 1);
        assert_eq!(
            kernel.advance_local_round(0),
            Err(RbcError::RoundRegression {
                current: 1,
                proposed: 0,
            })
        );
    }

    #[test]
    fn retained_round_floor_rejects_only_unseen_slots() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            3,
            BlockAuthenticationScheme::Ed25519,
        );
        let first = valid_canonical_header(0, 5, 0xD0).reference();
        receiver
            .handle_phase(
                0,
                phase_message(
                    Arc::clone(&committee),
                    &keyrings,
                    0,
                    3,
                    RbcPhase::Echo,
                    first,
                ),
            )
            .unwrap();

        receiver.advance_local_round(10).unwrap();
        assert_eq!(
            receiver.close_new_slots_before(11),
            Err(RbcError::RetainedRoundAheadOfLocal {
                local: 10,
                proposed: 11,
            })
        );
        receiver.close_new_slots_before(10).unwrap();
        assert_eq!(receiver.minimum_new_slot_round(), 10);
        assert_eq!(
            receiver.close_new_slots_before(9),
            Err(RbcError::RetainedRoundRegression {
                current: 10,
                proposed: 9,
            })
        );

        let retained_candidate = valid_canonical_header(0, 5, 0xD1);
        let retained_ref = retained_candidate.reference();
        receiver
            .handle_phase(
                1,
                phase_message(
                    Arc::clone(&committee),
                    &keyrings,
                    1,
                    3,
                    RbcPhase::Ready,
                    retained_ref,
                ),
            )
            .unwrap();
        assert!(
            receiver
                .accept_recovered_header(retained_candidate)
                .unwrap()
                .is_empty()
        );

        let unseen = block(1, 5, 0xD2);
        assert_eq!(
            receiver.handle_phase(
                0,
                phase_message(
                    Arc::clone(&committee),
                    &keyrings,
                    0,
                    3,
                    RbcPhase::Echo,
                    unseen,
                ),
            ),
            Err(RbcError::StaleRound {
                round: 5,
                minimum: 10,
            })
        );
        assert!(receiver.slots[&5].get(&1).is_none());
        assert!(receiver.candidate(&retained_ref).unwrap().header.is_some());
    }

    #[test]
    fn phase_sender_admission_bounds_equivocation_without_burning_invalid_messages() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let canonical = valid_canonical_header(0, 6, 0xD3);
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            3,
            BlockAuthenticationScheme::Ed25519,
        );
        let outcome = receiver
            .accept_direct_initial_header(
                0,
                canonical,
                &RbcInitialProof::Ed25519(SignatureBytes::default()),
            )
            .unwrap();
        assert!(matches!(
            outcome,
            RbcInitialHeaderOutcome::StagedUnauthenticated { .. }
        ));
        let conflicting_initial = valid_canonical_header(0, 6, 0xD5);
        let conflicting_ref = conflicting_initial.reference();
        assert!(matches!(
            receiver.accept_direct_initial_header(
                0,
                conflicting_initial,
                &RbcInitialProof::Ed25519(SignatureBytes::default()),
            ),
            Err(RbcError::ConflictingInitialHeader { received, .. }) if received == conflicting_ref
        ));

        let mut invalid = phase_message(
            Arc::clone(&committee),
            &keyrings,
            0,
            3,
            RbcPhase::Echo,
            block(0, 6, 0xD4),
        );
        invalid.tag = MacTag::from_bytes([0; 32]);
        assert_eq!(
            receiver.handle_phase(0, invalid),
            Err(RbcError::InvalidPhaseTag)
        );

        let mut first_echo = None;
        let mut first_ready = None;
        for sender in 0..3 {
            let echo = block(0, 6, 0xE0 + sender as u8);
            let ready = block(0, 6, 0xF0 + sender as u8);
            first_echo.get_or_insert(echo);
            first_ready.get_or_insert(ready);
            receiver
                .handle_phase(
                    sender,
                    phase_message(
                        Arc::clone(&committee),
                        &keyrings,
                        sender,
                        3,
                        RbcPhase::Echo,
                        echo,
                    ),
                )
                .unwrap();
            receiver
                .handle_phase(
                    sender,
                    phase_message(
                        Arc::clone(&committee),
                        &keyrings,
                        sender,
                        3,
                        RbcPhase::Ready,
                        ready,
                    ),
                )
                .unwrap();
        }

        for marker in 0..32 {
            for phase in [RbcPhase::Echo, RbcPhase::Ready] {
                let message = phase_message(
                    Arc::clone(&committee),
                    &keyrings,
                    0,
                    3,
                    phase,
                    block(0, 6, marker),
                );
                assert!(receiver.handle_phase(0, message).unwrap().is_empty());
            }
        }
        let slot = receiver.slot(&block(0, 6, 0)).unwrap();
        assert_eq!(slot.candidates.len(), 1 + 2 * (committee.len() - 1));
        assert!(slot.candidates.contains_key(&first_echo.unwrap()));
        assert!(slot.candidates.contains_key(&first_ready.unwrap()));
    }

    #[test]
    fn recovered_headers_require_prior_authenticated_phase_evidence() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let canonical = valid_canonical_header(0, 8, 0xD6);
        let block_ref = canonical.reference();
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            3,
            BlockAuthenticationScheme::Ed25519,
        );

        assert_eq!(
            receiver.accept_recovered_header(canonical.clone()),
            Err(RbcError::UnexpectedRecoveredHeader(block_ref))
        );
        assert!(receiver.slots.is_empty());

        receiver
            .handle_phase(
                0,
                phase_message(committee, &keyrings, 0, 3, RbcPhase::Ready, block_ref),
            )
            .unwrap();
        assert!(
            receiver
                .accept_recovered_header(canonical)
                .unwrap()
                .is_empty()
        );
        assert!(receiver.candidate(&block_ref).unwrap().header.is_some());
    }

    #[test]
    fn bounded_header_decoder_rejects_oversized_reference_vector() {
        #[derive(Serialize)]
        struct UnboundedReferences {
            references: Vec<BlockReference>,
        }
        #[derive(Deserialize)]
        struct BoundedReferences {
            #[serde(with = "super::bounded_references")]
            _references: Vec<BlockReference>,
        }

        let oversized = UnboundedReferences {
            references: vec![block(0, 1, 0x58); MAX_RBC_REFERENCES_PER_FIELD + 1],
        };
        let bytes = bincode::serialize(&oversized).unwrap();
        assert!(bincode::deserialize::<BoundedReferences>(&bytes).is_err());

        #[derive(Serialize)]
        struct UnboundedAckFields {
            intersection: Option<u8>,
            extra_references: Vec<BlockReference>,
        }
        #[derive(Serialize)]
        struct UnboundedHeader {
            reference: BlockReference,
            block_references: Vec<BlockReference>,
            acknowledgments: UnboundedAckFields,
            meta_creation_time_ns: TimestampNs,
            transactions_commitment: TransactionsCommitment,
        }

        let base = valid_canonical_header(0, 5, 0x59);
        let oversized_parent_header = UnboundedHeader {
            reference: base.reference,
            block_references: vec![block(0, 4, 0x58); MAX_RBC_REFERENCES_PER_FIELD + 1],
            acknowledgments: UnboundedAckFields {
                intersection: Some(0),
                extra_references: Vec::new(),
            },
            meta_creation_time_ns: base.meta_creation_time_ns,
            transactions_commitment: base.transactions_commitment,
        };
        let bytes = bincode::serialize(&oversized_parent_header).unwrap();
        assert!(bincode::deserialize::<RbcCanonicalHeader>(&bytes).is_err());

        let oversized_extra_header = UnboundedHeader {
            reference: base.reference,
            block_references: base.block_references,
            acknowledgments: UnboundedAckFields {
                intersection: Some(0),
                extra_references: vec![block(0, 4, 0x58); MAX_RBC_REFERENCES_PER_FIELD + 1],
            },
            meta_creation_time_ns: base.meta_creation_time_ns,
            transactions_commitment: base.transactions_commitment,
        };
        let bytes = bincode::serialize(&oversized_extra_header).unwrap();
        assert!(bincode::deserialize::<RbcCanonicalHeader>(&bytes).is_err());
    }

    #[test]
    fn canonical_header_content_size_enforces_the_four_mib_boundary() {
        let references = |count: usize, round: RoundNumber, domain: u8| {
            (0..count)
                .map(|index| {
                    let mut digest = [0; 32];
                    digest[0] = domain;
                    digest[1..9].copy_from_slice(&(index as u64).to_be_bytes());
                    BlockReference {
                        authority: index as AuthorityIndex % 4,
                        round,
                        digest: BlockDigest::from(digest),
                    }
                })
                .collect::<Vec<_>>()
        };
        let maximum_total_references = (MAX_RBC_HEADER_CONTENT_SIZE
            - RBC_HEADER_FIXED_CONTENT_SIZE)
            / RBC_BLOCK_REFERENCE_SIZE;
        let parent_count = maximum_total_references / 2;
        let acknowledgment_count = maximum_total_references - parent_count;
        let accepted = RbcCanonicalHeader::try_new(
            0,
            5,
            references(parent_count, 4, 0x01),
            references(acknowledgment_count, 3, 0x02),
            0,
            TransactionsCommitment::default(),
        )
        .unwrap();
        assert_eq!(
            accepted
                .encoded_content_size(accepted.acknowledgment_references().len())
                .unwrap(),
            MAX_RBC_HEADER_CONTENT_SIZE - 32
        );

        let mut too_large_acknowledgments = accepted.acknowledgment_references();
        too_large_acknowledgments.push(block(0, 3, 0x03));
        assert_eq!(
            RbcCanonicalHeader::try_new(
                accepted.reference.authority,
                accepted.reference.round,
                accepted.block_references.clone(),
                too_large_acknowledgments,
                accepted.meta_creation_time_ns,
                accepted.transactions_commitment,
            ),
            Err(RbcError::HeaderContentTooLarge)
        );
    }

    #[test]
    fn committee_id_is_stable_and_configuration_sensitive() {
        let committee = Committee::new_test(vec![1, 2, 3, 4]);
        let same_committee: Committee =
            serde_yaml::from_str(&serde_yaml::to_string(&*committee).unwrap()).unwrap();
        let changed_stake = Committee::new_test(vec![1, 2, 3, 5]);

        let id = RbcCommitteeId::derive(&committee).unwrap();
        assert_eq!(
            hex::encode(id.0),
            "b64d92de81940c0965e6b8abc7b0b8ff409e3399343e6206d26be20f768fe970"
        );
        assert_eq!(id, RbcCommitteeId::derive(&same_committee).unwrap());
        assert_ne!(id, RbcCommitteeId::derive(&changed_stake).unwrap());
    }

    #[test]
    fn committee_id_encodes_authority_indices_above_255() {
        let committee = Committee::new_test(vec![1; 300]);
        let id = RbcCommitteeId::derive(&committee).unwrap();
        let round_trip: Committee =
            serde_yaml::from_str(&serde_yaml::to_string(&*committee).unwrap()).unwrap();

        assert_eq!(id, RbcCommitteeId::derive(&round_trip).unwrap());
        assert_ne!(
            id,
            RbcCommitteeId::derive(&Committee::new_test(vec![1; 299])).unwrap()
        );
    }

    #[test]
    fn oversized_deserialized_committee_is_rejected_before_authority_set_use() {
        let committee = Committee::new_test(vec![1; MAX_COMMITTEE_SIZE as usize]);
        let mut value = serde_yaml::to_value(committee.as_ref()).unwrap();
        let authorities = value
            .as_mapping_mut()
            .unwrap()
            .get_mut(serde_yaml::Value::String("authorities".to_owned()))
            .unwrap()
            .as_sequence_mut()
            .unwrap();
        authorities.push(authorities[0].clone());
        let oversized = Arc::new(serde_yaml::from_value::<Committee>(value).unwrap());

        assert_eq!(oversized.len(), MAX_COMMITTEE_SIZE as usize + 1);
        let error = StarfishRbcKernel::new(
            oversized,
            0,
            instance(TEST_INSTANCE_BYTE),
            BlockAuthenticationScheme::Ed25519,
            Arc::new(Vec::new()),
            0,
        )
        .err()
        .unwrap();
        assert_eq!(
            error,
            RbcError::CommitteeTooLarge(MAX_COMMITTEE_SIZE as usize + 1)
        );
    }

    #[test]
    fn inconsistent_deserialized_threshold_is_rejected_and_changes_id() {
        let committee = Committee::new_test(vec![1, 1, 1, 1]);
        let yaml = serde_yaml::to_string(&*committee).unwrap();
        let tampered_yaml = yaml.replacen("validity_threshold: 1", "validity_threshold: 2", 1);
        assert_ne!(yaml, tampered_yaml);
        let tampered: Committee = serde_yaml::from_str(&tampered_yaml).unwrap();

        assert_ne!(
            RbcCommitteeId::derive(&committee).unwrap(),
            RbcCommitteeId::derive(&tampered).unwrap()
        );
        let error = StarfishRbcKernel::new(
            Arc::new(tampered),
            0,
            instance(TEST_INSTANCE_BYTE),
            BlockAuthenticationScheme::Ed25519,
            Arc::new(mac_keyrings_for_test(4)[0].clone()),
            0,
        )
        .err()
        .unwrap();
        assert!(matches!(error, RbcError::InvalidValidityThreshold { .. }));
    }

    #[test]
    fn protocol_instance_and_keyring_are_validated() {
        assert_eq!(
            RbcProtocolInstanceId::new([0; 32]),
            Err(RbcError::ZeroProtocolInstance)
        );
        let encoded = bincode::serialize(&[0u8; PROTOCOL_INSTANCE_SIZE]).unwrap();
        assert!(bincode::deserialize::<RbcProtocolInstanceId>(&encoded).is_err());
        let expected = instance(TEST_INSTANCE_BYTE);
        assert_eq!(
            bincode::deserialize::<RbcProtocolInstanceId>(&bincode::serialize(&expected).unwrap())
                .unwrap(),
            expected
        );
        let committee = Committee::new_test(vec![1; 4]);
        let error = StarfishRbcKernel::new(
            committee,
            0,
            instance(TEST_INSTANCE_BYTE),
            BlockAuthenticationScheme::Ed25519,
            Arc::new(Vec::new()),
            0,
        )
        .err()
        .unwrap();
        assert_eq!(
            error,
            RbcError::InvalidKeyringLength {
                expected: 4,
                actual: 0,
            }
        );
    }

    #[test]
    fn initial_mac_is_recipient_specific_and_direct_author_bound() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let author = kernel(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::MacVector,
        );
        let recipient = kernel(
            Arc::clone(&committee),
            &keyrings,
            1,
            BlockAuthenticationScheme::MacVector,
        );
        let other_recipient = kernel(
            Arc::clone(&committee),
            &keyrings,
            2,
            BlockAuthenticationScheme::MacVector,
        );
        let block_ref = block(0, 7, 0x44);
        let tag = author
            .make_initial_mac_tag_for_reference(block_ref, 1)
            .unwrap();

        recipient
            .verify_initial_mac_tag(0, block_ref, &tag)
            .unwrap();
        assert_eq!(
            other_recipient.verify_initial_mac_tag(0, block_ref, &tag),
            Err(RbcError::InvalidInitialTag)
        );
        assert!(matches!(
            recipient.verify_initial_mac_tag(2, block_ref, &tag),
            Err(RbcError::InitialAuthorMismatch { .. })
        ));
    }

    #[test]
    fn signature_digest_binds_context_scheme_and_reference() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let ed25519 = kernel_with_instance(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::Ed25519,
            0x11,
        );
        let ml_dsa = kernel_with_instance(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::MlDsa44,
            0x11,
        );
        let other_instance = kernel_with_instance(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::Ed25519,
            0x22,
        );
        let mac = kernel(
            committee,
            &keyrings,
            0,
            BlockAuthenticationScheme::MacVector,
        );
        let first = block(0, 9, 0x10);
        let second = block(0, 9, 0x11);

        assert_ne!(
            ed25519.initial_signature_digest(first).unwrap(),
            ed25519.initial_signature_digest(second).unwrap()
        );
        assert_ne!(
            ed25519.initial_signature_digest(first).unwrap(),
            ml_dsa.initial_signature_digest(first).unwrap()
        );
        assert_ne!(
            ed25519.initial_signature_digest(first).unwrap(),
            other_instance.initial_signature_digest(first).unwrap()
        );
        assert_eq!(
            mac.initial_signature_digest(first),
            Err(RbcError::InitialSignatureRequiresSignatureAuthentication)
        );
    }

    #[test]
    fn typed_initial_proofs_gate_echo_for_every_authentication_scheme() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let canonical = valid_canonical_header(0, 5, 0x20);
        let block_ref = canonical.reference();

        for authentication in [
            BlockAuthenticationScheme::Ed25519,
            BlockAuthenticationScheme::MlDsa44,
            BlockAuthenticationScheme::MlDsa65,
            BlockAuthenticationScheme::MacVector,
        ] {
            let mut receiver = kernel(Arc::clone(&committee), &keyrings, 1, authentication);
            let proof = match authentication {
                BlockAuthenticationScheme::Ed25519 => {
                    let digest = receiver.initial_signature_digest(block_ref).unwrap();
                    RbcInitialProof::Ed25519(dummy_signer().sign_digest(&digest))
                }
                BlockAuthenticationScheme::MlDsa44 => {
                    let digest =
                        BlockDigest::from(receiver.initial_signature_digest(block_ref).unwrap());
                    RbcInitialProof::MlDsa44(dummy_ml_dsa_44_signer().sign_digest(&digest))
                }
                BlockAuthenticationScheme::MlDsa65 => {
                    let digest =
                        BlockDigest::from(receiver.initial_signature_digest(block_ref).unwrap());
                    RbcInitialProof::MlDsa65(dummy_ml_dsa_65_signer().sign_digest(&digest))
                }
                BlockAuthenticationScheme::MacVector => {
                    let author = kernel(
                        Arc::clone(&committee),
                        &keyrings,
                        0,
                        BlockAuthenticationScheme::MacVector,
                    );
                    RbcInitialProof::Mac(
                        author
                            .make_initial_mac_tag_for_reference(block_ref, 1)
                            .unwrap(),
                    )
                }
            };
            let outcome = receiver
                .accept_direct_initial_header(0, canonical.clone(), &proof)
                .unwrap();
            assert!(matches!(outcome,
                RbcInitialHeaderOutcome::Authenticated { effects }
                    if matches!(effects.as_slice(), [RbcEffect::MulticastPhase {
                    phase: RbcPhase::Echo,
                    ..
                }])
            ));
        }
    }

    #[test]
    fn invalid_initial_proof_still_allows_content_recovery_without_echo() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let canonical = valid_canonical_header(0, 5, 0x25);
        let block_ref = canonical.reference();
        let mut receiver = kernel(committee, &keyrings, 1, BlockAuthenticationScheme::Ed25519);
        let invalid = RbcInitialProof::Ed25519(SignatureBytes::default());

        let outcome = receiver
            .accept_direct_initial_header(0, canonical, &invalid)
            .unwrap();
        assert!(matches!(
            outcome,
            RbcInitialHeaderOutcome::StagedUnauthenticated {
                effects,
                error: RbcError::InvalidInitialProof,
            } if effects.is_empty()
        ));
        let slot = receiver.slot(&block_ref).unwrap();
        assert_eq!(slot.echoed, None);
        assert_eq!(
            slot.candidates
                .get(&block_ref)
                .and_then(|candidate| candidate.header.as_ref())
                .map(PinnedRbcHeader::reference),
            Some(block_ref)
        );

        assert!(
            receiver
                .accept_recovered_header(valid_canonical_header(0, 5, 0x25))
                .unwrap()
                .is_empty()
        );

        assert_eq!(
            RbcInitialProof::from_block_authentication(&BlockAuthentication::MacVector(vec![])),
            Err(RbcError::InvalidInitialProof)
        );
    }

    #[test]
    fn pinned_headers_and_echo_capabilities_are_kernel_bound() {
        let committee_a = Committee::new_test(vec![1; 4]);
        let committee_b = Committee::new_test(vec![1, 1, 1, 10]);
        let keyrings = mac_keyrings_for_test(4);
        let canonical = valid_canonical_header(0, 5, 0xA8);
        let block_ref = canonical.reference();
        let pin_a = PinnedRbcHeader::validate(canonical.clone(), &committee_a).unwrap();
        assert_eq!(
            PinnedRbcHeader::validate(canonical.clone(), &committee_b),
            Err(RbcError::InvalidThresholdClock)
        );

        let mut committee_b_kernel = kernel(
            committee_b,
            &keyrings,
            1,
            BlockAuthenticationScheme::Ed25519,
        );
        assert_eq!(
            committee_b_kernel.note_header_available(pin_a.clone()),
            Err(RbcError::PinnedHeaderCommitteeMismatch)
        );
        assert!(committee_b_kernel.slots.is_empty());

        let author = kernel(
            Arc::clone(&committee_a),
            &keyrings,
            0,
            BlockAuthenticationScheme::MacVector,
        );
        let receiver_one = kernel(
            Arc::clone(&committee_a),
            &keyrings,
            1,
            BlockAuthenticationScheme::MacVector,
        );
        let proof = RbcInitialProof::Mac(
            author
                .make_initial_mac_tag_for_reference(block_ref, 1)
                .unwrap(),
        );
        let eligible_for_one = receiver_one
            .direct_initial_header(0, pin_a.clone(), &proof)
            .unwrap();
        let mut receiver_two = kernel(
            Arc::clone(&committee_a),
            &keyrings,
            2,
            BlockAuthenticationScheme::MacVector,
        );
        assert!(matches!(
            receiver_two.accept_direct_initial_header(1, canonical, &proof),
            Err(RbcError::InitialAuthorMismatch { .. })
        ));
        assert!(receiver_two.slots.is_empty());
        assert_eq!(
            receiver_two.accept_initial_header(eligible_for_one),
            Err(RbcError::EchoCapabilityContextMismatch)
        );
        assert!(receiver_two.slots.is_empty());

        let eligible_for_instance = receiver_one
            .direct_initial_header(0, pin_a, &proof)
            .unwrap();
        let mut other_instance = kernel_with_instance(
            committee_a,
            &keyrings,
            1,
            BlockAuthenticationScheme::MacVector,
            0xB6,
        );
        assert_eq!(
            other_instance.accept_initial_header(eligible_for_instance),
            Err(RbcError::EchoCapabilityContextMismatch)
        );
        assert!(other_instance.slots.is_empty());
    }

    #[test]
    fn invalid_initial_proof_preserves_ready_effect_unblocked_by_staging() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let canonical = valid_canonical_header(0, 7, 0xB7);
        let block_ref = canonical.reference();
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            3,
            BlockAuthenticationScheme::Ed25519,
        );

        for sender in 0..3 {
            let message = phase_message(
                Arc::clone(&committee),
                &keyrings,
                sender,
                3,
                RbcPhase::Echo,
                block_ref,
            );
            receiver.handle_phase(sender, message).unwrap();
        }
        let outcome = receiver
            .accept_direct_initial_header(
                0,
                canonical,
                &RbcInitialProof::Ed25519(SignatureBytes::default()),
            )
            .unwrap();
        assert!(matches!(
            outcome,
            RbcInitialHeaderOutcome::StagedUnauthenticated {
                effects,
                error: RbcError::InvalidInitialProof,
            } if effects == vec![RbcEffect::MulticastPhase {
                phase: RbcPhase::Ready,
                block_ref,
            }]
        ));
        let slot = receiver.slot(&block_ref).unwrap();
        assert_eq!(slot.echoed, None);
        assert_eq!(slot.readied, Some(block_ref));
        assert!(slot.candidates[&block_ref].header.is_some());
    }

    #[test]
    fn local_initial_constructor_binds_the_local_author_and_content() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let mut kernel = kernel(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::Ed25519,
        );
        let template = valid_canonical_header(1, 5, 0x27);

        let local = kernel
            .start_local_initial_header(
                template.reference.round,
                template.block_references.clone(),
                template.acknowledgment_references(),
                template.meta_creation_time_ns,
                template.transactions_commitment,
            )
            .unwrap();
        assert!(kernel.make_local_initial_signature_digest(&local).is_ok());
        let other_instance = kernel_with_instance(
            committee,
            &keyrings,
            0,
            BlockAuthenticationScheme::Ed25519,
            0xB8,
        );
        assert_eq!(
            other_instance.make_local_initial_signature_digest(&local),
            Err(RbcError::LocalInitialContextMismatch)
        );
        assert!(matches!(
            kernel.start_local_initial_header(
                template.reference.round,
                template.block_references.clone(),
                template.acknowledgment_references(),
                template.meta_creation_time_ns + 1,
                template.transactions_commitment,
            ),
            Err(RbcError::ConflictingInitialHeader { .. })
        ));
        let (pinned, effects) = local.into_parts();
        assert_eq!(pinned.reference().authority, 0);
        assert_ne!(pinned.reference(), template.reference());
        assert!(matches!(
            effects.as_slice(),
            [RbcEffect::MulticastPhase {
                phase: RbcPhase::Echo,
                ..
            }]
        ));

        assert!(matches!(
            kernel.start_local_initial_header(
                6,
                template.block_references[..2].to_vec(),
                Vec::new(),
                template.meta_creation_time_ns,
                template.transactions_commitment,
            ),
            Err(RbcError::InvalidThresholdClock)
        ));
    }

    #[test]
    fn phase_messages_are_specialized_for_each_recipient() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let mut sender = kernel(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::Ed25519,
        );
        let block_ref = block(0, 3, 0x21);
        authorize_echo(&mut sender, block_ref);
        let messages: Vec<_> = (1..4)
            .map(|recipient| {
                sender
                    .make_phase_message(RbcPhase::Echo, block_ref, recipient)
                    .unwrap()
            })
            .collect();
        assert_eq!(
            hex::encode(messages[0].tag.as_ref()),
            "4a7a795ced01bb5fa2856de4b6664947e6564c8bc250c81a3073735346febf58"
        );
        assert_eq!(
            hex::encode(bincode::serialize(&messages[0]).unwrap()),
            concat!(
                "030000000000200000000000000021212121212121212121212121212121212121212121",
                "21212121212121212121000001000000000020000000000000004a7a795ced01bb5fa2",
                "856de4b6664947e6564c8bc250c81a3073735346febf58"
            )
        );
        let distinct_tags: HashSet<_> = messages.iter().map(|message| message.tag).collect();
        assert_eq!(distinct_tags.len(), 3);

        for message in messages {
            let recipient = message.recipient;
            let mut receiver = kernel(
                Arc::clone(&committee),
                &keyrings,
                recipient,
                BlockAuthenticationScheme::Ed25519,
            );
            assert!(receiver.handle_phase(0, message).is_ok());
        }
    }

    #[test]
    fn phase_message_materialization_requires_authorized_local_state() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let first = block(0, 3, 0x23);
        let conflicting = block(0, 3, 0x24);
        let mut sender = kernel(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::Ed25519,
        );

        assert!(matches!(
            sender.make_phase_message(RbcPhase::Echo, first, 1),
            Err(RbcError::PhaseNotAuthorized { .. })
        ));
        sender
            .note_header_available(pinned_header(&committee, first))
            .unwrap();
        assert!(matches!(
            sender.make_phase_message(RbcPhase::Echo, first, 1),
            Err(RbcError::PhaseNotAuthorized { .. })
        ));

        assert!(matches!(
            sender.authorize_echo(first).unwrap().as_slice(),
            [RbcEffect::MulticastPhase {
                phase: RbcPhase::Echo,
                ..
            }]
        ));
        let first_message = sender.make_phase_message(RbcPhase::Echo, first, 1).unwrap();
        assert_eq!(
            first_message,
            sender.make_phase_message(RbcPhase::Echo, first, 1).unwrap()
        );

        sender
            .note_header_available(pinned_header(&committee, conflicting))
            .unwrap();
        assert!(sender.authorize_echo(conflicting).unwrap().is_empty());
        assert!(matches!(
            sender.make_phase_message(RbcPhase::Echo, conflicting, 1),
            Err(RbcError::PhaseNotAuthorized { .. })
        ));
        assert!(matches!(
            sender.make_phase_message(RbcPhase::Ready, first, 1),
            Err(RbcError::PhaseNotAuthorized { .. })
        ));

        for peer in [1, 2] {
            let message = phase_message(
                Arc::clone(&committee),
                &keyrings,
                peer,
                0,
                RbcPhase::Echo,
                first,
            );
            sender.handle_phase(peer, message).unwrap();
        }
        assert!(sender.make_phase_message(RbcPhase::Ready, first, 1).is_ok());
    }

    #[test]
    fn phase_macs_work_under_every_initial_authentication_mode() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let block_ref = block(0, 3, 0x22);

        for authentication in [
            BlockAuthenticationScheme::Ed25519,
            BlockAuthenticationScheme::MlDsa44,
            BlockAuthenticationScheme::MlDsa65,
            BlockAuthenticationScheme::MacVector,
        ] {
            let mut sender = kernel(Arc::clone(&committee), &keyrings, 0, authentication);
            let mut receiver = kernel(Arc::clone(&committee), &keyrings, 1, authentication);
            authorize_echo(&mut sender, block_ref);
            let message = sender
                .make_phase_message(RbcPhase::Echo, block_ref, 1)
                .unwrap();
            assert!(receiver.handle_phase(0, message).is_ok());
        }
    }

    #[test]
    fn every_authenticated_phase_field_and_direct_peer_are_checked() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let mut sender = kernel(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::Ed25519,
        );
        let block_ref = block(0, 5, 0x31);
        authorize_echo(&mut sender, block_ref);
        let valid = sender
            .make_phase_message(RbcPhase::Echo, block_ref, 1)
            .unwrap();

        let mut wrong_phase = valid.clone();
        wrong_phase.phase = RbcPhase::Ready;
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            1,
            BlockAuthenticationScheme::Ed25519,
        );
        assert_eq!(
            receiver.handle_phase(0, wrong_phase),
            Err(RbcError::InvalidPhaseTag)
        );
        assert!(receiver.slots.is_empty());

        let mut wrong_digest = valid.clone();
        wrong_digest.block_ref.digest = BlockDigest::from([0x32; 32]);
        assert_eq!(
            receiver.handle_phase(0, wrong_digest),
            Err(RbcError::InvalidPhaseTag)
        );
        assert!(receiver.slots.is_empty());

        let mut wrong_author = valid.clone();
        wrong_author.block_ref.authority = 1;
        assert_eq!(
            receiver.handle_phase(0, wrong_author),
            Err(RbcError::InvalidPhaseTag)
        );
        assert!(receiver.slots.is_empty());

        let mut wrong_round = valid.clone();
        wrong_round.block_ref.round += 1;
        assert_eq!(
            receiver.handle_phase(0, wrong_round),
            Err(RbcError::InvalidPhaseTag)
        );
        assert!(receiver.slots.is_empty());

        let mut wrong_sender = valid.clone();
        wrong_sender.sender = 2;
        assert_eq!(
            receiver.handle_phase(2, wrong_sender),
            Err(RbcError::InvalidPhaseTag)
        );
        assert!(receiver.slots.is_empty());

        assert!(matches!(
            receiver.handle_phase(2, valid.clone()),
            Err(RbcError::SenderPeerMismatch { .. })
        ));
        assert!(receiver.slots.is_empty());

        let mut wrong_recipient = valid.clone();
        wrong_recipient.recipient = 2;
        assert!(matches!(
            receiver.handle_phase(0, wrong_recipient),
            Err(RbcError::WrongRecipient { .. })
        ));
        assert!(receiver.slots.is_empty());

        let mut other_instance = kernel_with_instance(
            Arc::clone(&committee),
            &keyrings,
            1,
            BlockAuthenticationScheme::Ed25519,
            0xBB,
        );
        assert_eq!(
            other_instance.handle_phase(0, valid.clone()),
            Err(RbcError::InvalidPhaseTag)
        );
        assert!(other_instance.slots.is_empty());

        let mut other_scheme = kernel_with_instance(
            Arc::clone(&committee),
            &keyrings,
            1,
            BlockAuthenticationScheme::MlDsa44,
            TEST_INSTANCE_BYTE,
        );
        assert_eq!(
            other_scheme.handle_phase(0, valid.clone()),
            Err(RbcError::InvalidPhaseTag)
        );
        assert!(other_scheme.slots.is_empty());

        let changed_committee = Committee::new_test(vec![2, 1, 1, 1]);
        let mut other_committee = kernel(
            changed_committee,
            &keyrings,
            1,
            BlockAuthenticationScheme::Ed25519,
        );
        assert_eq!(
            other_committee.handle_phase(0, valid),
            Err(RbcError::InvalidPhaseTag)
        );
        assert!(other_committee.slots.is_empty());
    }

    #[test]
    fn initial_mac_cannot_be_substituted_for_phase_mac() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let mut sender = kernel(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::MacVector,
        );
        let mut receiver = kernel(
            committee,
            &keyrings,
            1,
            BlockAuthenticationScheme::MacVector,
        );
        let block_ref = block(0, 5, 0x41);
        authorize_echo(&mut sender, block_ref);
        let mut message = sender
            .make_phase_message(RbcPhase::Echo, block_ref, 1)
            .unwrap();
        message.tag = sender
            .make_initial_mac_tag_for_reference(block_ref, 1)
            .unwrap();

        assert_eq!(
            receiver.handle_phase(0, message),
            Err(RbcError::InvalidPhaseTag)
        );
        assert!(receiver.slots.is_empty());
    }

    #[test]
    fn truncated_phase_message_fails_deserialization() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let mut sender = kernel(committee, &keyrings, 0, BlockAuthenticationScheme::Ed25519);
        let block_ref = block(0, 5, 0x43);
        authorize_echo(&mut sender, block_ref);
        let message = sender
            .make_phase_message(RbcPhase::Echo, block_ref, 1)
            .unwrap();
        let mut encoded = bincode::serialize(&message).unwrap();
        encoded.pop();

        assert!(bincode::deserialize::<RbcPhaseMessage>(&encoded).is_err());
    }

    #[test]
    fn symmetric_key_cannot_reflect_message_direction() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let mut sender = kernel(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::Ed25519,
        );
        let block_ref = block(0, 5, 0x42);
        authorize_echo(&mut sender, block_ref);
        let mut reflected = sender
            .make_phase_message(RbcPhase::Echo, block_ref, 1)
            .unwrap();
        reflected.sender = 1;
        reflected.recipient = 0;
        let mut receiver = kernel(committee, &keyrings, 0, BlockAuthenticationScheme::Ed25519);

        assert_eq!(
            receiver.handle_phase(1, reflected),
            Err(RbcError::InvalidPhaseTag)
        );
        assert!(receiver.slots.is_empty());
    }

    #[test]
    fn echo_quorum_without_header_latches_fetch_then_ready() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let block_ref = block(0, 4, 0x51);
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            3,
            BlockAuthenticationScheme::Ed25519,
        );

        for sender in 0..2 {
            let message = phase_message(
                Arc::clone(&committee),
                &keyrings,
                sender,
                3,
                RbcPhase::Echo,
                block_ref,
            );
            assert!(receiver.handle_phase(sender, message).unwrap().is_empty());
        }
        let message = phase_message(
            Arc::clone(&committee),
            &keyrings,
            2,
            3,
            RbcPhase::Echo,
            block_ref,
        );
        let effects = receiver.handle_phase(2, message).unwrap();
        let mut expected_holders = AuthoritySet::default();
        expected_holders.insert(0);
        expected_holders.insert(1);
        expected_holders.insert(2);
        assert_eq!(
            effects,
            vec![RbcEffect::NeedHeader {
                block_ref,
                holders: expected_holders,
            }]
        );
        assert_eq!(
            holder_vec(receiver.header_holders(&block_ref)),
            vec![0, 1, 2]
        );

        assert_eq!(
            receiver
                .note_header_available(pinned_header(&committee, block_ref))
                .unwrap(),
            vec![RbcEffect::MulticastPhase {
                phase: RbcPhase::Ready,
                block_ref,
            }]
        );
    }

    #[test]
    fn ready_validity_without_header_can_ready_and_deliver_after_fetch() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let block_ref = block(0, 4, 0x52);
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            3,
            BlockAuthenticationScheme::Ed25519,
        );

        let first = phase_message(
            Arc::clone(&committee),
            &keyrings,
            0,
            3,
            RbcPhase::Ready,
            block_ref,
        );
        assert!(receiver.handle_phase(0, first).unwrap().is_empty());
        let second = phase_message(
            Arc::clone(&committee),
            &keyrings,
            1,
            3,
            RbcPhase::Ready,
            block_ref,
        );
        assert!(matches!(
            receiver.handle_phase(1, second).unwrap().as_slice(),
            [RbcEffect::NeedHeader { .. }]
        ));

        assert_eq!(
            receiver
                .note_header_available(pinned_header(&committee, block_ref))
                .unwrap(),
            vec![
                RbcEffect::MulticastPhase {
                    phase: RbcPhase::Ready,
                    block_ref,
                },
                RbcEffect::Deliver(pinned_header(&committee, block_ref)),
            ]
        );
    }

    #[test]
    fn header_fetch_can_retry_and_reemits_when_holder_set_grows() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let block_ref = block(0, 4, 0x54);
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            3,
            BlockAuthenticationScheme::Ed25519,
        );

        let first = phase_message(
            Arc::clone(&committee),
            &keyrings,
            0,
            3,
            RbcPhase::Ready,
            block_ref,
        );
        assert!(receiver.handle_phase(0, first).unwrap().is_empty());
        let second = phase_message(
            Arc::clone(&committee),
            &keyrings,
            1,
            3,
            RbcPhase::Ready,
            block_ref,
        );
        let initial_request = receiver.handle_phase(1, second).unwrap();
        assert_eq!(
            receiver.retry_header_request(block_ref).unwrap(),
            initial_request.first().cloned()
        );

        let third = phase_message(
            Arc::clone(&committee),
            &keyrings,
            2,
            3,
            RbcPhase::Ready,
            block_ref,
        );
        let expanded_request = receiver.handle_phase(2, third).unwrap();
        assert!(matches!(
            expanded_request.as_slice(),
            [RbcEffect::NeedHeader { holders, .. }] if holder_vec(*holders) == vec![0, 1, 2]
        ));
        assert_eq!(
            receiver.retry_header_request(block_ref).unwrap(),
            expanded_request.first().cloned()
        );

        receiver
            .note_header_available(pinned_header(&committee, block_ref))
            .unwrap();
        assert_eq!(receiver.retry_header_request(block_ref).unwrap(), None);
    }

    #[test]
    fn ready_quorum_never_delivers_before_header_arrives() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let block_ref = block(0, 4, 0x53);
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            3,
            BlockAuthenticationScheme::Ed25519,
        );

        for sender in 0..3 {
            let message = phase_message(
                Arc::clone(&committee),
                &keyrings,
                sender,
                3,
                RbcPhase::Ready,
                block_ref,
            );
            receiver.handle_phase(sender, message).unwrap();
        }
        assert_eq!(receiver.slot(&block_ref).unwrap().delivered, None);

        assert_eq!(
            receiver
                .note_header_available(pinned_header(&committee, block_ref))
                .unwrap(),
            vec![
                RbcEffect::MulticastPhase {
                    phase: RbcPhase::Ready,
                    block_ref,
                },
                RbcEffect::Deliver(pinned_header(&committee, block_ref)),
            ]
        );
    }

    #[test]
    fn duplicates_do_not_inflate_phase_stake() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let block_ref = block(0, 6, 0x61);
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            3,
            BlockAuthenticationScheme::Ed25519,
        );
        receiver
            .note_header_available(pinned_header(&committee, block_ref))
            .unwrap();

        for sender in [0, 0, 1] {
            let message = phase_message(
                Arc::clone(&committee),
                &keyrings,
                sender,
                3,
                RbcPhase::Echo,
                block_ref,
            );
            assert!(receiver.handle_phase(sender, message).unwrap().is_empty());
        }
        let message = phase_message(
            Arc::clone(&committee),
            &keyrings,
            2,
            3,
            RbcPhase::Echo,
            block_ref,
        );
        assert!(matches!(
            receiver.handle_phase(2, message).unwrap().as_slice(),
            [RbcEffect::MulticastPhase {
                phase: RbcPhase::Ready,
                ..
            }]
        ));
    }

    #[test]
    fn slot_global_echo_does_not_first_seen_lock_other_candidate() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let first = block(0, 8, 0x71);
        let quorum_candidate = block(0, 8, 0x72);
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            0,
            BlockAuthenticationScheme::Ed25519,
        );
        receiver
            .note_header_available(pinned_header(&committee, first))
            .unwrap();
        assert!(matches!(
            receiver.authorize_echo(first).unwrap().as_slice(),
            [RbcEffect::MulticastPhase {
                phase: RbcPhase::Echo,
                ..
            }]
        ));
        receiver
            .note_header_available(pinned_header(&committee, quorum_candidate))
            .unwrap();
        assert!(
            receiver
                .authorize_echo(quorum_candidate)
                .unwrap()
                .is_empty()
        );

        let mut last_effects = Vec::new();
        for sender in 1..4 {
            let message = phase_message(
                Arc::clone(&committee),
                &keyrings,
                sender,
                0,
                RbcPhase::Echo,
                quorum_candidate,
            );
            last_effects = receiver.handle_phase(sender, message).unwrap();
        }
        assert_eq!(
            last_effects,
            vec![RbcEffect::MulticastPhase {
                phase: RbcPhase::Ready,
                block_ref: quorum_candidate,
            }]
        );
        let slot = receiver.slot(&first).unwrap();
        assert_eq!(slot.echoed, Some(first));
        assert_eq!(slot.readied, Some(quorum_candidate));
    }

    #[test]
    fn phase_equivocation_is_ignored_and_delivery_is_slot_global() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let first = block(0, 10, 0x81);
        let second = block(0, 10, 0x82);
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            3,
            BlockAuthenticationScheme::Ed25519,
        );
        receiver
            .note_header_available(pinned_header(&committee, first))
            .unwrap();
        receiver
            .note_header_available(pinned_header(&committee, second))
            .unwrap();

        for candidate in [first, second] {
            let message = phase_message(
                Arc::clone(&committee),
                &keyrings,
                0,
                3,
                RbcPhase::Echo,
                candidate,
            );
            receiver.handle_phase(0, message).unwrap();
        }
        assert!(receiver.candidate(&first).unwrap().echoes.votes.contains(0));
        assert!(
            !receiver
                .candidate(&second)
                .unwrap()
                .echoes
                .votes
                .contains(0)
        );

        for sender in 0..2 {
            let message = phase_message(
                Arc::clone(&committee),
                &keyrings,
                sender,
                3,
                RbcPhase::Ready,
                first,
            );
            receiver.handle_phase(sender, message).unwrap();
        }
        assert_eq!(receiver.slot(&first).unwrap().delivered, Some(first));

        for sender in 0..3 {
            let message = phase_message(
                Arc::clone(&committee),
                &keyrings,
                sender,
                3,
                RbcPhase::Ready,
                second,
            );
            assert!(receiver.handle_phase(sender, message).unwrap().is_empty());
        }
        assert_eq!(receiver.slot(&second).unwrap().delivered, Some(first));
    }

    #[test]
    fn four_kernel_split_initial_values_converge_on_at_most_one_delivery() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let first_header = valid_canonical_header(0, 12, 0xA1);
        let conflicting_header = valid_canonical_header(0, 12, 0xA2);
        let first = first_header.reference();
        let conflicting = conflicting_header.reference();
        let mut kernels: Vec<_> = (0..4)
            .map(|authority| {
                kernel(
                    Arc::clone(&committee),
                    &keyrings,
                    authority,
                    BlockAuthenticationScheme::Ed25519,
                )
            })
            .collect();
        let mut header_stores = vec![AHashMap::new(); 4];

        let mut initial_effects = Vec::new();
        let local = kernels[0]
            .start_local_initial_header(
                first_header.reference.round,
                first_header.block_references.clone(),
                first_header.acknowledgment_references(),
                first_header.meta_creation_time_ns,
                first_header.transactions_commitment,
            )
            .unwrap();
        assert_eq!(local.header(), &first_header);
        let first_signature_digest = kernels[0]
            .make_local_initial_signature_digest(&local)
            .unwrap();
        let first_proof =
            RbcInitialProof::Ed25519(dummy_signer().sign_digest(&first_signature_digest));
        let (local_header, local_effects) = local.into_parts();
        header_stores[0].insert(first, local_header.header().clone());
        initial_effects.push((0, local_effects));

        for authority in 1..3 {
            let outcome = kernels[authority as usize]
                .accept_direct_initial_header(0, first_header.clone(), &first_proof)
                .unwrap();
            let RbcInitialHeaderOutcome::Authenticated { effects } = outcome else {
                panic!("valid direct initial header must authenticate")
            };
            header_stores[authority as usize].insert(first, first_header.clone());
            initial_effects.push((authority, effects));
        }

        let conflicting_digest = kernels[3].initial_signature_digest(conflicting).unwrap();
        let conflicting_proof =
            RbcInitialProof::Ed25519(dummy_signer().sign_digest(&conflicting_digest));
        let outcome = kernels[3]
            .accept_direct_initial_header(0, conflicting_header.clone(), &conflicting_proof)
            .unwrap();
        let RbcInitialHeaderOutcome::Authenticated { effects } = outcome else {
            panic!("valid conflicting author proof must authenticate at its recipient")
        };
        header_stores[3].insert(conflicting, conflicting_header);
        initial_effects.push((3, effects));

        let (deliveries, recoveries) =
            pump_phase_effects(&mut kernels, initial_effects, &mut header_stores);
        assert!(deliveries.iter().all(|delivered| delivered == &[first]));
        assert!(
            deliveries
                .iter()
                .flatten()
                .all(|delivered| *delivered != conflicting)
        );
        assert!(
            recoveries
                .iter()
                .any(|(requester, _, block_ref)| *requester == 3 && *block_ref == first)
        );
        assert_eq!(kernels[3].slot(&first).unwrap().echoed, Some(conflicting));
        assert_eq!(kernels[3].slot(&first).unwrap().readied, Some(first));
    }

    #[test]
    fn poisoned_initial_mac_does_not_block_rbc_totality() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let canonical = valid_canonical_header(0, 13, 0xA3);
        let block_ref = canonical.reference();
        let mut kernels: Vec<_> = (0..4)
            .map(|authority| {
                kernel(
                    Arc::clone(&committee),
                    &keyrings,
                    authority,
                    BlockAuthenticationScheme::MacVector,
                )
            })
            .collect();
        let mut header_stores = vec![AHashMap::new(); 4];

        let local = kernels[0]
            .start_local_initial_header(
                canonical.reference.round,
                canonical.block_references.clone(),
                canonical.acknowledgment_references(),
                canonical.meta_creation_time_ns,
                canonical.transactions_commitment,
            )
            .unwrap();
        let valid_for_one = kernels[0].make_local_initial_mac_tag(&local, 1).unwrap();
        let valid_for_two = kernels[0].make_local_initial_mac_tag(&local, 2).unwrap();
        let (local_header, local_effects) = local.into_parts();
        header_stores[0].insert(block_ref, local_header.header().clone());
        let mut initial_effects = vec![(0, local_effects)];
        for (authority, tag) in [(1, valid_for_one), (2, valid_for_two)] {
            let outcome = kernels[authority as usize]
                .accept_direct_initial_header(0, canonical.clone(), &RbcInitialProof::Mac(tag))
                .unwrap();
            let RbcInitialHeaderOutcome::Authenticated { effects } = outcome else {
                panic!("recipient-specific author MAC must authenticate")
            };
            header_stores[authority as usize].insert(block_ref, canonical.clone());
            initial_effects.push((authority, effects));
        }

        let poisoned = kernels[3]
            .accept_direct_initial_header(
                0,
                canonical.clone(),
                &RbcInitialProof::Mac(valid_for_two),
            )
            .unwrap();
        assert!(matches!(
            poisoned,
            RbcInitialHeaderOutcome::StagedUnauthenticated {
                effects,
                error: RbcError::InvalidInitialTag,
            } if effects.is_empty()
        ));
        header_stores[3].insert(block_ref, canonical);

        let (deliveries, recoveries) =
            pump_phase_effects(&mut kernels, initial_effects, &mut header_stores);
        assert!(deliveries.iter().all(|delivered| delivered == &[block_ref]));
        assert!(recoveries.is_empty());
        let recovered_slot = kernels[3].slot(&block_ref).unwrap();
        assert_eq!(recovered_slot.echoed, None);
        assert_eq!(recovered_slot.readied, Some(block_ref));
        assert_eq!(recovered_slot.delivered, Some(block_ref));
    }

    #[test]
    fn weighted_thresholds_and_author_echo_are_counted_exactly() {
        let committee = Committee::new_test(vec![3, 2, 1, 1]);
        assert_eq!(committee.validity_threshold(), 3);
        assert_eq!(committee.quorum_threshold(), 5);
        let keyrings = mac_keyrings_for_test(4);
        let block_ref = block(3, 11, 0x91);
        let mut receiver = kernel(
            Arc::clone(&committee),
            &keyrings,
            3,
            BlockAuthenticationScheme::Ed25519,
        );
        receiver
            .note_header_available(pinned_header(&committee, block_ref))
            .unwrap();
        assert_eq!(
            receiver.authorize_echo(block_ref).unwrap(),
            vec![RbcEffect::MulticastPhase {
                phase: RbcPhase::Echo,
                block_ref,
            }]
        );

        let high_stake = phase_message(
            Arc::clone(&committee),
            &keyrings,
            0,
            3,
            RbcPhase::Echo,
            block_ref,
        );
        assert!(receiver.handle_phase(0, high_stake).unwrap().is_empty());
        let boundary = phase_message(committee, &keyrings, 2, 3, RbcPhase::Echo, block_ref);
        assert!(matches!(
            receiver.handle_phase(2, boundary).unwrap().as_slice(),
            [RbcEffect::MulticastPhase {
                phase: RbcPhase::Ready,
                ..
            }]
        ));
    }
}
