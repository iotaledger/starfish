// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Synchronous reliable-broadcast kernel for Starfish-RBC.
//!
//! This module is deliberately not connected to networking or DAG admission
//! yet. The next milestones will supply content-validated headers and expand
//! multicast effects into recipient-specific network messages.

#![allow(dead_code)]

use std::{collections::BTreeMap, error::Error, fmt, sync::Arc};

use ahash::AHashMap;
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    committee::{Committee, QuorumThreshold, StakeAggregator, ValidityThreshold},
    crypto::{Blake3Hasher, MacKey, MacTag},
    types::{
        AuthorityIndex, AuthoritySet, BlockAuthenticationScheme, BlockReference,
        MAX_COMMITTEE_SIZE, RoundNumber, Stake,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum RbcPhase {
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
pub(crate) struct RbcPhaseMessage {
    block_ref: BlockReference,
    sender: AuthorityIndex,
    recipient: AuthorityIndex,
    phase: RbcPhase,
    tag: MacTag,
}

impl RbcPhaseMessage {
    pub(crate) fn block_ref(&self) -> BlockReference {
        self.block_ref
    }

    pub(crate) fn sender(&self) -> AuthorityIndex {
        self.sender
    }

    pub(crate) fn recipient(&self) -> AuthorityIndex {
        self.recipient
    }

    pub(crate) fn phase(&self) -> RbcPhase {
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
    Deliver(BlockReference),
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
    header_available: bool,
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
            header_available: false,
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

#[derive(Default)]
struct SlotState {
    echoed: Option<BlockReference>,
    readied: Option<BlockReference>,
    delivered: Option<BlockReference>,
    candidates: AHashMap<BlockReference, CandidateState>,
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
    slots: BTreeMap<RoundNumber, AHashMap<AuthorityIndex, SlotState>>,
}

impl StarfishRbcKernel {
    pub(crate) fn new(
        committee: Arc<Committee>,
        own_authority: AuthorityIndex,
        protocol_instance: RbcProtocolInstanceId,
        initial_authentication: BlockAuthenticationScheme,
        mac_keys: Arc<Vec<MacKey>>,
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
            slots: BTreeMap::new(),
        })
    }

    pub(crate) fn context(&self) -> RbcContext {
        self.context
    }

    /// Record deterministic content validation and local header availability.
    /// This does not authorize ECHO and does not imply initial authentication.
    /// It remains module-private until header staging can supply a typed,
    /// pinned content-validation result.
    fn note_header_available(
        &mut self,
        block_ref: BlockReference,
    ) -> Result<Vec<RbcEffect>, RbcError> {
        self.validate_block_ref(&block_ref)?;
        self.candidate_mut(block_ref).header_available = true;
        Ok(self.drive(block_ref))
    }

    /// Authorize the one local ECHO for this slot. It remains module-private
    /// until the integration layer can pass a typed direct-author proof (or a
    /// local-creation capability) instead of relying on call ordering.
    fn authorize_echo(&mut self, block_ref: BlockReference) -> Result<Vec<RbcEffect>, RbcError> {
        self.validate_block_ref(&block_ref)?;
        let header_available = self
            .candidate(&block_ref)
            .is_some_and(|candidate| candidate.header_available);
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
        let candidate = self.candidate_mut(message.block_ref);
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
                    .is_some_and(|candidate| candidate.header_available)
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

    /// Produce the common 32-byte digest signed by Ed25519 or ML-DSA for an
    /// initial Starfish-RBC header proposal.
    pub(crate) fn initial_signature_digest(
        &self,
        block_ref: BlockReference,
    ) -> Result<[u8; 32], RbcError> {
        if self.context.initial_authentication == BlockAuthenticationScheme::MacVector {
            return Err(RbcError::InitialSignatureRequiresSignatureAuthentication);
        }
        self.validate_block_ref(&block_ref)?;
        let statement = encode_base_statement(&self.context, INITIAL_KIND, &block_ref);
        Ok(blake3::hash(&statement).into())
    }

    /// Produce one receiver-specific initial MAC. The local author calls this
    /// separately for every non-local recipient.
    pub(crate) fn make_initial_mac_tag(
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

    pub(crate) fn header_holders(&self, block_ref: &BlockReference) -> AuthoritySet {
        self.candidate(block_ref)
            .map(CandidateState::holders)
            .unwrap_or_default()
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
        let blocked_on_header = !candidate.header_available
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
        Ok(())
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
                let blocked_on_header = !candidate.header_available
                    && ((can_send_ready && ready_trigger)
                        || (can_deliver && candidate.ready_quorum_observed));
                let holders = candidate.holders();
                if blocked_on_header && holders != candidate.header_request_holders {
                    candidate.header_request_holders = holders;
                    ProgressAction::NeedHeader(holders)
                } else if candidate.header_available && can_send_ready && ready_trigger {
                    ProgressAction::SendReady
                } else if candidate.header_available
                    && can_deliver
                    && candidate.ready_quorum_observed
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
                        effects.push(RbcEffect::Deliver(block_ref));
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
        crypto::mac_keyrings_for_test,
        types::{BlockDigest, BlockReference},
    };

    const TEST_INSTANCE_BYTE: u8 = 0xA5;

    fn block(authority: AuthorityIndex, round: RoundNumber, marker: u8) -> BlockReference {
        BlockReference {
            authority,
            round,
            digest: BlockDigest::from([marker; 32]),
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
        kernel.note_header_available(block_ref).unwrap();
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
        fetch_missing_headers: bool,
    ) -> Vec<Vec<BlockReference>> {
        let mut queue: VecDeque<_> = initial_effects
            .into_iter()
            .flat_map(|(authority, effects)| {
                effects.into_iter().map(move |effect| (authority, effect))
            })
            .collect();
        let mut deliveries = vec![Vec::new(); kernels.len()];

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
                RbcEffect::NeedHeader { block_ref, .. } if fetch_missing_headers => {
                    let effects = kernels[owner as usize]
                        .note_header_available(block_ref)
                        .unwrap();
                    queue.extend(effects.into_iter().map(|effect| (owner, effect)));
                }
                RbcEffect::NeedHeader { .. } => {}
                RbcEffect::Deliver(block_ref) => {
                    deliveries[owner as usize].push(block_ref);
                }
            }
        }
        deliveries
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
        let tag = author.make_initial_mac_tag(block_ref, 1).unwrap();

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
        sender.note_header_available(first).unwrap();
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

        sender.note_header_available(conflicting).unwrap();
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
        message.tag = sender.make_initial_mac_tag(block_ref, 1).unwrap();

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
            receiver.note_header_available(block_ref).unwrap(),
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
            receiver.note_header_available(block_ref).unwrap(),
            vec![
                RbcEffect::MulticastPhase {
                    phase: RbcPhase::Ready,
                    block_ref,
                },
                RbcEffect::Deliver(block_ref),
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

        let third = phase_message(committee, &keyrings, 2, 3, RbcPhase::Ready, block_ref);
        let expanded_request = receiver.handle_phase(2, third).unwrap();
        assert!(matches!(
            expanded_request.as_slice(),
            [RbcEffect::NeedHeader { holders, .. }] if holder_vec(*holders) == vec![0, 1, 2]
        ));
        assert_eq!(
            receiver.retry_header_request(block_ref).unwrap(),
            expanded_request.first().cloned()
        );

        receiver.note_header_available(block_ref).unwrap();
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
            receiver.note_header_available(block_ref).unwrap(),
            vec![
                RbcEffect::MulticastPhase {
                    phase: RbcPhase::Ready,
                    block_ref,
                },
                RbcEffect::Deliver(block_ref),
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
        receiver.note_header_available(block_ref).unwrap();

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
        receiver.note_header_available(first).unwrap();
        assert!(matches!(
            receiver.authorize_echo(first).unwrap().as_slice(),
            [RbcEffect::MulticastPhase {
                phase: RbcPhase::Echo,
                ..
            }]
        ));
        receiver.note_header_available(quorum_candidate).unwrap();
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
    fn evidence_is_per_candidate_but_delivery_is_slot_global() {
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
        receiver.note_header_available(first).unwrap();
        receiver.note_header_available(second).unwrap();

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
            receiver
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
        let first = block(0, 12, 0xA1);
        let conflicting = block(0, 12, 0xA2);
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

        let mut initial_effects = Vec::new();
        for (authority, block_ref) in [(0, first), (1, first), (2, first), (3, conflicting)] {
            kernels[authority as usize]
                .note_header_available(block_ref)
                .unwrap();
            let effects = kernels[authority as usize]
                .authorize_echo(block_ref)
                .unwrap();
            initial_effects.push((authority, effects));
        }

        let deliveries = pump_phase_effects(&mut kernels, initial_effects, true);
        assert!(deliveries.iter().all(|delivered| delivered == &[first]));
        assert!(
            deliveries
                .iter()
                .flatten()
                .all(|delivered| *delivered != conflicting)
        );
        assert_eq!(kernels[3].slot(&first).unwrap().echoed, Some(conflicting));
        assert_eq!(kernels[3].slot(&first).unwrap().readied, Some(first));
    }

    #[test]
    fn poisoned_initial_mac_does_not_block_rbc_totality() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let block_ref = block(0, 13, 0xA3);
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

        let valid_for_one = kernels[0].make_initial_mac_tag(block_ref, 1).unwrap();
        let valid_for_two = kernels[0].make_initial_mac_tag(block_ref, 2).unwrap();
        kernels[1]
            .verify_initial_mac_tag(0, block_ref, &valid_for_one)
            .unwrap();
        kernels[2]
            .verify_initial_mac_tag(0, block_ref, &valid_for_two)
            .unwrap();
        assert_eq!(
            kernels[3].verify_initial_mac_tag(0, block_ref, &valid_for_two),
            Err(RbcError::InvalidInitialTag)
        );

        let mut initial_effects = Vec::new();
        for authority in 0..3 {
            kernels[authority as usize]
                .note_header_available(block_ref)
                .unwrap();
            let effects = kernels[authority as usize]
                .authorize_echo(block_ref)
                .unwrap();
            initial_effects.push((authority, effects));
        }

        let deliveries = pump_phase_effects(&mut kernels, initial_effects, true);
        assert!(deliveries.iter().all(|delivered| delivered == &[block_ref]));
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
        receiver.note_header_available(block_ref).unwrap();
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
