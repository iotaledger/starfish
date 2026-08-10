// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Single-owner async adapter around the Starfish-RBC kernel.
//!
//! The service deliberately owns header-recovery state independently of any
//! one network connection. Connection workers only attach their trusted peer
//! identity and forward messages into this actor; reconnects therefore cannot
//! discard a pending recovery attempt.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::Arc,
    time::Duration,
};

use ahash::{AHashMap, AHashSet};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::MissedTickBehavior,
};

use crate::{
    committee::Committee,
    crypto::{MacKey, MlDsa44Signer, MlDsa65Signer, Signer, TransactionsCommitment},
    network::{NetworkMessage, RbcTransactionPayload},
    starfish_rbc::{
        PinnedRbcHeader, RbcCanonicalHeader, RbcEffect, RbcError, RbcHeaderProposal,
        RbcInitialHeaderOutcome, RbcInitialProof, RbcLocalInitial, RbcPhase, RbcPhaseMessage,
        RbcProtocolInstanceId, StarfishRbcKernel,
    },
    types::{
        AuthorityIndex, AuthoritySet, BlockAuthenticationScheme, BlockDigest, BlockReference,
        RoundNumber, TimestampNs, TransactionData,
    },
};

const HEADER_REQUEST_FANOUT: usize = 2;

/// Authentication material used only for the author's initial RBC proposal.
/// ECHO and READY always use the pairwise MAC keyring owned by the kernel.
#[derive(Clone)]
pub(crate) enum RbcInitialAuthenticator {
    Ed25519(Signer),
    MlDsa44(MlDsa44Signer),
    MlDsa65(MlDsa65Signer),
    Mac,
}

impl RbcInitialAuthenticator {
    fn scheme(&self) -> BlockAuthenticationScheme {
        match self {
            Self::Ed25519(_) => BlockAuthenticationScheme::Ed25519,
            Self::MlDsa44(_) => BlockAuthenticationScheme::MlDsa44,
            Self::MlDsa65(_) => BlockAuthenticationScheme::MlDsa65,
            Self::Mac => BlockAuthenticationScheme::MacVector,
        }
    }
}

/// Authentication-free inputs for atomically starting one local RBC slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RbcLocalHeader {
    pub round: RoundNumber,
    pub block_references: Vec<BlockReference>,
    pub acknowledgment_references: Vec<BlockReference>,
    pub meta_creation_time_ns: TimestampNs,
    pub transactions_commitment: TransactionsCommitment,
}

impl RbcLocalHeader {
    pub(crate) fn from_canonical(header: &RbcCanonicalHeader) -> Self {
        Self {
            round: header.reference().round,
            block_references: header.block_references().to_vec(),
            acknowledgment_references: header.acknowledgment_references(),
            meta_creation_time_ns: header.meta_creation_time_ns(),
            transactions_commitment: header.transactions_commitment(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RbcServiceError {
    Kernel(RbcError),
    InitialAuthenticatorSchemeMismatch {
        configured: BlockAuthenticationScheme,
        supplied: BlockAuthenticationScheme,
    },
    LocalAuthenticatorKeyMismatch(AuthorityIndex),
    ZeroHeaderRetryInterval,
    UnexpectedHeaderResponse(BlockReference),
    HeaderResponseFromNonHolder {
        block_ref: BlockReference,
        peer: AuthorityIndex,
    },
    UnexpectedTransactionPayload(BlockReference),
    TransactionPayloadNotFromAuthor {
        block_ref: BlockReference,
        peer: AuthorityIndex,
    },
    ServiceStopped,
}

impl From<RbcError> for RbcServiceError {
    fn from(error: RbcError) -> Self {
        Self::Kernel(error)
    }
}

impl fmt::Display for RbcServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel(error) => error.fmt(formatter),
            Self::InitialAuthenticatorSchemeMismatch {
                configured,
                supplied,
            } => write!(
                formatter,
                "Starfish-RBC initial authenticator mismatch: configured {configured:?}, \
                 supplied {supplied:?}"
            ),
            Self::LocalAuthenticatorKeyMismatch(authority) => write!(
                formatter,
                "Starfish-RBC initial authenticator key does not match authority {authority}"
            ),
            Self::ZeroHeaderRetryInterval => {
                formatter.write_str("Starfish-RBC header retry interval must be nonzero")
            }
            Self::UnexpectedHeaderResponse(block_ref) => write!(
                formatter,
                "unexpected Starfish-RBC header response for {block_ref}"
            ),
            Self::HeaderResponseFromNonHolder { block_ref, peer } => write!(
                formatter,
                "Starfish-RBC header response for {block_ref} came from non-holder {peer}"
            ),
            Self::UnexpectedTransactionPayload(block_ref) => write!(
                formatter,
                "Starfish-RBC transaction payload arrived before its header for {block_ref}"
            ),
            Self::TransactionPayloadNotFromAuthor { block_ref, peer } => write!(
                formatter,
                "Starfish-RBC transaction payload for {block_ref} came from non-author {peer}"
            ),
            Self::ServiceStopped => formatter.write_str("Starfish-RBC service stopped"),
        }
    }
}

impl Error for RbcServiceError {}

/// Events consumed by the network/core integration bridge.
#[derive(Debug)]
pub(crate) enum RbcServiceEvent {
    Network {
        recipient: AuthorityIndex,
        message: NetworkMessage,
    },
    HeaderStaged(PinnedRbcHeader),
    TransactionPayloadStaged {
        peer: AuthorityIndex,
        header: PinnedRbcHeader,
        payload: RbcTransactionPayload,
    },
    Delivered(PinnedRbcHeader),
    Rejected {
        peer: Option<AuthorityIndex>,
        error: RbcServiceError,
    },
}

enum RbcServiceMessage {
    StartLocal {
        header: RbcLocalHeader,
        transaction_data: Option<TransactionData>,
        reply: oneshot::Sender<Result<RbcCanonicalHeader, RbcServiceError>>,
    },
    DirectInitial {
        peer: AuthorityIndex,
        proposal: RbcHeaderProposal,
    },
    Phase {
        peer: AuthorityIndex,
        message: RbcPhaseMessage,
    },
    HeaderRequest {
        peer: AuthorityIndex,
        block_ref: BlockReference,
    },
    HeaderResponse {
        peer: AuthorityIndex,
        header: RbcCanonicalHeader,
    },
    TransactionPayload {
        peer: AuthorityIndex,
        payload: RbcTransactionPayload,
    },
    PeerConnected(AuthorityIndex),
    PeerDisconnected(AuthorityIndex),
    #[allow(dead_code)]
    AdvanceLocalRound {
        round: RoundNumber,
        reply: oneshot::Sender<Result<(), RbcServiceError>>,
    },
    #[allow(dead_code)]
    RetryHeaders(oneshot::Sender<()>),
}

#[derive(Clone)]
pub(crate) struct RbcServiceHandle {
    sender: mpsc::UnboundedSender<RbcServiceMessage>,
}

impl RbcServiceHandle {
    #[allow(dead_code)]
    pub(crate) async fn start_local_header(
        &self,
        header: RbcLocalHeader,
    ) -> Result<RbcCanonicalHeader, RbcServiceError> {
        self.start_local_header_with_payload(header, None).await
    }

    #[allow(dead_code)]
    pub(crate) async fn start_local_header_with_payload(
        &self,
        header: RbcLocalHeader,
        transaction_data: Option<TransactionData>,
    ) -> Result<RbcCanonicalHeader, RbcServiceError> {
        let (reply, receiver) = oneshot::channel();
        self.send(RbcServiceMessage::StartLocal {
            header,
            transaction_data,
            reply,
        })?;
        receiver
            .await
            .map_err(|_| RbcServiceError::ServiceStopped)?
    }

    /// Synchronous entry point for the dedicated core thread. The reply is
    /// completed only after the kernel has selected/pinned the slot and all
    /// INIT/phase events have been enqueued, so legacy dissemination cannot
    /// race ahead of local RBC authorization.
    pub(crate) fn start_local_header_with_payload_blocking(
        &self,
        header: RbcLocalHeader,
        transaction_data: Option<TransactionData>,
    ) -> Result<RbcCanonicalHeader, RbcServiceError> {
        let (reply, receiver) = oneshot::channel();
        self.send(RbcServiceMessage::StartLocal {
            header,
            transaction_data,
            reply,
        })?;
        receiver
            .blocking_recv()
            .map_err(|_| RbcServiceError::ServiceStopped)?
    }

    pub(crate) fn direct_initial(
        &self,
        peer: AuthorityIndex,
        proposal: RbcHeaderProposal,
    ) -> Result<(), RbcServiceError> {
        self.send(RbcServiceMessage::DirectInitial { peer, proposal })
    }

    pub(crate) fn phase(
        &self,
        peer: AuthorityIndex,
        message: RbcPhaseMessage,
    ) -> Result<(), RbcServiceError> {
        self.send(RbcServiceMessage::Phase { peer, message })
    }

    pub(crate) fn header_request(
        &self,
        peer: AuthorityIndex,
        block_ref: BlockReference,
    ) -> Result<(), RbcServiceError> {
        self.send(RbcServiceMessage::HeaderRequest { peer, block_ref })
    }

    pub(crate) fn header_response(
        &self,
        peer: AuthorityIndex,
        header: RbcCanonicalHeader,
    ) -> Result<(), RbcServiceError> {
        self.send(RbcServiceMessage::HeaderResponse { peer, header })
    }

    pub(crate) fn transaction_payload(
        &self,
        peer: AuthorityIndex,
        payload: RbcTransactionPayload,
    ) -> Result<(), RbcServiceError> {
        self.send(RbcServiceMessage::TransactionPayload { peer, payload })
    }

    pub(crate) fn peer_connected(&self, peer: AuthorityIndex) -> Result<(), RbcServiceError> {
        self.send(RbcServiceMessage::PeerConnected(peer))
    }

    pub(crate) fn peer_disconnected(&self, peer: AuthorityIndex) -> Result<(), RbcServiceError> {
        self.send(RbcServiceMessage::PeerDisconnected(peer))
    }

    #[allow(dead_code)]
    pub(crate) async fn advance_local_round(
        &self,
        round: RoundNumber,
    ) -> Result<(), RbcServiceError> {
        let (reply, receiver) = oneshot::channel();
        self.send(RbcServiceMessage::AdvanceLocalRound { round, reply })?;
        receiver
            .await
            .map_err(|_| RbcServiceError::ServiceStopped)?
    }

    /// Trigger a recovery wave immediately. Production also has an internal
    /// periodic timer; this method is useful after topology changes and makes
    /// retry behavior deterministic in tests.
    #[allow(dead_code)]
    pub(crate) async fn retry_headers(&self) -> Result<(), RbcServiceError> {
        let (reply, receiver) = oneshot::channel();
        self.send(RbcServiceMessage::RetryHeaders(reply))?;
        receiver.await.map_err(|_| RbcServiceError::ServiceStopped)
    }

    fn send(&self, message: RbcServiceMessage) -> Result<(), RbcServiceError> {
        self.sender
            .send(message)
            .map_err(|_| RbcServiceError::ServiceStopped)
    }
}

/// Start the single Starfish-RBC state-machine owner.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_starfish_rbc_service(
    committee: Arc<Committee>,
    own_authority: AuthorityIndex,
    protocol_instance: RbcProtocolInstanceId,
    initial_authentication: BlockAuthenticationScheme,
    mac_keys: Arc<Vec<MacKey>>,
    initial_authenticator: RbcInitialAuthenticator,
    local_round: RoundNumber,
    header_retry_interval: Duration,
) -> Result<
    (
        RbcServiceHandle,
        mpsc::UnboundedReceiver<RbcServiceEvent>,
        JoinHandle<()>,
    ),
    RbcServiceError,
> {
    if header_retry_interval.is_zero() {
        return Err(RbcServiceError::ZeroHeaderRetryInterval);
    }
    if initial_authenticator.scheme() != initial_authentication {
        return Err(RbcServiceError::InitialAuthenticatorSchemeMismatch {
            configured: initial_authentication,
            supplied: initial_authenticator.scheme(),
        });
    }
    validate_local_authenticator(&committee, own_authority, &initial_authenticator)?;

    let kernel = StarfishRbcKernel::new(
        committee.clone(),
        own_authority,
        protocol_instance,
        initial_authentication,
        mac_keys,
        local_round,
    )?;
    let (message_tx, message_rx) = mpsc::unbounded_channel();
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let state = RbcServiceState {
        committee,
        own_authority,
        initial_authenticator,
        kernel,
        events: event_tx,
        connected_peers: AuthoritySet::default(),
        pending_fetches: AHashMap::new(),
        staged_notifications: AHashSet::new(),
        retained_initials: BTreeMap::new(),
        retained_transaction_payloads: BTreeMap::new(),
        retained_phases: BTreeSet::new(),
    };
    let task = tokio::spawn(run_service(state, message_rx, header_retry_interval));
    Ok((RbcServiceHandle { sender: message_tx }, event_rx, task))
}

fn validate_local_authenticator(
    committee: &Committee,
    own_authority: AuthorityIndex,
    authenticator: &RbcInitialAuthenticator,
) -> Result<(), RbcServiceError> {
    let matches = match authenticator {
        RbcInitialAuthenticator::Ed25519(signer) => committee
            .get_public_key(own_authority)
            .is_some_and(|public_key| public_key == &signer.public_key()),
        RbcInitialAuthenticator::MlDsa44(signer) => committee
            .get_ml_dsa_44_public_key(own_authority)
            .is_some_and(|public_key| public_key == &signer.public_key()),
        RbcInitialAuthenticator::MlDsa65(signer) => committee
            .get_ml_dsa_65_public_key(own_authority)
            .is_some_and(|public_key| public_key == &signer.public_key()),
        RbcInitialAuthenticator::Mac => committee.known_authority(own_authority),
    };
    if matches {
        Ok(())
    } else {
        Err(RbcServiceError::LocalAuthenticatorKeyMismatch(
            own_authority,
        ))
    }
}

async fn run_service(
    mut state: RbcServiceState,
    mut messages: mpsc::UnboundedReceiver<RbcServiceMessage>,
    header_retry_interval: Duration,
) {
    let mut retry = tokio::time::interval(header_retry_interval);
    retry.set_missed_tick_behavior(MissedTickBehavior::Skip);
    retry.tick().await;

    loop {
        tokio::select! {
            maybe_message = messages.recv() => {
                let Some(message) = maybe_message else {
                    break;
                };
                state.process_message(message);
            }
            _ = retry.tick() => state.retry_pending_headers(),
        }
    }
}

struct PendingHeaderFetch {
    holders: AuthoritySet,
    requested_from: AuthoritySet,
}

struct RbcServiceState {
    committee: Arc<Committee>,
    own_authority: AuthorityIndex,
    initial_authenticator: RbcInitialAuthenticator,
    kernel: StarfishRbcKernel,
    events: mpsc::UnboundedSender<RbcServiceEvent>,
    connected_peers: AuthoritySet,
    pending_fetches: AHashMap<BlockReference, PendingHeaderFetch>,
    staged_notifications: AHashSet<BlockReference>,
    /// Recipient-specialized local proposals retained for replay after a
    /// connection is replaced. Version one keeps these for the run.
    retained_initials: BTreeMap<(BlockReference, AuthorityIndex), RbcHeaderProposal>,
    /// Header-free transaction payloads retained for replay after INIT. The
    /// same content-addressed payload is specialized only by its recipient
    /// routing, not by its bytes.
    retained_transaction_payloads: BTreeMap<BlockReference, RbcTransactionPayload>,
    /// Authorized local phase intents. Tags are rematerialized for the peer
    /// on replay rather than retaining or cloning a tagged wire message.
    retained_phases: BTreeSet<(BlockReference, RbcPhase)>,
}

impl RbcServiceState {
    fn process_message(&mut self, message: RbcServiceMessage) {
        match message {
            RbcServiceMessage::StartLocal {
                header,
                transaction_data,
                reply,
            } => {
                let result = self.start_local_header(header, transaction_data);
                let _ = reply.send(result);
            }
            RbcServiceMessage::DirectInitial { peer, proposal } => {
                self.accept_direct_initial(peer, proposal);
            }
            RbcServiceMessage::Phase { peer, message } => {
                match self.kernel.handle_phase(peer, message) {
                    Ok(effects) => self.process_effects(effects),
                    Err(error) => self.reject(Some(peer), error.into()),
                }
            }
            RbcServiceMessage::HeaderRequest { peer, block_ref } => {
                self.answer_header_request(peer, block_ref);
            }
            RbcServiceMessage::HeaderResponse { peer, header } => {
                self.accept_header_response(peer, header);
            }
            RbcServiceMessage::TransactionPayload { peer, payload } => {
                self.accept_transaction_payload(peer, payload);
            }
            RbcServiceMessage::PeerConnected(peer) => self.peer_connected(peer),
            RbcServiceMessage::PeerDisconnected(peer) => self.peer_disconnected(peer),
            RbcServiceMessage::AdvanceLocalRound { round, reply } => {
                let result = self
                    .kernel
                    .advance_local_round(round)
                    .map_err(RbcServiceError::from);
                let _ = reply.send(result);
            }
            RbcServiceMessage::RetryHeaders(reply) => {
                self.retry_pending_headers();
                let _ = reply.send(());
            }
        }
    }

    fn start_local_header(
        &mut self,
        header: RbcLocalHeader,
        transaction_data: Option<TransactionData>,
    ) -> Result<RbcCanonicalHeader, RbcServiceError> {
        self.kernel.advance_local_round(header.round)?;
        let local = self.kernel.start_local_initial_header(
            header.round,
            header.block_references,
            header.acknowledgment_references,
            header.meta_creation_time_ns,
            header.transactions_commitment,
        )?;
        let canonical = local.header().clone();
        let proposals = self.make_initial_proposals(&local);
        let (pinned, effects) = local.into_parts();
        let transaction_payload =
            transaction_data.map(|data| RbcTransactionPayload::new(canonical.reference(), data));
        if let Some(payload) = transaction_payload.as_ref() {
            self.retained_transaction_payloads
                .insert(canonical.reference(), payload.clone());
        }

        self.notify_header_staged(pinned);
        for (recipient, proposal) in proposals {
            self.retained_initials
                .insert((canonical.reference(), recipient), proposal.clone());
            self.send_network(recipient, NetworkMessage::RbcInitial(proposal));
            if let Some(payload) = transaction_payload.as_ref() {
                self.send_network(
                    recipient,
                    NetworkMessage::RbcTransactionPayload(payload.clone()),
                );
            }
        }
        self.process_effects(effects);
        Ok(canonical)
    }

    fn make_initial_proposals(
        &self,
        local: &RbcLocalInitial,
    ) -> Vec<(AuthorityIndex, RbcHeaderProposal)> {
        let header = local.header().clone();
        match &self.initial_authenticator {
            RbcInitialAuthenticator::Ed25519(signer) => {
                let digest = self
                    .kernel
                    .make_local_initial_signature_digest(local)
                    .expect("local RBC handle must remain selected");
                let proof = RbcInitialProof::Ed25519(signer.sign_digest(&digest));
                self.public_initial_proposals(header, proof)
            }
            RbcInitialAuthenticator::MlDsa44(signer) => {
                let digest = self
                    .kernel
                    .make_local_initial_signature_digest(local)
                    .expect("local RBC handle must remain selected");
                let proof =
                    RbcInitialProof::MlDsa44(signer.sign_digest(&BlockDigest::from(digest)));
                self.public_initial_proposals(header, proof)
            }
            RbcInitialAuthenticator::MlDsa65(signer) => {
                let digest = self
                    .kernel
                    .make_local_initial_signature_digest(local)
                    .expect("local RBC handle must remain selected");
                let proof =
                    RbcInitialProof::MlDsa65(signer.sign_digest(&BlockDigest::from(digest)));
                self.public_initial_proposals(header, proof)
            }
            RbcInitialAuthenticator::Mac => self
                .committee
                .authorities()
                .filter(|recipient| *recipient != self.own_authority)
                .map(|recipient| {
                    let tag = self
                        .kernel
                        .make_local_initial_mac_tag(local, recipient)
                        .expect("local RBC handle must remain selected");
                    (
                        recipient,
                        RbcHeaderProposal::new(header.clone(), RbcInitialProof::Mac(tag)),
                    )
                })
                .collect(),
        }
    }

    fn public_initial_proposals(
        &self,
        header: RbcCanonicalHeader,
        proof: RbcInitialProof,
    ) -> Vec<(AuthorityIndex, RbcHeaderProposal)> {
        self.committee
            .authorities()
            .filter(|recipient| *recipient != self.own_authority)
            .map(|recipient| {
                (
                    recipient,
                    RbcHeaderProposal::new(header.clone(), proof.clone()),
                )
            })
            .collect()
    }

    fn accept_direct_initial(&mut self, peer: AuthorityIndex, proposal: RbcHeaderProposal) {
        let (header, proof) = proposal.into_parts();
        let block_ref = header.reference();
        match self
            .kernel
            .accept_direct_initial_header(peer, header, &proof)
        {
            Ok(RbcInitialHeaderOutcome::Authenticated { effects }) => {
                self.finish_header_staging(block_ref, Some(peer));
                self.process_effects(effects);
            }
            Ok(RbcInitialHeaderOutcome::StagedUnauthenticated { effects, error }) => {
                self.finish_header_staging(block_ref, Some(peer));
                self.process_effects(effects);
                self.reject(Some(peer), error.into());
            }
            Err(error) => self.reject(Some(peer), error.into()),
        }
    }

    fn answer_header_request(&mut self, peer: AuthorityIndex, block_ref: BlockReference) {
        if !self.committee.known_authority(peer) {
            self.reject(Some(peer), RbcError::UnknownAuthority(peer).into());
            return;
        }
        if peer == self.own_authority {
            self.reject(Some(peer), RbcError::LoopbackPhase.into());
            return;
        }
        match self.kernel.pinned_header(block_ref) {
            Ok(Some(header)) => self.send_network(
                peer,
                NetworkMessage::RbcHeaderResponse(header.header().clone()),
            ),
            Ok(None) => {}
            Err(error) => self.reject(Some(peer), error.into()),
        }
    }

    fn accept_header_response(&mut self, peer: AuthorityIndex, header: RbcCanonicalHeader) {
        let block_ref = header.reference();
        if !self.committee.known_authority(peer) {
            self.reject(Some(peer), RbcError::UnknownAuthority(peer).into());
            return;
        }
        if peer == self.own_authority {
            self.reject(Some(peer), RbcError::LoopbackPhase.into());
            return;
        }
        let Some(fetch) = self.pending_fetches.get(&block_ref) else {
            self.reject(
                Some(peer),
                RbcServiceError::UnexpectedHeaderResponse(block_ref),
            );
            return;
        };
        if !fetch.holders.contains(peer) {
            self.reject(
                Some(peer),
                RbcServiceError::HeaderResponseFromNonHolder { block_ref, peer },
            );
            return;
        }

        match self.kernel.accept_recovered_header(header) {
            Ok(effects) => {
                self.finish_header_staging(block_ref, Some(peer));
                self.process_effects(effects);
            }
            Err(error) => self.reject(Some(peer), error.into()),
        }
    }

    fn accept_transaction_payload(&mut self, peer: AuthorityIndex, payload: RbcTransactionPayload) {
        let block_ref = payload.block_reference();
        if !self.committee.known_authority(peer) {
            self.reject(Some(peer), RbcError::UnknownAuthority(peer).into());
            return;
        }
        if peer != block_ref.authority {
            self.reject(
                Some(peer),
                RbcServiceError::TransactionPayloadNotFromAuthor { block_ref, peer },
            );
            return;
        }
        match self.kernel.pinned_header(block_ref) {
            Ok(Some(header)) => {
                let _ = self.events.send(RbcServiceEvent::TransactionPayloadStaged {
                    peer,
                    header,
                    payload,
                });
            }
            Ok(None) => self.reject(
                Some(peer),
                RbcServiceError::UnexpectedTransactionPayload(block_ref),
            ),
            Err(error) => self.reject(Some(peer), error.into()),
        }
    }

    fn finish_header_staging(&mut self, block_ref: BlockReference, peer: Option<AuthorityIndex>) {
        match self.kernel.pinned_header(block_ref) {
            Ok(Some(header)) => {
                self.pending_fetches.remove(&block_ref);
                self.notify_header_staged(header);
            }
            Ok(None) => self.reject(peer, RbcError::HeaderUnavailable(block_ref).into()),
            Err(error) => self.reject(peer, error.into()),
        }
    }

    fn notify_header_staged(&mut self, header: PinnedRbcHeader) {
        if self.staged_notifications.insert(header.reference()) {
            let _ = self.events.send(RbcServiceEvent::HeaderStaged(header));
        }
    }

    fn process_effects(&mut self, effects: Vec<RbcEffect>) {
        for effect in effects {
            match effect {
                RbcEffect::MulticastPhase { phase, block_ref } => {
                    self.retained_phases.insert((block_ref, phase));
                    let recipients: Vec<_> = self
                        .committee
                        .authorities()
                        .filter(|recipient| *recipient != self.own_authority)
                        .collect();
                    for recipient in recipients {
                        match self.kernel.make_phase_message(phase, block_ref, recipient) {
                            Ok(message) => {
                                self.send_network(recipient, NetworkMessage::RbcPhase(message))
                            }
                            Err(error) => self.reject(None, error.into()),
                        }
                    }
                }
                RbcEffect::NeedHeader { block_ref, holders } => {
                    self.note_pending_fetch(block_ref, holders);
                }
                RbcEffect::Deliver(header) => {
                    self.pending_fetches.remove(&header.reference());
                    let _ = self.events.send(RbcServiceEvent::Delivered(header));
                }
            }
        }
    }

    fn note_pending_fetch(&mut self, block_ref: BlockReference, holders: AuthoritySet) {
        self.pending_fetches
            .entry(block_ref)
            .and_modify(|fetch| fetch.holders |= holders)
            .or_insert(PendingHeaderFetch {
                holders,
                requested_from: AuthoritySet::default(),
            });
        self.send_fetch_wave(block_ref);
    }

    fn send_fetch_wave(&mut self, block_ref: BlockReference) {
        let Some(fetch) = self.pending_fetches.get_mut(&block_ref) else {
            return;
        };
        let eligible: Vec<_> = fetch
            .holders
            .present()
            .filter(|peer| *peer != self.own_authority && self.connected_peers.contains(*peer))
            .collect();
        let mut recipients: Vec<_> = eligible
            .iter()
            .copied()
            .filter(|peer| !fetch.requested_from.contains(*peer))
            .take(HEADER_REQUEST_FANOUT)
            .collect();
        if recipients.is_empty() && !eligible.is_empty() {
            fetch.requested_from.clear();
            recipients.extend(eligible.into_iter().take(HEADER_REQUEST_FANOUT));
        }
        for recipient in &recipients {
            fetch.requested_from.insert(*recipient);
        }
        for recipient in recipients {
            self.send_network(recipient, NetworkMessage::RbcHeaderRequest(block_ref));
        }
    }

    fn retry_pending_headers(&mut self) {
        let block_refs: Vec<_> = self.pending_fetches.keys().copied().collect();
        for block_ref in block_refs {
            match self.kernel.retry_header_request(block_ref) {
                Ok(Some(RbcEffect::NeedHeader { holders, .. })) => {
                    if let Some(fetch) = self.pending_fetches.get_mut(&block_ref) {
                        fetch.holders |= holders;
                    }
                    self.send_fetch_wave(block_ref);
                }
                Ok(Some(_)) => unreachable!("header retry can only request a header"),
                Ok(None) => {
                    self.pending_fetches.remove(&block_ref);
                }
                Err(error) => {
                    self.pending_fetches.remove(&block_ref);
                    self.reject(None, error.into());
                }
            }
        }
    }

    fn peer_connected(&mut self, peer: AuthorityIndex) {
        if !self.committee.known_authority(peer) {
            self.reject(Some(peer), RbcError::UnknownAuthority(peer).into());
            return;
        }
        if peer == self.own_authority {
            self.reject(Some(peer), RbcError::LoopbackPhase.into());
            return;
        }
        self.connected_peers.insert(peer);

        let initials: Vec<_> = self
            .retained_initials
            .iter()
            .filter_map(|((_, recipient), proposal)| {
                (*recipient == peer).then_some(proposal.clone())
            })
            .collect();
        for proposal in initials {
            self.send_network(peer, NetworkMessage::RbcInitial(proposal));
        }

        let payloads: Vec<_> = self
            .retained_transaction_payloads
            .values()
            .cloned()
            .collect();
        for payload in payloads {
            self.send_network(peer, NetworkMessage::RbcTransactionPayload(payload));
        }

        let phases: Vec<_> = self.retained_phases.iter().copied().collect();
        for (block_ref, phase) in phases {
            match self.kernel.make_phase_message(phase, block_ref, peer) {
                Ok(message) => self.send_network(peer, NetworkMessage::RbcPhase(message)),
                Err(error) => self.reject(Some(peer), error.into()),
            }
        }

        let pending: Vec<_> = self
            .pending_fetches
            .iter()
            .filter_map(|(block_ref, fetch)| fetch.holders.contains(peer).then_some(*block_ref))
            .collect();
        for block_ref in pending {
            if let Some(fetch) = self.pending_fetches.get_mut(&block_ref) {
                fetch.requested_from.insert(peer);
            }
            self.send_network(peer, NetworkMessage::RbcHeaderRequest(block_ref));
        }
    }

    fn peer_disconnected(&mut self, peer: AuthorityIndex) {
        if !self.committee.known_authority(peer) {
            self.reject(Some(peer), RbcError::UnknownAuthority(peer).into());
            return;
        }
        if peer == self.own_authority {
            self.reject(Some(peer), RbcError::LoopbackPhase.into());
            return;
        }
        self.connected_peers.remove(peer);
    }

    fn send_network(&self, recipient: AuthorityIndex, message: NetworkMessage) {
        let _ = self
            .events
            .send(RbcServiceEvent::Network { recipient, message });
    }

    fn reject(&self, peer: Option<AuthorityIndex>, error: RbcServiceError) {
        let _ = self.events.send(RbcServiceEvent::Rejected { peer, error });
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{
        crypto::{
            dummy_ml_dsa_44_signer, dummy_ml_dsa_65_signer, dummy_signer, mac_keyrings_for_test,
        },
        starfish_rbc::RbcPhase,
        types::{TransactionData, VerifiedBlock},
    };

    fn instance() -> RbcProtocolInstanceId {
        RbcProtocolInstanceId::new([0x51; 32]).unwrap()
    }

    fn local_header(round: RoundNumber, committee_size: AuthorityIndex) -> RbcLocalHeader {
        RbcLocalHeader {
            round,
            block_references: (0..committee_size)
                .map(|authority| BlockReference::new_test(authority, round - 1))
                .collect(),
            acknowledgment_references: Vec::new(),
            meta_creation_time_ns: 17,
            transactions_commitment: TransactionsCommitment::default(),
        }
    }

    fn start_service(
        own_authority: AuthorityIndex,
        scheme: BlockAuthenticationScheme,
    ) -> (
        RbcServiceHandle,
        mpsc::UnboundedReceiver<RbcServiceEvent>,
        JoinHandle<()>,
    ) {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let authenticator = match scheme {
            BlockAuthenticationScheme::Ed25519 => RbcInitialAuthenticator::Ed25519(dummy_signer()),
            BlockAuthenticationScheme::MacVector => RbcInitialAuthenticator::Mac,
            BlockAuthenticationScheme::MlDsa44 => {
                RbcInitialAuthenticator::MlDsa44(dummy_ml_dsa_44_signer())
            }
            BlockAuthenticationScheme::MlDsa65 => {
                RbcInitialAuthenticator::MlDsa65(dummy_ml_dsa_65_signer())
            }
        };
        start_starfish_rbc_service(
            committee,
            own_authority,
            instance(),
            scheme,
            Arc::new(keyrings[own_authority as usize].clone()),
            authenticator,
            1,
            Duration::from_secs(3_600),
        )
        .unwrap()
    }

    async fn next_event(events: &mut mpsc::UnboundedReceiver<RbcServiceEvent>) -> RbcServiceEvent {
        tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("service event timed out")
            .expect("service stopped unexpectedly")
    }

    #[tokio::test]
    async fn local_initial_authenticator_wiring_covers_all_four_modes() {
        for scheme in [
            BlockAuthenticationScheme::Ed25519,
            BlockAuthenticationScheme::MlDsa44,
            BlockAuthenticationScheme::MlDsa65,
            BlockAuthenticationScheme::MacVector,
        ] {
            let (handle, mut events, task) = start_service(0, scheme);
            let canonical = handle.start_local_header(local_header(1, 4)).await.unwrap();
            assert!(matches!(
                next_event(&mut events).await,
                RbcServiceEvent::HeaderStaged(ref header)
                    if header.reference() == canonical.reference()
            ));
            let RbcServiceEvent::Network {
                recipient: 1,
                message: NetworkMessage::RbcInitial(proposal),
            } = next_event(&mut events).await
            else {
                panic!("expected first recipient's INIT")
            };
            let proof_matches = matches!(
                (scheme, proposal.proof()),
                (
                    BlockAuthenticationScheme::Ed25519,
                    RbcInitialProof::Ed25519(_)
                ) | (
                    BlockAuthenticationScheme::MlDsa44,
                    RbcInitialProof::MlDsa44(_)
                ) | (
                    BlockAuthenticationScheme::MlDsa65,
                    RbcInitialProof::MlDsa65(_)
                ) | (
                    BlockAuthenticationScheme::MacVector,
                    RbcInitialProof::Mac(_)
                )
            );
            assert!(proof_matches, "wrong INIT proof for {scheme:?}");

            let committee = Committee::new_test(vec![1; 4]);
            let keyrings = mac_keyrings_for_test(4);
            let mut receiver = StarfishRbcKernel::new(
                committee,
                1,
                instance(),
                scheme,
                Arc::new(keyrings[1].clone()),
                1,
            )
            .unwrap();
            assert!(matches!(
                receiver
                    .accept_direct_initial_header(0, proposal.header().clone(), proposal.proof(),)
                    .unwrap(),
                RbcInitialHeaderOutcome::Authenticated { .. }
            ));

            // Two remaining INITs and three recipient-specific ECHOs.
            for _ in 0..5 {
                let _ = next_event(&mut events).await;
            }
            drop(handle);
            task.await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_local_start_waits_for_kernel_selection_and_event_enqueue() {
        let (handle, mut events, task) = start_service(0, BlockAuthenticationScheme::Ed25519);
        let blocking_handle = handle.clone();
        let canonical = tokio::task::spawn_blocking(move || {
            blocking_handle.start_local_header_with_payload_blocking(local_header(1, 4), None)
        })
        .await
        .unwrap()
        .unwrap();

        assert!(matches!(
            next_event(&mut events).await,
            RbcServiceEvent::HeaderStaged(ref header)
                if header.reference() == canonical.reference()
        ));
        drop(handle);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn local_payload_is_header_free_and_replayed_after_initial() {
        let (handle, mut events, task) = start_service(0, BlockAuthenticationScheme::MacVector);
        let transaction_data = TransactionData::new(Vec::new());
        let canonical = handle
            .start_local_header_with_payload(local_header(1, 4), Some(transaction_data))
            .await
            .unwrap();

        assert!(matches!(
            next_event(&mut events).await,
            RbcServiceEvent::HeaderStaged(ref header) if header.reference() == canonical.reference()
        ));
        for expected_recipient in 1..4 {
            assert!(matches!(
                next_event(&mut events).await,
                RbcServiceEvent::Network {
                    recipient,
                    message: NetworkMessage::RbcInitial(ref proposal),
                } if recipient == expected_recipient && proposal.header() == &canonical
            ));
            assert!(matches!(
                next_event(&mut events).await,
                RbcServiceEvent::Network {
                    recipient,
                    message: NetworkMessage::RbcTransactionPayload(ref payload),
                } if recipient == expected_recipient
                    && payload.block_reference() == canonical.reference()
            ));
        }

        // Drain the three initial ECHO messages, then reconnect one peer. The
        // replay FIFO must put INIT and payload before the rematerialized ECHO.
        for _ in 0..3 {
            assert!(matches!(
                next_event(&mut events).await,
                RbcServiceEvent::Network {
                    message: NetworkMessage::RbcPhase(_),
                    ..
                }
            ));
        }
        handle.peer_connected(2).unwrap();
        assert!(matches!(
            next_event(&mut events).await,
            RbcServiceEvent::Network {
                recipient: 2,
                message: NetworkMessage::RbcInitial(_),
            }
        ));
        assert!(matches!(
            next_event(&mut events).await,
            RbcServiceEvent::Network {
                recipient: 2,
                message: NetworkMessage::RbcTransactionPayload(ref payload),
            } if payload.block_reference() == canonical.reference()
        ));
        assert!(matches!(
            next_event(&mut events).await,
            RbcServiceEvent::Network {
                recipient: 2,
                message: NetworkMessage::RbcPhase(ref message),
            } if message.phase() == RbcPhase::Echo
        ));

        drop(handle);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn transaction_payload_requires_its_pinned_header_and_direct_author() {
        let (handle, mut events, task) = start_service(1, BlockAuthenticationScheme::MacVector);
        let block_ref = BlockReference::new_test(0, 1);
        let payload = RbcTransactionPayload::new(block_ref, TransactionData::new(Vec::new()));

        handle.transaction_payload(0, payload.clone()).unwrap();
        assert!(matches!(
            next_event(&mut events).await,
            RbcServiceEvent::Rejected {
                peer: Some(0),
                error: RbcServiceError::UnexpectedTransactionPayload(reference),
            } if reference == block_ref
        ));

        handle.transaction_payload(2, payload).unwrap();
        assert!(matches!(
            next_event(&mut events).await,
            RbcServiceEvent::Rejected {
                peer: Some(2),
                error: RbcServiceError::TransactionPayloadNotFromAuthor {
                    block_ref: reference,
                    peer: 2,
                },
            } if reference == block_ref
        ));

        drop(handle);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn local_start_advances_the_admission_window_before_pinning() {
        let (handle, events, task) = start_service(0, BlockAuthenticationScheme::Ed25519);

        // The kernel starts at round 1, whose ordinary future-admission window
        // ends at round 101. A locally selected proposal is trusted progress
        // and must move that window before its own reference is validated.
        let canonical = handle
            .start_local_header(local_header(150, 4))
            .await
            .unwrap();
        assert_eq!(canonical.reference().round, 150);

        drop(handle);
        drop(events);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn local_mac_start_materializes_distinct_recipient_messages() {
        let (handle, mut events, task) = start_service(0, BlockAuthenticationScheme::MacVector);
        let canonical = handle.start_local_header(local_header(1, 4)).await.unwrap();

        assert!(matches!(
            next_event(&mut events).await,
            RbcServiceEvent::HeaderStaged(ref header) if header.reference() == canonical.reference()
        ));

        let mut initial_proofs = Vec::new();
        for expected_recipient in 1..4 {
            let RbcServiceEvent::Network { recipient, message } = next_event(&mut events).await
            else {
                panic!("expected initial network event")
            };
            assert_eq!(recipient, expected_recipient);
            let NetworkMessage::RbcInitial(proposal) = message else {
                panic!("expected initial proposal")
            };
            assert_eq!(proposal.header(), &canonical);
            let RbcInitialProof::Mac(tag) = proposal.proof() else {
                panic!("MAC mode must send one tag")
            };
            initial_proofs.push(*tag);
        }
        assert!(initial_proofs.windows(2).all(|pair| pair[0] != pair[1]));

        let mut phases = Vec::new();
        for expected_recipient in 1..4 {
            let RbcServiceEvent::Network { recipient, message } = next_event(&mut events).await
            else {
                panic!("expected phase network event")
            };
            assert_eq!(recipient, expected_recipient);
            let NetworkMessage::RbcPhase(message) = message else {
                panic!("expected RBC phase")
            };
            assert_eq!(message.phase(), RbcPhase::Echo);
            assert_eq!(message.recipient(), recipient);
            assert_eq!(message.sender(), 0);
            phases.push(message);
        }
        assert!(phases.windows(2).all(|pair| pair[0] != pair[1]));

        // The initial proposal and authorized phase intent survive a missing
        // connection. Reconnection replays INIT first and rematerializes a
        // fresh recipient-specific phase message from the kernel intent.
        handle.peer_connected(2).unwrap();
        assert!(matches!(
            next_event(&mut events).await,
            RbcServiceEvent::Network {
                recipient: 2,
                message: NetworkMessage::RbcInitial(ref proposal),
            } if proposal.header() == &canonical
        ));
        assert!(matches!(
            next_event(&mut events).await,
            RbcServiceEvent::Network {
                recipient: 2,
                message: NetworkMessage::RbcPhase(ref message),
            } if message.phase() == RbcPhase::Echo && message.recipient() == 2
        ));

        handle.header_request(1, canonical.reference()).unwrap();
        let RbcServiceEvent::Network { recipient, message } = next_event(&mut events).await else {
            panic!("expected header response")
        };
        assert_eq!(recipient, 1);
        assert!(matches!(
            message,
            NetworkMessage::RbcHeaderResponse(header) if header == canonical
        ));

        drop(handle);
        task.await.unwrap();
    }

    fn echo_messages_for(
        canonical: &RbcCanonicalHeader,
        recipient: AuthorityIndex,
    ) -> Vec<(AuthorityIndex, RbcPhaseMessage)> {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let mut author = StarfishRbcKernel::new(
            committee.clone(),
            0,
            instance(),
            BlockAuthenticationScheme::Ed25519,
            Arc::new(keyrings[0].clone()),
            1,
        )
        .unwrap();
        let local = author
            .start_local_initial_header(
                canonical.reference().round,
                canonical.block_references().to_vec(),
                canonical.acknowledgment_references(),
                canonical.meta_creation_time_ns(),
                canonical.transactions_commitment(),
            )
            .unwrap();
        let digest = author.make_local_initial_signature_digest(&local).unwrap();
        let proof = RbcInitialProof::Ed25519(dummy_signer().sign_digest(&digest));
        drop(local.into_parts());

        let mut messages = vec![(
            0,
            author
                .make_phase_message(RbcPhase::Echo, canonical.reference(), recipient)
                .unwrap(),
        )];
        for sender in 1..=2 {
            let mut kernel = StarfishRbcKernel::new(
                committee.clone(),
                sender,
                instance(),
                BlockAuthenticationScheme::Ed25519,
                Arc::new(keyrings[sender as usize].clone()),
                1,
            )
            .unwrap();
            let outcome = kernel
                .accept_direct_initial_header(0, canonical.clone(), &proof)
                .unwrap();
            assert!(matches!(
                outcome,
                RbcInitialHeaderOutcome::Authenticated { .. }
            ));
            messages.push((
                sender,
                kernel
                    .make_phase_message(RbcPhase::Echo, canonical.reference(), recipient)
                    .unwrap(),
            ));
        }
        messages
    }

    #[tokio::test]
    async fn header_recovery_is_durable_and_fans_out_to_new_holders() {
        let (handle, mut events, task) = start_service(3, BlockAuthenticationScheme::Ed25519);
        for peer in 0..3 {
            handle.peer_connected(peer).unwrap();
        }

        let canonical = RbcCanonicalHeader::try_new(
            0,
            1,
            (0..4)
                .map(|authority| *VerifiedBlock::new_genesis(authority).reference())
                .collect(),
            Vec::new(),
            23,
            TransactionsCommitment::default(),
        )
        .unwrap();
        for (peer, message) in echo_messages_for(&canonical, 3) {
            handle.phase(peer, message).unwrap();
        }

        let mut first_wave = Vec::new();
        for _ in 0..2 {
            let RbcServiceEvent::Network { recipient, message } = next_event(&mut events).await
            else {
                panic!("expected header request")
            };
            assert!(matches!(
                message,
                NetworkMessage::RbcHeaderRequest(block_ref) if block_ref == canonical.reference()
            ));
            first_wave.push(recipient);
        }
        assert_eq!(first_wave, vec![0, 1]);

        let unrelated = RbcCanonicalHeader::try_new(
            1,
            1,
            canonical.block_references().to_vec(),
            Vec::new(),
            24,
            TransactionsCommitment::default(),
        )
        .unwrap();
        handle.header_response(0, unrelated).unwrap();
        assert!(matches!(
            next_event(&mut events).await,
            RbcServiceEvent::Rejected {
                peer: Some(0),
                error: RbcServiceError::UnexpectedHeaderResponse(_),
            }
        ));

        // Replacing a connection does not own or discard the fetch. The
        // central actor immediately retries the still-pending reference when
        // the untried authenticated holder reconnects.
        handle.peer_disconnected(2).unwrap();
        handle.peer_connected(2).unwrap();
        let RbcServiceEvent::Network { recipient, message } = next_event(&mut events).await else {
            panic!("expected reconnect retry to the untried holder")
        };
        assert_eq!(recipient, 2);
        assert!(matches!(
            message,
            NetworkMessage::RbcHeaderRequest(block_ref) if block_ref == canonical.reference()
        ));

        handle.header_response(2, canonical.clone()).unwrap();
        assert!(matches!(
            next_event(&mut events).await,
            RbcServiceEvent::HeaderStaged(ref header) if header.reference() == canonical.reference()
        ));
        for expected_recipient in 0..3 {
            let RbcServiceEvent::Network { recipient, message } = next_event(&mut events).await
            else {
                panic!("expected READY after recovery")
            };
            assert_eq!(recipient, expected_recipient);
            assert!(matches!(
                message,
                NetworkMessage::RbcPhase(ref phase)
                    if phase.phase() == RbcPhase::Ready
                        && phase.recipient() == expected_recipient
            ));
        }

        handle.retry_headers().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), events.recv())
                .await
                .is_err()
        );

        drop(handle);
        task.await.unwrap();
    }

    #[test]
    fn service_rejects_mismatched_initial_authenticator() {
        let committee = Committee::new_test(vec![1; 4]);
        let keyrings = mac_keyrings_for_test(4);
        let result = start_starfish_rbc_service(
            committee,
            0,
            instance(),
            BlockAuthenticationScheme::Ed25519,
            Arc::new(keyrings[0].clone()),
            RbcInitialAuthenticator::Mac,
            1,
            Duration::from_secs(1),
        );
        assert!(matches!(
            result,
            Err(RbcServiceError::InitialAuthenticatorSchemeMismatch { .. })
        ));
    }
}
