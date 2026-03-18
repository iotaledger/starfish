// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Async Sailfish++ certification and control service.
//!
//! Receives blocks and signature-free RBC phase messages, runs the
//! [`CertificationAggregator`], aggregates timeout and no-vote messages,
//! and emits certification/control events back to the syncer thread.

use std::{collections::VecDeque, sync::Arc};

use ahash::AHashMap;
use tokio::sync::mpsc;

use crate::{
    cert_aggregator::{CertEvent, CertificationAggregator},
    committee::Committee,
    crypto::{self, SignatureBytes, Signer},
    metrics::Metrics,
    types::{
        AuthorityIndex, BlockReference, CertMessage, CertMessageKind, RoundNumber,
        SailfishNoVoteCert, SailfishNoVoteMsg, SailfishTimeoutCert, SailfishTimeoutMsg, Stake,
    },
};

// ---------------------------------------------------------------------------
// Messages into the service
// ---------------------------------------------------------------------------

/// Messages sent to the Sailfish service.
#[allow(dead_code)]
pub enum SailfishServiceMessage {
    /// New blocks arrived — generate self-echoes.
    ProcessBlocks(Vec<BlockReference>),
    /// Incoming RBC message from a peer.
    CertMessage(CertMessage),
    /// Incoming signed timeout message from a peer.
    TimeoutMsg(SailfishTimeoutMsg),
    /// Incoming signed no-vote message from a peer.
    NoVoteMsg(SailfishNoVoteMsg),
    /// Local timeout expired for a round — sign and broadcast own timeout.
    LocalTimeout(RoundNumber),
    /// Local no-vote: we advanced past round `round` without voting for
    /// `leader`. Sign and send to the next-round leader.
    LocalNoVote {
        round: RoundNumber,
        leader: AuthorityIndex,
    },
    /// Cleanup aggregator state below round.
    Cleanup(RoundNumber),
}

// ---------------------------------------------------------------------------
// Events out of the service
// ---------------------------------------------------------------------------

/// Events sent back to the syncer/core thread.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SailfishCertEvent {
    /// Block certified (fast or slow path).
    Certified(BlockReference),
    /// Broadcast an RBC phase message to all peers.
    Broadcast(CertMessage),
    /// Broadcast a signed timeout message to all peers.
    BroadcastTimeout(SailfishTimeoutMsg),
    /// Send a signed no-vote message to the next-round leader.
    SendNoVote(SailfishNoVoteMsg),
    /// Timeout certificate formed for a round.
    TimeoutReady(SailfishTimeoutCert),
    /// No-vote certificate formed for (round, leader).
    NoVoteReady(SailfishNoVoteCert),
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// Handle for sending messages to the Sailfish service.
#[derive(Clone)]
pub struct SailfishServiceHandle {
    sender: mpsc::UnboundedSender<SailfishServiceMessage>,
}

impl SailfishServiceHandle {
    pub fn new(sender: mpsc::UnboundedSender<SailfishServiceMessage>) -> Self {
        Self { sender }
    }

    pub fn send(&self, msg: SailfishServiceMessage) {
        let _ = self.sender.send(msg);
    }
}

// ---------------------------------------------------------------------------
// Signed quorum aggregator — shared by timeout and no-vote paths
// ---------------------------------------------------------------------------

/// Accumulates signed messages from distinct authorities until a quorum
/// (2f+1 stake) is reached. Used for both timeout and no-vote certificates.
struct SignedQuorumAggregator {
    stake: Stake,
    seen: u128,
    signatures: Vec<(AuthorityIndex, SignatureBytes)>,
    formed: bool,
}

impl SignedQuorumAggregator {
    fn new() -> Self {
        Self {
            stake: 0,
            seen: 0,
            signatures: Vec::new(),
            formed: false,
        }
    }

    /// Try to add a signed message. Returns `true` when quorum is reached
    /// for the first time.
    fn add(
        &mut self,
        sender: AuthorityIndex,
        signature: SignatureBytes,
        committee: &Committee,
    ) -> bool {
        if self.formed {
            return false;
        }
        let mask = 1u128 << sender;
        if self.seen & mask != 0 {
            return false;
        }
        self.seen |= mask;
        self.stake += committee.get_stake(sender).unwrap_or(0);
        self.signatures.push((sender, signature));
        if self.stake >= committee.quorum_threshold() {
            self.formed = true;
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Service lifetime
// ---------------------------------------------------------------------------

/// Start the Sailfish RBC certification service as a tokio task.
pub fn start_sailfish_service(
    committee: Arc<Committee>,
    own_authority: AuthorityIndex,
    signer: Signer,
    receiver: mpsc::UnboundedReceiver<SailfishServiceMessage>,
    event_tx: mpsc::UnboundedSender<Vec<SailfishCertEvent>>,
    metrics: Arc<Metrics>,
) {
    tokio::spawn(run_sailfish_service(
        committee,
        own_authority,
        signer,
        receiver,
        event_tx,
        metrics,
    ));
}

async fn run_sailfish_service(
    committee: Arc<Committee>,
    own_authority: AuthorityIndex,
    signer: Signer,
    mut receiver: mpsc::UnboundedReceiver<SailfishServiceMessage>,
    event_tx: mpsc::UnboundedSender<Vec<SailfishCertEvent>>,
    metrics: Arc<Metrics>,
) {
    let mut state = ServiceState::new(committee, own_authority, signer, metrics);

    while let Some(msg) = receiver.recv().await {
        let mut all_events = Vec::new();

        state.process_message(msg, &mut all_events);

        while let Ok(msg) = receiver.try_recv() {
            state.process_message(msg, &mut all_events);
        }

        if !all_events.is_empty() {
            let _ = event_tx.send(all_events);
        }
    }
}

// ---------------------------------------------------------------------------
// Service state (all aggregators)
// ---------------------------------------------------------------------------

/// Result of checking an inbound RBC message against known canonical blocks.
enum RbcAcceptance {
    /// Block is known and the message references the canonical digest.
    Canonical,
    /// Block is known but the message references a different digest.
    Conflicting,
    /// No block is registered for this (round, authority) slot yet.
    Unknown,
}

struct ServiceState {
    committee: Arc<Committee>,
    own_authority: AuthorityIndex,
    signer: Signer,
    metrics: Arc<Metrics>,
    rbc: CertificationAggregator,
    canonical_blocks: AHashMap<(RoundNumber, AuthorityIndex), BlockReference>,
    /// RBC messages that arrived before the corresponding block was seen.
    /// Keyed by (round, authority) slot. Drained when the block is registered.
    pending_rbc: AHashMap<(RoundNumber, AuthorityIndex), Vec<CertMessage>>,
    /// Maximum number of buffered messages per slot (bound against spam).
    pending_rbc_cap: usize,
    timeouts: AHashMap<RoundNumber, SignedQuorumAggregator>,
    no_votes: AHashMap<(RoundNumber, AuthorityIndex), SignedQuorumAggregator>,
}

impl ServiceState {
    fn new(
        committee: Arc<Committee>,
        own_authority: AuthorityIndex,
        signer: Signer,
        metrics: Arc<Metrics>,
    ) -> Self {
        // At most 3 message types (Echo, Vote, Ready) per authority.
        let pending_rbc_cap = 3 * committee.len();
        Self {
            rbc: CertificationAggregator::new(committee.clone()),
            committee,
            own_authority,
            signer,
            metrics,
            canonical_blocks: AHashMap::new(),
            pending_rbc: AHashMap::new(),
            pending_rbc_cap,
            timeouts: AHashMap::new(),
            no_votes: AHashMap::new(),
        }
    }

    fn process_message(
        &mut self,
        msg: SailfishServiceMessage,
        events: &mut Vec<SailfishCertEvent>,
    ) {
        match msg {
            SailfishServiceMessage::ProcessBlocks(block_refs) => {
                for block_ref in block_refs {
                    if !self.register_canonical_block(block_ref, events) {
                        continue;
                    }
                    let echo = CertMessage {
                        block_ref,
                        sender: self.own_authority,
                        kind: CertMessageKind::Echo,
                    };
                    let cert_events = self.rbc.add_message(&echo);
                    self.dispatch_cert_events(cert_events, events);
                    events.push(SailfishCertEvent::Broadcast(echo));
                }
            }
            SailfishServiceMessage::CertMessage(message) => {
                match self.accept_rbc_message(&message) {
                    RbcAcceptance::Canonical => {
                        let cert_events = self.rbc.add_message(&message);
                        self.dispatch_cert_events(cert_events, events);
                    }
                    RbcAcceptance::Unknown => {
                        self.buffer_rbc_message(message);
                    }
                    RbcAcceptance::Conflicting => {}
                }
            }
            SailfishServiceMessage::TimeoutMsg(msg) => {
                self.add_timeout_msg(msg, events);
            }
            SailfishServiceMessage::NoVoteMsg(msg) => {
                self.add_novote_msg(msg, events);
            }
            SailfishServiceMessage::LocalTimeout(round) => {
                self.handle_local_timeout(round, events);
            }
            SailfishServiceMessage::LocalNoVote { round, leader } => {
                self.handle_local_novote(round, leader, events);
            }
            SailfishServiceMessage::Cleanup(round) => {
                self.rbc.cleanup_below_round(round);
                self.canonical_blocks.retain(|&(r, _), _| r >= round);
                self.pending_rbc.retain(|&(r, _), _| r >= round);
                self.timeouts.retain(|&r, _| r >= round);
                self.no_votes.retain(|&(r, _), _| r >= round);
            }
        }
    }

    fn register_canonical_block(
        &mut self,
        block_ref: BlockReference,
        events: &mut Vec<SailfishCertEvent>,
    ) -> bool {
        let slot = (block_ref.round, block_ref.authority);
        match self.canonical_blocks.get(&slot).copied() {
            None => {
                self.canonical_blocks.insert(slot, block_ref);
                // Drain any early RBC messages buffered for this slot.
                if let Some(buffered) = self.pending_rbc.remove(&slot) {
                    for msg in buffered {
                        if msg.block_ref == block_ref {
                            let cert_events = self.rbc.add_message(&msg);
                            self.dispatch_cert_events(cert_events, events);
                        }
                    }
                }
                true
            }
            Some(canonical) => {
                if canonical != block_ref {
                    tracing::warn!(
                        "Ignoring conflicting Sailfish block {:?}; \
                         canonical for ({}, {}) is {:?}",
                        block_ref,
                        block_ref.authority,
                        block_ref.round,
                        canonical,
                    );
                }
                false
            }
        }
    }

    fn accept_rbc_message(&self, message: &CertMessage) -> RbcAcceptance {
        let slot = (message.block_ref.round, message.block_ref.authority);
        match self.canonical_blocks.get(&slot) {
            Some(canonical) if *canonical == message.block_ref => RbcAcceptance::Canonical,
            Some(canonical) => {
                tracing::debug!(
                    "Ignoring RBC {:?} for conflicting block {:?}; \
                     canonical is {:?}",
                    message.kind,
                    message.block_ref,
                    canonical,
                );
                RbcAcceptance::Conflicting
            }
            None => RbcAcceptance::Unknown,
        }
    }

    /// Buffer an RBC message for a block we haven't seen yet.
    fn buffer_rbc_message(&mut self, message: CertMessage) {
        let slot = (message.block_ref.round, message.block_ref.authority);
        let buf = self.pending_rbc.entry(slot).or_default();
        if buf.len() >= self.pending_rbc_cap {
            tracing::warn!(
                "Dropping RBC {:?} for slot ({}, {}): buffer full",
                message.kind,
                slot.0,
                slot.1,
            );
            return;
        }
        buf.push(message);
    }

    // -- RBC event dispatch --------------------------------------------------

    fn dispatch_cert_events(
        &mut self,
        cert_events: Vec<CertEvent>,
        out: &mut Vec<SailfishCertEvent>,
    ) {
        let mut pending = VecDeque::from(cert_events);
        while let Some(event) = pending.pop_front() {
            match event {
                CertEvent::FastDelivery(block_ref) => {
                    self.metrics.sailfish_rbc_fast_total.inc();
                    out.push(SailfishCertEvent::Certified(block_ref));
                }
                CertEvent::SlowDelivery(block_ref) => {
                    self.metrics.sailfish_rbc_slow_total.inc();
                    out.push(SailfishCertEvent::Certified(block_ref));
                }
                CertEvent::SendVote(block_ref) => {
                    let vote = CertMessage {
                        block_ref,
                        sender: self.own_authority,
                        kind: CertMessageKind::Vote,
                    };
                    pending.extend(self.rbc.add_message(&vote));
                    out.push(SailfishCertEvent::Broadcast(vote));
                }
                CertEvent::SendReady(block_ref) => {
                    let ready = CertMessage {
                        block_ref,
                        sender: self.own_authority,
                        kind: CertMessageKind::Ready,
                    };
                    pending.extend(self.rbc.add_message(&ready));
                    out.push(SailfishCertEvent::Broadcast(ready));
                }
            }
        }
    }

    // -- Timeout aggregation -------------------------------------------------

    /// Sign a local timeout, count it, and emit a broadcast event.
    fn handle_local_timeout(&mut self, round: RoundNumber, events: &mut Vec<SailfishCertEvent>) {
        let digest = crypto::sailfish_timeout_digest(round);
        let signature = self.signer.sign_digest(&digest);
        let msg = SailfishTimeoutMsg {
            round,
            sender: self.own_authority,
            signature,
        };
        // Count own message in the aggregator first (may form cert immediately).
        self.add_verified_timeout(msg.clone(), events);
        events.push(SailfishCertEvent::BroadcastTimeout(msg));
    }

    fn add_timeout_msg(&mut self, msg: SailfishTimeoutMsg, events: &mut Vec<SailfishCertEvent>) {
        // Verify signature before aggregation.
        let digest = crypto::sailfish_timeout_digest(msg.round);
        let pk = match self.committee.get_public_key(msg.sender) {
            Some(pk) => pk,
            None => return,
        };
        if pk.verify_digest_signature(&digest, &msg.signature).is_err() {
            tracing::warn!(
                "Rejected invalid timeout sig from {} for round {}",
                msg.sender,
                msg.round,
            );
            return;
        }
        self.add_verified_timeout(msg, events);
    }

    /// Add a pre-verified timeout message to the aggregator.
    fn add_verified_timeout(
        &mut self,
        msg: SailfishTimeoutMsg,
        events: &mut Vec<SailfishCertEvent>,
    ) {
        let agg = self
            .timeouts
            .entry(msg.round)
            .or_insert_with(SignedQuorumAggregator::new);
        if agg.add(msg.sender, msg.signature, &self.committee) {
            events.push(SailfishCertEvent::TimeoutReady(SailfishTimeoutCert {
                round: msg.round,
                signatures: agg.signatures.clone(),
            }));
        }
    }

    // -- No-vote aggregation -------------------------------------------------

    /// Sign a local no-vote, count it, and emit a send event.
    fn handle_local_novote(
        &mut self,
        round: RoundNumber,
        leader: AuthorityIndex,
        events: &mut Vec<SailfishCertEvent>,
    ) {
        let digest = crypto::sailfish_novote_digest(round, leader);
        let signature = self.signer.sign_digest(&digest);
        let msg = SailfishNoVoteMsg {
            round,
            leader,
            sender: self.own_authority,
            signature,
        };
        self.add_verified_novote(msg.clone(), events);
        events.push(SailfishCertEvent::SendNoVote(msg));
    }

    fn add_novote_msg(&mut self, msg: SailfishNoVoteMsg, events: &mut Vec<SailfishCertEvent>) {
        // Verify signature before aggregation.
        let digest = crypto::sailfish_novote_digest(msg.round, msg.leader);
        let pk = match self.committee.get_public_key(msg.sender) {
            Some(pk) => pk,
            None => return,
        };
        if pk.verify_digest_signature(&digest, &msg.signature).is_err() {
            tracing::warn!(
                "Rejected invalid novote sig from {} for round {}, leader {}",
                msg.sender,
                msg.round,
                msg.leader,
            );
            return;
        }
        self.add_verified_novote(msg, events);
    }

    /// Add a pre-verified no-vote message to the aggregator.
    fn add_verified_novote(&mut self, msg: SailfishNoVoteMsg, events: &mut Vec<SailfishCertEvent>) {
        let agg = self
            .no_votes
            .entry((msg.round, msg.leader))
            .or_insert_with(SignedQuorumAggregator::new);
        if agg.add(msg.sender, msg.signature, &self.committee) {
            events.push(SailfishCertEvent::NoVoteReady(SailfishNoVoteCert {
                round: msg.round,
                leader: msg.leader,
                signatures: agg.signatures.clone(),
            }));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use prometheus::Registry;
    use tokio::time::timeout;

    use super::*;
    use crate::crypto;

    fn make_committee(n: usize) -> Arc<Committee> {
        Committee::new_test(vec![1; n])
    }

    fn test_signer(authority: AuthorityIndex) -> Signer {
        Signer::new_for_test(authority as usize + 1)
            .into_iter()
            .nth(authority as usize)
            .unwrap()
    }

    fn test_metrics() -> Arc<Metrics> {
        Metrics::new(&Registry::new(), None, None, None).0
    }

    fn conflicting_ref(block_ref: BlockReference) -> BlockReference {
        BlockReference {
            digest: crate::crypto::BlockDigest::new_without_transactions(
                block_ref.authority,
                block_ref.round,
                &[],
                &[],
                1,
                &crate::crypto::SignatureBytes::default(),
                crate::crypto::TransactionsCommitment::default(),
                None,
            ),
            ..block_ref
        }
    }

    /// N=4, F=1: 2 echoes triggers FastDelivery + SendVote + SendReady.
    /// Verifies that the local vote and ready are counted (via add_message)
    /// before being broadcast.
    #[tokio::test]
    async fn echoes_trigger_fast_delivery_and_vote_and_ready() {
        let committee = make_committee(4);
        let own_authority = 1;
        let block_ref = BlockReference::new_test(0, 7);
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(
            committee,
            own_authority,
            test_signer(own_authority),
            msg_rx,
            event_tx,
            test_metrics(),
        );

        // Own echo broadcast.
        msg_tx
            .send(SailfishServiceMessage::ProcessBlocks(vec![block_ref]))
            .unwrap();
        let events = event_rx
            .recv()
            .await
            .expect("expected local echo broadcast");
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage { kind, .. })
                    if *kind == CertMessageKind::Echo
            )
        }));

        // Second echo crosses all three thresholds at once.
        msg_tx
            .send(SailfishServiceMessage::CertMessage(CertMessage {
                block_ref,
                sender: 2,
                kind: CertMessageKind::Echo,
            }))
            .unwrap();
        let events = event_rx
            .recv()
            .await
            .expect("expected certification + vote + ready events");
        assert!(events.iter().any(|event| {
            matches!(event, SailfishCertEvent::Certified(received) if *received == block_ref)
        }));
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage { sender, kind, .. })
                    if *sender == own_authority && *kind == CertMessageKind::Vote
            )
        }));
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage { sender, kind, .. })
                    if *sender == own_authority && *kind == CertMessageKind::Ready
            )
        }));
    }

    /// For a locally-authored block, the service still broadcasts the local
    /// echo, but the broadcaster's echo must not count toward optimistic Echo
    /// or Vote thresholds.
    #[tokio::test]
    async fn local_author_echo_is_broadcast_but_not_counted() {
        let committee = make_committee(4);
        let own_authority = 0;
        let block_ref = BlockReference::new_test(0, 7);
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(
            committee,
            own_authority,
            test_signer(own_authority),
            msg_rx,
            event_tx,
            test_metrics(),
        );

        msg_tx
            .send(SailfishServiceMessage::ProcessBlocks(vec![block_ref]))
            .unwrap();
        let events = event_rx
            .recv()
            .await
            .expect("expected local echo broadcast");
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage {
                    sender,
                    block_ref: received,
                    kind,
                }) if *sender == own_authority
                    && *received == block_ref
                    && *kind == CertMessageKind::Echo
            )
        }));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, SailfishCertEvent::Certified(_)))
        );

        msg_tx
            .send(SailfishServiceMessage::CertMessage(CertMessage {
                block_ref,
                sender: 1,
                kind: CertMessageKind::Echo,
            }))
            .unwrap();
        assert!(
            timeout(Duration::from_millis(50), event_rx.recv())
                .await
                .is_err(),
            "author echo + one peer echo must not reach optimistic thresholds"
        );

        msg_tx
            .send(SailfishServiceMessage::CertMessage(CertMessage {
                block_ref,
                sender: 2,
                kind: CertMessageKind::Echo,
            }))
            .unwrap();
        let events = event_rx
            .recv()
            .await
            .expect("expected certification after two non-author echoes");
        assert!(events.iter().any(|event| {
            matches!(event, SailfishCertEvent::Certified(received) if *received == block_ref)
        }));
    }

    /// N=7, F=2: 4 echoes triggers SendVote + SendReady (both at threshold 4).
    /// Then 4 peer readys (+ own ready already counted) reaches quorum for
    /// SlowDelivery.
    #[tokio::test]
    async fn echoes_trigger_vote_and_ready_then_slow_delivery() {
        let committee = make_committee(7);
        let own_authority = 1;
        let block_ref = BlockReference::new_test(0, 9);
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(
            committee,
            own_authority,
            test_signer(own_authority),
            msg_rx,
            event_tx,
            test_metrics(),
        );

        // Own echo.
        msg_tx
            .send(SailfishServiceMessage::ProcessBlocks(vec![block_ref]))
            .unwrap();
        let _ = event_rx
            .recv()
            .await
            .expect("expected local echo broadcast");

        // 3 more echoes → 4 total → SendVote + SendReady.
        for sender in [2, 3, 4] {
            msg_tx
                .send(SailfishServiceMessage::CertMessage(CertMessage {
                    block_ref,
                    sender,
                    kind: CertMessageKind::Echo,
                }))
                .unwrap();
        }
        let events = event_rx.recv().await.expect("expected vote + ready events");
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage { sender, kind, .. })
                    if *sender == own_authority && *kind == CertMessageKind::Vote
            )
        }));
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage { sender, kind, .. })
                    if *sender == own_authority && *kind == CertMessageKind::Ready
            )
        }));

        // 4 peer readys → ready_stake = 1 (own) + 4 = 5 ≥ quorum (5) → SlowDelivery.
        for sender in [2, 3, 4, 5] {
            msg_tx
                .send(SailfishServiceMessage::CertMessage(CertMessage {
                    block_ref,
                    sender,
                    kind: CertMessageKind::Ready,
                }))
                .unwrap();
        }
        let events = event_rx
            .recv()
            .await
            .expect("expected slow-path certification event");
        assert!(events.iter().any(|event| {
            matches!(event, SailfishCertEvent::Certified(received) if *received == block_ref)
        }));
    }

    /// N=4, F=1: quorum_threshold = 3. Three timeout messages form a TC.
    #[tokio::test]
    async fn timeout_cert_formation() {
        let committee = make_committee(4);
        let own_authority = 0;
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(
            committee.clone(),
            own_authority,
            test_signer(own_authority),
            msg_rx,
            event_tx,
            test_metrics(),
        );

        let round = 5;
        let signers = crate::crypto::Signer::new_for_test(4);
        let digest = crypto::sailfish_timeout_digest(round);

        // Send 3 timeout messages (quorum = 3 for N=4)
        for sender in 0..3u8 {
            let sig = signers[sender as usize].sign_digest(&digest);
            msg_tx
                .send(SailfishServiceMessage::TimeoutMsg(SailfishTimeoutMsg {
                    round,
                    sender,
                    signature: sig,
                }))
                .unwrap();
        }

        let events = event_rx.recv().await.expect("expected timeout cert");
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::TimeoutReady(cert) if cert.round == round
                    && cert.signatures.len() == 3
            )
        }));
    }

    #[tokio::test]
    async fn only_first_block_for_author_round_gets_local_echo() {
        let committee = make_committee(4);
        let own_authority = 1;
        let block_ref = BlockReference::new_test(0, 7);
        let conflicting = conflicting_ref(block_ref);
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(
            committee,
            own_authority,
            test_signer(own_authority),
            msg_rx,
            event_tx,
            test_metrics(),
        );

        msg_tx
            .send(SailfishServiceMessage::ProcessBlocks(vec![block_ref]))
            .unwrap();
        let events = event_rx.recv().await.expect("expected local echo");
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage { block_ref: received, kind, .. })
                    if *received == block_ref && *kind == CertMessageKind::Echo
            )
        }));

        msg_tx
            .send(SailfishServiceMessage::ProcessBlocks(vec![conflicting]))
            .unwrap();
        assert!(
            timeout(Duration::from_millis(50), event_rx.recv())
                .await
                .is_err(),
            "conflicting block for same (author, round) must not trigger another echo"
        );
    }

    #[tokio::test]
    async fn conflicting_rbc_messages_are_ignored_for_same_author_round() {
        let committee = make_committee(4);
        let own_authority = 1;
        let block_ref = BlockReference::new_test(0, 7);
        let conflicting = conflicting_ref(block_ref);
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(
            committee,
            own_authority,
            test_signer(own_authority),
            msg_rx,
            event_tx,
            test_metrics(),
        );

        msg_tx
            .send(SailfishServiceMessage::ProcessBlocks(vec![block_ref]))
            .unwrap();
        let _ = event_rx.recv().await.expect("expected local echo");

        msg_tx
            .send(SailfishServiceMessage::CertMessage(CertMessage {
                block_ref: conflicting,
                sender: 2,
                kind: CertMessageKind::Echo,
            }))
            .unwrap();
        assert!(
            timeout(Duration::from_millis(50), event_rx.recv())
                .await
                .is_err(),
            "conflicting RBC message must be ignored"
        );

        msg_tx
            .send(SailfishServiceMessage::CertMessage(CertMessage {
                block_ref,
                sender: 2,
                kind: CertMessageKind::Echo,
            }))
            .unwrap();
        let events = event_rx
            .recv()
            .await
            .expect("expected canonical block to keep progressing");
        assert!(events.iter().any(|event| {
            matches!(event, SailfishCertEvent::Certified(received) if *received == block_ref)
        }));
    }

    /// Early RBC messages for unknown blocks are buffered and produce no
    /// immediate events. Once the block arrives via ProcessBlocks, the
    /// buffered echo is drained and counted alongside the local echo.
    /// N=4, F=1: 2 echoes (buffered peer + own) reach fast-path quorum.
    #[tokio::test]
    async fn unknown_rbc_message_is_buffered_until_block_arrives() {
        let committee = make_committee(4);
        let own_authority = 1;
        let block_ref = BlockReference::new_test(0, 7);
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(
            committee,
            own_authority,
            test_signer(own_authority),
            msg_rx,
            event_tx,
            test_metrics(),
        );

        // Peer echo arrives before we know the block — must not produce events.
        msg_tx
            .send(SailfishServiceMessage::CertMessage(CertMessage {
                block_ref,
                sender: 2,
                kind: CertMessageKind::Echo,
            }))
            .unwrap();
        assert!(
            timeout(Duration::from_millis(50), event_rx.recv())
                .await
                .is_err(),
            "RBC messages for unknown blocks must not produce events immediately"
        );

        // Block arrives: the local echo + drained buffered echo reach quorum.
        msg_tx
            .send(SailfishServiceMessage::ProcessBlocks(vec![block_ref]))
            .unwrap();
        let events = event_rx.recv().await.expect("expected events");
        // Local echo is broadcast.
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage {
                    block_ref: received,
                    kind,
                    ..
                }) if *received == block_ref && *kind == CertMessageKind::Echo
            )
        }));
        // Buffered peer echo + own echo = 2 echoes → fast-path certification.
        assert!(
            events
                .iter()
                .any(|event| matches!(event, SailfishCertEvent::Certified(r) if *r == block_ref)),
            "buffered echo should contribute to certification after block arrives"
        );
    }

    /// N=7, F=2: Send echo + ready from two peers before the block arrives,
    /// then ProcessBlocks. The drained buffer should produce the local echo
    /// broadcast, the buffered echoes feeding into the aggregator, and the
    /// buffered readys feeding into the aggregator — all in one event batch.
    #[tokio::test]
    async fn buffered_rbc_messages_drain_on_block_arrival() {
        let committee = make_committee(7);
        let own_authority = 1;
        let block_ref = BlockReference::new_test(0, 9);
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(
            committee,
            own_authority,
            test_signer(own_authority),
            msg_rx,
            event_tx,
            test_metrics(),
        );

        // Buffer echoes from 3 peers before the block is known.
        for sender in [2, 3, 4] {
            msg_tx
                .send(SailfishServiceMessage::CertMessage(CertMessage {
                    block_ref,
                    sender,
                    kind: CertMessageKind::Echo,
                }))
                .unwrap();
        }
        // No events yet.
        assert!(
            timeout(Duration::from_millis(50), event_rx.recv())
                .await
                .is_err(),
        );

        // Block arrives: local echo + 3 buffered echoes = 4 echoes → quorum.
        msg_tx
            .send(SailfishServiceMessage::ProcessBlocks(vec![block_ref]))
            .unwrap();
        let events = event_rx.recv().await.expect("expected events");

        // Local echo is broadcast.
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage {
                    block_ref: received,
                    kind,
                    ..
                }) if *received == block_ref && *kind == CertMessageKind::Echo
            )
        }));
        // SendVote triggered (own vote broadcast).
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage {
                    sender,
                    kind,
                    ..
                }) if *sender == own_authority && *kind == CertMessageKind::Vote
            )
        }));
        // SendReady triggered (own ready broadcast).
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage {
                    sender,
                    kind,
                    ..
                }) if *sender == own_authority && *kind == CertMessageKind::Ready
            )
        }));
    }

    /// Buffered messages for a conflicting digest are discarded when the
    /// canonical block arrives.
    #[tokio::test]
    async fn buffered_conflicting_messages_discarded_on_block_arrival() {
        let committee = make_committee(4);
        let own_authority = 1;
        let block_ref = BlockReference::new_test(0, 7);
        let conflicting = conflicting_ref(block_ref);
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(
            committee,
            own_authority,
            test_signer(own_authority),
            msg_rx,
            event_tx,
            test_metrics(),
        );

        // Buffer an echo for the conflicting digest.
        msg_tx
            .send(SailfishServiceMessage::CertMessage(CertMessage {
                block_ref: conflicting,
                sender: 2,
                kind: CertMessageKind::Echo,
            }))
            .unwrap();
        assert!(
            timeout(Duration::from_millis(50), event_rx.recv())
                .await
                .is_err(),
        );

        // Canonical block arrives — conflicting buffered echo is dropped.
        msg_tx
            .send(SailfishServiceMessage::ProcessBlocks(vec![block_ref]))
            .unwrap();
        let events = event_rx.recv().await.expect("expected local echo");
        // Only local echo broadcast, no certification (would need 2 echoes).
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage { kind, .. })
                    if *kind == CertMessageKind::Echo
            )
        }));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, SailfishCertEvent::Certified(_))),
            "conflicting buffered echo must not count toward certification"
        );
    }

    /// N=4, F=1: quorum_threshold = 3. Three no-vote messages form a NVC.
    #[tokio::test]
    async fn novote_cert_formation() {
        let committee = make_committee(4);
        let own_authority = 0;
        let leader = 2;
        let round = 7;
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(
            committee.clone(),
            own_authority,
            test_signer(own_authority),
            msg_rx,
            event_tx,
            test_metrics(),
        );

        let signers = crate::crypto::Signer::new_for_test(4);
        let digest = crypto::sailfish_novote_digest(round, leader);

        for sender in 0..3u8 {
            let sig = signers[sender as usize].sign_digest(&digest);
            msg_tx
                .send(SailfishServiceMessage::NoVoteMsg(SailfishNoVoteMsg {
                    round,
                    leader,
                    sender,
                    signature: sig,
                }))
                .unwrap();
        }

        let events = event_rx.recv().await.expect("expected novote cert");
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::NoVoteReady(cert) if cert.round == round
                    && cert.leader == leader
                    && cert.signatures.len() == 3
            )
        }));
    }

    /// Duplicate timeout messages from the same sender are ignored.
    /// Sends sender=0 twice, then senders 1 and 2. With dedup, the cert
    /// should form from exactly 3 unique signers (0, 1, 2), not 4.
    #[tokio::test]
    async fn duplicate_timeout_ignored() {
        let committee = make_committee(4);
        let own_authority = 0;
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(
            committee.clone(),
            own_authority,
            test_signer(own_authority),
            msg_rx,
            event_tx,
            test_metrics(),
        );

        let round = 3;
        let signers = crate::crypto::Signer::new_for_test(4);
        let digest = crypto::sailfish_timeout_digest(round);
        let sig = signers[0].sign_digest(&digest);

        // Send same timeout twice from sender 0 (duplicate)
        msg_tx
            .send(SailfishServiceMessage::TimeoutMsg(SailfishTimeoutMsg {
                round,
                sender: 0,
                signature: sig,
            }))
            .unwrap();
        msg_tx
            .send(SailfishServiceMessage::TimeoutMsg(SailfishTimeoutMsg {
                round,
                sender: 0,
                signature: sig,
            }))
            .unwrap();
        // Two more unique senders to reach quorum (3)
        msg_tx
            .send(SailfishServiceMessage::TimeoutMsg(SailfishTimeoutMsg {
                round,
                sender: 1,
                signature: signers[1].sign_digest(&digest),
            }))
            .unwrap();
        msg_tx
            .send(SailfishServiceMessage::TimeoutMsg(SailfishTimeoutMsg {
                round,
                sender: 2,
                signature: signers[2].sign_digest(&digest),
            }))
            .unwrap();

        let events = event_rx.recv().await.expect("expected timeout cert");
        let cert = events.iter().find_map(|e| match e {
            SailfishCertEvent::TimeoutReady(cert) => Some(cert),
            _ => None,
        });
        // Cert formed with exactly 3 unique signers (the duplicate was ignored)
        assert_eq!(cert.unwrap().signatures.len(), 3);
    }
}
