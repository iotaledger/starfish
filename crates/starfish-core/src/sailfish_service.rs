// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Async Sailfish++ RBC certification service.
//!
//! Receives blocks and signature-free RBC phase messages, runs the
//! [`CertificationAggregator`], and emits certification events back to the
//! syncer thread.

use std::{collections::VecDeque, sync::Arc};

use prometheus::Registry;
use tokio::sync::mpsc;

use crate::{
    cert_aggregator::{CertEvent, CertificationAggregator},
    committee::Committee,
    metrics::Metrics,
    types::{AuthorityIndex, BlockReference, CertMessage, CertMessageKind, RoundNumber},
};

/// Messages sent to the Sailfish service.
pub enum SailfishServiceMessage {
    /// New blocks arrived — generate self-echoes.
    ProcessBlocks(Vec<BlockReference>),
    /// Incoming RBC message from a peer.
    CertMessage(CertMessage),
    /// Cleanup aggregator state below round.
    Cleanup(RoundNumber),
}

/// Events sent back to the syncer/core thread.
#[derive(Debug, Clone)]
pub enum SailfishCertEvent {
    /// Block certified (fast or slow path).
    Certified(BlockReference),
    /// Broadcast an RBC phase message to all peers.
    Broadcast(CertMessage),
}

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

/// Start the Sailfish RBC certification service as a tokio task.
pub fn start_sailfish_service(
    committee: Arc<Committee>,
    own_authority: AuthorityIndex,
    receiver: mpsc::UnboundedReceiver<SailfishServiceMessage>,
    event_tx: mpsc::UnboundedSender<Vec<SailfishCertEvent>>,
    _metrics: Arc<Metrics>,
) {
    tokio::spawn(run_sailfish_service(
        committee,
        own_authority,
        receiver,
        event_tx,
    ));
}

async fn run_sailfish_service(
    committee: Arc<Committee>,
    own_authority: AuthorityIndex,
    mut receiver: mpsc::UnboundedReceiver<SailfishServiceMessage>,
    event_tx: mpsc::UnboundedSender<Vec<SailfishCertEvent>>,
) {
    let mut aggregator = CertificationAggregator::new(committee);

    while let Some(msg) = receiver.recv().await {
        let mut all_events = Vec::new();

        process_message(msg, &mut aggregator, own_authority, &mut all_events);

        while let Ok(msg) = receiver.try_recv() {
            process_message(msg, &mut aggregator, own_authority, &mut all_events);
        }

        if !all_events.is_empty() {
            let _ = event_tx.send(all_events);
        }
    }
}

fn process_message(
    msg: SailfishServiceMessage,
    aggregator: &mut CertificationAggregator,
    own_authority: AuthorityIndex,
    events: &mut Vec<SailfishCertEvent>,
) {
    match msg {
        SailfishServiceMessage::ProcessBlocks(block_refs) => {
            if std::env::var_os("SAILFISH_DEBUG_FLOW").is_some() {
                eprintln!("sailfish service process blocks {:?}", block_refs);
            }
            for block_ref in block_refs {
                let echo = CertMessage {
                    block_ref,
                    sender: own_authority,
                    kind: CertMessageKind::Echo,
                };
                let cert_events = aggregator.add_message(&echo);
                dispatch_cert_events(aggregator, cert_events, own_authority, events);
                events.push(SailfishCertEvent::Broadcast(echo));
            }
        }
        SailfishServiceMessage::CertMessage(message) => {
            if std::env::var_os("SAILFISH_DEBUG_FLOW").is_some() {
                eprintln!(
                    "sailfish service inbound kind={:?} block={} sender={}",
                    message.kind, message.block_ref, message.sender
                );
            }
            let cert_events = aggregator.add_message(&message);
            dispatch_cert_events(aggregator, cert_events, own_authority, events);
        }
        SailfishServiceMessage::Cleanup(round) => {
            aggregator.cleanup_below_round(round);
        }
    }
}

fn dispatch_cert_events(
    aggregator: &mut CertificationAggregator,
    cert_events: Vec<CertEvent>,
    own_authority: AuthorityIndex,
    out: &mut Vec<SailfishCertEvent>,
) {
    let mut pending = VecDeque::from(cert_events);
    while let Some(event) = pending.pop_front() {
        match event {
            CertEvent::FastDelivery(block_ref) | CertEvent::SlowDelivery(block_ref) => {
                if std::env::var_os("SAILFISH_DEBUG_FLOW").is_some() {
                    eprintln!("sailfish service certified {}", block_ref);
                }
                out.push(SailfishCertEvent::Certified(block_ref));
            }
            CertEvent::SendVote(block_ref) => {
                let vote = CertMessage {
                    block_ref,
                    sender: own_authority,
                    kind: CertMessageKind::Vote,
                };
                if std::env::var_os("SAILFISH_DEBUG_FLOW").is_some() {
                    eprintln!("sailfish service local vote {}", block_ref);
                }
                pending.extend(aggregator.add_message(&vote));
                out.push(SailfishCertEvent::Broadcast(vote));
            }
            CertEvent::SendReady(block_ref) => {
                let ready = CertMessage {
                    block_ref,
                    sender: own_authority,
                    kind: CertMessageKind::Ready,
                };
                if std::env::var_os("SAILFISH_DEBUG_FLOW").is_some() {
                    eprintln!("sailfish service local ready {}", block_ref);
                }
                pending.extend(aggregator.add_message(&ready));
                out.push(SailfishCertEvent::Broadcast(ready));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_committee(n: usize) -> Arc<Committee> {
        Committee::new_test(vec![1; n])
    }

    fn test_metrics() -> Arc<Metrics> {
        Metrics::new(&Registry::new(), None, None, None).0
    }

    #[tokio::test]
    async fn local_vote_is_counted_before_broadcast() {
        let committee = make_committee(4);
        let own_authority = 1;
        let block_ref = BlockReference::new_test(0, 7);
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(committee, own_authority, msg_rx, event_tx, test_metrics());

        msg_tx
            .send(SailfishServiceMessage::ProcessBlocks(vec![block_ref]))
            .unwrap();
        let events = event_rx.recv().await.expect("expected local echo broadcast");
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage { block_ref: received, sender, kind })
                    if *received == block_ref
                        && *sender == own_authority
                        && *kind == CertMessageKind::Echo
            )
        }));

        msg_tx
            .send(SailfishServiceMessage::CertMessage(CertMessage {
                block_ref,
                sender: 2,
                kind: CertMessageKind::Echo,
            }))
            .unwrap();
        let events = event_rx.recv().await.expect("expected certification events");
        assert!(events.iter().any(|event| {
            matches!(event, SailfishCertEvent::Certified(received) if *received == block_ref)
        }));
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage { block_ref: received, sender, kind })
                    if *received == block_ref
                        && *sender == own_authority
                        && *kind == CertMessageKind::Vote
            )
        }));

        msg_tx
            .send(SailfishServiceMessage::CertMessage(CertMessage {
                block_ref,
                sender: 2,
                kind: CertMessageKind::Vote,
            }))
            .unwrap();
        let events = event_rx.recv().await.expect("expected ready broadcast");
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage { block_ref: received, sender, kind })
                    if *received == block_ref
                        && *sender == own_authority
                        && *kind == CertMessageKind::Ready
            )
        }));
    }

    #[tokio::test]
    async fn local_ready_is_counted_before_broadcast() {
        let committee = make_committee(7);
        let own_authority = 1;
        let block_ref = BlockReference::new_test(0, 9);
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        start_sailfish_service(committee, own_authority, msg_rx, event_tx, test_metrics());

        msg_tx
            .send(SailfishServiceMessage::ProcessBlocks(vec![block_ref]))
            .unwrap();
        let _ = event_rx.recv().await.expect("expected local echo broadcast");

        for sender in [2, 3, 4] {
            msg_tx
                .send(SailfishServiceMessage::CertMessage(CertMessage {
                    block_ref,
                    sender,
                    kind: CertMessageKind::Echo,
                }))
                .unwrap();
        }
        let events = event_rx.recv().await.expect("expected vote event");
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage { block_ref: received, sender, kind })
                    if *received == block_ref
                        && *sender == own_authority
                        && *kind == CertMessageKind::Vote
            )
        }));

        for sender in [2, 3, 4] {
            msg_tx
                .send(SailfishServiceMessage::CertMessage(CertMessage {
                    block_ref,
                    sender,
                    kind: CertMessageKind::Vote,
                }))
                .unwrap();
        }
        let events = event_rx.recv().await.expect("expected ready event");
        assert!(events.iter().any(|event| {
            matches!(
                event,
                SailfishCertEvent::Broadcast(CertMessage { block_ref: received, sender, kind })
                    if *received == block_ref
                        && *sender == own_authority
                        && *kind == CertMessageKind::Ready
            )
        }));

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
}
