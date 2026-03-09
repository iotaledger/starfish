// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Standalone async BLS verification service.
//!
//! Receives copies of BLS signature data from network workers, performs
//! batch verification and aggregation via [`BlsCertificateAggregator`], and
//! sends accumulated [`CertificateEvent`]s to the Core thread.

use tokio::sync::mpsc;

use crate::{
    bls_certificate_aggregator::{BlsCertificateAggregator, CertificateEvent},
    crypto::BlsSignatureBytes,
    data::Data,
    types::{AuthorityIndex, BlockReference, RoundNumber, VerifiedBlock},
};

/// Messages sent to the BLS verification service.
pub enum BlsServiceMessage {
    /// Process BLS fields from a batch of verified blocks.
    ProcessBlocks(Vec<Data<VerifiedBlock>>),
    /// Process a standalone DAC partial signature from a peer.
    DacPartialSig(BlockReference, AuthorityIndex, BlsSignatureBytes),
    /// Clean up aggregator state below the given round.
    Cleanup(RoundNumber),
}

/// Handle for sending messages to the BLS service from async contexts.
#[derive(Clone)]
pub struct BlsServiceHandle {
    sender: mpsc::Sender<BlsServiceMessage>,
}

impl BlsServiceHandle {
    pub fn new(sender: mpsc::Sender<BlsServiceMessage>) -> Self {
        Self { sender }
    }

    pub async fn send(&self, msg: BlsServiceMessage) {
        let _ = self.sender.send(msg).await;
    }
}

/// Start the BLS verification service as an async task.
///
/// Takes the receiving end of the BLS message channel and an event sender
/// for delivering accumulated certificate events to the Core thread.
pub fn start_bls_service(
    aggregator: BlsCertificateAggregator,
    receiver: mpsc::Receiver<BlsServiceMessage>,
    event_tx: mpsc::UnboundedSender<Vec<CertificateEvent>>,
) {
    tokio::spawn(run_bls_service(aggregator, receiver, event_tx));
}

async fn run_bls_service(
    mut aggregator: BlsCertificateAggregator,
    mut receiver: mpsc::Receiver<BlsServiceMessage>,
    event_tx: mpsc::UnboundedSender<Vec<CertificateEvent>>,
) {
    while let Some(msg) = receiver.recv().await {
        let mut events = Vec::new();

        // Process the first message.
        process_message(&mut aggregator, msg, &mut events);

        // Drain any additional queued messages for batching.
        while let Ok(msg) = receiver.try_recv() {
            process_message(&mut aggregator, msg, &mut events);
        }

        // Send accumulated events to the Core thread.
        if !events.is_empty() {
            let _ = event_tx.send(events);
        }
    }
}

fn process_message(
    aggregator: &mut BlsCertificateAggregator,
    msg: BlsServiceMessage,
    events: &mut Vec<CertificateEvent>,
) {
    match msg {
        BlsServiceMessage::ProcessBlocks(blocks) => {
            events.extend(aggregator.add_blocks(&blocks));
        }
        BlsServiceMessage::DacPartialSig(block_ref, signer, sig) => {
            events.extend(aggregator.add_standalone_dac_sig(block_ref, signer, sig));
        }
        BlsServiceMessage::Cleanup(round) => {
            aggregator.cleanup_below_round(round);
        }
    }
}
