// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Standalone async BLS verification service.
//!
//! Receives copies of BLS signature data from network workers, performs
//! batch verification and aggregation via [`BlsCertificateAggregator`], and
//! sends accumulated [`CertificateEvent`]s to the Core thread.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::{
    bls_certificate_aggregator::{BlsCertificateAggregator, CertificateEvent},
    crypto::BlsSignatureBytes,
    data::Data,
    metrics::{Metrics, UtilizationTimerExt},
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
    metrics: Arc<Metrics>,
) {
    tokio::spawn(run_bls_service(aggregator, receiver, event_tx, metrics));
}

async fn run_bls_service(
    mut aggregator: BlsCertificateAggregator,
    mut receiver: mpsc::Receiver<BlsServiceMessage>,
    event_tx: mpsc::UnboundedSender<Vec<CertificateEvent>>,
    metrics: Arc<Metrics>,
) {
    while let Some(msg) = receiver.recv().await {
        let _timer = metrics.bls_service_util.utilization_timer();
        let mut events = Vec::new();

        // Process the first message.
        process_message(&mut aggregator, msg, &mut events, &metrics);

        // Drain any additional queued messages for batching.
        while let Ok(msg) = receiver.try_recv() {
            process_message(&mut aggregator, msg, &mut events, &metrics);
        }

        // Count completed certificates by type.
        for event in &events {
            match event {
                CertificateEvent::Round(..) => {
                    metrics
                        .bls_certificates_total
                        .with_label_values(&["round"])
                        .inc();
                }
                CertificateEvent::Leader(..) => {
                    metrics
                        .bls_certificates_total
                        .with_label_values(&["leader"])
                        .inc();
                }
                CertificateEvent::Dac(..) => {
                    metrics
                        .bls_certificates_total
                        .with_label_values(&["dac"])
                        .inc();
                }
                CertificateEvent::DacRejected(..) => {
                    metrics.bls_dac_rejections_total.inc();
                }
            }
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
    metrics: &Metrics,
) {
    match msg {
        BlsServiceMessage::ProcessBlocks(blocks) => {
            metrics
                .bls_blocks_processed_total
                .inc_by(blocks.len() as u64);
            let (new_events, batch_failures) = aggregator.add_blocks(&blocks);
            if batch_failures > 0 {
                metrics
                    .bls_batch_verification_failures_total
                    .inc_by(batch_failures);
            }
            events.extend(new_events);
        }
        BlsServiceMessage::DacPartialSig(block_ref, signer, sig) => {
            metrics.bls_standalone_dac_sigs_total.inc();
            events.extend(aggregator.add_standalone_dac_sig(block_ref, signer, sig));
        }
        BlsServiceMessage::Cleanup(round) => {
            aggregator.cleanup_below_round(round);
        }
    }
}
