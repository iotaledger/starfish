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
    aggregator: BlsCertificateAggregator,
    mut receiver: mpsc::Receiver<BlsServiceMessage>,
    event_tx: mpsc::UnboundedSender<Vec<CertificateEvent>>,
    metrics: Arc<Metrics>,
) {
    let mut aggregator = Some(aggregator);
    while let Some(msg) = receiver.recv().await {
        let _timer = metrics.bls_service_util.utilization_timer();

        // Collect all queued messages before processing, so blocks from
        // multiple ProcessBlocks messages are verified in a single batch.
        let mut all_blocks = Vec::new();
        let mut dac_sigs = Vec::new();
        collect_message(
            msg,
            &mut all_blocks,
            &mut dac_sigs,
            aggregator
                .as_mut()
                .expect("BLS aggregator should always be available"),
        );
        while let Ok(msg) = receiver.try_recv() {
            collect_message(
                msg,
                &mut all_blocks,
                &mut dac_sigs,
                aggregator
                    .as_mut()
                    .expect("BLS aggregator should always be available"),
            );
        }

        let num_blocks = all_blocks.len();
        let num_dac_sigs = dac_sigs.len();

        let events = if num_blocks == 0 && num_dac_sigs == 0 {
            Vec::new()
        } else {
            // Offload CPU-heavy verification to the blocking pool. Inside,
            // verify_batch_parallel fans out across BLS_VERIFICATION_WORKERS
            // threads via std::thread::scope.
            let mut worker_aggregator = aggregator
                .take()
                .expect("BLS aggregator should always be available");
            let metrics = metrics.clone();
            let (worker_aggregator, events) = tokio::task::spawn_blocking(move || {
                let mut events = Vec::new();

                if !all_blocks.is_empty() {
                    let (new_events, batch_failures) = worker_aggregator.add_blocks(&all_blocks);
                    if batch_failures > 0 {
                        metrics
                            .bls_batch_verification_failures_total
                            .inc_by(batch_failures);
                    }
                    events.extend(new_events);
                }

                if !dac_sigs.is_empty() {
                    events.extend(worker_aggregator.add_standalone_dac_sigs_batch(dac_sigs));
                }

                (worker_aggregator, events)
            })
            .await
            .expect("BLS blocking task should not panic");
            aggregator = Some(worker_aggregator);
            events
        };

        if num_blocks > 0 {
            metrics.bls_blocks_processed_total.inc_by(num_blocks as u64);
        }
        if num_dac_sigs > 0 {
            metrics
                .bls_standalone_dac_sigs_total
                .inc_by(num_dac_sigs as u64);
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

/// Classify a message into accumulated block or DAC-sig vectors.
/// Cleanup messages are applied immediately since they are cheap.
fn collect_message(
    msg: BlsServiceMessage,
    blocks: &mut Vec<Data<VerifiedBlock>>,
    dac_sigs: &mut Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    aggregator: &mut BlsCertificateAggregator,
) {
    match msg {
        BlsServiceMessage::ProcessBlocks(b) => blocks.extend(b),
        BlsServiceMessage::DacPartialSig(block_ref, signer, sig) => {
            dac_sigs.push((block_ref, signer, sig));
        }
        BlsServiceMessage::Cleanup(round) => {
            aggregator.cleanup_below_round(round);
        }
    }
}
