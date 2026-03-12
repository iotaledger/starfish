// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Standalone async BLS verification service.
//!
//! Receives copies of BLS signature data from network workers, performs
//! batch verification and aggregation via [`BlsCertificateAggregator`], and
//! sends accumulated [`CertificateEvent`]s to the Core thread.
//!
//! Standalone round partial signatures are pre-computed before block creation,
//! while leader partial signatures are pre-signed as soon as the corresponding
//! leader block is received.

use std::sync::Arc;

use ahash::AHashSet;
use tokio::{
    select,
    sync::{Notify, mpsc},
};

use crate::{
    bls_certificate_aggregator::{BlsCertificateAggregator, CertificateEvent},
    committee::Committee,
    crypto::{self, BlsSignatureBytes, BlsSigner},
    dag_state::DagState,
    data::Data,
    metrics::{Metrics, UtilizationTimerExt},
    types::{
        AuthorityIndex, BlockReference, PartialSig, PartialSigKind, RoundNumber, VerifiedBlock,
    },
};

/// Messages sent to the BLS verification service.
pub enum BlsServiceMessage {
    /// Process BLS fields from a batch of verified blocks.
    ProcessBlocks(Vec<Data<VerifiedBlock>>),
    /// Pre-sign and broadcast the standalone round partial for the given round.
    PresignRound(RoundNumber),
    /// Process a standalone partial signature from a peer.
    PartialSig(PartialSig),
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
    sender: mpsc::Sender<BlsServiceMessage>,
    receiver: mpsc::Receiver<BlsServiceMessage>,
    event_tx: mpsc::UnboundedSender<Vec<CertificateEvent>>,
    metrics: Arc<Metrics>,
    bls_signer: Option<BlsSigner>,
    own_authority: AuthorityIndex,
    committee: Arc<Committee>,
    partial_sig_broadcast: Option<mpsc::UnboundedSender<PartialSig>>,
    dag_state: DagState,
    block_ready_notify: Arc<Notify>,
    threshold_clock_notify: Arc<Notify>,
) {
    let has_bls_signer = bls_signer.is_some();
    tokio::spawn(run_bls_service(
        aggregator,
        receiver,
        event_tx,
        metrics,
        bls_signer,
        own_authority,
        committee,
        partial_sig_broadcast,
    ));
    if has_bls_signer {
        tokio::spawn(run_round_presign_signal_task(
            sender,
            dag_state,
            block_ready_notify,
            threshold_clock_notify,
        ));
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_bls_service(
    aggregator: BlsCertificateAggregator,
    mut receiver: mpsc::Receiver<BlsServiceMessage>,
    event_tx: mpsc::UnboundedSender<Vec<CertificateEvent>>,
    metrics: Arc<Metrics>,
    bls_signer: Option<BlsSigner>,
    own_authority: AuthorityIndex,
    committee: Arc<Committee>,
    partial_sig_broadcast: Option<mpsc::UnboundedSender<PartialSig>>,
) {
    let mut aggregator = Some(aggregator);
    let mut presigned_rounds: AHashSet<RoundNumber> = AHashSet::new();
    let mut presigned_leader_rounds: AHashSet<RoundNumber> = AHashSet::new();
    while let Some(msg) = receiver.recv().await {
        let _timer = metrics.bls_service_util.utilization_timer();

        // Collect all queued messages before processing, so blocks from
        // multiple ProcessBlocks messages are verified in a single batch.
        let mut all_blocks = Vec::new();
        let mut presign_rounds = Vec::new();
        let mut dac_sigs = Vec::new();
        let mut round_sigs = Vec::new();
        let mut leader_sigs = Vec::new();
        collect_message(
            msg,
            &mut all_blocks,
            &mut presign_rounds,
            &mut dac_sigs,
            &mut round_sigs,
            &mut leader_sigs,
            aggregator
                .as_mut()
                .expect("BLS aggregator should always be available"),
            &mut presigned_rounds,
            &mut presigned_leader_rounds,
        );
        while let Ok(msg) = receiver.try_recv() {
            collect_message(
                msg,
                &mut all_blocks,
                &mut presign_rounds,
                &mut dac_sigs,
                &mut round_sigs,
                &mut leader_sigs,
                aggregator
                    .as_mut()
                    .expect("BLS aggregator should always be available"),
                &mut presigned_rounds,
                &mut presigned_leader_rounds,
            );
        }

        let num_blocks = all_blocks.len();
        let num_dac_sigs = dac_sigs.len();
        let has_work = num_blocks > 0
            || !presign_rounds.is_empty()
            || num_dac_sigs > 0
            || !round_sigs.is_empty()
            || !leader_sigs.is_empty();

        let events = if !has_work {
            Vec::new()
        } else {
            // Offload CPU-heavy verification to the blocking pool. Inside,
            // verify_batch_parallel fans out across BLS_VERIFICATION_WORKERS
            // threads via std::thread::scope.
            let mut worker_aggregator = aggregator
                .take()
                .expect("BLS aggregator should always be available");
            let metrics_clone = metrics.clone();
            let bls_signer_clone = bls_signer.clone();
            let committee_clone = committee.clone();
            let broadcast_clone = partial_sig_broadcast.clone();
            let mut presigned_rounds_clone =
                std::mem::replace(&mut presigned_rounds, AHashSet::new());
            let mut presigned_clone =
                std::mem::replace(&mut presigned_leader_rounds, AHashSet::new());
            let (worker_aggregator, events, returned_rounds, returned_presigned) =
                tokio::task::spawn_blocking(move || {
                    let mut events = Vec::new();
                    let mut broadcast_sigs = Vec::new();
                    let mut local_round_sigs = Vec::new();
                    let mut local_leader_sigs = Vec::new();

                    if !all_blocks.is_empty() {
                        let (new_events, batch_failures) =
                            worker_aggregator.add_blocks(&all_blocks);
                        if batch_failures > 0 {
                            metrics_clone
                                .bls_batch_verification_failures_total
                                .inc_by(batch_failures);
                        }
                        events.extend(new_events);
                    }

                    if !dac_sigs.is_empty() {
                        events.extend(worker_aggregator.add_standalone_dac_sigs_batch(dac_sigs));
                    }

                    if !round_sigs.is_empty() {
                        events
                            .extend(worker_aggregator.add_standalone_round_sigs_batch(round_sigs));
                    }

                    if !leader_sigs.is_empty() {
                        events.extend(
                            worker_aggregator.add_standalone_leader_sigs_batch(leader_sigs),
                        );
                    }

                    if let Some(ref bs) = bls_signer_clone {
                        for round in presign_rounds {
                            if round == 0 || !presigned_rounds_clone.insert(round) {
                                continue;
                            }
                            let sig = bs.sign_digest(&crypto::bls_round_message(round));
                            events.push(CertificateEvent::PrecomputedRoundSig(round, sig));
                            local_round_sigs.push((round, own_authority, sig));
                            broadcast_sigs.push(PartialSig {
                                kind: PartialSigKind::Round(round),
                                signer: own_authority,
                                signature: sig,
                            });
                            metrics_clone
                                .bls_presign_total
                                .with_label_values(&["round"])
                                .inc();
                        }

                        for block in &all_blocks {
                            let round = block.round();
                            if round > 0
                                && block.authority() == committee_clone.elect_leader(round)
                                && !presigned_clone.contains(&round)
                            {
                                presigned_clone.insert(round);
                                let leader_ref = *block.reference();
                                let sig = bs.sign_digest(&crypto::bls_leader_message(&leader_ref));
                                events
                                    .push(CertificateEvent::PrecomputedLeaderSig(leader_ref, sig));
                                local_leader_sigs.push((leader_ref, own_authority, sig));
                                broadcast_sigs.push(PartialSig {
                                    kind: PartialSigKind::Leader(leader_ref),
                                    signer: own_authority,
                                    signature: sig,
                                });
                                metrics_clone
                                    .bls_presign_total
                                    .with_label_values(&["leader"])
                                    .inc();
                            }
                        }
                    }

                    if !local_round_sigs.is_empty() {
                        events.extend(
                            worker_aggregator.add_standalone_round_sigs_batch(local_round_sigs),
                        );
                    }

                    if !local_leader_sigs.is_empty() {
                        events.extend(
                            worker_aggregator.add_standalone_leader_sigs_batch(local_leader_sigs),
                        );
                    }

                    if let Some(ref tx) = broadcast_clone {
                        for sig in broadcast_sigs {
                            let _ = tx.send(sig);
                        }
                    }

                    (
                        worker_aggregator,
                        events,
                        presigned_rounds_clone,
                        presigned_clone,
                    )
                })
                .await
                .expect("BLS blocking task should not panic");
            aggregator = Some(worker_aggregator);
            presigned_rounds = returned_rounds;
            presigned_leader_rounds = returned_presigned;
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
                CertificateEvent::PrecomputedRoundSig(..)
                | CertificateEvent::PrecomputedLeaderSig(..) => {}
            }
        }

        // Send accumulated events to the Core thread.
        if !events.is_empty() {
            let _ = event_tx.send(events);
        }
    }
}

async fn run_round_presign_signal_task(
    sender: mpsc::Sender<BlsServiceMessage>,
    dag_state: DagState,
    block_ready_notify: Arc<Notify>,
    threshold_clock_notify: Arc<Notify>,
) {
    let bootstrap_round = dag_state.threshold_clock_round().max(
        dag_state
            .last_own_block_ref()
            .map(|reference| reference.round + 1)
            .unwrap_or(0),
    );
    if bootstrap_round > 0
        && sender
            .send(BlsServiceMessage::PresignRound(bootstrap_round))
            .await
            .is_err()
    {
        return;
    }

    loop {
        select! {
            _ = block_ready_notify.notified() => {
                let Some(reference) = dag_state.last_own_block_ref() else {
                    continue;
                };
                if sender
                    .send(BlsServiceMessage::PresignRound(reference.round + 1))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            _ = threshold_clock_notify.notified() => {
                let round = dag_state.threshold_clock_round();
                if round == 0 {
                    continue;
                }
                if sender
                    .send(BlsServiceMessage::PresignRound(round))
                    .await
                    .is_err()
                {
                    break;
                }
                // Speculatively presign one round ahead so the signature is
                // ready when the next block is built.
                if sender
                    .send(BlsServiceMessage::PresignRound(round + 1))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

/// Classify a message into accumulated block or partial-sig vectors.
/// Cleanup messages are applied immediately since they are cheap.
#[allow(clippy::too_many_arguments)]
fn collect_message(
    msg: BlsServiceMessage,
    blocks: &mut Vec<Data<VerifiedBlock>>,
    presign_rounds: &mut Vec<RoundNumber>,
    dac_sigs: &mut Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    round_sigs: &mut Vec<(RoundNumber, AuthorityIndex, BlsSignatureBytes)>,
    leader_sigs: &mut Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    aggregator: &mut BlsCertificateAggregator,
    presigned_rounds: &mut AHashSet<RoundNumber>,
    presigned_leader_rounds: &mut AHashSet<RoundNumber>,
) {
    match msg {
        BlsServiceMessage::ProcessBlocks(b) => blocks.extend(b),
        BlsServiceMessage::PresignRound(round) => presign_rounds.push(round),
        BlsServiceMessage::PartialSig(sig) => match sig.kind {
            PartialSigKind::Dac(block_ref) => {
                dac_sigs.push((block_ref, sig.signer, sig.signature));
            }
            PartialSigKind::Round(round) => {
                round_sigs.push((round, sig.signer, sig.signature));
            }
            PartialSigKind::Leader(leader_ref) => {
                leader_sigs.push((leader_ref, sig.signer, sig.signature));
            }
        },
        BlsServiceMessage::Cleanup(round) => {
            aggregator.cleanup_below_round(round);
            presigned_rounds.retain(|&r| r >= round);
            presigned_leader_rounds.retain(|&r| r >= round);
        }
    }
}
