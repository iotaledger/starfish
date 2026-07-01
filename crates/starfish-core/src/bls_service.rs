// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Standalone async BLS verification service.
//!
//! Receives copies of BLS signature data from network workers, performs
//! batch verification and aggregation via [`BlsCertificateAggregator`], and
//! sends accumulated [`CertificateEvent`]s to the Core thread.
//!
//! Verification is split into two phases per service tick so that
//! consensus-critical round/leader events reach the Core thread without
//! waiting for the slower DAC verification to complete.
//!
//! Standalone round partial signatures are pre-computed before block creation,
//! while leader partial signatures are pre-signed as soon as the corresponding
//! leader block is received.

use std::{collections::VecDeque, sync::Arc};

use ahash::AHashSet;
use tokio::{
    select,
    sync::{Notify, mpsc},
};

use crate::{
    bls_batch_verifier::BlsBatchVerifier,
    bls_certificate_aggregator::{BlsCertificateAggregator, CertificateEvent},
    committee::Committee,
    crypto::{self, BlsSignatureBytes, BlsSigner},
    dag_state::DagState,
    data::Data,
    metrics::{Metrics, UtilizationTimerExt},
    types::{
        AuthorityIndex,
        BlockReference,
        PartialSig,
        PartialSigKind,
        RoundNumber,
        VerifiedBlock,
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
    sender: mpsc::UnboundedSender<BlsServiceMessage>,
}

impl BlsServiceHandle {
    pub fn new(sender: mpsc::UnboundedSender<BlsServiceMessage>) -> Self {
        Self { sender }
    }

    pub fn send(&self, msg: BlsServiceMessage) {
        let _ = self.sender.send(msg);
    }
}

// Keep the BLS worker responsive under load by scheduling bounded batches in
// priority order instead of draining the entire unbounded queue at once.
const MAX_SCHEDULED_BLOCKS: usize = 256;
const MAX_SCHEDULED_DAC_SIGS: usize = 2048;
const MAX_SCHEDULED_ROUND_SIGS: usize = 1024;
const MAX_SCHEDULED_LEADER_SIGS: usize = 512;
const MAX_PRESIGN_ROUNDS: usize = 256;

/// Maximum consecutive ticks where DAC sigs may be deferred before a forced
/// batch to prevent starvation.
const MAX_DAC_CONSECUTIVE_SKIPS: usize = 5;

#[derive(Default)]
struct PendingBlsWork {
    blocks: VecDeque<Data<VerifiedBlock>>,
    presign_rounds: VecDeque<RoundNumber>,
    dac_sigs: VecDeque<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    round_sigs: VecDeque<(RoundNumber, AuthorityIndex, BlsSignatureBytes)>,
    leader_sigs: VecDeque<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    dac_consecutive_skips: usize,
}

impl PendingBlsWork {
    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
            && self.presign_rounds.is_empty()
            && self.dac_sigs.is_empty()
            && self.round_sigs.is_empty()
            && self.leader_sigs.is_empty()
    }

    fn take_next_batch(&mut self) -> ScheduledBlsBatch {
        // Under consensus backlog, defer DAC sigs so round/leader work gets
        // exclusive CPU time. A starvation guard forces DAC processing after
        // MAX_DAC_CONSECUTIVE_SKIPS ticks.
        let backlogged = self.blocks.len() > MAX_SCHEDULED_BLOCKS / 2
            || self.round_sigs.len() > MAX_SCHEDULED_ROUND_SIGS / 2;

        let (dac_sigs, dac_deferred) = if backlogged
            && !self.dac_sigs.is_empty()
            && self.dac_consecutive_skips < MAX_DAC_CONSECUTIVE_SKIPS
        {
            self.dac_consecutive_skips += 1;
            (Vec::new(), true)
        } else {
            self.dac_consecutive_skips = 0;
            (
                take_up_to(&mut self.dac_sigs, MAX_SCHEDULED_DAC_SIGS),
                false,
            )
        };

        ScheduledBlsBatch {
            blocks: take_up_to(&mut self.blocks, MAX_SCHEDULED_BLOCKS),
            presign_rounds: take_up_to(&mut self.presign_rounds, MAX_PRESIGN_ROUNDS),
            dac_sigs,
            round_sigs: take_up_to(&mut self.round_sigs, MAX_SCHEDULED_ROUND_SIGS),
            leader_sigs: take_up_to(&mut self.leader_sigs, MAX_SCHEDULED_LEADER_SIGS),
            dac_deferred,
        }
    }
}

struct ScheduledBlsBatch {
    blocks: Vec<Data<VerifiedBlock>>,
    presign_rounds: Vec<RoundNumber>,
    dac_sigs: Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    round_sigs: Vec<(RoundNumber, AuthorityIndex, BlsSignatureBytes)>,
    leader_sigs: Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    dac_deferred: bool,
}

impl ScheduledBlsBatch {
    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
            && self.presign_rounds.is_empty()
            && self.dac_sigs.is_empty()
            && self.round_sigs.is_empty()
            && self.leader_sigs.is_empty()
    }
}

fn take_up_to<T>(queue: &mut VecDeque<T>, limit: usize) -> Vec<T> {
    let count = queue.len().min(limit);
    queue.drain(..count).collect()
}

/// Start the BLS verification service as an async task.
///
/// Takes the receiving end of the BLS message channel and an event sender
/// for delivering accumulated certificate events to the Core thread.
pub fn start_bls_service(
    aggregator: BlsCertificateAggregator,
    sender: mpsc::UnboundedSender<BlsServiceMessage>,
    receiver: mpsc::UnboundedReceiver<BlsServiceMessage>,
    event_tx: mpsc::UnboundedSender<Vec<CertificateEvent>>,
    metrics: Arc<Metrics>,
    bls_signer: Option<BlsSigner>,
    own_authority: AuthorityIndex,
    committee: Arc<Committee>,
    partial_sig_broadcast: Option<mpsc::UnboundedSender<PartialSig>>,
    dag_state: DagState,
    block_ready_notify: Arc<Notify>,
    proposal_round_notify: Arc<Notify>,
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
            proposal_round_notify,
        ));
    }
}

/// Count completed certificate events and update Prometheus counters.
fn count_cert_events(events: &[CertificateEvent], metrics: &Metrics) {
    for event in events {
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
            CertificateEvent::BlockVerified(..) => {
                metrics
                    .bls_certificates_total
                    .with_label_values(&["block_verified"])
                    .inc();
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_bls_service(
    aggregator: BlsCertificateAggregator,
    mut receiver: mpsc::UnboundedReceiver<BlsServiceMessage>,
    event_tx: mpsc::UnboundedSender<Vec<CertificateEvent>>,
    metrics: Arc<Metrics>,
    bls_signer: Option<BlsSigner>,
    own_authority: AuthorityIndex,
    committee: Arc<Committee>,
    partial_sig_broadcast: Option<mpsc::UnboundedSender<PartialSig>>,
) {
    let mut aggregator = Some(aggregator);
    let mut pending = PendingBlsWork::default();
    let mut presigned_rounds: AHashSet<RoundNumber> = AHashSet::new();
    let mut presigned_leader_rounds: AHashSet<RoundNumber> = AHashSet::new();
    loop {
        if pending.is_empty() {
            let Some(msg) = receiver.recv().await else {
                break;
            };
            enqueue_message(
                msg,
                &mut pending,
                aggregator
                    .as_mut()
                    .expect("BLS aggregator should always be available"),
                &mut presigned_rounds,
                &mut presigned_leader_rounds,
            );
        }

        let _timer = metrics.bls_service_util.utilization_timer();

        while let Ok(msg) = receiver.try_recv() {
            enqueue_message(
                msg,
                &mut pending,
                aggregator
                    .as_mut()
                    .expect("BLS aggregator should always be available"),
                &mut presigned_rounds,
                &mut presigned_leader_rounds,
            );
        }

        let batch = pending.take_next_batch();
        if batch.is_empty() {
            continue;
        }

        let num_blocks = batch.blocks.len();
        let num_dac_sigs = batch.dac_sigs.len();

        // Check whether blocks carry embedded DAC acknowledgments before the
        // batch is moved into the first spawn_blocking.
        let has_embedded_dac = batch.blocks.iter().any(|b| {
            b.header()
                .acknowledgment_bls_signatures()
                .iter()
                .any(|cert| !cert.is_empty())
        });

        if batch.dac_deferred {
            metrics.bls_dac_sigs_deferred_total.inc();
        }

        // ── PHASE 1: Consensus-critical (round + leader) ────────────
        //
        // Merges block partials, embedded round/leader aggregates, and
        // standalone round/leader sigs into ONE verify_batch_parallel
        // call. Self-signed presign sigs bypass verification entirely.
        let mut worker_agg = aggregator
            .take()
            .expect("BLS aggregator should always be available");
        let metrics_c = metrics.clone();
        let bls_signer_c = bls_signer.clone();
        let committee_c = committee.clone();
        let broadcast_c = partial_sig_broadcast.clone();
        let mut presigned_rounds_c = std::mem::replace(&mut presigned_rounds, AHashSet::new());
        let mut presigned_leader_c =
            std::mem::replace(&mut presigned_leader_rounds, AHashSet::new());

        let (
            worker_agg,
            consensus_events,
            blocks_for_dac,
            dac_sigs_for_dac,
            returned_rounds,
            returned_presigned,
            batch_failures,
        ) = tokio::task::spawn_blocking(move || {
            let (tasks, origins) = worker_agg.collect_consensus_tasks(
                &batch.blocks,
                batch.round_sigs,
                batch.leader_sigs,
            );

            let invalid =
                match BlsBatchVerifier::verify_batch_parallel(&tasks, worker_agg.num_workers()) {
                    Ok(()) => AHashSet::new(),
                    Err(bad) => bad.into_iter().collect(),
                };
            let batch_failures = invalid.len() as u64;

            let mut events = worker_agg.dispatch_verified(origins, &invalid);

            // Presign round/leader sigs and add them directly — skip
            // verification for our own signatures.
            let mut broadcast_sigs = Vec::new();
            if let Some(ref bs) = bls_signer_c {
                for round in batch.presign_rounds {
                    if round == 0 || !presigned_rounds_c.insert(round) {
                        continue;
                    }
                    let sig = bs.sign_digest(&crypto::bls_round_message(round));
                    events.push(CertificateEvent::PrecomputedRoundSig(round, sig));
                    if let Some(e) = worker_agg.add_round_partial(round, own_authority, sig) {
                        events.push(e);
                    }
                    broadcast_sigs.push(PartialSig {
                        kind: PartialSigKind::Round(round),
                        signer: own_authority,
                        signature: sig,
                    });
                    metrics_c
                        .bls_presign_total
                        .with_label_values(&["round"])
                        .inc();
                }

                for block in &batch.blocks {
                    let round = block.round();
                    if round > 0
                        && block.authority() == committee_c.elect_leader(round)
                        && !presigned_leader_c.contains(&round)
                    {
                        presigned_leader_c.insert(round);
                        let leader_ref = *block.reference();
                        let sig = bs.sign_digest(&crypto::bls_leader_message(&leader_ref));
                        events.push(CertificateEvent::PrecomputedLeaderSig(leader_ref, sig));
                        if let Some(e) =
                            worker_agg.add_leader_partial(leader_ref, own_authority, sig)
                        {
                            events.push(e);
                        }
                        broadcast_sigs.push(PartialSig {
                            kind: PartialSigKind::Leader(leader_ref),
                            signer: own_authority,
                            signature: sig,
                        });
                        metrics_c
                            .bls_presign_total
                            .with_label_values(&["leader"])
                            .inc();
                    }
                }
            }

            if let Some(ref tx) = broadcast_c {
                for sig in broadcast_sigs {
                    let _ = tx.send(sig);
                }
            }

            (
                worker_agg,
                events,
                batch.blocks,
                batch.dac_sigs,
                presigned_rounds_c,
                presigned_leader_c,
                batch_failures,
            )
        })
        .await
        .expect("BLS consensus blocking task should not panic");

        aggregator = Some(worker_agg);
        presigned_rounds = returned_rounds;
        presigned_leader_rounds = returned_presigned;

        if batch_failures > 0 {
            metrics
                .bls_batch_verification_failures_total
                .inc_by(batch_failures);
        }

        // Dispatch consensus events IMMEDIATELY — round/leader certs reach
        // the core thread before DAC verification even starts.
        count_cert_events(&consensus_events, &metrics);
        if !consensus_events.is_empty() {
            let _ = event_tx.send(consensus_events);
        }

        // ── PHASE 2: DAC (deferrable under backlog) ──────────────────
        let has_dac_work = !dac_sigs_for_dac.is_empty() || has_embedded_dac;
        if has_dac_work {
            let mut worker_agg = aggregator
                .take()
                .expect("BLS aggregator should always be available");
            let (worker_agg, dac_events) = tokio::task::spawn_blocking(move || {
                let (tasks, origins) =
                    worker_agg.collect_dac_tasks(&blocks_for_dac, dac_sigs_for_dac);
                let invalid =
                    match BlsBatchVerifier::verify_batch_parallel(&tasks, worker_agg.num_workers())
                    {
                        Ok(()) => AHashSet::new(),
                        Err(bad) => bad.into_iter().collect(),
                    };
                let events = worker_agg.dispatch_verified(origins, &invalid);
                (worker_agg, events)
            })
            .await
            .expect("BLS DAC blocking task should not panic");

            aggregator = Some(worker_agg);
            count_cert_events(&dac_events, &metrics);
            if !dac_events.is_empty() {
                let _ = event_tx.send(dac_events);
            }
        }

        if num_blocks > 0 {
            metrics.bls_blocks_processed_total.inc_by(num_blocks as u64);
        }
        if num_dac_sigs > 0 {
            metrics
                .bls_standalone_dac_sigs_total
                .inc_by(num_dac_sigs as u64);
        }
    }
}

async fn run_round_presign_signal_task(
    sender: mpsc::UnboundedSender<BlsServiceMessage>,
    dag_state: DagState,
    block_ready_notify: Arc<Notify>,
    proposal_round_notify: Arc<Notify>,
) {
    let bootstrap_round = dag_state.proposal_round().max(
        dag_state
            .last_own_block_ref()
            .map(|reference| reference.round + 1)
            .unwrap_or(0),
    );
    if bootstrap_round > 0
        && sender
            .send(BlsServiceMessage::PresignRound(bootstrap_round))
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
                    .is_err()
                {
                    break;
                }
            }
            _ = proposal_round_notify.notified() => {
                let round = dag_state.proposal_round();
                if round == 0 {
                    continue;
                }
                if sender.send(BlsServiceMessage::PresignRound(round)).is_err()
                {
                    break;
                }
                // Speculatively presign one round ahead so the signature is
                // ready when the next block is built.
                if sender
                    .send(BlsServiceMessage::PresignRound(round + 1))
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
fn enqueue_message(
    msg: BlsServiceMessage,
    pending: &mut PendingBlsWork,
    aggregator: &mut BlsCertificateAggregator,
    presigned_rounds: &mut AHashSet<RoundNumber>,
    presigned_leader_rounds: &mut AHashSet<RoundNumber>,
) {
    match msg {
        BlsServiceMessage::ProcessBlocks(b) => pending.blocks.extend(b),
        BlsServiceMessage::PresignRound(round) => pending.presign_rounds.push_back(round),
        BlsServiceMessage::PartialSig(sig) => match sig.kind {
            PartialSigKind::Dac(block_ref) => {
                pending
                    .dac_sigs
                    .push_back((block_ref, sig.signer, sig.signature));
            }
            PartialSigKind::Round(round) => {
                pending
                    .round_sigs
                    .push_back((round, sig.signer, sig.signature));
            }
            PartialSigKind::Leader(leader_ref) => {
                pending
                    .leader_sigs
                    .push_back((leader_ref, sig.signer, sig.signature));
            }
        },
        BlsServiceMessage::Cleanup(round) => {
            aggregator.cleanup_below_round(round);
            presigned_rounds.retain(|&r| r >= round);
            presigned_leader_rounds.retain(|&r| r >= round);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::VerifiedBlock;

    #[test]
    fn scheduler_keeps_lower_priority_work_moving() {
        let mut pending = PendingBlsWork::default();
        let block = VerifiedBlock::new_genesis(0);
        for _ in 0..=MAX_SCHEDULED_BLOCKS {
            pending.blocks.push_back(block.clone());
        }
        pending.dac_sigs.push_back((
            BlockReference::new_test(0, 1),
            0,
            BlsSignatureBytes::default(),
        ));
        pending
            .round_sigs
            .push_back((1, 0, BlsSignatureBytes::default()));
        pending.leader_sigs.push_back((
            BlockReference::new_test(1, 1),
            0,
            BlsSignatureBytes::default(),
        ));
        pending.presign_rounds.push_back(7);

        let batch = pending.take_next_batch();
        assert_eq!(batch.blocks.len(), MAX_SCHEDULED_BLOCKS);
        // DAC sigs are deferred under consensus backlog — this is
        // intentional to prioritise round/leader cert delivery.
        assert!(batch.dac_deferred);
        assert!(batch.dac_sigs.is_empty());
        // Round and leader sigs still move even under backlog.
        assert_eq!(batch.round_sigs.len(), 1);
        assert_eq!(batch.leader_sigs.len(), 1);
        assert_eq!(batch.presign_rounds, vec![7]);

        assert_eq!(pending.blocks.len(), 1);
        assert_eq!(pending.dac_sigs.len(), 1);
        assert!(pending.round_sigs.is_empty());
        assert!(pending.leader_sigs.is_empty());
        assert!(pending.presign_rounds.is_empty());
    }

    /// Without backlog, DAC sigs are taken normally.
    #[test]
    fn scheduler_takes_dac_without_backlog() {
        let mut pending = PendingBlsWork::default();
        let block = VerifiedBlock::new_genesis(0);
        // Stay below the backlog threshold.
        for _ in 0..MAX_SCHEDULED_BLOCKS / 4 {
            pending.blocks.push_back(block.clone());
        }
        pending.dac_sigs.push_back((
            BlockReference::new_test(0, 1),
            0,
            BlsSignatureBytes::default(),
        ));

        let batch = pending.take_next_batch();
        assert!(!batch.dac_deferred);
        assert_eq!(batch.dac_sigs.len(), 1);
        assert!(pending.dac_sigs.is_empty());
    }

    #[test]
    fn dac_deferred_under_consensus_backlog() {
        let mut pending = PendingBlsWork::default();
        let block = VerifiedBlock::new_genesis(0);
        // Fill blocks above the backlog threshold (MAX_SCHEDULED_BLOCKS / 2).
        for _ in 0..MAX_SCHEDULED_BLOCKS {
            pending.blocks.push_back(block.clone());
        }
        pending.dac_sigs.push_back((
            BlockReference::new_test(0, 1),
            0,
            BlsSignatureBytes::default(),
        ));
        pending
            .round_sigs
            .push_back((1, 0, BlsSignatureBytes::default()));

        let batch = pending.take_next_batch();
        // DAC sigs should be deferred.
        assert!(batch.dac_deferred);
        assert!(batch.dac_sigs.is_empty());
        assert_eq!(pending.dac_sigs.len(), 1);

        // After MAX_DAC_CONSECUTIVE_SKIPS, starvation guard forces DAC batch.
        for _ in 0..MAX_DAC_CONSECUTIVE_SKIPS {
            // Refill blocks to stay backlogged.
            for _ in 0..MAX_SCHEDULED_BLOCKS {
                pending.blocks.push_back(block.clone());
            }
            let batch = pending.take_next_batch();
            if pending.dac_consecutive_skips == 0 {
                // Starvation guard fired on this tick.
                assert!(!batch.dac_deferred);
                assert_eq!(batch.dac_sigs.len(), 1);
                return;
            }
        }
        // If we get here, the guard should fire on the next tick.
        for _ in 0..MAX_SCHEDULED_BLOCKS {
            pending.blocks.push_back(block.clone());
        }
        let batch = pending.take_next_batch();
        assert!(!batch.dac_deferred);
        assert_eq!(batch.dac_sigs.len(), 1);
    }
}
