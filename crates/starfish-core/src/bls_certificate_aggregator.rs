// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Collects BLS verification results from received blocks and produces
//! verified aggregate certificates once a quorum (2f+1 by stake) is reached.
//!
//! Partial signatures carried in blocks are batch-verified before they can
//! update certificate state. Aggregate leader/DAC certificates embedded in
//! blocks are also verified before being accepted.

use std::{collections::BTreeMap, sync::Arc};

use ahash::{AHashMap, AHashSet};

use crate::{
    bls_batch_verifier::{BlsBatchVerifier, BlsVerificationTask},
    committee::{Committee, QuorumThreshold, StakeAggregator},
    crypto::{self, BlsPublicKey, BlsSignatureBytes, bls_aggregate, bls_aggregate_public_keys},
    dag_state::DagState,
    data::Data,
    types::{AuthorityIndex, BlockReference, BlsAggregateCertificate, RoundNumber, VerifiedBlock},
};

/// Apply certificate events to a `DagState`, returning `true` if any new
/// certificate was learned.
pub fn apply_certificate_events(dag_state: &DagState, events: Vec<CertificateEvent>) -> bool {
    dag_state.apply_certificate_events(events)
}

/// Partial-sig task extracted from a block header for batch verification.
enum PartialTaskKind {
    Round {
        round: RoundNumber,
        signer: AuthorityIndex,
        sig: BlsSignatureBytes,
        source_block: Option<BlockReference>,
    },
    Leader {
        leader_ref: BlockReference,
        signer: AuthorityIndex,
        sig: BlsSignatureBytes,
        source_block: Option<BlockReference>,
    },
}

/// Events emitted when a new verified certificate is completed.
#[derive(Debug)]
pub enum CertificateEvent {
    Round(RoundNumber, BlsAggregateCertificate),
    Leader(BlockReference, BlsAggregateCertificate),
    Dac(BlockReference, BlsAggregateCertificate),
    DacRejected(BlockReference),
    PrecomputedRoundSig(RoundNumber, BlsSignatureBytes),
    PrecomputedLeaderSig(BlockReference, BlsSignatureBytes),
    /// All embedded BLS fields of this block have been verified.
    /// Used by dual-DAG BLS protocols to mark a vertex as pre-clean.
    BlockVerified(BlockReference),
}

/// Tracks per-block BLS field verification progress for dual-DAG pre-clean.
struct BlockVerificationTracker {
    /// Total BLS fields requiring verification on this block.
    expected: usize,
    /// Fields verified so far (valid or already-known).
    verified: usize,
    /// Set if any field failed verification — block can never become pre-clean
    /// via the normal path (only via f+1 inference).
    failed: bool,
}

/// Verified-task origin for unified batch verification + dispatch.
///
/// Each variant records enough state so that, after batch verification
/// identifies invalid entries, [`BlsCertificateAggregator::dispatch_verified`]
/// can route valid results to the correct `add_*_partial` or cert-insertion
/// path.
pub(crate) enum TaskOrigin {
    RoundPartial {
        round: RoundNumber,
        signer: AuthorityIndex,
        sig: BlsSignatureBytes,
        source_blocks: Vec<BlockReference>,
    },
    LeaderPartial {
        leader_ref: BlockReference,
        signer: AuthorityIndex,
        sig: BlsSignatureBytes,
        source_blocks: Vec<BlockReference>,
    },
    DacPartial {
        block_ref: BlockReference,
        signer: AuthorityIndex,
        sig: BlsSignatureBytes,
    },
    AggRound(RoundNumber, BlsAggregateCertificate, Vec<BlockReference>),
    AggLeader(BlockReference, BlsAggregateCertificate, Vec<BlockReference>),
    AggDac(BlockReference, BlsAggregateCertificate, Vec<BlockReference>),
}

fn push_task_source(origin: &mut TaskOrigin, source: BlockReference) {
    match origin {
        TaskOrigin::RoundPartial { source_blocks, .. }
        | TaskOrigin::LeaderPartial { source_blocks, .. } => source_blocks.push(source),
        TaskOrigin::AggRound(_, _, sources)
        | TaskOrigin::AggLeader(_, _, sources)
        | TaskOrigin::AggDac(_, _, sources) => sources.push(source),
        TaskOrigin::DacPartial { .. } => unreachable!("dedupe index must point to source origin"),
    }
}

/// Number of parallel threads used for BLS batch verification.
pub const BLS_VERIFICATION_WORKERS: usize = 5;

pub struct BlsCertificateAggregator {
    committee: Arc<Committee>,
    num_workers: usize,

    // Round r -> (authority -> partial round sig)
    round_partial_sigs: BTreeMap<RoundNumber, AHashMap<AuthorityIndex, BlsSignatureBytes>>,
    round_stake: BTreeMap<RoundNumber, StakeAggregator<QuorumThreshold>>,
    /// Completed round certificates.
    round_certs: BTreeMap<RoundNumber, BlsAggregateCertificate>,

    // leader_ref -> (authority -> partial leader sig)
    leader_partial_sigs: AHashMap<BlockReference, AHashMap<AuthorityIndex, BlsSignatureBytes>>,
    leader_stake: AHashMap<BlockReference, StakeAggregator<QuorumThreshold>>,
    /// Completed leader certificates.
    leader_certs: AHashMap<BlockReference, BlsAggregateCertificate>,

    // block_ref -> (authority -> partial DAC sig on payloadCommit)
    dac_partial_sigs: AHashMap<BlockReference, AHashMap<AuthorityIndex, BlsSignatureBytes>>,
    dac_stake: AHashMap<BlockReference, StakeAggregator<QuorumThreshold>>,
    /// Completed DAC certificates.
    dac_certs: AHashMap<BlockReference, BlsAggregateCertificate>,
    /// DAC certificates that failed verification and must not be sequenced.
    dac_rejections: AHashSet<BlockReference>,
    /// Per-block BLS field verification tracking for dual-DAG pre-clean.
    block_verification: AHashMap<BlockReference, BlockVerificationTracker>,
    aggregate_public_key_cache: AHashMap<crate::types::AuthoritySet, BlsPublicKey>,
}

impl BlsCertificateAggregator {
    pub fn new(committee: Arc<Committee>) -> Self {
        Self::with_workers(committee, BLS_VERIFICATION_WORKERS)
    }

    pub fn with_workers(committee: Arc<Committee>, num_workers: usize) -> Self {
        Self {
            committee,
            num_workers: num_workers.max(1),
            round_partial_sigs: BTreeMap::new(),
            round_stake: BTreeMap::new(),
            round_certs: BTreeMap::new(),
            leader_partial_sigs: AHashMap::new(),
            leader_stake: AHashMap::new(),
            leader_certs: AHashMap::new(),
            dac_partial_sigs: AHashMap::new(),
            dac_stake: AHashMap::new(),
            dac_certs: AHashMap::new(),
            dac_rejections: AHashSet::new(),
            block_verification: AHashMap::new(),
            aggregate_public_key_cache: AHashMap::new(),
        }
    }

    pub(crate) fn num_workers(&self) -> usize {
        self.num_workers
    }

    pub(crate) fn set_num_workers(&mut self, n: usize) {
        self.num_workers = n.max(1);
    }

    /// Collect all consensus-critical verification tasks (block partials +
    /// embedded round/leader aggregates + standalone round/leader sigs) into
    /// a single batch for [`BlsBatchVerifier::verify_batch_parallel`].
    pub(crate) fn collect_consensus_tasks(
        &mut self,
        blocks: &[Data<VerifiedBlock>],
        round_sigs: Vec<(RoundNumber, AuthorityIndex, BlsSignatureBytes)>,
        leader_sigs: Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    ) -> (Vec<BlsVerificationTask>, Vec<TaskOrigin>) {
        let mut tasks = Vec::new();
        let mut origins = Vec::new();
        let mut seen_round_partials = AHashMap::new();
        let mut seen_leader_partials = AHashMap::new();

        // 1. Block-header partials (round + leader).
        for block in blocks {
            let signer = block.authority();
            let source = *block.reference();
            self.register_block_verification(block);

            if let Some(sig) = block.header().bls_round_signature() {
                let round = block.round();
                if *sig != BlsSignatureBytes::default() {
                    if self.round_certs.contains_key(&round)
                        || self
                            .round_stake
                            .get(&round)
                            .is_some_and(|s| s.is_quorum(&self.committee))
                        || self
                            .round_partial_sigs
                            .get(&round)
                            .is_some_and(|sigs| sigs.contains_key(&signer))
                    {
                        // Already known — count as verified.
                        self.mark_block_field_verified(&source);
                    } else if let Some(&origin_index) =
                        seen_round_partials.get(&(round, signer, *sig))
                    {
                        push_task_source(&mut origins[origin_index], source);
                    } else if let Some(pk) = self.committee.get_bls_public_key(signer).cloned() {
                        tasks.push(BlsVerificationTask {
                            message: crypto::bls_round_message(round),
                            signature: *sig,
                            public_key: pk,
                            block_index: origins.len(),
                        });
                        seen_round_partials.insert((round, signer, *sig), origins.len());
                        origins.push(TaskOrigin::RoundPartial {
                            round,
                            signer,
                            sig: *sig,
                            source_blocks: vec![source],
                        });
                    }
                }
            }
            if let Some((leader_ref, sig)) = block.header().voted_leader() {
                if *sig != BlsSignatureBytes::default() {
                    if self.leader_certs.contains_key(leader_ref)
                        || self
                            .leader_stake
                            .get(leader_ref)
                            .is_some_and(|s| s.is_quorum(&self.committee))
                        || self
                            .leader_partial_sigs
                            .get(leader_ref)
                            .is_some_and(|sigs| sigs.contains_key(&signer))
                    {
                        self.mark_block_field_verified(&source);
                    } else if let Some(&origin_index) =
                        seen_leader_partials.get(&(*leader_ref, signer, *sig))
                    {
                        push_task_source(&mut origins[origin_index], source);
                    } else if let Some(pk) = self.committee.get_bls_public_key(signer).cloned() {
                        tasks.push(BlsVerificationTask {
                            message: crypto::bls_leader_message(leader_ref),
                            signature: *sig,
                            public_key: pk,
                            block_index: origins.len(),
                        });
                        seen_leader_partials.insert((*leader_ref, signer, *sig), origins.len());
                        origins.push(TaskOrigin::LeaderPartial {
                            leader_ref: *leader_ref,
                            signer,
                            sig: *sig,
                            source_blocks: vec![source],
                        });
                    }
                }
            }
        }

        // 2. Embedded round + leader aggregate certs.
        let mut seen_round_certs = AHashMap::new();
        let mut seen_leader_certs = AHashMap::new();
        for block in blocks {
            let source = *block.reference();
            if let Some(cert) = block.header().bls_aggregate_round_signature() {
                let certified_round = block.round().saturating_sub(1);
                if !cert.is_empty() && certified_round != 0 {
                    if self.round_certs.contains_key(&certified_round) {
                        self.mark_block_field_verified(&source);
                    } else if let Some(&origin_index) =
                        seen_round_certs.get(&(certified_round, *cert))
                    {
                        push_task_source(&mut origins[origin_index], source);
                    } else if let Some(task) = self.aggregate_same_message_task(
                        crypto::bls_round_message(certified_round),
                        cert,
                    ) {
                        tasks.push(BlsVerificationTask {
                            block_index: origins.len(),
                            ..task
                        });
                        seen_round_certs.insert((certified_round, *cert), origins.len());
                        origins.push(TaskOrigin::AggRound(certified_round, *cert, vec![source]));
                    }
                }
            }
            if let Some((leader_ref, cert)) = block.header().certified_leader() {
                if !cert.is_empty() {
                    if self.leader_certs.contains_key(leader_ref) {
                        self.mark_block_field_verified(&source);
                    } else if let Some(&origin_index) = seen_leader_certs.get(&(*leader_ref, *cert))
                    {
                        push_task_source(&mut origins[origin_index], source);
                    } else {
                        if let Some(task) = self.aggregate_same_message_task(
                            crypto::bls_leader_message(leader_ref),
                            cert,
                        ) {
                            tasks.push(BlsVerificationTask {
                                block_index: origins.len(),
                                ..task
                            });
                            seen_leader_certs.insert((*leader_ref, *cert), origins.len());
                            origins.push(TaskOrigin::AggLeader(*leader_ref, *cert, vec![source]));
                        }
                    }
                }
            }
        }

        // 3. Standalone round sigs (no source block).
        for (round, signer, sig) in round_sigs {
            if self.round_certs.contains_key(&round)
                || self
                    .round_stake
                    .get(&round)
                    .is_some_and(|s| s.is_quorum(&self.committee))
                || self
                    .round_partial_sigs
                    .get(&round)
                    .is_some_and(|sigs| sigs.contains_key(&signer))
            {
                continue;
            }
            if seen_round_partials.contains_key(&(round, signer, sig)) {
                continue;
            }
            let Some(pk) = self.committee.get_bls_public_key(signer).cloned() else {
                continue;
            };
            tasks.push(BlsVerificationTask {
                message: crypto::bls_round_message(round),
                signature: sig,
                public_key: pk,
                block_index: origins.len(),
            });
            seen_round_partials.insert((round, signer, sig), origins.len());
            origins.push(TaskOrigin::RoundPartial {
                round,
                signer,
                sig,
                source_blocks: Vec::new(),
            });
        }

        // 4. Standalone leader sigs (no source block).
        for (leader_ref, signer, sig) in leader_sigs {
            if self.leader_certs.contains_key(&leader_ref)
                || self
                    .leader_stake
                    .get(&leader_ref)
                    .is_some_and(|s| s.is_quorum(&self.committee))
                || self
                    .leader_partial_sigs
                    .get(&leader_ref)
                    .is_some_and(|sigs| sigs.contains_key(&signer))
            {
                continue;
            }
            if seen_leader_partials.contains_key(&(leader_ref, signer, sig)) {
                continue;
            }
            let Some(pk) = self.committee.get_bls_public_key(signer).cloned() else {
                continue;
            };
            tasks.push(BlsVerificationTask {
                message: crypto::bls_leader_message(&leader_ref),
                signature: sig,
                public_key: pk,
                block_index: origins.len(),
            });
            seen_leader_partials.insert((leader_ref, signer, sig), origins.len());
            origins.push(TaskOrigin::LeaderPartial {
                leader_ref,
                signer,
                sig,
                source_blocks: Vec::new(),
            });
        }

        (tasks, origins)
    }

    /// Collect all DAC verification tasks (embedded DAC aggregates +
    /// standalone DAC sigs) into a single batch.
    pub(crate) fn collect_dac_tasks(
        &mut self,
        blocks: &[Data<VerifiedBlock>],
        dac_sigs: Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    ) -> (Vec<BlsVerificationTask>, Vec<TaskOrigin>) {
        let mut tasks = Vec::new();
        let mut origins = Vec::new();
        let mut seen_dac_certs = AHashMap::new();

        // 1. Embedded DAC aggregate certs from block acknowledgments.
        for block in blocks {
            let source = *block.reference();
            for (ack_ref, cert) in block
                .acknowledgments()
                .into_iter()
                .zip(block.header().acknowledgment_bls_signatures().iter())
            {
                if cert.is_empty() {
                    continue;
                }
                if self.dac_certs.contains_key(&ack_ref) || self.dac_rejections.contains(&ack_ref) {
                    // Already known — count as verified for the carrier block.
                    self.mark_block_field_verified(&source);
                    continue;
                }
                if let Some(&origin_index) = seen_dac_certs.get(&(ack_ref, *cert)) {
                    push_task_source(&mut origins[origin_index], source);
                    continue;
                }
                let Some(task) =
                    self.aggregate_same_message_task(crypto::bls_dac_message(&ack_ref), cert)
                else {
                    continue;
                };
                tasks.push(BlsVerificationTask {
                    block_index: origins.len(),
                    ..task
                });
                seen_dac_certs.insert((ack_ref, *cert), origins.len());
                origins.push(TaskOrigin::AggDac(ack_ref, *cert, vec![source]));
            }
        }

        // 2. Standalone DAC sigs (no source block).
        let mut seen_dac_partials = AHashSet::new();
        for (block_ref, signer, sig) in dac_sigs {
            if self.dac_certs.contains_key(&block_ref)
                || self.dac_rejections.contains(&block_ref)
                || self
                    .dac_stake
                    .get(&block_ref)
                    .is_some_and(|s| s.is_quorum(&self.committee))
                || self
                    .dac_partial_sigs
                    .get(&block_ref)
                    .is_some_and(|sigs| sigs.contains_key(&signer))
            {
                continue;
            }
            if !seen_dac_partials.insert((block_ref, signer, sig)) {
                continue;
            }
            let Some(pk) = self.committee.get_bls_public_key(signer).cloned() else {
                continue;
            };
            tasks.push(BlsVerificationTask {
                message: crypto::bls_dac_message(&block_ref),
                signature: sig,
                public_key: pk,
                block_index: origins.len(),
            });
            origins.push(TaskOrigin::DacPartial {
                block_ref,
                signer,
                sig,
            });
        }

        (tasks, origins)
    }

    /// Route verification results to the appropriate partial-sig or
    /// cert-insertion path. Must be called after
    /// [`BlsBatchVerifier::verify_batch_parallel`] with the `invalid` set.
    pub(crate) fn dispatch_verified(
        &mut self,
        origins: Vec<TaskOrigin>,
        invalid: &AHashSet<usize>,
    ) -> Vec<CertificateEvent> {
        let mut events = Vec::new();
        let mut valid_dacs: AHashMap<BlockReference, BlsAggregateCertificate> = AHashMap::new();
        let mut rejected_dacs: AHashSet<BlockReference> = AHashSet::new();

        for (index, origin) in origins.into_iter().enumerate() {
            let is_bad = invalid.contains(&index);
            match origin {
                TaskOrigin::RoundPartial {
                    round,
                    signer,
                    sig,
                    source_blocks,
                } => {
                    if is_bad {
                        self.mark_block_fields_failed(&source_blocks);
                    } else {
                        if let Some(e) = self.add_round_partial(round, signer, sig) {
                            events.push(e);
                        }
                        self.mark_block_fields_verified(&source_blocks);
                    }
                }
                TaskOrigin::LeaderPartial {
                    leader_ref,
                    signer,
                    sig,
                    source_blocks,
                } => {
                    if is_bad {
                        self.mark_block_fields_failed(&source_blocks);
                    } else {
                        if let Some(e) = self.add_leader_partial(leader_ref, signer, sig) {
                            events.push(e);
                        }
                        self.mark_block_fields_verified(&source_blocks);
                    }
                }
                TaskOrigin::DacPartial {
                    block_ref,
                    signer,
                    sig,
                } => {
                    if !is_bad {
                        if let Some(e) = self.add_dac_partial(block_ref, signer, sig) {
                            events.push(e);
                        }
                    }
                }
                TaskOrigin::AggRound(round, cert, source_blocks) => {
                    if is_bad {
                        self.mark_block_fields_failed(&source_blocks);
                    } else {
                        if self.round_certs.insert(round, cert).is_none() {
                            events.push(CertificateEvent::Round(round, cert));
                        }
                        self.mark_block_fields_verified(&source_blocks);
                    }
                }
                TaskOrigin::AggLeader(leader_ref, cert, source_blocks) => {
                    if is_bad {
                        self.mark_block_fields_failed(&source_blocks);
                    } else {
                        if self.leader_certs.insert(leader_ref, cert).is_none() {
                            events.push(CertificateEvent::Leader(leader_ref, cert));
                        }
                        self.mark_block_fields_verified(&source_blocks);
                    }
                }
                TaskOrigin::AggDac(block_ref, cert, source_blocks) => {
                    if is_bad {
                        if !valid_dacs.contains_key(&block_ref) {
                            rejected_dacs.insert(block_ref);
                        }
                        self.mark_block_fields_failed(&source_blocks);
                    } else {
                        rejected_dacs.remove(&block_ref);
                        valid_dacs.entry(block_ref).or_insert(cert);
                        self.mark_block_fields_verified(&source_blocks);
                    }
                }
            }
        }

        for (block_ref, cert) in valid_dacs {
            if self.dac_certs.insert(block_ref, cert).is_none() {
                events.push(CertificateEvent::Dac(block_ref, cert));
            }
        }
        for block_ref in rejected_dacs {
            if self.dac_rejections.insert(block_ref) {
                events.push(CertificateEvent::DacRejected(block_ref));
            }
        }

        // Emit BlockVerified for blocks whose all BLS fields are now verified.
        events.extend(self.drain_verified_blocks());

        events
    }

    /// Process a batch of new blocks: batch-verify partial BLS signatures,
    /// verify any aggregate certificates embedded in those blocks, and return
    /// newly completed certificate events together with the number of partial
    /// signatures that failed batch verification.
    pub fn add_blocks(&mut self, blocks: &[Data<VerifiedBlock>]) -> (Vec<CertificateEvent>, u64) {
        if blocks.is_empty() {
            return (Vec::new(), 0);
        }

        // Register all blocks for verification tracking.
        for block in blocks {
            self.register_block_verification(block);
        }

        // 1. Collect round + leader partial sigs from block headers.
        let (tasks, partial_tasks) = self.collect_partial_tasks(blocks);

        // 2. Batch-verify collected partials.
        let invalid = match BlsBatchVerifier::verify_batch_parallel(&tasks, self.num_workers) {
            Ok(()) => AHashSet::new(),
            Err(bad) => bad.into_iter().collect(),
        };

        let batch_failures = invalid.len() as u64;

        // 3. Add verified partials.
        let mut events = Vec::new();
        for (index, task) in partial_tasks.into_iter().enumerate() {
            let is_bad = invalid.contains(&index);
            match task {
                PartialTaskKind::Round {
                    round,
                    signer,
                    sig,
                    source_block,
                } => {
                    if is_bad {
                        if let Some(sb) = source_block {
                            self.mark_block_field_failed(&sb);
                        }
                    } else {
                        if let Some(event) = self.add_round_partial(round, signer, sig) {
                            events.push(event);
                        }
                        if let Some(sb) = source_block {
                            self.mark_block_field_verified(&sb);
                        }
                    }
                }
                PartialTaskKind::Leader {
                    leader_ref,
                    signer,
                    sig,
                    source_block,
                } => {
                    if is_bad {
                        if let Some(sb) = source_block {
                            self.mark_block_field_failed(&sb);
                        }
                    } else {
                        if let Some(event) = self.add_leader_partial(leader_ref, signer, sig) {
                            events.push(event);
                        }
                        if let Some(sb) = source_block {
                            self.mark_block_field_verified(&sb);
                        }
                    }
                }
            }
        }

        // 4. Verify embedded aggregate certificates (DAC, round, leader).
        events.extend(self.verify_embedded_aggregate_certificates(blocks));

        // Emit BlockVerified for blocks whose all BLS fields are now verified.
        events.extend(self.drain_verified_blocks());

        (events, batch_failures)
    }

    /// Extract round and leader partial signatures from block headers into
    /// verification tasks. Deduplicates against existing certs/sigs.
    fn collect_partial_tasks(
        &mut self,
        blocks: &[Data<VerifiedBlock>],
    ) -> (Vec<BlsVerificationTask>, Vec<PartialTaskKind>) {
        let mut tasks = Vec::new();
        let mut partial_tasks = Vec::new();

        for block in blocks {
            let signer = block.authority();
            let source = *block.reference();

            // Round partial from header.
            if let Some(sig) = block.header().bls_round_signature() {
                let round = block.round();
                if *sig != BlsSignatureBytes::default() {
                    if self.round_certs.contains_key(&round)
                        || self
                            .round_stake
                            .get(&round)
                            .is_some_and(|s| s.is_quorum(&self.committee))
                        || self
                            .round_partial_sigs
                            .get(&round)
                            .is_some_and(|sigs| sigs.contains_key(&signer))
                    {
                        self.mark_block_field_verified(&source);
                    } else if let Some(public_key) =
                        self.committee.get_bls_public_key(signer).cloned()
                    {
                        tasks.push(BlsVerificationTask {
                            message: crypto::bls_round_message(round),
                            signature: *sig,
                            public_key,
                            block_index: partial_tasks.len(),
                        });
                        partial_tasks.push(PartialTaskKind::Round {
                            round,
                            signer,
                            sig: *sig,
                            source_block: Some(source),
                        });
                    }
                }
            }

            // Leader partial from header.
            if let Some((leader_ref, sig)) = block.header().voted_leader() {
                if *sig != BlsSignatureBytes::default() {
                    if self.leader_certs.contains_key(leader_ref)
                        || self
                            .leader_stake
                            .get(leader_ref)
                            .is_some_and(|s| s.is_quorum(&self.committee))
                        || self
                            .leader_partial_sigs
                            .get(leader_ref)
                            .is_some_and(|sigs| sigs.contains_key(&signer))
                    {
                        self.mark_block_field_verified(&source);
                    } else if let Some(public_key) =
                        self.committee.get_bls_public_key(signer).cloned()
                    {
                        tasks.push(BlsVerificationTask {
                            message: crypto::bls_leader_message(leader_ref),
                            signature: *sig,
                            public_key,
                            block_index: partial_tasks.len(),
                        });
                        partial_tasks.push(PartialTaskKind::Leader {
                            leader_ref: *leader_ref,
                            signer,
                            sig: *sig,
                            source_block: Some(source),
                        });
                    }
                }
            }
        }

        (tasks, partial_tasks)
    }

    /// Cleanup state for rounds below the given threshold.
    pub fn cleanup_below_round(&mut self, round: RoundNumber) {
        self.round_partial_sigs = self.round_partial_sigs.split_off(&round);
        self.round_stake = self.round_stake.split_off(&round);
        self.round_certs = self.round_certs.split_off(&round);

        self.leader_partial_sigs.retain(|r, _| r.round >= round);
        self.leader_stake.retain(|r, _| r.round >= round);
        self.leader_certs.retain(|r, _| r.round >= round);

        self.dac_partial_sigs.retain(|r, _| r.round >= round);
        self.dac_stake.retain(|r, _| r.round >= round);
        self.dac_certs.retain(|r, _| r.round >= round);
        self.dac_rejections.retain(|r| r.round >= round);

        self.block_verification.retain(|r, _| r.round >= round);
    }

    /// Register a block for BLS field verification tracking.
    /// Counts all present BLS fields and initialises the tracker.
    /// Returns `true` if the block was newly registered (or has zero fields).
    fn register_block_verification(&mut self, block: &VerifiedBlock) -> bool {
        let block_ref = *block.reference();
        if self.block_verification.contains_key(&block_ref) {
            return false;
        }

        let mut expected = 0;
        if block
            .header()
            .bls_round_signature()
            .is_some_and(|s| *s != BlsSignatureBytes::default())
        {
            expected += 1;
        }
        if block
            .header()
            .voted_leader()
            .is_some_and(|(_, s)| *s != BlsSignatureBytes::default())
        {
            expected += 1;
        }
        if block
            .header()
            .bls_aggregate_round_signature()
            .is_some_and(|c| !c.is_empty() && block.round() > 1)
        {
            expected += 1;
        }
        if block
            .header()
            .certified_leader()
            .is_some_and(|(_, c)| !c.is_empty())
        {
            expected += 1;
        }
        expected += block
            .header()
            .acknowledgment_bls_signatures()
            .iter()
            .filter(|c| !c.is_empty())
            .count();

        // Skip blocks with no BLS fields - they don't need verification tracking.
        if expected == 0 {
            return false;
        }

        self.block_verification.insert(
            block_ref,
            BlockVerificationTracker {
                expected,
                verified: 0,
                failed: false,
            },
        );
        true
    }

    /// Increment the verified count for a block's BLS field.
    fn mark_block_field_verified(&mut self, block_ref: &BlockReference) {
        if let Some(tracker) = self.block_verification.get_mut(block_ref) {
            tracker.verified += 1;
        }
    }

    /// Mark a block as having a failed BLS field.
    fn mark_block_field_failed(&mut self, block_ref: &BlockReference) {
        if let Some(tracker) = self.block_verification.get_mut(block_ref) {
            tracker.failed = true;
        }
    }

    fn mark_block_fields_verified(&mut self, block_refs: &[BlockReference]) {
        for block_ref in block_refs {
            self.mark_block_field_verified(block_ref);
        }
    }

    fn mark_block_fields_failed(&mut self, block_refs: &[BlockReference]) {
        for block_ref in block_refs {
            self.mark_block_field_failed(block_ref);
        }
    }

    /// Drain blocks whose all BLS fields have been verified.
    fn drain_verified_blocks(&mut self) -> Vec<CertificateEvent> {
        let mut events = Vec::new();
        self.block_verification.retain(|block_ref, tracker| {
            if !tracker.failed && tracker.verified >= tracker.expected {
                events.push(CertificateEvent::BlockVerified(*block_ref));
                false
            } else {
                true
            }
        });
        events
    }

    /// Process a standalone DAC partial signature received directly from a
    /// peer (not embedded in a block). Same verification + accumulation +
    /// quorum logic as the embedded path in `add_blocks`.
    /// Process a single standalone DAC partial signature.
    pub fn add_standalone_dac_sig(
        &mut self,
        block_ref: BlockReference,
        signer: AuthorityIndex,
        sig: BlsSignatureBytes,
    ) -> Vec<CertificateEvent> {
        self.add_standalone_dac_sigs_batch(vec![(block_ref, signer, sig)])
    }

    /// Process a batch of standalone DAC partial signatures using a single
    /// multi-pairing check instead of verifying each individually.
    pub fn add_standalone_dac_sigs_batch(
        &mut self,
        sigs: Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    ) -> Vec<CertificateEvent> {
        let (tasks, filtered) = self.collect_standalone_dac_tasks(sigs);

        let invalid = match BlsBatchVerifier::verify_batch_parallel(&tasks, self.num_workers) {
            Ok(()) => AHashSet::new(),
            Err(bad) => bad.into_iter().collect(),
        };

        let mut events = Vec::new();
        for (index, (block_ref, signer, sig)) in filtered.into_iter().enumerate() {
            if invalid.contains(&index) {
                continue;
            }
            if let Some(event) = self.add_dac_partial(block_ref, signer, sig) {
                events.push(event);
            }
        }
        events
    }

    /// Process a batch of standalone round partial signatures received from
    /// peers (pre-computed by their BLS service, not embedded in blocks).
    pub fn add_standalone_round_sigs_batch(
        &mut self,
        sigs: Vec<(RoundNumber, AuthorityIndex, BlsSignatureBytes)>,
    ) -> Vec<CertificateEvent> {
        let (tasks, filtered) = self.collect_standalone_round_tasks(sigs);

        let invalid = match BlsBatchVerifier::verify_batch_parallel(&tasks, self.num_workers) {
            Ok(()) => AHashSet::new(),
            Err(bad) => bad.into_iter().collect(),
        };

        let mut events = Vec::new();
        for (index, (round, signer, sig)) in filtered.into_iter().enumerate() {
            if invalid.contains(&index) {
                continue;
            }
            if let Some(event) = self.add_round_partial(round, signer, sig) {
                events.push(event);
            }
        }
        events
    }

    /// Process a batch of standalone leader partial signatures received from
    /// peers (pre-computed by their BLS service, not embedded in blocks).
    pub fn add_standalone_leader_sigs_batch(
        &mut self,
        sigs: Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    ) -> Vec<CertificateEvent> {
        let (tasks, filtered) = self.collect_standalone_leader_tasks(sigs);

        let invalid = match BlsBatchVerifier::verify_batch_parallel(&tasks, self.num_workers) {
            Ok(()) => AHashSet::new(),
            Err(bad) => bad.into_iter().collect(),
        };

        let mut events = Vec::new();
        for (index, (leader_ref, signer, sig)) in filtered.into_iter().enumerate() {
            if invalid.contains(&index) {
                continue;
            }
            if let Some(event) = self.add_leader_partial(leader_ref, signer, sig) {
                events.push(event);
            }
        }
        events
    }

    /// Collect standalone DAC partial sig tasks without verifying.
    fn collect_standalone_dac_tasks(
        &self,
        sigs: Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    ) -> (
        Vec<BlsVerificationTask>,
        Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    ) {
        let mut tasks = Vec::new();
        let mut filtered = Vec::new();
        for (block_ref, signer, sig) in sigs {
            if self.dac_certs.contains_key(&block_ref)
                || self.dac_rejections.contains(&block_ref)
                || self
                    .dac_stake
                    .get(&block_ref)
                    .is_some_and(|s| s.is_quorum(&self.committee))
                || self
                    .dac_partial_sigs
                    .get(&block_ref)
                    .is_some_and(|sigs| sigs.contains_key(&signer))
            {
                continue;
            }
            let Some(public_key) = self.committee.get_bls_public_key(signer).cloned() else {
                continue;
            };
            tasks.push(BlsVerificationTask {
                message: crypto::bls_dac_message(&block_ref),
                signature: sig,
                public_key,
                block_index: filtered.len(),
            });
            filtered.push((block_ref, signer, sig));
        }
        (tasks, filtered)
    }

    /// Collect standalone round partial sig tasks without verifying.
    fn collect_standalone_round_tasks(
        &self,
        sigs: Vec<(RoundNumber, AuthorityIndex, BlsSignatureBytes)>,
    ) -> (
        Vec<BlsVerificationTask>,
        Vec<(RoundNumber, AuthorityIndex, BlsSignatureBytes)>,
    ) {
        let mut tasks = Vec::new();
        let mut filtered = Vec::new();
        for (round, signer, sig) in sigs {
            if self.round_certs.contains_key(&round)
                || self
                    .round_stake
                    .get(&round)
                    .is_some_and(|s| s.is_quorum(&self.committee))
                || self
                    .round_partial_sigs
                    .get(&round)
                    .is_some_and(|sigs| sigs.contains_key(&signer))
            {
                continue;
            }
            let Some(public_key) = self.committee.get_bls_public_key(signer).cloned() else {
                continue;
            };
            tasks.push(BlsVerificationTask {
                message: crypto::bls_round_message(round),
                signature: sig,
                public_key,
                block_index: filtered.len(),
            });
            filtered.push((round, signer, sig));
        }
        (tasks, filtered)
    }

    /// Collect standalone leader partial sig tasks without verifying.
    fn collect_standalone_leader_tasks(
        &self,
        sigs: Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    ) -> (
        Vec<BlsVerificationTask>,
        Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)>,
    ) {
        let mut tasks = Vec::new();
        let mut filtered = Vec::new();
        for (leader_ref, signer, sig) in sigs {
            if self.leader_certs.contains_key(&leader_ref)
                || self
                    .leader_stake
                    .get(&leader_ref)
                    .is_some_and(|s| s.is_quorum(&self.committee))
                || self
                    .leader_partial_sigs
                    .get(&leader_ref)
                    .is_some_and(|sigs| sigs.contains_key(&signer))
            {
                continue;
            }
            let Some(public_key) = self.committee.get_bls_public_key(signer).cloned() else {
                continue;
            };
            tasks.push(BlsVerificationTask {
                message: crypto::bls_leader_message(&leader_ref),
                signature: sig,
                public_key,
                block_index: filtered.len(),
            });
            filtered.push((leader_ref, signer, sig));
        }
        (tasks, filtered)
    }

    fn verify_embedded_aggregate_certificates(
        &mut self,
        blocks: &[Data<VerifiedBlock>],
    ) -> Vec<CertificateEvent> {
        enum AggregateTaskKind {
            Round(RoundNumber, BlsAggregateCertificate, BlockReference),
            Leader(BlockReference, BlsAggregateCertificate, BlockReference),
            Dac(BlockReference, BlsAggregateCertificate, BlockReference),
        }

        let mut events = Vec::new();
        let mut tasks = Vec::new();
        let mut entries = Vec::new();
        let mut seen_leaders = AHashSet::new();

        for block in blocks {
            let source = *block.reference();
            if let Some(cert) = block.header().bls_aggregate_round_signature() {
                let certified_round = block.round().saturating_sub(1);
                if !cert.is_empty() && certified_round != 0 {
                    if self.round_certs.contains_key(&certified_round) {
                        self.mark_block_field_verified(&source);
                    } else if let Some(task) = self.aggregate_same_message_task(
                        crypto::bls_round_message(certified_round),
                        cert,
                    ) {
                        tasks.push(BlsVerificationTask {
                            block_index: entries.len(),
                            ..task
                        });
                        entries.push(AggregateTaskKind::Round(certified_round, *cert, source));
                    }
                }
            }

            if let Some((leader_ref, cert)) = block.header().certified_leader() {
                if !cert.is_empty() {
                    if self.leader_certs.contains_key(leader_ref) {
                        self.mark_block_field_verified(&source);
                    } else if seen_leaders.insert(*leader_ref) {
                        if let Some(task) = self.aggregate_same_message_task(
                            crypto::bls_leader_message(leader_ref),
                            cert,
                        ) {
                            tasks.push(BlsVerificationTask {
                                block_index: entries.len(),
                                ..task
                            });
                            entries.push(AggregateTaskKind::Leader(*leader_ref, *cert, source));
                        }
                    }
                }
            }

            for (ack_ref, cert) in block
                .acknowledgments()
                .into_iter()
                .zip(block.header().acknowledgment_bls_signatures().iter())
            {
                if cert.is_empty() {
                    continue;
                }
                if self.dac_certs.contains_key(&ack_ref) || self.dac_rejections.contains(&ack_ref) {
                    self.mark_block_field_verified(&source);
                    continue;
                }
                let Some(task) =
                    self.aggregate_same_message_task(crypto::bls_dac_message(&ack_ref), cert)
                else {
                    continue;
                };
                tasks.push(BlsVerificationTask {
                    block_index: entries.len(),
                    ..task
                });
                entries.push(AggregateTaskKind::Dac(ack_ref, *cert, source));
            }
        }

        let invalid = match BlsBatchVerifier::verify_batch_parallel(&tasks, self.num_workers) {
            Ok(()) => AHashSet::new(),
            Err(bad) => bad.into_iter().collect(),
        };

        let mut valid_dacs = AHashMap::new();
        let mut rejected_dacs = AHashSet::new();
        for (index, entry) in entries.into_iter().enumerate() {
            let is_bad = invalid.contains(&index);
            match entry {
                AggregateTaskKind::Round(round, cert, source) => {
                    if is_bad {
                        self.mark_block_field_failed(&source);
                    } else {
                        if self.round_certs.insert(round, cert).is_none() {
                            events.push(CertificateEvent::Round(round, cert));
                        }
                        self.mark_block_field_verified(&source);
                    }
                }
                AggregateTaskKind::Leader(leader_ref, cert, source) => {
                    if is_bad {
                        self.mark_block_field_failed(&source);
                    } else {
                        if self.leader_certs.insert(leader_ref, cert).is_none() {
                            events.push(CertificateEvent::Leader(leader_ref, cert));
                        }
                        self.mark_block_field_verified(&source);
                    }
                }
                AggregateTaskKind::Dac(block_ref, cert, source) => {
                    if is_bad {
                        if !valid_dacs.contains_key(&block_ref) {
                            rejected_dacs.insert(block_ref);
                        }
                        self.mark_block_field_failed(&source);
                    } else {
                        rejected_dacs.remove(&block_ref);
                        valid_dacs.entry(block_ref).or_insert(cert);
                        self.mark_block_field_verified(&source);
                    }
                }
            }
        }

        for (block_ref, cert) in valid_dacs {
            if self.dac_certs.insert(block_ref, cert).is_none() {
                events.push(CertificateEvent::Dac(block_ref, cert));
            }
        }
        for block_ref in rejected_dacs {
            if self.dac_rejections.insert(block_ref) {
                events.push(CertificateEvent::DacRejected(block_ref));
            }
        }

        events
    }

    fn aggregate_same_message_task(
        &mut self,
        message: [u8; 32],
        cert: &BlsAggregateCertificate,
    ) -> Option<BlsVerificationTask> {
        let aggregate_public_key = self.aggregate_public_key(cert.signers())?;
        Some(BlsVerificationTask {
            message,
            signature: *cert.signature(),
            public_key: aggregate_public_key,
            block_index: 0,
        })
    }

    fn aggregate_public_key(
        &mut self,
        signers: crate::types::AuthoritySet,
    ) -> Option<BlsPublicKey> {
        if let Some(public_key) = self.aggregate_public_key_cache.get(&signers) {
            return Some(public_key.clone());
        }
        let pubkeys = crypto::bls_public_keys_for_signers(&self.committee, signers)?;
        let aggregate_public_key = bls_aggregate_public_keys(&pubkeys)?;
        self.aggregate_public_key_cache
            .insert(signers, aggregate_public_key.clone());
        Some(aggregate_public_key)
    }

    pub(crate) fn add_round_partial(
        &mut self,
        round: RoundNumber,
        signer: AuthorityIndex,
        sig: BlsSignatureBytes,
    ) -> Option<CertificateEvent> {
        if self.round_certs.contains_key(&round) {
            return None;
        }
        let sigs = self.round_partial_sigs.entry(round).or_default();
        sigs.entry(signer).or_insert(sig);
        let (reached_quorum, signers) = {
            let stake = self.round_stake.entry(round).or_default();
            (stake.add(signer, &self.committee), stake.votes)
        };
        if reached_quorum {
            let cert = BlsAggregateCertificate::new(self.aggregate_round(round), signers);
            self.round_certs.insert(round, cert);
            Some(CertificateEvent::Round(round, cert))
        } else {
            None
        }
    }

    pub(crate) fn add_leader_partial(
        &mut self,
        leader_ref: BlockReference,
        signer: AuthorityIndex,
        sig: BlsSignatureBytes,
    ) -> Option<CertificateEvent> {
        if self.leader_certs.contains_key(&leader_ref) {
            return None;
        }
        let sigs = self.leader_partial_sigs.entry(leader_ref).or_default();
        sigs.entry(signer).or_insert(sig);
        let (reached_quorum, signers) = {
            let stake = self.leader_stake.entry(leader_ref).or_default();
            (stake.add(signer, &self.committee), stake.votes)
        };
        if reached_quorum {
            let cert = BlsAggregateCertificate::new(self.aggregate_leader(&leader_ref), signers);
            self.leader_certs.insert(leader_ref, cert);
            Some(CertificateEvent::Leader(leader_ref, cert))
        } else {
            None
        }
    }

    fn add_dac_partial(
        &mut self,
        block_ref: BlockReference,
        signer: AuthorityIndex,
        sig: BlsSignatureBytes,
    ) -> Option<CertificateEvent> {
        if self.dac_certs.contains_key(&block_ref) || self.dac_rejections.contains(&block_ref) {
            return None;
        }
        let sigs = self.dac_partial_sigs.entry(block_ref).or_default();
        sigs.entry(signer).or_insert(sig);
        let (reached_quorum, signers) = {
            let stake = self.dac_stake.entry(block_ref).or_default();
            (stake.add(signer, &self.committee), stake.votes)
        };
        if reached_quorum {
            let cert = BlsAggregateCertificate::new(self.aggregate_dac(&block_ref), signers);
            self.dac_certs.insert(block_ref, cert);
            Some(CertificateEvent::Dac(block_ref, cert))
        } else {
            None
        }
    }

    fn aggregate_round(&self, round: RoundNumber) -> BlsSignatureBytes {
        let sigs = &self.round_partial_sigs[&round];
        let sig_refs: Vec<&BlsSignatureBytes> = sigs.values().collect();
        bls_aggregate(&sig_refs)
    }

    fn aggregate_leader(&self, leader_ref: &BlockReference) -> BlsSignatureBytes {
        let sigs = &self.leader_partial_sigs[leader_ref];
        let sig_refs: Vec<&BlsSignatureBytes> = sigs.values().collect();
        bls_aggregate(&sig_refs)
    }

    fn aggregate_dac(&self, block_ref: &BlockReference) -> BlsSignatureBytes {
        let sigs = &self.dac_partial_sigs[block_ref];
        let sig_refs: Vec<&BlsSignatureBytes> = sigs.values().collect();
        bls_aggregate(&sig_refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        committee::Committee,
        crypto::{BlsSigner, Signer},
        dag_state::ConsensusProtocol,
        encoder::{Encoder, ShardEncoder},
        types::{AuthoritySet, BaseTransaction, VerifiedBlock},
    };

    fn make_starfish_bls_block(
        committee: &Committee,
        signers: &[Signer],
        bls_signers: &[BlsSigner],
        authority: AuthorityIndex,
        round: RoundNumber,
        acknowledgments: Vec<BlockReference>,
        dac_certs: Vec<BlsAggregateCertificate>,
    ) -> VerifiedBlock {
        let info_length = committee.info_length();
        let parity_length = committee.len() - info_length;
        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let transactions = Vec::<BaseTransaction>::new();
        let encoded_transactions =
            encoder.encode_transactions(&transactions, info_length, parity_length);
        let is_round_leader = authority == committee.elect_leader(round);
        let mut block_references = if is_round_leader {
            vec![
                BlockReference::new_test(0, round - 1),
                BlockReference::new_test(1, round - 1),
                BlockReference::new_test(2, round - 1),
            ]
        } else {
            vec![BlockReference::new_test(authority, round - 1)]
        };
        let voted_leader_ref = (round > 1).then(|| {
            let leader = committee.elect_leader(round - 1);
            BlockReference::new_test(leader, round - 1)
        });
        if let Some(leader_ref) = voted_leader_ref {
            if !block_references.contains(&leader_ref) {
                block_references.push(leader_ref);
            }
        }
        VerifiedBlock::new_with_signer(
            authority,
            round,
            block_references,
            voted_leader_ref,
            acknowledgments,
            0,
            &signers[authority as usize],
            Some(&bls_signers[authority as usize]),
            Some(committee),
            dac_certs,
            transactions,
            Some(encoded_transactions),
            ConsensusProtocol::StarfishBls,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[test]
    fn learns_embedded_dac_certificate_from_received_starfish_bls_block() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let bls_signers = BlsSigner::new_for_test(committee.len());
        let ack_ref = BlockReference::new_test(1, 1);

        let mut author_aggregator = BlsCertificateAggregator::new(committee.clone());
        let mut dac_cert = None;
        for signer in [0, 1, 2] {
            for event in author_aggregator.add_standalone_dac_sig(
                ack_ref,
                signer,
                bls_signers[signer as usize].sign_digest(&crypto::bls_dac_message(&ack_ref)),
            ) {
                if let CertificateEvent::Dac(block_ref, cert) = event {
                    assert_eq!(block_ref, ack_ref);
                    dac_cert = Some(cert);
                }
            }
        }
        let dac_cert = dac_cert.expect("quorum partials should build a DAC cert");
        assert_eq!(
            dac_cert.signers().present().collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        let carrier = make_starfish_bls_block(
            committee.as_ref(),
            &signers,
            &bls_signers,
            1,
            3,
            vec![BlockReference::new_test(1, 2), ack_ref],
            vec![
                // Keep the latest own ack first to mirror runtime behavior.
                BlsAggregateCertificate::new(
                    bls_signers[0]
                        .sign_digest(&crypto::bls_dac_message(&BlockReference::new_test(1, 2))),
                    {
                        let mut signers = AuthoritySet::default();
                        assert!(signers.insert(0));
                        signers
                    },
                ),
                dac_cert,
            ],
        );

        let mut remote_aggregator = BlsCertificateAggregator::new(committee);
        let (events, _) = remote_aggregator.add_blocks(&[Data::new(carrier)]);
        assert!(
            events.iter().any(|event| matches!(
                event,
                CertificateEvent::Dac(block_ref, cert)
                    if *block_ref == ack_ref && *cert == dac_cert
            )),
            "remote aggregator should learn the embedded DAC cert for the acknowledged block"
        );
    }

    #[test]
    fn learns_embedded_dac_certificate_from_large_committee_block() {
        let committee = Committee::new_for_benchmarks(16);
        let signers = Signer::new_for_test(committee.len());
        let bls_signers = BlsSigner::new_for_test(committee.len());
        let ack_ref = BlockReference::new_test(1, 1);

        let mut author_aggregator = BlsCertificateAggregator::new(committee.clone());
        let mut dac_cert = None;
        for signer in 0..committee.quorum_threshold() as AuthorityIndex {
            for event in author_aggregator.add_standalone_dac_sig(
                ack_ref,
                signer,
                bls_signers[signer as usize].sign_digest(&crypto::bls_dac_message(&ack_ref)),
            ) {
                if let CertificateEvent::Dac(block_ref, cert) = event {
                    assert_eq!(block_ref, ack_ref);
                    dac_cert = Some(cert);
                }
            }
        }
        let dac_cert = dac_cert.expect("quorum partials should build a DAC cert");

        let previous_own = BlockReference::new_test(1, 2);
        let previous_own_cert = {
            let mut previous_own_author = BlsCertificateAggregator::new(committee.clone());
            let mut cert = None;
            for signer in 0..committee.quorum_threshold() as AuthorityIndex {
                for event in previous_own_author.add_standalone_dac_sig(
                    previous_own,
                    signer,
                    bls_signers[signer as usize]
                        .sign_digest(&crypto::bls_dac_message(&previous_own)),
                ) {
                    if let CertificateEvent::Dac(block_ref, new_cert) = event {
                        assert_eq!(block_ref, previous_own);
                        cert = Some(new_cert);
                    }
                }
            }
            cert.expect("quorum partials should build a DAC cert for the previous own block")
        };

        let carrier = make_starfish_bls_block(
            committee.as_ref(),
            &signers,
            &bls_signers,
            1,
            3,
            vec![previous_own, ack_ref],
            vec![previous_own_cert, dac_cert],
        );

        let mut remote_aggregator = BlsCertificateAggregator::new(committee);
        let (events, _) = remote_aggregator.add_blocks(&[Data::new(carrier)]);
        assert!(
            events.iter().any(|event| matches!(
                event,
                CertificateEvent::Dac(block_ref, cert)
                    if *block_ref == ack_ref && *cert == dac_cert
            )),
            "remote aggregator should learn the embedded DAC cert for the acknowledged block"
        );
    }

    #[test]
    fn duplicate_round_certificate_does_not_skip_embedded_dac_verification() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let bls_signers = BlsSigner::new_for_test(committee.len());
        let ack_ref = BlockReference::new_test(1, 1);

        let mut author_aggregator = BlsCertificateAggregator::new(committee.clone());
        let mut dac_cert = None;
        for signer in [0, 1, 2] {
            for event in author_aggregator.add_standalone_dac_sig(
                ack_ref,
                signer,
                bls_signers[signer as usize].sign_digest(&crypto::bls_dac_message(&ack_ref)),
            ) {
                if let CertificateEvent::Dac(block_ref, cert) = event {
                    assert_eq!(block_ref, ack_ref);
                    dac_cert = Some(cert);
                }
            }
        }
        let dac_cert = dac_cert.expect("quorum partials should build a DAC cert");

        let mut carrier = make_starfish_bls_block(
            committee.as_ref(),
            &signers,
            &bls_signers,
            1,
            3,
            vec![ack_ref],
            vec![dac_cert],
        );
        carrier
            .header
            .bls
            .as_mut()
            .expect("StarfishBls block should carry BLS fields")
            .aggregate_round_signature = Some(dac_cert);

        let mut remote_aggregator = BlsCertificateAggregator::new(committee);
        remote_aggregator.round_certs.insert(2, dac_cert);
        let (events, _) = remote_aggregator.add_blocks(&[Data::new(carrier)]);
        assert!(
            events.iter().any(|event| matches!(
                event,
                CertificateEvent::Dac(block_ref, cert)
                    if *block_ref == ack_ref && *cert == dac_cert
            )),
            "duplicate round cert must not prevent learning embedded DAC certs"
        );
    }

    #[test]
    fn duplicate_leader_certificate_does_not_skip_embedded_dac_verification() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let bls_signers = BlsSigner::new_for_test(committee.len());
        let ack_ref = BlockReference::new_test(1, 1);
        let leader_ref = BlockReference::new_test(0, 2);

        let mut author_aggregator = BlsCertificateAggregator::new(committee.clone());
        let mut dac_cert = None;
        for signer in [0, 1, 2] {
            for event in author_aggregator.add_standalone_dac_sig(
                ack_ref,
                signer,
                bls_signers[signer as usize].sign_digest(&crypto::bls_dac_message(&ack_ref)),
            ) {
                if let CertificateEvent::Dac(block_ref, cert) = event {
                    assert_eq!(block_ref, ack_ref);
                    dac_cert = Some(cert);
                }
            }
        }
        let dac_cert = dac_cert.expect("quorum partials should build a DAC cert");

        let mut carrier = make_starfish_bls_block(
            committee.as_ref(),
            &signers,
            &bls_signers,
            1,
            3,
            vec![ack_ref],
            vec![dac_cert],
        );
        carrier
            .header
            .bls
            .as_mut()
            .expect("StarfishBls block should carry BLS fields")
            .certified_leader = Some((leader_ref, dac_cert));

        let mut remote_aggregator = BlsCertificateAggregator::new(committee);
        remote_aggregator.leader_certs.insert(leader_ref, dac_cert);
        let (events, _) = remote_aggregator.add_blocks(&[Data::new(carrier)]);
        assert!(
            events.iter().any(|event| matches!(
                event,
                CertificateEvent::Dac(block_ref, cert)
                    if *block_ref == ack_ref && *cert == dac_cert
            )),
            "duplicate leader cert must not prevent learning embedded DAC certs"
        );
    }
}
