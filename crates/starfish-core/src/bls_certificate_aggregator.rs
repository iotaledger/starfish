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
    crypto::{self, BlsSignatureBytes, bls_aggregate, bls_aggregate_public_keys},
    dag_state::DagState,
    data::Data,
    types::{AuthorityIndex, BlockReference, BlsAggregateCertificate, RoundNumber, VerifiedBlock},
};

/// Apply certificate events to a `DagState`, returning `true` if any new
/// certificate was learned.
pub fn apply_certificate_events(dag_state: &DagState, events: Vec<CertificateEvent>) -> bool {
    let mut changed = false;
    for event in events {
        match event {
            CertificateEvent::Round(round, cert) => {
                changed |= dag_state.mark_round_certified(round, cert);
            }
            CertificateEvent::Leader(leader_ref, cert) => {
                changed |= dag_state.mark_leader_certified(leader_ref, cert);
            }
            CertificateEvent::Dac(block_ref, cert) => {
                changed |= dag_state.mark_dac_certified(block_ref, cert);
            }
            CertificateEvent::DacRejected(block_ref) => {
                changed |= dag_state.mark_dac_rejected(block_ref);
            }
        }
    }
    changed
}

/// Events emitted when a new verified certificate is completed.
#[derive(Debug)]
pub enum CertificateEvent {
    Round(RoundNumber, BlsAggregateCertificate),
    Leader(BlockReference, BlsAggregateCertificate),
    Dac(BlockReference, BlsAggregateCertificate),
    DacRejected(BlockReference),
}

enum PartialTaskKind {
    Round {
        round: RoundNumber,
        signer: AuthorityIndex,
        sig: BlsSignatureBytes,
    },
    Leader {
        leader_ref: BlockReference,
        signer: AuthorityIndex,
        sig: BlsSignatureBytes,
    },
}

pub struct BlsCertificateAggregator {
    committee: Arc<Committee>,

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
}

impl BlsCertificateAggregator {
    pub fn new(committee: Arc<Committee>) -> Self {
        Self {
            committee,
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
        }
    }

    /// Process a batch of new blocks: batch-verify partial BLS signatures,
    /// verify any aggregate certificates embedded in those blocks, and return
    /// newly completed certificate events.
    pub fn add_blocks(&mut self, blocks: &[Data<VerifiedBlock>]) -> Vec<CertificateEvent> {
        if blocks.is_empty() {
            return Vec::new();
        }

        let mut events = Vec::new();
        let mut tasks = Vec::new();
        let mut task_kinds = Vec::new();

        for block in blocks {
            self.collect_partial_tasks(block, &mut tasks, &mut task_kinds);
        }

        let invalid = match BlsBatchVerifier::verify_batch(&tasks) {
            Ok(()) => AHashSet::new(),
            Err(bad) => bad.into_iter().collect(),
        };

        for (index, kind) in task_kinds.into_iter().enumerate() {
            if invalid.contains(&index) {
                continue;
            }

            match kind {
                PartialTaskKind::Round { round, signer, sig } => {
                    if let Some(event) = self.add_round_partial(round, signer, sig) {
                        events.push(event);
                    }
                }
                PartialTaskKind::Leader {
                    leader_ref,
                    signer,
                    sig,
                } => {
                    if let Some(event) = self.add_leader_partial(leader_ref, signer, sig) {
                        events.push(event);
                    }
                }
            }
        }

        events.extend(self.verify_embedded_aggregate_certificates(blocks));
        events
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
    }

    /// Process a standalone DAC partial signature received directly from a
    /// peer (not embedded in a block). Same verification + accumulation +
    /// quorum logic as the embedded path in `add_blocks`.
    pub fn add_standalone_dac_sig(
        &mut self,
        block_ref: BlockReference,
        signer: AuthorityIndex,
        sig: BlsSignatureBytes,
    ) -> Vec<CertificateEvent> {
        let mut events = Vec::new();
        if self.dac_certs.contains_key(&block_ref) || self.dac_rejections.contains(&block_ref) {
            return events;
        }

        let Some(public_key) = self.committee.get_bls_public_key(signer).cloned() else {
            return events;
        };
        let digest = crypto::bls_dac_message(&block_ref);
        let task = BlsVerificationTask {
            message: digest,
            signature: sig,
            public_key,
            block_index: 0,
        };
        if BlsBatchVerifier::verify_batch(&[task]).is_err() {
            return events;
        }

        if let Some(event) = self.add_dac_partial(block_ref, signer, sig) {
            events.push(event);
        }
        events
    }

    fn collect_partial_tasks(
        &self,
        block: &Data<VerifiedBlock>,
        tasks: &mut Vec<BlsVerificationTask>,
        task_kinds: &mut Vec<PartialTaskKind>,
    ) {
        let author = block.authority();
        let Some(public_key) = self.committee.get_bls_public_key(author).cloned() else {
            return;
        };

        if let Some(sig) = block.header().bls_round_signature() {
            let round = block.round();
            if !self.round_certs.contains_key(&round)
                && !self
                    .round_partial_sigs
                    .get(&round)
                    .is_some_and(|sigs| sigs.contains_key(&author))
            {
                tasks.push(BlsVerificationTask {
                    message: crypto::bls_round_message(round),
                    signature: *sig,
                    public_key: public_key.clone(),
                    block_index: task_kinds.len(),
                });
                task_kinds.push(PartialTaskKind::Round {
                    round,
                    signer: author,
                    sig: *sig,
                });
            }
        }

        if let Some((leader_ref, sig)) = block.header().voted_leader() {
            if !self.leader_certs.contains_key(leader_ref)
                && !self
                    .leader_partial_sigs
                    .get(leader_ref)
                    .is_some_and(|sigs| sigs.contains_key(&author))
            {
                tasks.push(BlsVerificationTask {
                    message: crypto::bls_leader_message(leader_ref),
                    signature: *sig,
                    public_key,
                    block_index: task_kinds.len(),
                });
                task_kinds.push(PartialTaskKind::Leader {
                    leader_ref: *leader_ref,
                    signer: author,
                    sig: *sig,
                });
            }
        }
    }

    fn verify_embedded_aggregate_certificates(
        &mut self,
        blocks: &[Data<VerifiedBlock>],
    ) -> Vec<CertificateEvent> {
        let mut events = Vec::new();
        let mut tasks = Vec::new();
        let mut entries = Vec::new();
        let mut seen_leaders = AHashSet::new();

        enum AggregateTaskKind {
            Round(RoundNumber, BlsAggregateCertificate),
            Leader(BlockReference, BlsAggregateCertificate),
            Dac(BlockReference, BlsAggregateCertificate),
        }

        for block in blocks {
            if let Some(cert) = block.header().bls_aggregate_round_signature() {
                let certified_round = block.round().saturating_sub(1);
                if cert.is_empty()
                    || certified_round == 0
                    || self.round_certs.contains_key(&certified_round)
                {
                    continue;
                }
                let Some(task) = self
                    .aggregate_same_message_task(crypto::bls_round_message(certified_round), cert)
                else {
                    continue;
                };
                tasks.push(BlsVerificationTask {
                    block_index: entries.len(),
                    ..task
                });
                entries.push(AggregateTaskKind::Round(certified_round, *cert));
            }

            if let Some((leader_ref, cert)) = block.header().certified_leader() {
                if cert.is_empty() {
                    continue;
                }
                if self.leader_certs.contains_key(leader_ref) || !seen_leaders.insert(*leader_ref) {
                    continue;
                }
                let Some(task) =
                    self.aggregate_same_message_task(crypto::bls_leader_message(leader_ref), cert)
                else {
                    continue;
                };
                tasks.push(BlsVerificationTask {
                    block_index: entries.len(),
                    ..task
                });
                entries.push(AggregateTaskKind::Leader(*leader_ref, *cert));
            }

            for (ack_ref, cert) in block
                .acknowledgments()
                .into_iter()
                .zip(block.header().acknowledgment_bls_signatures().iter())
            {
                if cert.is_empty()
                    || self.dac_certs.contains_key(&ack_ref)
                    || self.dac_rejections.contains(&ack_ref)
                {
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
                entries.push(AggregateTaskKind::Dac(ack_ref, *cert));
            }
        }

        let invalid = match BlsBatchVerifier::verify_batch(&tasks) {
            Ok(()) => AHashSet::new(),
            Err(bad) => bad.into_iter().collect(),
        };

        let mut valid_dacs = AHashMap::new();
        let mut rejected_dacs = AHashSet::new();
        for (index, entry) in entries.into_iter().enumerate() {
            match entry {
                AggregateTaskKind::Round(round, cert) => {
                    if invalid.contains(&index) {
                        continue;
                    }
                    if self.round_certs.insert(round, cert).is_none() {
                        events.push(CertificateEvent::Round(round, cert));
                    }
                }
                AggregateTaskKind::Leader(leader_ref, cert) => {
                    if invalid.contains(&index) {
                        continue;
                    }
                    if self.leader_certs.insert(leader_ref, cert).is_none() {
                        events.push(CertificateEvent::Leader(leader_ref, cert));
                    }
                }
                AggregateTaskKind::Dac(block_ref, cert) => {
                    if invalid.contains(&index) {
                        if !valid_dacs.contains_key(&block_ref) {
                            rejected_dacs.insert(block_ref);
                        }
                    } else {
                        rejected_dacs.remove(&block_ref);
                        valid_dacs.entry(block_ref).or_insert(cert);
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
        &self,
        message: [u8; 32],
        cert: &BlsAggregateCertificate,
    ) -> Option<BlsVerificationTask> {
        let pubkeys = crypto::bls_public_keys_for_signers(&self.committee, cert.signers())?;
        let aggregate_public_key = bls_aggregate_public_keys(&pubkeys)?;
        Some(BlsVerificationTask {
            message,
            signature: *cert.signature(),
            public_key: aggregate_public_key,
            block_index: 0,
        })
    }

    fn add_round_partial(
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

    fn add_leader_partial(
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
