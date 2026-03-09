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
        }
    }

    /// Process a batch of new blocks: batch-verify partial BLS signatures,
    /// verify any aggregate certificates embedded in those blocks, and return
    /// newly completed certificate events together with the number of partial
    /// signatures that failed batch verification.
    pub fn add_blocks(&mut self, blocks: &[Data<VerifiedBlock>]) -> (Vec<CertificateEvent>, u64) {
        if blocks.is_empty() {
            return (Vec::new(), 0);
        }

        let mut events = Vec::new();
        let mut tasks = Vec::new();
        let mut task_kinds = Vec::new();

        for block in blocks {
            self.collect_partial_tasks(block, &mut tasks, &mut task_kinds);
        }

        let (invalid, batch_failures) =
            match BlsBatchVerifier::verify_batch_parallel(&tasks, self.num_workers) {
                Ok(()) => (AHashSet::new(), 0),
                Err(bad) => {
                    let count = bad.len() as u64;
                    (bad.into_iter().collect(), count)
                }
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
        (events, batch_failures)
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
        let mut tasks = Vec::new();
        // Track which input indices survive filtering.
        let mut filtered: Vec<(BlockReference, AuthorityIndex, BlsSignatureBytes)> = Vec::new();

        for (block_ref, signer, sig) in sigs {
            // Skip if cert already complete, rejected, duplicate, or quorum
            // already reached.
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
                    .round_stake
                    .get(&round)
                    .is_some_and(|s| s.is_quorum(&self.committee))
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
                    .leader_stake
                    .get(leader_ref)
                    .is_some_and(|s| s.is_quorum(&self.committee))
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
                if !cert.is_empty()
                    && certified_round != 0
                    && !self.round_certs.contains_key(&certified_round)
                {
                    if let Some(task) = self.aggregate_same_message_task(
                        crypto::bls_round_message(certified_round),
                        cert,
                    ) {
                        tasks.push(BlsVerificationTask {
                            block_index: entries.len(),
                            ..task
                        });
                        entries.push(AggregateTaskKind::Round(certified_round, *cert));
                    }
                }
            }

            if let Some((leader_ref, cert)) = block.header().certified_leader() {
                if !cert.is_empty()
                    && !self.leader_certs.contains_key(leader_ref)
                    && seen_leaders.insert(*leader_ref)
                {
                    if let Some(task) = self
                        .aggregate_same_message_task(crypto::bls_leader_message(leader_ref), cert)
                    {
                        tasks.push(BlsVerificationTask {
                            block_index: entries.len(),
                            ..task
                        });
                        entries.push(AggregateTaskKind::Leader(*leader_ref, *cert));
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
                if self.dac_certs.contains_key(&ack_ref) {
                    continue;
                }
                if self.dac_rejections.contains(&ack_ref) {
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

        let invalid = match BlsBatchVerifier::verify_batch_parallel(&tasks, self.num_workers) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        committee::Committee,
        crypto::{BlsSigner, Signer},
        dag_state::ConsensusProtocol,
        encoder::{Encoder, ShardEncoder},
        types::{BaseTransaction, VerifiedBlock},
    };

    fn make_starfish_l_block(
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
            ConsensusProtocol::StarfishL,
            None,
            None,
            None,
        )
    }

    #[test]
    fn learns_embedded_dac_certificate_from_received_starfish_l_block() {
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

        let carrier = make_starfish_l_block(
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
                        let mut signers = crate::types::AuthoritySet::default();
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

        let carrier = make_starfish_l_block(
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

        let mut carrier = make_starfish_l_block(
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
            .expect("StarfishL block should carry BLS fields")
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

        let mut carrier = make_starfish_l_block(
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
            .expect("StarfishL block should carry BLS fields")
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
