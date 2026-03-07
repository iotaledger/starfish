// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Collects partial BLS signatures from received blocks and produces aggregate
//! certificates once a quorum (2f+1 by stake) is reached.
//!
//! Three certificate types are tracked:
//! - **Round certificates**: aggregate of `bls_round_signature` values from
//!   blocks at the same round.
//! - **Leader certificates**: aggregate of `bls_leader_signature` values for a
//!   particular leader block.
//! - **DAC certificates**: aggregate of per-block partial BLS signatures over
//!   `payloadCommit` (transactions commitment) for acknowledged blocks.

use std::{collections::BTreeMap, sync::Arc};

use ahash::AHashMap;

use crate::{
    committee::{Committee, QuorumThreshold, StakeAggregator},
    crypto::{self, BlsSignatureBytes, bls_aggregate},
    data::Data,
    types::{AuthorityIndex, BlockReference, RoundNumber, VerifiedBlock},
};

/// Events emitted when a new certificate is completed.
#[derive(Debug)]
#[allow(dead_code)]
pub enum CertificateEvent {
    Round(RoundNumber, BlsSignatureBytes),
    Leader(BlockReference, BlsSignatureBytes),
    Dac(BlockReference, BlsSignatureBytes),
}

pub struct BlsCertificateAggregator {
    committee: Arc<Committee>,

    // Round r -> (authority -> partial round sig)
    round_partial_sigs: BTreeMap<RoundNumber, AHashMap<AuthorityIndex, BlsSignatureBytes>>,
    round_stake: BTreeMap<RoundNumber, StakeAggregator<QuorumThreshold>>,
    /// Completed round certificates.
    round_certs: BTreeMap<RoundNumber, BlsSignatureBytes>,

    // leader_ref -> (authority -> partial leader sig)
    leader_partial_sigs: AHashMap<BlockReference, AHashMap<AuthorityIndex, BlsSignatureBytes>>,
    leader_stake: AHashMap<BlockReference, StakeAggregator<QuorumThreshold>>,
    /// Completed leader certificates.
    leader_certs: AHashMap<BlockReference, BlsSignatureBytes>,

    // block_ref -> (authority -> partial DAC sig on payloadCommit)
    dac_partial_sigs: AHashMap<BlockReference, AHashMap<AuthorityIndex, BlsSignatureBytes>>,
    dac_stake: AHashMap<BlockReference, StakeAggregator<QuorumThreshold>>,
    /// Completed DAC certificates.
    dac_certs: AHashMap<BlockReference, BlsSignatureBytes>,
}

#[allow(dead_code)]
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
        }
    }

    /// Verify a BLS signature against the author's public key.
    /// Returns `false` (and the signature is silently dropped) on failure.
    fn verify_sig(
        &self,
        author: AuthorityIndex,
        digest: &[u8; 32],
        sig: &BlsSignatureBytes,
    ) -> bool {
        let Some(pk) = self.committee.get_bls_public_key(author) else {
            return false;
        };
        pk.verify(digest, sig).is_ok()
    }

    /// Process a new block: verify and accumulate partial BLS sigs.
    /// Returns newly completed certificates.
    ///
    /// `commitment_lookup` resolves the `transactions_commitment` for
    /// acknowledged block references (needed for DAC sig verification).
    pub fn add_block(
        &mut self,
        block: &Data<VerifiedBlock>,
        commitment_lookup: impl Fn(&BlockReference) -> crate::crypto::TransactionsCommitment,
    ) -> Vec<CertificateEvent> {
        let mut events = Vec::new();
        let author = block.author();
        let round = block.round();

        // 1. Round signature — verify against block digest
        if let Some(sig) = block.header().bls_round_signature() {
            if !self.round_certs.contains_key(&round) {
                // Compute the same digest the signer used.
                let mut bls_hasher = crypto::Blake3Hasher::new();
                crypto::BlockDigest::digest_without_signature(
                    &mut bls_hasher,
                    block.author(),
                    round,
                    block.block_references(),
                    &block.acknowledgments(),
                    block.meta_creation_time_ns(),
                    block.epoch_changed(),
                    block.merkle_root(),
                    block.strong_vote(),
                );
                let digest: [u8; 32] = bls_hasher.finalize().into();
                if self.verify_sig(author, &digest, sig) {
                    let sigs = self.round_partial_sigs.entry(round).or_default();
                    sigs.entry(author).or_insert(*sig);
                    let stake = self.round_stake.entry(round).or_default();
                    if stake.add(author, &self.committee) {
                        let agg = self.aggregate_round(round);
                        self.round_certs.insert(round, agg);
                        events.push(CertificateEvent::Round(round, agg));
                    }
                }
            }
        }

        // 2. Leader signature — verify against leader message
        if let Some(sig) = block.header().bls_leader_signature() {
            let leader_round = round.saturating_sub(1);
            let leader_authority = self.committee.elect_leader(leader_round);
            if let Some(leader_ref) = block
                .block_references()
                .iter()
                .find(|r| r.round == leader_round && r.authority == leader_authority)
            {
                let leader_ref = *leader_ref;
                if !self.leader_certs.contains_key(&leader_ref) {
                    let digest = crypto::bls_leader_message(&leader_ref);
                    if self.verify_sig(author, &digest, sig) {
                        let sigs = self.leader_partial_sigs.entry(leader_ref).or_default();
                        sigs.entry(author).or_insert(*sig);
                        let stake = self.leader_stake.entry(leader_ref).or_default();
                        if stake.add(author, &self.committee) {
                            let agg = self.aggregate_leader(&leader_ref);
                            self.leader_certs.insert(leader_ref, agg);
                            events.push(CertificateEvent::Leader(leader_ref, agg));
                        }
                    }
                }
            }
        }

        // 3. DAC partial signatures — verify against dac message.
        // The commitment lookup retrieves the transactions_commitment from the
        // acknowledged block (which must already be in the DAG).
        let ack_refs = block.acknowledgments();
        let ack_bls_sigs = block.header().acknowledgment_bls_signatures();
        for (ack_ref, sig) in ack_refs.iter().zip(ack_bls_sigs.iter()) {
            if !self.dac_certs.contains_key(ack_ref) {
                let commitment = commitment_lookup(ack_ref);
                let digest = crypto::bls_dac_message(ack_ref, commitment);
                if self.verify_sig(author, &digest, sig) {
                    let sigs = self.dac_partial_sigs.entry(*ack_ref).or_default();
                    sigs.entry(author).or_insert(*sig);
                    let stake = self.dac_stake.entry(*ack_ref).or_default();
                    if stake.add(author, &self.committee) {
                        let agg = self.aggregate_dac(ack_ref);
                        self.dac_certs.insert(*ack_ref, agg);
                        events.push(CertificateEvent::Dac(*ack_ref, agg));
                    }
                }
            }
        }

        events
    }

    /// Check if round certificate is available.
    pub fn round_certificate(&self, round: RoundNumber) -> Option<&BlsSignatureBytes> {
        self.round_certs.get(&round)
    }

    /// Check if leader certificate is available.
    pub fn leader_certificate(&self, leader_ref: &BlockReference) -> Option<&BlsSignatureBytes> {
        self.leader_certs.get(leader_ref)
    }

    /// Get completed DAC certificate for a specific block.
    pub fn dac_certificate(&self, block_ref: &BlockReference) -> Option<&BlsSignatureBytes> {
        self.dac_certs.get(block_ref)
    }

    /// Get completed DAC certificates ready to include in next block.
    pub fn pending_dac_certificates(&self) -> Vec<(BlockReference, BlsSignatureBytes)> {
        self.dac_certs.iter().map(|(r, s)| (*r, *s)).collect()
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
        types::VerifiedBlock,
    };

    fn make_block(
        authority: AuthorityIndex,
        round: RoundNumber,
        block_refs: Vec<BlockReference>,
        ack_refs: Vec<BlockReference>,
        signer: &Signer,
        bls_signer: &BlsSigner,
        committee: &Committee,
    ) -> Data<VerifiedBlock> {
        let block = VerifiedBlock::new_with_signer(
            authority,
            round,
            block_refs,
            ack_refs,
            0,
            false,
            signer,
            Some(bls_signer),
            Some(committee),
            &[],
            vec![],
            Some(vec![vec![]; committee.len()]),
            ConsensusProtocol::StarfishL,
            None,
        );
        Data::new(block)
    }

    #[test]
    fn round_certificate_quorum() {
        let signers = Signer::new_for_test(4);
        let bls_signers = BlsSigner::new_for_test(4);
        let committee = Committee::new_test(vec![1, 1, 1, 1]);
        let mut aggregator = BlsCertificateAggregator::new(committee.clone());

        let genesis_refs: Vec<_> = (0..4)
            .map(|a| *VerifiedBlock::new_genesis(a).reference())
            .collect();

        // Add 2 blocks at round 1 — not yet quorum
        for i in 0..2u64 {
            let block = make_block(
                i,
                1,
                genesis_refs.clone(),
                vec![],
                &signers[i as usize],
                &bls_signers[i as usize],
                &committee,
            );
            aggregator.add_block(&block, |_| Default::default());
        }
        assert!(aggregator.round_certificate(1).is_none());

        // Add 3rd block — reaches quorum
        let block = make_block(
            2,
            1,
            genesis_refs.clone(),
            vec![],
            &signers[2],
            &bls_signers[2],
            &committee,
        );
        let events = aggregator.add_block(&block, |_| Default::default());
        assert!(aggregator.round_certificate(1).is_some());
        assert!(
            events
                .iter()
                .any(|e| matches!(e, CertificateEvent::Round(1, _)))
        );
    }

    #[test]
    fn cleanup_removes_old_state() {
        let committee = Committee::new_test(vec![1, 1, 1, 1]);
        let mut aggregator = BlsCertificateAggregator::new(committee);
        // Insert some dummy data
        aggregator.round_partial_sigs.insert(5, AHashMap::new());
        aggregator.round_partial_sigs.insert(10, AHashMap::new());

        aggregator.cleanup_below_round(8);
        assert!(!aggregator.round_partial_sigs.contains_key(&5));
        assert!(aggregator.round_partial_sigs.contains_key(&10));
    }
}
