// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub type AuthorityIndex = u16;

pub const MAX_COMMITTEE_SIZE: AuthorityIndex = 512;
const MAX_COMMITTEE_WORDS: usize = (MAX_COMMITTEE_SIZE as usize).div_ceil(64);

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct Transaction {
    data: Vec<u8>,
}

pub type RoundNumber = u32;

pub type ShardIndex = usize;
pub type BlockDigest = crate::crypto::BlockDigest;
pub type Stake = u64;
pub type KeyPair = u64;
pub type PublicKey = crate::crypto::PublicKey;
pub type Shard = Vec<u8>;
pub type Encoder = ReedSolomonEncoder;
pub type Decoder = ReedSolomonDecoder;

use std::{
    fmt,
    hash::{Hash, Hasher},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not},
    sync::atomic::Ordering,
    time::Duration,
};

use ahash::AHashSet;
use bytes::Bytes;
use eyre::{bail, ensure};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use serde::{Deserialize, Serialize};

use crate::{
    committee::Committee,
    crypto,
    crypto::{
        AsBytes, BlsSignatureBytes, BlsSigner, CryptoHash, SignatureBytes, Signer,
        TransactionsCommitment,
    },
    dag_state::ConsensusProtocol,
    data::{Data, IN_MEMORY_BLOCKS, IN_MEMORY_BLOCKS_BYTES},
    encoder::ShardEncoder,
    threshold_clock::threshold_clock_valid_block_header,
};

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct BlockReference {
    pub round: RoundNumber,
    pub authority: AuthorityIndex,
    pub digest: BlockDigest,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum BaseTransaction {
    /// Authority Shares a transactions, without accepting it or not.
    Share(Transaction),
}

impl Hash for BlockReference {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.authority.hash(state);
        self.round.hash(state);
        state.write(&self.digest.as_ref()[..8]);
    }
}

impl Ord for BlockReference {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.round
            .cmp(&other.round)
            .then_with(|| self.authority.cmp(&other.authority))
            .then_with(|| self.digest.cmp(&other.digest))
    }
}

impl PartialOrd for BlockReference {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ---------------------------------------------------------------------------
// BlockHeader — signed, content-addressed block identity.
// Contains exactly the fields that feed into BlockDigest::new() and
// sign_block().
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Protocol-specific field groups.
// ---------------------------------------------------------------------------

/// Acknowledgment compression fields (Starfish, StarfishSpeed, StarfishBls).
///
/// Acknowledgments are a compressed representation: a suffix of
/// `block_references` is shared with the acknowledgment list (`intersection`),
/// and any remaining acknowledged references are stored in `extra_references`.
#[derive(Clone, Serialize, Deserialize)]
pub struct AckFields {
    /// Index into `block_references` where the shared acknowledgment suffix
    /// starts. `None` for legacy blocks where `extra_references` stores the
    /// full logical acknowledgment list.
    pub(crate) intersection: Option<u8>,
    /// Acknowledged references not covered by the trailing
    /// `block_references` suffix.
    pub(crate) extra_references: Vec<BlockReference>,
}

/// BLS certificate data (StarfishBls only).
///
/// `certified_leader` pairs the leader ref with an aggregate certificate once
/// quorum is reached. `acknowledgment_signatures`
/// is parallel to the block's acknowledgment list.
#[derive(Clone, Copy, Default, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct BlsAggregateCertificate {
    pub(crate) signature: BlsSignatureBytes,
    pub(crate) signers: AuthoritySet,
}

impl BlsAggregateCertificate {
    pub fn new(signature: BlsSignatureBytes, signers: AuthoritySet) -> Self {
        Self { signature, signers }
    }

    pub fn signature(&self) -> &BlsSignatureBytes {
        &self.signature
    }

    pub fn signers(&self) -> AuthoritySet {
        self.signers
    }

    pub fn is_empty(&self) -> bool {
        self.signature == BlsSignatureBytes::default() || self.signers.is_empty()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BlsFields {
    /// BLS partial signature on the round message, included as
    /// belt-and-suspenders alongside standalone `PartialSig` messages.
    pub(crate) round_signature: BlsSignatureBytes,
    /// Voted leader reference paired with its BLS partial signature.
    /// `None` when the block does not vote for a leader.
    pub(crate) voted_leader: Option<(BlockReference, BlsSignatureBytes)>,
    /// Aggregate BLS round signature (populated by protocol layer).
    pub(crate) aggregate_round_signature: Option<BlsAggregateCertificate>,
    /// Certified leader: the leader block reference paired with its aggregate
    /// BLS certificate. `None` when no leader is certified by this block.
    pub(crate) certified_leader: Option<(BlockReference, BlsAggregateCertificate)>,
    /// BLS DAC signatures, parallel to the acknowledgment list.
    pub(crate) acknowledgment_signatures: Vec<BlsAggregateCertificate>,
}

/// Discriminator for the three kinds of BLS partial signatures exchanged
/// between validators (round pre-sign, leader pre-sign, DAC acknowledgment).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PartialSigKind {
    Round(RoundNumber),
    Leader(BlockReference),
    Dac(BlockReference),
}

/// A generic BLS partial signature with its kind, signer, and raw bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSig {
    pub kind: PartialSigKind,
    pub signer: AuthorityIndex,
    pub signature: BlsSignatureBytes,
}

// ---------------------------------------------------------------------------
// Signature-free RBC messages (SailfishPlusPlus).
// Authentication relies on the underlying authenticated TCP channels.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CertMessageKind {
    Echo,
    Vote,
    Ready,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertMessage {
    pub block_ref: BlockReference,
    pub sender: AuthorityIndex,
    pub kind: CertMessageKind,
}

// ---------------------------------------------------------------------------
// Sailfish++ control-plane messages (signed with Ed25519).
// Timeout certificates enable liveness when a leader is silent.
// No-vote certificates let honest leaders prove they didn't see the
// previous leader, enabling direct skip in the commit rule.
// ---------------------------------------------------------------------------

/// Signed timeout message: "I haven't seen a certified leader for round
/// `round`."
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SailfishTimeoutMsg {
    pub round: RoundNumber,
    pub sender: AuthorityIndex,
    pub signature: SignatureBytes,
}

/// Aggregated timeout certificate: ≥ 2f+1 signed timeout messages for a round.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SailfishTimeoutCert {
    pub round: RoundNumber,
    pub signatures: Vec<(AuthorityIndex, SignatureBytes)>,
}

/// Signed no-vote message: "I am advancing past round `round` without voting
/// for leader `leader`." Sent to the next-round leader so it can build a
/// no-vote certificate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SailfishNoVoteMsg {
    pub round: RoundNumber,
    pub leader: AuthorityIndex,
    pub sender: AuthorityIndex,
    pub signature: SignatureBytes,
}

/// Aggregated no-vote certificate: ≥ 2f+1 signed no-vote messages for a
/// (round, leader) slot. Embedded in the leader's block to prove it may skip
/// the previous leader.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SailfishNoVoteCert {
    pub round: RoundNumber,
    pub leader: AuthorityIndex,
    pub signatures: Vec<(AuthorityIndex, SignatureBytes)>,
}

/// Protocol-specific fields embedded in SailfishPlusPlus block headers.
/// Part of the signed block hash.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SailfishFields {
    /// Timeout certificate for the previous round, if this block advances
    /// without a path to the previous-round leader.
    pub timeout_cert: Option<SailfishTimeoutCert>,
    /// No-vote certificate for the previous round's leader slot, included
    /// only by the current round's elected leader when it lacks a path to
    /// the previous-round leader.
    pub no_vote_cert: Option<SailfishNoVoteCert>,
}

// ---------------------------------------------------------------------------
// BlockHeader — signed, content-addressed block identity.
// Contains exactly the fields that feed into BlockDigest::new() and
// sign_block().
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    // -- Base fields (all protocols) ------------------------------------------
    pub(crate) reference: BlockReference,
    /// Causal history — references to blocks this block includes.
    /// Order matters: the first reference for a given (round, authority) is the
    /// vote.
    pub(crate) block_references: Vec<BlockReference>,
    /// Creation time as reported by creator (currently not enforced).
    pub(crate) meta_creation_time_ns: TimestampNs,
    /// Signature by the block author over the header fields.
    pub(crate) signature: SignatureBytes,
    /// Explicit payload commitment stored in the header.
    /// Starfish-family protocols carry the Merkle root over encoded shards.
    /// Full-block protocols leave this as `None` and recompute the raw
    /// transaction hash directly from the payload while verifying.
    pub(crate) transactions_commitment: Option<TransactionsCommitment>,

    // -- Acknowledgment fields (Starfish variants) ----------------------------
    pub(crate) ack: Option<AckFields>,

    // -- Protocol-specific extensions -----------------------------------------
    /// StarfishSpeed strong-vote hint mask. `Some(empty)` means a strong vote;
    /// `Some(nonempty)` means the voter is missing payload from the authorities
    /// whose bits are set.
    pub(crate) strong_vote: Option<AuthoritySet>,
    /// BLS certificate fields (StarfishBls only). None for all other protocols.
    pub(crate) bls: Option<Box<BlsFields>>,
    /// Sailfish++ control certificates (timeout/no-vote). None for all other
    /// protocols.
    pub(crate) sailfish: Option<Box<SailfishFields>>,
    /// Bluestreak unprovable certificate: optional reference to a
    /// leader at round r-2 certified by 2f+1 votes at r-1.
    pub(crate) unprovable_certificate: Option<BlockReference>,

    // -- Cache (not serialized) -----------------------------------------------
    /// Cached bincode-serialized bytes. Populated by `preserialize()` off the
    /// core thread so that store writes are zero-serialization on the critical
    /// path.
    #[serde(skip, default)]
    pub(crate) serialized: Option<Bytes>,
}

impl BlockHeader {
    pub fn reference(&self) -> &BlockReference {
        &self.reference
    }

    pub fn block_references(&self) -> &Vec<BlockReference> {
        &self.block_references
    }

    pub fn acknowledgment_intersection(&self) -> Option<usize> {
        self.ack
            .as_ref()
            .and_then(|ack| ack.intersection.map(|start| start as usize))
    }

    pub fn extra_acknowledgment_references(&self) -> &[BlockReference] {
        self.ack
            .as_ref()
            .map_or(&[], |ack| ack.extra_references.as_slice())
    }

    pub fn acknowledgments(&self) -> Vec<BlockReference> {
        let Some(ack) = self.ack.as_ref() else {
            return Vec::new();
        };
        expand_acknowledgments(
            &self.block_references,
            ack.intersection,
            &ack.extra_references,
        )
    }

    pub fn acknowledgment_count(&self) -> usize {
        let Some(ack) = self.ack.as_ref() else {
            return 0;
        };
        count_acknowledgments(
            &self.block_references,
            ack.intersection,
            &ack.extra_references,
        )
    }

    pub fn authority(&self) -> AuthorityIndex {
        self.reference.authority
    }

    pub fn round(&self) -> RoundNumber {
        self.reference.round
    }

    pub fn digest(&self) -> BlockDigest {
        self.reference.digest
    }

    pub fn author_round(&self) -> (AuthorityIndex, RoundNumber) {
        self.reference.author_round()
    }

    pub fn signature(&self) -> &SignatureBytes {
        &self.signature
    }

    pub fn meta_creation_time_ns(&self) -> TimestampNs {
        self.meta_creation_time_ns
    }

    pub fn meta_creation_time(&self) -> Duration {
        let secs = self.meta_creation_time_ns / NANOS_IN_SEC;
        let nanos = self.meta_creation_time_ns % NANOS_IN_SEC;
        Duration::new(secs, nanos as u32)
    }

    /// Returns the stored header commitment. Panics if the field is `None`.
    pub fn merkle_root(&self) -> TransactionsCommitment {
        self.transactions_commitment
            .expect("transactions_commitment required for this protocol")
    }

    pub fn has_empty_payload(&self) -> bool {
        match self.transactions_commitment {
            None => false,
            Some(tc) => tc == TransactionsCommitment::default(),
        }
    }

    pub fn strong_vote(&self) -> Option<AuthoritySet> {
        self.strong_vote
    }

    pub fn is_strong_vote(&self) -> bool {
        self.strong_vote == Some(AuthoritySet::default())
    }

    pub fn is_strong_blame(&self) -> bool {
        self.strong_vote.is_some_and(|mask| !mask.is_empty())
    }

    pub fn bls(&self) -> Option<&BlsFields> {
        self.bls.as_deref()
    }

    pub fn bls_round_signature(&self) -> Option<&BlsSignatureBytes> {
        self.bls.as_ref().map(|b| &b.round_signature)
    }

    pub fn voted_leader(&self) -> Option<&(BlockReference, BlsSignatureBytes)> {
        self.bls.as_ref().and_then(|b| b.voted_leader.as_ref())
    }

    pub fn starfish_bls_voted_leader(&self, committee: &Committee) -> Option<&BlockReference> {
        let leader_round = self.round().checked_sub(1)?;
        if leader_round == 0 {
            return None;
        }
        let leader_authority = committee.elect_leader(leader_round);
        self.block_references.iter().find(|reference| {
            reference.round == leader_round && reference.authority == leader_authority
        })
    }

    pub fn bls_aggregate_round_signature(&self) -> Option<&BlsAggregateCertificate> {
        self.bls
            .as_ref()
            .and_then(|b| b.aggregate_round_signature.as_ref())
    }

    pub fn certified_leader(&self) -> Option<&(BlockReference, BlsAggregateCertificate)> {
        self.bls.as_ref().and_then(|b| b.certified_leader.as_ref())
    }

    pub fn acknowledgment_bls_signatures(&self) -> &[BlsAggregateCertificate] {
        self.bls
            .as_ref()
            .map(|b| b.acknowledgment_signatures.as_slice())
            .unwrap_or(&[])
    }

    pub fn unprovable_certificate(&self) -> Option<&BlockReference> {
        self.unprovable_certificate.as_ref()
    }

    pub fn sailfish(&self) -> Option<&SailfishFields> {
        self.sailfish.as_deref()
    }

    pub fn sailfish_timeout_cert(&self) -> Option<&SailfishTimeoutCert> {
        self.sailfish
            .as_ref()
            .and_then(|sf| sf.timeout_cert.as_ref())
    }

    pub fn sailfish_no_vote_cert(&self) -> Option<&SailfishNoVoteCert> {
        self.sailfish
            .as_ref()
            .and_then(|sf| sf.no_vote_cert.as_ref())
    }

    pub fn preserialize(&mut self) {
        if self.serialized.is_none() {
            self.serialized = Some(
                bincode::serialize(&self)
                    .expect("header serialization")
                    .into(),
            );
        }
    }

    pub fn serialized_bytes(&self) -> Option<&Bytes> {
        self.serialized.as_ref()
    }
}

fn expand_acknowledgments(
    block_references: &[BlockReference],
    acknowledgment_intersection: Option<u8>,
    acknowledgment_references: &[BlockReference],
) -> Vec<BlockReference> {
    let Some(start) = acknowledgment_intersection else {
        return acknowledgment_references.to_vec();
    };

    let start = usize::min(start as usize, block_references.len());
    let mut acknowledgments = block_references[start..].to_vec();
    acknowledgments.extend_from_slice(acknowledgment_references);
    acknowledgments
}

fn count_acknowledgments(
    block_references: &[BlockReference],
    acknowledgment_intersection: Option<u8>,
    acknowledgment_references: &[BlockReference],
) -> usize {
    let Some(start) = acknowledgment_intersection else {
        return acknowledgment_references.len();
    };

    let start = usize::min(start as usize, block_references.len());
    (block_references.len() - start) + acknowledgment_references.len()
}

fn compress_acknowledgments(
    block_references: &[BlockReference],
    acknowledgment_references: &[BlockReference],
) -> (Option<u8>, Vec<BlockReference>) {
    let acknowledged: AHashSet<_> = acknowledgment_references.iter().copied().collect();

    let mut intersection_start = block_references.len();
    while intersection_start > 0 && acknowledged.contains(&block_references[intersection_start - 1])
    {
        intersection_start -= 1;
    }

    let shared_suffix: AHashSet<_> = block_references[intersection_start..]
        .iter()
        .copied()
        .collect();
    let extra_acknowledgments = acknowledgment_references
        .iter()
        .copied()
        .filter(|reference| !shared_suffix.contains(reference))
        .collect();

    let Some(intersection_start) = u8::try_from(intersection_start).ok() else {
        // Large Starfish-BLS frontiers can exceed the compact suffix index.
        // Fall back to the legacy full-ack encoding instead of panicking.
        return (None, acknowledgment_references.to_vec());
    };

    (Some(intersection_start), extra_acknowledgments)
}

fn align_acknowledgment_certificates(
    acknowledgments: &[BlockReference],
    acknowledgment_references: &[BlockReference],
    certificates: Vec<BlsAggregateCertificate>,
) -> Vec<BlsAggregateCertificate> {
    if certificates.is_empty() {
        return certificates;
    }

    assert_eq!(
        acknowledgment_references.len(),
        certificates.len(),
        "acknowledgment references and DAC certificates must stay parallel",
    );

    let mut pairs: Vec<_> = acknowledgment_references
        .iter()
        .copied()
        .zip(certificates)
        .collect();
    acknowledgments
        .iter()
        .map(|ack_ref| {
            let position = pairs
                .iter()
                .position(|(reference, _)| reference == ack_ref)
                .expect("every acknowledgment should have a matching DAC certificate");
            pairs.remove(position).1
        })
        .collect()
}

// ---------------------------------------------------------------------------
// TransactionData — the actual committed payload.
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
pub struct TransactionData {
    pub(crate) transactions: Vec<BaseTransaction>,
    #[serde(skip, default)]
    pub(crate) serialized: Option<Bytes>,
}

impl TransactionData {
    pub fn new(transactions: Vec<BaseTransaction>) -> Self {
        Self {
            transactions,
            serialized: None,
        }
    }

    pub fn transactions(&self) -> &Vec<BaseTransaction> {
        &self.transactions
    }

    pub fn number_transactions(&self) -> usize {
        self.transactions.len()
    }

    pub fn preserialize(&mut self) {
        if self.serialized.is_none() {
            self.serialized = Some(
                bincode::serialize(&self)
                    .expect("tx_data serialization")
                    .into(),
            );
        }
    }

    pub fn serialized_bytes(&self) -> Option<&Bytes> {
        self.serialized.as_ref()
    }
}

// ---------------------------------------------------------------------------
// ReconstructedTransactionData — tx data recovered from erasure-coded shards.
// ---------------------------------------------------------------------------

/// Transaction data recovered from shard reconstruction. Sent to core via a
/// dedicated `add_transaction_data` path that bypasses the block manager
/// (the block header is already in the DAG).
///
/// Components carry their own pre-serialized bytes (populated by
/// `preserialize()` in shard_reconstructor worker threads).
pub struct ReconstructedTransactionData {
    pub block_reference: BlockReference,
    pub transaction_data: TransactionData,
    pub shard_data: ProvableShard,
}

// ---------------------------------------------------------------------------
// ProvableShard — one erasure-coded piece with its Merkle proof.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvableShard {
    pub(crate) shard: Shard,
    pub(crate) shard_index: ShardIndex,
    pub(crate) merkle_proof: Vec<u8>,
    pub(crate) transactions_commitment: TransactionsCommitment,
    #[serde(skip, default)]
    pub(crate) serialized: Option<Bytes>,
}

impl ProvableShard {
    pub fn new(
        shard: Shard,
        shard_index: ShardIndex,
        merkle_proof: Vec<u8>,
        transactions_commitment: TransactionsCommitment,
    ) -> Self {
        Self {
            shard,
            shard_index,
            merkle_proof,
            transactions_commitment,
            serialized: None,
        }
    }

    pub fn shard(&self) -> &Shard {
        &self.shard
    }

    pub fn shard_index(&self) -> ShardIndex {
        self.shard_index
    }

    pub fn merkle_proof(&self) -> &Vec<u8> {
        &self.merkle_proof
    }

    pub fn transactions_commitment(&self) -> TransactionsCommitment {
        self.transactions_commitment
    }

    pub fn preserialize(&mut self) {
        if self.serialized.is_none() {
            self.serialized = Some(
                bincode::serialize(&self)
                    .expect("shard_data serialization")
                    .into(),
            );
        }
    }

    pub fn serialized_bytes(&self) -> Option<&Bytes> {
        self.serialized.as_ref()
    }

    /// Verify the Merkle proof against the embedded transactions commitment.
    pub fn verify(&self, committee_size: usize) -> bool {
        if self.merkle_proof.is_empty() {
            return false;
        }
        TransactionsCommitment::check_correctness_merkle_leaf(
            self.shard.clone(),
            self.transactions_commitment,
            self.merkle_proof.clone(),
            committee_size,
            self.shard_index,
        )
    }
}

// ---------------------------------------------------------------------------
// VerifiedBlock — header + optional transaction payload.
// Shards are now stored and transported as separate sidecars.
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
pub struct VerifiedBlock {
    pub(crate) header: BlockHeader,
    pub(crate) transaction_data: Option<TransactionData>,
}

impl VerifiedBlock {
    pub fn new(
        authority: AuthorityIndex,
        round: RoundNumber,
        block_references: Vec<BlockReference>,
        acknowledgment_references: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        signature: SignatureBytes,
        transactions: Vec<BaseTransaction>,
        merkle_root: Option<TransactionsCommitment>,
        strong_vote: Option<AuthoritySet>,
        bls: Option<BlsFields>,
        sailfish: Option<SailfishFields>,
    ) -> Self {
        Self::new_with_unprovable(
            authority,
            round,
            block_references,
            acknowledgment_references,
            meta_creation_time_ns,
            signature,
            transactions,
            merkle_root,
            strong_vote,
            bls,
            sailfish,
            None,
        )
    }

    pub fn new_with_unprovable(
        authority: AuthorityIndex,
        round: RoundNumber,
        block_references: Vec<BlockReference>,
        acknowledgment_references: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        signature: SignatureBytes,
        transactions: Vec<BaseTransaction>,
        merkle_root: Option<TransactionsCommitment>,
        strong_vote: Option<AuthoritySet>,
        bls: Option<BlsFields>,
        sailfish: Option<SailfishFields>,
        unprovable_certificate: Option<BlockReference>,
    ) -> Self {
        let (acknowledgment_intersection, acknowledgment_references) =
            compress_acknowledgments(&block_references, &acknowledgment_references);
        let acknowledgments = expand_acknowledgments(
            &block_references,
            acknowledgment_intersection,
            &acknowledgment_references,
        );
        let header = BlockHeader {
            reference: BlockReference {
                authority,
                round,
                digest: BlockDigest::new_without_transactions_with_unprovable(
                    authority,
                    round,
                    &block_references,
                    &acknowledgments,
                    meta_creation_time_ns,
                    &signature,
                    merkle_root,
                    strong_vote,
                    unprovable_certificate.as_ref(),
                ),
            },
            block_references,
            meta_creation_time_ns,
            signature,
            transactions_commitment: merkle_root,
            ack: Some(AckFields {
                intersection: acknowledgment_intersection,
                extra_references: acknowledgment_references,
            }),
            strong_vote,
            bls: bls.map(Box::new),
            sailfish: sailfish.map(Box::new),
            unprovable_certificate,
            serialized: None,
        };

        let transaction_data = if transactions.is_empty() {
            None
        } else {
            Some(TransactionData::new(transactions))
        };
        Self {
            header,
            transaction_data,
        }
    }

    pub fn new_genesis(authority: AuthorityIndex) -> Data<Self> {
        let block_refs: Vec<BlockReference> = vec![];
        let ack_refs: Vec<BlockReference> = vec![];
        let header = BlockHeader {
            reference: BlockReference {
                authority,
                round: GENESIS_ROUND,
                digest: BlockDigest::new_without_transactions(
                    authority,
                    GENESIS_ROUND,
                    &block_refs,
                    &ack_refs,
                    0,
                    &SignatureBytes::default(),
                    None,
                    None,
                ),
            },
            block_references: block_refs,
            meta_creation_time_ns: 0,
            signature: SignatureBytes::default(),
            transactions_commitment: None,
            ack: None,
            strong_vote: None,
            bls: None,
            sailfish: None,
            unprovable_certificate: None,
            serialized: None,
        };
        let mut block = Self {
            header,
            transaction_data: None,
        };
        block.preserialize();
        Data::new(block)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_signer(
        authority: AuthorityIndex,
        round: RoundNumber,
        block_references: Vec<BlockReference>,
        voted_leader_ref: Option<BlockReference>,
        acknowledgment_references: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        signer: &Signer,
        bls_signer: Option<&BlsSigner>,
        committee_opt: Option<&Committee>,
        aggregate_dac_sigs: Vec<BlsAggregateCertificate>,
        transactions: Vec<BaseTransaction>,
        encoded_transactions: Option<Vec<Shard>>,
        consensus_protocol: ConsensusProtocol,
        strong_vote: Option<AuthoritySet>,
        aggregate_round_sig: Option<BlsAggregateCertificate>,
        certified_leader: Option<(BlockReference, BlsAggregateCertificate)>,
        precomputed_round_sig: Option<BlsSignatureBytes>,
        precomputed_leader_sig: Option<BlsSignatureBytes>,
        sailfish: Option<SailfishFields>,
    ) -> Self {
        Self::new_with_signer_and_unprovable(
            authority,
            round,
            block_references,
            voted_leader_ref,
            acknowledgment_references,
            meta_creation_time_ns,
            signer,
            bls_signer,
            committee_opt,
            aggregate_dac_sigs,
            transactions,
            encoded_transactions,
            consensus_protocol,
            strong_vote,
            aggregate_round_sig,
            certified_leader,
            precomputed_round_sig,
            precomputed_leader_sig,
            sailfish,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_signer_and_unprovable(
        authority: AuthorityIndex,
        round: RoundNumber,
        block_references: Vec<BlockReference>,
        voted_leader_ref: Option<BlockReference>,
        acknowledgment_references: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        signer: &Signer,
        bls_signer: Option<&BlsSigner>,
        committee_opt: Option<&Committee>,
        aggregate_dac_sigs: Vec<BlsAggregateCertificate>,
        transactions: Vec<BaseTransaction>,
        encoded_transactions: Option<Vec<Shard>>,
        consensus_protocol: ConsensusProtocol,
        strong_vote: Option<AuthoritySet>,
        aggregate_round_sig: Option<BlsAggregateCertificate>,
        certified_leader: Option<(BlockReference, BlsAggregateCertificate)>,
        precomputed_round_sig: Option<BlsSignatureBytes>,
        precomputed_leader_sig: Option<BlsSignatureBytes>,
        sailfish: Option<SailfishFields>,
        unprovable_certificate: Option<BlockReference>,
    ) -> Self {
        let supports_acknowledgments = consensus_protocol.supports_acknowledgments();
        let header_transactions_commitment = if consensus_protocol.supports_acknowledgments() {
            Some(if let Some(ref encoded) = encoded_transactions {
                TransactionsCommitment::new_from_encoded_transactions(encoded, authority as usize).0
            } else {
                TransactionsCommitment::default()
            })
        } else {
            None
        };
        let acknowledgment_references = if supports_acknowledgments {
            acknowledgment_references
        } else {
            Vec::new()
        };
        let aggregate_dac_sigs = if supports_acknowledgments {
            aggregate_dac_sigs
        } else {
            Vec::new()
        };
        let digest_transactions_commitment = header_transactions_commitment
            .or_else(|| Some(TransactionsCommitment::new_from_transactions(&transactions)));
        let (acknowledgment_intersection, extra_acknowledgment_references) =
            compress_acknowledgments(&block_references, &acknowledgment_references);
        let acknowledgments = expand_acknowledgments(
            &block_references,
            acknowledgment_intersection,
            &extra_acknowledgment_references,
        );
        let acknowledgment_signatures = align_acknowledgment_certificates(
            &acknowledgments,
            &acknowledgment_references,
            aggregate_dac_sigs,
        );
        let signature = signer.sign_block_with_unprovable(
            authority,
            round,
            &block_references,
            &acknowledgments,
            meta_creation_time_ns,
            digest_transactions_commitment,
            strong_vote,
            unprovable_certificate.as_ref(),
        );

        // Build BLS fields when the StarfishBls path is active. Partial round
        // and leader signatures are embedded as belt-and-suspenders alongside
        // standalone PartialSig messages.
        let bls = bls_signer.map(|bs| {
            let round_signature = precomputed_round_sig
                .unwrap_or_else(|| bs.sign_digest(&crypto::bls_round_message(round)));
            let voted_leader = (|| {
                let _committee = committee_opt?;
                let leader_round = round.checked_sub(1)?;
                if leader_round == 0 {
                    return None;
                }
                let leader_ref = voted_leader_ref?;
                let sig = precomputed_leader_sig
                    .unwrap_or_else(|| bs.sign_digest(&crypto::bls_leader_message(&leader_ref)));
                Some((leader_ref, sig))
            })();
            BlsFields {
                round_signature,
                voted_leader,
                aggregate_round_signature: aggregate_round_sig,
                certified_leader,
                acknowledgment_signatures,
            }
        });

        let transaction_data = if transactions.is_empty() {
            None
        } else {
            Some(TransactionData::new(transactions))
        };
        let header = BlockHeader {
            reference: BlockReference {
                authority,
                round,
                digest: BlockDigest::new_without_transactions_with_unprovable(
                    authority,
                    round,
                    &block_references,
                    &acknowledgments,
                    meta_creation_time_ns,
                    &signature,
                    digest_transactions_commitment,
                    strong_vote,
                    unprovable_certificate.as_ref(),
                ),
            },
            block_references,
            meta_creation_time_ns,
            signature,
            transactions_commitment: header_transactions_commitment,
            ack: supports_acknowledgments.then_some(AckFields {
                intersection: acknowledgment_intersection,
                extra_references: extra_acknowledgment_references,
            }),
            strong_vote,
            bls: bls.map(Box::new),
            sailfish: sailfish.map(Box::new),
            unprovable_certificate,
            serialized: None,
        };

        Self {
            header,
            transaction_data,
        }
    }

    // --- Header accessors (delegate) ---

    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn reference(&self) -> &BlockReference {
        self.header.reference()
    }

    pub fn block_references(&self) -> &Vec<BlockReference> {
        self.header.block_references()
    }

    pub fn acknowledgment_intersection(&self) -> Option<usize> {
        self.header.acknowledgment_intersection()
    }

    pub fn extra_acknowledgment_references(&self) -> &[BlockReference] {
        self.header.extra_acknowledgment_references()
    }

    pub fn acknowledgments(&self) -> Vec<BlockReference> {
        self.header.acknowledgments()
    }

    pub fn acknowledgment_count(&self) -> usize {
        self.header.acknowledgment_count()
    }

    pub fn authority(&self) -> AuthorityIndex {
        self.header.authority()
    }

    pub fn round(&self) -> RoundNumber {
        self.header.round()
    }

    pub fn digest(&self) -> BlockDigest {
        self.header.digest()
    }

    pub fn author_round(&self) -> (AuthorityIndex, RoundNumber) {
        self.header.author_round()
    }

    pub fn signature(&self) -> &SignatureBytes {
        self.header.signature()
    }

    pub fn meta_creation_time_ns(&self) -> TimestampNs {
        self.header.meta_creation_time_ns()
    }

    pub fn meta_creation_time(&self) -> Duration {
        self.header.meta_creation_time()
    }

    pub fn merkle_root(&self) -> TransactionsCommitment {
        self.header.merkle_root()
    }

    pub fn has_empty_payload(&self) -> bool {
        self.header.has_empty_payload()
    }

    pub fn strong_vote(&self) -> Option<AuthoritySet> {
        self.header.strong_vote()
    }

    pub fn is_strong_vote(&self) -> bool {
        self.header.is_strong_vote()
    }

    pub fn is_strong_blame(&self) -> bool {
        self.header.is_strong_blame()
    }

    pub fn unprovable_certificate(&self) -> Option<&BlockReference> {
        self.header.unprovable_certificate()
    }

    pub fn sailfish(&self) -> Option<&SailfishFields> {
        self.header.sailfish()
    }

    pub fn sailfish_timeout_cert(&self) -> Option<&SailfishTimeoutCert> {
        self.header.sailfish_timeout_cert()
    }

    pub fn sailfish_no_vote_cert(&self) -> Option<&SailfishNoVoteCert> {
        self.header.sailfish_no_vote_cert()
    }

    // --- Payload accessors ---

    pub fn transaction_data(&self) -> Option<&TransactionData> {
        self.transaction_data.as_ref()
    }

    /// Compatibility: returns transactions slice if transaction data is
    /// present.
    pub fn transactions(&self) -> Option<&Vec<BaseTransaction>> {
        self.transaction_data.as_ref().map(|td| &td.transactions)
    }

    pub fn number_transactions(&self) -> usize {
        self.transaction_data
            .as_ref()
            .map_or(0, |td| td.number_transactions())
    }

    pub fn has_transaction_data(&self) -> bool {
        self.transaction_data.is_some()
    }

    /// Create a lightweight copy with only the header (no transaction data).
    pub fn as_header_only(&self) -> Self {
        Self {
            header: self.header.clone(),
            transaction_data: None,
        }
    }

    // --- Decomposition ---

    /// Extract the header, consuming self.
    pub fn into_parts(self) -> (BlockHeader, Option<TransactionData>) {
        (self.header, self.transaction_data)
    }

    /// Assemble from header + optional transaction data.
    pub fn from_parts(header: BlockHeader, transaction_data: Option<TransactionData>) -> Self {
        Self {
            header,
            transaction_data,
        }
    }

    // --- Pre-serialization (call off the core thread) ---

    /// Eagerly serialize all components into cached `Bytes` for zero-copy
    /// store writes. Must be called before the block enters the core thread.
    pub fn preserialize(&mut self) {
        self.header.preserialize();
        if let Some(ref mut tx) = self.transaction_data {
            tx.preserialize();
        }
    }

    pub fn serialized_header_bytes(&self) -> Option<&Bytes> {
        self.header.serialized_bytes()
    }

    pub fn serialized_tx_data_bytes(&self) -> Option<&Bytes> {
        self.transaction_data
            .as_ref()
            .and_then(|t| t.serialized_bytes())
    }

    // --- Serialization ---

    pub fn from_bytes(bytes: Bytes) -> bincode::Result<Self> {
        IN_MEMORY_BLOCKS.fetch_add(1, Ordering::Relaxed);
        IN_MEMORY_BLOCKS_BYTES.fetch_add(bytes.len(), Ordering::Relaxed);
        let t = bincode::deserialize(&bytes)?;
        Ok(t)
    }

    // --- Verification ---

    /// Verify the block and return the derived shard sidecar (if any).
    pub fn verify(
        &mut self,
        committee: &Committee,
        own_id: usize,
        _peer_id: usize,
        encoder: &mut Encoder,
        consensus_protocol: ConsensusProtocol,
    ) -> eyre::Result<Option<ProvableShard>> {
        let (shard, digest_transactions_commitment) =
            self.verify_transactions(committee, own_id, encoder, consensus_protocol)?;
        self.verify_block_structure(
            committee,
            consensus_protocol,
            digest_transactions_commitment,
        )?;
        Ok(shard)
    }

    /// Verify transaction commitments and shard proofs (protocol-dependent).
    /// Returns the own-shard sidecar when a full Starfish-style block is
    /// verified.
    fn verify_transactions(
        &mut self,
        committee: &Committee,
        own_id: usize,
        encoder: &mut Encoder,
        consensus_protocol: ConsensusProtocol,
    ) -> eyre::Result<(Option<ProvableShard>, Option<TransactionsCommitment>)> {
        if consensus_protocol.supports_acknowledgments() {
            let Some(header_commitment) = self.header.transactions_commitment else {
                bail!("Starfish block missing transactions commitment")
            };
            let info_length = committee.info_length();
            let parity_length = committee.len() - info_length;
            if let Some(td) = self.transaction_data.as_ref() {
                if td.transactions.is_empty() && self.header.has_empty_payload() {
                    return Ok((None, Some(header_commitment)));
                }
                let encoded_transactions =
                    encoder.encode_transactions(&td.transactions, info_length, parity_length);
                let (transactions_commitment, merkle_proof_bytes) =
                    TransactionsCommitment::new_from_encoded_transactions(
                        &encoded_transactions,
                        own_id,
                    );
                ensure!(
                    transactions_commitment == header_commitment,
                    "Incorrect Merkle root"
                );
                return Ok((
                    Some(ProvableShard::new(
                        encoded_transactions[own_id].clone(),
                        own_id,
                        merkle_proof_bytes,
                        header_commitment,
                    )),
                    Some(header_commitment),
                ));
            }
            // Header-only blocks: shard sidecars are verified and carried
            // externally via `process_standalone_shards`.
            Ok((None, Some(header_commitment)))
        } else {
            ensure!(
                self.header.transactions_commitment.is_none(),
                "Full-block protocols must not carry transactions_commitment"
            );
            let empty_transactions = Vec::new();
            let transactions = self
                .transaction_data
                .as_ref()
                .map_or(&empty_transactions, |td| &td.transactions);
            Ok((
                None,
                Some(TransactionsCommitment::new_from_transactions(transactions)),
            ))
        }
    }

    /// Verify digest, signature, includes, and threshold clock.
    fn verify_block_structure(
        &self,
        committee: &Committee,
        consensus_protocol: ConsensusProtocol,
        digest_transactions_commitment: Option<TransactionsCommitment>,
    ) -> eyre::Result<()> {
        let round = self.round();
        if let Some(intersection_start) = self.header.acknowledgment_intersection() {
            ensure!(
                intersection_start <= self.header.block_references.len(),
                "Acknowledgment intersection {} exceeds block reference count {}",
                intersection_start,
                self.header.block_references.len(),
            );
        }
        let acknowledgments = self.header.acknowledgments();
        if !consensus_protocol.supports_acknowledgments() {
            ensure!(
                self.header.ack.is_none(),
                "{consensus_protocol:?} blocks must not carry AckFields"
            );
            ensure!(
                acknowledgments.is_empty(),
                "{consensus_protocol:?} blocks must not carry acknowledgments"
            );
        }
        let digest = BlockDigest::new_with_unprovable(
            self.authority(),
            round,
            &self.header.block_references,
            &acknowledgments,
            self.header.meta_creation_time_ns,
            &self.header.signature,
            digest_transactions_commitment,
            self.header.strong_vote,
            self.header.unprovable_certificate(),
        );
        ensure!(
            digest == self.digest(),
            "Digest does not match, calculated {:?}, provided {:?}",
            digest,
            self.digest()
        );
        let pub_key = committee.get_public_key(self.authority());
        let Some(pub_key) = pub_key else {
            bail!("Unknown block author {}", self.authority())
        };
        if round == GENESIS_ROUND {
            bail!("Genesis block should not go through verification");
        }
        if let Err(e) =
            pub_key.verify_signature_in_block(&self.header, digest_transactions_commitment)
        {
            bail!("Block signature verification has failed: {:?}", e);
        }
        for include in &self.header.block_references {
            ensure!(
                committee.known_authority(include.authority),
                "Include {:?} references unknown authority",
                include
            );
            ensure!(
                include.round < round,
                "Include {:?} round is greater or equal to own round {}",
                include,
                round
            );
        }
        match consensus_protocol {
            ConsensusProtocol::StarfishBls => {
                ensure!(
                    self.header.unprovable_certificate().is_none(),
                    "Only Bluestreak blocks may carry unprovable_certificate"
                );
                let bls = self
                    .header
                    .bls()
                    .ok_or_else(|| eyre::eyre!("StarfishBls block is missing BLS fields"))?;
                ensure!(
                    bls.round_signature != BlsSignatureBytes::default(),
                    "StarfishBls block is missing round BLS signature"
                );
                ensure!(
                    self.header.acknowledgment_bls_signatures().len() == acknowledgments.len(),
                    "StarfishBls acknowledgment count {} does not match DAC certificate count {}",
                    acknowledgments.len(),
                    self.header.acknowledgment_bls_signatures().len()
                );
                let is_round_leader = self.authority() == committee.elect_leader(round);
                if is_round_leader {
                    ensure!(
                        threshold_clock_valid_block_header(&self.header, committee),
                        "StarfishBls leader block must reference a quorum of previous-round blocks"
                    );
                } else {
                    ensure!(
                        self.header.block_references.len() <= 2,
                        "StarfishBls non-leader block may reference only \
                         the author's previous block and the \
                         previous-round leader"
                    );
                    let _self_ref = *self
                        .header
                        .block_references
                        .iter()
                        .find(|r| r.authority == self.authority())
                        .ok_or_else(|| {
                            eyre::eyre!(
                                "StarfishBls non-leader block must reference its own previous block"
                            )
                        })?;
                }
                if let Some((leader_ref, _sig)) = self.header.voted_leader() {
                    ensure!(
                        leader_ref.round + 1 == round,
                        "StarfishBls leader vote {:?} must target the previous round",
                        leader_ref
                    );
                    ensure!(
                        leader_ref.authority == committee.elect_leader(leader_ref.round),
                        "StarfishBls leader vote {:?} must target the scheduled leader",
                        leader_ref
                    );
                    ensure!(
                        self.header.block_references.contains(leader_ref),
                        "StarfishBls leader vote {:?} must also appear in block references",
                        leader_ref
                    );
                } else if !is_round_leader && round > 1 {
                    ensure!(
                        self.header
                            .block_references
                            .iter()
                            .all(|r| r.authority == self.authority()),
                        "StarfishBls non-leader block without a leader \
                         vote must not reference other parties"
                    );
                }
                for (ack_ref, cert) in acknowledgments
                    .iter()
                    .zip(self.header.acknowledgment_bls_signatures())
                {
                    ensure!(
                        ack_ref.authority == self.authority(),
                        "StarfishBls acknowledgment {:?} must target the block author's own data",
                        ack_ref
                    );
                    ensure!(
                        ack_ref.round < round,
                        "StarfishBls acknowledgment {:?} must be from a past round",
                        ack_ref
                    );
                    ensure!(
                        !cert.is_empty(),
                        "StarfishBls acknowledgment {:?} is missing DAC certificate",
                        ack_ref
                    );
                }
                if let Some(cert) = self.header.bls_aggregate_round_signature() {
                    ensure!(
                        !cert.is_empty(),
                        "StarfishBls aggregate round certificate must not be empty"
                    );
                }
                if let Some((leader_ref, cert)) = self.header.certified_leader() {
                    ensure!(
                        !cert.is_empty(),
                        "StarfishBls certified leader {:?} must not have an empty certificate",
                        leader_ref
                    );
                }
            }
            ConsensusProtocol::MysticetiBls => {
                ensure!(
                    acknowledgments.is_empty(),
                    "MysticetiBls blocks must not carry acknowledgments"
                );
                ensure!(
                    self.header.unprovable_certificate().is_none(),
                    "Only Bluestreak blocks may carry unprovable_certificate"
                );
                let bls = self
                    .header
                    .bls()
                    .ok_or_else(|| eyre::eyre!("MysticetiBls block is missing BLS fields"))?;
                ensure!(
                    bls.round_signature != BlsSignatureBytes::default(),
                    "MysticetiBls block is missing round BLS signature"
                );
                ensure!(
                    self.header.acknowledgment_bls_signatures().is_empty(),
                    "MysticetiBls blocks must not carry DAC certificates"
                );
                let is_round_leader = self.authority() == committee.elect_leader(round);
                if is_round_leader {
                    ensure!(
                        threshold_clock_valid_block_header(&self.header, committee),
                        "MysticetiBls leader block must reference a quorum of previous-round blocks"
                    );
                } else {
                    ensure!(
                        self.header.block_references.len() <= 2,
                        "MysticetiBls non-leader block may reference only \
                         the author's previous block and the \
                         previous-round leader"
                    );
                    let _self_ref = *self
                        .header
                        .block_references
                        .iter()
                        .find(|r| r.authority == self.authority())
                        .ok_or_else(|| {
                            eyre::eyre!(
                                "MysticetiBls non-leader block must \
                                 reference its own previous block"
                            )
                        })?;
                }
                if let Some((leader_ref, _sig)) = self.header.voted_leader() {
                    ensure!(
                        leader_ref.round + 1 == round,
                        "MysticetiBls leader vote {:?} must target the previous round",
                        leader_ref
                    );
                    ensure!(
                        leader_ref.authority == committee.elect_leader(leader_ref.round),
                        "MysticetiBls leader vote {:?} must target the scheduled leader",
                        leader_ref
                    );
                    ensure!(
                        self.header.block_references.contains(leader_ref),
                        "MysticetiBls leader vote {:?} must also appear in block references",
                        leader_ref
                    );
                } else if !is_round_leader && round > 1 {
                    ensure!(
                        self.header
                            .block_references
                            .iter()
                            .all(|r| r.authority == self.authority()),
                        "MysticetiBls non-leader block without a leader \
                         vote must not reference other parties"
                    );
                }
                if let Some(cert) = self.header.bls_aggregate_round_signature() {
                    ensure!(
                        !cert.is_empty(),
                        "MysticetiBls aggregate round certificate must not be empty"
                    );
                }
                if let Some((leader_ref, cert)) = self.header.certified_leader() {
                    ensure!(
                        !cert.is_empty(),
                        "MysticetiBls certified leader {:?} must not have an empty certificate",
                        leader_ref
                    );
                }
            }
            ConsensusProtocol::Starfish | ConsensusProtocol::StarfishSpeed => {
                ensure!(
                    threshold_clock_valid_block_header(&self.header, committee),
                    "Threshold clock is not valid"
                );
                ensure!(
                    self.header.bls().is_none(),
                    "Only StarfishBls blocks may carry BLS fields"
                );
                ensure!(
                    self.header.unprovable_certificate().is_none(),
                    "Only Bluestreak blocks may carry unprovable_certificate"
                );
            }
            ConsensusProtocol::Mysticeti | ConsensusProtocol::CordialMiners => {
                ensure!(
                    acknowledgments.is_empty(),
                    "{consensus_protocol:?} blocks must not carry acknowledgments"
                );
                ensure!(
                    threshold_clock_valid_block_header(&self.header, committee),
                    "Threshold clock is not valid"
                );
                ensure!(
                    self.header.bls().is_none(),
                    "Only StarfishBls blocks may carry BLS fields"
                );
                ensure!(
                    self.header.unprovable_certificate().is_none(),
                    "Only Bluestreak blocks may carry unprovable_certificate"
                );
            }
            ConsensusProtocol::Bluestreak => {
                ensure!(
                    acknowledgments.is_empty(),
                    "Bluestreak blocks must not carry acknowledgments"
                );
                ensure!(
                    self.header.bls().is_none(),
                    "Only StarfishBls blocks may carry BLS fields"
                );
                ensure!(
                    self.header.sailfish().is_none(),
                    "Only SailfishPlusPlus blocks may carry sailfish fields"
                );
                let is_leader = self.authority() == committee.elect_leader(round);
                if !is_leader {
                    ensure!(
                        self.header.block_references.len() <= 2,
                        "Bluestreak non-leader may reference at most own_prev + leader"
                    );
                    let _self_ref = *self
                        .header
                        .block_references
                        .iter()
                        .find(|r| r.authority == self.authority())
                        .ok_or_else(|| {
                            eyre::eyre!(
                                "Bluestreak non-leader block must reference its own previous block"
                            )
                        })?;
                } else {
                    ensure!(
                        threshold_clock_valid_block_header(&self.header, committee),
                        "Bluestreak leader must reference 2f+1 blocks from previous round"
                    );
                }
                if let Some(cert_ref) = self.header.unprovable_certificate() {
                    ensure!(
                        round >= 3 && cert_ref.round + 2 == round,
                        "unprovable_certificate must reference leader at round r-2"
                    );
                    ensure!(
                        cert_ref.authority == committee.elect_leader(cert_ref.round),
                        "unprovable_certificate must reference the elected leader"
                    );
                }
            }
            ConsensusProtocol::SailfishPlusPlus => {
                ensure!(
                    acknowledgments.is_empty(),
                    "SailfishPlusPlus blocks must not carry acknowledgments"
                );
                ensure!(
                    threshold_clock_valid_block_header(&self.header, committee),
                    "Threshold clock is not valid"
                );
                ensure!(
                    self.header.bls().is_none(),
                    "Only StarfishBls blocks may carry BLS fields"
                );
                ensure!(
                    self.header.unprovable_certificate().is_none(),
                    "Only Bluestreak blocks may carry unprovable_certificate"
                );
                if round > 1 {
                    let prev_round = round - 1;
                    let prev_leader = committee.elect_leader(prev_round);
                    let has_prev_leader_parent = self
                        .header
                        .block_references
                        .iter()
                        .any(|r| r.round == prev_round && r.authority == prev_leader);

                    if has_prev_leader_parent {
                        if let Some(sf) = self.header.sailfish() {
                            self.verify_sailfish_fields(sf, committee)?;
                        }
                    } else {
                        let sf = self.header.sailfish().ok_or_else(|| {
                            eyre::eyre!(
                                "SailfishPlusPlus block missing timeout cert \
                                 because previous-round leader \
                                 {prev_leader} is not referenced"
                            )
                        })?;
                        ensure!(
                            sf.timeout_cert.is_some(),
                            "SailfishPlusPlus block missing timeout cert \
                             because previous-round leader {} is not referenced",
                            prev_leader
                        );
                        if self.authority() == committee.elect_leader(round) {
                            ensure!(
                                sf.no_vote_cert.is_some(),
                                "SailfishPlusPlus leader block missing \
                                 no-vote cert because previous-round \
                                 leader {} is not referenced",
                                prev_leader
                            );
                        }
                        self.verify_sailfish_fields(sf, committee)?;
                    }
                } else if let Some(sf) = self.header.sailfish() {
                    self.verify_sailfish_fields(sf, committee)?;
                }
            }
        }
        Ok(())
    }

    /// Validate Sailfish++ timeout and no-vote certificates embedded in
    /// the block header.
    fn verify_sailfish_fields(
        &self,
        sf: &SailfishFields,
        committee: &Committee,
    ) -> eyre::Result<()> {
        let round = self.round();
        ensure!(round > 1, "SailfishFields not expected in round 0 or 1");
        let prev_round = round - 1;

        if let Some(tc) = &sf.timeout_cert {
            ensure!(
                tc.round == prev_round,
                "Timeout cert round {} does not match expected {}",
                tc.round,
                prev_round
            );
            let digest = crypto::sailfish_timeout_digest(tc.round);
            verify_signed_quorum(&tc.signatures, &digest, committee, "timeout")?;
        }

        if let Some(nvc) = &sf.no_vote_cert {
            ensure!(
                nvc.round == prev_round,
                "NoVote cert round {} does not match expected {}",
                nvc.round,
                prev_round
            );
            ensure!(
                nvc.leader == committee.elect_leader(prev_round),
                "NoVote cert leader {} does not match elected leader",
                nvc.leader
            );
            let digest = crypto::sailfish_novote_digest(nvc.round, nvc.leader);
            verify_signed_quorum(&nvc.signatures, &digest, committee, "novote")?;
        }

        Ok(())
    }
}

/// Verify that a vector of (authority, Ed25519 signature) pairs forms a valid
/// quorum over the given digest. Checks signer uniqueness, quorum stake, and
/// every signature.
fn verify_signed_quorum(
    signatures: &[(AuthorityIndex, SignatureBytes)],
    digest: &[u8; 32],
    committee: &Committee,
    label: &str,
) -> eyre::Result<()> {
    let mut seen = AuthoritySet::default();
    let mut stake: Stake = 0;
    for &(signer, ref sig) in signatures {
        ensure!(
            !seen.contains(signer),
            "Duplicate signer {} in {} cert",
            signer,
            label
        );
        seen.insert(signer);
        let pk = committee
            .get_public_key(signer)
            .ok_or_else(|| eyre::eyre!("Unknown signer {} in {} cert", signer, label))?;
        pk.verify_digest_signature(digest, sig)
            .map_err(|e| eyre::eyre!("Bad {} sig from {}: {}", label, signer, e))?;
        stake += committee.get_stake(signer).unwrap_or(0);
    }
    ensure!(
        stake >= committee.quorum_threshold(),
        "{} cert stake {} < quorum {}",
        label,
        stake,
        committee.quorum_threshold()
    );
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Default, Debug)]
pub struct AuthoritySet([u64; MAX_COMMITTEE_WORDS]);

pub type TimestampNs = u64;
const NANOS_IN_SEC: u64 = 1_000_000_000;

const GENESIS_ROUND: RoundNumber = 0;

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub struct TransactionLocator {
    block: BlockReference,
    offset: u64,
}

impl BlockReference {
    #[cfg(test)]
    pub fn new_test(authority: AuthorityIndex, round: RoundNumber) -> Self {
        if round == 0 {
            VerifiedBlock::new_genesis(authority).header.reference
        } else {
            Self {
                authority,
                round,
                digest: Default::default(),
            }
        }
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn author_round(&self) -> (AuthorityIndex, RoundNumber) {
        (self.authority, self.round)
    }

    pub fn author_digest(&self) -> (AuthorityIndex, BlockDigest) {
        (self.authority, self.digest)
    }
}

impl fmt::Debug for BlockReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for BlockReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.authority < 26 {
            write!(
                f,
                "{}{}{}",
                format_authority_index(self.authority),
                self.round,
                self.digest
            )
        } else {
            write!(f, "[{:02}]{}", self.authority, self.round)
        }
    }
}

impl AuthoritySet {
    /// Decompose an authority index into (word index, bit within word).
    #[inline]
    fn pos(v: AuthorityIndex) -> (usize, u32) {
        assert!(
            v < MAX_COMMITTEE_SIZE,
            "Authority index {} exceeds MAX_COMMITTEE_SIZE ({})",
            v,
            MAX_COMMITTEE_SIZE
        );
        ((v as usize) / 64, (v % 64) as u32)
    }

    /// Create a set containing a single authority.
    #[inline]
    pub fn singleton(v: AuthorityIndex) -> Self {
        let (word, bit) = Self::pos(v);
        let mut words = [0u64; MAX_COMMITTEE_WORDS];
        words[word] = 1u64 << bit;
        Self(words)
    }

    /// Create a set containing all authorities `0..committee_size`.
    pub fn full(committee_size: AuthorityIndex) -> Self {
        assert!(
            committee_size <= MAX_COMMITTEE_SIZE,
            "Committee size {} exceeds MAX_COMMITTEE_SIZE ({})",
            committee_size,
            MAX_COMMITTEE_SIZE
        );
        let mut words = [0u64; MAX_COMMITTEE_WORDS];
        let full_words = committee_size as usize / 64;
        let remaining_bits = committee_size % 64;
        for w in words.iter_mut().take(full_words) {
            *w = u64::MAX;
        }
        if remaining_bits > 0 {
            words[full_words] = (1u64 << remaining_bits) - 1;
        }
        Self(words)
    }

    /// Insert an authority. Returns `true` if it was not already present.
    #[inline]
    pub fn insert(&mut self, v: AuthorityIndex) -> bool {
        let (word, bit) = Self::pos(v);
        let mask = 1u64 << bit;
        if self.0[word] & mask != 0 {
            return false;
        }
        self.0[word] |= mask;
        true
    }

    /// Remove an authority. Returns `true` if it was present.
    #[inline]
    pub fn remove(&mut self, v: AuthorityIndex) -> bool {
        let (word, bit) = Self::pos(v);
        let mask = 1u64 << bit;
        if self.0[word] & mask == 0 {
            return false;
        }
        self.0[word] &= !mask;
        true
    }

    /// Iterate over all present authorities using O(popcount) bit-scanning.
    pub fn present(&self) -> AuthoritySetIter {
        AuthoritySetIter {
            words: self.0,
            word_index: 0,
        }
    }

    #[inline]
    pub fn contains(&self, v: AuthorityIndex) -> bool {
        let (word, bit) = Self::pos(v);
        self.0[word] & (1u64 << bit) != 0
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&w| w == 0)
    }

    #[inline]
    pub fn clear(&mut self) {
        self.0 = [0u64; MAX_COMMITTEE_WORDS];
    }

    /// Number of authorities in the set.
    #[inline]
    pub fn count_ones(&self) -> u32 {
        self.0.iter().map(|w| w.count_ones()).sum()
    }

    /// Access the raw words.
    #[inline]
    pub fn words(&self) -> &[u64; MAX_COMMITTEE_WORDS] {
        &self.0
    }
}

/// O(popcount) iterator over set bits in an `AuthoritySet`.
pub struct AuthoritySetIter {
    words: [u64; MAX_COMMITTEE_WORDS],
    word_index: usize,
}

impl Iterator for AuthoritySetIter {
    type Item = AuthorityIndex;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.word_index < MAX_COMMITTEE_WORDS {
            let w = self.words[self.word_index];
            if w != 0 {
                let bit = w.trailing_zeros() as AuthorityIndex;
                // Clear the lowest set bit.
                self.words[self.word_index] = w & (w - 1);
                return Some(bit + (self.word_index as AuthorityIndex) * 64);
            }
            self.word_index += 1;
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining: u32 = self.words[self.word_index..]
            .iter()
            .map(|w| w.count_ones())
            .sum();
        (remaining as usize, Some(remaining as usize))
    }
}

impl BitOr for AuthoritySet {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        let mut words = self.0;
        for (w, r) in words.iter_mut().zip(rhs.0.iter()) {
            *w |= r;
        }
        Self(words)
    }
}

impl BitOrAssign for AuthoritySet {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        for (w, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *w |= r;
        }
    }
}

impl BitAnd for AuthoritySet {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        let mut words = self.0;
        for (w, r) in words.iter_mut().zip(rhs.0.iter()) {
            *w &= r;
        }
        Self(words)
    }
}

impl BitAndAssign for AuthoritySet {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        for (w, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *w &= r;
        }
    }
}

impl Not for AuthoritySet {
    type Output = Self;
    #[inline]
    fn not(self) -> Self {
        let mut words = self.0;
        for w in words.iter_mut() {
            *w = !*w;
        }
        Self(words)
    }
}

pub fn format_authority_index(i: AuthorityIndex) -> String {
    if i < 26 {
        ((b'A' + i as u8) as char).to_string()
    } else {
        format!("[{i}]")
    }
}

pub fn format_authority_round(i: AuthorityIndex, r: RoundNumber) -> String {
    format!("{}{}", format_authority_index(i), r)
}

impl fmt::Debug for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[", self.reference)?;
        for include in self.block_references() {
            write!(f, "{include},")?;
        }
        write!(f, "]")
    }
}

impl PartialEq for BlockHeader {
    fn eq(&self, other: &Self) -> bool {
        self.reference == other.reference
    }
}
impl Eq for BlockHeader {}

impl std::hash::Hash for BlockHeader {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.reference.hash(state);
    }
}

impl fmt::Debug for VerifiedBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for VerifiedBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[", self.header.reference)?;
        for include in self.block_references() {
            write!(f, "{include},")?;
        }
        write!(f, "](")?;
        if self.transaction_data.is_some() {
            write!(f, "ledger")?;
        } else {
            write!(f, "header")?;
        }
        write!(f, ")")
    }
}
impl PartialEq for VerifiedBlock {
    fn eq(&self, other: &Self) -> bool {
        self.header.reference == other.header.reference
    }
}
impl Eq for VerifiedBlock {}

impl std::hash::Hash for VerifiedBlock {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.header.reference.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_signer_cert(
        digest: [u8; 32],
        signer: AuthorityIndex,
        bls_signers: &[BlsSigner],
    ) -> BlsAggregateCertificate {
        let mut signers = AuthoritySet::default();
        assert!(signers.insert(signer));
        BlsAggregateCertificate::new(bls_signers[signer as usize].sign_digest(&digest), signers)
    }

    fn make_starfish_bls_block(
        authority: AuthorityIndex,
        round: RoundNumber,
        acknowledgments: Vec<BlockReference>,
        dac_certs: Vec<BlsAggregateCertificate>,
    ) -> (VerifiedBlock, std::sync::Arc<Committee>) {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let bls_signers = BlsSigner::new_for_test(committee.len());
        let info_length = committee.info_length();
        let parity_length = committee.len() - info_length;
        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let transactions = vec![];
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
        let block = VerifiedBlock::new_with_signer(
            authority,
            round,
            block_references,
            voted_leader_ref,
            acknowledgments,
            0,
            &signers[authority as usize],
            Some(&bls_signers[authority as usize]),
            Some(committee.as_ref()),
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
        );
        (block, committee)
    }

    fn make_cordial_miners_block(
        authority: AuthorityIndex,
        round: RoundNumber,
        acknowledgments: Vec<BlockReference>,
    ) -> (VerifiedBlock, std::sync::Arc<Committee>) {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        // Include references from a quorum of authorities at round-1 so that
        // threshold clock validation passes.
        let block_references: Vec<_> = (0..committee.quorum_threshold() as AuthorityIndex)
            .map(|a| BlockReference::new_test(a, round - 1))
            .collect();
        let block = VerifiedBlock::new_with_signer(
            authority,
            round,
            block_references,
            None,
            acknowledgments,
            0,
            &signers[authority as usize],
            None,
            None,
            vec![],
            vec![],
            None,
            ConsensusProtocol::CordialMiners,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        (block, committee)
    }

    fn make_sailfish_timeout_cert(
        round: RoundNumber,
        signers: &[Signer],
        committee: &Committee,
    ) -> SailfishTimeoutCert {
        let digest = crypto::sailfish_timeout_digest(round);
        let signatures = (0..committee.quorum_threshold() as AuthorityIndex)
            .map(|authority| (authority, signers[authority as usize].sign_digest(&digest)))
            .collect();
        SailfishTimeoutCert { round, signatures }
    }

    fn make_sailfish_no_vote_cert(
        round: RoundNumber,
        leader: AuthorityIndex,
        signers: &[Signer],
        committee: &Committee,
    ) -> SailfishNoVoteCert {
        let digest = crypto::sailfish_novote_digest(round, leader);
        let signatures = (0..committee.quorum_threshold() as AuthorityIndex)
            .map(|authority| (authority, signers[authority as usize].sign_digest(&digest)))
            .collect();
        SailfishNoVoteCert {
            round,
            leader,
            signatures,
        }
    }

    fn make_sailfish_block(
        authority: AuthorityIndex,
        round: RoundNumber,
        include_prev_leader: bool,
        sailfish: Option<SailfishFields>,
    ) -> (VerifiedBlock, std::sync::Arc<Committee>) {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let prev_round = round - 1;
        let prev_leader = committee.elect_leader(prev_round);
        let block_references = committee
            .authorities()
            .filter(|candidate| include_prev_leader || *candidate != prev_leader)
            .take(committee.quorum_threshold() as usize)
            .map(|candidate| BlockReference::new_test(candidate, prev_round))
            .collect();
        let block = VerifiedBlock::new_with_signer(
            authority,
            round,
            block_references,
            None,
            vec![],
            0,
            &signers[authority as usize],
            None,
            None,
            vec![],
            vec![],
            None,
            ConsensusProtocol::SailfishPlusPlus,
            None,
            None,
            None,
            None,
            None,
            sailfish,
        );
        (block, committee)
    }

    #[test]
    fn compresses_acknowledgments_against_shared_suffix() {
        let a = BlockReference::new_test(0, 1);
        let b = BlockReference::new_test(1, 1);
        let c = BlockReference::new_test(2, 1);
        let d = BlockReference::new_test(3, 1);
        let block = VerifiedBlock::new(
            0,
            2,
            vec![a, b, c],
            vec![d, c],
            0,
            SignatureBytes::default(),
            vec![],
            None,
            None,
            None,
            None,
        );

        assert_eq!(block.acknowledgment_intersection(), Some(2));
        assert_eq!(block.extra_acknowledgment_references(), &vec![d]);
        assert_eq!(block.acknowledgment_count(), 2);
        assert_eq!(block.acknowledgments(), vec![c, d]);
    }

    #[test]
    fn falls_back_to_legacy_ack_encoding_when_suffix_index_exceeds_u8() {
        let block_references: Vec<_> = (0..300)
            .map(|round| BlockReference::new_test(0, round))
            .collect();
        let acknowledgment_references = block_references[290..].to_vec();

        let (intersection, extra_acknowledgments) =
            compress_acknowledgments(&block_references, &acknowledgment_references);

        assert_eq!(intersection, None);
        assert_eq!(extra_acknowledgments, acknowledgment_references);
    }

    #[test]
    fn preserves_legacy_acknowledgment_encoding() {
        let a = BlockReference::new_test(0, 1);
        let b = BlockReference::new_test(1, 1);
        let header = BlockHeader {
            reference: BlockReference::new_test(0, 2),
            block_references: vec![a],
            meta_creation_time_ns: 0,
            signature: SignatureBytes::default(),
            transactions_commitment: None,
            ack: Some(AckFields {
                intersection: None,
                extra_references: vec![b],
            }),
            strong_vote: None,
            bls: None,
            sailfish: None,
            unprovable_certificate: None,
            serialized: None,
        };

        assert_eq!(header.acknowledgment_count(), 1);
        assert_eq!(header.acknowledgments(), vec![b]);
    }

    #[test]
    fn aligns_starfish_bls_ack_certificates_with_compressed_ack_order() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let bls_signers = BlsSigner::new_for_test(committee.len());
        let info_length = committee.info_length();
        let parity_length = committee.len() - info_length;
        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let transactions = vec![];
        let encoded_transactions =
            encoder.encode_transactions(&transactions, info_length, parity_length);

        let a = BlockReference::new_test(0, 1);
        let b = BlockReference::new_test(1, 1);
        let c = BlockReference::new_test(2, 1);
        let d = BlockReference::new_test(3, 1);
        let cert_d = single_signer_cert(crypto::bls_dac_message(&d), 3, &bls_signers);
        let cert_c = single_signer_cert(crypto::bls_dac_message(&c), 2, &bls_signers);

        let block = VerifiedBlock::new_with_signer(
            0,
            2,
            vec![a, b, c],
            None,
            vec![d, c],
            0,
            &signers[0],
            Some(&bls_signers[0]),
            Some(committee.as_ref()),
            vec![cert_d, cert_c],
            transactions,
            Some(encoded_transactions),
            ConsensusProtocol::StarfishBls,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert_eq!(block.acknowledgments(), vec![c, d]);
        assert_eq!(
            block.header().acknowledgment_bls_signatures(),
            &[cert_c, cert_d]
        );
    }

    #[test]
    fn verifies_starfish_bls_ack_count_matches_dac_certificates() {
        let ack_ref = BlockReference::new_test(0, 1);
        let bls_signers = BlsSigner::new_for_test(4);
        let dac_cert = single_signer_cert(crypto::bls_dac_message(&ack_ref), 0, &bls_signers);
        let (mut block, committee) = make_starfish_bls_block(0, 2, vec![ack_ref], vec![dac_cert]);
        block
            .header
            .bls
            .as_mut()
            .expect("StarfishBls block should carry BLS fields")
            .acknowledgment_signatures
            .clear();

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let err = block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::StarfishBls,
            )
            .unwrap_err();

        assert!(
            err.to_string().contains(
                "StarfishBls acknowledgment count 1 does not match DAC certificate count 0"
            )
        );
    }

    #[test]
    fn verifies_starfish_bls_acks_target_only_own_past_blocks() {
        let invalid_ack_ref = BlockReference::new_test(1, 1);
        let bls_signers = BlsSigner::new_for_test(4);
        let dac_cert =
            single_signer_cert(crypto::bls_dac_message(&invalid_ack_ref), 1, &bls_signers);
        let (mut block, committee) =
            make_starfish_bls_block(0, 2, vec![invalid_ack_ref], vec![dac_cert]);

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let err = block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::StarfishBls,
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("must target the block author's own data")
        );

        let own_current_round_ack = BlockReference::new_test(0, 2);
        let own_current_round_cert = single_signer_cert(
            crypto::bls_dac_message(&own_current_round_ack),
            0,
            &bls_signers,
        );
        let (mut block, committee) = make_starfish_bls_block(
            0,
            2,
            vec![own_current_round_ack],
            vec![own_current_round_cert],
        );
        let err = block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::StarfishBls,
            )
            .unwrap_err();
        assert!(err.to_string().contains("must be from a past round"));
    }

    #[test]
    fn verifies_starfish_bls_non_leader_references_only_self_chain() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let bls_signers = BlsSigner::new_for_test(committee.len());
        let info_length = committee.info_length();
        let parity_length = committee.len() - info_length;
        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let transactions = vec![];
        let encoded_transactions =
            encoder.encode_transactions(&transactions, info_length, parity_length);
        let block = VerifiedBlock::new_with_signer(
            0,
            2,
            vec![
                BlockReference::new_test(0, 1),
                BlockReference::new_test(1, 1),
                BlockReference::new_test(2, 1),
            ],
            Some(BlockReference::new_test(1, 1)),
            vec![],
            0,
            &signers[0],
            Some(&bls_signers[0]),
            Some(committee.as_ref()),
            vec![],
            transactions,
            Some(encoded_transactions),
            ConsensusProtocol::StarfishBls,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let mut block = block;
        let err = block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::StarfishBls,
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("StarfishBls non-leader block may reference only",)
        );
    }

    #[test]
    fn rejects_cordial_miners_acknowledgments() {
        let ack_ref = BlockReference::new_test(1, 1);
        let committee = Committee::new_for_benchmarks(4);
        let block_references: Vec<_> = (0..committee.quorum_threshold() as AuthorityIndex)
            .map(|a| BlockReference::new_test(a, 1))
            .collect();
        let mut block = VerifiedBlock::new(
            0,
            2,
            block_references,
            vec![ack_ref],
            0,
            SignatureBytes::default(),
            vec![],
            None,
            None,
            None,
            None,
        );

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let err = block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::CordialMiners,
            )
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("CordialMiners blocks must not carry AckFields")
        );
    }

    #[test]
    fn bluestreak_blocks_omit_ack_fields() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let authority = committee
            .authorities()
            .find(|authority| *authority != committee.elect_leader(1))
            .unwrap();
        let block = VerifiedBlock::new_with_signer(
            authority,
            2,
            vec![
                BlockReference::new_test(authority, 1),
                BlockReference::new_test(committee.elect_leader(1), 1),
            ],
            None,
            vec![],
            0,
            &signers[authority as usize],
            None,
            None,
            vec![],
            vec![],
            None,
            ConsensusProtocol::Bluestreak,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert!(block.header.ack.is_none());
        assert!(block.acknowledgments().is_empty());
    }

    #[test]
    fn verifies_bluestreak_non_leader_with_unprovable_certificate() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let authority = committee
            .authorities()
            .find(|authority| *authority != committee.elect_leader(3))
            .unwrap();
        let round_2_leader = committee.elect_leader(2);
        let round_1_leader = committee.elect_leader(1);
        let mut block = VerifiedBlock::new_with_signer_and_unprovable(
            authority,
            3,
            vec![
                BlockReference::new_test(authority, 2),
                BlockReference::new_test(round_2_leader, 2),
            ],
            None,
            vec![],
            0,
            &signers[authority as usize],
            None,
            None,
            vec![],
            vec![],
            None,
            ConsensusProtocol::Bluestreak,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(BlockReference::new_test(round_1_leader, 1)),
        );

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::Bluestreak,
            )
            .unwrap();
    }

    #[test]
    fn accepts_bluestreak_leader_with_unprovable_certificate() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let leader = committee.elect_leader(3);
        let round_1_leader = committee.elect_leader(1);
        let mut block = VerifiedBlock::new_with_signer_and_unprovable(
            leader,
            3,
            (0..committee.quorum_threshold() as AuthorityIndex)
                .map(|authority| BlockReference::new_test(authority, 2))
                .collect(),
            None,
            vec![],
            0,
            &signers[leader as usize],
            None,
            None,
            vec![],
            vec![],
            None,
            ConsensusProtocol::Bluestreak,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(BlockReference::new_test(round_1_leader, 1)),
        );

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::Bluestreak,
            )
            .unwrap();
    }

    #[test]
    fn verifies_empty_mysticeti_block_without_transaction_data() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let mut block = VerifiedBlock::new_with_signer(
            0,
            2,
            vec![
                BlockReference::new_test(0, 1),
                BlockReference::new_test(1, 1),
            ],
            None,
            vec![],
            0,
            &signers[0],
            None,
            None,
            vec![],
            vec![],
            None,
            ConsensusProtocol::Mysticeti,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::Mysticeti,
            )
            .unwrap();
    }

    #[test]
    fn verifies_empty_cordial_miners_block_without_transaction_data() {
        let (mut block, committee) = make_cordial_miners_block(0, 2, vec![]);

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::CordialMiners,
            )
            .unwrap();
    }

    #[test]
    fn rejects_bluestreak_payload_tampering_without_header_commitment() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let leader = committee.elect_leader(1);
        let authority = committee
            .authorities()
            .find(|authority| *authority != leader)
            .unwrap();
        let mut block = VerifiedBlock::new_with_signer(
            authority,
            2,
            vec![
                BlockReference::new_test(authority, 1),
                BlockReference::new_test(leader, 1),
            ],
            None,
            vec![],
            0,
            &signers[authority as usize],
            None,
            None,
            vec![],
            vec![BaseTransaction::Share(Transaction {
                data: vec![1, 2, 3, 4],
            })],
            None,
            ConsensusProtocol::Bluestreak,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::Bluestreak,
            )
            .unwrap();

        block
            .transaction_data
            .as_mut()
            .expect("block should carry payload")
            .transactions[0] = BaseTransaction::Share(Transaction {
            data: vec![9, 9, 9, 9],
        });

        let err = block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::Bluestreak,
            )
            .unwrap_err();

        assert!(err.to_string().contains("Digest does not match"));
    }

    #[test]
    fn rejects_sailfish_block_without_timeout_cert_when_previous_leader_is_missing() {
        let committee = Committee::new_for_benchmarks(4);
        let non_leader = committee
            .authorities()
            .find(|authority| *authority != committee.elect_leader(3))
            .unwrap();
        let (mut block, committee) = make_sailfish_block(non_leader, 3, false, None);

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let err = block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::SailfishPlusPlus,
            )
            .unwrap_err();

        assert!(err.to_string().contains("missing timeout cert"));
    }

    #[test]
    fn rejects_sailfish_leader_block_without_no_vote_cert_when_previous_leader_is_missing() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let leader = committee.elect_leader(3);
        let timeout_cert = make_sailfish_timeout_cert(2, &signers, committee.as_ref());
        let sailfish = SailfishFields {
            timeout_cert: Some(timeout_cert),
            no_vote_cert: None,
        };
        let (mut block, committee) = make_sailfish_block(leader, 3, false, Some(sailfish));

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let err = block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::SailfishPlusPlus,
            )
            .unwrap_err();

        assert!(err.to_string().contains("missing no-vote cert"));
    }

    #[test]
    fn verifies_sailfish_block_with_previous_leader_parent_and_no_control_fields() {
        let committee = Committee::new_for_benchmarks(4);
        let non_leader = committee
            .authorities()
            .find(|authority| *authority != committee.elect_leader(3))
            .unwrap();
        let (mut block, committee) = make_sailfish_block(non_leader, 3, true, None);

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::SailfishPlusPlus,
            )
            .unwrap();
    }

    #[test]
    fn verifies_sailfish_leader_with_timeout_no_vote_certs_when_prev_leader_missing() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let leader = committee.elect_leader(3);
        let prev_leader = committee.elect_leader(2);
        let sailfish = SailfishFields {
            timeout_cert: Some(make_sailfish_timeout_cert(2, &signers, committee.as_ref())),
            no_vote_cert: Some(make_sailfish_no_vote_cert(
                2,
                prev_leader,
                &signers,
                committee.as_ref(),
            )),
        };
        let (mut block, committee) = make_sailfish_block(leader, 3, false, Some(sailfish));

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::SailfishPlusPlus,
            )
            .unwrap();
    }

    #[test]
    fn verifies_starfish_bls_non_leader_may_reference_latest_own_block_from_earlier_round() {
        let committee = Committee::new_for_benchmarks(4);
        let signers = Signer::new_for_test(committee.len());
        let bls_signers = BlsSigner::new_for_test(committee.len());
        let info_length = committee.info_length();
        let parity_length = committee.len() - info_length;
        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let transactions = vec![];
        let encoded_transactions =
            encoder.encode_transactions(&transactions, info_length, parity_length);
        let mut block = VerifiedBlock::new_with_signer(
            0,
            5,
            vec![
                BlockReference::new_test(0, 3),
                BlockReference::new_test(0, 4),
            ],
            Some(BlockReference::new_test(0, 4)),
            vec![],
            0,
            &signers[0],
            Some(&bls_signers[0]),
            Some(committee.as_ref()),
            vec![],
            transactions,
            Some(encoded_transactions),
            ConsensusProtocol::StarfishBls,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::StarfishBls,
            )
            .expect("non-leader StarfishBls block should allow skipped own rounds");
    }
}

impl fmt::Debug for BaseTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl CryptoHash for BlockReference {
    fn crypto_hash(&self, state: &mut crypto::Blake3Hasher) {
        self.authority.crypto_hash(state);
        self.round.crypto_hash(state);
        self.digest.crypto_hash(state);
    }
}

impl CryptoHash for Shard {
    fn crypto_hash(&self, state: &mut crypto::Blake3Hasher) {
        state.update(self);
    }
}

impl CryptoHash for BaseTransaction {
    fn crypto_hash(&self, state: &mut crypto::Blake3Hasher) {
        match self {
            BaseTransaction::Share(tx) => {
                [0].crypto_hash(state);
                tx.crypto_hash(state);
            }
        }
    }
}

impl fmt::Display for BaseTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseTransaction::Share(_tx) => write!(f, "tx"),
        }
    }
}

impl Transaction {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl AsBytes for Transaction {
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn authority_set_test() {
        let mut a = AuthoritySet::default();
        assert!(a.insert(0));
        assert!(!a.insert(0));
        assert!(a.insert(1));
        assert!(a.insert(2));
        assert!(!a.insert(1));
        assert!(a.insert(127));
        assert!(!a.insert(127));
        assert!(a.insert(3));
        assert!(!a.insert(3));
        assert!(!a.insert(2));
    }

    #[test]
    fn authority_set_high_indices() {
        let mut a = AuthoritySet::default();
        assert!(a.insert(128));
        assert!(!a.insert(128));
        assert!(a.insert(200));
        assert!(a.insert(255));
        assert!(!a.insert(255));
        assert!(a.insert(500));
        assert!(a.insert(MAX_COMMITTEE_SIZE - 1));
        assert!(!a.insert(MAX_COMMITTEE_SIZE - 1));
        assert!(a.contains(128));
        assert!(a.contains(200));
        assert!(a.contains(255));
        assert!(a.contains(500));
        assert!(a.contains(MAX_COMMITTEE_SIZE - 1));
        assert!(!a.contains(0));
        assert!(!a.contains(127));
        assert_eq!(a.count_ones(), 5);
    }

    #[test]
    fn authority_present_test() {
        let mut a = AuthoritySet::default();
        let present = vec![1, 2, 3, 4, 5, 64, 127];
        for x in &present {
            a.insert(*x);
        }
        assert_eq!(present, a.present().collect::<Vec<_>>());
    }

    #[test]
    fn authority_present_spans_multiple_words() {
        let mut a = AuthoritySet::default();
        let present = vec![0, 63, 127, 128, 200, 255, 256, 500, MAX_COMMITTEE_SIZE - 1];
        for x in &present {
            a.insert(*x);
        }
        assert_eq!(present, a.present().collect::<Vec<_>>());
    }

    #[test]
    fn authority_set_singleton_and_ops() {
        let a = AuthoritySet::singleton(5);
        let b = AuthoritySet::singleton(500);
        let c = a | b;
        assert!(c.contains(5));
        assert!(c.contains(500));
        assert!(!c.contains(0));

        let d = c & a;
        assert!(d.contains(5));
        assert!(!d.contains(500));
    }

    #[test]
    fn authority_set_full() {
        let f = AuthoritySet::full(100);
        assert_eq!(f.count_ones(), 100);
        assert!(f.contains(0));
        assert!(f.contains(99));
        assert!(!f.contains(100));

        let f = AuthoritySet::full(MAX_COMMITTEE_SIZE);
        assert_eq!(f.count_ones(), MAX_COMMITTEE_SIZE as u32);
        assert!(f.contains(0));
        assert!(f.contains(MAX_COMMITTEE_SIZE - 1));

        let f = AuthoritySet::full(64);
        assert_eq!(f.count_ones(), 64);
        assert!(f.contains(63));
        assert!(!f.contains(64));

        let f = AuthoritySet::full(0);
        assert!(f.is_empty());
    }

    #[test]
    fn authority_set_not_as_mask() {
        // Not is safe when used as a mask with &= against a bounded set
        let full = AuthoritySet::full(100);
        let exclude = AuthoritySet::singleton(50);
        let result = full & !exclude;
        assert_eq!(result.count_ones(), 99);
        assert!(!result.contains(50));
        assert!(result.contains(49));
        assert!(result.contains(51));
    }

    #[test]
    fn authority_set_remove() {
        let mut a = AuthoritySet::default();
        a.insert(10);
        a.insert(500);
        assert!(a.remove(10));
        assert!(!a.remove(10));
        assert!(!a.contains(10));
        assert!(a.contains(500));
    }

    #[test]
    fn format_authority_index_handles_high_indices() {
        assert_eq!(format_authority_index(0), "A");
        assert_eq!(format_authority_index(25), "Z");
        assert_eq!(format_authority_index(26), "[26]");
        assert_eq!(format_authority_index(255), "[255]");
        assert_eq!(format_authority_index(1023), "[1023]");
    }
}
