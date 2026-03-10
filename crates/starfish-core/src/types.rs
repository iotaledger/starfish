// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub type AuthorityIndex = u64;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct Transaction {
    data: Vec<u8>,
}

pub type RoundNumber = u64;

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

/// Acknowledgment compression fields (Starfish, StarfishS, StarfishL,
/// StarfishPull).
///
/// Acknowledgments are a compressed representation: a suffix of
/// `block_references` is shared with the acknowledgment list (`intersection`),
/// and any remaining acknowledged references are stored in `extra_references`.
#[derive(Clone, Serialize, Deserialize)]
pub struct AckFields {
    /// Index into `block_references` where the shared acknowledgment suffix
    /// starts. `None` for legacy blocks where `extra_references` stores the
    /// full logical acknowledgment list.
    pub(crate) intersection: Option<u32>,
    /// Acknowledged references not covered by the trailing
    /// `block_references` suffix.
    pub(crate) extra_references: Vec<BlockReference>,
}

/// BLS certificate data (StarfishL only).
///
/// `round_signature` is always present — every StarfishL block signs the
/// canonical round message. `voted_leader` pairs the leader reference with the
/// partial BLS sig when the block includes the previous-round leader.
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
    /// BLS round signature over the canonical round message.
    pub(crate) round_signature: BlsSignatureBytes,
    /// Leader this block votes for, paired with the partial BLS leader sig.
    /// `None` when the block does not include the previous-round leader.
    pub(crate) voted_leader: Option<(BlockReference, BlsSignatureBytes)>,
    /// Aggregate BLS round signature (populated by protocol layer).
    pub(crate) aggregate_round_signature: Option<BlsAggregateCertificate>,
    /// Certified leader: the leader block reference paired with its aggregate
    /// BLS certificate. `None` when no leader is certified by this block.
    pub(crate) certified_leader: Option<(BlockReference, BlsAggregateCertificate)>,
    /// BLS DAC signatures, parallel to the acknowledgment list.
    pub(crate) acknowledgment_signatures: Vec<BlsAggregateCertificate>,
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
    /// Merkle root over encoded transactions (Starfish) or raw transactions
    /// (Mysticeti).
    pub(crate) transactions_commitment: TransactionsCommitment,

    // -- Acknowledgment fields (Starfish variants) ----------------------------
    pub(crate) ack: AckFields,

    // -- Protocol-specific extensions -----------------------------------------
    /// StarfishS strong-vote hint mask. `Some(0)` means a strong vote;
    /// `Some(nonzero)` means the voter is missing payload from the authorities
    /// whose bits are set.
    pub(crate) strong_vote: Option<u128>,
    /// BLS certificate fields (StarfishL only). None for all other protocols.
    pub(crate) bls: Option<Box<BlsFields>>,

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
        self.ack.intersection.map(|start| start as usize)
    }

    pub fn extra_acknowledgment_references(&self) -> &Vec<BlockReference> {
        &self.ack.extra_references
    }

    pub fn acknowledgments(&self) -> Vec<BlockReference> {
        expand_acknowledgments(
            &self.block_references,
            self.ack.intersection,
            &self.ack.extra_references,
        )
    }

    pub fn acknowledgment_count(&self) -> usize {
        count_acknowledgments(
            &self.block_references,
            self.ack.intersection,
            &self.ack.extra_references,
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
        Duration::new(secs as u64, nanos as u32)
    }

    pub fn merkle_root(&self) -> TransactionsCommitment {
        self.transactions_commitment
    }

    pub fn has_empty_payload(&self) -> bool {
        self.transactions_commitment == TransactionsCommitment::default()
    }

    pub fn strong_vote(&self) -> Option<u128> {
        self.strong_vote
    }

    pub fn is_strong_vote(&self) -> bool {
        self.strong_vote == Some(0)
    }

    pub fn is_strong_blame(&self) -> bool {
        self.strong_vote.is_some_and(|mask| mask != 0)
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
    acknowledgment_intersection: Option<u32>,
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
    acknowledgment_intersection: Option<u32>,
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
) -> (Option<u32>, Vec<BlockReference>) {
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

    (
        Some(
            u32::try_from(intersection_start)
                .expect("block reference intersection should fit into u32"),
        ),
        extra_acknowledgments,
    )
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
        merkle_root: TransactionsCommitment,
        strong_vote: Option<u128>,
        bls: Option<BlsFields>,
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
                digest: BlockDigest::new_without_transactions(
                    authority,
                    round,
                    &block_references,
                    &acknowledgments,
                    meta_creation_time_ns,
                    &signature,
                    merkle_root,
                    strong_vote,
                ),
            },
            block_references,
            meta_creation_time_ns,
            signature,
            transactions_commitment: merkle_root,
            ack: AckFields {
                intersection: acknowledgment_intersection,
                extra_references: acknowledgment_references,
            },
            strong_vote,
            bls: bls.map(Box::new),
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
                    TransactionsCommitment::default(),
                    None,
                ),
            },
            block_references: block_refs,
            meta_creation_time_ns: 0,
            signature: SignatureBytes::default(),
            transactions_commitment: TransactionsCommitment::default(),
            ack: AckFields {
                intersection: Some(0),
                extra_references: ack_refs,
            },
            strong_vote: None,
            bls: None,
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
    pub fn new_with_signer(
        authority: AuthorityIndex,
        round: RoundNumber,
        block_references: Vec<BlockReference>,
        voted_leader_ref: Option<BlockReference>,
        acknowledgment_references: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        signer: &Signer,
        bls_signer: Option<&BlsSigner>,
        committee: Option<&Committee>,
        aggregate_dac_sigs: Vec<BlsAggregateCertificate>,
        transactions: Vec<BaseTransaction>,
        encoded_transactions: Option<Vec<Shard>>,
        consensus_protocol: ConsensusProtocol,
        strong_vote: Option<u128>,
        aggregate_round_sig: Option<BlsAggregateCertificate>,
        certified_leader: Option<(BlockReference, BlsAggregateCertificate)>,
    ) -> Self {
        let transactions_commitment = match consensus_protocol {
            ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishPull
            | ConsensusProtocol::StarfishS
            | ConsensusProtocol::StarfishL => {
                if let Some(ref encoded) = encoded_transactions {
                    TransactionsCommitment::new_from_encoded_transactions(
                        encoded,
                        authority as usize,
                    )
                    .0
                } else {
                    TransactionsCommitment::default()
                }
            }
            ConsensusProtocol::Mysticeti | ConsensusProtocol::CordialMiners => {
                TransactionsCommitment::new_from_transactions(&transactions)
            }
        };
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
        let signature = signer.sign_block(
            authority,
            round,
            &block_references,
            &acknowledgments,
            meta_creation_time_ns,
            transactions_commitment,
            strong_vote,
        );

        // Build BLS fields if a BLS signer is provided (StarfishL).
        let bls = bls_signer.map(|bs| {
            // Round signature over the canonical round message.
            let round_signature = bs.sign_digest(&crypto::bls_round_message(round));

            // Leader vote: sign the previous-round leader when it is available.
            let voted_leader = (|| {
                let _committee = committee?;
                let leader_round = round.checked_sub(1)?;
                if leader_round == 0 {
                    return None;
                }
                let leader_ref = voted_leader_ref?;
                let msg = crypto::bls_leader_message(&leader_ref);
                Some((leader_ref, bs.sign_digest(&msg)))
            })();

            // Aggregated DAC certificates from the aggregator.
            BlsFields {
                round_signature,
                voted_leader,
                aggregate_round_signature: aggregate_round_sig,
                certified_leader,
                acknowledgment_signatures,
            }
        });

        Self::new(
            authority,
            round,
            block_references,
            acknowledgment_references,
            meta_creation_time_ns,
            signature,
            transactions,
            transactions_commitment,
            strong_vote,
            bls,
        )
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

    pub fn extra_acknowledgment_references(&self) -> &Vec<BlockReference> {
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

    pub fn strong_vote(&self) -> Option<u128> {
        self.header.strong_vote()
    }

    pub fn is_strong_vote(&self) -> bool {
        self.header.is_strong_vote()
    }

    pub fn is_strong_blame(&self) -> bool {
        self.header.is_strong_blame()
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
        let shard = self.verify_transactions(committee, own_id, encoder, consensus_protocol)?;
        self.verify_block_structure(committee, consensus_protocol)?;
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
    ) -> eyre::Result<Option<ProvableShard>> {
        match consensus_protocol {
            ConsensusProtocol::StarfishPull
            | ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishS
            | ConsensusProtocol::StarfishL => {
                let info_length = committee.info_length();
                let parity_length = committee.len() - info_length;
                if let Some(td) = self.transaction_data.as_ref() {
                    if td.transactions.is_empty() && self.header.has_empty_payload() {
                        return Ok(None);
                    }
                    let encoded_transactions =
                        encoder.encode_transactions(&td.transactions, info_length, parity_length);
                    let (transactions_commitment, merkle_proof_bytes) =
                        TransactionsCommitment::new_from_encoded_transactions(
                            &encoded_transactions,
                            own_id,
                        );
                    ensure!(
                        transactions_commitment == self.header.transactions_commitment,
                        "Incorrect Merkle root"
                    );
                    return Ok(Some(ProvableShard::new(
                        encoded_transactions[own_id].clone(),
                        own_id,
                        merkle_proof_bytes,
                        self.header.transactions_commitment,
                    )));
                }
                // Header-only blocks: shard sidecars are verified and carried
                // externally via `process_standalone_shards`.
            }
            ConsensusProtocol::Mysticeti | ConsensusProtocol::CordialMiners => {
                if let Some(td) = &self.transaction_data {
                    let transactions_commitment =
                        TransactionsCommitment::new_from_transactions(&td.transactions);
                    ensure!(
                        transactions_commitment == self.header.transactions_commitment,
                        "Incorrect Merkle root"
                    );
                } else {
                    bail!("The peer didn't include transactions in block");
                }
            }
        }
        Ok(None)
    }

    /// Verify digest, signature, includes, and threshold clock.
    fn verify_block_structure(
        &self,
        committee: &Committee,
        consensus_protocol: ConsensusProtocol,
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
        let digest = BlockDigest::new(
            self.authority(),
            round,
            &self.header.block_references,
            &acknowledgments,
            self.header.meta_creation_time_ns,
            &self.header.signature,
            self.header.transactions_commitment,
            self.header.strong_vote,
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
        if let Err(e) = pub_key.verify_signature_in_block(&self.header) {
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
            ConsensusProtocol::StarfishL => {
                let bls = self
                    .header
                    .bls()
                    .ok_or_else(|| eyre::eyre!("StarfishL block is missing BLS fields"))?;
                ensure!(
                    bls.round_signature != BlsSignatureBytes::default(),
                    "StarfishL block is missing round BLS signature"
                );
                ensure!(
                    self.header.acknowledgment_bls_signatures().len() == acknowledgments.len(),
                    "StarfishL acknowledgment count {} does not match DAC certificate count {}",
                    acknowledgments.len(),
                    self.header.acknowledgment_bls_signatures().len()
                );
                let is_round_leader = self.authority() == committee.elect_leader(round);
                if is_round_leader {
                    ensure!(
                        threshold_clock_valid_block_header(&self.header, committee),
                        "StarfishL leader block must reference a quorum of previous-round blocks"
                    );
                } else {
                    ensure!(
                        self.header.block_references.len() <= 2,
                        "StarfishL non-leader block may reference only \
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
                                "StarfishL non-leader block must reference its own previous block"
                            )
                        })?;
                }
                if let Some((leader_ref, _)) = self.header.voted_leader() {
                    ensure!(
                        leader_ref.round + 1 == round,
                        "StarfishL leader vote {:?} must target the previous round",
                        leader_ref
                    );
                    ensure!(
                        leader_ref.authority == committee.elect_leader(leader_ref.round),
                        "StarfishL leader vote {:?} must target the scheduled leader",
                        leader_ref
                    );
                    ensure!(
                        self.header.block_references.contains(leader_ref),
                        "StarfishL leader vote {:?} must also appear in block references",
                        leader_ref
                    );
                } else if !is_round_leader && round > 1 {
                    ensure!(
                        self.header
                            .block_references
                            .iter()
                            .all(|r| r.authority == self.authority()),
                        "StarfishL non-leader block without a leader \
                         vote must not reference other parties"
                    );
                }
                for (ack_ref, cert) in acknowledgments
                    .iter()
                    .zip(self.header.acknowledgment_bls_signatures())
                {
                    ensure!(
                        ack_ref.authority == self.authority(),
                        "StarfishL acknowledgment {:?} must target the block author's own data",
                        ack_ref
                    );
                    ensure!(
                        ack_ref.round < round,
                        "StarfishL acknowledgment {:?} must be from a past round",
                        ack_ref
                    );
                    ensure!(
                        !cert.is_empty(),
                        "StarfishL acknowledgment {:?} is missing DAC certificate",
                        ack_ref
                    );
                }
                if let Some(cert) = self.header.bls_aggregate_round_signature() {
                    ensure!(
                        !cert.is_empty(),
                        "StarfishL aggregate round certificate must not be empty"
                    );
                }
                if let Some((leader_ref, cert)) = self.header.certified_leader() {
                    ensure!(
                        !cert.is_empty(),
                        "StarfishL certified leader {:?} must not have an empty certificate",
                        leader_ref
                    );
                }
            }
            ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishPull
            | ConsensusProtocol::StarfishS => {
                ensure!(
                    threshold_clock_valid_block_header(&self.header, committee),
                    "Threshold clock is not valid"
                );
                ensure!(
                    self.header.bls().is_none(),
                    "Only StarfishL blocks may carry BLS fields"
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
                    "Only StarfishL blocks may carry BLS fields"
                );
            }
        }
        Ok(())
    }
}
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Default, Debug,
)]
pub struct AuthoritySet(u128); // todo - support more then 128 authorities

pub type TimestampNs = u128;
const NANOS_IN_SEC: u128 = Duration::from_secs(1).as_nanos();

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
    #[inline]
    pub fn insert(&mut self, v: AuthorityIndex) -> bool {
        let bit = 1u128 << v;
        if self.0 & bit == bit {
            return false;
        }
        self.0 |= bit;
        true
    }

    pub fn present(&self) -> impl Iterator<Item = AuthorityIndex> + '_ {
        (0..128).filter(move |&bit| (self.0 & (1u128 << bit)) != 0)
    }

    #[inline]
    pub fn contains(&self, v: AuthorityIndex) -> bool {
        let bit = 1u128 << v;
        self.0 & bit == bit
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

pub fn format_authority_index(i: AuthorityIndex) -> char {
    ('A' as u64 + i) as u8 as char
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

    fn make_starfish_l_block(
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
            ConsensusProtocol::StarfishL,
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
        let block = VerifiedBlock::new_with_signer(
            authority,
            round,
            vec![BlockReference::new_test(authority, round - 1)],
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
            TransactionsCommitment::default(),
            None,
            None,
        );

        assert_eq!(block.acknowledgment_intersection(), Some(2));
        assert_eq!(block.extra_acknowledgment_references(), &vec![d]);
        assert_eq!(block.acknowledgment_count(), 2);
        assert_eq!(block.acknowledgments(), vec![c, d]);
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
            transactions_commitment: TransactionsCommitment::default(),
            ack: AckFields {
                intersection: None,
                extra_references: vec![b],
            },
            strong_vote: None,
            bls: None,
            serialized: None,
        };

        assert_eq!(header.acknowledgment_count(), 1);
        assert_eq!(header.acknowledgments(), vec![b]);
    }

    #[test]
    fn aligns_starfish_l_ack_certificates_with_compressed_ack_order() {
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
            ConsensusProtocol::StarfishL,
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
    fn verifies_starfish_l_ack_count_matches_dac_certificates() {
        let ack_ref = BlockReference::new_test(0, 1);
        let bls_signers = BlsSigner::new_for_test(4);
        let dac_cert = single_signer_cert(crypto::bls_dac_message(&ack_ref), 0, &bls_signers);
        let (mut block, committee) = make_starfish_l_block(0, 2, vec![ack_ref], vec![dac_cert]);
        block
            .header
            .bls
            .as_mut()
            .expect("StarfishL block should carry BLS fields")
            .acknowledgment_signatures
            .clear();

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let err = block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::StarfishL,
            )
            .unwrap_err();

        assert!(
            err.to_string().contains(
                "StarfishL acknowledgment count 1 does not match DAC certificate count 0"
            )
        );
    }

    #[test]
    fn verifies_starfish_l_acks_target_only_own_past_blocks() {
        let invalid_ack_ref = BlockReference::new_test(1, 1);
        let bls_signers = BlsSigner::new_for_test(4);
        let dac_cert =
            single_signer_cert(crypto::bls_dac_message(&invalid_ack_ref), 1, &bls_signers);
        let (mut block, committee) =
            make_starfish_l_block(0, 2, vec![invalid_ack_ref], vec![dac_cert]);

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let err = block
            .verify(
                committee.as_ref(),
                0,
                1,
                &mut encoder,
                ConsensusProtocol::StarfishL,
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
        let (mut block, committee) = make_starfish_l_block(
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
                ConsensusProtocol::StarfishL,
            )
            .unwrap_err();
        assert!(err.to_string().contains("must be from a past round"));
    }

    #[test]
    fn verifies_starfish_l_non_leader_references_only_self_chain() {
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
            ConsensusProtocol::StarfishL,
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
                ConsensusProtocol::StarfishL,
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("StarfishL non-leader block may reference only",)
        );
    }

    #[test]
    fn rejects_cordial_miners_acknowledgments() {
        let ack_ref = BlockReference::new_test(1, 1);
        let (mut block, committee) = make_cordial_miners_block(0, 2, vec![ack_ref]);

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
                .contains("CordialMiners blocks must not carry acknowledgments")
        );
    }

    #[test]
    fn verifies_starfish_l_non_leader_may_reference_latest_own_block_from_earlier_round() {
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
            ConsensusProtocol::StarfishL,
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
                ConsensusProtocol::StarfishL,
            )
            .expect("non-leader StarfishL block should allow skipped own rounds");
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
    fn authority_present_test() {
        let mut a = AuthoritySet::default();
        let present = vec![1, 2, 3, 4, 5, 64, 127];
        for x in &present {
            a.insert(*x);
        }
        assert_eq!(present, a.present().collect::<Vec<_>>());
    }
}
