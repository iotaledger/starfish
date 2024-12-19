// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub type AuthorityIndex = u64;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct Transaction {
    data: Vec<u8>,
}

pub type RoundNumber = u64;
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
    ops::Range,
    time::Duration,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use digest::Digest;
use eyre::{bail, ensure};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use serde::{Deserialize, Serialize};
use minibytes::Bytes;
#[cfg(test)]
pub use test::Dag;

use crate::crypto::{MerkleRoot};
use crate::{
    committee::{Committee},
    crypto::{AsBytes, CryptoHash, SignatureBytes, Signer},
    data::Data,
};
use crate::data::{IN_MEMORY_BLOCKS, IN_MEMORY_BLOCKS_BYTES};
use crate::encoder::ShardEncoder;
use crate::threshold_clock::threshold_clock_valid_verified_block;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum Vote {
    Accept,
    Reject(Option<TransactionLocator>),
}

pub type EpochStatus = bool;

#[derive(PartialEq, Default, Clone, Copy, Serialize, Deserialize)]
pub enum InternalEpochStatus {
    #[default]
    Open,
    /// Change is triggered by an external deterministic mechanism
    BeginChange,
    /// Epoch is safe to close -- committed blocks from >= 2f+1 stake indicate epoch change
    SafeToClose,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct BlockReference {
    pub authority: AuthorityIndex,
    pub round: RoundNumber,
    pub digest: BlockDigest,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum BaseStatement {
    /// Authority Shares a transactions, without accepting it or not.
    Share(Transaction),
    /// Authority votes to accept or reject a transaction.
    Vote(TransactionLocator, Vote),
    // For now only accept votes are batched
    VoteRange(TransactionLocatorRange),
}

impl Hash for BlockReference {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.digest.as_ref()[..8]);
    }
}

#[derive(Clone, Serialize, Deserialize)]
// Important. Adding fields here requires updating BlockDigest::new, and StatementBlock::verify
pub struct VerifiedStatementBlock {
    reference: BlockReference,

    //  A list of block references to other blocks that this block includes
    //  Note that the order matters: if a reference to two blocks from the same round and same authority
    //  are included, then the first reference is the one that this block conceptually votes for.
    includes: Vec<BlockReference>,

    // Transaction data acknowledgment
    acknowledgement_statements: Vec<BlockReference>,

    // Creation time of the block as reported by creator, currently not enforced
    meta_creation_time_ns: TimestampNs,

    epoch_marker: EpochStatus,

    // Signature by the block author
    signature: SignatureBytes,
    // It could be either a vector of BaseStatement or None
    statements: Option<Vec<BaseStatement>>,
    // It could be a pair of encoded shard and position or none
    encoded_shard: Option<(Shard, usize)>,
    // This is Some only when the above has one some
    merkle_proof:  Option<Vec<u8>>,
    // merkle root is computed for encoded_statements
    merkle_root: MerkleRoot,

}


#[derive(Clone, Serialize, Deserialize)]
// Important. Adding fields here requires updating BlockDigest::new, and StatementBlock::verify
pub struct CachedStatementBlock {
    reference: BlockReference,

    //  A list of block references to other blocks that this block includes
    //  Note that the order matters: if a reference to two blocks from the same round and same authority
    //  are included, then the first reference is the one that this block conceptually votes for.
    includes: Vec<BlockReference>,

    // Transaction data acknowledgment
    acknowledgement_statements: Vec<BlockReference>,

    // Creation time of the block as reported by creator, currently not enforced
    meta_creation_time_ns: TimestampNs,

    epoch_marker: EpochStatus,

    // Signature by the block author
    signature: SignatureBytes,
    // It could be either a vector of BaseStatement or None
    statements: Option<Vec<BaseStatement>>,
    // It could be a pair of encoded shard and position or none
    encoded_statements: Vec<Option<Shard>>,
    // This is Some only when the above has one some
    merkle_proof:  Option<Vec<u8>>,
    // merkle root is computed for encoded_statements
    merkle_root: MerkleRoot,

}

impl CachedStatementBlock {
    pub(crate) fn to_verified_block(
        &self,
        encoded_shard: Option<(Shard,usize)>,
        merkle_proof: Vec<u8>
    ) -> VerifiedStatementBlock {
        VerifiedStatementBlock {
            reference: self.reference.clone(),
            includes: self.includes.clone(),
            acknowledgement_statements: self.acknowledgement_statements.clone(),
            meta_creation_time_ns: self.meta_creation_time_ns,
            epoch_marker: self.epoch_marker.clone(),
            signature: self.signature.clone(),
            statements: self.statements.clone(),
            encoded_shard, // Replace `0` with the actual position logic
            merkle_proof: Some(merkle_proof),
            merkle_root: self.merkle_root.clone(),
        }
    }


}

impl CachedStatementBlock {
    pub fn encoded_statements(&self) -> &Vec<Option<Shard>> {
        &self.encoded_statements
    }

    pub fn add_encoded_shard(&mut self, position: usize, shard: Shard) {
        self.encoded_statements[position] = Some(shard);
    }

    pub fn add_encoded_statements(& mut self, encoded_statements: Vec<Option<Shard>>) {
        self.encoded_statements = encoded_statements;
    }


    pub fn merkle_root(&self) -> MerkleRoot {
        self.merkle_root.clone()
    }

}

impl VerifiedStatementBlock {

    pub fn new(
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: Vec<BlockReference>,
        acknowledgement_statements: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        epoch_marker: EpochStatus,
        signature: SignatureBytes,
        statements: Vec<BaseStatement>,
        encoded_shard: Option<(Shard,usize)>,
        merkle_proof: Option<Vec<u8>>,
        merkle_root: MerkleRoot,
    ) -> Self {
        Self {
            reference: BlockReference {
                authority,
                round,
                digest: BlockDigest::new_without_statements(
                    authority,
                    round,
                    &includes,
                    &acknowledgement_statements,
                    meta_creation_time_ns,
                    epoch_marker,
                    &signature,
                    merkle_root,
                ),
            },
            includes,
            acknowledgement_statements,
            meta_creation_time_ns,
            epoch_marker,
            signature,
            statements: Some(statements),
            encoded_shard,
            merkle_proof,
            merkle_root,
        }
    }

    pub fn to_cached_block(
        &self,
        committee_size: usize,
    ) -> CachedStatementBlock {
        let mut encoded_statements: Vec<Option<Shard>> = Vec::new();
        for i in 0..committee_size {
            if let Some((shard, position)) = self.encoded_shard.as_ref() {
                if i == *position {
                    let new_shard: Shard = shard.clone();
                    encoded_statements.push(Some(new_shard));
                }
            }
            encoded_statements.push(None);
        }
        CachedStatementBlock {
            reference: self.reference.clone(),
            includes: self.includes.clone(),
            acknowledgement_statements: self.acknowledgement_statements.clone(),
            meta_creation_time_ns: self.meta_creation_time_ns,
            epoch_marker: self.epoch_marker.clone(),
            signature: self.signature.clone(),
            statements: self.statements.clone(),
            encoded_statements, // Replace `0` with the actual position logic
            merkle_proof: self.merkle_proof.clone(),
            merkle_root: self.merkle_root.clone(),
        }
    }

    pub fn from_storage_to_transmission(&self, own_id: AuthorityIndex) -> Self {
        if own_id != self.reference.authority {
            if let Some((_,position)) = self.encoded_shard().as_ref() {
                if *position != own_id as usize{
                    return Self {
                        reference: self.reference.clone(),
                        includes: self.includes.clone(),
                        acknowledgement_statements: self.acknowledgement_statements.clone(),
                        meta_creation_time_ns: self.meta_creation_time_ns,
                        epoch_marker: self.epoch_marker.clone(),
                        signature: self.signature.clone(),
                        statements: None,
                        encoded_shard: None,
                        merkle_proof: None,
                        merkle_root: self.merkle_root.clone(),
                    }
                }
            }
            Self {
                reference: self.reference.clone(),
                includes: self.includes.clone(),
                acknowledgement_statements: self.acknowledgement_statements.clone(),
                meta_creation_time_ns: self.meta_creation_time_ns,
                epoch_marker: self.epoch_marker.clone(),
                signature: self.signature.clone(),
                statements: None,
                encoded_shard: self.encoded_shard.clone(),
                merkle_proof: self.merkle_proof.clone(),
                merkle_root: self.merkle_root.clone(),
            }
        } else {
            Self {
                reference: self.reference.clone(),
                includes: self.includes.clone(),
                acknowledgement_statements: self.acknowledgement_statements.clone(),
                meta_creation_time_ns: self.meta_creation_time_ns,
                epoch_marker: self.epoch_marker.clone(),
                signature: self.signature.clone(),
                statements: self.statements.clone(),
                encoded_shard: None,
                merkle_proof: None,
                merkle_root: self.merkle_root.clone(),
            }
        }
    }

    pub fn new_genesis(authority: AuthorityIndex) -> Data<Self> {
        Data::new(Self::new(
            authority,
            GENESIS_ROUND,
            vec![],
            vec![],
            0,
            false,
            SignatureBytes::default(),
            vec![],
            None,
            None,
            MerkleRoot::default(),
        ))
    }

    pub fn merkle_root(&self) -> MerkleRoot {
        self.merkle_root.clone()
    }

    pub fn acknowledgement_statements(&self) -> &Vec<BlockReference> {
        &self.acknowledgement_statements
    }

    pub fn reference(&self) -> &BlockReference {
        &self.reference
    }

    pub fn includes(&self) -> &Vec<BlockReference> {
        &self.includes
    }



    pub fn encoded_shard(&self) -> &Option<(Shard,usize)> {
        &self
            .encoded_shard
    }

    pub fn statements(&self) -> &Option<Vec<BaseStatement>> {
        &self
            .statements
    }



    pub fn author(&self) -> AuthorityIndex {
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
        // Some context: https://github.com/rust-lang/rust/issues/51107
        let secs = self.meta_creation_time_ns / NANOS_IN_SEC;
        let nanos = self.meta_creation_time_ns % NANOS_IN_SEC;
        Duration::new(secs as u64, nanos as u32)
    }

    pub fn epoch_changed(&self) -> EpochStatus {
        self.epoch_marker
    }

    pub fn from_bytes(bytes: Bytes) -> bincode::Result<Self> {
        IN_MEMORY_BLOCKS.fetch_add(1, Ordering::Relaxed);
        IN_MEMORY_BLOCKS_BYTES.fetch_add(bytes.len(), Ordering::Relaxed);
        let t = bincode::deserialize(&bytes)?;
        Ok(t)
    }

    pub fn set_merkle_proof(&mut self, merkle_proof: Vec<u8>) {
        self.merkle_proof = Some(merkle_proof);
    }
    pub fn new_with_signer(
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: Vec<BlockReference>,
        acknowledgement_statements: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        epoch_marker: EpochStatus,
        signer: &Signer,
        statements: Vec<BaseStatement>,
        encoded_statements: Vec<Shard>,
    ) -> Self {
        let (merkle_root, merkle_proof_bytes) = MerkleRoot::new_from_encoded_statements(&encoded_statements, authority as usize);
        let signature = signer.sign_block(
            authority,
            round,
            &includes,
            &acknowledgement_statements,
            meta_creation_time_ns,
            epoch_marker,
            merkle_root,
        );
        //let encoded_shard = Some((encoded_statements[authority as usize].clone(), authority as usize));
        Self::new(
            authority,
            round,
            includes,
            acknowledgement_statements,
            meta_creation_time_ns,
            epoch_marker,
            signature,
            statements,
            None,
            None,
            merkle_root,
        )
    }

    pub fn verify(&mut self, committee: &Committee, own_id: usize, peer_id: usize, encoder: &mut Encoder) -> eyre::Result<()> {
        let round = self.round();
        let committee_size = committee.len();
        let info_length = committee.info_length();
        let parity_length = committee_size-info_length;
        if self.statements.is_some() {
            let computed_encoded_statements = encoder.encode_statements(self.statements.clone().unwrap(), info_length, parity_length);
            let (computed_merkle_tree_root, merkle_proof_bytes) = MerkleRoot::new_from_encoded_statements(&computed_encoded_statements, own_id);
            ensure!(computed_merkle_tree_root== self.merkle_root, "Incorrect Merkle root");
            self.merkle_proof = Some(merkle_proof_bytes);
            self.encoded_shard = Some((computed_encoded_statements[own_id as usize].clone(), own_id));
        } else {
            if self.encoded_shard.is_some() {
                    let (encoded_shard, position) = self.encoded_shard.clone().expect("We expect an encoded shard");
                    if position != peer_id {
                        bail!("The peer delivers a wrong encoded chunk");
                    }
                    if self.merkle_proof.is_none() {
                        bail!("The peer didn't include the proof for the chunk");
                    }
                    ensure!(MerkleRoot::check_correctness_merkle_leaf(encoded_shard, self.merkle_root, self.merkle_proof.as_ref().cloned().unwrap(), committee_size, position),
                    "Merkle proof check failed");
            }
        }

        // TODO: check correctness of encoded data/ chunks and merkle_root

        let digest = BlockDigest::new(
            self.author(),
            round,
            &self.includes,
            &self.acknowledgement_statements,
            self.meta_creation_time_ns,
            self.epoch_marker,
            &self.signature,
            self.merkle_root,
        );
        ensure!(
            digest == self.digest(),
            "Digest does not match, calculated {:?}, provided {:?}",
            digest,
            self.digest()
        );
        let pub_key = committee.get_public_key(self.author());
        let Some(pub_key) = pub_key else {
            bail!("Unknown block author {}", self.author())
        };
        if round == GENESIS_ROUND {
            bail!("Genesis block should not go through verification");
        }
        if let Err(e) = pub_key.verify_signature_in_block(self) {
            bail!("Block signature verification has failed: {:?}", e);
        }
        for include in &self.includes {
            // Also check duplicate includes?
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
        ensure!(
            threshold_clock_valid_verified_block(self, committee),
            "Threshold clock is not valid"
        );
        Ok(())
    }

}

#[derive(Clone, Serialize, Deserialize)]
// Important. Adding fields here requires updating BlockDigest::new, and StatementBlock::verify
pub struct StatementBlock {
    reference: BlockReference,

    //  A list of block references to other blocks that this block includes
    //  Note that the order matters: if a reference to two blocks from the same round and same authority
    //  are included, then the first reference is the one that this block conceptually votes for.
    includes: Vec<BlockReference>,

    // Transaction data acknowledgment
    acknowledgement_statements: Vec<BlockReference>,

        // Creation time of the block as reported by creator, currently not enforced
    meta_creation_time_ns: TimestampNs,

    epoch_marker: EpochStatus,

    // Signature by the block author
    signature: SignatureBytes,
    // It could be either vector of Nones, vector of Somes or a vector with one Some
    encoded_statements: Vec<Option<Shard>>,
    // This is Some only when the above is a vector with 1 Some and all other Nones
    merkle_proof:  Option<Vec<u8>>,
    // merkle root is computed for encoded_statements
    merkle_root: MerkleRoot,

}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub struct AuthoritySet(u128); // todo - support more then 128 authorities

pub type TimestampNs = u128;
const NANOS_IN_SEC: u128 = Duration::from_secs(1).as_nanos();

const GENESIS_ROUND: RoundNumber = 0;

impl PartialOrd for BlockReference {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockReference {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.round, self.authority, self.digest).cmp(&(other.round, other.authority, self.digest))
    }
}


#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub struct TransactionLocator {
    block: BlockReference,
    offset: u64,
}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub struct TransactionLocatorRange {
    block: BlockReference,
    offset_start_inclusive: u64,
    offset_end_exclusive: u64,
}

impl TransactionLocator {
    pub(crate) fn new(block: BlockReference, offset: u64) -> Self {
        Self { block, offset }
    }

    pub fn block(&self) -> &BlockReference {
        &self.block
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }
}

impl TransactionLocatorRange {

    pub fn one(locator: TransactionLocator) -> Self {
        Self {
            block: locator.block,
            offset_start_inclusive: locator.offset,
            offset_end_exclusive: locator.offset + 1,
        }
    }

    pub fn locators(&self) -> impl Iterator<Item = TransactionLocator> + '_ {
        self.range()
            .map(|offset| TransactionLocator::new(self.block, offset))
    }

    pub fn len(&self) -> usize {
        (self.offset_end_exclusive - self.offset_start_inclusive) as usize
    }

    pub fn verify(&self) -> eyre::Result<()> {
        ensure!(
            self.offset_end_exclusive >= self.offset_start_inclusive,
            "offset_end_exclusive must be greater or equal offset_start_inclusive: {}, {}",
            self.offset_end_exclusive,
            self.offset_start_inclusive,
        );
        // todo - should have constant for max transactions per block and use it here
        const MAX_LEN: u64 = 1024 * 1024;
        let len = self.len() as u64;
        ensure!(
            len < MAX_LEN,
            "Include is too large when uncompressed: {len}"
        );
        ensure!(
            self.offset_end_exclusive < MAX_LEN,
            "offset_end_exclusive is too large when uncompressed: {}",
            self.offset_end_exclusive
        );
        Ok(())
    }

    pub fn range(&self) -> Range<u64> {
        self.offset_start_inclusive..self.offset_end_exclusive
    }

    pub fn block(&self) -> &BlockReference {
        &self.block
    }
}

impl BlockReference {
    #[cfg(test)]
    pub fn new_test(authority: AuthorityIndex, round: RoundNumber) -> Self {
        if round == 0 {
            VerifiedStatementBlock::new_genesis(authority).reference
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
        write!(f, "{}", self)
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



impl fmt::Debug for VerifiedStatementBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}



impl fmt::Display for VerifiedStatementBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[", self.reference)?;
        for include in self.includes() {
            write!(f, "{},", include)?;
        }
        write!(f, "](")?;
        write!(f, ")")
    }
}

impl fmt::Debug for TransactionLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for TransactionLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.block, self.offset)
    }
}

impl PartialEq for StatementBlock {
    fn eq(&self, other: &Self) -> bool {
        self.reference == other.reference
    }
}

impl PartialEq for VerifiedStatementBlock {
    fn eq(&self, other: &Self) -> bool {
        self.reference == other.reference
    }
}

impl Eq for StatementBlock {}

impl Eq for VerifiedStatementBlock {}

impl std::hash::Hash for StatementBlock {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.reference.hash(state);
    }
}


impl std::hash::Hash for VerifiedStatementBlock {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.reference.hash(state);
    }
}


impl fmt::Debug for BaseStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl CryptoHash for BlockReference {
    fn crypto_hash(&self, state: &mut impl Digest) {
        self.authority.crypto_hash(state);
        self.round.crypto_hash(state);
        self.digest.crypto_hash(state);
    }
}

impl CryptoHash for TransactionLocator {
    fn crypto_hash(&self, state: &mut impl Digest) {
        self.block.crypto_hash(state);
        self.offset.crypto_hash(state);
    }
}

impl CryptoHash for Shard {
    fn crypto_hash(&self, state: &mut impl Digest) {
        state.update(self);
    }
}

impl CryptoHash for TransactionLocatorRange {
    fn crypto_hash(&self, state: &mut impl Digest) {
        self.block.crypto_hash(state);
        self.offset_start_inclusive.crypto_hash(state);
        self.offset_end_exclusive.crypto_hash(state);
    }
}

impl CryptoHash for EpochStatus {
    fn crypto_hash(&self, state: &mut impl Digest) {
        match self {
            false => [0].crypto_hash(state),
            true => [1].crypto_hash(state),
        }
    }
}

impl CryptoHash for BaseStatement {
    fn crypto_hash(&self, state: &mut impl Digest) {
        match self {
            BaseStatement::Share(tx) => {
                [0].crypto_hash(state);
                tx.crypto_hash(state);
            }
            BaseStatement::Vote(id, Vote::Accept) => {
                [1].crypto_hash(state);
                id.crypto_hash(state);
            }
            BaseStatement::Vote(id, Vote::Reject(None)) => {
                [2].crypto_hash(state);
                id.crypto_hash(state);
            }
            BaseStatement::Vote(id, Vote::Reject(Some(other))) => {
                [3].crypto_hash(state);
                id.crypto_hash(state);
                other.crypto_hash(state);
            }
            BaseStatement::VoteRange(range) => {
                [4].crypto_hash(state);
                range.crypto_hash(state);
            }
        }
    }
}

impl fmt::Display for BaseStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseStatement::Share(_tx) => write!(f, "tx"),
            BaseStatement::Vote(id, Vote::Accept) => write!(f, "+{id:08}"),
            BaseStatement::Vote(id, Vote::Reject(_)) => write!(f, "-{id:08}"),
            BaseStatement::VoteRange(range) => write!(
                f,
                "+{}:{}:{}",
                range.block, range.offset_start_inclusive, range.offset_end_exclusive
            ),
        }
    }
}

impl Transaction {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    #[allow(dead_code)]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[allow(dead_code)]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

impl AsBytes for Transaction {
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
    };

    use rand::{prelude::SliceRandom, Rng};
    use crate::test_util::byzantine_committee_and_cores_epoch_duration;
    use super::*;

    pub struct Dag(HashMap<BlockReference, Data<VerifiedStatementBlock>>);

    #[cfg(test)]
    impl Dag {
        /// Takes a string in form "Block:[Dependencies, ...]; ..."
        /// Where Block is one letter denoting a node and a number denoting a round
        /// For example B3 is a block for round 3 made by validator index 2
        /// Note that blocks are separated with semicolon(;) and dependencies within block are separated with coma(,)
        pub fn draw(s: &str) -> Self {
            let mut blocks = HashMap::new();
            for block in s.split(";") {
                let block = Self::draw_block(block);
                blocks.insert(*block.reference(), Data::new(block));
            }
            Self(blocks)
        }

        pub fn draw_block(block: &str) -> VerifiedStatementBlock {
            let block = block.trim();
            assert!(block.ends_with(']'), "Invalid block definition: {}", block);
            let block = &block[..block.len() - 1];
            let Some((name, includes)) = block.split_once(":[") else {
                panic!("Invalid block definition: {}", block);
            };
            let reference = Self::parse_name(name);
            let includes = includes.trim();
            let includes = if includes.len() == 0 {
                vec![]
            } else {
                let includes = includes.split(',');
                includes.map(Self::parse_name).collect()
            };
            let acknowledgement_statements = includes
                .clone();
            VerifiedStatementBlock {
                reference,
                includes,
                acknowledgement_statements,
                meta_creation_time_ns: 0,
                epoch_marker: false,
                signature: Default::default(),
                statements: None,
                encoded_shard: None,
                merkle_proof: None,
                merkle_root: MerkleRoot::default(),
            }
        }

        fn parse_name(s: &str) -> BlockReference {
            let s = s.trim();
            assert!(s.len() >= 2, "Invalid block: {}", s);
            let authority = s.as_bytes()[0];
            let authority = authority.wrapping_sub('A' as u8);
            assert!(authority < 26, "Invalid block: {}", s);
            let Ok(round): Result<u64, _> = s[1..].parse() else {
                panic!("Invalid block: {}", s);
            };
            BlockReference::new_test(authority as u64, round)
        }

        /// For each authority add a 0 round block if not present
        pub fn add_genesis_blocks(mut self) -> Self {
            for authority in self.authorities() {
                let block = VerifiedStatementBlock::new_genesis(authority);
                let entry = self.0.entry(*block.reference());
                entry.or_insert_with(move || block);
            }
            self
        }

        pub fn random_iter(&self, rng: &mut impl Rng) -> RandomDagIter {
            let mut v: Vec<_> = self.0.keys().cloned().collect();
            v.shuffle(rng);
            RandomDagIter(self, v.into_iter())
        }

        pub fn len(&self) -> usize {
            self.0.len()
        }

        fn authorities(&self) -> HashSet<AuthorityIndex> {
            let mut authorities = HashSet::new();
            for (k, v) in &self.0 {
                authorities.insert(k.authority);
                for include in v.includes() {
                    authorities.insert(include.authority);
                }
            }
            authorities
        }

        pub fn committee(&self) -> Arc<Committee> {
            Committee::new_test(vec![1; self.authorities().len()])
        }
    }

    pub struct RandomDagIter<'a>(&'a Dag, std::vec::IntoIter<BlockReference>);

    impl<'a> Iterator for RandomDagIter<'a> {
        type Item = &'a Data<VerifiedStatementBlock>;

        fn next(&mut self) -> Option<Self::Item> {
            let next = self.1.next()?;
            Some(self.0 .0.get(&next).unwrap())
        }
    }

    #[test]
    fn test_draw_dag() {
        let d = Dag::draw("A1:[A0, B1]; B2:[B1]").0;
        assert_eq!(d.len(), 2);
        let a0: BlockReference = BlockReference::new_test(0, 1);
        let b2: BlockReference = BlockReference::new_test(1, 2);
        assert_eq!(&d.get(&a0).unwrap().reference, &a0);
        assert_eq!(
            &d.get(&a0).unwrap().includes,
            &vec![
                BlockReference::new_test(0, 0),
                BlockReference::new_test(1, 1)
            ]
        );
        assert_eq!(&d.get(&b2).unwrap().reference, &b2);
        assert_eq!(
            &d.get(&b2).unwrap().includes,
            &vec![BlockReference::new_test(1, 1)]
        );
    }

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

    /// Function to generate a random Vec<BaseStatement> with only Share(Transaction)
    pub fn generate_random_shares(count: usize) -> Vec<BaseStatement> {
        let mut rng = rand::thread_rng();
        let mut statements = Vec::new();

        for _ in 0..count {
            // Generate random Transaction
            let transaction = Transaction {
                data: (0..rng.gen_range(1..100)) // Random length of data
                    .map(|_| rng.gen()) // Random bytes
                    .collect(),
            };

            // Add Share variant to the list
            statements.push(BaseStatement::Share(transaction));
        }

        statements
    }
}
