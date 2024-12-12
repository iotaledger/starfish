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
    threshold_clock::threshold_clock_valid_non_genesis,
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
    // It could be one some or all nones
    encoded_statements: Vec<Option<Shard>>,
    // This is Some only when the above has one some
    merkle_proof:  Option<Vec<u8>>,
    // merkle root is computed for encoded_statements
    merkle_root: MerkleRoot,

}

impl VerifiedStatementBlock {
    pub(crate) fn change_for_not_own_index(&mut self) {
        self.statements = None;
    }
}

impl VerifiedStatementBlock {
    pub(crate) fn change_for_own_index(&mut self) {
       for i in 0..self.encoded_statements.len() {
           self.encoded_statements[i] = None;
       }
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
        encoded_statements: Vec<Option<Shard>>,
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
            encoded_statements,
            merkle_proof,
            merkle_root,
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
            vec![],
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



    pub fn encoded_statements(&self) -> &Vec<Option<Shard>> {
        &self
            .encoded_statements
    }

    pub fn statements(&self) -> &Option<Vec<BaseStatement>> {
        &self
            .statements
    }
    pub fn add_encoded_shard(&mut self, position: usize, shard: Shard) {
        self.encoded_statements[position] = Some(shard);
    }

    pub fn add_encoded_statements(& mut self, encoded_statements: Vec<Option<Shard>>) {
        self.encoded_statements = encoded_statements;
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

    pub fn from_bytes(bytes: Bytes) -> bincode::Result<Arc<Self>> {
        IN_MEMORY_BLOCKS.fetch_add(1, Ordering::Relaxed);
        IN_MEMORY_BLOCKS_BYTES.fetch_add(bytes.len(), Ordering::Relaxed);
        let t = bincode::deserialize(&bytes)?;
        Ok(Arc::new(t))
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
        encoded_statements: Vec<Option<Shard>>,
    ) -> Self {
        let (merkle_root, merkle_proof_bytes) = MerkleRoot::new_from_encoded_statements(&encoded_statements, authority);
        let signature = signer.sign_block(
            authority,
            round,
            &includes,
            &acknowledgement_statements,
            meta_creation_time_ns,
            epoch_marker,
            merkle_root,
        );
        let mut encoded_statements = encoded_statements;
        for i in 0..encoded_statements.len() {
            if i != authority as usize {
                encoded_statements[i] = None;
            }
        }
        Self::new(
            authority,
            round,
            includes,
            acknowledgement_statements,
            meta_creation_time_ns,
            epoch_marker,
            signature,
            statements,
            encoded_statements,
            Some(merkle_proof_bytes),
            merkle_root,
        )
    }

    pub fn verify(&mut self, committee: &Committee, own_id: AuthorityIndex, peer_id: AuthorityIndex, encoder: &mut Encoder) -> eyre::Result<()> {
        let round = self.round();
        let committee_size = committee.len();
        let info_length = committee.info_length();
        let parity_length = committee_size-info_length;
        if self.statements.is_some() {
            let computed_encoded_statements = encoder.encode_statements(self.statements.clone().unwrap(), info_length, parity_length);
            let (computed_merkle_tree, merkle_proof_bytes) = MerkleRoot::new_from_encoded_statements(&computed_encoded_statements, own_id);
            ensure!(computed_merkle_tree== self.merkle_root, "Incorrect Merkle root");
            self.merkle_proof = Some(merkle_proof_bytes);
            for i in 0..computed_encoded_statements.len() {
                if i != own_id as usize {
                    self.encoded_statements[i] = None;
                } else {
                    self.encoded_statements[i] = computed_encoded_statements[i].clone();
                }
            }
        } else {
            let number_somes = self.encoded_statements.iter().filter(|s| s.is_some()).count();
            match number_somes {
                0 => {},
                1 => {
                    let position = self.encoded_statements.iter().position(|s| s.is_some()).expect("Should be one some");
                    if position != peer_id as usize {
                        bail!("The peer delivers a wrong encoded chunk");
                    }
                    ensure!(MerkleRoot::check_correctness_merkle_leaf(self.encoded_statements(), self.merkle_root, self.merkle_proof.as_ref().cloned().unwrap(), committee_size, position),
                    "Merkle proof check failed");
                }
                _ => {
                    bail!("Only three options are possible");
                }
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
        if let Err(e) = pub_key.verify_signature_block(self) {
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

impl StatementBlock {
    pub fn new_genesis(authority: AuthorityIndex) -> Data<Self> {
        Data::new(Self::new(
            authority,
            GENESIS_ROUND,
            vec![],
            vec![],
            0,
            false,
            SignatureBytes::default(),
            vec![None],
            None,
            MerkleRoot::default(),
        ))
    }



    pub fn change_for_own_index(&mut self, info_length: usize) {
        for i in info_length..self.encoded_statements.len() {
            self.encoded_statements[i] = None;
        }
    }
    pub fn change_for_not_own_index(&mut self, authority_index: AuthorityIndex) {
        for i in 0..self.encoded_statements.len() {
            if i as AuthorityIndex != authority_index {
                self.encoded_statements[i] = None;
            }
        }
    }

    pub fn new_with_signer(
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: Vec<BlockReference>,
        acknowledgement_statements: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        epoch_marker: EpochStatus,
        signer: &Signer,
        encoded_statements: Vec<Option<Shard>>,
    ) -> Self {
        let (merkle_root, merkle_proof_bytes) = MerkleRoot::new_from_encoded_statements(&encoded_statements, authority);
        let signature = signer.sign_block(
            authority,
            round,
            &includes,
            &acknowledgement_statements,
            meta_creation_time_ns,
            epoch_marker,
            merkle_root,
        );
        Self::new(
            authority,
            round,
            includes,
            acknowledgement_statements,
            meta_creation_time_ns,
            epoch_marker,
            signature,
            encoded_statements,
            Some(merkle_proof_bytes),
            merkle_root,
        )
    }

    pub fn new(
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: Vec<BlockReference>,
        acknowledgement_statements: Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        epoch_marker: EpochStatus,
        signature: SignatureBytes,
        encoded_statements: Vec<Option<Shard>>,
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
            encoded_statements,
            merkle_proof,
            merkle_root,
        }
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



    pub fn encoded_statements(&self) -> &Vec<Option<Shard>> {
        &self
            .encoded_statements
    }
    pub fn add_encoded_shard(&mut self, position: usize, shard: Shard) {
        self.encoded_statements[position] = Some(shard);
    }

    pub fn add_encoded_statements(& mut self, encoded_statements: Vec<Option<Shard>>) {
       self.encoded_statements = encoded_statements;
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

    pub fn epoch_changed(&self) -> EpochStatus {
        self.epoch_marker
    }

    pub fn meta_creation_time(&self) -> Duration {
        // Some context: https://github.com/rust-lang/rust/issues/51107
        let secs = self.meta_creation_time_ns / NANOS_IN_SEC;
        let nanos = self.meta_creation_time_ns % NANOS_IN_SEC;
        Duration::new(secs as u64, nanos as u32)
    }

    pub fn transform_to_verified(self,  own_id: AuthorityIndex, committee: &Committee) -> VerifiedStatementBlock {
        let info_length = committee.info_length();
        let number_somes = self.encoded_statements.iter().filter(|s|s.is_some()).count();
        let number_info_somes = self.encoded_statements.iter().enumerate().filter(|(i,s)|*i< info_length && s.is_some()).count();
        if number_info_somes == info_length {
            let info_shards: Vec<Vec<u8>> = self.encoded_statements()
                .iter()
                .enumerate()
                .filter(|(i, s)| *i < info_length && s.is_some())
                .map(|(_, s)| s.clone().unwrap()) // Safe to unwrap because we filtered for `is_some()`
                .collect();
            // Combine all the shards into a single Vec<u8> (assuming they are in order)
            let mut reconstructed_data = Vec::new();
            for shard in info_shards {
                reconstructed_data.extend(shard);
            }

            // Read the first 4 bytes for `bytes_length` to get the size of the original serialized block
            if reconstructed_data.len() < 4 {
                panic!("Reconstructed data is too short to contain a valid length");
            }

            let bytes_length = u32::from_le_bytes(
                reconstructed_data[0..4].try_into().expect("Failed to read bytes_length"),
            ) as usize;

            // Ensure the data length matches the declared length
            if reconstructed_data.len() < 4 + bytes_length {
                panic!("Reconstructed data length does not match the declared bytes_length");
            }

            // Deserialize the rest of the data into `Vec<BaseStatement>`
            let serialized_data_statements = &reconstructed_data[4..4 + bytes_length];
            let reconstructed_statements: Vec<BaseStatement> = bincode::deserialize(serialized_data_statements)
                .expect("Deserialization of reconstructed data failed");

            let mut encoded_statements = self.encoded_statements;
            for (i, shard) in encoded_statements.iter_mut().enumerate() {
                if i != own_id as usize {
                    *shard = None;
                }
            }

            VerifiedStatementBlock {
                reference: self.reference,
                includes: self.includes,
                acknowledgement_statements: self.acknowledgement_statements,
                meta_creation_time_ns: self.meta_creation_time_ns,
                epoch_marker: self.epoch_marker,
                signature: self.signature,
                statements: Some(reconstructed_statements),
                encoded_statements,
                merkle_proof: self.merkle_proof,
                merkle_root: self.merkle_root,
            }
        } else {
            if number_somes == 1 {
                VerifiedStatementBlock {
                    reference: self.reference,
                    includes: self.includes,
                    acknowledgement_statements: self.acknowledgement_statements,
                    meta_creation_time_ns: self.meta_creation_time_ns,
                    epoch_marker: self.epoch_marker,
                    signature: self.signature,
                    statements: None,
                    encoded_statements: self.encoded_statements,
                    merkle_proof: self.merkle_proof,
                    merkle_root: self.merkle_root,
                }
            } else {
                VerifiedStatementBlock {
                    reference: self.reference,
                    includes: self.includes,
                    acknowledgement_statements: self.acknowledgement_statements,
                    meta_creation_time_ns: self.meta_creation_time_ns,
                    epoch_marker: self.epoch_marker,
                    signature: self.signature,
                    statements: None,
                    encoded_statements: vec![None; committee.len()],
                    merkle_proof: None,
                    merkle_root: self.merkle_root,
                }
            }
        }
    }

    pub fn verify(&mut self, committee: &Committee, own_id: AuthorityIndex, peer_id: AuthorityIndex, encoder: &mut Encoder) -> eyre::Result<()> {
        let round = self.round();
        let committee_size = committee.len();
        let info_size = committee.info_length();
        let parity_size = committee_size-info_size;
        let number_somes = self.encoded_statements.iter().filter(|s|s.is_some()).count();
        let number_info_somes = self.encoded_statements.iter().enumerate().filter(|(i,s)|*i< info_size && s.is_some()).count();
        match number_somes {
            0 => {},
            1 => {
                let position = self.encoded_statements.iter().position(|s|s.is_some()).expect("Should be one some");
                if position != peer_id as usize {
                    bail!("The peer delivers a wrong encoded chunk");
                }
                ensure!(MerkleRoot::check_correctness_merkle_leaf(self.encoded_statements(), self.merkle_root, self.merkle_proof.as_ref().cloned().unwrap(), committee_size, position),
                "Merkle proof check failed");
                }
            x if x>= info_size && number_info_somes== info_size => {
                let shard_size= self.encoded_statements()[0].as_ref().unwrap().len();
                encoder.reset(info_size, parity_size, shard_size).expect("encoder reset failed");
                for shard_index in 0..info_size {
                    let shard = self.encoded_statements()[shard_index].clone();
                    encoder.add_original_shard(shard.unwrap()).expect("Adding shard failed");
                }
                let result = encoder.encode().expect("Encoding failed");
                let recovery: Vec<Option<Shard>> = result.recovery_iter().map(|slice| Some(slice.to_vec())).collect();
                for i in info_size..committee_size {
                    self.encoded_statements[i] = recovery[i- info_size].clone();
                }
                let (computed_merkle_tree, merkle_proof_bytes) = MerkleRoot::new_from_encoded_statements(self.encoded_statements(), own_id);



                ensure!(computed_merkle_tree== self.merkle_root, "Incorrect Merkle root");

                self.merkle_proof = Some(merkle_proof_bytes);
            }
            _ => {
                bail!("Only three options are possible");
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
        if let Err(e) = pub_key.verify_block(self) {
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
            threshold_clock_valid_non_genesis(self, committee),
            "Threshold clock is not valid"
        );
        Ok(())
    }

    pub fn detailed(&self) -> Detailed {
        Detailed(self)
    }

    pub fn set_merkle_proof(&mut self, merkle_proof: Vec<u8>) {
        self.merkle_proof = Some(merkle_proof);
    }

    pub fn from_bytes(bytes: Bytes) -> bincode::Result<Arc<Self>> {
        IN_MEMORY_BLOCKS.fetch_add(1, Ordering::Relaxed);
        IN_MEMORY_BLOCKS_BYTES.fetch_add(bytes.len(), Ordering::Relaxed);
        let t = bincode::deserialize(&bytes)?;
        Ok(Arc::new(t))
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
            StatementBlock::new_genesis(authority).reference
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

impl fmt::Debug for StatementBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Debug for VerifiedStatementBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}
pub struct Detailed<'a>(&'a StatementBlock);

impl<'a> fmt::Debug for Detailed<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StatementBlock {:?} {{", self.0.reference())?;
        write!(
            f,
            "includes({})={:?},",
            self.0.includes().len(),
            self.0.includes()
        )?;

        writeln!(f, "}}")
    }
}

impl fmt::Display for StatementBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[", self.reference)?;
        for include in self.includes() {
            write!(f, "{},", include)?;
        }
        write!(f, "](")?;
        write!(f, ")")
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

    pub struct Dag(HashMap<BlockReference, Data<StatementBlock>>);

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

        pub fn draw_block(block: &str) -> StatementBlock {
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
            StatementBlock {
                reference,
                includes,
                acknowledgement_statements,
                meta_creation_time_ns: 0,
                epoch_marker: false,
                signature: Default::default(),
                encoded_statements: vec![],
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
                let block = StatementBlock::new_genesis(authority);
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
        type Item = &'a Data<StatementBlock>;

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
    #[test]
    fn create_block_and_verify() {
        let committee_size = 4;
        let number_byzantine = 0;
        let byzantine_strategy = "honest".to_string();
        let rounds_in_epoch = 100;
        let (committee, mut cores, reporters) = byzantine_committee_and_cores_epoch_duration(
            committee_size,
            number_byzantine,
            byzantine_strategy,
            rounds_in_epoch,
        );

        let first_peer_index: AuthorityIndex = 1 as AuthorityIndex;
        let second_peer_index: AuthorityIndex = 2 as AuthorityIndex;
        let third_peer_index: AuthorityIndex = 3 as AuthorityIndex;
        let own_index: AuthorityIndex = 0 as AuthorityIndex;
        let mut own_core = &mut cores[own_index as usize];
        let clock_round = 1;
        let mut genesis_blocks = Vec::new();
        for i in 0..committee_size {
            genesis_blocks.push(StatementBlock::new_genesis(i as AuthorityIndex));
        }
        let includes: Vec<BlockReference> = genesis_blocks.iter().map(|x| x.reference().clone()).collect();
        let acknowledgement_statements = includes.clone();


        let info_length = committee.info_length();
        let parity_length = committee.len() - info_length;
        let statements = generate_random_shares(5);
        let mut encoded_statements = own_core.encode(statements, info_length, parity_length);


        let mut full_block = StatementBlock::new_with_signer(
            own_index,
            clock_round,
            includes.clone(),
            acknowledgement_statements,
            0,
            false,
            &own_core.get_signer(),
            encoded_statements.clone(),
        );
        let mut encoder = ReedSolomonEncoder::new(2,
                                                  4,
                                                  64).unwrap();
        let mut original_full_block = full_block.clone();
        // Before sending remove Somes from parity symbols
        full_block.change_for_own_index(info_length);

        // Assume the block is sent 0->1. Make verification by first peer
        // The block is modified by encoding and including another Merkle proof
        let result_full_block = full_block.verify(&committee, first_peer_index, own_index, &mut encoder);
        assert!(result_full_block.is_ok());

        let mut one_some_block_from_first = full_block.clone();
        // Before sending between 1->2 leave one some
        one_some_block_from_first.change_for_not_own_index(first_peer_index);

        let result_one_some_block = one_some_block_from_first.verify(&committee, second_peer_index, first_peer_index, &mut encoder);
        assert!(result_one_some_block.is_ok());

        let mut one_some_block_from_second = original_full_block.verify(&committee, second_peer_index, first_peer_index, &mut encoder);
        // Before sending between 1->3 leave one some
        original_full_block.change_for_not_own_index(second_peer_index);
        let mut one_some_block_from_second = original_full_block;

        let result_one_some_block = one_some_block_from_second.verify(&committee, third_peer_index, second_peer_index, &mut encoder);
        assert!(result_one_some_block.is_ok());

        // Now sending between 2->0
        let mut none_block = one_some_block_from_first.clone();
        // Before sending leave one some, but actually remove all of them
        none_block.change_for_not_own_index(second_peer_index);

        let result_all_none_block = none_block.verify(&committee, own_index, second_peer_index, &mut encoder);
        assert!(result_all_none_block.is_ok());
    }
}
