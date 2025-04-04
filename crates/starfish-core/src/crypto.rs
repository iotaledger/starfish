// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::types::{BaseStatement, Shard, VerifiedStatementBlock};
use crate::{
    crypto,
    serde::{ByteRepr, BytesVisitor},
    types::{AuthorityIndex, BlockReference, EpochStatus, RoundNumber, TimestampNs},
};
use ed25519_consensus::Signature;
use rand::{rngs::StdRng, SeedableRng};
use rs_merkle::Hasher;
use rs_merkle::{MerkleProof, MerkleTree};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroize;

pub const SIGNATURE_SIZE: usize = 64;
pub const BLOCK_DIGEST_SIZE: usize = 32;

pub const TRANSACTIONS_DIGEST_SIZE: usize = 32;

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Default, Hash)]
pub struct BlockDigest([u8; BLOCK_DIGEST_SIZE]);

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Default, Hash)]
pub struct TransactionsCommitment([u8; TRANSACTIONS_DIGEST_SIZE]);

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct PublicKey(ed25519_consensus::VerificationKey);

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Hash)]
pub struct SignatureBytes([u8; SIGNATURE_SIZE]);

// Box ensures value is not copied in memory when Signer itself is moved around for better security
#[derive(Serialize, Deserialize, Clone)]
pub struct Signer(Box<ed25519_consensus::SigningKey>);
pub type Blake3Hasher = blake3::Hasher;

#[derive(Clone)]
pub struct Blake3;

impl Hasher for Blake3 {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

impl TransactionsCommitment {
    pub fn new_from_encoded_statements(
        encoded_statements: &Vec<Shard>,
        authority_index: usize,
    ) -> (TransactionsCommitment, Vec<u8>) {
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        for shard in encoded_statements {
            let mut hasher = crypto::Blake3Hasher::new();
            shard.crypto_hash(&mut hasher);
            let leaf = hasher.finalize().into();
            leaves.push(leaf);
        }
        let merkle_tree = MerkleTree::<Blake3>::from_leaves(&leaves);
        let merkle_root = merkle_tree
            .root()
            .ok_or("couldn't get the merkle root")
            .unwrap();
        let indices_to_prove = vec![authority_index];
        let merkle_proof = merkle_tree.proof(&indices_to_prove);
        let merkle_proof_bytes = merkle_proof.to_bytes();
        (TransactionsCommitment(merkle_root), merkle_proof_bytes)
    }
    pub fn new_from_statements(statements: &Vec<BaseStatement>) -> TransactionsCommitment {
        let mut hasher = crypto::Blake3Hasher::new();
        for statement in statements {
            statement.crypto_hash(&mut hasher);
        }
        let digest = hasher.finalize().into();
        TransactionsCommitment(digest)
    }

    pub fn check_correctness_merkle_root(
        encoded_statements: &Vec<Shard>,
        merkle_root: TransactionsCommitment,
    ) -> bool {
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        for shard in encoded_statements {
            let mut hasher = Blake3Hasher::new();
            shard.crypto_hash(&mut hasher);
            let leaf = hasher.finalize().into();
            leaves.push(leaf);
        }
        let computed_merkle_tree = MerkleTree::<Blake3>::from_leaves(&leaves);
        let computed_merkle_root = computed_merkle_tree
            .root()
            .ok_or("couldn't get the merkle root")
            .unwrap();
        computed_merkle_root == merkle_root.0
    }

    // The function assumes that encoded_statements[leaf_index] is Some. Otherwise panics
    pub fn check_correctness_merkle_leaf(
        shard: Shard,
        merkle_root: TransactionsCommitment,
        proof_bytes: Vec<u8>,
        tree_size: usize,
        leaf_index: usize,
    ) -> bool {
        let mut hasher = crypto::Blake3Hasher::new();
        shard.crypto_hash(&mut hasher);
        let leaf_to_prove: [u8; 32] = hasher.finalize().into();
        let proof = MerkleProof::<Blake3>::try_from(proof_bytes).unwrap();

        proof.verify(merkle_root.0, &[leaf_index], &[leaf_to_prove], tree_size)
    }
}
impl BlockDigest {
    pub fn new_without_statements(
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: &[BlockReference],
        acknowledgement_statements: &Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        epoch_marker: EpochStatus,
        signature: &SignatureBytes,
        merkle_root: TransactionsCommitment,
    ) -> Self {
        let mut hasher = Blake3Hasher::new();
        Self::digest_without_signature(
            &mut hasher,
            authority,
            round,
            includes,
            acknowledgement_statements,
            meta_creation_time_ns,
            epoch_marker,
            merkle_root,
        );
        hasher.update(signature.as_bytes());
        Self(hasher.finalize().into())
    }

    pub fn new(
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: &[BlockReference],
        acknowledgement_statements: &Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        epoch_marker: EpochStatus,
        signature: &SignatureBytes,
        transactions_commitment: TransactionsCommitment,
    ) -> Self {
        let mut hasher = Blake3Hasher::new();
        Self::digest_without_signature(
            &mut hasher,
            authority,
            round,
            includes,
            acknowledgement_statements,
            meta_creation_time_ns,
            epoch_marker,
            transactions_commitment,
        );
        hasher.update(signature.as_bytes());
        Self(hasher.finalize().into())
    }

    fn digest_without_signature(
        hasher: &mut Blake3Hasher,
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: &[BlockReference],
        acknowledgement_statements: &Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        epoch_marker: EpochStatus,
        transactions_commitment: TransactionsCommitment,
    ) {
        authority.crypto_hash(hasher);
        round.crypto_hash(hasher);
        for include in includes {
            include.crypto_hash(hasher);
        }
        for block_ref in acknowledgement_statements {
            block_ref.crypto_hash(hasher);
        }
        meta_creation_time_ns.crypto_hash(hasher);
        epoch_marker.crypto_hash(hasher);
        transactions_commitment.crypto_hash(hasher);
    }
}

pub trait AsBytes {
    // This is pretty much same as AsRef<[u8]>
    //
    // We need this separate trait because we want to impl CryptoHash
    // for primitive types(u64, etc) and types like XxxDigest that implement AsRef<[u8]>.
    //
    // Rust unfortunately does not allow to impl trait for AsRef<[u8]> and primitive types like u64.
    //
    // While AsRef<[u8]> is not implemented for u64, it seem to be reserved in compiler,
    // so `impl CryptoHash for u64` and `impl<T: AsRef<[u8]>> CryptoHash for T` collide.
    fn as_bytes(&self) -> &[u8];
}

impl<const N: usize> AsBytes for [u8; N] {
    fn as_bytes(&self) -> &[u8] {
        self
    }
}

pub trait CryptoHash {
    fn crypto_hash(&self, state: &mut Blake3Hasher);
}

impl CryptoHash for u64 {
    fn crypto_hash(&self, state: &mut Blake3Hasher) {
        state.update(&self.to_be_bytes());
    }
}

/*impl CryptoHash for StatementDigest {
    fn crypto_hash(&self, state: &mut BlockHasher) {
        state.update(self.as_ref());
    }
}*/

impl CryptoHash for u128 {
    fn crypto_hash(&self, state: &mut Blake3Hasher) {
        state.update(&self.to_be_bytes());
    }
}

impl<T: AsBytes> CryptoHash for T {
    fn crypto_hash(&self, state: &mut Blake3Hasher) {
        state.update(self.as_bytes());
    }
}

impl PublicKey {
    pub fn verify_signature_in_block(
        &self,
        block: &VerifiedStatementBlock,
    ) -> Result<(), ed25519_consensus::Error> {
        let signature = Signature::from(block.signature().0);
        let mut hasher = Blake3Hasher::new();
        BlockDigest::digest_without_signature(
            &mut hasher,
            block.author(),
            block.round(),
            block.includes(),
            block.acknowledgement_statements(),
            block.meta_creation_time_ns(),
            block.epoch_changed(),
            block.merkle_root(),
        );
        let digest: [u8; BLOCK_DIGEST_SIZE] = hasher.finalize().into();
        self.0.verify(&signature, digest.as_ref())
    }
}

impl Signer {
    pub fn new_for_test(n: usize) -> Vec<Self> {
        let mut rng = StdRng::seed_from_u64(0);
        (0..n)
            .map(|_| Self(Box::new(ed25519_consensus::SigningKey::new(&mut rng))))
            .collect()
    }

    pub fn sign_block(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: &[BlockReference],
        acknowledgement_statements: &Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        epoch_marker: EpochStatus,
        transactions_commitment: TransactionsCommitment,
    ) -> SignatureBytes {
        let mut hasher = Blake3Hasher::new();
        BlockDigest::digest_without_signature(
            &mut hasher,
            authority,
            round,
            includes,
            acknowledgement_statements,
            meta_creation_time_ns,
            epoch_marker,
            transactions_commitment,
        );
        let digest: [u8; BLOCK_DIGEST_SIZE] = hasher.finalize().into();
        let signature = self.0.sign(digest.as_ref());
        SignatureBytes(signature.to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verification_key())
    }
}

impl AsRef<[u8]> for TransactionsCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for BlockDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsBytes for TransactionsCommitment {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsBytes for BlockDigest {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsBytes for SignatureBytes {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for BlockDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_string = hex::encode(self.0); // Encode the byte array into a hex string
        write!(f, "@{}", &hex_string[..2]) // Slice the first 2 characters and print
    }
}

impl fmt::Display for BlockDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_string = hex::encode(self.0); // Encode the byte array into a hex string
        write!(f, "@{}", &hex_string[..2])
    }
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signer(public_key={:?})", self.public_key())
    }
}

impl fmt::Display for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signer(public_key={:?})", self.public_key())
    }
}

impl Default for SignatureBytes {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl ByteRepr for SignatureBytes {
    fn try_copy_from_slice<E: de::Error>(v: &[u8]) -> Result<Self, E> {
        if v.len() != SIGNATURE_SIZE {
            return Err(E::custom(format!("Invalid signature length: {}", v.len())));
        }
        let mut inner = [0u8; SIGNATURE_SIZE];
        inner.copy_from_slice(v);
        Ok(Self(inner))
    }
}

impl Serialize for SignatureBytes {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(BytesVisitor::new())
    }
}

impl ByteRepr for BlockDigest {
    fn try_copy_from_slice<E: de::Error>(v: &[u8]) -> Result<Self, E> {
        if v.len() != BLOCK_DIGEST_SIZE {
            return Err(E::custom(format!(
                "Invalid block digest length: {}",
                v.len()
            )));
        }
        let mut inner = [0u8; BLOCK_DIGEST_SIZE];
        inner.copy_from_slice(v);
        Ok(Self(inner))
    }
}

impl ByteRepr for TransactionsCommitment {
    fn try_copy_from_slice<E: de::Error>(v: &[u8]) -> Result<Self, E> {
        if v.len() != BLOCK_DIGEST_SIZE {
            return Err(E::custom(format!(
                "Invalid block digest length: {}",
                v.len()
            )));
        }
        let mut inner = [0u8; BLOCK_DIGEST_SIZE];
        inner.copy_from_slice(v);
        Ok(Self(inner))
    }
}

impl fmt::Debug for TransactionsCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_string = hex::encode(self.0); // Encode the byte array into a hex string
        write!(f, "@{}", &hex_string[..2]) // Slice the first 2 characters and print
    }
}

impl fmt::Display for TransactionsCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_string = hex::encode(self.0); // Encode the byte array into a hex string
        write!(f, "@{}", &hex_string[..2])
    }
}
impl Serialize for TransactionsCommitment {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}
impl Serialize for BlockDigest {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}
impl<'de> Deserialize<'de> for TransactionsCommitment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(BytesVisitor::new())
    }
}
impl<'de> Deserialize<'de> for BlockDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(BytesVisitor::new())
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

pub fn dummy_signer() -> Signer {
    Signer(Box::new(ed25519_consensus::SigningKey::from([0u8; 32])))
}

pub fn dummy_public_key() -> PublicKey {
    dummy_signer().public_key()
}
