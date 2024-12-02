// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use digest::Digest;
use ed25519_consensus::Signature;
use rand::{rngs::StdRng, SeedableRng};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;
use crate::{
    crypto,
    serde::{ByteRepr, BytesVisitor},
    types::{
        AuthorityIndex, BlockReference, EpochStatus, RoundNumber, StatementBlock,
        TimestampNs,
    },
};
use rs_merkle::{MerkleProof, MerkleTree};
use rs_merkle::algorithms::Sha256;
use crate::types::Shard;

pub const SIGNATURE_SIZE: usize = 64;
pub const BLOCK_DIGEST_SIZE: usize = 32;


pub const MERKLE_DIGEST_SIZE: usize = 32;

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Default, Hash)]
pub struct BlockDigest([u8; BLOCK_DIGEST_SIZE]);

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Default, Hash)]
pub struct MerkleRoot([u8; MERKLE_DIGEST_SIZE]);

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct PublicKey(ed25519_consensus::VerificationKey);

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Hash)]
pub struct SignatureBytes([u8; SIGNATURE_SIZE]);

// Box ensures value is not copied in memory when Signer itself is moved around for better security
#[derive(Serialize, Deserialize)]
pub struct Signer(Box<ed25519_consensus::SigningKey>);

#[cfg(not(test))]
type BlockHasher = blake2::Blake2b<digest::consts::U32>;

#[cfg(test)]
type BlockHasher = blake2::Blake2b<digest::consts::U32>;


impl MerkleRoot {
    pub fn new_from_encoded_statements(encoded_statements: &Vec<Option<Shard>>) -> Self {
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        for shard in encoded_statements {
            let mut hasher = crypto::BlockHasher::default();
            shard.clone().unwrap().crypto_hash(&mut hasher);
            let leaf = hasher.finalize().into();
            leaves.push(leaf);
        }
        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let merkle_root = merkle_tree
            .root()
            .ok_or("couldn't get the merkle root")
            .unwrap();
        MerkleRoot(merkle_root)
    }

    pub fn check_correctness_merkle_root(encoded_statements: &Vec<Option<Shard>>, merkle_root: MerkleRoot) -> bool {
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        for shard in encoded_statements {
            let mut hasher = crypto::BlockHasher::default();
            shard.clone().unwrap().crypto_hash(&mut hasher);
            let leaf = hasher.finalize().into();
            leaves.push(leaf);
       }
        let computed_merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let computed_merkle_root = computed_merkle_tree
            .root()
            .ok_or("couldn't get the merkle root")
            .unwrap();
        computed_merkle_root == merkle_root.0
    }

    pub fn check_correctness_merkle_leaf(encoded_statements: &Vec<Option<Shard>>, merkle_root: MerkleRoot, proof_bytes: Vec<u8>, tree_size: usize) -> bool {
        let mut leaf_index = 0;
        while leaf_index < encoded_statements.len() {
            if encoded_statements[leaf_index].is_some() {
                break;
            }
            leaf_index += 1;
        }
        let shard = encoded_statements[leaf_index].clone().unwrap();
        let mut hasher = crypto::BlockHasher::default();
        shard.crypto_hash(&mut hasher);
        let leaf_to_prove: [u8; 32] = hasher.finalize().into();
        let proof = MerkleProof::<Sha256>::try_from(proof_bytes).unwrap();
        let result = proof.verify(
            merkle_root.0,
            &[leaf_index],
            &[leaf_to_prove],
            tree_size,
        );
        result
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
        merkle_root: MerkleRoot,
    ) -> Self {
        let mut hasher = BlockHasher::default();
        Self::digest_without_signature(
            &mut hasher,
            authority,
            round,
            includes,
            acknowledgement_statements,
            meta_creation_time_ns,
            epoch_marker,
            merkle_root
        );
        hasher.update(signature);
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
        merkle_root: MerkleRoot,
    ) -> Self {
        let mut hasher = BlockHasher::default();
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
        hasher.update(signature);
        Self(hasher.finalize().into())
    }

    fn digest_without_signature(
        hasher: &mut BlockHasher,
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: &[BlockReference],
        acknowledgement_statements: &Vec<BlockReference>,
        meta_creation_time_ns: TimestampNs,
        epoch_marker: EpochStatus,
        merkle_root: MerkleRoot,
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
        merkle_root.crypto_hash(hasher);
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
    fn crypto_hash(&self, state: &mut impl Digest);
}

impl CryptoHash for u64 {
    fn crypto_hash(&self, state: &mut impl Digest) {
        state.update(self.to_be_bytes());
    }
}



/*impl CryptoHash for StatementDigest {
    fn crypto_hash(&self, state: &mut impl Digest) {
        state.update(self.as_ref());
    }
}*/

impl CryptoHash for u128 {
    fn crypto_hash(&self, state: &mut impl Digest) {
        state.update(self.to_be_bytes());
    }
}

impl<T: AsBytes> CryptoHash for T {
    fn crypto_hash(&self, state: &mut impl Digest) {
        state.update(self.as_bytes());
    }
}

impl PublicKey {
    pub fn verify_block(&self, block: &StatementBlock) -> Result<(), ed25519_consensus::Error> {
        let signature = Signature::from(block.signature().0);
        let mut hasher = BlockHasher::default();
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
        merkle_root: MerkleRoot,
    ) -> SignatureBytes {
        let mut hasher = BlockHasher::default();
        BlockDigest::digest_without_signature(
            &mut hasher,
            authority,
            round,
            includes,
            acknowledgement_statements,
            meta_creation_time_ns,
            epoch_marker,
            merkle_root,
        );
        let digest: [u8; BLOCK_DIGEST_SIZE] = hasher.finalize().into();
        let signature = self.0.sign(digest.as_ref());
        SignatureBytes(signature.to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verification_key())
    }
}

impl AsRef<[u8]> for MerkleRoot {
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

impl AsBytes for MerkleRoot {
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

impl ByteRepr for MerkleRoot {
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

impl fmt::Debug for MerkleRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_string = hex::encode(self.0); // Encode the byte array into a hex string
        write!(f, "@{}", &hex_string[..2]) // Slice the first 2 characters and print
    }
}

impl fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_string = hex::encode(self.0); // Encode the byte array into a hex string
        write!(f, "@{}", &hex_string[..2])
    }
}
impl Serialize for MerkleRoot {
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
impl<'de> Deserialize<'de> for MerkleRoot {
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
