// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use blst::min_pk as bls;
use ed25519_consensus::Signature;
use rand::{SeedableRng, rngs::StdRng};
use rs_merkle::{Hasher, MerkleProof, MerkleTree};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use zeroize::Zeroize;

use crate::{
    crypto,
    serde::{ByteRepr, BytesVisitor},
    types::{
        AuthorityIndex, BaseTransaction, BlockHeader, BlockReference, RoundNumber, Shard,
        TimestampNs,
    },
};

/// Build the 32-byte message that validators sign (BLS) to certify a leader.
/// Domain separation: `b"leader" || leader_ref` fields.
pub fn bls_leader_message(leader_ref: &BlockReference) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"leader");
    leader_ref.crypto_hash(&mut hasher);
    hasher.finalize().into()
}

/// Build the 32-byte message that validators sign (BLS) to certify data
/// availability for an acknowledged block.
/// Domain separation: `b"dac" || ack_ref || commitment`.
pub fn bls_dac_message(ack_ref: &BlockReference, commitment: TransactionsCommitment) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"dac");
    ack_ref.crypto_hash(&mut hasher);
    commitment.crypto_hash(&mut hasher);
    hasher.finalize().into()
}

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

// Box ensures value is not copied in memory when Signer itself is moved around
// for better security
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
    pub fn new_from_encoded_transactions(
        encoded_transactions: &Vec<Shard>,
        authority_index: usize,
    ) -> (TransactionsCommitment, Vec<u8>) {
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        for shard in encoded_transactions {
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
    pub fn new_from_transactions(transactions: &Vec<BaseTransaction>) -> TransactionsCommitment {
        let mut hasher = crypto::Blake3Hasher::new();
        for transaction in transactions {
            transaction.crypto_hash(&mut hasher);
        }
        let digest = hasher.finalize().into();
        TransactionsCommitment(digest)
    }

    pub fn check_correctness_merkle_root(
        encoded_transactions: &Vec<Shard>,
        merkle_root: TransactionsCommitment,
    ) -> bool {
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        for shard in encoded_transactions {
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

    // The function assumes that encoded_transactions[leaf_index] is Some. Otherwise
    // panics
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
    pub fn new_without_transactions(
        authority: AuthorityIndex,
        round: RoundNumber,
        block_references: &[BlockReference],
        acknowledgment_references: &[BlockReference],
        meta_creation_time_ns: TimestampNs,
        signature: &SignatureBytes,
        merkle_root: TransactionsCommitment,
        strong_vote: Option<bool>,
    ) -> Self {
        let mut hasher = Blake3Hasher::new();
        Self::digest_without_signature(
            &mut hasher,
            authority,
            round,
            block_references,
            acknowledgment_references,
            meta_creation_time_ns,
            merkle_root,
            strong_vote,
        );
        hasher.update(signature.as_bytes());
        Self(hasher.finalize().into())
    }

    pub fn new(
        authority: AuthorityIndex,
        round: RoundNumber,
        block_references: &[BlockReference],
        acknowledgment_references: &[BlockReference],
        meta_creation_time_ns: TimestampNs,
        signature: &SignatureBytes,
        transactions_commitment: TransactionsCommitment,
        strong_vote: Option<bool>,
    ) -> Self {
        let mut hasher = Blake3Hasher::new();
        Self::digest_without_signature(
            &mut hasher,
            authority,
            round,
            block_references,
            acknowledgment_references,
            meta_creation_time_ns,
            transactions_commitment,
            strong_vote,
        );
        hasher.update(signature.as_bytes());
        Self(hasher.finalize().into())
    }

    pub(crate) fn digest_without_signature(
        hasher: &mut Blake3Hasher,
        authority: AuthorityIndex,
        round: RoundNumber,
        block_references: &[BlockReference],
        acknowledgment_references: &[BlockReference],
        meta_creation_time_ns: TimestampNs,
        transactions_commitment: TransactionsCommitment,
        strong_vote: Option<bool>,
    ) {
        authority.crypto_hash(hasher);
        round.crypto_hash(hasher);
        for block_ref in block_references {
            block_ref.crypto_hash(hasher);
        }
        for block_ref in acknowledgment_references {
            block_ref.crypto_hash(hasher);
        }
        meta_creation_time_ns.crypto_hash(hasher);
        transactions_commitment.crypto_hash(hasher);
        // Conditional hashing: only hash when Some for backward compatibility
        if let Some(sv) = strong_vote {
            [sv as u8].crypto_hash(hasher);
        }
    }
}

pub trait AsBytes {
    // This is pretty much same as AsRef<[u8]>
    //
    // We need this separate trait because we want to impl CryptoHash
    // for primitive types(u64, etc) and types like XxxDigest that implement
    // AsRef<[u8]>.
    //
    // Rust unfortunately does not allow to impl trait for AsRef<[u8]> and primitive
    // types like u64.
    //
    // While AsRef<[u8]> is not implemented for u64, it seem to be reserved in
    // compiler, so `impl CryptoHash for u64` and `impl<T: AsRef<[u8]>>
    // CryptoHash for T` collide.
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

// impl CryptoHash for TransactionDigest {
// fn crypto_hash(&self, state: &mut BlockHasher) {
// state.update(self.as_ref());
// }
// }

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
        header: &BlockHeader,
    ) -> Result<(), ed25519_consensus::Error> {
        let signature = Signature::from(header.signature().0);
        let acknowledgments = header.acknowledgments();
        let mut hasher = Blake3Hasher::new();
        BlockDigest::digest_without_signature(
            &mut hasher,
            header.author(),
            header.round(),
            header.block_references(),
            &acknowledgments,
            header.meta_creation_time_ns(),
            header.merkle_root(),
            header.strong_vote(),
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
        block_references: &[BlockReference],
        acknowledgment_references: &[BlockReference],
        meta_creation_time_ns: TimestampNs,
        transactions_commitment: TransactionsCommitment,
        strong_vote: Option<bool>,
    ) -> SignatureBytes {
        let mut hasher = Blake3Hasher::new();
        BlockDigest::digest_without_signature(
            &mut hasher,
            authority,
            round,
            block_references,
            acknowledgment_references,
            meta_creation_time_ns,
            transactions_commitment,
            strong_vote,
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

// ---------------------------------------------------------------------------
// BLS12-381 types (min_pk variant: 48-byte G1 public keys, 96-byte G2
// signatures).
// ---------------------------------------------------------------------------

pub const BLS_SIGNATURE_SIZE: usize = 96;
pub const BLS_PUBLIC_KEY_SIZE: usize = 48;

/// Domain separation tag for BLS signatures in Starfish.
pub(crate) const BLS_DST: &[u8] = b"STARFISH_BLS_SIG";

#[derive(Clone, Copy, Eq, Ord, PartialOrd, PartialEq, Hash)]
pub struct BlsSignatureBytes(pub(crate) [u8; BLS_SIGNATURE_SIZE]);

impl Default for BlsSignatureBytes {
    fn default() -> Self {
        Self([0u8; BLS_SIGNATURE_SIZE])
    }
}

#[derive(Clone)]
pub struct BlsPublicKey(bls::PublicKey);

/// BLS secret key. Boxed to avoid stack copies of key material.
#[derive(Clone)]
pub struct BlsSigner(Box<bls::SecretKey>);

// --- BlsSignatureBytes impls ---

impl AsBytes for BlsSignatureBytes {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for BlsSignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ByteRepr for BlsSignatureBytes {
    fn try_copy_from_slice<E: de::Error>(v: &[u8]) -> Result<Self, E> {
        if v.len() != BLS_SIGNATURE_SIZE {
            return Err(E::custom(format!(
                "Invalid BLS signature length: {}",
                v.len()
            )));
        }
        let mut inner = [0u8; BLS_SIGNATURE_SIZE];
        inner.copy_from_slice(v);
        Ok(Self(inner))
    }
}

impl Serialize for BlsSignatureBytes {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for BlsSignatureBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(BytesVisitor::new())
    }
}

impl fmt::Debug for BlsSignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsSig({})", &hex::encode(&self.0[..4]))
    }
}

// --- BlsPublicKey impls ---

impl BlsPublicKey {
    pub fn verify(
        &self,
        digest: &[u8; 32],
        sig: &BlsSignatureBytes,
    ) -> Result<(), blst::BLST_ERROR> {
        let signature =
            bls::Signature::from_bytes(&sig.0).map_err(|_| blst::BLST_ERROR::BLST_BAD_ENCODING)?;
        let result = signature.verify(true, digest, BLS_DST, &[], &self.0, true);
        if result == blst::BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(result)
        }
    }

    pub fn to_bytes(&self) -> [u8; BLS_PUBLIC_KEY_SIZE] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; BLS_PUBLIC_KEY_SIZE]) -> Result<Self, blst::BLST_ERROR> {
        bls::PublicKey::from_bytes(bytes).map(Self)
    }

    /// Access the inner `blst::min_pk::PublicKey`.
    pub fn inner(&self) -> &bls::PublicKey {
        &self.0
    }
}

impl PartialEq for BlsPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}
impl Eq for BlsPublicKey {}

impl Serialize for BlsPublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for BlsPublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BlsPkVisitor;
        impl<'de> de::Visitor<'de> for BlsPkVisitor {
            type Value = BlsPublicKey;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("48-byte BLS public key")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() != BLS_PUBLIC_KEY_SIZE {
                    return Err(E::custom(format!(
                        "Invalid BLS public key length: {}",
                        v.len()
                    )));
                }
                let mut buf = [0u8; BLS_PUBLIC_KEY_SIZE];
                buf.copy_from_slice(v);
                BlsPublicKey::from_bytes(&buf)
                    .map_err(|e| E::custom(format!("Invalid BLS public key: {:?}", e)))
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                self.visit_bytes(&v)
            }
        }
        deserializer.deserialize_bytes(BlsPkVisitor)
    }
}

impl fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsPk({})", &hex::encode(&self.to_bytes()[..4]))
    }
}

// --- BlsSigner impls ---

impl BlsSigner {
    /// Deterministic keygen for tests. Generates `n` signers from sequential
    /// seeds.
    pub fn new_for_test(n: usize) -> Vec<Self> {
        (0..n)
            .map(|i| {
                let mut ikm = [0u8; 32];
                ikm[..8].copy_from_slice(&(i as u64).to_le_bytes());
                let sk = bls::SecretKey::key_gen(&ikm, &[]).expect("BLS keygen");
                Self(Box::new(sk))
            })
            .collect()
    }

    /// Sign a 32-byte digest using BLS with the Starfish DST.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> BlsSignatureBytes {
        let sig = self.0.sign(digest, BLS_DST, &[]);
        BlsSignatureBytes(sig.to_bytes())
    }

    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(self.0.sk_to_pk())
    }

    /// Access the inner `blst::min_pk::SecretKey`.
    pub fn inner(&self) -> &bls::SecretKey {
        &self.0
    }
}

impl fmt::Debug for BlsSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsSigner(pk={:?})", self.public_key())
    }
}

impl fmt::Display for BlsSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsSigner(pk={:?})", self.public_key())
    }
}

impl Serialize for BlsSigner {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> Deserialize<'de> for BlsSigner {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BlsSkVisitor;
        impl<'de> de::Visitor<'de> for BlsSkVisitor {
            type Value = BlsSigner;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("32-byte BLS secret key")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() != 32 {
                    return Err(E::custom(format!(
                        "Invalid BLS secret key length: {}",
                        v.len()
                    )));
                }
                let mut buf = [0u8; 32];
                buf.copy_from_slice(v);
                let sk = bls::SecretKey::from_bytes(&buf)
                    .map_err(|e| E::custom(format!("Invalid BLS secret key: {:?}", e)))?;
                Ok(BlsSigner(Box::new(sk)))
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                self.visit_bytes(&v)
            }
        }
        deserializer.deserialize_bytes(BlsSkVisitor)
    }
}

impl Drop for BlsSigner {
    fn drop(&mut self) {
        // Zeroize the secret key material. blst::SecretKey stores a 32-byte
        // scalar internally. We rewrite it with a dummy key from zeroed IKM.
        let zero_sk = bls::SecretKey::key_gen(&[0u8; 32], &[]).expect("BLS keygen");
        *self.0 = zero_sk;
    }
}

/// Aggregate N partial BLS signatures into one 96-byte signature.
#[allow(dead_code)]
pub fn bls_aggregate(sigs: &[&BlsSignatureBytes]) -> BlsSignatureBytes {
    assert!(!sigs.is_empty(), "Cannot aggregate zero signatures");
    let parsed: Vec<bls::Signature> = sigs
        .iter()
        .map(|s| bls::Signature::from_bytes(&s.0).expect("valid BLS signature bytes"))
        .collect();
    let refs: Vec<&bls::Signature> = parsed.iter().collect();
    let agg = bls::AggregateSignature::aggregate(&refs, true).expect("BLS aggregation");
    BlsSignatureBytes(agg.to_signature().to_bytes())
}

/// Verify an aggregate signature against multiple public keys (all signed same
/// message).
#[allow(dead_code)]
pub fn bls_fast_aggregate_verify(
    message: &[u8],
    agg_sig: &BlsSignatureBytes,
    pubkeys: &[&BlsPublicKey],
) -> bool {
    let sig = match bls::Signature::from_bytes(&agg_sig.0) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pks: Vec<&bls::PublicKey> = pubkeys.iter().map(|pk| &pk.0).collect();
    let result = sig.fast_aggregate_verify(true, message, BLS_DST, &pks);
    result == blst::BLST_ERROR::BLST_SUCCESS
}

pub fn dummy_bls_signer() -> BlsSigner {
    let ikm = [0u8; 32];
    let sk = bls::SecretKey::key_gen(&ikm, &[]).expect("BLS keygen");
    BlsSigner(Box::new(sk))
}

pub fn dummy_bls_public_key() -> BlsPublicKey {
    dummy_bls_signer().public_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bls_sign_verify_roundtrip() {
        let signers = BlsSigner::new_for_test(3);
        for signer in &signers {
            let msg = [0xABu8; 32];
            let sig = signer.sign_digest(&msg);
            let pk = signer.public_key();
            assert!(pk.verify(&msg, &sig).is_ok());
        }
    }

    #[test]
    fn bls_wrong_key_rejects() {
        let signers = BlsSigner::new_for_test(2);
        let msg = [0xCDu8; 32];
        let sig = signers[0].sign_digest(&msg);
        let wrong_pk = signers[1].public_key();
        assert!(wrong_pk.verify(&msg, &sig).is_err());
    }

    #[test]
    fn bls_wrong_message_rejects() {
        let signers = BlsSigner::new_for_test(1);
        let msg = [1u8; 32];
        let sig = signers[0].sign_digest(&msg);
        let pk = signers[0].public_key();
        let wrong_msg = [2u8; 32];
        assert!(pk.verify(&wrong_msg, &sig).is_err());
    }

    #[test]
    fn bls_serde_roundtrip() {
        let signers = BlsSigner::new_for_test(1);
        let pk = signers[0].public_key();
        let bytes = pk.to_bytes();
        let pk2 = BlsPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn bls_signature_bytes_serde_roundtrip() {
        let signers = BlsSigner::new_for_test(1);
        let msg = [42u8; 32];
        let sig = signers[0].sign_digest(&msg);
        let encoded = bincode::serialize(&sig).unwrap();
        let decoded: BlsSignatureBytes = bincode::deserialize(&encoded).unwrap();
        assert_eq!(sig, decoded);
    }
}
