// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Batch BLS12-381 signature verification using `blst::Pairing`.
//!
//! Accumulates `(message, signature, public_key)` triples and verifies them
//! in a single multi-pairing check. On failure, falls back to individual
//! verification to identify bad signatures.

use std::cell::RefCell;

use blst::min_sig as bls;
use rand::{Rng, SeedableRng, rngs::SmallRng};

use crate::crypto::{BLS_DST, BlsPublicKey, BlsSignatureBytes};

thread_local! {
    /// Random scalar source for batch verification. Seeded once per worker
    /// thread from the OS, then reused across all batches on that thread.
    /// Avoids the per-batch `getrandom(2)` syscall cost from the previous
    /// `SmallRng::from_entropy()`. Security note: scalars must be
    /// unpredictable to an adversary at the moment they're used; a per-thread
    /// `SmallRng` seeded from `OsRng` satisfies that — the adversary doesn't
    /// see internal RNG state and can't influence which scalars are paired
    /// with which signatures.
    static BATCH_RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_entropy());
}

/// A single verification task within a batch.
pub struct BlsVerificationTask {
    /// The 32-byte message digest that was signed.
    pub message: [u8; 32],
    /// The BLS signature to verify.
    pub signature: BlsSignatureBytes,
    /// The signer's public key.
    pub public_key: BlsPublicKey,
    /// Caller-defined index for identifying bad entries on failure.
    pub block_index: usize,
}

/// Batch BLS verifier using `blst::Pairing` for efficient multi-pairing.
pub struct BlsBatchVerifier;

impl BlsBatchVerifier {
    /// Verify a batch of BLS signatures in a single multi-pairing check.
    ///
    /// Returns `Ok(())` if all signatures are valid. On failure, falls back
    /// to individual verification and returns `Err(bad_indices)` with the
    /// `block_index` values of the invalid entries.
    pub fn verify_batch(tasks: &[BlsVerificationTask]) -> Result<(), Vec<usize>> {
        if tasks.is_empty() {
            return Ok(());
        }

        // Single signature: skip batch overhead.
        if tasks.len() == 1 {
            return if Self::verify_single(
                &tasks[0].message,
                &tasks[0].signature,
                &tasks[0].public_key,
            ) {
                Ok(())
            } else {
                Err(vec![tasks[0].block_index])
            };
        }

        // Batch verification via blst::Pairing with random scalars drawn
        // from the per-thread RNG (cheaper than reseeding from /dev/urandom
        // on every call).
        let mut pairing = blst::Pairing::new(false, BLS_DST);

        for task in tasks {
            let sig = match bls::Signature::from_bytes(&task.signature.0) {
                Ok(s) => s,
                Err(_) => {
                    // Malformed signature — fall back immediately.
                    return Self::fallback_individual(tasks);
                }
            };

            // Random 64-bit scalar for subgroup security.
            let rand_bytes = BATCH_RNG.with(|rng| rng.borrow_mut().gen::<[u8; 8]>());

            // Convert to affine types for blst::Pairing which uses `dyn Any`
            // downcasting (min_sig: pk=blst_p2_affine, sig=blst_p1_affine).
            let pk_aff: &blst::blst_p2_affine = task.public_key.inner().into();
            let sig_aff: &blst::blst_p1_affine = (&sig).into();

            let result = pairing.mul_n_aggregate(
                pk_aff,
                false, // pk_validate (committee keys validated once at startup)
                sig_aff,
                // sig_groupcheck: blst::Signature::from_bytes only decompresses
                // the curve point — it does NOT verify that the point lies in
                // the prime-order subgroup of G1. Without this check, a
                // malicious signer could craft a non-subgroup signature that
                // still passes finalverify, breaking message-binding under
                // known conjugate-element attacks.
                true,
                &rand_bytes,
                64, // nbits
                &task.message,
                &[], // aug (no augmentation)
            );
            if result != blst::BLST_ERROR::BLST_SUCCESS {
                return Self::fallback_individual(tasks);
            }
        }

        pairing.commit();

        if pairing.finalverify(None) {
            Ok(())
        } else {
            Self::fallback_individual(tasks)
        }
    }

    /// Verify a single BLS signature.
    pub fn verify_single(
        message: &[u8; 32],
        signature: &BlsSignatureBytes,
        public_key: &BlsPublicKey,
    ) -> bool {
        public_key.verify_trusted(message, signature).is_ok()
    }

    /// Verify a batch of BLS signatures across multiple threads.
    ///
    /// Splits the tasks into `num_workers` chunks, each verified in its own
    /// `blst::Pairing`. The calling thread processes one chunk while
    /// `num_workers - 1` OS threads handle the rest via `std::thread::scope`.
    pub fn verify_batch_parallel(
        tasks: &[BlsVerificationTask],
        num_workers: usize,
    ) -> Result<(), Vec<usize>> {
        if tasks.len() <= num_workers || num_workers <= 1 {
            return Self::verify_batch(tasks);
        }

        let chunk_size = tasks.len().div_ceil(num_workers);
        let mut all_bad = Vec::new();

        std::thread::scope(|s| {
            // Spawn workers for all chunks except the first.
            let handles: Vec<_> = tasks[chunk_size..]
                .chunks(chunk_size)
                .map(|chunk| s.spawn(|| Self::verify_batch(chunk)))
                .collect();

            // Process the first chunk on the calling thread.
            if let Err(bad) = Self::verify_batch(&tasks[..chunk_size]) {
                all_bad.extend(bad);
            }

            for handle in handles {
                if let Err(bad) = handle.join().expect("BLS worker panicked") {
                    all_bad.extend(bad);
                }
            }
        });

        if all_bad.is_empty() {
            Ok(())
        } else {
            Err(all_bad)
        }
    }

    /// Individual fallback: verify each task independently and collect bad
    /// indices.
    fn fallback_individual(tasks: &[BlsVerificationTask]) -> Result<(), Vec<usize>> {
        let bad: Vec<usize> = tasks
            .iter()
            .filter(|t| !Self::verify_single(&t.message, &t.signature, &t.public_key))
            .map(|t| t.block_index)
            .collect();

        if bad.is_empty() {
            // Rare: batch failed but individuals all pass (randomized check
            // false positive is negligible). Treat as OK.
            Ok(())
        } else {
            Err(bad)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BlsSigner;

    #[test]
    fn single_valid_signature() {
        let signers = BlsSigner::new_for_test(1);
        let msg = [42u8; 32];
        let sig = signers[0].sign_digest(&msg);
        let pk = signers[0].public_key();

        assert!(BlsBatchVerifier::verify_single(&msg, &sig, &pk));
    }

    #[test]
    fn single_invalid_signature() {
        let signers = BlsSigner::new_for_test(2);
        let msg = [42u8; 32];
        let sig = signers[0].sign_digest(&msg);
        let wrong_pk = signers[1].public_key();

        assert!(!BlsBatchVerifier::verify_single(&msg, &sig, &wrong_pk));
    }

    #[test]
    fn batch_all_valid() {
        let n = 10;
        let signers = BlsSigner::new_for_test(n);
        let tasks: Vec<_> = (0..n)
            .map(|i| {
                let mut msg = [0u8; 32];
                msg[0] = i as u8;
                let sig = signers[i].sign_digest(&msg);
                BlsVerificationTask {
                    message: msg,
                    signature: sig,
                    public_key: signers[i].public_key(),
                    block_index: i,
                }
            })
            .collect();

        assert!(BlsBatchVerifier::verify_batch(&tasks).is_ok());
    }

    #[test]
    fn batch_one_invalid_identifies_bad_index() {
        let n = 5;
        let signers = BlsSigner::new_for_test(n + 1);
        let bad_idx = 3;

        let tasks: Vec<_> = (0..n)
            .map(|i| {
                let mut msg = [0u8; 32];
                msg[0] = i as u8;
                let sig = signers[i].sign_digest(&msg);
                let pk = if i == bad_idx {
                    // Use wrong public key for bad_idx.
                    signers[n].public_key()
                } else {
                    signers[i].public_key()
                };
                BlsVerificationTask {
                    message: msg,
                    signature: sig,
                    public_key: pk,
                    block_index: i,
                }
            })
            .collect();

        let result = BlsBatchVerifier::verify_batch(&tasks);
        assert!(result.is_err());
        let bad_indices = result.unwrap_err();
        assert_eq!(bad_indices, vec![bad_idx]);
    }

    #[test]
    fn batch_empty() {
        assert!(BlsBatchVerifier::verify_batch(&[]).is_ok());
    }
}
