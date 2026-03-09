// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use reed_solomon_simd::ReedSolomonDecoder;

use crate::{
    committee::Committee,
    crypto::TransactionsCommitment,
    encoder::{Encoder, ShardEncoder},
    types::{AuthorityIndex, ProvableShard, Shard, TransactionData},
};

pub type Decoder = ReedSolomonDecoder;

/// Decode transaction data from collected shards + block header.
///
/// Returns `Some((TransactionData, ProvableShard))` with the reconstructed
/// transactions and the caller's own shard+proof, or `None` on merkle mismatch.
pub fn decode_shards(
    decoder: &mut Decoder,
    committee: &Committee,
    encoder: &mut Encoder,
    merkle_root: TransactionsCommitment,
    shards: &[Option<Shard>],
    own_id: AuthorityIndex,
) -> Option<(TransactionData, ProvableShard)> {
    let info_length = committee.info_length();
    let total_length = committee.len();
    let parity_length = total_length - info_length;

    let position = shards.iter().position(|x| x.is_some());
    let position = position.expect("Expect shards with a sufficient number of available shards");
    let shard_size = shards[position].as_ref().unwrap().len();

    decoder
        .reset(info_length, parity_length, shard_size)
        .expect("decoder reset failed");

    for (i, slot) in shards.iter().enumerate().take(info_length) {
        if let Some(shard) = slot {
            decoder
                .add_original_shard(i, shard)
                .expect("adding shard failed");
        }
    }
    for (i, slot) in shards
        .iter()
        .enumerate()
        .take(total_length)
        .skip(info_length)
    {
        if let Some(shard) = slot {
            decoder
                .add_recovery_shard(i - info_length, shard)
                .expect("adding shard failed");
        }
    }

    let mut data: Vec<Shard> = vec![vec![]; info_length];
    for (i, item) in data.iter_mut().enumerate().take(info_length) {
        if let Some(shard) = &shards[i] {
            *item = shard.clone();
        }
    }
    let result = decoder.decode().expect("Decoding should be correct");
    let restored: HashMap<_, _> = result.restored_original_iter().collect();
    for el in restored {
        data[el.0] = Shard::from(el.1);
    }
    drop(result);

    let recovered_transactions = encoder.encode_shards(data, info_length, parity_length);
    let (computed_merkle_root, computed_merkle_proof) =
        TransactionsCommitment::new_from_encoded_transactions(
            &recovered_transactions,
            own_id as usize,
        );

    if computed_merkle_root == merkle_root {
        let transactions =
            reconstruct_transactions_from_shards(&recovered_transactions, info_length);
        let own_shard = ProvableShard::new(
            recovered_transactions[own_id as usize].clone(),
            own_id as usize,
            computed_merkle_proof,
            computed_merkle_root,
        );
        Some((TransactionData::new(transactions), own_shard))
    } else {
        None
    }
}

/// Reconstruct transactions by concatenating info shards and deserializing.
fn reconstruct_transactions_from_shards(
    encoded_transactions: &[Shard],
    info_length: usize,
) -> Vec<crate::types::BaseTransaction> {
    let reconstructed_data: Vec<u8> = encoded_transactions
        .iter()
        .take(info_length)
        .flat_map(|s| s.iter().copied())
        .collect();

    assert!(
        reconstructed_data.len() >= 4,
        "Reconstructed data is too short to contain a valid length"
    );

    let bytes_length = u32::from_le_bytes(
        reconstructed_data[0..4]
            .try_into()
            .expect("Failed to read bytes_length"),
    ) as usize;

    assert!(
        reconstructed_data.len() >= 4 + bytes_length,
        "Reconstructed data length {} does not match declared bytes_length {}",
        reconstructed_data.len(),
        bytes_length
    );
    tracing::debug!(
        "Reconstructed data length {}, bytes_length {}",
        reconstructed_data.len(),
        bytes_length
    );

    bincode::deserialize(&reconstructed_data[4..4 + bytes_length])
        .expect("Deserialization of reconstructed data failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::Signer,
        dag_state::ConsensusProtocol,
        encoder::ShardEncoder,
        types::{BaseTransaction, Transaction, VerifiedBlock},
    };

    fn make_test_block(
        transactions: Vec<BaseTransaction>,
        authority: AuthorityIndex,
        committee: &Committee,
        encoder: &mut Encoder,
        signer: &Signer,
    ) -> (VerifiedBlock, Vec<Shard>) {
        let info_length = committee.info_length();
        let parity_length = committee.len() - info_length;
        let encoded = encoder.encode_transactions(&transactions, info_length, parity_length);
        let block = VerifiedBlock::new_with_signer(
            authority,
            1,
            vec![],
            None,
            vec![],
            0,
            signer,
            None,
            None,
            vec![],
            transactions,
            Some(encoded.clone()),
            ConsensusProtocol::Starfish,
            None,
            None,
            None,
        );
        (block, encoded)
    }

    #[test]
    fn decode_successful_with_info_shards_only() {
        let committee_size = 4;
        let signers = Signer::new_for_test(committee_size);
        let committee = Committee::new_for_benchmarks(committee_size);
        let own_id: AuthorityIndex = 0;

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let mut decoder = Decoder::new(2, 4, 2).unwrap();

        let transactions = vec![
            BaseTransaction::Share(Transaction::new(vec![1, 2, 3])),
            BaseTransaction::Share(Transaction::new(vec![4, 5, 6, 7, 8])),
        ];

        let (block, shards) = make_test_block(
            transactions.clone(),
            0,
            &committee,
            &mut encoder,
            &signers[0],
        );

        // Build shard collection with only info shards (0 and 1)
        let mut shard_slots: Vec<Option<Shard>> = vec![None; committee_size];
        for (i, shard) in shards[..committee.info_length()].iter().enumerate() {
            shard_slots[i] = Some(shard.clone());
        }

        let result = decode_shards(
            &mut decoder,
            &committee,
            &mut encoder,
            block.merkle_root(),
            &shard_slots,
            own_id,
        );
        assert!(
            result.is_some(),
            "decode_shards should succeed with all info shards"
        );
        let (tx_data, own_shard) = result.unwrap();
        assert_eq!(
            tx_data.transactions(),
            &transactions,
            "reconstructed transactions should match originals"
        );
        assert!(
            own_shard.transactions_commitment() == block.merkle_root(),
            "merkle root should match"
        );
    }

    #[test]
    fn decode_successful_with_parity_recovery() {
        let committee_size = 4;
        let signers = Signer::new_for_test(committee_size);
        let committee = Committee::new_for_benchmarks(committee_size);
        let own_id: AuthorityIndex = 0;

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let mut decoder = Decoder::new(2, 4, 2).unwrap();

        let transactions = vec![BaseTransaction::Share(Transaction::new(vec![42; 100]))];

        let (block, shards) = make_test_block(
            transactions.clone(),
            0,
            &committee,
            &mut encoder,
            &signers[0],
        );

        // Provide shard 0 (info) + shard 2 (first parity), skip shard 1 and 3
        let mut shard_slots: Vec<Option<Shard>> = vec![None; committee_size];
        shard_slots[0] = Some(shards[0].clone());
        shard_slots[2] = Some(shards[2].clone());

        let result = decode_shards(
            &mut decoder,
            &committee,
            &mut encoder,
            block.merkle_root(),
            &shard_slots,
            own_id,
        );
        assert!(
            result.is_some(),
            "decode_shards should succeed with parity recovery"
        );
        let (tx_data, _own_shard) = result.unwrap();
        assert_eq!(
            tx_data.transactions(),
            &transactions,
            "reconstructed transactions should match originals"
        );
    }

    #[test]
    fn decode_returns_none_on_merkle_mismatch() {
        let committee_size = 4;
        let signers = Signer::new_for_test(committee_size);
        let committee = Committee::new_for_benchmarks(committee_size);
        let own_id: AuthorityIndex = 0;

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let mut decoder = Decoder::new(2, 4, 2).unwrap();

        let transactions = vec![BaseTransaction::Share(Transaction::new(vec![1, 2, 3]))];

        let (block, shards) =
            make_test_block(transactions, 0, &committee, &mut encoder, &signers[0]);

        // Build shards with tampered data
        let mut shard_slots: Vec<Option<Shard>> = vec![None; committee_size];
        for (i, shard) in shards.iter().enumerate() {
            shard_slots[i] = Some(shard.clone());
        }
        // Tamper: overwrite info shard 0 with garbage
        shard_slots[0] = Some(vec![0xFF; shards[0].len()]);

        let result = decode_shards(
            &mut decoder,
            &committee,
            &mut encoder,
            block.merkle_root(),
            &shard_slots,
            own_id,
        );
        assert!(
            result.is_none(),
            "decode_shards should return None on merkle mismatch"
        );
    }
}
