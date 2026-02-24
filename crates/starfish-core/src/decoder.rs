// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::committee::Committee;
use crate::crypto::TransactionsCommitment;
use crate::encoder::{Encoder, ShardEncoder};
use crate::types::{AuthorityIndex, CachedStatementBlock, Shard, VerifiedStatementBlock};
use reed_solomon_simd::ReedSolomonDecoder;
use std::collections::HashMap;

pub type Decoder = ReedSolomonDecoder;

pub trait CachedStatementBlockDecoder {
    fn decode_shards(
        &mut self,
        committee: &Committee,
        encoder: &mut Encoder,
        cached_statement_block: CachedStatementBlock,
        own_id: AuthorityIndex,
    ) -> Option<VerifiedStatementBlock>;
}

impl CachedStatementBlockDecoder for Decoder {
    fn decode_shards(
        &mut self,
        committee: &Committee,
        encoder: &mut Encoder,
        cached_block: CachedStatementBlock,
        own_id: AuthorityIndex,
    ) -> Option<VerifiedStatementBlock> {
        let info_length = committee.info_length();
        let total_length = committee.len();
        let parity_length = total_length - info_length;
        let position = cached_block
            .encoded_statements()
            .iter()
            .position(|x| x.is_some());
        let position = position
            .expect("Expect a block in cached blocks with a sufficient number of available shards");
        let shard_size = cached_block.encoded_statements()[position]
            .as_ref()
            .unwrap()
            .len();
        self.reset(info_length, parity_length, shard_size)
            .expect("decoder reset failed");
        for i in 0..info_length {
            if cached_block.encoded_statements()[i].is_some() {
                self.add_original_shard(i, cached_block.encoded_statements()[i].as_ref().unwrap())
                    .expect("adding shard failed")
            }
        }
        for i in info_length..total_length {
            if cached_block.encoded_statements()[i].is_some() {
                self.add_recovery_shard(
                    i - info_length,
                    cached_block.encoded_statements()[i].as_ref().unwrap(),
                )
                .expect("adding shard failed")
            }
        }

        let mut data: Vec<Shard> = vec![vec![]; info_length];
        for (i, item) in data.iter_mut().enumerate().take(info_length) {
            if cached_block.encoded_statements()[i].is_some() {
                *item = cached_block.encoded_statements()[i].clone().unwrap();
            }
        }
        let result = self.decode().expect("Decoding should be correct");
        let restored: HashMap<_, _> = result.restored_original_iter().collect();
        for el in restored {
            data[el.0] = Shard::from(el.1);
        }
        drop(result);

        let recovered_statements = encoder.encode_shards(data, info_length, parity_length);
        let (computed_merkle_root, computed_merkle_proof) =
            TransactionsCommitment::new_from_encoded_statements(
                &recovered_statements,
                own_id as usize,
            );

        if computed_merkle_root == cached_block.merkle_root() {
            let mut reconstructed_cached_block = cached_block;
            for (i, item) in recovered_statements.iter().enumerate().take(total_length) {
                if reconstructed_cached_block.encoded_statements()[i].is_none() {
                    reconstructed_cached_block.add_encoded_shard(i, item.clone());
                }
            }
            let storage_block: VerifiedStatementBlock = reconstructed_cached_block
                .to_verified_block(own_id as usize, computed_merkle_proof, info_length);
            return Some(storage_block);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_store::ConsensusProtocol;
    use crate::crypto::Signer;
    use crate::types::{BaseStatement, Transaction};

    fn make_test_block(
        statements: Vec<BaseStatement>,
        authority: AuthorityIndex,
        committee: &Committee,
        encoder: &mut Encoder,
        signer: &Signer,
    ) -> (VerifiedStatementBlock, Vec<Shard>) {
        let info_length = committee.info_length();
        let parity_length = committee.len() - info_length;
        let encoded = encoder.encode_statements(statements.clone(), info_length, parity_length);
        let block = VerifiedStatementBlock::new_with_signer(
            authority,
            1,
            vec![],
            vec![],
            0,
            false,
            signer,
            statements,
            Some(encoded.clone()),
            ConsensusProtocol::Starfish,
            None,
        );
        (block, encoded)
    }

    #[test]
    fn decode_successful_with_info_shards_only() {
        let committee_size = 4; // info=2, parity=2
        let signers = Signer::new_for_test(committee_size);
        let committee = Committee::new_for_benchmarks(committee_size);
        let own_id: AuthorityIndex = 0;

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let mut decoder = Decoder::new(2, 4, 2).unwrap();

        let statements = vec![
            BaseStatement::Share(Transaction::new(vec![1, 2, 3])),
            BaseStatement::Share(Transaction::new(vec![4, 5, 6, 7, 8])),
        ];

        let (block, shards) =
            make_test_block(statements.clone(), 0, &committee, &mut encoder, &signers[0]);

        // Build CachedStatementBlock with only info shards (0 and 1)
        let mut cached = block.to_cached_block(committee_size);
        for i in 0..committee.info_length() {
            cached.add_encoded_shard(i, shards[i].clone());
        }

        let result = decoder.decode_shards(&committee, &mut encoder, cached, own_id);
        assert!(
            result.is_some(),
            "decode_shards should succeed with all info shards"
        );
        let reconstructed = result.unwrap();
        assert!(
            reconstructed.statements().as_ref().unwrap() == &statements,
            "reconstructed statements should match originals"
        );
        assert!(
            reconstructed.merkle_root() == block.merkle_root(),
            "merkle root should match"
        );
    }

    #[test]
    fn decode_successful_with_parity_recovery() {
        let committee_size = 4; // info=2, parity=2
        let signers = Signer::new_for_test(committee_size);
        let committee = Committee::new_for_benchmarks(committee_size);
        let own_id: AuthorityIndex = 0;

        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let mut decoder = Decoder::new(2, 4, 2).unwrap();

        let statements = vec![BaseStatement::Share(Transaction::new(vec![42; 100]))];

        let (block, shards) =
            make_test_block(statements.clone(), 0, &committee, &mut encoder, &signers[0]);

        // Provide shard 0 (info) + shard 2 (first parity), skip shard 1 and 3
        let mut cached = block.to_cached_block(committee_size);
        cached.add_encoded_shard(0, shards[0].clone());
        cached.add_encoded_shard(2, shards[2].clone());

        let result = decoder.decode_shards(&committee, &mut encoder, cached, own_id);
        assert!(
            result.is_some(),
            "decode_shards should succeed with parity recovery"
        );
        let reconstructed = result.unwrap();
        assert!(
            reconstructed.statements().as_ref().unwrap() == &statements,
            "reconstructed statements should match originals"
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

        let statements = vec![BaseStatement::Share(Transaction::new(vec![1, 2, 3]))];

        let (block, shards) =
            make_test_block(statements.clone(), 0, &committee, &mut encoder, &signers[0]);

        // Build CachedStatementBlock with all shards, then tamper with one
        let mut cached = block.to_cached_block(committee_size);
        for (i, shard) in shards.iter().enumerate() {
            cached.add_encoded_shard(i, shard.clone());
        }
        // Tamper: overwrite info shard 0 with garbage
        cached.add_encoded_shard(0, vec![0xFF; shards[0].len()]);

        let result = decoder.decode_shards(&committee, &mut encoder, cached, own_id);
        assert!(
            result.is_none(),
            "decode_shards should return None on merkle mismatch"
        );
    }
}
