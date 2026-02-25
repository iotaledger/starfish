// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::types::{BaseStatement, Shard};
use reed_solomon_simd::ReedSolomonEncoder;

pub type Encoder = ReedSolomonEncoder;

pub trait ShardEncoder {
    fn encode_shards(
        &mut self,
        data: Vec<Shard>,
        info_length: usize,
        parity_length: usize,
    ) -> Vec<Shard>;

    fn encode_statements(
        &mut self,
        block: Vec<BaseStatement>,
        info_length: usize,
        parity_length: usize,
    ) -> Vec<Shard>;
}

impl ShardEncoder for Encoder {
    fn encode_shards(
        &mut self,
        mut data: Vec<Shard>,
        info_length: usize,
        parity_length: usize,
    ) -> Vec<Shard> {
        let shard_bytes = data[0].len();
        self.reset(info_length, parity_length, shard_bytes)
            .expect("Reset failed");
        for shard in data.clone() {
            self.add_original_shard(shard).expect("Adding shard failed");
        }
        let result = self.encode().expect("Encoding failed");
        let recovery: Vec<Shard> = result.recovery_iter().map(|slice| slice.to_vec()).collect();
        data.extend(recovery);
        data
    }

    fn encode_statements(
        &mut self,
        block: Vec<BaseStatement>,
        info_length: usize,
        parity_length: usize,
    ) -> Vec<Shard> {
        let mut serialized =
            bincode::serialize(&block).expect("Serialization of statements before encoding failed");
        let bytes_length = serialized.len();
        let mut statements_with_len: Vec<u8> = (bytes_length as u32).to_le_bytes().to_vec();
        statements_with_len.append(&mut serialized);
        // increase the length by 4 for u32
        let mut shard_bytes = (bytes_length + 4).div_ceil(info_length);

        // Ensure shard_bytes meets alignment requirements (must be multiple of 2).
        if !shard_bytes.is_multiple_of(2) {
            shard_bytes += 1;
        }

        let length_with_padding = shard_bytes * info_length;
        statements_with_len.resize(length_with_padding, 0);

        let data: Vec<Shard> = statements_with_len
            .chunks(shard_bytes)
            .map(|chunk| chunk.to_vec())
            .collect();

        self.encode_shards(data, info_length, parity_length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::Committee;
    use crate::types::{BaseStatement, Transaction};
    use rand::prelude::SliceRandom;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use reed_solomon_simd::ReedSolomonDecoder;
    use std::collections::HashMap;

    fn random_statements(rng: &mut impl Rng, count: usize, tx_size: usize) -> Vec<BaseStatement> {
        (0..count)
            .map(|_| {
                let data: Vec<u8> = (0..tx_size).map(|_| rng.gen::<u8>()).collect();
                BaseStatement::Share(Transaction::new(data))
            })
            .collect()
    }

    #[test]
    #[should_panic]
    fn encode_should_fail_mismatched_length() {
        let mut encoder = ReedSolomonEncoder::new(2, 2, 2).unwrap();
        // 3 shards but info_length=2 → will panic at add_original_shard
        let data = vec![vec![0u8; 64]; 3];
        encoder.encode_shards(data, 2, 2);
    }

    #[test]
    fn rs_encode_decode_round_trip() {
        let mut rng = StdRng::seed_from_u64(42);

        for committee_size in 4..10 {
            let committee = Committee::new_for_benchmarks(committee_size);
            let info_length = committee.info_length();
            let parity_length = committee_size - info_length;

            let mut encoder = ReedSolomonEncoder::new(2, 4, 2).unwrap();
            let mut decoder = ReedSolomonDecoder::new(2, 4, 2).unwrap();

            for _ in 0..10 {
                let num_tx = rng.gen_range(1..8);
                let tx_size = rng.gen_range(1..200);
                let statements = random_statements(&mut rng, num_tx, tx_size);

                let shards =
                    encoder.encode_statements(statements.clone(), info_length, parity_length);
                assert_eq!(shards.len(), committee_size);

                // Verify alignment: every shard must be a multiple of 2
                for shard in &shards {
                    assert_eq!(
                        shard.len() % 2,
                        0,
                        "shard size {} not aligned to 2 for committee_size={}",
                        shard.len(),
                        committee_size
                    );
                }

                // Drop up to parity_length random shards
                let drop_count = rng.gen_range(0..=parity_length);
                let mut available: Vec<Option<Shard>> =
                    shards.iter().map(|s| Some(s.clone())).collect();
                let mut indices: Vec<usize> = (0..committee_size).collect();
                indices.shuffle(&mut rng);
                for &i in indices.iter().take(drop_count) {
                    available[i] = None;
                }

                // Decode via ReedSolomonDecoder
                let shard_size = shards[0].len();
                decoder
                    .reset(info_length, parity_length, shard_size)
                    .unwrap();
                for (i, shard) in available[..info_length].iter().enumerate() {
                    if let Some(ref s) = shard {
                        decoder.add_original_shard(i, s).unwrap();
                    }
                }
                for (i, shard) in available[info_length..committee_size].iter().enumerate() {
                    if let Some(ref s) = shard {
                        decoder.add_recovery_shard(i, s).unwrap();
                    }
                }

                let result = decoder.decode().unwrap();
                let mut info_shards: Vec<Shard> = (0..info_length)
                    .map(|i| available[i].clone().unwrap_or_default())
                    .collect();
                let restored: HashMap<_, _> = result.restored_original_iter().collect();
                for (idx, data) in restored {
                    info_shards[idx] = data.to_vec();
                }
                drop(result);

                // Reconstruct statements from info shards
                let reconstructed_data: Vec<u8> =
                    info_shards.iter().flat_map(|s| s.clone()).collect();
                let bytes_length =
                    u32::from_le_bytes(reconstructed_data[0..4].try_into().unwrap()) as usize;
                let reconstructed: Vec<BaseStatement> =
                    bincode::deserialize(&reconstructed_data[4..4 + bytes_length]).unwrap();
                assert!(
                    reconstructed == statements,
                    "Mismatch for committee_size={committee_size}"
                );
            }
        }
    }
}
