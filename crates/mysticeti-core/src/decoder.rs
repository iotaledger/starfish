use std::collections::HashMap;
use reed_solomon_simd::{ReedSolomonDecoder};
use crate::committee::Committee;
use crate::crypto::MerkleRoot;
use crate::encoder::{Encoder, ShardEncoder};
use crate::types::{AuthorityIndex,  CachedStatementBlock, Shard, VerifiedStatementBlock};

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
        block: CachedStatementBlock,
        own_id: AuthorityIndex,
    ) -> Option<VerifiedStatementBlock> {
        let info_length = committee.info_length();
        let total_length = committee.len();
        let parity_length = total_length - info_length;
        let position =  block.encoded_statements().iter().position(|x| x.is_some());
        let position = position.expect("Expect a block in cached blocks with a sufficient number of available shards");
        let shard_size = block.encoded_statements()[position].as_ref().unwrap().len();
        self.reset(info_length, parity_length, shard_size).expect("decoder reset failed");
        for i in 0..info_length {
            if block.encoded_statements()[i].is_some() {
                self.add_original_shard(i, block.encoded_statements()[i].as_ref().unwrap()).expect("adding shard failed")
            }
        }
        for i in info_length..total_length {
            if block.encoded_statements()[i].is_some() {
                self.add_recovery_shard(i - info_length, block.encoded_statements()[i].as_ref().unwrap()).expect("adding shard failed")
            }
        }

        let mut data: Vec<Shard> = vec![vec![]; info_length];
        for i in 0..info_length {
            if block.encoded_statements()[i].is_some() {
                data[i] = block.encoded_statements()[i].clone().unwrap();
            }
        }
        let result = self.decode().expect("Decoding should be correct");
        let restored: HashMap<_, _> = result.restored_original_iter().collect();
        for el in restored {
            data[el.0] = Shard::from(el.1);
        }
        drop(result);

        let recovered_statements = encoder.encode_shards(data, info_length, parity_length);
        let (computed_merkle_root, computed_merkle_proof) = MerkleRoot::new_from_encoded_statements(&recovered_statements, own_id as usize);
        if computed_merkle_root == block.merkle_root() {
            let storage_block: VerifiedStatementBlock = block.to_verified_block(Some((recovered_statements[own_id as usize].clone(), own_id as usize)), computed_merkle_proof);
            return Some(storage_block)
        }
        return None;
    }
}