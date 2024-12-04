// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashSet, VecDeque},
    mem,
    sync::{atomic::AtomicU64, Arc},
};
use std::collections::HashMap;
use reed_solomon_simd::ReedSolomonEncoder;
use reed_solomon_simd::ReedSolomonDecoder;
use minibytes::Bytes;

use crate::{
    block_handler::BlockHandler,
    block_manager::BlockManager,
    block_store::{
        BlockStore, BlockWriter, CommitData, OwnBlockData, WAL_ENTRY_COMMIT,
        WAL_ENTRY_STATE,
    },
    committee::Committee,
    config::{NodePrivateConfig, NodePublicConfig},
    consensus::{
        linearizer::CommittedSubDag,
        universal_committer::{UniversalCommitter, UniversalCommitterBuilder},
    },
    crypto::Signer,
    data::Data,
    epoch_close::EpochManager,
    metrics::{Metrics, UtilizationTimerVecExt},
    runtime::timestamp_utc,
    state::RecoveredState,
    threshold_clock::ThresholdClockAggregator,
    types::{AuthorityIndex, BaseStatement, BlockReference, RoundNumber, StatementBlock},
    wal::{WalPosition, WalSyncer, WalWriter},
};
use crate::crypto::{BlockDigest, MerkleRoot};
use crate::types::{Encoder, Decoder, Shard};

pub struct Core<H: BlockHandler> {
    block_manager: BlockManager,
    pending: VecDeque<(WalPosition, MetaStatement)>,
    // For Byzantine node, last_own_block contains a vector of blocks
    last_own_block: Vec<OwnBlockData>,
    block_handler: H,
    authority: AuthorityIndex,
    threshold_clock: ThresholdClockAggregator,
    pub(crate) committee: Arc<Committee>,
    last_commit_leader: BlockReference,
    wal_writer: WalWriter,
    block_store: BlockStore,
    pub(crate) metrics: Arc<Metrics>,
    options: CoreOptions,
    signer: Signer,
    // todo - ugly, probably need to merge syncer and core
    recovered_committed_blocks: Option<(HashSet<BlockReference>, Option<Bytes>)>,
    epoch_manager: EpochManager,
    rounds_in_epoch: RoundNumber,
    committer: UniversalCommitter,
    //coding_engine : reed_solomon_simd::engine::DefaultEngine,
    encoder : Encoder,
    decoder: Decoder,
}

pub struct CoreOptions {
    fsync: bool,
}

#[derive(Debug, Clone)]
pub enum MetaStatement {
    Include(BlockReference),
    Payload(Vec<BaseStatement>),
}

impl<H: BlockHandler> Core<H> {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        mut block_handler: H,
        authority: AuthorityIndex,
        committee: Arc<Committee>,
        private_config: NodePrivateConfig,
        public_config: &NodePublicConfig,
        metrics: Arc<Metrics>,
        recovered: RecoveredState,
        mut wal_writer: WalWriter,
        options: CoreOptions,
    ) -> Self {
        let RecoveredState {
            block_store,
            last_own_block,
            mut pending,
            state,
            unprocessed_blocks,
            last_committed_leader,
            committed_blocks,
            committed_state,
        } = recovered;
        let mut threshold_clock = ThresholdClockAggregator::new(0);
        let last_own_block = if let Some(own_block) = last_own_block {
            for (_, pending_block) in pending.iter() {
                if let MetaStatement::Include(include) = pending_block {
                    threshold_clock.add_block(*include, &committee);
                }
            }
            own_block
        } else {
            // todo(fix) - this technically has a race condition if node crashes after genesis
            assert!(pending.is_empty());
            // Initialize empty block store
            // A lot of this code is shared with Self::add_blocks, this is not great and some code reuse would be great
            let (own_genesis_block, other_genesis_blocks) = committee.genesis_blocks(authority);
            assert_eq!(own_genesis_block.author(), authority);
            let mut block_writer = (&mut wal_writer, &block_store);
            for block in other_genesis_blocks {
                let reference = *block.reference();
                threshold_clock.add_block(reference, &committee);
                let position = block_writer.insert_block(block);
                pending.push_back((position, MetaStatement::Include(reference)));
            }
            threshold_clock.add_block(*own_genesis_block.reference(), &committee);
            let own_block_data = OwnBlockData {
                next_entry: WalPosition::MAX,
                block: own_genesis_block,
            };
            block_writer.insert_own_block(&own_block_data, 0, committee.len() as AuthorityIndex);
            own_block_data
        };
        let block_manager = BlockManager::new(block_store.clone(), &committee);

        if let Some(state) = state {
            block_handler.recover_state(&state);
        }

        let epoch_manager = EpochManager::new();

        let committer =
            UniversalCommitterBuilder::new(committee.clone(), block_store.clone(), metrics.clone())
                .with_number_of_leaders(public_config.parameters.number_of_leaders)
                .with_pipeline(public_config.parameters.enable_pipelining)
                .build();
        tracing::info!(
            "Pipeline enabled: {}",
            public_config.parameters.enable_pipelining
        );
        tracing::info!(
            "Number of leaders: {}",
            public_config.parameters.number_of_leaders
        );
        let encoder = ReedSolomonEncoder::new(2,
                                              4,
                                              64).unwrap();
        let decoder = ReedSolomonDecoder::new(2,
                                              4,
                                              64).unwrap();
        let this = Self {
            block_manager,
            pending,
            last_own_block: vec![last_own_block],
            block_handler,
            authority,
            threshold_clock,
            committee,
            last_commit_leader: last_committed_leader.unwrap_or_default(),
            wal_writer,
            block_store,
            metrics,
            options,
            signer: private_config.keypair,
            recovered_committed_blocks: Some((committed_blocks, committed_state)),
            epoch_manager,
            rounds_in_epoch: public_config.parameters.rounds_in_epoch,
            committer,
            encoder,
            decoder,
        };

        if !unprocessed_blocks.is_empty() {
            tracing::info!(
                "Replaying {} blocks for transaction aggregator",
                unprocessed_blocks.len()
            );
        }

        this
    }

    pub fn get_universal_committer(&self) -> UniversalCommitter {
        self.committer.clone()
    }

    pub fn with_options(mut self, options: CoreOptions) -> Self {
        self.options = options;
        self
    }

    // Note that generally when you update this function you also want to change genesis initialization above
    pub fn add_blocks(&mut self, blocks: Vec<Data<StatementBlock>>) -> Vec<Data<StatementBlock>> {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::add_blocks");
        let (processed, new_blocks_to_reconstruct) = self
            .block_manager
            .add_blocks(blocks, &mut (&mut self.wal_writer, &self.block_store));
        self.reconstruct_data_blocks(new_blocks_to_reconstruct);

        let mut result = Vec::with_capacity(processed.len());
        for (position, processed) in processed.into_iter() {
            self.threshold_clock
                .add_block(*processed.reference(), &self.committee);
            self.pending
                .push_back((position, MetaStatement::Include(*processed.reference())));
            result.push(processed);
        }
        result
    }



    pub fn encode_shards(&mut self, mut data: Vec<Option<Shard>>, info_length: usize, parity_length: usize) -> Vec<Option<Shard>> {
        let shard_bytes = data[0].as_ref().unwrap().len();
        self.encoder.reset(info_length, parity_length, shard_bytes).expect("reset failed");
        for shard in data.clone() {
            self.encoder.add_original_shard(shard.unwrap()).expect("Adding shard failed");
        }
        let result = self.encoder.encode().expect("Encoding failed");
        let recovery: Vec<Option<Shard>> = result.recovery_iter().map(|slice| Some(slice.to_vec())).collect();
        data.extend(recovery);
        data
    }

    pub fn encode(&mut self, block: Vec<BaseStatement>, info_length: usize, parity_length: usize) -> Vec<Option<Shard>> {
        let mut serialized = bincode::serialize(&block).expect("Serialization of statements before encoding failed");
        let bytes_length = serialized.len();
        let mut statements_with_len:Vec<u8> = (bytes_length as u32).to_le_bytes().to_vec();
        statements_with_len.append(&mut serialized);
        let mut shard_bytes = (bytes_length + info_length - 1) / info_length;
        //shard_bytes should be divisible by 64 in version 2.2.2
        //it only needs to be even in a new version 3.0.1, but it requires a newer version of rust 1.80
        if shard_bytes % 64 != 0 {
            shard_bytes += 64 - shard_bytes % 64;
        }
        let length_with_padding = shard_bytes * info_length;
        statements_with_len.resize(length_with_padding, 0);
        let data : Vec<Option<Shard>> = statements_with_len.chunks(shard_bytes).map(|chunk| Some(chunk.to_vec())).collect();
        self.encode_shards(data, info_length, parity_length)
    }
    pub fn reconstruct_data_blocks(&mut self, new_blocks_to_reconstruct: HashSet<BlockDigest>) {
        let info_length = self.committee.info_length();
        let parity_length = self.committee.len() - info_length;
        let total_length = info_length + parity_length;

        for block_digest in new_blocks_to_reconstruct {
            let mut block = self.block_store.get_cached_block(block_digest);
            let position =  block.encoded_statements().iter().position(|x| x.is_some());
            let position = position.expect("Expect a block in cached blocks with a sufficient number of available shards");
            let shard_size = block.encoded_statements()[position].as_ref().unwrap().len();
            self.decoder.reset(info_length, parity_length, shard_size).expect("decoder reset failed");
            for i in 0..info_length {
                if block.encoded_statements()[i].is_some() {
                    self.decoder.add_original_shard(i, block.encoded_statements()[i].as_ref().unwrap()).expect("adding shard failed")
                }
            }
            for i in info_length..total_length {
                if block.encoded_statements()[i].is_some() {
                    self.decoder.add_recovery_shard(i - info_length, block.encoded_statements()[i].as_ref().unwrap()).expect("adding shard failed")
                }
            }
            let result = self.decoder.decode().expect("Decoding should be correct");
            let mut data = block.encoded_statements()[..info_length].to_vec();
            let restored: HashMap<_, _> = result.restored_original_iter().collect();
            for el in restored {
                data[el.0] = Some(Shard::from(el.1));
            }
            drop(result);

            let recovered_statements = self.encode_shards(data, info_length, parity_length);
            let (computed_merkle_root, computed_merkle_proof) = MerkleRoot::new_from_encoded_statements(&recovered_statements, self.authority);
            if computed_merkle_root == block.merkle_root() {
                block.add_encoded_statements(recovered_statements);
                block.set_merkle_proof(computed_merkle_proof);
                let block = Data::new(block);
                (&mut self.wal_writer, &self.block_store).insert_block(block.clone());
                self.block_store.update_data_availability_and_cached_blocks(&block);
                self.block_store.updated_unknown_by_others(block.reference().clone());
            }
        }
    }


    pub fn try_new_block(&mut self) -> Option<Data<StatementBlock>> {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::try_new_block");
        let clock_round = self.threshold_clock.get_round();
        if clock_round <= self.last_proposed() {
            return None;
        }
        let first_include_index = self
            .pending
            .iter()
            .position(|(_, statement)| match statement {
                MetaStatement::Include(block_ref) => block_ref.round >= clock_round,
                _ => false,
            })
            .unwrap_or(self.pending.len());

        let mut taken = self.pending.split_off(first_include_index);
        // Split off returns the "tail", what we want is keep the tail in "pending" and get the head
        mem::swap(&mut taken, &mut self.pending);

        let mut blocks = vec![];
        if self.block_store.byzantine_strategy.is_some() && self.last_own_block.len() < self.committee.len() {
            for _j in self.last_own_block.len()..self.committee.len() {
                self.last_own_block.push(self.last_own_block[0].clone());
            }
        }
        let mut statements =  Vec::new();
        for (_, statement) in taken.clone().into_iter() {
            match statement {
                MetaStatement::Include(_) => {
                }
                MetaStatement::Payload(payload) => {
                    if self.block_store.byzantine_strategy.is_none() && !self.epoch_changing() {
                        statements.extend(payload);
                    }
                }
            }
        }
        let info_length = self.committee.info_length();
        let parity_length = self.committee.len() - info_length;
        let encoded_statements = self.encode(statements, info_length, parity_length);


        for j in 0..self.last_own_block.len() {
            // Compress the references in the block
            // Iterate through all the include statements in the block, and make a set of all the references in their includes.
            let mut references_in_block: HashSet<BlockReference> = HashSet::new();
            references_in_block.extend(self.last_own_block[j].block.includes());
            for (_, statement) in &taken {
                if let MetaStatement::Include(block_ref) = statement {
                    // for all the includes in the block, add the references in the block to the set
                    if let Some(block) = self.block_store.get_block(*block_ref) {
                        references_in_block.extend(block.includes());
                    }
                }
            }
            let mut includes = vec![];
            includes.push(*self.last_own_block[j].block.reference());
            for (_, statement) in taken.clone().into_iter() {
                match statement {
                    MetaStatement::Include(include) => {
                        if !references_in_block.contains(&include)
                            && include.authority != self.authority
                        {
                            includes.push(include);
                        }
                    }
                    MetaStatement::Payload(_) => {

                    }
                }
            }

            assert!(!includes.is_empty());
            let time_ns = timestamp_utc().as_nanos() + j as u128;
            // Todo change this once we track known transactions
            let acknowledgement_statements = includes.clone();

            let new_block = StatementBlock::new_with_signer(
                self.authority,
                clock_round,
                includes.clone(),
                acknowledgement_statements,
                time_ns,
                self.epoch_changing(),
                &self.signer,
                encoded_statements.clone(),
            );
            blocks.push(new_block);
        }

        let mut return_blocks = vec![];
        let mut authority_bounds = vec![0];
        for i in 1..=blocks.len() {
            authority_bounds.push(i * self.committee.len() / blocks.len());
        }
        self.last_own_block = vec![];
        let mut block_id = 0;
        for block in blocks {
            assert_eq!(
                block.includes().get(0).unwrap().authority,
                self.authority,
                "Invalid block {}",
                block.clone()
            );

            let block = Data::new(block);
            if block.serialized_bytes().len() > crate::wal::MAX_ENTRY_SIZE / 2 {
                // Sanity check for now
                panic!(
                    "Created an oversized block (check all limits set properly: {} > {}): {:?}",
                    block.serialized_bytes().len(),
                    crate::wal::MAX_ENTRY_SIZE / 2,
                    block.detailed()
                );
            }
            self.threshold_clock
                .add_block(*block.reference(), &self.committee);
            self.proposed_block_stats(&block);
            let next_entry = if let Some((pos, _)) = self.pending.get(0) {
                *pos
            } else {
                WalPosition::MAX
            };
            self.last_own_block.push(OwnBlockData {
                next_entry,
                block: block.clone(),
            });
            (&mut self.wal_writer, &self.block_store).insert_own_block(
                &self.last_own_block.last().unwrap(),
                authority_bounds[block_id] as AuthorityIndex,
                authority_bounds[block_id + 1] as AuthorityIndex,
            );

            if self.options.fsync {
                self.wal_writer.sync().expect("Wal sync failed");
            }

            tracing::debug!("Created block {block:?}");
            return_blocks.push(block);
            block_id += 1;
        }
        Some(return_blocks[0].clone())
    }


    pub fn wal_syncer(&self) -> WalSyncer {
        self.wal_writer
            .syncer()
            .expect("Failed to create wal syncer")
    }

    fn proposed_block_stats(&self, block: &Data<StatementBlock>) {
        self.metrics
            .proposed_block_size_bytes
            .observe(block.serialized_bytes().len());
    }

    pub fn try_commit(&mut self) -> Vec<Data<StatementBlock>> {
        let sequence: Vec<_> = self
            .committer
            .try_commit(self.last_commit_leader)
            .into_iter()
            .filter_map(|leader| leader.into_decided_block())
            .collect();

        if let Some(last) = sequence.last() {
            self.last_commit_leader = *last.reference();
        }

        // todo: should ideally come from execution result of epoch smart contract
        if self.last_commit_leader.round() > self.rounds_in_epoch {
            self.epoch_manager.epoch_change_begun();
        }

        sequence
    }

    pub fn cleanup(&self) {
        const RETAIN_BELOW_COMMIT_ROUNDS: RoundNumber = 100;

        self.block_store.cleanup(
            self.last_commit_leader
                .round()
                .saturating_sub(RETAIN_BELOW_COMMIT_ROUNDS),
        );

        self.block_handler.cleanup();
    }

    /// This only checks readiness in terms of helping liveness for commit rule,
    /// try_new_block might still return None if threshold clock is not ready
    ///
    /// The algorithm to calling is roughly: if timeout || commit_ready_new_block then try_new_block(..)
    pub fn ready_new_block(
        &self,
        period: u64,
        connected_authorities: &HashSet<AuthorityIndex>,
    ) -> bool {
        let quorum_round = self.threshold_clock.get_round();

        // Leader round we check if we have a leader block
        if quorum_round > self.last_commit_leader.round().max(period - 1) {
            let leader_round = quorum_round - 1;
            let mut leaders = self.committer.get_leaders(leader_round);
            leaders.retain(|leader| connected_authorities.contains(leader));
            self.block_store
                .all_blocks_exists_at_authority_round(&leaders, leader_round)
        } else {
            false
        }
    }

    pub fn handle_committed_subdag(
        &mut self,
        committed: Vec<CommittedSubDag>,
        state: &Bytes,
    ) -> Vec<CommitData> {
        let mut commit_data = vec![];
        for commit in &committed {
            for block in &commit.blocks {
                self.epoch_manager
                    .observe_committed_block(block, &self.committee);
            }
            commit_data.push(CommitData::from(commit));
        }
        self.write_state(); // todo - this can be done less frequently to reduce IO
        self.write_commits(&commit_data, state);
        // todo - We should also persist state of the epoch manager, otherwise if validator
        // restarts during epoch change it will fork on the epoch change state.
        commit_data
    }

    pub fn write_state(&mut self) {
        #[cfg(feature = "simulator")]
        if self.block_handler().state().len() >= crate::wal::MAX_ENTRY_SIZE {
            // todo - this is something needs a proper fix
            // Need to revisit this after we have a proper synchronizer
            // We need to put some limit/backpressure on the accumulator state
            return;
        }
        self.wal_writer
            .write(WAL_ENTRY_STATE, &self.block_handler().state())
            .expect("Write to wal has failed");
    }

    pub fn write_commits(&mut self, commits: &[CommitData], state: &Bytes) {
        let commits = bincode::serialize(&(commits, state)).expect("Commits serialization failed");
        self.wal_writer
            .write(WAL_ENTRY_COMMIT, &commits)
            .expect("Write to wal has failed");
    }

    pub fn take_recovered_committed_blocks(&mut self) -> (HashSet<BlockReference>, Option<Bytes>) {
        self.recovered_committed_blocks
            .take()
            .expect("take_recovered_committed_blocks called twice")
    }

    pub fn block_store(&self) -> &BlockStore {
        &self.block_store
    }

    // This function is needed only for signalling that we created a new block
    pub fn last_own_block(&self) -> &Data<StatementBlock> {
        &self.last_own_block[0].block
    }

    // This function is needed only for retrieving the last round of a block we proposed
    pub fn last_proposed(&self) -> RoundNumber {
        self.last_own_block[0].block.round()
    }

    pub fn authority(&self) -> AuthorityIndex {
        self.authority
    }

    pub fn block_handler(&self) -> &H {
        &self.block_handler
    }

    pub fn block_manager(&self) -> &BlockManager {
        &self.block_manager
    }

    pub fn block_handler_mut(&mut self) -> &mut H {
        &mut self.block_handler
    }

    pub fn committee(&self) -> &Arc<Committee> {
        &self.committee
    }

    pub fn epoch_closed(&self) -> bool {
        self.epoch_manager.closed()
    }

    pub fn epoch_changing(&self) -> bool {
        self.epoch_manager.changing()
    }

    pub fn epoch_closing_time(&self) -> Arc<AtomicU64> {
        self.epoch_manager.closing_time()
    }
}

impl Default for CoreOptions {
    fn default() -> Self {
        Self::test()
    }
}

impl CoreOptions {
    pub fn test() -> Self {
        Self { fsync: false }
    }

    pub fn production() -> Self {
        Self { fsync: true }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    fn push_all(
        p: &mut Vec<Vec<Data<StatementBlock>>>,
        except: AuthorityIndex,
        block: &Data<StatementBlock>,
    ) {
        for (i, q) in p.iter_mut().enumerate() {
            if i as AuthorityIndex != except {
                q.push(block.clone());
            }
        }
    }
}
