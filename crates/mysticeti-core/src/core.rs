// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashSet},
    mem,
    sync::{atomic::AtomicU64, Arc},
};
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
    types::{AuthorityIndex, BaseStatement, BlockReference, RoundNumber},
    wal::{WalPosition, WalSyncer, WalWriter},
};
use crate::block_store::WAL_ENTRY_PAYLOAD;
use crate::decoder::CachedStatementBlockDecoder;
use crate::encoder::ShardEncoder;
use crate::types::{Encoder, Decoder, VerifiedStatementBlock};

pub struct Core<H: BlockHandler> {
    block_manager: BlockManager,
    pending: Vec<(WalPosition, MetaStatement)>,
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
    pub(crate) encoder : Encoder,
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
                let position = block_writer.insert_block((block.clone(), block));
                pending.push((position, MetaStatement::Include(reference)));
            }
            threshold_clock.add_block(*own_genesis_block.reference(), &committee);
            let own_block_data = OwnBlockData {
                next_entry: WalPosition::MAX,
                storage_transmission_blocks: (own_genesis_block.clone(), own_genesis_block),
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
                .build();
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

    pub fn get_signer(&self) -> &Signer { &self.signer}

    pub fn get_universal_committer(&self) -> UniversalCommitter {
        self.committer.clone()
    }

    pub fn with_options(mut self, options: CoreOptions) -> Self {
        self.options = options;
        self
    }

    // Note that generally when you update this function you also want to change genesis initialization above
    pub fn add_blocks(&mut self, blocks: Vec<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>) -> bool  {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::add_blocks");
        let (processed, new_blocks_to_reconstruct, updated_statements) = self
            .block_manager
            .add_blocks(blocks, &mut (&mut self.wal_writer, &self.block_store));
        let success: bool = if processed.len() > 0 || new_blocks_to_reconstruct.len() > 0 || updated_statements {
            true
        } else {
            false
        };
        tracing::debug!("Processed {:?}; to be reconstructed {:?}", processed, new_blocks_to_reconstruct);
        self.reconstruct_data_blocks(new_blocks_to_reconstruct);

        let mut result = Vec::with_capacity(processed.len());
        for (position, processed) in processed.into_iter() {
            self.threshold_clock
                .add_block(*processed.reference(), &self.committee);
            self.pending
                .push((position, MetaStatement::Include(*processed.reference())));
            result.push(processed);
        }
        self.run_block_handler();
        success
    }

    fn run_block_handler(&mut self) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::run_block_handler");
        let statements = self
            .block_handler
            .handle_blocks(!self.epoch_changing());
        let serialized_statements =
            bincode::serialize(&statements).expect("Payload serialization failed");
        let position = self
            .wal_writer
            .write(WAL_ENTRY_PAYLOAD, &serialized_statements)
            .expect("Failed to write statements to wal");
        self.pending
            .push((position, MetaStatement::Payload(statements)));
    }

    fn sort_includes_in_pending(&mut self) {
        // Temporarily extract Includes, leaving Payloads untouched
        let mut include_positions: Vec<usize> = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, (_, meta))| matches!(meta, MetaStatement::Include(_)))
            .map(|(index, _)| index)
            .collect();
        // Sort the Include entries by round
        include_positions.sort_by_key(|&index| {
            if let MetaStatement::Include(block_ref) = &self.pending[index].1 {
                block_ref.round()
            } else {
                unreachable!() // This should never happen
            }
        });

        // Reorder the Include entries in place
        for i in 0..include_positions.len() {
            for j in (i + 1)..include_positions.len() {
                let i_pos = include_positions[i];
                let j_pos = include_positions[j];

                if let (MetaStatement::Include(ref i_meta), MetaStatement::Include(ref j_meta)) = (
                    &self.pending[i_pos].1,
                    &self.pending[j_pos].1,
                ) {
                    if j_meta.round() < i_meta.round() {
                        // Swap the positions and the entries directly
                        self.pending.swap(i_pos, j_pos);
                        include_positions.swap(i, j);
                    }
                }
            }
        }
    }


    pub fn reconstruct_data_blocks(&mut self, new_blocks_to_reconstruct: HashSet<BlockReference>) {
        let info_length = self.committee.info_length();
        let parity_length = self.committee.len() - info_length;

        for block_reference in new_blocks_to_reconstruct {
            let block = self.block_store.get_cached_block(&block_reference);
            let storage_block = self.decoder.decode_shards(&self.committee, &mut self.encoder, block, self.authority);
            if storage_block.is_some() {
                tracing::debug!("Block {block_reference} is reconstructed in core thread");
                let storage_block: VerifiedStatementBlock = storage_block.expect("Block is verified to be reconstructed");
                let transmission_block = storage_block.from_storage_to_transmission(self.authority);
                let data_storage_block = Data::new(storage_block);
                let data_transmission_block = Data::new(transmission_block);

                (&mut self.wal_writer, &self.block_store).insert_block((data_storage_block,data_transmission_block));
                self.block_store.updated_unknown_by_others(block_reference);
            }
            else {
                tracing::debug!("Block {block_reference} is not correctly reconstructed");
            }
        }
    }


    pub fn try_new_block(&mut self) -> Option<Data<VerifiedStatementBlock>> {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::try_new_block");
        let clock_round = self.threshold_clock.get_round();
        if clock_round <= self.last_proposed() {
            return None;
        }

        // Sort includes in pending to include all blocks up to the given round
        self.sort_includes_in_pending();

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
        let number_statements = statements.len();
        tracing::debug!("Include in block {} transactions", number_statements);
        let info_length = self.committee.info_length();
        let parity_length = self.committee.len() - info_length;


        let timer_for_encoding = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::try_new_block::encoding");
        let encoded_statements = self.encoder.encode_statements(statements.clone(), info_length, parity_length);
        drop(timer_for_encoding);

        let acknowledgment_statements_retrieved = self.block_store.get_pending_acknowledgment(clock_round.saturating_sub(1));

        for j in 0..self.last_own_block.len() {
            // Compress the references in the block
            // Iterate through all the include statements in the block, and make a set of all the references in their includes.
            let mut references_in_block: HashSet<BlockReference> = HashSet::new();
            references_in_block.extend(self.last_own_block[j].storage_transmission_blocks.0.includes());
            for (_, statement) in &taken {
                if let MetaStatement::Include(block_ref) = statement {
                    // for all the includes in the block, add the references in the block to the set
                    if let Some(block) = self.block_store.get_storage_block(*block_ref) {
                        references_in_block.extend(block.includes());
                    }
                }
            }
            let mut includes = vec![];
            includes.push(*self.last_own_block[j].storage_transmission_blocks.0.reference());
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

            let acknowledgement_statements = acknowledgment_statements_retrieved.clone();
            let timer_for_building_block = self
                .metrics
                .utilization_timer
                .utilization_timer("Core::try_new_block::build block");
            let storage_block = VerifiedStatementBlock::new_with_signer(
                self.authority,
                clock_round,
                includes.clone(),
                acknowledgement_statements,
                time_ns,
                self.epoch_changing(),
                &self.signer,
                statements.clone(),
                encoded_statements.clone(),
            );
            drop(timer_for_building_block);
            blocks.push(storage_block);
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
                block.reference()
            );
            let timer_for_serialization = self
                .metrics
                .utilization_timer
                .utilization_timer("Core::try_new_block::serialize block");
            // Todo: for own blocks no need to serialize twice
            let data_block = Data::new(block);
            let storage_and_transmission_blocks = (data_block.clone(), data_block);
            drop(timer_for_serialization);
            if storage_and_transmission_blocks.0.serialized_bytes().len() > crate::wal::MAX_ENTRY_SIZE / 2 {
                // Sanity check for now
                panic!(
                    "Created an oversized block (check all limits set properly: {} > {}): {:?}",
                    storage_and_transmission_blocks.0.serialized_bytes().len(),
                    crate::wal::MAX_ENTRY_SIZE / 2,
                    storage_and_transmission_blocks,
                );
            }
            self.threshold_clock
                .add_block(*storage_and_transmission_blocks.0.reference(), &self.committee);
            self.block_handler.handle_proposal(number_statements);
            self.proposed_block_stats(&storage_and_transmission_blocks.0);
            let next_entry = if let Some((pos, _)) = self.pending.get(0) {
                *pos
            } else {
                WalPosition::MAX
            };
            self.last_own_block.push(OwnBlockData {
                next_entry,
                storage_transmission_blocks: storage_and_transmission_blocks.clone(),
            });
            let timer_for_disk = self
                .metrics
                .utilization_timer
                .utilization_timer("Core::try_new_block::writing to disk");
            (&mut self.wal_writer, &self.block_store).insert_own_block(
                &self.last_own_block.last().unwrap(),
                authority_bounds[block_id] as AuthorityIndex,
                authority_bounds[block_id + 1] as AuthorityIndex,
            );

            if self.options.fsync {
                self.wal_writer.sync().expect("Wal sync failed");
            }
            drop(timer_for_disk);

            tracing::debug!("Created block {storage_and_transmission_blocks:?} with refs {:?}", storage_and_transmission_blocks.0.includes().len());
            return_blocks.push(storage_and_transmission_blocks);
            block_id += 1;
        }
        Some(return_blocks[0].0.clone())
    }


    pub fn wal_syncer(&self) -> WalSyncer {
        self.wal_writer
            .syncer()
            .expect("Failed to create wal syncer")
    }

    fn proposed_block_stats(&self, block: &Data<VerifiedStatementBlock>) {
        self.metrics
            .proposed_block_size_bytes
            .observe(block.serialized_bytes().len());
    }

    pub fn try_commit(&mut self) -> Vec<Data<VerifiedStatementBlock>> {
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
    pub fn last_own_block(&self) -> &Data<VerifiedStatementBlock> {
        &self.last_own_block[0].storage_transmission_blocks.0
    }

    // This function is needed only for retrieving the last round of a block we proposed
    pub fn last_proposed(&self) -> RoundNumber {
        self.last_own_block[0].storage_transmission_blocks.0.round()
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


