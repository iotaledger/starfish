// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use reed_solomon_simd::ReedSolomonDecoder;
use reed_solomon_simd::ReedSolomonEncoder;
use std::{
    collections::HashSet,
    mem,
    sync::{atomic::AtomicU64, Arc},
};

use crate::block_store::ConsensusProtocol;
use crate::decoder::CachedStatementBlockDecoder;
use crate::encoder::ShardEncoder;
use crate::rocks_store::RocksStore;
use crate::types::{Decoder, Encoder, Shard, VerifiedStatementBlock};
use crate::{
    block_handler::BlockHandler,
    block_manager::BlockManager,
    block_store::{BlockStore, ByzantineStrategy, CommitData, OwnBlockData},
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
};

pub struct Core<H: BlockHandler> {
    block_manager: BlockManager,
    pending: Vec<MetaStatement>,
    // For Byzantine node, last_own_block contains a vector of blocks
    last_own_block: Vec<OwnBlockData>,
    block_handler: H,
    rocks_store: Arc<RocksStore>,
    authority: AuthorityIndex,
    threshold_clock: ThresholdClockAggregator,
    pub(crate) committee: Arc<Committee>,
    last_commit_leader: BlockReference,
    block_store: BlockStore,
    pub(crate) metrics: Arc<Metrics>,
    options: CoreOptions,
    signer: Signer,
    // todo - ugly, probably need to merge syncer and core
    recovered_committed_blocks: Option<HashSet<BlockReference>>,
    epoch_manager: EpochManager,
    rounds_in_epoch: RoundNumber,
    committer: UniversalCommitter,
    pub(crate) encoder: Encoder,
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
        block_handler: H,
        authority: AuthorityIndex,
        committee: Arc<Committee>,
        private_config: NodePrivateConfig,
        public_config: &NodePublicConfig,
        metrics: Arc<Metrics>,
        recovered: RecoveredState,
        options: CoreOptions,
    ) -> Self {
        let RecoveredState {
            block_store,
            rocks_store,
            unprocessed_blocks,
            last_committed_leader,
            committed_blocks,
        } = recovered;

        let mut threshold_clock = ThresholdClockAggregator::new(0);

        // Initialize genesis blocks if needed
        let (own_genesis_block, other_genesis_blocks) = committee.genesis_blocks(authority);
        assert_eq!(own_genesis_block.author(), authority);

        // Pending references for inclusion
        let mut pending = Vec::new();
        // Store genesis blocks if necessary
        for block in other_genesis_blocks {
            let reference = *block.reference();
            threshold_clock.add_block(reference, &committee);
            block_store.insert_block_bounds(
                (block.clone(), block.clone()),
                0,
                committee.len() as AuthorityIndex,
            );
            pending.push(MetaStatement::Include(*block.reference()));
        }

        threshold_clock.add_block(*own_genesis_block.reference(), &committee);
        block_store.insert_block_bounds(
            (own_genesis_block.clone(), own_genesis_block.clone()),
            0,
            committee.len() as AuthorityIndex,
        );
        pending.push(MetaStatement::Include(*own_genesis_block.reference()));

        let block_manager = BlockManager::new(block_store.clone(), &committee);

        let epoch_manager = EpochManager::new();

        let committer =
            UniversalCommitterBuilder::new(committee.clone(), block_store.clone(), metrics.clone())
                .build();
        let encoder = ReedSolomonEncoder::new(2, 4, 64).unwrap();
        let decoder = ReedSolomonDecoder::new(2, 4, 64).unwrap();

        let this = Self {
            block_manager,
            rocks_store,
            pending,
            last_own_block: vec![OwnBlockData {
                storage_transmission_blocks: (own_genesis_block.clone(), own_genesis_block.clone()),
                authority_index_start: 0 as AuthorityIndex,
                authority_index_end: committee.len() as AuthorityIndex,
            }],
            block_handler,
            authority,
            threshold_clock,
            committee,
            last_commit_leader: last_committed_leader.unwrap_or_default(),
            block_store,
            metrics,
            options,
            signer: private_config.keypair,
            recovered_committed_blocks: Some(committed_blocks),
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

    pub fn get_signer(&self) -> &Signer {
        &self.signer
    }

    pub fn get_universal_committer(&self) -> UniversalCommitter {
        self.committer.clone()
    }

    pub fn with_options(mut self, options: CoreOptions) -> Self {
        self.options = options;
        self
    }

    // This function attempts to add blocks to the local DAG (and in addition update with shards)
    // It return true if any update was made successfully
    // It also return a vector of references for blocks with statements that are not added to the local DAG and remain pending
    // For such blocks we need to send a missing history request
    pub fn add_blocks(
        &mut self,
        blocks: Vec<(Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>)>,
    ) -> (bool, Vec<BlockReference>, HashSet<BlockReference>) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::add_blocks");
        let block_references_with_statements: Vec<_> = blocks
            .iter()
            .filter(|(b, _)| b.statements().is_some())
            .map(|(b, _)| *b.reference())
            .collect();
        let block_manager_timer = self
            .metrics
            .utilization_timer
            .utilization_timer("BlockManager::add_blocks");
        let (processed, new_blocks_to_reconstruct, updated_statements, missing_references) =
            self.block_manager.add_blocks(blocks);
        drop(block_manager_timer);
        let processed_references: Vec<_> = processed
            .iter()
            .filter(|b| b.statements().is_some())
            .map(|b| *b.reference())
            .collect();
        let not_processed_blocks: Vec<_> = block_references_with_statements
            .iter()
            .filter(|block_reference| !processed_references.contains(block_reference))
            .copied()
            .collect();

        let success: bool =
            !processed.is_empty() || !new_blocks_to_reconstruct.is_empty() || updated_statements;
        tracing::debug!(
            "Processed {:?}; to be reconstructed {:?}",
            processed,
            new_blocks_to_reconstruct
        );
        match self.block_store.consensus_protocol {
            ConsensusProtocol::StarfishPull | ConsensusProtocol::Starfish => {
                self.reconstruct_data_blocks(new_blocks_to_reconstruct);
            }
            _ => {}
        };

        let mut result = Vec::with_capacity(processed.len());
        for processed in &processed {
            self.threshold_clock
                .add_block(*processed.reference(), &self.committee);
            self.pending
                .push(MetaStatement::Include(*processed.reference()));
            result.push(processed.clone());
        }
        tracing::debug!("Pending after adding blocks: {:?}", self.pending);
        self.run_block_handler();
        (success, not_processed_blocks, missing_references)
    }

    fn run_block_handler(&mut self) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::run_block_handler");
        let statements = self.block_handler.handle_blocks(!self.epoch_changing());
        let _serialized_statements =
            bincode::serialize(&statements).expect("Payload serialization failed");
        self.pending.push(MetaStatement::Payload(statements));
    }

    fn sort_includes_in_pending(&mut self) {
        // Temporarily extract Includes, leaving Payloads untouched
        let mut include_positions: Vec<usize> = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, meta)| matches!(meta, MetaStatement::Include(_)))
            .map(|(index, _)| index)
            .collect();
        // Sort the Include entries by round
        include_positions.sort_by_key(|&index| {
            if let MetaStatement::Include(block_ref) = &self.pending[index] {
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

                if let (MetaStatement::Include(ref i_meta), MetaStatement::Include(ref j_meta)) =
                    (&self.pending[i_pos], &self.pending[j_pos])
                {
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
        for block_reference in new_blocks_to_reconstruct {
            let block = self.block_store.get_cached_block(&block_reference);
            let storage_block = self.decoder.decode_shards(
                &self.committee,
                &mut self.encoder,
                block,
                self.authority,
            );
            if storage_block.is_some() {
                tracing::debug!(
                    "Reconstruction of block {:?} within core thread task is successful",
                    block_reference
                );
                let storage_block: VerifiedStatementBlock =
                    storage_block.expect("Block is verified to be reconstructed");
                let transmission_block = storage_block.from_storage_to_transmission(self.authority);
                let data_storage_block = Data::new(storage_block);
                let data_transmission_block = Data::new(transmission_block);
                self.block_store()
                    .insert_general_block((data_storage_block, data_transmission_block));
                self.block_store.updated_unknown_by_others(block_reference);
            } else {
                tracing::debug!("Block {block_reference} is not correctly reconstructed");
            }
        }
    }

    pub fn try_new_block(&mut self) -> Option<Data<VerifiedStatementBlock>> {
        let _block_timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::new_block::try_new_block");

        // Check if we're ready for a new block
        let clock_round = self.threshold_clock.get_round();
        tracing::debug!(
            "Attemp to construct block in round {}. Current pending: {:?}",
            clock_round,
            self.pending
        );
        if clock_round <= self.last_proposed() {
            return None;
        }

        // Get relevant pending statements for this round
        let _pending_timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::new_block::get_pending_statements");
        let pending_statements = self.get_pending_statements(clock_round);
        drop(_pending_timer);

        // Collect statements and references
        let _collect_timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::new_block::collect_statements_and_references");
        let (mut statements, block_references) =
            self.collect_statements_and_references(&pending_statements);
        drop(_collect_timer);

        // Create blocks based on byzantine strategy
        let _prepare_timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::new_block::prepare_last_blocks");
        self.prepare_last_blocks();
        drop(_prepare_timer);

        // Prepare encoded statements if needed
        let _encode_timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::new_block::prepare_encoded_statements");
        let mut encoded_statements = self.prepare_encoded_statements(&statements);
        drop(_encode_timer);

        // Get pending acknowledgments
        let _ack_timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::new_block::get_pending_acknowledgment");
        let acknowledgments = self.block_store.get_pending_acknowledgment(clock_round);
        drop(_ack_timer);

        // Calculate authority bounds
        let number_of_blocks_to_create = self.last_own_block.len();
        let _bounds_timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::new_block::calculate_authority_bounds");
        let authority_bounds = self.calculate_authority_bounds(number_of_blocks_to_create);
        drop(_bounds_timer);

        // Create and store blocks
        let mut return_blocks = Vec::new();
        for block_id in 0..number_of_blocks_to_create {
            // Equivocators include their transactions only in first block, but leave other empty
            // to not overload the bandwidth
            if block_id == 1 {
                statements = vec![];
                encoded_statements = self.prepare_encoded_statements(&statements);
            }
            let _build_timer = self
                .metrics
                .utilization_timer
                .utilization_timer("Core::new_block::build_block");
            let block_data = self.build_block(
                &block_references,
                &statements,
                &encoded_statements,
                &acknowledgments,
                clock_round,
                block_id,
            );
            drop(_build_timer);

            tracing::debug!("Created block {:?}", block_data.0);

            let _store_timer = self
                .metrics
                .utilization_timer
                .utilization_timer("Core::new_block::store_block");
            self.store_block(block_data.clone(), &authority_bounds, block_id);
            drop(_store_timer);

            return_blocks.push(block_data);
        }

        // Sync if needed
        if self.options.fsync {
            let _sync_timer = self
                .metrics
                .utilization_timer
                .utilization_timer("Core::new_block::sync_with_disk");
            self.rocks_store.sync().expect("RocksDB sync failed");
            drop(_sync_timer);
        } else {
            let _sync_timer = self
                .metrics
                .utilization_timer
                .utilization_timer("Core::new_block::flush_to_buffer");
            self.rocks_store.flush().expect("RocksDB sync failed");
            drop(_sync_timer);
        }

        Some(return_blocks[0].0.clone())
    }

    fn get_pending_statements(&mut self, clock_round: RoundNumber) -> Vec<MetaStatement> {
        self.sort_includes_in_pending();

        let split_point = self
            .pending
            .iter()
            .position(|statement| match statement {
                MetaStatement::Include(block_ref) => block_ref.round >= clock_round,
                _ => false,
            })
            .unwrap_or(self.pending.len());

        let mut taken = self.pending.split_off(split_point);
        mem::swap(&mut taken, &mut self.pending);
        taken
    }

    fn collect_statements_and_references(
        &self,
        pending: &[MetaStatement],
    ) -> (Vec<BaseStatement>, Vec<BlockReference>) {
        let mut statements = Vec::new();
        for meta_statement in pending {
            if let MetaStatement::Payload(payload) = meta_statement {
                if !self.epoch_changing() {
                    statements.extend(payload.clone());
                }
            }
        }
        let block_references = self.compress_pending_block_references(pending);
        (statements, block_references)
    }

    fn prepare_encoded_statements(
        &mut self,
        statements: &[BaseStatement],
    ) -> Option<Vec<Shard>> {
        let info_length = self.committee.info_length();
        let parity_length = self.committee.len() - info_length;

        match self.block_store.consensus_protocol {
            ConsensusProtocol::StarfishPull | ConsensusProtocol::Starfish => Some(
                self.encoder
                    .encode_statements(statements.to_owned(), info_length, parity_length),
            ),
            ConsensusProtocol::Mysticeti | ConsensusProtocol::CordialMiners => None,
        }
    }

    fn build_block(
        &self,
        block_references_without_own: &[BlockReference],
        statements: &[BaseStatement],
        encoded_statements: &Option<Vec<Shard>>,
        acknowledgments: &[BlockReference],
        clock_round: RoundNumber,
        block_id_in_round: usize,
    ) -> (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>) {
        let time_ns = timestamp_utc().as_nanos() + block_id_in_round as u128;
        let mut block_references = vec![*self.last_own_block[block_id_in_round]
            .storage_transmission_blocks
            .0
            .reference()];
        block_references.extend(block_references_without_own.iter().cloned());
        let block = VerifiedStatementBlock::new_with_signer(
            self.authority,
            clock_round,
            block_references,
            acknowledgments.to_vec(),
            time_ns,
            self.epoch_changing(),
            &self.signer,
            statements.to_vec(),
            encoded_statements.clone(),
            self.block_store.consensus_protocol,
        );

        let data_block = Data::new(block);
        (data_block.clone(), data_block)
    }

    fn prepare_last_blocks(&mut self) {
        if let Some(ref strategy) = self.block_store.byzantine_strategy {
            match strategy {
                ByzantineStrategy::EquivocatingChains => {
                    for _ in self.last_own_block.len()..self.committee.len() {
                        self.last_own_block.push(self.last_own_block[0].clone());
                    }
                }
                ByzantineStrategy::EquivocatingTwoChains => {
                    for _ in self.last_own_block.len()..2 {
                        self.last_own_block.push(self.last_own_block[0].clone());
                    }
                }
                ByzantineStrategy::EquivocatingChainsBomb => {
                    for _ in self.last_own_block.len()..self.committee.len() {
                        self.last_own_block.push(self.last_own_block[0].clone());
                    }
                }
                _ => {}
            }
        }
    }

    fn calculate_authority_bounds(&self, num_blocks: usize) -> Vec<usize> {
        let mut authority_bounds = vec![0];

        match self.block_store.byzantine_strategy {
            // Skipping Equivocating: Divide the authorities into two groups
            Some(ByzantineStrategy::EquivocatingTwoChains) => {
                authority_bounds.push((self.committee.len() as f64 / 2.0).ceil() as usize);
                authority_bounds.push(self.committee.len());
            }
            // Default behavior: Distribute blocks evenly across all authorities
            _ => {
                for i in 1..=num_blocks {
                    authority_bounds.push(i * self.committee.len() / num_blocks);
                }
            }
        }
        authority_bounds
    }

    fn compress_pending_block_references(&self, pending: &[MetaStatement]) -> Vec<BlockReference> {
        let mut references_in_block: HashSet<BlockReference> = HashSet::new();

        for statement in pending {
            if let MetaStatement::Include(block_ref) = statement {
                if let Some(block) = self.block_store.get_storage_block(*block_ref) {
                    references_in_block.extend(block.includes());
                }
            }
        }

        let mut includes = vec![];

        for statement in pending {
            if let MetaStatement::Include(include) = statement {
                if !references_in_block.contains(include) && include.authority != self.authority {
                    includes.push(*include);
                }
            }
        }

        assert!(!includes.is_empty());
        includes
    }

    fn store_block(
        &mut self,
        block_data: (Data<VerifiedStatementBlock>, Data<VerifiedStatementBlock>),
        authority_bounds: &[usize],
        block_id: usize,
    ) {
        self.threshold_clock
            .add_block(*block_data.0.reference(), &self.committee);
        self.block_handler
            .handle_proposal(block_data.0.number_transactions());
        self.proposed_block_stats(&block_data.0);

        let own_block = OwnBlockData {
            storage_transmission_blocks: block_data.clone(),
            authority_index_start: authority_bounds[block_id] as AuthorityIndex,
            authority_index_end: authority_bounds[block_id + 1] as AuthorityIndex,
        };
        self.last_own_block[block_id] = own_block.clone();
        self.block_store.insert_own_block(own_block);
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
        const RETAIN_BELOW_COMMIT_ROUNDS: RoundNumber = 50;

        self.block_store.cleanup(
            self.last_commit_leader
                .round()
                .saturating_sub(RETAIN_BELOW_COMMIT_ROUNDS),
        );
    }

    /// This only checks readiness in terms of helping liveness for commit rule,
    /// try_new_block might still return None if threshold clock is not ready
    ///
    /// The algorithm to calling is roughly: if timeout || commit_ready_new_block then try_new_block(..)
    pub fn ready_new_block(&self, connected_authorities: &HashSet<AuthorityIndex>) -> bool {
        let quorum_round = self.threshold_clock.get_round();
        tracing::debug!("Attempt ready new block, quorum round {}", quorum_round);
        // Leader round we check if we have a leader block
        if quorum_round >= self.last_commit_leader.round().max(1) {
            let leader_round = quorum_round - 1;
            let mut leaders = self.committer.get_leaders(leader_round);
            leaders.retain(|leader| connected_authorities.contains(leader));
            tracing::debug!(
                "Attempt ready new block, quorum round {}, Before exist at authority round",
                quorum_round
            );
            self.block_store
                .all_blocks_exists_at_authority_round(&leaders, leader_round)
        } else {
            false
        }
    }

    pub fn handle_committed_subdag(&mut self, committed: Vec<CommittedSubDag>) {
        let mut commit_data = vec![];
        for commit in &committed {
            for block in &commit.blocks {
                self.epoch_manager
                    .observe_committed_block(block, &self.committee);
            }
            commit_data.push(CommitData::from(commit));
        }
        self.rocks_store
            .store_commits(commit_data)
            .expect("Store commits should not fail");
        // Sync if needed
        if self.options.fsync && !committed.is_empty() {
            let timer = self
                .metrics
                .utilization_timer
                .utilization_timer("Core::commit::sync with disk");
            self.rocks_store.sync().expect("RocksDB sync failed");
            drop(timer);
        } else if !committed.is_empty() {
            let _sync_timer = self
                .metrics
                .utilization_timer
                .utilization_timer("Core::commit::flush_to_buffer");
            self.rocks_store.flush().expect("RocksDB sync failed");
            drop(_sync_timer);
        }
    }

    pub fn write_commits(&mut self, _commits: &[CommitData]) {}

    pub fn take_recovered_committed_blocks(&mut self) -> HashSet<BlockReference> {
        self.recovered_committed_blocks
            .take()
            .expect("take_recovered_committed_blocks called twice")
    }

    pub fn block_store(&self) -> &BlockStore {
        &self.block_store
    }
    pub fn rocks_store(&self) -> Arc<RocksStore> {
        self.rocks_store.clone()
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
