// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    mem,
    sync::{Arc, atomic::AtomicU64},
};

use ahash::{AHashMap, AHashSet};
use reed_solomon_simd::ReedSolomonEncoder;

use crate::{
    block_handler::BlockHandler,
    block_manager::BlockManager,
    committee::Committee,
    config::{NodePrivateConfig, NodePublicConfig},
    consensus::{
        CommitMetastate,
        linearizer::CommittedSubDag,
        universal_committer::{UniversalCommitter, UniversalCommitterBuilder},
    },
    crypto::{AsBytes, Signer},
    dag_state::{ByzantineStrategy, CommitData, ConsensusProtocol, DagState, OwnBlockData},
    data::Data,
    encoder::ShardEncoder,
    epoch_close::EpochManager,
    metrics::{Metrics, UtilizationTimerVecExt},
    runtime::timestamp_utc,
    state::RecoveredState,
    store::Store,
    types::{
        AuthorityIndex, BaseTransaction, BlockReference, Encoder, ReconstructedTransactionData,
        RoundNumber, Shard, VerifiedBlock,
    },
};

macro_rules! timed {
    ($metrics:expr, $name:expr, $body:expr) => {{
        let _timer = $metrics.utilization_timer.utilization_timer($name);
        $body
    }};
}

pub struct Core<H: BlockHandler> {
    block_manager: BlockManager,
    pending: Vec<MetaTransaction>,
    pending_reconstructed_data: AHashMap<BlockReference, ReconstructedTransactionData>,
    // For Byzantine node, last_own_block contains a vector of blocks
    last_own_block: Vec<OwnBlockData>,
    block_handler: H,
    store: Arc<dyn Store>,
    authority: AuthorityIndex,
    pub(crate) committee: Arc<Committee>,
    last_commit_leader: BlockReference,
    dag_state: DagState,
    pub(crate) metrics: Arc<Metrics>,
    options: CoreOptions,
    signer: Signer,
    // todo - ugly, probably need to merge syncer and core
    recovered_committed_blocks: Option<AHashSet<BlockReference>>,
    recovered_committed_leaders_count: Option<usize>,
    epoch_manager: EpochManager,
    rounds_in_epoch: RoundNumber,
    committer: UniversalCommitter,
    pub(crate) encoder: Encoder,
}

pub struct CoreOptions {
    fsync: bool,
}

#[derive(Debug, Clone)]
pub enum MetaTransaction {
    Include(BlockReference),
    Payload(Vec<BaseTransaction>),
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
            dag_state,
            store,
            unprocessed_blocks,
            last_committed_leader,
            committed_blocks,
            committed_leaders_count,
        } = recovered;

        // Use genesis blocks cached in DagState (already inserted into DAG on
        // clean start by DagState::open()). Threshold clock is also initialized
        // inside DagState::open().
        let own_genesis_block = dag_state
            .genesis_blocks()
            .iter()
            .find(|b| b.author() == authority)
            .expect("own genesis block not found")
            .clone();

        // Pending references for inclusion
        let mut pending = Vec::new();
        let committee_len = committee.len() as AuthorityIndex;
        let mut last_own_block = OwnBlockData {
            block: own_genesis_block.clone(),
            authority_index_start: 0,
            authority_index_end: committee_len,
        };

        if unprocessed_blocks.is_empty() {
            // Clean start: genesis blocks and threshold clock already populated
            // by DagState::open(). Just build the pending queue.
            for block in dag_state.genesis_blocks() {
                pending.push(MetaTransaction::Include(*block.reference()));
            }
        } else {
            // Rebuild runtime-only state (pending frontier and last own block)
            // from recovered DAG blocks. Threshold clock is already populated
            // by DagState::open().
            let mut recovered_last_own_round = None;
            for block in &unprocessed_blocks {
                let reference = *block.reference();
                if reference.authority == authority
                    && recovered_last_own_round
                        .map(|round| reference.round > round)
                        .unwrap_or(true)
                {
                    recovered_last_own_round = Some(reference.round);
                    last_own_block = OwnBlockData {
                        block: block.clone(),
                        authority_index_start: 0,
                        authority_index_end: committee_len,
                    };
                }
            }

            let pending_start_round = recovered_last_own_round
                .unwrap_or_default()
                .max(dag_state.threshold_clock_round().saturating_sub(1));
            for block in &unprocessed_blocks {
                if block.round() >= pending_start_round {
                    pending.push(MetaTransaction::Include(*block.reference()));
                }
            }
            if pending.is_empty() {
                pending.push(MetaTransaction::Include(*last_own_block.block.reference()));
            }
        }

        let block_manager = BlockManager::new(dag_state.clone(), &committee);

        let epoch_manager = EpochManager::new();

        let committer =
            UniversalCommitterBuilder::new(committee.clone(), dag_state.clone(), metrics.clone())
                .build();
        let encoder = ReedSolomonEncoder::new(2, 4, 2).unwrap();

        let this = Self {
            block_manager,
            store,
            pending,
            pending_reconstructed_data: AHashMap::new(),
            last_own_block: vec![last_own_block],
            block_handler,
            authority,
            committee,
            last_commit_leader: last_committed_leader.unwrap_or_default(),
            dag_state,
            metrics,
            options,
            signer: private_config.keypair,
            recovered_committed_blocks: Some(committed_blocks),
            recovered_committed_leaders_count: Some(committed_leaders_count),
            epoch_manager,
            rounds_in_epoch: public_config.parameters.rounds_in_epoch,
            committer,
            encoder,
        };

        if !unprocessed_blocks.is_empty() {
            tracing::info!(
                "Recovered {} blocks from storage; rebuilt pending and clock",
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

    // This function attempts to add blocks to the local DAG.
    // It returns four values. First is bool which is true if any update was made
    // successfully. Second, it returns a vector of references for blocks with
    // transactions that are not added to the local DAG and remain
    // pending. For such blocks we need to send a missing history
    // request.
    // Third, it returns a set of parents that are still missing
    // and need to be requested.
    // Fourth, it returns a vector of references for blocks without
    // transactions that are added to the local DAG.
    pub fn add_blocks(
        &mut self,
        blocks: Vec<Data<VerifiedBlock>>,
    ) -> (
        bool,
        Vec<BlockReference>,
        AHashSet<BlockReference>,
        Vec<BlockReference>,
    ) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::add_blocks");
        let block_references_with_transactions: Vec<_> = blocks
            .iter()
            .filter(|b| b.transactions().is_some())
            .map(|b| *b.reference())
            .collect();
        let (processed, updated_existing_with_transactions, missing_references) = timed!(
            self.metrics,
            "BlockManager::add_blocks",
            self.block_manager.add_blocks(blocks)
        );
        let mut processed_references_with_transactions = AHashSet::new();
        let mut processed_references_without_transactions = Vec::new();
        for block in &processed {
            if block.transactions().is_some() {
                processed_references_with_transactions.insert(*block.reference());
            } else {
                processed_references_without_transactions.push(*block.reference());
            }
        }
        for block in &updated_existing_with_transactions {
            if block.transactions().is_some() {
                processed_references_with_transactions.insert(*block.reference());
            }
        }
        let not_processed_block_references_with_transactions: Vec<_> =
            block_references_with_transactions
                .iter()
                .filter(|block_reference| {
                    !processed_references_with_transactions.contains(block_reference)
                })
                .copied()
                .collect();

        let success: bool = !processed.is_empty() || !updated_existing_with_transactions.is_empty();
        tracing::debug!("Processed new {:?}", processed);
        tracing::debug!(
            "Processed existing blocks with upgraded transactions {:?}",
            updated_existing_with_transactions
        );

        for processed in &processed {
            self.dag_state
                .add_to_threshold_clock(*processed.reference());
            self.pending
                .push(MetaTransaction::Include(*processed.reference()));
            self.attach_pending_transaction_data(processed);
        }
        tracing::debug!("Pending after adding blocks: {:?}", self.pending);
        self.run_block_handler();
        self.update_pending_metrics();
        (
            success,
            not_processed_block_references_with_transactions,
            missing_references,
            processed_references_without_transactions,
        )
    }

    /// Add header-only blocks to the DAG. Skips transaction-related bookkeeping
    /// that `add_blocks` performs (transaction tracking, partitioning by
    /// transaction presence).
    pub fn add_headers(
        &mut self,
        headers: Vec<Data<VerifiedBlock>>,
    ) -> (bool, AHashSet<BlockReference>, Vec<BlockReference>) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::add_headers");
        let (processed, _, missing_references) = timed!(
            self.metrics,
            "BlockManager::add_headers",
            self.block_manager.add_blocks(headers)
        );
        let success = !processed.is_empty();
        let mut processed_refs = Vec::with_capacity(processed.len());
        for block in &processed {
            self.dag_state
                .add_to_threshold_clock(*block.reference());
            self.pending
                .push(MetaTransaction::Include(*block.reference()));
            self.attach_pending_transaction_data(block);
            processed_refs.push(*block.reference());
        }
        self.run_block_handler();
        self.update_pending_metrics();
        (success, missing_references, processed_refs)
    }

    /// Attach recovered transaction data directly to existing blocks in the
    /// DAG. Bypasses the block manager — headers are already accepted and
    /// connected.
    pub fn add_transaction_data(&mut self, items: Vec<ReconstructedTransactionData>) {
        for item in items {
            self.attach_or_buffer_transaction_data(item);
        }
        self.update_pending_metrics();
    }

    fn attach_or_buffer_transaction_data(&mut self, item: ReconstructedTransactionData) {
        if !self.dag_state.attach_transaction_data(
            item.block_reference,
            &item.transaction_data,
            &item.shard_data,
        ) {
            self.pending_reconstructed_data
                .insert(item.block_reference, item);
        }
    }

    fn update_pending_metrics(&self) {
        self.metrics
            .block_manager_pending_blocks
            .set(self.block_manager.pending_blocks_count() as i64);
        for (i, missing_set) in self.block_manager.missing_blocks().iter().enumerate() {
            self.metrics
                .missing_blocks
                .with_label_values(&[&i.to_string()])
                .set(missing_set.len() as i64);
        }
        self.metrics
            .core_pending_reconstructed_data
            .set(self.pending_reconstructed_data.len() as i64);
    }

    fn attach_pending_transaction_data(&mut self, block: &Data<VerifiedBlock>) {
        let block_ref = *block.reference();
        let Some(item) = self.pending_reconstructed_data.remove(&block_ref) else {
            return;
        };

        if block.has_transaction_data() {
            return;
        }

        if !self.dag_state.attach_transaction_data(
            item.block_reference,
            &item.transaction_data,
            &item.shard_data,
        ) {
            self.pending_reconstructed_data.insert(block_ref, item);
        }
    }

    fn run_block_handler(&mut self) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::run_block_handler");
        let transactions = self.block_handler.handle_blocks(!self.epoch_changing());
        self.pending.push(MetaTransaction::Payload(transactions));
    }

    fn sort_includes_in_pending(&mut self) {
        let mut include_positions = Vec::new();
        let mut includes = Vec::new();
        for (i, meta) in self.pending.iter().enumerate() {
            if let MetaTransaction::Include(r) = meta {
                include_positions.push(i);
                includes.push(*r);
            }
        }
        includes.sort_by_key(|r| r.round);
        for (pos, include) in include_positions.into_iter().zip(includes) {
            self.pending[pos] = MetaTransaction::Include(include);
        }
    }

    pub fn try_new_block(&mut self) -> Option<Data<VerifiedBlock>> {
        let _block_timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::new_block::try_new_block");

        // Check if we're ready for a new block
        let clock_round = self.dag_state.threshold_clock_round();
        tracing::debug!(
            "Attempt to construct block in round {}. Current pending: {:?}",
            clock_round,
            self.pending
        );
        if clock_round <= self.last_proposed() {
            return None;
        }

        let pending_transactions = timed!(
            self.metrics,
            "Core::new_block::get_pending_transactions",
            self.get_pending_transactions(clock_round)
        );
        let (mut transactions, block_references) = timed!(
            self.metrics,
            "Core::new_block::collect_transactions_and_references",
            self.collect_transactions_and_references(pending_transactions)
        );
        timed!(
            self.metrics,
            "Core::new_block::prepare_last_blocks",
            self.prepare_last_blocks()
        );
        let mut encoded_transactions = timed!(
            self.metrics,
            "Core::new_block::prepare_encoded_transactions",
            self.prepare_encoded_transactions(&transactions)
        );
        let acknowledgment_references =
            if self.dag_state.consensus_protocol.supports_acknowledgments() {
                timed!(
                    self.metrics,
                    "Core::new_block::get_pending_acknowledgment",
                    self.dag_state.get_pending_acknowledgment(clock_round)
                )
            } else {
                Vec::new()
            };
        let number_of_blocks_to_create = self.last_own_block.len();
        let authority_bounds = timed!(
            self.metrics,
            "Core::new_block::calculate_authority_bounds",
            self.calculate_authority_bounds(number_of_blocks_to_create)
        );

        // Create and store blocks
        let mut first_block = None;
        for block_id in 0..number_of_blocks_to_create {
            // Equivocators include their transactions only in first block, but leave other
            // empty to not overload the bandwidth
            if block_id == 1 {
                transactions = vec![];
                encoded_transactions = self.prepare_encoded_transactions(&transactions);
            }
            let block_data = timed!(
                self.metrics,
                "Core::new_block::build_block",
                self.build_block(
                    &block_references,
                    &transactions,
                    &encoded_transactions,
                    &acknowledgment_references,
                    clock_round,
                    block_id,
                )
            );
            tracing::debug!("Created block {:?}", block_data);
            if first_block.is_none() {
                first_block = Some(block_data.clone());
            }
            timed!(
                self.metrics,
                "Core::new_block::store_block",
                self.store_block(block_data, &authority_bounds, block_id)
            );
        }

        self.persist_to_storage("Core::new_block");

        first_block
    }

    fn get_pending_transactions(&mut self, clock_round: RoundNumber) -> Vec<MetaTransaction> {
        self.sort_includes_in_pending();

        let split_point = self
            .pending
            .iter()
            .position(|meta_tx| match meta_tx {
                MetaTransaction::Include(block_ref) => block_ref.round >= clock_round,
                _ => false,
            })
            .unwrap_or(self.pending.len());

        let mut taken = self.pending.split_off(split_point);
        mem::swap(&mut taken, &mut self.pending);
        taken
    }

    fn collect_transactions_and_references(
        &self,
        pending: Vec<MetaTransaction>,
    ) -> (Vec<BaseTransaction>, Vec<BlockReference>) {
        let mut transactions = Vec::new();
        let mut pending_refs = Vec::new();
        let epoch_changing = self.epoch_changing();
        for meta_transaction in pending {
            match meta_transaction {
                MetaTransaction::Payload(payload) => {
                    if !epoch_changing {
                        transactions.extend(payload);
                    }
                }
                MetaTransaction::Include(include) => pending_refs.push(include),
            }
        }
        let block_references = self.compress_pending_block_references(&pending_refs);
        (transactions, block_references)
    }

    fn prepare_encoded_transactions(
        &mut self,
        transactions: &[BaseTransaction],
    ) -> Option<Vec<Shard>> {
        let info_length = self.committee.info_length();
        let parity_length = self.committee.len() - info_length;

        match self.dag_state.consensus_protocol {
            ConsensusProtocol::StarfishPull
            | ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishS => Some(self.encoder.encode_transactions(
                transactions,
                info_length,
                parity_length,
            )),
            ConsensusProtocol::Mysticeti | ConsensusProtocol::CordialMiners => None,
        }
    }

    /// For StarfishS, compute whether this block carries a strong vote for the
    /// current leader. A strong vote is true when the party votes for the
    /// leader AND has data available for the leader block and all blocks in
    /// the leader's acknowledgment_references.
    fn compute_strong_vote(
        &self,
        clock_round: RoundNumber,
        block_references: &[BlockReference],
    ) -> Option<bool> {
        if self.dag_state.consensus_protocol != ConsensusProtocol::StarfishS {
            return None;
        }

        // The leader is from the previous round.
        let leader_round = clock_round.saturating_sub(1);
        if leader_round == 0 {
            return Some(false);
        }
        let leader = self.committee.elect_leader(leader_round);

        // Check if we include (vote for) the leader's block.
        let leader_ref = block_references
            .iter()
            .find(|r| r.round == leader_round && r.authority == leader);

        let Some(leader_ref) = leader_ref else {
            // We don't vote for the leader → not a strong vote.
            return Some(false);
        };

        // We vote for the leader. Check data availability for the leader block
        // and all blocks in the leader's acknowledgment_references.
        if !self.dag_state.is_data_available(leader_ref) {
            return Some(false);
        }

        let leader_block = self
            .dag_state
            .get_storage_block(*leader_ref)
            .expect("Leader block should exist if it's in our includes");

        for ack_ref in leader_block.acknowledgments() {
            if !self.dag_state.is_data_available(&ack_ref) {
                return Some(false);
            }
        }

        Some(true)
    }

    fn build_block(
        &self,
        block_references_without_own: &[BlockReference],
        transactions: &[BaseTransaction],
        encoded_transactions: &Option<Vec<Shard>>,
        acknowledgment_references: &[BlockReference],
        clock_round: RoundNumber,
        block_id_in_round: usize,
    ) -> Data<VerifiedBlock> {
        let time_ns = timestamp_utc().as_nanos() + block_id_in_round as u128;
        let mut block_references = vec![*self.last_own_block[block_id_in_round].block.reference()];
        block_references.extend(block_references_without_own.iter().cloned());

        let prev_round_ref_count = block_references
            .iter()
            .filter(|r| r.round + 1 == clock_round)
            .count();
        let block_ref_count = block_references.len();
        self.metrics
            .previous_round_refs
            .observe(prev_round_ref_count as f64);

        let strong_vote = self.compute_strong_vote(clock_round, &block_references);

        let mut block = VerifiedBlock::new_with_signer(
            self.authority,
            clock_round,
            block_references,
            acknowledgment_references.to_vec(),
            time_ns,
            self.epoch_changing(),
            &self.signer,
            transactions.to_vec(),
            encoded_transactions.clone(),
            self.dag_state.consensus_protocol,
            strong_vote,
        );

        self.metrics
            .proposed_block_refs
            .observe(block_ref_count as f64);
        self.metrics
            .proposed_block_acks
            .observe(block.acknowledgment_count() as f64);

        block.preserialize();
        Data::new(block)
    }

    fn prepare_last_blocks(&mut self) {
        let target = match self.dag_state.byzantine_strategy {
            Some(
                ByzantineStrategy::EquivocatingChains | ByzantineStrategy::EquivocatingChainsBomb,
            ) => self.committee.len(),
            Some(ByzantineStrategy::EquivocatingTwoChains) => 2,
            _ => return,
        };
        for _ in self.last_own_block.len()..target {
            self.last_own_block.push(self.last_own_block[0].clone());
        }
    }

    fn calculate_authority_bounds(&self, num_blocks: usize) -> Vec<usize> {
        let len = self.committee.len();
        let mut bounds = vec![0];
        if matches!(
            self.dag_state.byzantine_strategy,
            Some(ByzantineStrategy::EquivocatingTwoChains)
        ) {
            bounds.push(len.div_ceil(2));
            bounds.push(len);
        } else {
            for i in 1..=num_blocks {
                bounds.push(i * len / num_blocks);
            }
        }
        bounds
    }

    fn compress_pending_block_references(
        &self,
        pending_refs: &[BlockReference],
    ) -> Vec<BlockReference> {
        let mut references_in_block: AHashSet<BlockReference> = AHashSet::new();

        let blocks = self.dag_state.get_storage_blocks(pending_refs);
        for block in blocks.into_iter().flatten() {
            references_in_block.extend(block.block_references());
        }

        let mut compressed = vec![];

        for r in pending_refs {
            if !references_in_block.contains(r) && r.authority != self.authority {
                compressed.push(*r);
            }
        }

        assert!(!compressed.is_empty());
        compressed
    }

    fn store_block(
        &mut self,
        block_data: Data<VerifiedBlock>,
        authority_bounds: &[usize],
        block_id: usize,
    ) {
        self.dag_state
            .add_to_threshold_clock(*block_data.reference());
        self.block_handler
            .handle_proposal(block_data.number_transactions());
        self.proposed_block_stats(&block_data);

        let own_block = OwnBlockData {
            block: block_data,
            authority_index_start: authority_bounds[block_id] as AuthorityIndex,
            authority_index_end: authority_bounds[block_id + 1] as AuthorityIndex,
        };
        self.last_own_block[block_id] = own_block.clone();
        self.dag_state.insert_own_block(own_block);
    }

    fn proposed_block_stats(&self, block: &Data<VerifiedBlock>) {
        self.metrics.created_own_blocks.inc();
        self.metrics
            .proposed_block_size_bytes
            .observe(block.serialized_bytes().len());
        if let Some(transactions) = block.transactions() {
            if transactions.is_empty() {
                self.metrics.proposed_transaction_size_bytes.observe(0);
            } else {
                let total_bytes: usize = transactions
                    .iter()
                    .map(|stmt| {
                        let BaseTransaction::Share(tx) = stmt;
                        tx.as_bytes().len()
                    })
                    .sum();
                self.metrics
                    .proposed_transaction_size_bytes
                    .observe(total_bytes);
            }
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn try_commit(&mut self) -> (Vec<(Data<VerifiedBlock>, Option<CommitMetastate>)>, bool) {
        let leaders = self.committer.try_commit(self.last_commit_leader);
        let any_decided = !leaders.is_empty();
        let sequence: Vec<_> = leaders
            .into_iter()
            .filter_map(|leader| leader.into_decided_block())
            .collect();

        if let Some((last, _meta)) = sequence.last() {
            self.last_commit_leader = *last.reference();
        }

        // todo: should ideally come from execution result of epoch smart contract
        if self.last_commit_leader.round() > self.rounds_in_epoch {
            self.epoch_manager.epoch_change_begun();
        }

        (sequence, any_decided)
    }

    pub fn cleanup(&mut self) -> RoundNumber {
        self.dag_state.cleanup();
        let threshold = self.dag_state.gc_round();
        self.pending_reconstructed_data
            .retain(|block_ref, _| block_ref.round >= threshold);
        self.committer.cleanup(threshold);
        self.update_pending_metrics();
        threshold
    }

    /// This only checks readiness in terms of helping liveness for commit rule,
    /// try_new_block might still return None if threshold clock is not ready
    ///
    /// The algorithm to calling is roughly:
    /// if timeout || commit_ready_new_block then try_new_block(..)
    pub fn ready_new_block(&self, connected_authorities: &AHashSet<AuthorityIndex>) -> bool {
        let quorum_round = self.dag_state.threshold_clock_round();
        tracing::debug!("Attempt ready new block, quorum round {}", quorum_round);

        if quorum_round < self.last_commit_leader.round().max(1) {
            return false;
        }

        let leader_round = quorum_round - 1;
        let mut leaders = self.committer.get_leaders(leader_round);
        leaders.retain(|leader| connected_authorities.contains(leader));
        tracing::debug!(
            "Attempt ready new block, quorum round {}, Before exist at authority round",
            quorum_round
        );
        if !self
            .dag_state
            .all_blocks_exists_at_authority_round(&leaders, leader_round)
        {
            return false;
        }

        // Wait for a quorum of blocks at leader_round that voted for
        // the leader of leader_round - 1.
        if leader_round >= 2 {
            let prev_leader = self.committee.elect_leader(leader_round - 1);
            if !self.dag_state.has_votes_quorum_at_round(
                leader_round,
                prev_leader,
                leader_round - 1,
                &self.committee,
            ) {
                return false;
            }

            // StarfishS: also require a quorum of strong votes at leader_round.
            if self.dag_state.consensus_protocol == ConsensusProtocol::StarfishS
                && !self
                    .dag_state
                    .has_strong_votes_quorum_at_round(leader_round, &self.committee)
            {
                return false;
            }
        }

        true
    }

    pub fn handle_committed_subdag(&mut self, committed: Vec<CommittedSubDag>, any_decided: bool) {
        let mut commit_data = vec![];
        for commit in &committed {
            self.dag_state
                .update_last_available_commit(commit.anchor.round);
            self.dag_state.update_last_committed_rounds(commit);
            for block in &commit.blocks {
                self.epoch_manager
                    .observe_committed_block(block, &self.committee);
            }
            let committed_rounds = self.dag_state.last_committed_rounds();
            commit_data.push(CommitData::new(commit, committed_rounds));
        }
        let store_start = std::time::Instant::now();
        self.store
            .store_commits(commit_data)
            .expect("Store commits should not fail");
        self.metrics
            .store_commits_latency_us
            .inc_by(store_start.elapsed().as_micros() as u64);
        self.metrics.store_commits_count.inc();
        if any_decided {
            self.persist_to_storage("Core::commit");
        }
    }

    fn persist_to_storage(&self, label: &str) {
        if self.options.fsync {
            let _t = self
                .metrics
                .utilization_timer
                .utilization_timer(&format!("{label}::sync_with_disk"));
            self.store.sync().expect("Storage sync failed");
        } else {
            let _t = self
                .metrics
                .utilization_timer
                .utilization_timer(&format!("{label}::flush_to_buffer"));
            self.store.flush().expect("Storage flush failed");
        }
    }

    pub fn write_commits(&mut self, _commits: &[CommitData]) {}

    pub fn take_recovered_committed(&mut self) -> (AHashSet<BlockReference>, usize) {
        let committed_blocks = self
            .recovered_committed_blocks
            .take()
            .expect("take_recovered_committed called twice");
        let committed_leaders_count = self
            .recovered_committed_leaders_count
            .take()
            .expect("take_recovered_committed called twice");
        (committed_blocks, committed_leaders_count)
    }

    pub fn dag_state(&self) -> &DagState {
        &self.dag_state
    }
    pub fn store(&self) -> Arc<dyn Store> {
        self.store.clone()
    }

    // This function is needed only for signalling that we created a new block
    pub fn last_own_block(&self) -> &Data<VerifiedBlock> {
        &self.last_own_block[0].block
    }

    // This function is needed only for retrieving the last round of a block we
    // proposed
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
