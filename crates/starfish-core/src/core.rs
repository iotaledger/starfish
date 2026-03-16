// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{mem, sync::Arc};

use ahash::{AHashMap, AHashSet};
use reed_solomon_simd::ReedSolomonEncoder;

use tokio::sync::mpsc;

use crate::{
    block_handler::BlockHandler,
    block_manager::BlockManager,
    bls_certificate_aggregator::{BlsCertificateAggregator, apply_certificate_events},
    committee::Committee,
    config::NodePrivateConfig,
    consensus::{
        CommitMetastate,
        linearizer::CommittedSubDag,
        universal_committer::{UniversalCommitter, UniversalCommitterBuilder},
    },
    crypto::{self, AsBytes, BlsSignatureBytes, BlsSigner, Signer},
    dag_state::{
        ByzantineStrategy, CACHED_ROUNDS, CommitData, ConsensusProtocol, DagState, DataSource,
        OwnBlockData,
    },
    data::Data,
    encoder::ShardEncoder,
    metrics::{Metrics, UtilizationTimerVecExt},
    runtime::timestamp_utc,
    state::RecoveredState,
    store::Store,
    types::{
        AuthorityIndex, BaseTransaction, BlockReference, BlsAggregateCertificate, Encoder,
        PartialSig, PartialSigKind, ProvableShard, ReconstructedTransactionData, RoundNumber,
        Shard, VerifiedBlock,
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
    signer: Signer,
    bls_signer: BlsSigner,
    partial_sig_outbox: Option<mpsc::UnboundedSender<PartialSig>>,
    // todo - ugly, probably need to merge syncer and core
    recovered_committed_blocks: Option<AHashSet<BlockReference>>,
    recovered_committed_leaders_count: Option<usize>,
    committer: UniversalCommitter,
    pub(crate) encoder: Encoder,
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
        metrics: Arc<Metrics>,
        recovered: RecoveredState,
        partial_sig_outbox: Option<mpsc::UnboundedSender<PartialSig>>,
    ) -> (Self, Option<BlsCertificateAggregator>) {
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
            .find(|b| b.authority() == authority)
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

        let committer =
            UniversalCommitterBuilder::new(committee.clone(), dag_state.clone(), metrics.clone())
                .build();
        let encoder = ReedSolomonEncoder::new(2, 4, 2).unwrap();

        let bls_cert_aggregator = if dag_state.consensus_protocol == ConsensusProtocol::StarfishBls
        {
            let mut aggregator = BlsCertificateAggregator::new(committee.clone());
            // Replay recovered blocks through the aggregator to rebuild
            // certificate state (in-memory only — not persisted).
            let (events, _) = aggregator.add_blocks(&unprocessed_blocks);
            apply_certificate_events(&dag_state, events);
            Some(aggregator)
        } else {
            None
        };

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
            signer: private_config.keypair,
            bls_signer: private_config.bls_keypair,
            partial_sig_outbox,
            recovered_committed_blocks: Some(committed_blocks),
            recovered_committed_leaders_count: Some(committed_leaders_count),
            committer,
            encoder,
        };

        if !unprocessed_blocks.is_empty() {
            tracing::info!(
                "Recovered {} blocks from storage; rebuilt pending and clock",
                unprocessed_blocks.len()
            );
        }

        (this, bls_cert_aggregator)
    }

    pub fn get_signer(&self) -> &Signer {
        &self.signer
    }

    pub fn get_universal_committer(&self) -> UniversalCommitter {
        self.committer.clone()
    }

    // This function attempts to add blocks to the local DAG.
    // It returns four values. First is bool which is true if any update was made
    // successfully. Second, it returns a vector of references for blocks with
    // transactions that are not added to the local DAG and remain
    // pending. For such blocks we need to send a missing parents request.
    // Third, it returns a set of parents that are still missing
    // and need to be requested.
    // Fourth, it returns a vector of references for blocks without
    // transactions that are added to the local DAG.
    #[allow(clippy::type_complexity)]
    pub fn add_blocks(
        &mut self,
        blocks: Vec<(Data<VerifiedBlock>, Option<ProvableShard>)>,
        source: DataSource,
    ) -> (
        bool,
        Vec<BlockReference>,
        AHashSet<BlockReference>,
        Vec<BlockReference>,
        Vec<Data<VerifiedBlock>>,
    ) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::add_blocks");
        let mut block_shards = Vec::new();
        let blocks: Vec<_> = blocks
            .into_iter()
            .map(|(block, shard)| {
                if let Some(shard) = shard {
                    block_shards.push((*block.reference(), shard));
                }
                block
            })
            .collect();
        if !block_shards.is_empty() {
            self.dag_state.insert_shards_batch(block_shards);
        }
        let block_references_with_transactions: Vec<_> = blocks
            .iter()
            .filter(|b| b.transactions().is_some())
            .map(|b| *b.reference())
            .collect();
        let (processed, updated_existing_with_transactions, missing_references) = timed!(
            self.metrics,
            "BlockManager::add_blocks",
            self.block_manager.add_blocks(blocks, source)
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

        for block in &processed {
            self.pending
                .push(MetaTransaction::Include(*block.reference()));
            self.attach_pending_transaction_data(block);
            if block.transactions().is_some() {
                self.sign_and_enqueue_dac(block.reference());
            }
        }
        tracing::debug!("Pending after adding blocks: {:?}", self.pending);
        self.run_block_handler();
        self.update_pending_metrics();
        (
            success,
            not_processed_block_references_with_transactions,
            missing_references,
            processed_references_without_transactions,
            processed,
        )
    }

    /// Add header-only blocks to the DAG. Skips transaction-related bookkeeping
    /// that `add_blocks` performs (transaction tracking, partitioning by
    /// transaction presence).
    pub fn add_headers(
        &mut self,
        headers: Vec<Data<VerifiedBlock>>,
        source: DataSource,
    ) -> (
        bool,
        AHashSet<BlockReference>,
        Vec<BlockReference>,
        Vec<Data<VerifiedBlock>>,
    ) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::add_headers");
        let (processed, _, missing_references) = timed!(
            self.metrics,
            "BlockManager::add_headers",
            self.block_manager.add_blocks(headers, source)
        );
        let success = !processed.is_empty();
        let mut processed_refs = Vec::with_capacity(processed.len());
        for block in &processed {
            self.pending
                .push(MetaTransaction::Include(*block.reference()));
            self.attach_pending_transaction_data(block);
            processed_refs.push(*block.reference());
        }
        self.run_block_handler();
        self.update_pending_metrics();
        (success, missing_references, processed_refs, processed)
    }

    /// Attach recovered transaction data directly to existing blocks in the
    /// DAG. Bypasses the block manager — headers are already accepted and
    /// connected.
    pub fn add_transaction_data(
        &mut self,
        items: Vec<ReconstructedTransactionData>,
        source: DataSource,
    ) {
        for item in items {
            let block_ref = item.block_reference;
            self.attach_or_buffer_transaction_data(item, source);
            self.sign_and_enqueue_dac(&block_ref);
        }
        self.update_pending_metrics();
    }

    fn attach_or_buffer_transaction_data(
        &mut self,
        item: ReconstructedTransactionData,
        source: DataSource,
    ) {
        if !self.dag_state.attach_transaction_data(
            item.block_reference,
            &item.transaction_data,
            &item.shard_data,
            source,
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

        if self.dag_state.attach_transaction_data(
            item.block_reference,
            &item.transaction_data,
            &item.shard_data,
            DataSource::ShardReconstructor,
        ) {
            self.sign_and_enqueue_dac(&block_ref);
        } else {
            self.pending_reconstructed_data.insert(block_ref, item);
        }
    }

    /// Sign and enqueue a standalone DAC partial signature for a remote block.
    /// No-op for non-StarfishBls or own blocks.
    fn sign_and_enqueue_dac(&self, block_ref: &BlockReference) {
        if block_ref.authority == self.authority {
            return;
        }
        let Some(ref outbox) = self.partial_sig_outbox else {
            return;
        };
        let digest = crypto::bls_dac_message(block_ref);
        let sig = self.bls_signer.sign_digest(&digest);
        let _ = outbox.send(PartialSig {
            kind: PartialSigKind::Dac(*block_ref),
            signer: self.authority,
            signature: sig,
        });
    }

    fn run_block_handler(&mut self) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::run_block_handler");
        let transactions = self.block_handler.handle_blocks(true);
        self.pending.push(MetaTransaction::Payload(transactions));
    }

    fn requeue_transactions(&mut self, transactions: Vec<BaseTransaction>) {
        if transactions.is_empty() {
            return;
        }
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

    pub fn try_new_block(&mut self, reason: &'static str) -> Option<Data<VerifiedBlock>> {
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

        let voted_leader_ref =
            if self.dag_state.consensus_protocol == ConsensusProtocol::StarfishBls {
                self.select_starfish_bls_voted_leader(clock_round)
            } else {
                None
            };

        // StarfishBls must not drain the pending frontier before the previous
        // round certificate is available, otherwise timeout retries can rebuild
        // the same round from a truncated queue.
        let aggregate_round_sig =
            if self.dag_state.consensus_protocol == ConsensusProtocol::StarfishBls {
                if clock_round <= 1 {
                    None
                } else {
                    Some(self.dag_state.round_certificate(clock_round - 1)?)
                }
            } else {
                None
            };

        let pending_transactions = timed!(
            self.metrics,
            "Core::new_block::get_pending_transactions",
            self.get_pending_transactions(clock_round)
        );
        let (mut transactions, block_references) = timed!(
            self.metrics,
            "Core::new_block::collect_transactions_and_references",
            self.collect_transactions_and_references(pending_transactions, clock_round)
        );
        let starfish_speed_excluded_authors = self.starfish_speed_excluded_ack_authors(clock_round);
        if starfish_speed_excluded_authors & (1u128 << self.authority) != 0 {
            self.requeue_transactions(std::mem::take(&mut transactions));
        }
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
        let acknowledgment_references = self.filter_starfish_speed_leader_acknowledgments(
            starfish_speed_excluded_authors,
            acknowledgment_references,
        );
        let number_of_blocks_to_create = self.last_own_block.len();
        let authority_bounds = timed!(
            self.metrics,
            "Core::new_block::calculate_authority_bounds",
            self.calculate_authority_bounds(number_of_blocks_to_create)
        );

        let certified_leader =
            if self.dag_state.consensus_protocol == ConsensusProtocol::StarfishBls {
                // Leader cert for leader of clock_round - 1 (if we include that leader).
                if clock_round <= 2 {
                    None
                } else {
                    let leader_round = clock_round - 1;
                    let leader_authority = self.committee.elect_leader(leader_round);
                    block_references
                        .iter()
                        .find(|r| r.round == leader_round && r.authority == leader_authority)
                        .and_then(|leader_ref| {
                            self.dag_state
                                .leader_certificate(leader_ref)
                                .map(|cert| (*leader_ref, cert))
                        })
                }
            } else {
                None
            };

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
                    voted_leader_ref,
                    &transactions,
                    &encoded_transactions,
                    &acknowledgment_references,
                    clock_round,
                    block_id,
                    aggregate_round_sig,
                    certified_leader,
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

        self.metrics
            .created_own_blocks
            .with_label_values(&[reason])
            .inc();

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
        block_round: RoundNumber,
    ) -> (Vec<BaseTransaction>, Vec<BlockReference>) {
        let mut transactions = Vec::new();
        let mut pending_refs = Vec::new();
        for meta_transaction in pending {
            match meta_transaction {
                MetaTransaction::Payload(payload) => {
                    transactions.extend(payload);
                }
                MetaTransaction::Include(include) => pending_refs.push(include),
            }
        }
        let block_references = self.compress_pending_block_references(&pending_refs, block_round);
        (transactions, block_references)
    }

    fn prepare_encoded_transactions(
        &mut self,
        transactions: &[BaseTransaction],
    ) -> Option<Vec<Shard>> {
        if transactions.is_empty() {
            return None;
        }
        let info_length = self.committee.info_length();
        let parity_length = self.committee.len() - info_length;

        match self.dag_state.consensus_protocol {
            ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishSpeed
            | ConsensusProtocol::StarfishBls => Some(self.encoder.encode_transactions(
                transactions,
                info_length,
                parity_length,
            )),
            ConsensusProtocol::Mysticeti
            | ConsensusProtocol::CordialMiners
            | ConsensusProtocol::SailfishPlusPlus => None,
        }
    }

    /// For StarfishSpeed, compute the strong-vote hint mask for the current
    /// leader. `Some(0)` means the vote is strong; `Some(nonzero)` records the
    /// authorities whose payloads are still missing locally.
    fn compute_strong_vote(
        &self,
        clock_round: RoundNumber,
        block_references: &[BlockReference],
    ) -> Option<u128> {
        if self.dag_state.consensus_protocol != ConsensusProtocol::StarfishSpeed {
            return None;
        }

        // The leader is from the previous round.
        let leader_round = clock_round.saturating_sub(1);
        if leader_round == 0 {
            return None;
        }
        let leader = self.committee.elect_leader(leader_round);

        // Check if we include (vote for) the leader's block.
        let leader_ref = block_references
            .iter()
            .find(|r| r.round == leader_round && r.authority == leader);

        let leader_ref = leader_ref?;

        let mut missing_mask = 0u128;
        if !self.dag_state.is_data_available(leader_ref) {
            missing_mask |= 1u128 << leader_ref.authority;
        }

        let leader_block = self
            .dag_state
            .get_storage_block(*leader_ref)
            .expect("Leader block should exist if it's in our includes");

        for ack_ref in leader_block.acknowledgments() {
            if !self.dag_state.is_data_available(&ack_ref) {
                missing_mask |= 1u128 << ack_ref.authority;
            }
        }

        Some(missing_mask)
    }

    fn starfish_speed_excluded_ack_authors(&self, clock_round: RoundNumber) -> u128 {
        if self.dag_state.consensus_protocol != ConsensusProtocol::StarfishSpeed
            || self.committee.elect_leader(clock_round) != self.authority
        {
            return 0;
        }

        self.dag_state.starfish_speed_excluded_ack_authorities()
    }

    fn filter_starfish_speed_leader_acknowledgments(
        &self,
        excluded_authors: u128,
        acknowledgment_references: Vec<BlockReference>,
    ) -> Vec<BlockReference> {
        if excluded_authors == 0 {
            return acknowledgment_references;
        }

        let (to_include, to_requeue): (Vec<_>, Vec<_>) = acknowledgment_references
            .into_iter()
            .partition(|ack_ref| excluded_authors & (1u128 << ack_ref.authority) == 0);
        if !to_requeue.is_empty() {
            self.dag_state.requeue_pending_acknowledgment(to_requeue);
        }
        to_include
    }

    fn build_block(
        &self,
        block_references_without_own: &[BlockReference],
        voted_leader_ref: Option<BlockReference>,
        transactions: &[BaseTransaction],
        encoded_transactions: &Option<Vec<Shard>>,
        acknowledgment_references: &[BlockReference],
        clock_round: RoundNumber,
        block_id_in_round: usize,
        aggregate_round_sig: Option<BlsAggregateCertificate>,
        certified_leader: Option<(BlockReference, BlsAggregateCertificate)>,
    ) -> Data<VerifiedBlock> {
        let time_ns = timestamp_utc().as_nanos() as u64 + block_id_in_round as u64;
        let own_previous = *self.last_own_block[block_id_in_round].block.reference();
        let mut block_references = vec![own_previous];
        if self.dag_state.consensus_protocol == ConsensusProtocol::StarfishBls {
            if let Some(leader_ref) = voted_leader_ref {
                if leader_ref != own_previous {
                    block_references.push(leader_ref);
                }
            }
        }
        block_references.extend(block_references_without_own.iter().cloned());
        let mut seen_references = AHashSet::new();
        block_references.retain(|reference| seen_references.insert(*reference));

        let prev_round_ref_count = block_references
            .iter()
            .filter(|r| r.round + 1 == clock_round)
            .count();
        let block_ref_count = block_references.len();
        self.metrics
            .previous_round_refs
            .observe(prev_round_ref_count as f64);

        let strong_vote = self.compute_strong_vote(clock_round, &block_references);

        let is_starfish_l = self.dag_state.consensus_protocol == ConsensusProtocol::StarfishBls;
        let bls_signer_opt = if is_starfish_l {
            Some(&self.bls_signer)
        } else {
            None
        };
        let committee_opt = if is_starfish_l {
            Some(self.committee.as_ref())
        } else {
            None
        };

        // Fetch aggregated DAC certificates from the BLS aggregator.
        let aggregate_dac_sigs = if is_starfish_l {
            acknowledgment_references
                .iter()
                .map(|ack_ref| {
                    self.dag_state
                        .dac_certificate(ack_ref)
                        .expect("ack queued without DAC certificate")
                })
                .collect()
        } else {
            vec![]
        };

        let precomputed_round_sig = if is_starfish_l {
            let sig = self.dag_state.take_precomputed_round_sig(clock_round);
            if sig.is_some() {
                self.metrics.bls_presign_hit_total.inc();
            } else {
                self.metrics.bls_presign_miss_total.inc();
            }
            sig
        } else {
            None
        };
        let precomputed_leader_sig = if is_starfish_l {
            voted_leader_ref.and_then(|r| self.dag_state.take_precomputed_leader_sig(&r))
        } else {
            None
        };

        let mut block = VerifiedBlock::new_with_signer(
            self.authority,
            clock_round,
            block_references,
            voted_leader_ref,
            acknowledgment_references.to_vec(),
            time_ns,
            &self.signer,
            bls_signer_opt,
            committee_opt,
            aggregate_dac_sigs,
            transactions.to_vec(),
            encoded_transactions.clone(),
            self.dag_state.consensus_protocol,
            strong_vote,
            aggregate_round_sig,
            certified_leader,
            precomputed_round_sig,
            precomputed_leader_sig,
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
        block_round: RoundNumber,
    ) -> Vec<BlockReference> {
        if self.dag_state.consensus_protocol == ConsensusProtocol::StarfishBls {
            if self.committee.elect_leader(block_round) != self.authority {
                return Vec::new();
            }

            // StarfishBls leaders keep the full frontier so their header preserves
            // the direct previous-round quorum required by the protocol.
            let mut seen_references = AHashSet::new();
            return pending_refs
                .iter()
                .copied()
                .filter(|reference| {
                    reference.authority != self.authority && seen_references.insert(*reference)
                })
                .collect();
        }

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
        if compressed.is_empty() {
            return pending_refs
                .iter()
                .copied()
                .filter(|r| r.authority != self.authority)
                .collect();
        }
        compressed
    }

    fn select_starfish_bls_voted_leader(&self, clock_round: RoundNumber) -> Option<BlockReference> {
        let leader_round = clock_round.checked_sub(1)?;
        if leader_round == 0 {
            return None;
        }
        let leader_authority = self.committee.elect_leader(leader_round);
        self.dag_state
            .get_blocks_at_authority_round(leader_authority, leader_round)
            .into_iter()
            .min_by_key(|block| *block.reference())
            .map(|block| *block.reference())
    }

    fn store_block(
        &mut self,
        block_data: Data<VerifiedBlock>,
        authority_bounds: &[usize],
        block_id: usize,
    ) {
        self.block_handler
            .handle_proposal(block_data.number_transactions());
        self.proposed_block_stats(&block_data);

        let own_block = OwnBlockData {
            block: block_data,
            authority_index_start: authority_bounds[block_id] as AuthorityIndex,
            authority_index_end: authority_bounds[block_id + 1] as AuthorityIndex,
        };
        self.last_own_block[block_id] = own_block.clone();
        self.dag_state.insert_own_block(own_block.clone());
    }

    /// Generate an own DAC partial signature for a block we just created.
    /// Returns the data needed by the aggregator without touching it.
    pub fn generate_own_dac_partial_sig(
        &self,
        block: &Data<VerifiedBlock>,
    ) -> Option<(BlockReference, AuthorityIndex, BlsSignatureBytes)> {
        if self.dag_state.consensus_protocol != ConsensusProtocol::StarfishBls {
            return None;
        }
        if block.has_empty_payload() {
            return None;
        }
        let own_ref = *block.reference();
        let digest = crypto::bls_dac_message(&own_ref);
        let sig = self.bls_signer.sign_digest(&digest);
        Some((own_ref, self.authority, sig))
    }

    fn proposed_block_stats(&self, block: &Data<VerifiedBlock>) {
        self.metrics
            .proposed_block_size_bytes
            .observe(block.serialized_bytes().len());
        if let Some(header_bytes) = block.serialized_header_bytes() {
            self.metrics
                .proposed_header_size_bytes
                .observe(header_bytes.len());
        }
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

        (sequence, any_decided)
    }

    pub fn cleanup(&mut self) -> RoundNumber {
        self.dag_state.cleanup();
        let threshold = self.dag_state.gc_round();
        self.block_manager
            .cleanup(threshold.saturating_sub(CACHED_ROUNDS));
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
    pub fn ready_new_block_relaxed(
        &self,
        connected_authorities: &AHashSet<AuthorityIndex>,
    ) -> bool {
        self.ready_new_block_impl(connected_authorities, true)
    }

    pub fn ready_new_block(&self, connected_authorities: &AHashSet<AuthorityIndex>) -> bool {
        self.ready_new_block_impl(connected_authorities, false)
    }

    fn ready_new_block_impl(
        &self,
        connected_authorities: &AHashSet<AuthorityIndex>,
        relaxed: bool,
    ) -> bool {
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
        self.dag_state.is_ready_for_new_block(
            quorum_round,
            &leaders,
            relaxed,
            self.authority,
            &self.committee,
        )
    }

    pub fn handle_committed_subdag(&mut self, committed: Vec<CommittedSubDag>, _any_decided: bool) {
        let mut commit_data = vec![];
        for commit in &committed {
            let committed_rounds = self.dag_state.update_commit_state(commit);
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
}
