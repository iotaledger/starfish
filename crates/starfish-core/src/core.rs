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
        AuthorityIndex, AuthoritySet, BaseTransaction, BlockReference, BlsAggregateCertificate,
        Encoder, PartialSig, PartialSigKind, ProvableShard, ReconstructedTransactionData,
        RoundNumber, SailfishFields, Shard, VerifiedBlock,
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
        let committee_len = committee.len();
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
                .max(dag_state.proposal_round().saturating_sub(1));
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

        let bls_cert_aggregator = if dag_state.consensus_protocol.uses_bls() {
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
        let clock_round = self.next_block_round();
        self.try_new_block_at_round(clock_round, reason)
    }

    fn try_new_block_at_round(
        &mut self,
        clock_round: RoundNumber,
        reason: &'static str,
    ) -> Option<Data<VerifiedBlock>> {
        let _block_timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::try_new_block");

        let proposal_round = self.dag_state.proposal_round();
        tracing::debug!(
            "Attempt to construct block in round {} (proposal round {}). Current pending: {:?}",
            clock_round,
            proposal_round,
            self.pending
        );
        if clock_round == 0 || proposal_round < clock_round {
            return None;
        }
        if clock_round != self.next_block_round() {
            return None;
        }

        let protocol = self.dag_state.consensus_protocol;

        // Dual-DAG protocols: require clean parent quorum before creating a block.
        if protocol.uses_dual_dag()
            && clock_round > 1
            && !self.dag_state.clean_parent_quorum(clock_round - 1)
        {
            tracing::debug!(
                "Cannot construct block in round {}: clean parent quorum \
                 missing for previous round {}",
                clock_round,
                clock_round - 1
            );
            return None;
        }

        let voted_leader_ref = if protocol.uses_bls() {
            self.select_starfish_bls_voted_leader(clock_round)
        } else {
            None
        };

        // BLS protocols must not drain the pending frontier before the previous
        // round certificate is available, otherwise timeout retries can rebuild
        // the same round from a truncated queue.
        let aggregate_round_sig = if protocol.uses_bls() {
            if clock_round <= 1 {
                None
            } else {
                Some(self.dag_state.round_certificate(clock_round - 1)?)
            }
        } else {
            None
        };

        let pending_transactions = self.get_pending_transactions(clock_round);
        let (mut transactions, block_references, raw_refs) =
            self.collect_transactions_and_references(pending_transactions, clock_round);

        // Dual-DAG protocols: if the clean-parent filter reduced the parent
        // set below threshold-clock quorum, we cannot build a valid block yet.
        // BLS non-leaders are exempt because they may legally build with only
        // their own previous block and, if present, the previous-round leader.
        // Requeue both transactions and include refs so the next attempt sees
        // them again.
        let is_current_leader = self.committee.elect_leader(clock_round) == self.authority;
        // BLS non-leaders can always build with minimal refs.
        let bls_non_leader = protocol.uses_bls() && !is_current_leader;
        // Bluestreak prev-round leader can build with own-prev only.
        let bluestreak_prev_leader = protocol.is_bluestreak()
            && self.committee.elect_leader(clock_round.saturating_sub(1)) == self.authority;
        // For Bluestreak non-leaders, forced (leader-timeout) block creation is
        // allowed to fall back to "own-prev only" when the previous-round
        // leader block is missing locally. Without this, a delayed/slow
        // previous leader can stall block production at large scale even after
        // the timeout fires.
        let bluestreak_timeout =
            reason == "force_timeout" && protocol.is_bluestreak() && !is_current_leader;
        let allows_minimal_refs = bls_non_leader || bluestreak_prev_leader || bluestreak_timeout;
        if bluestreak_timeout && block_references.is_empty() && !bluestreak_prev_leader {
            tracing::debug!(
                "Bluestreak: forcing block in round {} \
                 with only own-prev (missing clean prev-leader parent)",
                clock_round
            );
        }
        if protocol.uses_dual_dag()
            && clock_round > 1
            && block_references.is_empty()
            && !allows_minimal_refs
        {
            tracing::debug!(
                "Cannot construct block in round {}: no usable clean parent \
                 refs after filtering. raw_refs={:?}, reason={}, \
                 is_current_leader={}",
                clock_round,
                raw_refs,
                reason,
                is_current_leader
            );
            for r in raw_refs {
                self.pending.push(MetaTransaction::Include(r));
            }
            self.requeue_transactions(std::mem::take(&mut transactions));
            return None;
        }

        // SailfishPlusPlus: if the previous-round leader is not referenced,
        // the timeout-control rule must be satisfied before we construct the
        // block. Requeue both transactions and include refs so the next retry
        // sees the full frontier again.
        if protocol.is_sailfish_pp() && !self.sailfish_control_ready(clock_round, &block_references)
        {
            for r in raw_refs {
                self.pending.push(MetaTransaction::Include(r));
            }
            self.requeue_transactions(std::mem::take(&mut transactions));
            return None;
        }

        let starfish_speed_excluded_authors = self.starfish_speed_excluded_ack_authors(clock_round);
        if starfish_speed_excluded_authors.contains(self.authority) {
            self.requeue_transactions(std::mem::take(&mut transactions));
        }
        self.prepare_last_blocks();
        let mut encoded_transactions = self.prepare_encoded_transactions(&transactions);
        let acknowledgment_references = if protocol.supports_acknowledgments() {
            self.dag_state.get_pending_acknowledgment(clock_round)
        } else {
            Vec::new()
        };
        let acknowledgment_references = self.filter_starfish_speed_leader_acknowledgments(
            starfish_speed_excluded_authors,
            acknowledgment_references,
        );
        let number_of_blocks_to_create = self.last_own_block.len();
        let authority_bounds = self.calculate_authority_bounds(number_of_blocks_to_create);

        let certified_leader = if protocol.uses_bls() {
            // Votes for leader at round r are in round r+1; the
            // aggregated certificate is embedded in round r+2.
            if clock_round <= 3 {
                None
            } else {
                let leader_round = clock_round - 2;
                let leader_authority = self.committee.elect_leader(leader_round);
                self.dag_state
                    .get_blocks_at_authority_round(leader_authority, leader_round)
                    .into_iter()
                    .min_by_key(|b| *b.reference())
                    .and_then(|b| {
                        self.dag_state
                            .leader_certificate(b.reference())
                            .map(|cert| (*b.reference(), cert))
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
            let block_data = self.build_block(
                &block_references,
                voted_leader_ref,
                &transactions,
                &encoded_transactions,
                &acknowledgment_references,
                clock_round,
                block_id,
                aggregate_round_sig,
                certified_leader,
            );
            tracing::debug!("Created block {:?}", block_data);
            if first_block.is_none() {
                first_block = Some(block_data.clone());
            }
            self.store_block(block_data, &authority_bounds, block_id);
        }

        self.metrics
            .created_own_blocks
            .with_label_values(&[reason])
            .inc();

        first_block
    }

    pub fn next_block_round(&self) -> RoundNumber {
        self.last_proposed().saturating_add(1)
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
    ) -> (
        Vec<BaseTransaction>,
        Vec<BlockReference>,
        Vec<BlockReference>,
    ) {
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
        let raw_refs = pending_refs.clone();
        let mut block_references =
            self.compress_pending_block_references(&pending_refs, block_round);

        // Dual-DAG protocols: filter parents to only include clean blocks.
        if self.dag_state.consensus_protocol.uses_dual_dag() {
            let before = block_references.clone();
            block_references.retain(|r| r.round == 0 || self.dag_state.has_clean_vertex(r));
            let filtered_out_refs: Vec<_> = before
                .into_iter()
                .filter(|r| !block_references.contains(r))
                .collect();
            if !filtered_out_refs.is_empty() {
                tracing::debug!(
                    "Filtered non-clean parent refs for block round {}: kept={:?}, dropped={:?}",
                    block_round,
                    block_references,
                    filtered_out_refs
                );
            }
        }

        // Dual-DAG leaders: verify the filtered parent set, together with
        // the creator's own previous block (always included by build_block),
        // still has quorum stake at round-1. Compressed-ref non-leaders are
        // exempt since they only carry 1-2 references by design.
        let is_compressed_non_leader = self.dag_state.consensus_protocol.uses_compressed_refs()
            && self.committee.elect_leader(block_round) != self.authority;
        if self.dag_state.consensus_protocol.uses_dual_dag()
            && block_round > 1
            && !is_compressed_non_leader
        {
            let prev_round = block_round - 1;
            let mut prev_round_stake: u64 = 0;
            let mut seen = AuthoritySet::default();
            // Count own_previous: build_block always prepends the author's
            // previous block, which is at prev_round after a successful round.
            let own_prev_stake = self.committee.get_stake(self.authority).unwrap_or(0);
            if self
                .last_own_block
                .first()
                .is_some_and(|ob| ob.block.round() == prev_round)
            {
                seen.insert(self.authority);
                prev_round_stake += own_prev_stake;
            }
            for r in &block_references {
                if r.round == prev_round && !seen.contains(r.authority) {
                    seen.insert(r.authority);
                    prev_round_stake += self.committee.get_stake(r.authority).unwrap_or(0);
                }
            }
            if !self.committee.is_quorum(prev_round_stake) {
                tracing::debug!(
                    "Insufficient clean parent stake for block round {}: \
                     prev_round={}, prev_round_stake={}, filtered_refs={:?}, \
                     raw_refs={:?}, own_prev_present={}, \
                     is_compressed_non_leader={}",
                    block_round,
                    prev_round,
                    prev_round_stake,
                    block_references,
                    raw_refs,
                    seen.contains(self.authority),
                    is_compressed_non_leader
                );
                return (transactions, vec![], raw_refs);
            }
        }

        (transactions, block_references, raw_refs)
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

        if self.dag_state.consensus_protocol.supports_acknowledgments() {
            Some(
                self.encoder
                    .encode_transactions(transactions, info_length, parity_length),
            )
        } else {
            None
        }
    }

    /// For StarfishSpeed, compute the strong-vote hint mask for the current
    /// leader. `Some(empty)` means the vote is strong; `Some(nonempty)` records
    /// the authorities whose payloads are still missing locally.
    fn compute_strong_vote(
        &self,
        clock_round: RoundNumber,
        block_references: &[BlockReference],
    ) -> Option<AuthoritySet> {
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

        let mut missing_mask = AuthoritySet::default();
        if !self.dag_state.is_data_available(leader_ref) {
            missing_mask.insert(leader_ref.authority);
        }

        let leader_block = self
            .dag_state
            .get_storage_block(*leader_ref)
            .expect("Leader block should exist if it's in our includes");

        for ack_ref in leader_block.acknowledgments() {
            if !self.dag_state.is_data_available(&ack_ref) {
                missing_mask.insert(ack_ref.authority);
            }
        }

        Some(missing_mask)
    }

    fn starfish_speed_excluded_ack_authors(&self, clock_round: RoundNumber) -> AuthoritySet {
        if self.dag_state.consensus_protocol != ConsensusProtocol::StarfishSpeed
            || self.committee.elect_leader(clock_round) != self.authority
        {
            return AuthoritySet::default();
        }

        self.dag_state.starfish_speed_excluded_ack_authorities()
    }

    fn filter_starfish_speed_leader_acknowledgments(
        &self,
        excluded_authors: AuthoritySet,
        acknowledgment_references: Vec<BlockReference>,
    ) -> Vec<BlockReference> {
        if excluded_authors.is_empty() {
            return acknowledgment_references;
        }

        let (to_include, to_requeue): (Vec<_>, Vec<_>) = acknowledgment_references
            .into_iter()
            .partition(|ack_ref| !excluded_authors.contains(ack_ref.authority));
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
        let protocol = self.dag_state.consensus_protocol;
        if protocol.uses_bls() {
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

        let uses_bls = protocol.uses_bls();
        let bls_signer_opt = if uses_bls {
            Some(&self.bls_signer)
        } else {
            None
        };
        let committee_opt = if uses_bls {
            Some(self.committee.as_ref())
        } else {
            None
        };

        // Fetch aggregated DAC certificates from the BLS aggregator.
        let aggregate_dac_sigs = if uses_bls {
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

        let precomputed_round_sig = if uses_bls {
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
        let precomputed_leader_sig = if uses_bls {
            voted_leader_ref.and_then(|r| self.dag_state.take_precomputed_leader_sig(&r))
        } else {
            None
        };

        // SailfishPlusPlus: compute control-plane fields (TC / NVC).
        let sailfish_fields = if protocol.is_sailfish_pp() && clock_round > 1 {
            self.compute_sailfish_fields(clock_round, &block_references)
        } else {
            None
        };
        let unprovable_certificate = if protocol.is_bluestreak() && clock_round >= 3 {
            self.compute_unprovable_certificate(clock_round, &block_references)
        } else {
            None
        };

        let mut block = VerifiedBlock::new_with_signer_and_unprovable(
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
            sailfish_fields,
            unprovable_certificate,
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

    /// Compute SailfishPlusPlus control fields for a new block at
    /// `clock_round`.
    ///
    /// Returns `Some(fields)` with the control certs to embed, or `None` if no
    /// control fields are needed (block has a path to the previous leader).
    ///
    /// The caller must ensure that when this returns `None` the block actually
    /// has a parent link to the previous leader.  The gating logic that blocks
    /// block creation when certs are missing lives in `try_new_block`.
    fn compute_sailfish_fields(
        &self,
        clock_round: RoundNumber,
        block_references: &[BlockReference],
    ) -> Option<SailfishFields> {
        let prev_round = clock_round - 1;
        let prev_leader = self.committee.elect_leader(prev_round);

        // If we have a direct parent to the previous leader, no control
        // certs are needed.
        let has_path_to_prev_leader = block_references
            .iter()
            .any(|r| r.round == prev_round && r.authority == prev_leader);

        if has_path_to_prev_leader {
            return None;
        }

        // We lack a path — collect the control certs.
        let timeout_cert = self.dag_state.get_timeout_cert(prev_round);
        let is_leader = self.committee.elect_leader(clock_round) == self.authority;
        let no_vote_cert = if is_leader {
            self.dag_state.get_novote_cert(prev_round, prev_leader)
        } else {
            None
        };

        Some(SailfishFields {
            timeout_cert,
            no_vote_cert,
        })
    }

    /// Check whether Sailfish++ control-plane prerequisites are met for
    /// creating a block in `clock_round`. Returns true if block creation can
    /// proceed.
    fn sailfish_control_ready(
        &self,
        clock_round: RoundNumber,
        block_references: &[BlockReference],
    ) -> bool {
        if clock_round <= 1 {
            return true;
        }
        let prev_round = clock_round - 1;
        let prev_leader = self.committee.elect_leader(prev_round);

        let has_path = self.last_own_block.first().is_some_and(|own_block| {
            own_block.block.round() == prev_round && own_block.block.authority() == prev_leader
        }) || block_references
            .iter()
            .any(|r| r.round == prev_round && r.authority == prev_leader);
        if has_path {
            return true;
        }

        // Must have a TC for the previous round.
        if !self.dag_state.has_timeout_cert(prev_round) {
            return false;
        }
        // Leader must additionally have a NVC.
        if self.committee.elect_leader(clock_round) == self.authority
            && !self.dag_state.has_novote_cert(prev_round, prev_leader)
        {
            return false;
        }
        true
    }

    fn compute_unprovable_certificate(
        &self,
        clock_round: RoundNumber,
        _block_references: &[BlockReference],
    ) -> Option<BlockReference> {
        let leader_round = clock_round.checked_sub(2)?;
        let leader = self.committee.elect_leader(leader_round);
        let leader_blocks = self
            .dag_state
            .get_blocks_at_authority_round(leader, leader_round)
            .into_iter();

        for leader_block in leader_blocks {
            let leader_ref = *leader_block.reference();
            if self
                .dag_state
                .has_bluestreak_certificate_evidence(clock_round, &leader_ref)
            {
                return Some(leader_ref);
            }
        }

        None
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
        let protocol = self.dag_state.consensus_protocol;

        // Compressed-ref protocols (Bluestreak, StarfishBls, MysticetiBls):
        // non-leaders keep only the prev-round leader, leaders keep the full
        // unique frontier.
        if protocol.uses_compressed_refs() {
            let is_leader = self.committee.elect_leader(block_round) == self.authority;
            if !is_leader {
                let prev_round = block_round.saturating_sub(1);
                let leader = self.committee.elect_leader(prev_round);
                return pending_refs
                    .iter()
                    .copied()
                    .filter(|r| r.authority == leader && r.round == prev_round)
                    .take(1)
                    .collect();
            }
            let mut seen = AHashSet::new();
            return pending_refs
                .iter()
                .copied()
                .filter(|r| r.authority != self.authority && seen.insert(*r))
                .collect();
        }

        // SailfishPlusPlus: keep all previous-round references unconditionally
        // so that clean-parent filtering doesn't drop below quorum.
        if protocol.is_sailfish_pp() {
            let prev_round = block_round.saturating_sub(1);
            let mut seen = AHashSet::new();
            return pending_refs
                .iter()
                .copied()
                .filter(|r| {
                    r.authority != self.authority && seen.insert(*r) && r.round >= prev_round
                })
                .collect();
        }

        // Default (Mysticeti, CordialMiners, Starfish, StarfishSpeed):
        // transitive reduction.
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
            authority_index_start: authority_bounds[block_id],
            authority_index_end: authority_bounds[block_id + 1],
        };
        self.last_own_block[block_id] = own_block.clone();
        self.dag_state.insert_own_block(own_block.clone());
        self.flush_pending_clean_refs();
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
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::try_commit");
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
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::cleanup");
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
        let quorum_round = self.next_block_round();
        self.ready_new_block_impl(quorum_round, connected_authorities, true)
    }

    pub fn ready_new_block(&self, connected_authorities: &AHashSet<AuthorityIndex>) -> bool {
        let quorum_round = self.next_block_round();
        self.ready_new_block_impl(quorum_round, connected_authorities, false)
    }

    fn ready_new_block_impl(
        &self,
        quorum_round: RoundNumber,
        connected_authorities: &AHashSet<AuthorityIndex>,
        relaxed: bool,
    ) -> bool {
        if quorum_round == 0 || self.dag_state.proposal_round() < quorum_round {
            return false;
        }
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
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::handle_committed_subdag");
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
        self.flush_pending_clean_refs();
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

    fn flush_pending_clean_refs(&self) {
        if !self.dag_state.consensus_protocol.uses_dual_dag() {
            return;
        }
        self.dag_state.flush_pending_clean_refs();
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

#[cfg(test)]
mod tests {
    use prometheus::Registry;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        bls_certificate_aggregator::CertificateEvent,
        config::{DisseminationMode, NodePrivateConfig, StorageBackend},
        crypto::{self, BlsSigner, Signer},
        dag_state::{DagState, DataSource},
        data::Data,
        metrics::Metrics,
        types::{AuthoritySet, BlockReference, BlsAggregateCertificate, VerifiedBlock},
    };

    struct NoopBlockHandler;

    impl BlockHandler for NoopBlockHandler {
        fn handle_proposal(&mut self, _number_transactions: usize) {}

        fn handle_blocks(&mut self, _require_response: bool) -> Vec<BaseTransaction> {
            Vec::new()
        }
    }

    fn make_bluestreak_non_leader_round_1_block(
        signers: &[Signer],
        authority: AuthorityIndex,
    ) -> Data<VerifiedBlock> {
        let mut block = VerifiedBlock::new_with_signer(
            authority,
            1,
            vec![BlockReference::new_test(authority, 0)],
            None,
            vec![],
            0,
            &signers[authority as usize],
            None,
            None,
            vec![],
            vec![],
            None,
            ConsensusProtocol::Bluestreak,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        block.preserialize();
        Data::new(block)
    }

    fn make_mysticeti_bls_round_1_block(
        committee: &Committee,
        signers: &[Signer],
        bls_signers: &[BlsSigner],
        authority: AuthorityIndex,
    ) -> Data<VerifiedBlock> {
        let block_references = if authority == committee.elect_leader(1) {
            committee
                .authorities()
                .map(|auth| BlockReference::new_test(auth, 0))
                .collect()
        } else {
            vec![BlockReference::new_test(authority, 0)]
        };
        let mut block = VerifiedBlock::new_with_signer(
            authority,
            1,
            block_references,
            None,
            vec![],
            0,
            &signers[authority as usize],
            Some(&bls_signers[authority as usize]),
            Some(committee),
            vec![],
            vec![],
            None,
            ConsensusProtocol::MysticetiBls,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        block.preserialize();
        Data::new(block)
    }

    fn make_test_round_certificate(
        bls_signers: &[BlsSigner],
        round: RoundNumber,
    ) -> BlsAggregateCertificate {
        let mut signers = AuthoritySet::default();
        assert!(signers.insert(0));
        assert!(signers.insert(1));
        assert!(signers.insert(2));
        BlsAggregateCertificate::new(
            bls_signers[0].sign_digest(&crypto::bls_round_message(round)),
            signers,
        )
    }

    #[test]
    fn bluestreak_force_timeout_allows_prev_only_when_prev_leader_missing() {
        let authority = 0;
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("bluestreak"),
            None,
        );
        let dir = TempDir::new().unwrap();
        let recovered = DagState::open(
            authority,
            dir.path(),
            metrics.clone(),
            committee.clone(),
            "honest".to_string(),
            "bluestreak".to_string(),
            &StorageBackend::Rocksdb,
            false,
            DisseminationMode::ProtocolDefault,
        );
        let private_config = NodePrivateConfig::new_for_tests(authority);
        let (mut core, _) = Core::open(
            NoopBlockHandler,
            authority,
            committee.clone(),
            private_config,
            metrics,
            recovered,
            None,
        );

        // Create our round-1 block (non-leader; may reference only own genesis).
        let round_1 = core
            .try_new_block("new_blocks")
            .expect("round-1 block should be creatable");
        assert_eq!(round_1.round(), 1);
        assert_eq!(core.last_proposed(), 1);

        // Advance the threshold clock + clean-parent quorum to round 2 without
        // ever adding the elected leader's round-1 block (authority 1).
        let signers = Signer::new_for_test(committee.len());
        core.add_blocks(
            vec![
                (make_bluestreak_non_leader_round_1_block(&signers, 2), None),
                (make_bluestreak_non_leader_round_1_block(&signers, 3), None),
            ],
            DataSource::BlockBundleStreaming,
        );
        assert_eq!(core.dag_state().proposal_round(), 2);

        // Normal block creation stalls because we cannot reference the
        // previous-round leader (authority 1) from the pending frontier.
        assert!(
            core.try_new_block("new_blocks").is_none(),
            "expected normal creation to stall without prev-leader ref"
        );

        // Forced creation after timeout should fall back to own-prev only.
        let round_2 = core
            .try_new_block("force_timeout")
            .expect("forced round-2 block should be creatable");
        assert_eq!(round_2.round(), 2);
        assert_eq!(core.last_proposed(), 2);

        let refs = round_2.block_references();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], *round_1.reference());
    }

    #[test]
    fn mysticeti_bls_non_leader_can_build_round_2_with_prev_leader_parent() {
        let authority = 0;
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("mysticeti-bls"),
            None,
        );
        let dir = TempDir::new().unwrap();
        let recovered = DagState::open(
            authority,
            dir.path(),
            metrics.clone(),
            committee.clone(),
            "honest".to_string(),
            "mysticeti-bls".to_string(),
            &StorageBackend::Rocksdb,
            false,
            DisseminationMode::ProtocolDefault,
        );
        let private_config = NodePrivateConfig::new_for_tests(authority);
        let (mut core, _) = Core::open(
            NoopBlockHandler,
            authority,
            committee.clone(),
            private_config,
            metrics,
            recovered,
            None,
        );

        let own_round_1 = core
            .try_new_block("new_blocks")
            .expect("round-1 block should be creatable");
        let signers = Signer::new_for_test(committee.len());
        let bls_signers = BlsSigner::new_for_test(committee.len());
        let leader_round_1 =
            make_mysticeti_bls_round_1_block(committee.as_ref(), &signers, &bls_signers, 1);
        let peer_round_1_a =
            make_mysticeti_bls_round_1_block(committee.as_ref(), &signers, &bls_signers, 2);
        let peer_round_1_b =
            make_mysticeti_bls_round_1_block(committee.as_ref(), &signers, &bls_signers, 3);

        core.add_blocks(
            vec![
                (leader_round_1.clone(), None),
                (peer_round_1_a.clone(), None),
                (peer_round_1_b.clone(), None),
            ],
            DataSource::BlockBundleStreaming,
        );

        let round_1_refs = vec![
            *own_round_1.reference(),
            *leader_round_1.reference(),
            *peer_round_1_a.reference(),
            *peer_round_1_b.reference(),
        ];
        core.dag_state().mark_vertices_clean(&round_1_refs);
        core.dag_state()
            .apply_certificate_events(vec![CertificateEvent::Round(
                1,
                make_test_round_certificate(&bls_signers, 1),
            )]);

        assert_eq!(core.dag_state().proposal_round(), 2);

        let round_2 = core
            .try_new_block("new_blocks")
            .expect("non-leader round-2 block should be creatable");
        assert_eq!(round_2.round(), 2);

        let refs = round_2.block_references();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0], *own_round_1.reference());
        assert_eq!(refs[1], *leader_round_1.reference());
    }
}
