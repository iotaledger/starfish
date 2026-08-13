// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeSet, fmt, mem, sync::Arc};

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
    crypto::{
        self, AsBytes, BlsSignatureBytes, BlsSigner, MacKey, MlDsa44Signer, MlDsa65Signer, Signer,
    },
    dag_state::{
        ByzantineStrategy, CACHED_ROUNDS, CommitData, ConsensusProtocol, DagState, DataSource,
        OwnBlockData,
    },
    data::Data,
    encoder::ShardEncoder,
    metrics::{Metrics, UtilizationTimerVecExt},
    runtime::timestamp_utc,
    starfish_rbc_dag::ConsensusVertexReference,
    starfish_rbc_dag_shadow::RbcDagFrontierRecoveryCursorV1,
    state::RecoveredState,
    store::{RbcDagFrontierReceipt, Store},
    types::{
        AuthorityIndex, AuthoritySet, BaseTransaction, BlockAuthenticationScheme, BlockAuthorizer,
        BlockReference, BlsAggregateCertificate, Encoder, PartialSig, PartialSigKind,
        ProvableShard, ReconstructedTransactionData, RoundNumber, SailfishFields, Shard,
        StarfishRbcFieldsV3, StarfishRbcReferenceV3, VerifiedBlock,
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
    /// Irrevocable local ECHO/READY statements waiting to ride on the next
    /// ordinary block in the single-DAG protocol.
    pending_starfish_rbc_references: BTreeSet<StarfishRbcReferenceV3>,
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
    ml_dsa_44_signer: MlDsa44Signer,
    ml_dsa_65_signer: MlDsa65Signer,
    mac_keys: Arc<Vec<MacKey>>,
    partial_sig_outbox: Option<mpsc::UnboundedSender<PartialSig>>,
    // todo - ugly, probably need to merge syncer and core
    recovered_committed_blocks: Option<AHashSet<BlockReference>>,
    recovered_committed_leaders_count: Option<usize>,
    committer: UniversalCommitter,
    pub(crate) encoder: Encoder,
    /// M7 application-production mode: direct Starfish headers are payload
    /// descriptors only. Their dirty/clean DAG is no longer a consensus or
    /// output authority, so raw threshold-clock progress may produce them.
    rbc_dag_application_production: bool,
    /// Latest atomically persisted authoritative carrier-frontier cursor.
    /// Loaded before the shadow actor opens and advanced only after the
    /// commit/receipt storage batch succeeds.
    latest_rbc_dag_frontier_cursor: Option<RbcDagFrontierRecoveryCursorV1>,
}

#[derive(Debug)]
pub(crate) enum RbcDagFrontierApplyError {
    StaleSequence {
        current_sequence: RoundNumber,
        actual_sequence: RoundNumber,
    },
    SequenceGap {
        expected_sequence: RoundNumber,
        actual_sequence: RoundNumber,
    },
    ConflictingAnchor {
        output_sequence: RoundNumber,
        expected: BlockReference,
        actual: BlockReference,
    },
    ConflictingApplications {
        output_sequence: RoundNumber,
        anchor: BlockReference,
        expected: Vec<BlockReference>,
        actual: Vec<BlockReference>,
    },
    ReusedAnchor {
        anchor: BlockReference,
        previous_sequence: RoundNumber,
        actual_sequence: RoundNumber,
    },
    MissingApplication(BlockReference),
    UnavailableApplication(BlockReference),
}

impl fmt::Display for RbcDagFrontierApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleSequence {
                current_sequence,
                actual_sequence,
            } => write!(
                formatter,
                "stale RBC-DAG frontier output sequence {actual_sequence}; durable sequence is {current_sequence}"
            ),
            Self::SequenceGap {
                expected_sequence,
                actual_sequence,
            } => write!(
                formatter,
                "RBC-DAG frontier output sequence gap: expected {expected_sequence}, got {actual_sequence}"
            ),
            Self::ConflictingAnchor {
                output_sequence,
                expected,
                actual,
            } => write!(
                formatter,
                "conflicting RBC-DAG frontier anchor at output sequence {output_sequence}: durable {expected}, actual {actual}"
            ),
            Self::ReusedAnchor {
                anchor,
                previous_sequence,
                actual_sequence,
            } => write!(
                formatter,
                "RBC-DAG carrier anchor {anchor} was reused at output sequence {actual_sequence} after durable sequence {previous_sequence}"
            ),
            Self::ConflictingApplications {
                output_sequence,
                anchor,
                expected,
                actual,
            } => write!(
                formatter,
                "conflicting RBC-DAG frontier applications at output sequence {output_sequence} for anchor {anchor}: durable {expected:?}, actual {actual:?}"
            ),
            Self::MissingApplication(reference) => {
                write!(
                    formatter,
                    "committed RBC-DAG application {reference} is missing"
                )
            }
            Self::UnavailableApplication(reference) => write!(
                formatter,
                "committed RBC-DAG application {reference} is unavailable"
            ),
        }
    }
}

impl std::error::Error for RbcDagFrontierApplyError {}

pub(crate) enum RbcDagFrontierApplyOutcome {
    Applied(Vec<CommittedSubDag>),
    ExactReplay,
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

        let latest_rbc_dag_frontier_receipt = store
            .read_latest_rbc_dag_frontier_receipt()
            .expect("Failed to read the latest RBC-DAG frontier receipt");
        let latest_rbc_dag_frontier_cursor = latest_rbc_dag_frontier_receipt.map(|receipt| {
            assert!(
                dag_state.consensus_protocol.is_starfish_rbc(),
                "an RBC-DAG frontier receipt cannot be recovered under a non-RBC protocol"
            );
            dag_state.restore_rbc_dag_committed_rounds(&receipt.committed_rounds);
            let application_references = store
                .get_commit(&receipt.carrier_anchor)
                .expect("Failed to read the RBC-DAG frontier application commit")
                .map(|commit| {
                    assert!(
                        !commit.sub_dag.is_empty(),
                        "a present RBC-DAG frontier application commit must not be empty; control-only frontiers are represented by absence"
                    );
                    assert_eq!(
                        commit.leader, receipt.carrier_anchor,
                        "RBC-DAG frontier application commit must be keyed by its carrier anchor"
                    );
                    assert_eq!(
                        commit.committed_rounds, receipt.committed_rounds,
                        "RBC-DAG frontier application commit watermarks must match its atomic receipt"
                    );
                    commit.sub_dag
                })
                .unwrap_or_default();
            RbcDagFrontierRecoveryCursorV1 {
                receipt,
                application_references,
            }
        });

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
            pending_starfish_rbc_references: BTreeSet::new(),
            last_own_block: vec![last_own_block],
            block_handler,
            authority,
            committee,
            last_commit_leader: last_committed_leader.unwrap_or_default(),
            dag_state,
            metrics,
            signer: private_config.keypair,
            bls_signer: private_config.bls_keypair,
            ml_dsa_44_signer: private_config.ml_dsa_44_keypair,
            ml_dsa_65_signer: private_config.ml_dsa_65_keypair,
            mac_keys: Arc::new(private_config.mac_keys),
            partial_sig_outbox,
            recovered_committed_blocks: Some(committed_blocks),
            recovered_committed_leaders_count: Some(committed_leaders_count),
            committer,
            encoder,
            rbc_dag_application_production: false,
            latest_rbc_dag_frontier_cursor,
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

    pub(crate) fn add_starfish_rbc_reference(&mut self, reference: StarfishRbcReferenceV3) {
        assert!(
            self.dag_state
                .consensus_protocol
                .is_starfish_rbc_single_dag(),
            "embedded RBC references require single-DAG Starfish-RBC"
        );
        self.pending_starfish_rbc_references.insert(reference);
    }

    pub(crate) fn get_ml_dsa_44_signer(&self) -> &crate::crypto::MlDsa44Signer {
        &self.ml_dsa_44_signer
    }

    pub(crate) fn get_ml_dsa_65_signer(&self) -> &crate::crypto::MlDsa65Signer {
        &self.ml_dsa_65_signer
    }

    pub fn mac_keys(&self) -> Arc<Vec<MacKey>> {
        self.mac_keys.clone()
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

        let proposal_round = if self.rbc_dag_application_production {
            self.dag_state.threshold_clock_round()
        } else {
            self.dag_state.proposal_round()
        };
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
        if !self.rbc_dag_application_production
            && protocol.uses_dual_dag()
            && !protocol.is_starfish_rbc_single_dag()
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

        // `build_block` always prepends the creator's previous block. For
        // Starfish-RBC that local header is dirty until the local RBC instance
        // delivers it; another clean quorum must not let us smuggle this dirty
        // mandatory parent into a proposal.
        if !self.rbc_dag_application_production
            && protocol.is_starfish_rbc()
            && !protocol.is_starfish_rbc_single_dag()
            && clock_round > 1
            && self
                .last_own_block
                .iter()
                .any(|own| !self.dag_state.has_clean_vertex(own.block.reference()))
        {
            tracing::debug!(
                "Cannot construct Starfish-RBC block in round {}: own previous header is not clean",
                clock_round
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
        let (mut transactions, block_references, raw_refs, deferred_dirty_refs) =
            self.collect_transactions_and_references(pending_transactions, clock_round);
        // A header can reach the dirty DAG before the local RBC instance
        // delivers it. Keep its include notification pending so a proposal
        // created from some other clean quorum does not permanently consume
        // the only chance to reference it once delivery completes.
        self.pending.extend(
            deferred_dirty_refs
                .into_iter()
                .map(MetaTransaction::Include),
        );

        // Dual-DAG protocols: if the clean-parent filter reduced the parent
        // set below threshold-clock quorum, we cannot build a valid block yet.
        // BLS non-leaders are exempt because they may legally build with only
        // their own previous block and, if present, the previous-round leader.
        // Requeue both transactions and include refs so the next attempt sees
        // them again.
        let is_current_leader = self.committee.elect_leader(clock_round) == self.authority;
        // BLS non-leaders can always build with minimal refs.
        let bls_non_leader = protocol.uses_bls() && !is_current_leader;
        // Compressed-ref + dual-DAG protocols (Bluestreak, SparseStarfishSpeed):
        // prev-round leader can build with own-prev only when its causal
        // frontier is unavailable.
        let compressed_dual_dag =
            protocol.uses_compressed_refs() && protocol.carries_unprovable_certificate();
        let compressed_prev_leader = compressed_dual_dag
            && self.committee.elect_leader(clock_round.saturating_sub(1)) == self.authority;
        // For compressed-ref dual-DAG non-leaders, block creation may fall
        // back to "own-prev only" when the previous-round leader block is
        // missing locally. Unlike Mysticeti, Bluestreak/SSFS compress
        // references down to the previous-round leader; if that leader isn't
        // available/clean yet, we still want to keep producing blocks (this
        // also matches the BLS non-leader behavior which always permits
        // minimal refs).
        let compressed_non_leader = compressed_dual_dag && !is_current_leader;
        let allows_minimal_refs = bls_non_leader || compressed_prev_leader || compressed_non_leader;
        if compressed_non_leader && block_references.is_empty() && !compressed_prev_leader {
            tracing::debug!(
                "{:?}: constructing block in round {} \
                 with only own-prev (missing clean prev-leader parent)",
                protocol,
                clock_round
            );
        }
        if !self.rbc_dag_application_production
            && protocol.uses_dual_dag()
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

        let strong_vote_excluded_authors = self.strong_vote_excluded_ack_authors(clock_round);
        if strong_vote_excluded_authors.contains(self.authority) {
            self.requeue_transactions(std::mem::take(&mut transactions));
        }
        self.prepare_last_blocks();
        let mut encoded_transactions = self.prepare_encoded_transactions(&transactions);
        let acknowledgment_references = if protocol.supports_acknowledgments() {
            // SparseStarfishSpeed: only the round-r leader drains the pending
            // queue. Non-leader blocks carry an empty ack list because their
            // implicit acks are derived at commit time from
            // (leader.acks, voter.strong_vote).
            if protocol == ConsensusProtocol::SparseStarfishSpeed && !is_current_leader {
                Vec::new()
            } else {
                self.dag_state.get_pending_acknowledgment(clock_round)
            }
        } else {
            Vec::new()
        };
        let acknowledgment_references = self.filter_strong_vote_leader_acknowledgments(
            strong_vote_excluded_authors,
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
        let single_dag_rbc = protocol.is_starfish_rbc_single_dag().then(|| {
            let maximum = self.committee.len().saturating_mul(6);
            let references: Vec<_> = self
                .pending_starfish_rbc_references
                .iter()
                .copied()
                .filter(|evidence| evidence.reference().round <= clock_round)
                .take(maximum)
                .collect();
            for reference in &references {
                self.pending_starfish_rbc_references.remove(reference);
            }
            StarfishRbcFieldsV3::new(references)
        });

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
                single_dag_rbc.as_ref(),
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
        // Dirty vertices must not even participate in transitive reduction:
        // otherwise a dirty child can suppress one of its clean parents and
        // then be filtered itself, shrinking the usable clean frontier.
        let (compression_candidates, deferred_dirty_refs): (Vec<_>, Vec<_>) =
            if self.dag_state.consensus_protocol.is_starfish_rbc()
                && !self
                    .dag_state
                    .consensus_protocol
                    .is_starfish_rbc_single_dag()
                && !self.rbc_dag_application_production
            {
                pending_refs.into_iter().partition(|reference| {
                    reference.round == 0 || self.dag_state.has_clean_vertex(reference)
                })
            } else {
                (pending_refs, Vec::new())
            };
        // These are the usable inputs that callers must retry when a later
        // proposal gate fails. Dirty RBC refs are retried independently above
        // so the two retry paths cannot duplicate them.
        let raw_refs = compression_candidates.clone();
        let mut block_references =
            self.compress_pending_block_references(&compression_candidates, block_round);

        // Dual-DAG protocols: filter parents to only include clean blocks.
        if self.dag_state.consensus_protocol.uses_dual_dag()
            && !self
                .dag_state
                .consensus_protocol
                .is_starfish_rbc_single_dag()
            && !self.rbc_dag_application_production
        {
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
            && !self.rbc_dag_application_production
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
                return (transactions, vec![], raw_refs, deferred_dirty_refs);
            }
        }

        (
            transactions,
            block_references,
            raw_refs,
            deferred_dirty_refs,
        )
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

    /// For StarfishSpeed and SparseStarfishSpeed, compute the strong-vote hint
    /// mask for the current leader. `Some(empty)` means the vote is strong;
    /// `Some(nonempty)` records the authorities whose payloads are still
    /// missing locally (one bit per authority — coarse-grained: any missing
    /// block by that author sets the bit). Returns `None` when the block is
    /// not a voter of any leader (no leader_r-1 reference).
    fn compute_strong_vote(
        &self,
        clock_round: RoundNumber,
        block_references: &[BlockReference],
    ) -> Option<AuthoritySet> {
        if !self.dag_state.consensus_protocol.uses_strong_vote() {
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

        let leader_block = self
            .dag_state
            .get_storage_block(*leader_ref)
            .expect("Leader block should exist if it's in our includes");

        // Single batched data-availability check over [leader_ref, ack_refs...]
        // — one DagState read lock instead of (1 + acks.len()) acquisitions.
        let acks = leader_block.acknowledgments();
        let mut refs_to_check = Vec::with_capacity(1 + acks.len());
        refs_to_check.push(*leader_ref);
        refs_to_check.extend_from_slice(&acks);
        let availability = self.dag_state.is_data_available_batch(&refs_to_check);

        let mut missing_mask = AuthoritySet::default();
        for (r, available) in refs_to_check.iter().zip(availability) {
            if !available {
                missing_mask.insert(r.authority);
            }
        }

        Some(missing_mask)
    }

    fn strong_vote_excluded_ack_authors(&self, clock_round: RoundNumber) -> AuthoritySet {
        if !self.dag_state.consensus_protocol.uses_strong_vote()
            || self.committee.elect_leader(clock_round) != self.authority
        {
            return AuthoritySet::default();
        }

        self.dag_state.strong_vote_excluded_ack_authorities()
    }

    fn filter_strong_vote_leader_acknowledgments(
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
        single_dag_rbc: Option<&StarfishRbcFieldsV3>,
    ) -> Data<VerifiedBlock> {
        let time_ns = timestamp_utc().as_nanos() as u64 + block_id_in_round as u64;
        let own_previous = *self.last_own_block[block_id_in_round].block.reference();
        let mut block_references = vec![own_previous];
        let protocol = self.dag_state.consensus_protocol;
        let is_round_leader = self.committee.elect_leader(clock_round) == self.authority;
        if protocol.uses_bls() {
            if let Some(leader_ref) = voted_leader_ref {
                if leader_ref != own_previous {
                    block_references.push(leader_ref);
                }
            }
        }
        if protocol.uses_bls() && !is_round_leader {
            let prev_round = clock_round.saturating_sub(1);
            let prev_round_leader = self.committee.elect_leader(prev_round);
            block_references.extend(block_references_without_own.iter().copied().filter(
                |reference| {
                    reference.round != prev_round || reference.authority != prev_round_leader
                },
            ));
        } else {
            block_references.extend(block_references_without_own.iter().cloned());
        }
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
        let unprovable_certificate = if (protocol.is_bluestreak()
            || protocol == ConsensusProtocol::SparseStarfishSpeed)
            && clock_round >= 3
        {
            self.compute_unprovable_certificate(clock_round, &block_references)
        } else {
            None
        };

        let mut block = if protocol.is_starfish_rbc_single_dag() {
            VerifiedBlock::new_starfish_rbc_single_dag(
                self.authority,
                clock_round,
                block_references,
                acknowledgment_references.to_vec(),
                time_ns,
                transactions.to_vec(),
                encoded_transactions.clone(),
                single_dag_rbc
                    .cloned()
                    .expect("single-DAG Starfish-RBC block requires V3 fields"),
            )
        } else if protocol == ConsensusProtocol::StarfishRbc {
            VerifiedBlock::new_starfish_rbc(
                self.authority,
                clock_round,
                block_references,
                acknowledgment_references.to_vec(),
                time_ns,
                transactions.to_vec(),
                encoded_transactions.clone(),
            )
        } else {
            let authorizer = match self.dag_state.block_authentication_scheme {
                BlockAuthenticationScheme::Ed25519 => BlockAuthorizer::Ed25519(&self.signer),
                BlockAuthenticationScheme::MacVector => BlockAuthorizer::MacVector(&self.mac_keys),
                BlockAuthenticationScheme::MlDsa44 => {
                    BlockAuthorizer::MlDsa44(&self.ml_dsa_44_signer)
                }
                BlockAuthenticationScheme::MlDsa65 => {
                    BlockAuthorizer::MlDsa65(&self.ml_dsa_65_signer)
                }
            };
            VerifiedBlock::new_with_authorizer_and_unprovable(
                self.authority,
                clock_round,
                block_references,
                voted_leader_ref,
                acknowledgment_references.to_vec(),
                time_ns,
                &authorizer,
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
            )
        };

        let role = if is_round_leader {
            "leader"
        } else {
            "non_leader"
        };
        self.metrics
            .proposed_block_refs
            .with_label_values(&[role])
            .observe(block_ref_count as f64);
        self.metrics
            .proposed_block_acks
            .with_label_values(&[role])
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
    ) -> Option<(BlockReference, bool)> {
        let leader_round = clock_round.checked_sub(2)?;
        let leader = self.committee.elect_leader(leader_round);
        let leader_blocks = self
            .dag_state
            .get_blocks_at_authority_round(leader, leader_round)
            .into_iter();

        let is_sparse = self.dag_state.consensus_protocol == ConsensusProtocol::SparseStarfishSpeed;

        for leader_block in leader_blocks {
            let leader_ref = *leader_block.reference();

            if is_sparse {
                // SparseStarfishSpeed: O(1) precomputed-tally lookups.
                // `record_ssfs_leader_vote_support` in DagState updates
                // both `leader_vote_support` and `leader_strong_vote_support`
                // on every block insert, so we don't rescan round-(r+1)
                // voters here.
                //  - strong (true)  iff strong-vote quorum reached.
                //  - standard (false) iff vote quorum exists but strong quorum hasn't.
                //  - absent (None) iff no vote quorum.
                if self.dag_state.ssfs_leader_strong_vote_quorum(&leader_ref) {
                    return Some((leader_ref, true));
                }
                if self.dag_state.ssfs_leader_vote_quorum(&leader_ref) {
                    return Some((leader_ref, false));
                }
                continue;
            }

            // Bluestreak path: existing certificate evidence; standard
            // (bool = false) only.
            if self
                .dag_state
                .has_unprovable_certificate_evidence(clock_round, &leader_ref, false)
            {
                return Some((leader_ref, false));
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
        if self.rbc_dag_application_production {
            return quorum_round > 0 && self.dag_state.threshold_clock_round() >= quorum_round;
        }
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
        // SparseStarfishSpeed: drop sequenced refs from the local pending
        // acknowledgment queue right after each commit so future leaders
        // don't republish them. Other protocols leave the queue intact and
        // rely on round-bounded drains in `get_pending_acknowledgment`.
        if self.dag_state.consensus_protocol == ConsensusProtocol::SparseStarfishSpeed {
            let sequenced: Vec<BlockReference> = committed
                .iter()
                .flat_map(|c| c.blocks.iter().map(|b| *b.reference()))
                .collect();
            self.dag_state.purge_pending_acknowledgments(&sequenced);
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

    /// Atomically persist one authoritative RBC-DAG frontier and its optional
    /// application commit. Classification against the in-memory durable
    /// cursor happens before application materialization or observer effects.
    pub(crate) fn handle_rbc_dag_committed_delta(
        &mut self,
        output_sequence: RoundNumber,
        anchor: ConsensusVertexReference,
        applications: &[BlockReference],
    ) -> Result<RbcDagFrontierApplyOutcome, RbcDagFrontierApplyError> {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::handle_rbc_dag_committed_delta");

        if let Some(current) = &self.latest_rbc_dag_frontier_cursor {
            if output_sequence < current.receipt.output_sequence {
                return Err(RbcDagFrontierApplyError::StaleSequence {
                    current_sequence: current.receipt.output_sequence,
                    actual_sequence: output_sequence,
                });
            }
            if output_sequence == current.receipt.output_sequence {
                if anchor.carrier() == current.receipt.carrier_anchor {
                    if applications == current.application_references {
                        return Ok(RbcDagFrontierApplyOutcome::ExactReplay);
                    }
                    return Err(RbcDagFrontierApplyError::ConflictingApplications {
                        output_sequence,
                        anchor: anchor.carrier(),
                        expected: current.application_references.clone(),
                        actual: applications.to_vec(),
                    });
                }
                return Err(RbcDagFrontierApplyError::ConflictingAnchor {
                    output_sequence,
                    expected: current.receipt.carrier_anchor,
                    actual: anchor.carrier(),
                });
            }
            if anchor.carrier() == current.receipt.carrier_anchor {
                return Err(RbcDagFrontierApplyError::ReusedAnchor {
                    anchor: anchor.carrier(),
                    previous_sequence: current.receipt.output_sequence,
                    actual_sequence: output_sequence,
                });
            }
            let expected_sequence = current.receipt.output_sequence.checked_add(1).ok_or(
                RbcDagFrontierApplyError::SequenceGap {
                    expected_sequence: RoundNumber::MAX,
                    actual_sequence: output_sequence,
                },
            )?;
            if output_sequence != expected_sequence {
                return Err(RbcDagFrontierApplyError::SequenceGap {
                    expected_sequence,
                    actual_sequence: output_sequence,
                });
            }
        } else if output_sequence != 1 {
            return Err(RbcDagFrontierApplyError::SequenceGap {
                expected_sequence: 1,
                actual_sequence: output_sequence,
            });
        }

        let blocks = applications
            .iter()
            .map(|reference| {
                let block = self
                    .dag_state
                    .get_storage_block(*reference)
                    .ok_or(RbcDagFrontierApplyError::MissingApplication(*reference))?;
                if !self.dag_state.is_data_available(reference) {
                    return Err(RbcDagFrontierApplyError::UnavailableApplication(*reference));
                }
                Ok(block)
            })
            .collect::<Result<Vec<_>, RbcDagFrontierApplyError>>()?;
        let committed = CommittedSubDag::new(anchor.carrier(), blocks);
        self.dag_state.update_last_committed_rounds(&committed);
        let committed_rounds = self.dag_state.last_committed_rounds();
        let receipt = RbcDagFrontierReceipt {
            carrier_anchor: anchor.carrier(),
            output_sequence,
            committed_rounds: committed_rounds.clone(),
        };
        // A control-only frontier has no application CommitData, but the
        // receipt still advances atomically through the same storage API.
        let commit_data = (!applications.is_empty())
            .then(|| CommitData::new(&committed, committed_rounds))
            .into_iter()
            .collect();
        let store_start = std::time::Instant::now();
        self.store
            .store_commits_with_rbc_dag_receipt(commit_data, receipt.clone())
            .expect("Store RBC-DAG frontier commits should not fail");
        self.metrics
            .store_commits_latency_us
            .inc_by(store_start.elapsed().as_micros() as u64);
        self.metrics.store_commits_count.inc();
        self.latest_rbc_dag_frontier_cursor = Some(RbcDagFrontierRecoveryCursorV1 {
            receipt,
            application_references: applications.to_vec(),
        });
        Ok(RbcDagFrontierApplyOutcome::Applied(vec![committed]))
    }

    #[cfg(test)]
    pub(crate) fn latest_rbc_dag_frontier_receipt(&self) -> Option<RbcDagFrontierReceipt> {
        self.latest_rbc_dag_frontier_cursor
            .as_ref()
            .map(|cursor| cursor.receipt.clone())
    }

    /// Return the exact runtime recovery cursor before Core is moved into its
    /// dispatcher. The durable receipt intentionally remains compact; exact
    /// application references are reconstructed from the atomic CommitData
    /// stored under the carrier anchor.
    pub(crate) fn rbc_dag_frontier_recovery_cursor(
        &self,
    ) -> Option<RbcDagFrontierRecoveryCursorV1> {
        self.latest_rbc_dag_frontier_cursor.clone()
    }

    pub(crate) fn enable_rbc_dag_application_production(&mut self) {
        assert!(
            self.dag_state.consensus_protocol.is_starfish_rbc(),
            "RBC-DAG application production requires Starfish-RBC payload headers"
        );
        self.rbc_dag_application_production = true;
    }

    pub fn write_commits(&mut self, _commits: &[CommitData]) {}

    pub fn take_recovered_committed(
        &mut self,
        rbc_dag_frontier_authority: bool,
    ) -> (AHashSet<BlockReference>, usize) {
        let legacy_committed_blocks = self
            .recovered_committed_blocks
            .take()
            .expect("take_recovered_committed called twice");
        let legacy_committed_leaders_count = self
            .recovered_committed_leaders_count
            .take()
            .expect("take_recovered_committed called twice");
        if !rbc_dag_frontier_authority {
            return (legacy_committed_blocks, legacy_committed_leaders_count);
        }

        assert!(
            self.dag_state.consensus_protocol.is_starfish_rbc(),
            "embedded RBC-DAG observer recovery requires the Starfish-RBC protocol"
        );
        // Carrier-keyed CommitData is intentionally not discoverable through
        // DagState's Core-block scan, and the latest application CommitData
        // contains only one frontier delta. Exactly-once is owned by the
        // durable receipt plus the authoritative WAL; the observer needs only
        // its monotone output count in this mode and never runs the legacy
        // Linearizer.
        let committed_frontier_count = self
            .latest_rbc_dag_frontier_cursor
            .as_ref()
            .map(|cursor| {
                usize::try_from(cursor.receipt.output_sequence)
                    .expect("RBC-DAG output sequence must fit usize")
            })
            .unwrap_or_default();
        (AHashSet::new(), committed_frontier_count)
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
        dag_state::{CommitData, DagState, DataSource},
        data::Data,
        metrics::Metrics,
        types::{
            AuthoritySet, BlockReference, BlsAggregateCertificate, Transaction, TransactionData,
            VerifiedBlock,
        },
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

    fn make_starfish_rbc_round_1_block(
        committee: &Committee,
        authority: AuthorityIndex,
    ) -> Data<VerifiedBlock> {
        let mut block = VerifiedBlock::new_starfish_rbc(
            authority,
            1,
            committee
                .authorities()
                .map(|auth| BlockReference::new_test(auth, 0))
                .collect(),
            Vec::new(),
            authority as u64,
            Vec::new(),
            None,
        );
        block.preserialize();
        Data::new(block)
    }

    fn rbc_application_is_materialized<H: BlockHandler>(
        core: &Core<H>,
        reference: BlockReference,
    ) -> bool {
        core.dag_state().get_storage_block(reference).is_some()
            && core.dag_state().is_data_available(&reference)
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
    fn bluestreak_non_leader_can_build_with_prev_only_when_prev_leader_missing() {
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

        // Block creation should fall back to own-prev only (no need to wait
        // for the timeout).
        let round_2 = core
            .try_new_block("new_blocks")
            .expect("round-2 block should be creatable without prev-leader ref");
        assert_eq!(round_2.round(), 2);
        assert_eq!(core.last_proposed(), 2);

        let refs = round_2.block_references();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], *round_1.reference());
    }

    #[test]
    fn starfish_rbc_proposal_defers_dirty_include_until_delivery() {
        let authority = 0;
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("starfish-rbc"),
            None,
        );
        let dir = TempDir::new().unwrap();
        let recovered = DagState::open(
            authority,
            dir.path(),
            metrics.clone(),
            committee.clone(),
            "honest".to_string(),
            "starfish-rbc".to_string(),
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

        let own_round_one = core
            .try_new_block("new_blocks")
            .expect("round-one block should be creatable");
        let peer_one = make_starfish_rbc_round_1_block(&committee, 1);
        let peer_two = make_starfish_rbc_round_1_block(&committee, 2);
        let dirty_peer = make_starfish_rbc_round_1_block(&committee, 3);
        let dirty_ref = *dirty_peer.reference();
        core.add_headers(
            vec![peer_one.clone(), peer_two.clone(), dirty_peer],
            DataSource::BlockBundleStreamingHeader,
        );

        assert!(
            core.dag_state()
                .apply_starfish_rbc_delivery_refs_for_test(&[
                    *own_round_one.reference(),
                    *peer_one.reference(),
                    *peer_two.reference(),
                ])
        );
        let round_two = core
            .try_new_block("new_blocks")
            .expect("a clean quorum should permit the round-two proposal");
        assert!(!round_two.block_references().contains(&dirty_ref));
        assert!(core.pending.iter().any(|pending| {
            matches!(pending, MetaTransaction::Include(reference) if *reference == dirty_ref)
        }));
    }

    #[test]
    fn rbc_dag_application_production_does_not_wait_for_legacy_clean_delivery() {
        let authority = 0;
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("starfish-rbc"),
            None,
        );
        let dir = TempDir::new().unwrap();
        let recovered = DagState::open(
            authority,
            dir.path(),
            metrics.clone(),
            committee.clone(),
            "honest".to_string(),
            "starfish-rbc".to_string(),
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
        core.enable_rbc_dag_application_production();

        let own_round_one = core
            .try_new_block("new_blocks")
            .expect("round-one application header should be creatable");
        let peers = [1, 2]
            .into_iter()
            .map(|peer| make_starfish_rbc_round_1_block(&committee, peer))
            .collect::<Vec<_>>();
        core.add_headers(peers, DataSource::BlockBundleStreamingHeader);

        assert_eq!(core.dag_state().threshold_clock_round(), 2);
        assert!(!core.dag_state().has_clean_vertex(own_round_one.reference()));
        let round_two = core
            .try_new_block("new_blocks")
            .expect("RBC-DAG application production must follow the raw threshold clock");
        assert_eq!(round_two.round(), 2);
        assert!(
            round_two
                .block_references()
                .contains(own_round_one.reference())
        );
    }

    #[test]
    fn rbc_dag_control_frontier_cursor_reopens_and_binds_exact_empty_output() {
        let authority = 0;
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("starfish-rbc"),
            None,
        );
        let dir = TempDir::new().unwrap();
        let open = || {
            DagState::open(
                authority,
                dir.path(),
                metrics.clone(),
                committee.clone(),
                "honest".to_string(),
                "starfish-rbc".to_string(),
                &StorageBackend::Rocksdb,
                false,
                DisseminationMode::ProtocolDefault,
            )
        };
        let (mut core, _) = Core::open(
            NoopBlockHandler,
            authority,
            committee.clone(),
            NodePrivateConfig::new_for_tests(authority),
            metrics.clone(),
            open(),
            None,
        );
        let anchor = ConsensusVertexReference::new(BlockReference::new_test(2, 20), 7);
        assert!(matches!(
            core.handle_rbc_dag_committed_delta(1, anchor, &[]),
            Ok(RbcDagFrontierApplyOutcome::Applied(_))
        ));
        assert!(matches!(
            core.handle_rbc_dag_committed_delta(1, anchor, &[]),
            Ok(RbcDagFrontierApplyOutcome::ExactReplay)
        ));
        let unexpected = BlockReference::new_test(1, 3);
        assert!(matches!(
            core.handle_rbc_dag_committed_delta(1, anchor, &[unexpected]),
            Err(RbcDagFrontierApplyError::ConflictingApplications {
                output_sequence: 1,
                expected,
                actual,
                ..
            }) if expected.is_empty() && actual == vec![unexpected]
        ));
        drop(core);

        let (mut reopened, _) = Core::open(
            NoopBlockHandler,
            authority,
            committee.clone(),
            NodePrivateConfig::new_for_tests(authority),
            metrics.clone(),
            open(),
            None,
        );
        let cursor = reopened
            .rbc_dag_frontier_recovery_cursor()
            .expect("control-only receipt must reopen as an exact cursor");
        assert_eq!(cursor.receipt.carrier_anchor, anchor.carrier());
        assert_eq!(cursor.receipt.output_sequence, 1);
        assert!(cursor.application_references.is_empty());
        assert!(matches!(
            reopened.handle_rbc_dag_committed_delta(1, anchor, &[]),
            Ok(RbcDagFrontierApplyOutcome::ExactReplay)
        ));
    }

    #[test]
    fn rbc_dag_application_frontier_cursor_reconstructs_exact_references() {
        let authority = 0;
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("starfish-rbc"),
            None,
        );
        let dir = TempDir::new().unwrap();
        let open = || {
            DagState::open(
                authority,
                dir.path(),
                metrics.clone(),
                committee.clone(),
                "honest".to_string(),
                "starfish-rbc".to_string(),
                &StorageBackend::Rocksdb,
                false,
                DisseminationMode::ProtocolDefault,
            )
        };
        let (mut core, _) = Core::open(
            NoopBlockHandler,
            authority,
            committee.clone(),
            NodePrivateConfig::new_for_tests(authority),
            metrics.clone(),
            open(),
            None,
        );
        let application = make_starfish_rbc_round_1_block(&committee, 1);
        let application_reference = *application.reference();
        core.add_blocks(vec![(application, None)], DataSource::BlockBundleStreaming);
        assert!(core.dag_state().is_data_available(&application_reference));
        let anchor = ConsensusVertexReference::new(BlockReference::new_test(3, 30), 9);
        assert!(matches!(
            core.handle_rbc_dag_committed_delta(1, anchor, &[application_reference]),
            Ok(RbcDagFrontierApplyOutcome::Applied(_))
        ));
        drop(core);

        let (mut reopened, _) = Core::open(
            NoopBlockHandler,
            authority,
            committee.clone(),
            NodePrivateConfig::new_for_tests(authority),
            metrics.clone(),
            open(),
            None,
        );
        let cursor = reopened
            .rbc_dag_frontier_recovery_cursor()
            .expect("application frontier receipt must reopen with exact references");
        assert_eq!(cursor.application_references, vec![application_reference]);
        assert!(matches!(
            reopened.handle_rbc_dag_committed_delta(1, anchor, &[application_reference]),
            Ok(RbcDagFrontierApplyOutcome::ExactReplay)
        ));
        assert!(matches!(
            reopened.handle_rbc_dag_committed_delta(1, anchor, &[]),
            Err(RbcDagFrontierApplyError::ConflictingApplications { .. })
        ));
    }

    #[test]
    fn rbc_dag_frontier_sequence_accepts_regressing_anchor_round_and_rejects_gaps() {
        let authority = 0;
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("starfish-rbc"),
            None,
        );
        let dir = TempDir::new().unwrap();
        let recovered = DagState::open(
            authority,
            dir.path(),
            metrics.clone(),
            committee.clone(),
            "honest".to_string(),
            "starfish-rbc".to_string(),
            &StorageBackend::Rocksdb,
            false,
            DisseminationMode::ProtocolDefault,
        );
        let (mut core, _) = Core::open(
            NoopBlockHandler,
            authority,
            committee,
            NodePrivateConfig::new_for_tests(authority),
            metrics,
            recovered,
            None,
        );
        let later_certifier = ConsensusVertexReference::new(BlockReference::new_test(2, 50), 8);
        let older_leader = ConsensusVertexReference::new(BlockReference::new_test(1, 40), 3);
        assert!(matches!(
            core.handle_rbc_dag_committed_delta(1, later_certifier, &[]),
            Ok(RbcDagFrontierApplyOutcome::Applied(_))
        ));
        assert!(matches!(
            core.handle_rbc_dag_committed_delta(3, older_leader, &[]),
            Err(RbcDagFrontierApplyError::SequenceGap {
                expected_sequence: 2,
                actual_sequence: 3
            })
        ));
        assert!(matches!(
            core.handle_rbc_dag_committed_delta(2, older_leader, &[]),
            Ok(RbcDagFrontierApplyOutcome::Applied(_))
        ));
        let receipt = core.latest_rbc_dag_frontier_receipt().unwrap();
        assert_eq!(receipt.output_sequence, 2);
        assert_eq!(receipt.carrier_anchor, older_leader.carrier());
        let (legacy_refs, observer_count) = core.take_recovered_committed(true);
        assert!(legacy_refs.is_empty());
        assert_eq!(observer_count, 2);
    }

    #[test]
    #[should_panic(expected = "a present RBC-DAG frontier application commit must not be empty")]
    fn rbc_dag_frontier_reopen_rejects_present_empty_commit_data() {
        let authority = 0;
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("starfish-rbc"),
            None,
        );
        let dir = TempDir::new().unwrap();
        let recovered = DagState::open(
            authority,
            dir.path(),
            metrics.clone(),
            committee.clone(),
            "honest".to_string(),
            "starfish-rbc".to_string(),
            &StorageBackend::Rocksdb,
            false,
            DisseminationMode::ProtocolDefault,
        );
        let anchor = BlockReference::new_test(2, 7);
        let receipt = RbcDagFrontierReceipt {
            carrier_anchor: anchor,
            output_sequence: 1,
            committed_rounds: vec![0; committee.len()],
        };
        recovered
            .store
            .store_commits_with_rbc_dag_receipt(Vec::new(), receipt.clone())
            .unwrap();
        recovered
            .store
            .store_commits(vec![CommitData {
                leader: anchor,
                sub_dag: Vec::new(),
                committed_rounds: receipt.committed_rounds,
            }])
            .unwrap();

        let _ = Core::open(
            NoopBlockHandler,
            authority,
            committee,
            NodePrivateConfig::new_for_tests(authority),
            metrics,
            recovered,
            None,
        );
    }

    #[test]
    fn rbc_dag_frontier_rejects_missing_or_unavailable_applications_without_advancing_receipt() {
        let authority = 0;
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("starfish-rbc"),
            None,
        );
        let dir = TempDir::new().unwrap();
        let recovered = DagState::open(
            authority,
            dir.path(),
            metrics.clone(),
            committee.clone(),
            "honest".to_string(),
            "starfish-rbc".to_string(),
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
        let anchor = ConsensusVertexReference::new(BlockReference::new_test(authority, 1), 1);
        let missing = BlockReference::new_test(1, 7);

        assert!(matches!(
            core.handle_rbc_dag_committed_delta(1, anchor, &[missing]),
            Err(RbcDagFrontierApplyError::MissingApplication(reference)) if reference == missing
        ));
        assert!(core.latest_rbc_dag_frontier_receipt().is_none());

        let transactions = vec![BaseTransaction::Share(Transaction::new(vec![9; 64]))];
        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let encoded = encoder.encode_transactions(
            &transactions,
            committee.info_length(),
            committee.len() - committee.info_length(),
        );
        let mut unavailable = VerifiedBlock::new_starfish_rbc(
            1,
            1,
            committee
                .authorities()
                .map(|parent| BlockReference::new_test(parent, 0))
                .collect(),
            Vec::new(),
            1,
            Vec::new(),
            Some(encoded),
        );
        unavailable.preserialize();
        let unavailable = Data::new(unavailable);
        let unavailable_reference = *unavailable.reference();
        let (processed, missing_parents, processed_references, _) =
            core.add_headers(vec![unavailable], DataSource::BlockBundleStreamingHeader);
        assert!(processed);
        assert!(missing_parents.is_empty());
        assert!(processed_references.contains(&unavailable_reference));
        assert!(!core.dag_state().is_data_available(&unavailable_reference));

        assert!(matches!(
            core.handle_rbc_dag_committed_delta(1, anchor, &[unavailable_reference]),
            Err(RbcDagFrontierApplyError::UnavailableApplication(reference))
                if reference == unavailable_reference
        ));
        assert!(core.latest_rbc_dag_frontier_receipt().is_none());
    }

    #[test]
    fn buffered_payload_materializes_only_after_missing_header_parents_arrive() {
        let authority = 0;
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(
            &registry,
            Some(committee.as_ref()),
            Some("starfish-rbc"),
            None,
        );
        let dir = TempDir::new().unwrap();
        let recovered = DagState::open(
            authority,
            dir.path(),
            metrics.clone(),
            committee.clone(),
            "honest".to_string(),
            "starfish-rbc".to_string(),
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

        let parents = [1, 2, 3]
            .into_iter()
            .map(|peer| make_starfish_rbc_round_1_block(&committee, peer))
            .collect::<Vec<_>>();
        let parent_references = parents
            .iter()
            .map(|parent| *parent.reference())
            .collect::<Vec<_>>();
        let transactions = vec![BaseTransaction::Share(Transaction::new(vec![7; 64]))];
        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let encoded = encoder.encode_transactions(
            &transactions,
            committee.info_length(),
            committee.len() - committee.info_length(),
        );
        let mut child = VerifiedBlock::new_starfish_rbc(
            1,
            2,
            parent_references.clone(),
            Vec::new(),
            2,
            Vec::new(),
            Some(encoded.clone()),
        );
        child.preserialize();
        let child = Data::new(child);
        let child_reference = *child.reference();

        let mut transaction_data = TransactionData::new(transactions);
        transaction_data.preserialize();
        let (commitment, proof) =
            crypto::TransactionsCommitment::new_from_encoded_transactions(&encoded, 0);
        let mut shard_data = ProvableShard::new(encoded[0].clone(), 0, proof, commitment);
        shard_data.preserialize();

        // Payload-first arrival is buffered because no dependency-closed
        // DagState block exists. It must not be treated as availability.
        core.add_transaction_data(
            vec![ReconstructedTransactionData {
                block_reference: child_reference,
                transaction_data,
                shard_data,
            }],
            DataSource::StarfishRbcPayload,
        );
        assert_eq!(core.pending_reconstructed_data.len(), 1);
        assert!(!rbc_application_is_materialized(&core, child_reference));

        let (processed, missing, processed_references, _) =
            core.add_headers(vec![child], DataSource::BlockBundleStreamingHeader);
        assert!(!processed);
        assert!(!missing.is_empty());
        assert!(!processed_references.contains(&child_reference));
        assert!(!rbc_application_is_materialized(&core, child_reference));

        // Adding the parents activates the pending child and atomically
        // attaches the buffered payload. HeaderStaged must use this returned
        // processed-reference set to emit the delayed availability signal.
        let (processed, missing, processed_references, _) =
            core.add_headers(parents, DataSource::BlockBundleStreamingHeader);
        assert!(processed);
        assert!(missing.is_empty());
        assert!(processed_references.contains(&child_reference));
        assert!(core.pending_reconstructed_data.is_empty());
        assert!(rbc_application_is_materialized(&core, child_reference));
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

    #[test]
    fn mysticeti_bls_non_leader_prefers_voted_leader_over_pending_equivocation() {
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
        let voted_leader =
            make_mysticeti_bls_round_1_block(committee.as_ref(), &signers, &bls_signers, 1);
        let pending_equivocation = BlockReference::new_test(1, 1);

        assert_ne!(
            *voted_leader.reference(),
            pending_equivocation,
            "test requires a distinct equivocated leader ref"
        );

        let round_2 = core.build_block(
            &[pending_equivocation],
            Some(*voted_leader.reference()),
            &[],
            &None,
            &[],
            2,
            0,
            Some(make_test_round_certificate(&bls_signers, 1)),
            None,
            None,
        );

        let refs = round_2.block_references();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0], *own_round_1.reference());
        assert_eq!(refs[1], *voted_leader.reference());
        assert!(!refs.contains(&pending_equivocation));
    }
}
