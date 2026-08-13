// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashSet;

use tokio::sync::mpsc;

use crate::{
    block_handler::BlockHandler,
    bls_certificate_aggregator::{CertificateEvent, apply_certificate_events},
    bls_service::BlsServiceMessage,
    consensus::{CommitMetastate, linearizer::CommittedSubDag},
    core::{Core, RbcDagFrontierApplyError, RbcDagFrontierApplyOutcome},
    dag_state::{DagState, DataSource},
    data::Data,
    metrics::Metrics,
    runtime::timestamp_utc,
    sailfish_service::SailfishServiceMessage,
    starfish_rbc::{PinnedRbcHeader, RbcCanonicalHeader},
    starfish_rbc_dag_shadow::CommittedFrontierDeltaV1,
    starfish_rbc_dag_shadow_service::StarfishRbcDagShadowServiceHandleV1,
    starfish_rbc_service::{RbcLocalHeader, RbcServiceHandle},
    types::{
        AuthorityIndex, BlockReference, PartialSig, PartialSigKind, ProvableShard,
        ReconstructedTransactionData, RoundNumber, SailfishNoVoteCert, SailfishTimeoutCert, Stake,
        VerifiedBlock,
    },
};

#[derive(Debug, Clone, Copy)]
pub enum BlockCreationReason {
    NewBlocks,
    NewHeaders,
    TransactionData,
    CertificateEvent,
    ForceTimeout,
    RelaxedTimeout,
    PostCommit,
}

/// Testbed pacing for the V3 single-DAG protocol. Authenticated quorum may
/// advance the production clock immediately, but an honest authority fixes at
/// most one ordinary block per interval. This prevents a zero-latency quorum
/// from becoming a self-sustaining empty-block loop while leaving the existing
/// leader timeout and all consensus thresholds unchanged.
pub(crate) const STARFISH_RBC_SINGLE_DAG_ROUND_INTERVAL: Duration = Duration::from_millis(50);

impl BlockCreationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewBlocks => "new_blocks",
            Self::NewHeaders => "new_headers",
            Self::TransactionData => "transaction_data",
            Self::CertificateEvent => "certificate_event",
            Self::ForceTimeout => "force_timeout",
            Self::RelaxedTimeout => "relaxed_timeout",
            Self::PostCommit => "post_commit",
        }
    }
}

pub struct Syncer<H: BlockHandler, S: SyncerSignals, C: CommitObserver> {
    core: Core<H>,
    forced_block_rounds: BTreeSet<RoundNumber>,
    proposal_wait_started_at: Option<Instant>,
    proposal_wait_round: Option<RoundNumber>,
    single_dag_last_proposal_at: Option<Instant>,
    signals: S,
    commit_observer: C,
    pub(crate) connected_authorities: AHashSet<AuthorityIndex>,
    pub(crate) subscribed_by_authorities: AHashSet<AuthorityIndex>,
    subscriber_stake: Stake,
    pub(crate) metrics: Arc<Metrics>,
    bls_tx: Option<mpsc::UnboundedSender<BlsServiceMessage>>,
    sailfish_tx: Option<mpsc::UnboundedSender<SailfishServiceMessage>>,
    starfish_rbc_service: Option<RbcServiceHandle>,
    starfish_rbc_dag_shadow_service: Option<StarfishRbcDagShadowServiceHandleV1>,
    rbc_dag_frontier_authority: bool,
    /// Production remains closed until the ordered service event bridge has
    /// drained startup recovery and persisted every replayed frontier before
    /// processing `Ready`.
    rbc_dag_authority_ready: bool,
    /// Exact locally produced application header waiting for durable carrier
    /// assignment. Authoritative RBC-DAG mode permits only one outstanding
    /// application so a fast legacy proposal clock cannot outrun the carrier
    /// actor or turn a fixed queue size into a protocol parameter.
    rbc_dag_pending_application: Option<BlockReference>,
}

pub trait SyncerSignals: Send + Sync {
    fn new_block_ready(&mut self);
    fn proposal_round_advanced(&mut self, round: RoundNumber);
}

pub trait CommitObserver: Send + Sync {
    fn handle_commit(
        &mut self,
        dag_state: &DagState,
        committed_leaders: Vec<(Data<VerifiedBlock>, Option<CommitMetastate>)>,
    ) -> Vec<CommittedSubDag>;

    /// Observe an RBC-DAG frontier only after Core atomically persisted its
    /// application commit (if any) and durable frontier receipt.
    fn handle_rbc_dag_commit(&mut self, committed: &[CommittedSubDag]);

    fn recover_committed(
        &mut self,
        committed: AHashSet<BlockReference>,
        committed_leaders_count: usize,
    );

    fn cleanup(&mut self, threshold_round: RoundNumber);
}

impl<H: BlockHandler, S: SyncerSignals, C: CommitObserver> Syncer<H, S, C> {
    pub fn new(
        core: Core<H>,
        signals: S,
        commit_observer: C,
        metrics: Arc<Metrics>,
        bls_tx: Option<mpsc::UnboundedSender<BlsServiceMessage>>,
        sailfish_tx: Option<mpsc::UnboundedSender<SailfishServiceMessage>>,
        starfish_rbc_service: Option<RbcServiceHandle>,
        starfish_rbc_dag_shadow_service: Option<StarfishRbcDagShadowServiceHandleV1>,
        rbc_dag_frontier_authority: bool,
    ) -> Self {
        let committee_size = core.committee().len();
        let own_stake = core
            .committee()
            .get_stake(core.authority())
            .expect("Own authority should exist in committee");
        Self {
            core,
            forced_block_rounds: BTreeSet::new(),
            proposal_wait_started_at: None,
            proposal_wait_round: None,
            single_dag_last_proposal_at: None,
            signals,
            commit_observer,
            connected_authorities: AHashSet::with_capacity(committee_size),
            subscribed_by_authorities: AHashSet::with_capacity(committee_size),
            subscriber_stake: own_stake,
            metrics,
            bls_tx,
            sailfish_tx,
            starfish_rbc_service,
            starfish_rbc_dag_shadow_service,
            rbc_dag_frontier_authority,
            rbc_dag_authority_ready: !rbc_dag_frontier_authority,
            rbc_dag_pending_application: None,
        }
    }

    pub fn add_blocks(
        &mut self,
        blocks: Vec<(Data<VerifiedBlock>, Option<ProvableShard>)>,
        source: DataSource,
    ) -> (
        Vec<BlockReference>,
        AHashSet<BlockReference>,
        Vec<BlockReference>,
    ) {
        if self.rbc_dag_frontier_authority {
            tracing::warn!(
                %source,
                count = blocks.len(),
                "Rejected generic block ingress while embedded RBC-DAG authority is active"
            );
            return (Vec::new(), AHashSet::new(), Vec::new());
        }
        self.add_blocks_inner(blocks, source)
    }

    fn add_blocks_inner(
        &mut self,
        blocks: Vec<(Data<VerifiedBlock>, Option<ProvableShard>)>,
        source: DataSource,
    ) -> (
        Vec<BlockReference>,
        AHashSet<BlockReference>,
        Vec<BlockReference>,
    ) {
        let previous_rounds = self.capture_rounds();
        let mut materialization_candidates = blocks
            .iter()
            .map(|(block, _)| *block.reference())
            .collect::<Vec<_>>();
        // todo: when block is updated we might return false here and it can make
        // committing longer
        let (
            success,
            pending_blocks_with_transactions,
            missing_parents,
            used_additional_blocks,
            processed_blocks,
        ) = self.core.add_blocks(blocks, source);
        materialization_candidates.extend(processed_blocks.iter().map(|block| *block.reference()));
        self.notify_materialized_shadow_applications(materialization_candidates);
        if !processed_blocks.is_empty() {
            let block_refs: Vec<_> = processed_blocks.iter().map(|b| *b.reference()).collect();
            self.send_sailfish_message(SailfishServiceMessage::ProcessBlocks(block_refs));
            // Send blocks to BLS service for verification of embedded BLS fields.
            self.send_bls_message(BlsServiceMessage::ProcessBlocks(processed_blocks.clone()));
        }
        self.maybe_update_proposal_wait();
        self.maybe_signal_proposal_round_advance(previous_rounds);
        if success {
            tracing::debug!("Attempt to create block from syncer after adding block");
            self.try_new_block(BlockCreationReason::NewBlocks);
            if self.core.dag_state().consensus_protocol.is_starfish_rbc() {
                // A previously delivered header may have become dirty-DAG
                // connected and clean during insertion.
                self.try_new_commit();
            }
        }
        (
            pending_blocks_with_transactions,
            missing_parents,
            used_additional_blocks,
        )
    }

    /// Add header-only blocks and attempt block creation.
    pub fn add_headers(
        &mut self,
        headers: Vec<Data<VerifiedBlock>>,
        source: DataSource,
    ) -> (AHashSet<BlockReference>, Vec<BlockReference>) {
        if self.rbc_dag_frontier_authority {
            tracing::warn!(
                %source,
                count = headers.len(),
                "Rejected generic header ingress while embedded RBC-DAG authority is active"
            );
            return (AHashSet::new(), Vec::new());
        }
        self.add_headers_inner(headers, source)
    }

    fn add_headers_inner(
        &mut self,
        headers: Vec<Data<VerifiedBlock>>,
        source: DataSource,
    ) -> (AHashSet<BlockReference>, Vec<BlockReference>) {
        let previous_rounds = self.capture_rounds();
        let mut materialization_candidates = headers
            .iter()
            .map(|header| *header.reference())
            .collect::<Vec<_>>();
        let (success, missing_parents, processed_refs, processed_blocks) =
            self.core.add_headers(headers, source);
        materialization_candidates.extend(processed_refs.iter().copied());
        self.notify_materialized_shadow_applications(materialization_candidates);
        if !processed_blocks.is_empty() {
            // Send blocks to BLS service for verification of embedded BLS fields.
            self.send_bls_message(BlsServiceMessage::ProcessBlocks(processed_blocks.clone()));
            let block_refs: Vec<_> = processed_blocks.iter().map(|b| *b.reference()).collect();
            self.send_sailfish_message(SailfishServiceMessage::ProcessBlocks(block_refs));
        }
        self.maybe_update_proposal_wait();
        self.maybe_signal_proposal_round_advance(previous_rounds);
        if success {
            tracing::debug!("Attempt to create block from syncer after adding headers");
            self.try_new_block(BlockCreationReason::NewHeaders);
            if self.core.dag_state().consensus_protocol.is_starfish_rbc() {
                self.try_new_commit();
            }
        }
        (missing_parents, processed_refs)
    }

    /// Attach recovered transaction data to existing blocks and attempt block
    /// creation.
    pub fn add_transaction_data(
        &mut self,
        items: Vec<ReconstructedTransactionData>,
        source: DataSource,
    ) {
        if self.rbc_dag_frontier_authority {
            tracing::warn!(
                %source,
                count = items.len(),
                "Rejected generic transaction-data ingress while embedded RBC-DAG authority is active"
            );
            return;
        }
        self.add_transaction_data_inner(items, source);
    }

    fn add_transaction_data_inner(
        &mut self,
        items: Vec<ReconstructedTransactionData>,
        source: DataSource,
    ) {
        let references = items
            .iter()
            .map(|item| item.block_reference)
            .collect::<Vec<_>>();
        self.core.add_transaction_data(items, source);
        self.notify_materialized_shadow_applications(references);
        self.maybe_update_proposal_wait();
        self.try_new_block(BlockCreationReason::TransactionData);
    }

    /// Materialize one application header whose authority was established by
    /// the carrier actor. Keeping this as a separate core-thread command makes
    /// the capability impossible to forge through `BlockBatch::source`.
    pub(crate) fn add_authorized_rbc_dag_header(
        &mut self,
        header: RbcCanonicalHeader,
    ) -> (AHashSet<BlockReference>, Vec<BlockReference>) {
        assert!(
            self.rbc_dag_frontier_authority,
            "carrier-authorized header ingress requires embedded RBC-DAG authority"
        );
        let mut block = header.to_authentication_free_block();
        block.preserialize();
        self.add_headers_inner(
            vec![Data::new(block)],
            DataSource::StarfishRbcDagAuthorizedHeader,
        )
    }

    /// Attach payload data already verified against a carrier-authorized
    /// canonical header. This cannot be invoked by a peer-controlled source
    /// discriminator; only the typed core-thread command exposes it.
    pub(crate) fn add_authorized_rbc_dag_payload(&mut self, item: ReconstructedTransactionData) {
        assert!(
            self.rbc_dag_frontier_authority,
            "carrier-authorized payload ingress requires embedded RBC-DAG authority"
        );
        self.add_transaction_data_inner(vec![item], DataSource::StarfishRbcDagAuthorizedPayload);
    }

    /// Embedded RBC-DAG data availability is proven only by a concrete,
    /// data-available DagState block. Payloads may arrive before their header
    /// dependencies and remain buffered in Core; any later add path that
    /// materializes the block retries this notification using the exact
    /// processed references returned by Core.
    fn notify_materialized_shadow_applications(
        &self,
        references: impl IntoIterator<Item = BlockReference>,
    ) {
        let Some(shadow) = self.starfish_rbc_dag_shadow_service.as_ref() else {
            return;
        };
        for reference in references {
            if self.core.dag_state().get_storage_block(reference).is_none()
                || !self.core.dag_state().is_data_available(&reference)
            {
                continue;
            }
            if let Err(error) = shadow.application_data_available(reference) {
                self.metrics.starfish_rbc_dag_shadow_comparison_valid.set(0);
                self.metrics.starfish_rbc_dag_shadow_clock_valid.set(0);
                tracing::warn!(
                    ?reference,
                    "Failed to record materialized RBC-DAG application availability: {error}"
                );
            }
        }
    }

    /// Called after Sailfish RBC certification events have been applied to
    /// DagState on the core thread. Retries block creation and sequencing
    /// when any clean vertex is new.
    pub fn apply_sailfish_certificates(&mut self, certified_refs: Vec<BlockReference>) {
        let previous_rounds = self.capture_rounds();
        if self.core.dag_state().mark_vertices_clean(&certified_refs) {
            self.maybe_update_proposal_wait();
            self.maybe_signal_proposal_round_advance(previous_rounds);
            self.try_new_block(BlockCreationReason::CertificateEvent);
            self.try_new_commit();
        }
    }

    /// Called after the local Starfish-RBC service delivers exact header
    /// references. Delivery is separate from dirty insertion and transaction
    /// availability; any newly dependency-closed vertices can immediately
    /// unblock both proposal and commit paths.
    pub fn apply_starfish_rbc_deliveries(&mut self, delivered_headers: Vec<PinnedRbcHeader>) {
        let previous_rounds = self.capture_rounds();
        if self
            .core
            .dag_state()
            .apply_starfish_rbc_deliveries(&delivered_headers)
        {
            self.maybe_update_proposal_wait();
            self.maybe_signal_proposal_round_advance(previous_rounds);
            self.try_new_block(BlockCreationReason::CertificateEvent);
            self.try_new_commit();
        }
    }

    /// Queue one locally locked RBC statement for the next ordinary
    /// single-DAG block. The statement changes no delivery state until peers
    /// authenticate the carrying block.
    pub fn apply_starfish_rbc_reference(
        &mut self,
        reference: crate::types::StarfishRbcReferenceV3,
    ) {
        self.core.add_starfish_rbc_reference(reference);
        self.try_new_block(BlockCreationReason::CertificateEvent);
    }

    pub fn apply_starfish_rbc_echo_vote(&mut self, vote: crate::types::StarfishRbcEchoVoteV3) {
        self.core.add_starfish_rbc_echo_vote(vote);
        self.try_new_block(BlockCreationReason::CertificateEvent);
    }

    pub fn apply_starfish_rbc_echo_qc(&mut self, qc: crate::types::StarfishRbcEchoQcV3) {
        self.core.add_starfish_rbc_echo_qc(qc);
        self.try_new_block(BlockCreationReason::CertificateEvent);
    }

    /// Sequence one exact deterministic carrier-frontier delta. In M7 this is
    /// the sole application-ordering authority; the legacy Starfish committer
    /// remains disabled in this mode.
    pub fn apply_starfish_rbc_dag_frontier(
        &mut self,
        delta: CommittedFrontierDeltaV1,
    ) -> Result<bool, RbcDagFrontierApplyError> {
        assert!(
            self.rbc_dag_frontier_authority,
            "RBC-DAG frontier output requires the explicit authority mode"
        );
        let applications = delta
            .applications
            .iter()
            .map(RbcCanonicalHeader::reference)
            .collect::<Vec<_>>();
        match self.core.handle_rbc_dag_committed_delta(
            delta.output_sequence,
            delta.anchor,
            &applications,
        )? {
            RbcDagFrontierApplyOutcome::ExactReplay => Ok(false),
            RbcDagFrontierApplyOutcome::Applied(committed) => {
                self.commit_observer.handle_rbc_dag_commit(&committed);
                self.try_new_block(BlockCreationReason::PostCommit);
                Ok(true)
            }
        }
    }

    /// Open the authoritative application-production gate only after the
    /// service bridge observes `Ready`. Because the bridge awaits every prior
    /// command, this is also a FIFO persistence barrier for recovery output.
    pub(crate) fn activate_starfish_rbc_dag_authority(&mut self) {
        assert!(
            self.rbc_dag_frontier_authority,
            "only embedded RBC-DAG authority mode has a startup barrier"
        );
        if self.rbc_dag_authority_ready {
            return;
        }
        self.rbc_dag_authority_ready = true;
        self.core.enable_rbc_dag_application_production();
        let initial_round = self.core.next_block_round();
        self.force_new_block(initial_round);
    }

    /// Acknowledge that the exact local application header is durably bound
    /// into a carrier. This releases application production independently of
    /// later RBC delivery/consensus commitment, preserving the carrier
    /// pipeline while bounding producer lead to one header.
    pub fn apply_starfish_rbc_dag_application_assigned(&mut self, reference: BlockReference) {
        assert!(
            self.rbc_dag_frontier_authority,
            "RBC-DAG application assignment requires the explicit authority mode"
        );
        let Some(expected) = self.rbc_dag_pending_application else {
            tracing::debug!(
                ?reference,
                "Ignoring stale RBC-DAG application-assignment acknowledgement"
            );
            return;
        };
        if expected != reference {
            tracing::debug!(
                ?expected,
                ?reference,
                "Ignoring RBC-DAG application-assignment acknowledgement for a different header"
            );
            return;
        }
        self.rbc_dag_pending_application = None;
        self.try_new_block(BlockCreationReason::CertificateEvent);
    }

    /// Store a Sailfish++ timeout certificate in DagState and retry block
    /// creation (a TC may unblock block creation for the next round).
    pub fn apply_timeout_cert(&mut self, cert: SailfishTimeoutCert) {
        self.core.dag_state().add_timeout_cert(cert);
        self.maybe_update_proposal_wait();
        self.try_new_block(BlockCreationReason::CertificateEvent);
    }

    /// Store a Sailfish++ no-vote certificate in DagState and retry block
    /// creation + commit (an NVC may enable direct skip).
    pub fn apply_novote_cert(&mut self, cert: SailfishNoVoteCert) {
        self.core.dag_state().add_novote_cert(cert);
        self.maybe_update_proposal_wait();
        self.try_new_block(BlockCreationReason::CertificateEvent);
        self.try_new_commit();
    }

    /// Apply BLS certificate events from the BLS verification service.
    /// Fresh certificates can unblock both block production and sequencing, so
    /// retry both paths immediately when DAG state changed.
    pub fn apply_certificate_events(&mut self, events: Vec<CertificateEvent>) {
        let previous_rounds = self.capture_rounds();
        if apply_certificate_events(self.core.dag_state(), events) {
            self.maybe_update_proposal_wait();
            self.maybe_signal_proposal_round_advance(previous_rounds);
            self.try_new_block(BlockCreationReason::CertificateEvent);
            self.try_new_commit();
        }
    }

    /// Arm timeout-based block creation for a specific proposal round.
    pub fn force_new_block(&mut self, round: RoundNumber) -> bool {
        if self.core.last_proposed() < round {
            self.metrics.leader_timeout_total.inc();
            self.forced_block_rounds.insert(round);
            tracing::debug!("Attempt to force new block in round {round} after timeout");
            self.maybe_update_proposal_wait();
            self.try_new_block(BlockCreationReason::ForceTimeout);
            true
        } else {
            false
        }
    }

    pub(crate) fn recompute_subscriber_stake(&mut self) {
        let committee = self.core.committee();
        let own_authority = self.core.authority();
        let mut stake = committee.get_total_stake(&self.subscribed_by_authorities);
        if !self.subscribed_by_authorities.contains(&own_authority) {
            stake += committee
                .get_stake(own_authority)
                .expect("Own authority should exist in committee");
        }
        self.subscriber_stake = stake;
    }

    /// Attempt block creation with relaxed readiness (skips the strong-vote
    /// quorum requirement) for a specific proposal round. This acts only once
    /// we are still in that round and have not yet proposed into it. Keyed
    /// on the proposal round so dual-DAG protocols (where the proposal
    /// round can lag the threshold clock) target the round they can
    /// actually enter.
    pub fn try_new_block_relaxed(&mut self, proposal_round: RoundNumber) -> bool {
        if !self.rbc_dag_authority_ready || self.rbc_dag_pending_application.is_some() {
            return false;
        }
        if self.core.dag_state().proposal_round() != proposal_round {
            return false;
        }
        if self.core.last_proposed() >= proposal_round {
            return false;
        }
        self.maybe_update_proposal_wait();
        if !self.core.committee().is_quorum(self.subscriber_stake) {
            return false;
        }
        if self
            .core
            .ready_new_block_relaxed(&self.connected_authorities)
        {
            return self.create_new_block(BlockCreationReason::RelaxedTimeout);
        }
        false
    }

    fn try_new_block(&mut self, reason: BlockCreationReason) -> bool {
        if !self.rbc_dag_authority_ready || self.rbc_dag_pending_application.is_some() {
            return false;
        }
        self.maybe_update_proposal_wait();
        if !self.core.committee().is_quorum(self.subscriber_stake) {
            return false;
        }
        let target_round = self.core.next_block_round();
        let effective_reason = if self.forced_block_rounds.contains(&target_round) {
            BlockCreationReason::ForceTimeout
        } else if !self.core.ready_new_block(&self.connected_authorities) {
            return false;
        } else {
            reason
        };
        if self
            .core
            .dag_state()
            .consensus_protocol
            .is_starfish_rbc_single_dag()
            && !matches!(effective_reason, BlockCreationReason::ForceTimeout)
            && self.single_dag_last_proposal_at.is_some_and(|created_at| {
                created_at.elapsed() < STARFISH_RBC_SINGLE_DAG_ROUND_INTERVAL
            })
        {
            return false;
        }
        self.create_new_block(effective_reason)
    }

    fn create_new_block(&mut self, reason: BlockCreationReason) -> bool {
        if self.rbc_dag_pending_application.is_some() {
            return false;
        }
        tracing::debug!("Attempt to create new block in syncer after one trigger");
        let previous_rounds = self.capture_rounds();
        if let Some(ref block) = self.core.try_new_block(reason.as_str()) {
            if self
                .core
                .dag_state()
                .consensus_protocol
                .is_starfish_rbc_single_dag()
            {
                self.single_dag_last_proposal_at = Some(Instant::now());
            }
            if self.core.dag_state().consensus_protocol.is_starfish_rbc() {
                let canonical = RbcCanonicalHeader::from_block_header(block.header())
                    .expect("locally built Starfish-RBC block must have canonical header content");
                if self.rbc_dag_frontier_authority {
                    self.rbc_dag_pending_application = Some(canonical.reference());
                    let shadow = self
                        .starfish_rbc_dag_shadow_service
                        .as_ref()
                        .expect("embedded RBC-DAG authority must start its carrier service");
                    if let Err(error) = shadow.local_application(
                        &canonical,
                        block.transaction_data().cloned().map(Arc::new),
                    ) {
                        self.metrics.starfish_rbc_dag_shadow_comparison_valid.set(0);
                        self.metrics.starfish_rbc_dag_shadow_clock_valid.set(0);
                        self.metrics
                            .starfish_rbc_dag_shadow_inputs_total
                            .with_label_values(&["local", "dropped"])
                            .inc();
                        tracing::warn!(
                            "Failed to enqueue RBC-DAG application carrier; the research run is invalid: {error}"
                        );
                    } else {
                        self.notify_materialized_shadow_applications([canonical.reference()]);
                    }
                } else {
                    let selected = self
                        .starfish_rbc_service
                        .as_ref()
                        .expect("direct Starfish-RBC mode must start its RBC service")
                        .start_local_header_with_payload_blocking(
                            RbcLocalHeader::from_canonical(&canonical),
                            block.transaction_data().cloned(),
                        )
                        .expect("local Starfish-RBC header must be accepted before dissemination");
                    assert_eq!(
                        selected.reference(),
                        *block.reference(),
                        "RBC service selected a different local header reference"
                    );
                    if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                        if let Err(error) = shadow.local_header(&canonical) {
                            self.metrics.starfish_rbc_dag_shadow_comparison_valid.set(0);
                            self.metrics
                                .starfish_rbc_dag_shadow_inputs_total
                                .with_label_values(&["local", "dropped"])
                                .inc();
                            tracing::warn!("Failed to enqueue RBC-DAG mirror carrier: {error}");
                        } else {
                            self.notify_materialized_shadow_applications([canonical.reference()]);
                        }
                    }
                }
            }
            if let Some(started_at) = self.proposal_wait_started_at.take() {
                self.metrics
                    .proposal_wait_time_total_us
                    .inc_by(started_at.elapsed().as_micros() as u64);
            }
            self.proposal_wait_round = None;
            // Send own block and DAC partial sig to BLS service.
            self.send_bls_message(BlsServiceMessage::ProcessBlocks(vec![block.clone()]));
            // Send own block reference to Sailfish certification service.
            self.send_sailfish_message(SailfishServiceMessage::ProcessBlocks(vec![
                *block.reference(),
            ]));
            // SailfishPlusPlus: if we created a block without referencing the
            // previous-round leader, send a LocalNoVote so the service can
            // sign and aggregate a no-vote certificate.
            if self.core.dag_state().consensus_protocol.is_sailfish_pp() {
                let block_round = block.round();
                if block_round > 1 {
                    let prev_leader = self.core.committee().elect_leader(block_round - 1);
                    let has_prev_leader = block
                        .block_references()
                        .iter()
                        .any(|r| r.round == block_round - 1 && r.authority == prev_leader);
                    if !has_prev_leader {
                        self.send_sailfish_message(SailfishServiceMessage::LocalNoVote {
                            round: block_round - 1,
                            leader: prev_leader,
                        });
                    }
                }
            }
            if let Some((block_ref, auth, sig)) = self.core.generate_own_dac_partial_sig(block) {
                self.send_bls_message(BlsServiceMessage::PartialSig(PartialSig {
                    kind: PartialSigKind::Dac(block_ref),
                    signer: auth,
                    signature: sig,
                }));
            }
            self.maybe_signal_proposal_round_advance(previous_rounds);
            self.signals.new_block_ready();
            self.forced_block_rounds.remove(&block.round());
            return true;
        }
        false
    }

    fn send_bls_message(&self, message: BlsServiceMessage) {
        if let Some(ref sender) = self.bls_tx {
            let _ = sender.send(message);
        }
    }

    fn send_sailfish_message(&self, message: SailfishServiceMessage) {
        if let Some(ref sender) = self.sailfish_tx {
            let _ = sender.send(message);
        }
    }

    fn maybe_update_proposal_wait(&mut self) {
        let threshold_round = self.core.dag_state().proposal_round();
        if threshold_round <= self.core.last_proposed() {
            return;
        }

        match self.proposal_wait_round {
            None => {
                self.proposal_wait_round = Some(threshold_round);
                self.proposal_wait_started_at = Some(Instant::now());
            }
            Some(wait_round) if threshold_round > wait_round => {
                if let Some(started_at) = self.proposal_wait_started_at.replace(Instant::now()) {
                    self.metrics
                        .proposal_wait_time_total_us
                        .inc_by(started_at.elapsed().as_micros() as u64);
                }
                self.proposal_wait_round = Some(threshold_round);
            }
            _ => {}
        }
    }

    fn capture_rounds(&self) -> (RoundNumber, RoundNumber) {
        (
            self.core.dag_state().threshold_clock_round(),
            self.core.dag_state().proposal_round(),
        )
    }

    fn maybe_signal_proposal_round_advance(&mut self, previous_rounds: (RoundNumber, RoundNumber)) {
        let (previous_threshold_round, previous_proposal_round) = previous_rounds;
        let current_threshold_round = self.core.dag_state().threshold_clock_round();
        let current_proposal_round = self.core.dag_state().proposal_round();
        debug_assert!(current_threshold_round >= previous_threshold_round);
        if current_proposal_round > previous_proposal_round {
            self.signals.proposal_round_advanced(current_proposal_round);
        }
    }

    pub fn try_new_commit(&mut self) {
        if self.rbc_dag_frontier_authority {
            return;
        }
        let (newly_committed, any_decided) = self.core.try_commit();
        let utc_now = timestamp_utc();
        if !newly_committed.is_empty() {
            let committed_refs: Vec<_> = newly_committed
                .iter()
                .map(|(block, _meta)| {
                    let age = utc_now
                        .checked_sub(block.meta_creation_time())
                        .unwrap_or_default();
                    format!("{}({}ms)", block.reference(), age.as_millis())
                })
                .collect();
            tracing::debug!("Committed {:?}", committed_refs);
        }
        let committed_subdag = self
            .commit_observer
            .handle_commit(self.core.dag_state(), newly_committed);

        self.core
            .handle_committed_subdag(committed_subdag, any_decided);
        self.try_new_block(BlockCreationReason::PostCommit);
    }

    pub fn cleanup(&mut self) {
        let threshold = self.core.cleanup();
        self.commit_observer.cleanup(threshold);
    }

    pub fn core(&self) -> &Core<H> {
        &self.core
    }

    pub fn missing_parent_references(&self) -> Vec<BlockReference> {
        self.core.block_manager().missing_block_references()
    }
}

impl SyncerSignals for bool {
    fn new_block_ready(&mut self) {
        *self = true;
    }

    fn proposal_round_advanced(&mut self, _round: RoundNumber) {
        *self = true;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use prometheus::Registry;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        block_handler::BlockHandler,
        committee::Committee,
        config::{DisseminationMode, NodePrivateConfig, StorageBackend},
        crypto::{Signer, TransactionsCommitment, mac_keyrings_for_test},
        dag_state::{ConsensusProtocol, DagState},
        encoder::ShardEncoder,
        metrics::Metrics,
        starfish_rbc_dag::{
            RbcDagCommitteeContextV1, RbcDagContextV1, RbcDagProtocolInstanceId,
            storage::ShadowWalSyncPolicyV1,
        },
        starfish_rbc_dag_shadow::ShadowAuthorizerV1,
        starfish_rbc_dag_shadow_service::{
            ShadowServiceEventV1, start_starfish_rbc_dag_autonomous_clock_service_v1,
        },
        types::{
            BaseTransaction, BlockAuthenticationScheme, Encoder, Transaction, TransactionData,
        },
    };

    #[derive(Default)]
    struct TestBlockHandler;

    impl BlockHandler for TestBlockHandler {
        fn handle_proposal(&mut self, _number_transactions: usize) {}

        fn handle_blocks(&mut self, _require_response: bool) -> Vec<BaseTransaction> {
            Vec::new()
        }
    }

    #[derive(Default)]
    struct NoopCommitObserver;

    impl CommitObserver for NoopCommitObserver {
        fn handle_commit(
            &mut self,
            _dag_state: &DagState,
            _committed_leaders: Vec<(Data<VerifiedBlock>, Option<CommitMetastate>)>,
        ) -> Vec<CommittedSubDag> {
            Vec::new()
        }

        fn handle_rbc_dag_commit(&mut self, _committed: &[CommittedSubDag]) {}

        fn recover_committed(
            &mut self,
            _committed: AHashSet<BlockReference>,
            _committed_leaders_count: usize,
        ) {
        }

        fn cleanup(&mut self, _threshold_round: RoundNumber) {}
    }

    #[derive(Default)]
    struct TestSignals {
        new_block_ready_count: usize,
        proposal_round_advances: Vec<RoundNumber>,
    }

    impl SyncerSignals for TestSignals {
        fn new_block_ready(&mut self) {
            self.new_block_ready_count += 1;
        }

        fn proposal_round_advanced(&mut self, round: RoundNumber) {
            self.proposal_round_advances.push(round);
        }
    }

    fn open_test_syncer_with_future_rounds() -> Syncer<TestBlockHandler, bool, NoopCommitObserver> {
        let authority = 0;
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) =
            Metrics::new(&registry, Some(committee.as_ref()), Some("mysticeti"), None);
        let dir = TempDir::new().unwrap();
        let recovered = DagState::open(
            authority,
            dir.path(),
            metrics.clone(),
            committee.clone(),
            "honest".to_string(),
            "mysticeti".to_string(),
            &StorageBackend::Rocksdb,
            false,
            DisseminationMode::ProtocolDefault,
        );
        let private_config = NodePrivateConfig::new_for_tests(authority);
        let (mut core, _) = Core::open(
            TestBlockHandler,
            authority,
            committee.clone(),
            private_config,
            metrics.clone(),
            recovered,
            None,
        );
        let signers = Signer::new_for_test(committee.len());

        let round_1_refs = vec![
            BlockReference::new_test(0, 0),
            BlockReference::new_test(1, 0),
            BlockReference::new_test(2, 0),
        ];
        let round_1_blocks = vec![
            make_mysticeti_block(&signers, 1, 1, round_1_refs.clone()),
            make_mysticeti_block(&signers, 2, 1, round_1_refs.clone()),
            make_mysticeti_block(&signers, 3, 1, round_1_refs.clone()),
        ];
        let round_2_refs: Vec<_> = round_1_blocks
            .iter()
            .map(|block| *block.reference())
            .collect();
        let round_2_blocks = vec![
            make_mysticeti_block(&signers, 1, 2, round_2_refs.clone()),
            make_mysticeti_block(&signers, 2, 2, round_2_refs.clone()),
            make_mysticeti_block(&signers, 3, 2, round_2_refs),
        ];

        core.add_blocks(
            round_1_blocks
                .into_iter()
                .map(|block| (block, None))
                .collect(),
            DataSource::BlockBundleStreaming,
        );
        core.add_blocks(
            round_2_blocks
                .into_iter()
                .map(|block| (block, None))
                .collect(),
            DataSource::BlockBundleStreaming,
        );
        assert_eq!(core.dag_state().proposal_round(), 3);
        assert_eq!(core.last_proposed(), 0);

        let mut syncer = Syncer::new(
            core,
            false,
            NoopCommitObserver,
            metrics,
            None,
            None,
            None,
            None,
            false,
        );
        syncer.connected_authorities.extend([1, 2, 3]);
        syncer.subscribed_by_authorities.extend([1, 2, 3]);
        syncer.recompute_subscriber_stake();
        syncer
    }

    fn open_test_syncer_where_local_block_advances_round()
    -> Syncer<TestBlockHandler, TestSignals, NoopCommitObserver> {
        let authority = 0;
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) =
            Metrics::new(&registry, Some(committee.as_ref()), Some("mysticeti"), None);
        let dir = TempDir::new().unwrap();
        let recovered = DagState::open(
            authority,
            dir.path(),
            metrics.clone(),
            committee.clone(),
            "honest".to_string(),
            "mysticeti".to_string(),
            &StorageBackend::Rocksdb,
            false,
            DisseminationMode::ProtocolDefault,
        );
        let private_config = NodePrivateConfig::new_for_tests(authority);
        let (mut core, _) = Core::open(
            TestBlockHandler,
            authority,
            committee.clone(),
            private_config,
            metrics.clone(),
            recovered,
            None,
        );
        let signers = Signer::new_for_test(committee.len());

        let round_1_refs = vec![
            BlockReference::new_test(0, 0),
            BlockReference::new_test(1, 0),
            BlockReference::new_test(2, 0),
        ];
        let round_1_blocks = vec![
            make_mysticeti_block(&signers, 1, 1, round_1_refs.clone()),
            make_mysticeti_block(&signers, 2, 1, round_1_refs.clone()),
            make_mysticeti_block(&signers, 3, 1, round_1_refs.clone()),
        ];
        let round_2_refs: Vec<_> = round_1_blocks
            .iter()
            .map(|block| *block.reference())
            .collect();
        let round_2_blocks = vec![
            make_mysticeti_block(&signers, 1, 2, round_2_refs.clone()),
            make_mysticeti_block(&signers, 2, 2, round_2_refs.clone()),
            make_mysticeti_block(&signers, 3, 2, round_2_refs.clone()),
        ];
        let round_3_refs: Vec<_> = round_2_blocks
            .iter()
            .map(|block| *block.reference())
            .collect();
        let round_3_blocks = vec![
            make_mysticeti_block(&signers, 1, 3, round_3_refs.clone()),
            make_mysticeti_block(&signers, 2, 3, round_3_refs),
        ];

        core.add_blocks(
            round_1_blocks
                .into_iter()
                .map(|block| (block, None))
                .collect(),
            DataSource::BlockBundleStreaming,
        );
        core.add_blocks(
            round_2_blocks
                .into_iter()
                .map(|block| (block, None))
                .collect(),
            DataSource::BlockBundleStreaming,
        );
        core.add_blocks(
            round_3_blocks
                .into_iter()
                .map(|block| (block, None))
                .collect(),
            DataSource::BlockBundleStreaming,
        );
        assert_eq!(core.dag_state().proposal_round(), 3);
        assert_eq!(core.last_proposed(), 0);

        let mut syncer = Syncer::new(
            core,
            TestSignals::default(),
            NoopCommitObserver,
            metrics,
            None,
            None,
            None,
            None,
            false,
        );
        syncer.connected_authorities.extend([1, 2, 3]);
        syncer.subscribed_by_authorities.extend([1, 2, 3]);
        syncer.recompute_subscriber_stake();
        syncer
    }

    fn make_mysticeti_block(
        signers: &[Signer],
        authority: AuthorityIndex,
        round: RoundNumber,
        block_references: Vec<BlockReference>,
    ) -> Data<VerifiedBlock> {
        let mut block = VerifiedBlock::new_with_signer(
            authority,
            round,
            block_references,
            None,
            vec![],
            0,
            &signers[authority as usize],
            None,
            None,
            vec![],
            vec![],
            None,
            ConsensusProtocol::Mysticeti,
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

    fn make_starfish_rbc_round_1_application(
        committee: &Committee,
        authority: AuthorityIndex,
        receiver: AuthorityIndex,
    ) -> (
        Data<VerifiedBlock>,
        RbcCanonicalHeader,
        ReconstructedTransactionData,
    ) {
        let payload_byte = u8::try_from(authority).unwrap();
        let transactions = vec![BaseTransaction::Share(Transaction::new(vec![
            payload_byte;
            64
        ]))];
        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let encoded = encoder.encode_transactions(
            &transactions,
            committee.info_length(),
            committee.len() - committee.info_length(),
        );
        let mut block = VerifiedBlock::new_starfish_rbc(
            authority,
            1,
            committee
                .authorities()
                .map(|authority| BlockReference::new_test(authority, 0))
                .collect(),
            Vec::new(),
            u64::from(authority) + 1,
            transactions.clone(),
            Some(encoded.clone()),
        );
        let canonical = RbcCanonicalHeader::from_block_header(block.header()).unwrap();
        block.preserialize();

        let mut transaction_data = TransactionData::new(transactions);
        transaction_data.preserialize();
        let (commitment, proof) =
            TransactionsCommitment::new_from_encoded_transactions(&encoded, receiver as usize);
        assert_eq!(commitment, canonical.transactions_commitment());
        let mut shard_data = ProvableShard::new(
            encoded[receiver as usize].clone(),
            receiver as usize,
            proof,
            commitment,
        );
        shard_data.preserialize();
        let payload = ReconstructedTransactionData {
            block_reference: canonical.reference(),
            transaction_data,
            shard_data,
        };
        (Data::new(block), canonical, payload)
    }

    fn make_reconstructed_payload(
        full_block: &Data<VerifiedBlock>,
        committee: &Committee,
        receiver: AuthorityIndex,
    ) -> ReconstructedTransactionData {
        let transactions = full_block
            .transaction_data()
            .expect("test application must carry transaction data")
            .transactions()
            .clone();
        let mut encoder = Encoder::new(2, 4, 2).unwrap();
        let encoded = encoder.encode_transactions(
            &transactions,
            committee.info_length(),
            committee.len() - committee.info_length(),
        );
        let mut transaction_data = TransactionData::new(transactions);
        transaction_data.preserialize();
        let (commitment, proof) =
            TransactionsCommitment::new_from_encoded_transactions(&encoded, receiver as usize);
        let mut shard_data = ProvableShard::new(
            encoded[receiver as usize].clone(),
            receiver as usize,
            proof,
            commitment,
        );
        shard_data.preserialize();
        ReconstructedTransactionData {
            block_reference: *full_block.reference(),
            transaction_data,
            shard_data,
        }
    }

    async fn wait_for_shadow_ready(events: &mut mpsc::Receiver<ShadowServiceEventV1>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match events.recv().await {
                    Some(ShadowServiceEventV1::Ready { autonomous_clock }) => {
                        assert!(autonomous_clock);
                        break;
                    }
                    Some(_) => {}
                    None => panic!("autonomous shadow service stopped before Ready"),
                }
            }
        })
        .await
        .expect("autonomous shadow service did not become ready");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rbc_dag_gate_and_typed_ingress_are_enforced() {
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
        let (core, _) = Core::open(
            TestBlockHandler,
            authority,
            committee.clone(),
            private_config,
            metrics.clone(),
            recovered,
            None,
        );

        let shadow_directory = TempDir::new().unwrap();
        let keyrings = mac_keyrings_for_test(committee.len());
        let committee_context = RbcDagCommitteeContextV1::new(committee.clone()).unwrap();
        let context = RbcDagContextV1::new_with_committee(
            RbcDagProtocolInstanceId::new([0x53; 32]).unwrap(),
            &committee_context,
            BlockAuthenticationScheme::MacVector,
        );
        let (shadow_service, mut shadow_events, shadow_task) =
            start_starfish_rbc_dag_autonomous_clock_service_v1(
                shadow_directory.path().join("standalone.wal"),
                committee_context,
                authority,
                context,
                ShadowAuthorizerV1::MacVector(keyrings[authority as usize].clone()),
                Vec::new(),
                Duration::from_secs(3_600),
                ShadowWalSyncPolicyV1::EveryBatch,
            )
            .unwrap();
        wait_for_shadow_ready(&mut shadow_events).await;
        // This unit drives the Syncer boundary directly instead of running the
        // production event bridge. Keep draining the actor's bounded event
        // channel so local carrier fanout cannot block the actor (and hence a
        // later graceful shutdown) behind events this test intentionally does
        // not consume.
        let shadow_event_drain =
            tokio::spawn(async move { while shadow_events.recv().await.is_some() {} });

        let mut syncer = Syncer::new(
            core,
            TestSignals::default(),
            NoopCommitObserver,
            metrics,
            None,
            None,
            None,
            Some(shadow_service.clone()),
            true,
        );
        syncer.connected_authorities.extend([1, 2, 3]);
        syncer.subscribed_by_authorities.extend([1, 2, 3]);
        syncer.recompute_subscriber_stake();

        // Production is intentionally closed until the ordered service bridge
        // consumes `Ready`. Exercise that authority barrier before asserting
        // the one-outstanding application gate.
        syncer.activate_starfish_rbc_dag_authority();
        let first = syncer
            .rbc_dag_pending_application
            .expect("round-one application must wait for carrier assignment");
        assert_eq!(first.round, 1);
        assert_eq!(syncer.core.last_proposed(), 1);
        assert_eq!(syncer.signals.new_block_ready_count, 1);
        assert!(!shadow_task.is_finished());

        // Peer-controlled generic ingress cannot materialize authentication-
        // free applications in standalone mode.
        let (full_one, canonical_one, payload_one) =
            make_starfish_rbc_round_1_application(&committee, 1, authority);
        let reference_one = canonical_one.reference();
        let mut header_one = canonical_one.to_authentication_free_block();
        header_one.preserialize();
        let generic_headers = syncer.add_headers(
            vec![Data::new(header_one)],
            DataSource::BlockBundleStreamingHeader,
        );
        assert!(generic_headers.0.is_empty());
        assert!(generic_headers.1.is_empty());
        assert!(
            syncer
                .core
                .dag_state()
                .get_storage_block(reference_one)
                .is_none()
        );

        let (full_two, canonical_two, _) =
            make_starfish_rbc_round_1_application(&committee, 2, authority);
        let reference_two = canonical_two.reference();
        let generic_blocks =
            syncer.add_blocks(vec![(full_two, None)], DataSource::BlockBundleStreaming);
        assert!(generic_blocks.0.is_empty());
        assert!(generic_blocks.1.is_empty());
        assert!(generic_blocks.2.is_empty());
        assert!(
            syncer
                .core
                .dag_state()
                .get_storage_block(reference_two)
                .is_none()
        );

        // The actor-only typed header command admits the exact canonical
        // application, while the generic payload command remains closed.
        let (missing_one, _) = syncer.add_authorized_rbc_dag_header(canonical_one);
        assert!(missing_one.is_empty());
        assert!(
            syncer
                .core
                .dag_state()
                .get_storage_block(reference_one)
                .is_some()
        );
        assert!(!syncer.core.dag_state().is_data_available(&reference_one));

        syncer.add_transaction_data(
            vec![payload_one],
            DataSource::StarfishRbcDagAuthorizedPayload,
        );
        assert!(!syncer.core.dag_state().is_data_available(&reference_one));

        syncer.add_authorized_rbc_dag_payload(make_reconstructed_payload(
            &full_one, &committee, authority,
        ));
        assert!(syncer.core.dag_state().is_data_available(&reference_one));

        let (missing_two, _) = syncer.add_authorized_rbc_dag_header(canonical_two);
        assert!(missing_two.is_empty());
        assert!(
            syncer
                .core
                .dag_state()
                .get_storage_block(reference_two)
                .is_some()
        );

        // Even after a typed header quorum advances the application clock,
        // all creation triggers remain closed while the first header is pending.
        assert_eq!(syncer.core.dag_state().threshold_clock_round(), 2);
        assert!(!syncer.try_new_block(BlockCreationReason::NewHeaders));
        assert_eq!(syncer.core.last_proposed(), 1);
        assert_eq!(syncer.rbc_dag_pending_application, Some(first));

        let wrong = BlockReference::new_test(3, first.round);
        syncer.apply_starfish_rbc_dag_application_assigned(wrong);
        assert_eq!(syncer.rbc_dag_pending_application, Some(first));
        assert_eq!(syncer.core.last_proposed(), 1);

        // The exact acknowledgement releases one proposal attempt. That
        // attempt creates round two and immediately closes the gate around
        // the new outstanding header; it cannot create more than one block.
        syncer.apply_starfish_rbc_dag_application_assigned(first);
        let second = syncer
            .rbc_dag_pending_application
            .expect("round-two application must become the sole outstanding header");
        assert_eq!(second.round, 2);
        assert_ne!(second, first);
        assert_eq!(syncer.core.last_proposed(), 2);
        assert_eq!(syncer.signals.new_block_ready_count, 2);
        assert!(!syncer.try_new_block(BlockCreationReason::CertificateEvent));
        assert_eq!(syncer.core.last_proposed(), 2);

        // A duplicate acknowledgement for the old header is stale and must
        // neither release nor replace the current gate.
        syncer.apply_starfish_rbc_dag_application_assigned(first);
        assert_eq!(syncer.rbc_dag_pending_application, Some(second));
        assert_eq!(syncer.core.last_proposed(), 2);

        // With no round-three quorum, the exact second acknowledgement simply
        // clears the gate. A later duplicate is harmless and leaves it clear.
        syncer.apply_starfish_rbc_dag_application_assigned(second);
        assert_eq!(syncer.rbc_dag_pending_application, None);
        assert_eq!(syncer.core.last_proposed(), 2);
        syncer.apply_starfish_rbc_dag_application_assigned(second);
        assert_eq!(syncer.rbc_dag_pending_application, None);
        assert_eq!(syncer.signals.new_block_ready_count, 2);

        shadow_service.shutdown().await.unwrap();
        shadow_task.await.unwrap();
        shadow_event_drain.await.unwrap();
    }

    #[test]
    fn normal_block_creation_uses_next_missing_round() {
        let mut syncer = open_test_syncer_with_future_rounds();

        assert!(syncer.try_new_block(BlockCreationReason::NewBlocks));
        assert_eq!(syncer.core.last_proposed(), 1);
    }

    #[test]
    fn timeout_rounds_stay_pinned_until_their_turn() {
        let mut syncer = open_test_syncer_with_future_rounds();

        assert!(syncer.force_new_block(2));
        assert_eq!(syncer.core.last_proposed(), 1);
        assert!(syncer.forced_block_rounds.contains(&2));

        assert!(syncer.try_new_block(BlockCreationReason::NewBlocks));
        assert_eq!(syncer.core.last_proposed(), 2);
        assert!(!syncer.forced_block_rounds.contains(&2));
    }

    #[test]
    fn local_block_creation_signals_round_advance() {
        let mut syncer = open_test_syncer_where_local_block_advances_round();

        assert!(syncer.try_new_block(BlockCreationReason::NewBlocks));
        assert!(syncer.try_new_block(BlockCreationReason::NewBlocks));
        assert_eq!(syncer.core.last_proposed(), 2);
        assert!(syncer.signals.proposal_round_advances.is_empty());

        assert!(syncer.try_new_block(BlockCreationReason::NewBlocks));
        assert_eq!(syncer.core.last_proposed(), 3);
        assert_eq!(syncer.core.dag_state().proposal_round(), 4);
        assert_eq!(syncer.signals.proposal_round_advances, vec![4]);
        assert_eq!(syncer.signals.new_block_ready_count, 3);
    }

    // Bluestreak-specific behavior is tested in core; Syncer stays
    // protocol-agnostic.
}
