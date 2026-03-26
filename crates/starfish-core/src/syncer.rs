// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeSet, sync::Arc, time::Instant};

use ahash::AHashSet;

use tokio::sync::mpsc;

use crate::{
    block_handler::BlockHandler,
    bls_certificate_aggregator::{CertificateEvent, apply_certificate_events},
    bls_service::BlsServiceMessage,
    consensus::{CommitMetastate, linearizer::CommittedSubDag},
    core::Core,
    dag_state::{DagState, DataSource},
    data::Data,
    metrics::Metrics,
    runtime::timestamp_utc,
    sailfish_service::SailfishServiceMessage,
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
    signals: S,
    commit_observer: C,
    pub(crate) connected_authorities: AHashSet<AuthorityIndex>,
    pub(crate) subscribed_by_authorities: AHashSet<AuthorityIndex>,
    subscriber_stake: Stake,
    pub(crate) metrics: Arc<Metrics>,
    bls_tx: Option<mpsc::UnboundedSender<BlsServiceMessage>>,
    sailfish_tx: Option<mpsc::UnboundedSender<SailfishServiceMessage>>,
}

pub trait SyncerSignals: Send + Sync {
    fn new_block_ready(&mut self);
    fn threshold_clock_round_advanced(&mut self, round: RoundNumber);
}

pub trait CommitObserver: Send + Sync {
    fn handle_commit(
        &mut self,
        dag_state: &DagState,
        committed_leaders: Vec<(Data<VerifiedBlock>, Option<CommitMetastate>)>,
    ) -> Vec<CommittedSubDag>;

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
            signals,
            commit_observer,
            connected_authorities: AHashSet::with_capacity(committee_size),
            subscribed_by_authorities: AHashSet::with_capacity(committee_size),
            subscriber_stake: own_stake,
            metrics,
            bls_tx,
            sailfish_tx,
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
        let previous_threshold_round = self.core.dag_state().proposal_round();
        // todo: when block is updated we might return false here and it can make
        // committing longer
        let (
            success,
            pending_blocks_with_transactions,
            missing_parents,
            used_additional_blocks,
            processed_blocks,
        ) = self.core.add_blocks(blocks, source);
        if !processed_blocks.is_empty() {
            let block_refs: Vec<_> = processed_blocks.iter().map(|b| *b.reference()).collect();
            self.send_sailfish_message(SailfishServiceMessage::ProcessBlocks(block_refs));
            // Send blocks to BLS service for verification of embedded BLS fields.
            self.send_bls_message(BlsServiceMessage::ProcessBlocks(processed_blocks.clone()));
        }
        self.maybe_update_proposal_wait();
        self.maybe_signal_threshold_round_advance(previous_threshold_round);
        if success {
            tracing::debug!("Attempt to create block from syncer after adding block");
            self.try_new_block(BlockCreationReason::NewBlocks);
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
        let previous_threshold_round = self.core.dag_state().proposal_round();
        let (success, missing_parents, processed_refs, processed_blocks) =
            self.core.add_headers(headers, source);
        if !processed_blocks.is_empty() {
            // Send blocks to BLS service for verification of embedded BLS fields.
            self.send_bls_message(BlsServiceMessage::ProcessBlocks(processed_blocks.clone()));
            let block_refs: Vec<_> = processed_blocks.iter().map(|b| *b.reference()).collect();
            self.send_sailfish_message(SailfishServiceMessage::ProcessBlocks(block_refs));
        }
        self.maybe_update_proposal_wait();
        self.maybe_signal_threshold_round_advance(previous_threshold_round);
        if success {
            tracing::debug!("Attempt to create block from syncer after adding headers");
            self.try_new_block(BlockCreationReason::NewHeaders);
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
        self.core.add_transaction_data(items, source);
        self.maybe_update_proposal_wait();
        self.try_new_block(BlockCreationReason::TransactionData);
    }

    /// Called after Sailfish RBC certification events have been applied to
    /// DagState on the core thread. Retries block creation and sequencing
    /// when any clean vertex is new.
    pub fn apply_sailfish_certificates(&mut self, certified_refs: Vec<BlockReference>) {
        let previous_threshold_round = self.core.dag_state().proposal_round();
        if self.core.dag_state().mark_vertices_clean(&certified_refs) {
            self.maybe_update_proposal_wait();
            self.maybe_signal_threshold_round_advance(previous_threshold_round);
            self.try_new_block(BlockCreationReason::CertificateEvent);
            self.try_new_commit();
        }
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
        let previous_proposal_round = self.core.dag_state().proposal_round();
        if apply_certificate_events(self.core.dag_state(), events) {
            self.maybe_update_proposal_wait();
            self.maybe_signal_threshold_round_advance(previous_proposal_round);
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

    /// Attempt block creation with relaxed readiness (skips StarfishSpeed
    /// strong-vote quorum requirement) for a specific threshold-clock round.
    /// This acts only once we are still in that round and have not yet proposed
    /// into it.
    pub fn try_new_block_relaxed(&mut self, threshold_round: RoundNumber) -> bool {
        if self.core.dag_state().threshold_clock_round() != threshold_round {
            return false;
        }
        if self.core.last_proposed() >= threshold_round {
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
        self.create_new_block(effective_reason)
    }

    fn create_new_block(&mut self, reason: BlockCreationReason) -> bool {
        tracing::debug!("Attempt to create new block in syncer after one trigger");
        let previous_proposal_round = self.core.dag_state().proposal_round();
        if let Some(ref block) = self.core.try_new_block(reason.as_str()) {
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
            self.maybe_signal_threshold_round_advance(previous_proposal_round);
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

    fn maybe_signal_threshold_round_advance(&mut self, previous_threshold_round: RoundNumber) {
        let current_threshold_round = self.core.dag_state().proposal_round();
        if current_threshold_round > previous_threshold_round {
            self.signals
                .threshold_clock_round_advanced(current_threshold_round);
        }
    }

    pub fn try_new_commit(&mut self) {
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

    fn threshold_clock_round_advanced(&mut self, _round: RoundNumber) {
        *self = true;
    }
}

#[cfg(test)]
mod tests {
    use prometheus::Registry;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        block_handler::BlockHandler,
        committee::Committee,
        config::{DisseminationMode, NodePrivateConfig, StorageBackend},
        crypto::Signer,
        dag_state::{ConsensusProtocol, DagState},
        metrics::Metrics,
        types::BaseTransaction,
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
        threshold_round_advances: Vec<RoundNumber>,
    }

    impl SyncerSignals for TestSignals {
        fn new_block_ready(&mut self) {
            self.new_block_ready_count += 1;
        }

        fn threshold_clock_round_advanced(&mut self, round: RoundNumber) {
            self.threshold_round_advances.push(round);
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

        let mut syncer = Syncer::new(core, false, NoopCommitObserver, metrics, None, None);
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
        assert!(syncer.signals.threshold_round_advances.is_empty());

        assert!(syncer.try_new_block(BlockCreationReason::NewBlocks));
        assert_eq!(syncer.core.last_proposed(), 3);
        assert_eq!(syncer.core.dag_state().proposal_round(), 4);
        assert_eq!(syncer.signals.threshold_round_advances, vec![4]);
        assert_eq!(syncer.signals.new_block_ready_count, 3);
    }
}
