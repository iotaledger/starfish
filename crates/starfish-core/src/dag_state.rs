// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    cmp::max,
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
    sync::Arc,
    time::Instant,
};

use ahash::{AHashMap, AHashSet};
use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{
    committee::{Committee, QuorumThreshold, StakeAggregator},
    config::{DisseminationMode, StorageBackend},
    consensus::linearizer::{CommittedSubDag, MAX_TRAVERSAL_DEPTH},
    crypto::{BlsSignatureBytes, TransactionsCommitment},
    data::Data,
    metrics::{Metrics, UtilizationTimerExt},
    network::ShardPayload,
    rocks_store::RocksStore,
    state::{RecoveredState, RecoveredStateBuilder},
    store::Store,
    threshold_clock::ThresholdClockAggregator,
    types::{
        AuthorityIndex, BlockDigest, BlockReference, BlsAggregateCertificate, ProvableShard,
        RoundNumber, TransactionData, VerifiedBlock,
    },
};

/// Bitmask tracking which authorities know about a block. Supports up to 128
/// authorities.
type AuthorityBitmask = u128;

pub type PendingSubDag = (CommittedSubDag, Vec<StakeAggregator<QuorumThreshold>>);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DacCertificateVerificationState {
    #[default]
    Unchecked,
    Verified,
    Rejected,
}

#[derive(Clone, Debug, Copy, PartialEq)]
pub enum ConsensusProtocol {
    Mysticeti,
    CordialMiners,
    Starfish,
    StarfishSpeed,
    StarfishBls,
}

impl ConsensusProtocol {
    pub fn from_str(s: &str) -> Self {
        match s {
            "mysticeti" => ConsensusProtocol::Mysticeti,
            "cordial-miners" => ConsensusProtocol::CordialMiners,
            "starfish" => ConsensusProtocol::Starfish,
            "starfish-bls" | "starfish-l" => ConsensusProtocol::StarfishBls,
            "starfish-speed" | "starfish-s" => ConsensusProtocol::StarfishSpeed,
            _ => ConsensusProtocol::Starfish,
        }
    }

    pub fn supports_acknowledgments(self) -> bool {
        matches!(
            self,
            ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishBls
                | ConsensusProtocol::StarfishSpeed
        )
    }

    pub fn default_dissemination_mode(self) -> DisseminationMode {
        match self {
            ConsensusProtocol::Mysticeti => DisseminationMode::Pull,
            ConsensusProtocol::CordialMiners
            | ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishSpeed
            | ConsensusProtocol::StarfishBls => DisseminationMode::PushCausal,
        }
    }

    pub fn resolve_dissemination_mode(self, configured: DisseminationMode) -> DisseminationMode {
        match configured {
            DisseminationMode::ProtocolDefault => self.default_dissemination_mode(),
            other => other,
        }
    }
}

const STARFISH_SPEED_HINT_WINDOW_LEADER_ROUNDS: usize = 10;

#[allow(unused)]
#[derive(Clone, Debug, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ByzantineStrategy {
    TimeoutLeader,          // Adversary waits timeout before sending their leader blocks
    EquivocatingChains,     // Equivocation attack: N-1 equivocations per round
    EquivocatingTwoChains,  // Skipping rule equivocation: 2 equivocations split across validators
    RandomDrop,             // Drop messages randomly
    LeaderWithholding,      // Withholding leader blocks (sent to f+1+c validators)
    ChainBomb,              // Fork bomb: withhold a chain of blocks and release it all at once
    EquivocatingChainsBomb, // Equivocation fork bomb: send different chains to each validator
}

impl ByzantineStrategy {
    /// Strategies that create multiple equivocating blocks per round.
    /// These must not generate transactions — encoding tx data for each
    /// equivocating block is prohibitively expensive.
    pub fn is_equivocating(&self) -> bool {
        matches!(
            self,
            Self::EquivocatingChains | Self::EquivocatingTwoChains | Self::EquivocatingChainsBomb
        )
    }

    pub fn from_strategy_str(s: &str) -> Option<Self> {
        match s {
            "timeout-leader" => Some(Self::TimeoutLeader),
            "leader-withholding" => Some(Self::LeaderWithholding),
            "equivocating-chains" => Some(Self::EquivocatingChains),
            "equivocating-two-chains" => Some(Self::EquivocatingTwoChains),
            "chain-bomb" => Some(Self::ChainBomb),
            "equivocating-chains-bomb" => Some(Self::EquivocatingChainsBomb),
            "random-drop" => Some(Self::RandomDrop),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct DagState {
    dag_state_inner: Arc<RwLock<DagStateInner>>,
    store: Arc<dyn Store>,
    metrics: Arc<Metrics>,
    pub(crate) consensus_protocol: ConsensusProtocol,
    pub(crate) committee_size: usize,
    pub(crate) byzantine_strategy: Option<ByzantineStrategy>,
    committee: Arc<Committee>,
    /// Version-gated cache of round block snapshots (outside the RwLock).
    round_block_cache: Arc<parking_lot::Mutex<RoundBlockCache>>,
    /// Immutable genesis blocks, one per authority. Cached for the lifetime
    /// of the node to prevent eviction.
    genesis: Vec<Data<VerifiedBlock>>,
    starfish_speed_adaptive_acknowledgments: bool,
}

type RoundBlockCache = AHashMap<RoundNumber, (u64, Arc<[Data<VerifiedBlock>]>)>;

/// Number of rounds to keep in memory per authority beyond the evicted
/// frontier. Must be >= 2 * MAX_TRAVERSAL_DEPTH to guarantee consensus
/// traversals can complete without storage fallback.
pub(crate) const CACHED_ROUNDS: RoundNumber = 2 * MAX_TRAVERSAL_DEPTH;

/// Per-authority DAG: round → (digest → (parents, known_by_bitmask)).
type DagAuthorityMap =
    BTreeMap<RoundNumber, HashMap<BlockDigest, (Vec<BlockReference>, AuthorityBitmask)>>;

#[derive(Default)]
struct StarfishSpeedLeaderRoundHints {
    voter_masks: AHashMap<AuthorityIndex, u128>,
    complaint_counts: Vec<u16>,
}

impl StarfishSpeedLeaderRoundHints {
    fn new(committee_size: usize) -> Self {
        Self {
            voter_masks: AHashMap::new(),
            complaint_counts: vec![0; committee_size],
        }
    }

    fn apply_mask_delta(&mut self, mask: u128, delta: i32) {
        for (authority, count) in self.complaint_counts.iter_mut().enumerate() {
            if mask & (1u128 << authority) == 0 {
                continue;
            }
            if delta > 0 {
                *count = count.saturating_add(delta as u16);
            } else {
                *count = count.saturating_sub((-delta) as u16);
            }
        }
    }

    fn update_vote(&mut self, voter: AuthorityIndex, mask: u128) {
        if let Some(previous_mask) = self.voter_masks.insert(voter, mask) {
            self.apply_mask_delta(previous_mask, -1);
        }
        self.apply_mask_delta(mask, 1);
    }
}

struct DagStateInner {
    store: Arc<dyn Store>,
    /// Per-authority block storage. Vec index = authority.
    index: Vec<BTreeMap<RoundNumber, HashMap<BlockDigest, Data<VerifiedBlock>>>>,
    /// Per-authority shard sidecar index. Vec index = authority.
    shard_index: Vec<BTreeMap<RoundNumber, HashMap<BlockDigest, ProvableShard>>>,
    /// Per-authority data availability tracking. Vec index = authority.
    data_availability: Vec<BTreeSet<BlockReference>>,
    // Blocks for which we have transaction data and still need to acknowledge.
    // Unsupported protocols leave this disabled entirely.
    pending_acknowledgment: Option<Vec<BlockReference>>,
    // Per-recipient index of our own blocks. Vec index = recipient authority.
    // Byzantine nodes may create different blocks for different validators.
    own_blocks: Vec<BTreeMap<RoundNumber, BlockDigest>>,
    highest_round: RoundNumber,
    authority: AuthorityIndex,
    committee_size: usize,
    last_seen_by_authority: Vec<RoundNumber>,
    last_own_block: Option<BlockReference>,
    /// Per-authority DAG metadata. Vec index = authority.
    dag: Vec<DagAuthorityMap>,
    /// Per-authority eviction frontier: highest round evicted for each
    /// authority.
    evicted_rounds: Vec<RoundNumber>,
    // Round of the latest committed leader whose sub-dag was fully sequenced
    // (all data available).
    last_available_commit: RoundNumber,
    // per-round version counter, incremented on each add_block to that round
    round_version: AHashMap<RoundNumber, u64>,
    // committed subdag which contains blocks with unresolved DAC certificates
    pending_not_certified: Vec<PendingSubDag>,
    // committed subdag which contains blocks with at least one unavailable transaction data
    pending_not_available: Vec<PendingSubDag>,
    /// Per-authority highest committed round. Used for populating CommitData
    /// and for windowed recovery on restart.
    last_committed_rounds: Vec<RoundNumber>,
    /// Threshold clock tracking quorum round advancement.
    threshold_clock: ThresholdClockAggregator,
    /// Verified BLS round certificates keyed by round (StarfishBls).
    round_certificates: BTreeMap<RoundNumber, BlsAggregateCertificate>,
    /// Leader references with confirmed BLS leader certificates (StarfishBls).
    /// Stored per-authority in round order so cleanup can `split_off()` at the
    /// eviction frontier instead of scanning the full certificate set.
    leader_certificates: Vec<BTreeMap<BlockReference, BlsAggregateCertificate>>,
    /// Block references with confirmed BLS DAC certificates (StarfishBls).
    /// Stored per-authority in round order for the same reason as leaders.
    dac_certificates: Vec<BTreeMap<BlockReference, BlsAggregateCertificate>>,
    /// Block references with DAC certificates that failed BLS verification.
    rejected_dac_certificates: Vec<BTreeSet<BlockReference>>,
    /// For StarfishSpeed, keep the recent complaint masks reported by voters
    /// about leader blocks, keyed by leader authority then leader round.
    starfish_speed_leader_hints: Vec<BTreeMap<RoundNumber, StarfishSpeedLeaderRoundHints>>,
    starfish_speed_adaptive_acknowledgments: bool,
    /// Protocol variant, needed to gate ack queueing on DAC certificates.
    consensus_protocol: ConsensusProtocol,
    /// Pre-computed BLS round partial signatures (StarfishBls). Keyed by the
    /// round the signature covers.
    precomputed_round_sigs: BTreeMap<RoundNumber, BlsSignatureBytes>,
    /// Pre-computed BLS leader partial signatures (StarfishBls). Keyed by the
    /// leader block reference the signature covers.
    precomputed_leader_sigs: BTreeMap<BlockReference, BlsSignatureBytes>,
}

impl DagState {
    pub fn open(
        authority: AuthorityIndex,
        path: impl AsRef<Path>,
        metrics: Arc<Metrics>,
        committee: Arc<Committee>,
        byzantine_strategy: String,
        consensus: String,
        storage_backend: &StorageBackend,
        starfish_speed_adaptive_acknowledgments: bool,
    ) -> RecoveredState {
        assert!(
            committee.len() <= 128,
            "Committee size {} exceeds AuthorityBitmask capacity (128)",
            committee.len()
        );
        let store: Arc<dyn Store> = match storage_backend {
            #[cfg(feature = "tidehunter")]
            StorageBackend::Tidehunter => {
                tracing::info!("Using TideHunter storage backend");
                metrics.storage_backend_info.set(1);
                Arc::new(
                    crate::tidehunter_store::TideHunterStore::open(&path)
                        .expect("Failed to open TideHunter"),
                )
            }
            #[cfg(not(feature = "tidehunter"))]
            StorageBackend::Tidehunter => {
                panic!("TideHunter storage requested but the `tidehunter` feature is not enabled");
            }
            StorageBackend::Rocksdb => {
                metrics.storage_backend_info.set(0);
                Arc::new(RocksStore::open(&path).expect("Failed to open RocksDB"))
            }
        };
        let consensus_protocol = ConsensusProtocol::from_str(&consensus);
        let last_seen_by_authority = committee.authorities().map(|_| 0).collect();
        let n = committee.len();
        let mut inner = DagStateInner {
            store: store.clone(),
            authority,
            last_seen_by_authority,
            last_available_commit: 0,
            committee_size: n,
            index: (0..n).map(|_| BTreeMap::new()).collect(),
            shard_index: (0..n).map(|_| BTreeMap::new()).collect(),
            data_availability: (0..n).map(|_| BTreeSet::new()).collect(),
            pending_acknowledgment: consensus_protocol.supports_acknowledgments().then(Vec::new),
            own_blocks: (0..n).map(|_| BTreeMap::new()).collect(),
            highest_round: 0,
            last_own_block: None,
            dag: (0..n).map(|_| BTreeMap::new()).collect(),
            evicted_rounds: vec![0; n],
            pending_not_certified: Vec::new(),
            pending_not_available: Vec::new(),
            round_version: AHashMap::new(),
            last_committed_rounds: vec![0; n],
            threshold_clock: ThresholdClockAggregator::new(0),
            round_certificates: BTreeMap::new(),
            leader_certificates: (0..n).map(|_| BTreeMap::new()).collect(),
            dac_certificates: (0..n).map(|_| BTreeMap::new()).collect(),
            rejected_dac_certificates: (0..n).map(|_| BTreeSet::new()).collect(),
            starfish_speed_leader_hints: (0..n).map(|_| BTreeMap::new()).collect(),
            starfish_speed_adaptive_acknowledgments,
            consensus_protocol,
            precomputed_round_sigs: BTreeMap::new(),
            precomputed_leader_sigs: BTreeMap::new(),
        };
        let mut builder = RecoveredStateBuilder::new();
        let replay_started = Instant::now();
        let mut block_count = 0u64;
        let mut bfs_buf = Vec::new();

        // Try windowed recovery: load only a bounded window around the last
        // committed frontier instead of replaying every round from 0.
        let last_commit = store
            .read_last_commit()
            .expect("Failed to read last commit from storage");

        let use_windowed = last_commit
            .as_ref()
            .map(|c| c.committed_rounds.len() == n)
            .unwrap_or(false);

        if use_windowed {
            let committed_rounds = &last_commit.as_ref().unwrap().committed_rounds;

            // Compute per-authority eviction rounds and the global scan start.
            for (i, &cr) in committed_rounds.iter().enumerate() {
                inner.evicted_rounds[i] = cr.saturating_sub(CACHED_ROUNDS);
                inner.last_committed_rounds[i] = cr;
            }
            let global_start = inner.evicted_rounds.iter().copied().min().unwrap_or(0);

            // Load blocks within the cached window.
            let blocks = store
                .scan_blocks_from_round(global_start)
                .expect("Failed to scan blocks from storage");

            for block in blocks {
                let block_ref = *block.reference();
                let auth = block_ref.authority as usize;

                // Skip blocks outside the authority's cached window.
                if block_ref.round <= inner.evicted_rounds[auth] {
                    continue;
                }

                // Recover shard sidecars.
                if let Some(shard) = store
                    .get_shard_data(&block_ref)
                    .expect("Failed to read shard data from storage")
                {
                    inner.shard_index[auth]
                        .entry(block_ref.round)
                        .or_default()
                        .insert(block_ref.digest, shard);
                }

                inner.threshold_clock.add_block(block_ref, &committee);
                builder.block(block_ref.round, block.clone());
                block_count += 1;
                inner.add_block(block, 0, committee.len() as AuthorityIndex, &mut bfs_buf);

                if let Some(commit_data) = store
                    .get_commit(&block_ref)
                    .expect("Failed to read commit data from storage")
                {
                    builder.commit(commit_data);
                }
            }

            tracing::info!(
                "authority={} windowed recovery from round {}: {} blocks",
                authority,
                global_start,
                block_count,
            );
        } else {
            // Fallback: full replay from round 0 (pre-migration data or fresh start).
            let mut recovered_commit_leaders = AHashSet::new();
            let mut current_round = 0;
            loop {
                let blocks = store
                    .get_blocks_by_round(current_round)
                    .expect("Failed to read blocks from storage");

                if blocks.is_empty() {
                    break;
                }

                for block in blocks {
                    let block_ref = *block.reference();

                    // Recover shard sidecars into the shard index.
                    if let Some(shard) = store
                        .get_shard_data(&block_ref)
                        .expect("Failed to read shard data from storage")
                    {
                        let auth = block_ref.authority as usize;
                        inner.shard_index[auth]
                            .entry(block_ref.round)
                            .or_default()
                            .insert(block_ref.digest, shard);
                    }

                    inner.threshold_clock.add_block(block_ref, &committee);
                    builder.block(current_round, block.clone());
                    block_count += 1;
                    inner.add_block(block, 0, committee.len() as AuthorityIndex, &mut bfs_buf);
                    if recovered_commit_leaders.insert(block_ref) {
                        if let Some(commit_data) = store
                            .get_commit(&block_ref)
                            .expect("Failed to read commit data from storage")
                        {
                            // Rebuild last_committed_rounds from committed blocks.
                            for r in &commit_data.sub_dag {
                                let auth = r.authority as usize;
                                inner.last_committed_rounds[auth] =
                                    inner.last_committed_rounds[auth].max(r.round);
                            }
                            builder.commit(commit_data);
                        }
                    }
                }

                current_round += 1;
            }
        }

        metrics.dag_state_entries.inc_by(block_count);
        metrics.dag_highest_round.set(inner.highest_round as i64);
        metrics
            .dag_lowest_round
            .set(inner.global_lowest_round() as i64);
        tracing::debug!(
            "authority={} storage replay: {} blocks in {:?}, highest_round={}",
            authority,
            block_count,
            replay_started.elapsed(),
            inner.highest_round
        );
        // Generate genesis blocks (one per authority).
        let genesis: Vec<Data<VerifiedBlock>> = committee
            .authorities()
            .map(VerifiedBlock::new_genesis)
            .collect();

        // On clean start (no blocks recovered), insert genesis into the DAG
        // and populate the threshold clock.
        if block_count == 0 {
            let committee_len = committee.len() as AuthorityIndex;
            for block in &genesis {
                inner
                    .threshold_clock
                    .add_block(*block.reference(), &committee);
                inner.add_block(block.clone(), 0, committee_len, &mut bfs_buf);
            }
        }

        let byzantine_strategy = ByzantineStrategy::from_strategy_str(byzantine_strategy.as_str());
        match &consensus_protocol {
            ConsensusProtocol::Mysticeti => tracing::info!("Starting Mysticeti protocol"),
            ConsensusProtocol::Starfish => tracing::info!("Starting Starfish protocol"),
            ConsensusProtocol::StarfishBls => tracing::info!("Starting Starfish-BLS protocol"),
            ConsensusProtocol::StarfishSpeed => tracing::info!("Starting Starfish-Speed protocol"),
            ConsensusProtocol::CordialMiners => tracing::info!("Starting Cordial Miners protocol"),
        }
        let dag_state = Self {
            store: store.clone(),
            byzantine_strategy,
            committee_size: committee.len(),
            committee,
            dag_state_inner: Arc::new(RwLock::new(inner)),
            metrics,
            consensus_protocol,
            round_block_cache: Arc::new(parking_lot::Mutex::new(AHashMap::new())),
            genesis,
            starfish_speed_adaptive_acknowledgments,
        };
        builder.build(store, dag_state)
    }

    /// Returns the cached genesis blocks (one per authority, round 0).
    pub fn genesis_blocks(&self) -> &[Data<VerifiedBlock>] {
        &self.genesis
    }

    /// Return the current quorum round from the threshold clock.
    pub fn threshold_clock_round(&self) -> RoundNumber {
        self.dag_state_inner.read().threshold_clock.get_round()
    }

    pub fn get_dag_sorted(&self) -> Vec<(BlockReference, Vec<BlockReference>, AuthorityBitmask)> {
        let inner = self.dag_state_inner.read();
        let mut result: Vec<_> = inner
            .dag
            .iter()
            .enumerate()
            .flat_map(|(auth_idx, auth_dag)| {
                auth_dag.iter().flat_map(move |(round, entries)| {
                    entries.iter().map(move |(digest, (parents, known_by))| {
                        (
                            BlockReference {
                                authority: auth_idx as AuthorityIndex,
                                round: *round,
                                digest: *digest,
                            },
                            parents.clone(),
                            *known_by,
                        )
                    })
                })
            })
            .collect();
        result.sort_by_key(|(r, _, _)| r.round);
        result
    }

    pub fn get_own_authority_index(&self) -> AuthorityIndex {
        self.dag_state_inner.read().authority
    }

    pub fn read_pending_not_certified(&self) -> Vec<PendingSubDag> {
        self.dag_state_inner.read().read_pending_not_certified()
    }

    pub fn update_pending_not_certified(&self, pending: Vec<PendingSubDag>) {
        self.dag_state_inner
            .write()
            .update_pending_not_certified(pending);
    }

    pub fn read_pending_unavailable(&self) -> Vec<PendingSubDag> {
        self.dag_state_inner.read().read_pending_unavailable()
    }

    pub fn update_pending_unavailable(&self, pending: Vec<PendingSubDag>) {
        self.dag_state_inner
            .write()
            .update_pending_unavailable(pending);
    }

    pub fn insert_block_bounds(
        &self,
        block: Data<VerifiedBlock>,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        self.metrics.dag_state_entries.inc();

        // Persist to storage — use component stores for header-only blocks
        // to avoid writing empty payloads, and store_block for full blocks.
        // Pre-serialized bytes (from preserialize()) are used when available.
        let store_start = std::time::Instant::now();
        if block.has_transaction_data() {
            self.store
                .store_block(block.clone())
                .expect("Failed to store block");
        } else {
            let header_bytes = block
                .serialized_header_bytes()
                .expect("header should be preserialized before entering core thread");
            self.store
                .store_header_bytes(block.reference(), header_bytes)
                .expect("Failed to store header");
        }
        self.metrics
            .store_block_latency_us
            .inc_by(store_start.elapsed().as_micros() as u64);
        self.metrics.store_block_count.inc();

        let (highest_round, lowest_round) = {
            let mut inner = self.dag_state_inner.write();
            // Keep threshold clock mutation co-located with DAG insertion so
            // runtime block acceptance and recovery use the same path.
            inner
                .threshold_clock
                .add_block(*block.reference(), &self.committee);
            let mut bfs_buf = Vec::new();
            inner.add_block(
                block,
                authority_index_start,
                authority_index_end,
                &mut bfs_buf,
            );
            (inner.highest_round, inner.global_lowest_round())
        };
        self.metrics.dag_highest_round.set(highest_round as i64);
        self.metrics.dag_lowest_round.set(lowest_round as i64);
    }

    pub fn insert_general_block(&self, block: Data<VerifiedBlock>) {
        let authority_index_start = 0;
        let authority_index_end = self.committee_size as AuthorityIndex;
        self.insert_block_bounds(block, authority_index_start, authority_index_end);
    }

    /// Batch-insert multiple blocks, persisting all to the store first, then
    /// acquiring the DAG write lock once for all in-memory mutations.
    pub fn insert_general_blocks(&self, blocks: Vec<Data<VerifiedBlock>>) {
        if blocks.is_empty() {
            return;
        }
        let authority_index_start = 0;
        let authority_index_end = self.committee_size as AuthorityIndex;

        // Phase 1: persist all blocks to the store batch (no DAG lock needed).
        for block in &blocks {
            let store_start = std::time::Instant::now();
            if block.has_transaction_data() {
                self.store
                    .store_block(block.clone())
                    .expect("Failed to store block");
            } else {
                let header_bytes = block
                    .serialized_header_bytes()
                    .expect("header should be preserialized before entering core thread");
                self.store
                    .store_header_bytes(block.reference(), header_bytes)
                    .expect("Failed to store header");
            }
            self.metrics
                .store_block_latency_us
                .inc_by(store_start.elapsed().as_micros() as u64);
            self.metrics.store_block_count.inc();
            self.metrics.dag_state_entries.inc();
        }

        // Phase 2: single write lock for all DAG mutations.
        let (highest_round, lowest_round) = {
            let mut inner = self.dag_state_inner.write();
            let mut bfs_buf = Vec::new();
            for block in blocks {
                inner
                    .threshold_clock
                    .add_block(*block.reference(), &self.committee);
                inner.add_block(
                    block,
                    authority_index_start,
                    authority_index_end,
                    &mut bfs_buf,
                );
            }
            (inner.highest_round, inner.global_lowest_round())
        };
        self.metrics.dag_highest_round.set(highest_round as i64);
        self.metrics.dag_lowest_round.set(lowest_round as i64);
    }

    // Insert own blocks is primarily needed to capture Byzantine behavior with
    // equivocating blocks
    pub fn insert_own_block(&self, own_block: OwnBlockData) {
        self.insert_block_bounds(
            own_block.block,
            own_block.authority_index_start,
            own_block.authority_index_end,
        );
    }

    pub fn get_storage_block(&self, reference: BlockReference) -> Option<Data<VerifiedBlock>> {
        self.dag_state_inner.read().get_storage_block(reference)
    }

    /// Look up the `transactions_commitment` for a block in the DAG.
    pub fn get_transactions_commitment(
        &self,
        reference: &BlockReference,
    ) -> Option<crate::crypto::TransactionsCommitment> {
        self.dag_state_inner
            .read()
            .get_storage_block(*reference)
            .map(|b| b.merkle_root())
    }

    /// Mark a round as having a confirmed BLS certificate.
    pub fn mark_round_certified(
        &self,
        round: RoundNumber,
        certificate: BlsAggregateCertificate,
    ) -> bool {
        self.dag_state_inner
            .write()
            .round_certificates
            .insert(round, certificate)
            .is_none()
    }

    /// Mark a leader block as having a confirmed BLS leader certificate.
    pub fn mark_leader_certified(
        &self,
        leader_ref: BlockReference,
        certificate: BlsAggregateCertificate,
    ) -> bool {
        self.dag_state_inner.write().leader_certificates[leader_ref.authority as usize]
            .insert(leader_ref, certificate)
            .is_none()
    }

    /// Mark a block as having a confirmed BLS DAC certificate.
    /// If data is already available, the acknowledgment is queued immediately.
    pub fn mark_dac_certified(
        &self,
        block_ref: BlockReference,
        certificate: BlsAggregateCertificate,
    ) -> bool {
        let mut inner = self.dag_state_inner.write();
        if inner.rejected_dac_certificates[block_ref.authority as usize].contains(&block_ref) {
            return false;
        }
        let is_new = inner.dac_certificates[block_ref.authority as usize]
            .insert(block_ref, certificate)
            .is_none();
        if is_new {
            tracing::debug!("Certified DAC for {}", block_ref);
            inner.maybe_queue_ack(block_ref);
        }
        is_new
    }

    /// Mark a block as carrying a DAC certificate that failed BLS verification.
    pub fn mark_dac_rejected(&self, block_ref: BlockReference) -> bool {
        let mut inner = self.dag_state_inner.write();
        if inner.dac_certificates[block_ref.authority as usize].contains_key(&block_ref) {
            return false;
        }
        let is_new =
            inner.rejected_dac_certificates[block_ref.authority as usize].insert(block_ref);
        if is_new {
            tracing::debug!("Rejected DAC for {}", block_ref);
        }
        is_new
    }

    /// Apply a batch of BLS certificate events while holding the DAG write
    /// lock once.
    pub fn apply_certificate_events(
        &self,
        events: Vec<crate::bls_certificate_aggregator::CertificateEvent>,
    ) -> bool {
        use crate::bls_certificate_aggregator::CertificateEvent;

        let mut inner = self.dag_state_inner.write();
        let mut changed = false;
        for event in events {
            match event {
                CertificateEvent::Round(round, certificate) => {
                    changed |= inner
                        .round_certificates
                        .insert(round, certificate)
                        .is_none();
                }
                CertificateEvent::Leader(leader_ref, certificate) => {
                    changed |= inner.leader_certificates[leader_ref.authority as usize]
                        .insert(leader_ref, certificate)
                        .is_none();
                }
                CertificateEvent::Dac(block_ref, certificate) => {
                    if inner.rejected_dac_certificates[block_ref.authority as usize]
                        .contains(&block_ref)
                    {
                        continue;
                    }
                    let is_new = inner.dac_certificates[block_ref.authority as usize]
                        .insert(block_ref, certificate)
                        .is_none();
                    if is_new {
                        tracing::debug!("Certified DAC for {}", block_ref);
                        inner.maybe_queue_ack(block_ref);
                    }
                    changed |= is_new;
                }
                CertificateEvent::DacRejected(block_ref) => {
                    if inner.dac_certificates[block_ref.authority as usize].contains_key(&block_ref)
                    {
                        continue;
                    }
                    let is_new = inner.rejected_dac_certificates[block_ref.authority as usize]
                        .insert(block_ref);
                    if is_new {
                        tracing::debug!("Rejected DAC for {}", block_ref);
                    }
                    changed |= is_new;
                }
                CertificateEvent::PrecomputedRoundSig(round, sig) => {
                    inner.precomputed_round_sigs.insert(round, sig);
                }
                CertificateEvent::PrecomputedLeaderSig(leader_ref, sig) => {
                    inner.precomputed_leader_sigs.insert(leader_ref, sig);
                }
            }
        }
        changed
    }

    /// Check whether the given round has a confirmed BLS certificate.
    pub fn has_round_certificate(&self, round: RoundNumber) -> bool {
        self.dag_state_inner
            .read()
            .round_certificates
            .contains_key(&round)
    }

    /// Retrieve the confirmed BLS round certificate, if any.
    pub fn round_certificate(&self, round: RoundNumber) -> Option<BlsAggregateCertificate> {
        self.dag_state_inner
            .read()
            .round_certificates
            .get(&round)
            .copied()
    }

    /// Check whether the given leader has a confirmed BLS leader certificate.
    pub fn has_leader_certificate(&self, leader_ref: &BlockReference) -> bool {
        self.dag_state_inner.read().leader_certificates[leader_ref.authority as usize]
            .contains_key(leader_ref)
    }

    /// Retrieve the confirmed BLS leader certificate, if any.
    pub fn leader_certificate(
        &self,
        leader_ref: &BlockReference,
    ) -> Option<BlsAggregateCertificate> {
        self.dag_state_inner.read().leader_certificates[leader_ref.authority as usize]
            .get(leader_ref)
            .copied()
    }

    /// Check whether the given block has a confirmed BLS DAC certificate.
    pub fn has_dac_certificate(&self, block_ref: &BlockReference) -> bool {
        self.dag_state_inner.read().dac_certificates[block_ref.authority as usize]
            .contains_key(block_ref)
    }

    pub fn has_rejected_dac_certificate(&self, block_ref: &BlockReference) -> bool {
        self.dag_state_inner.read().rejected_dac_certificates[block_ref.authority as usize]
            .contains(block_ref)
    }

    pub fn dac_certificate_state(
        &self,
        block_ref: &BlockReference,
    ) -> DacCertificateVerificationState {
        let inner = self.dag_state_inner.read();
        if inner.rejected_dac_certificates[block_ref.authority as usize].contains(block_ref) {
            DacCertificateVerificationState::Rejected
        } else if inner.dac_certificates[block_ref.authority as usize].contains_key(block_ref) {
            DacCertificateVerificationState::Verified
        } else {
            DacCertificateVerificationState::Unchecked
        }
    }

    /// Retrieve the confirmed BLS DAC certificate, if any.
    pub fn dac_certificate(&self, block_ref: &BlockReference) -> Option<BlsAggregateCertificate> {
        self.dag_state_inner.read().dac_certificates[block_ref.authority as usize]
            .get(block_ref)
            .copied()
    }

    /// Store a pre-computed BLS round partial signature.
    pub fn store_precomputed_round_sig(&self, round: RoundNumber, sig: BlsSignatureBytes) {
        self.dag_state_inner
            .write()
            .precomputed_round_sigs
            .insert(round, sig);
    }

    /// Store a pre-computed BLS leader partial signature.
    pub fn store_precomputed_leader_sig(&self, leader_ref: BlockReference, sig: BlsSignatureBytes) {
        self.dag_state_inner
            .write()
            .precomputed_leader_sigs
            .insert(leader_ref, sig);
    }

    /// Take (remove) a pre-computed BLS round partial signature, if available.
    pub fn take_precomputed_round_sig(&self, round: RoundNumber) -> Option<BlsSignatureBytes> {
        self.dag_state_inner
            .write()
            .precomputed_round_sigs
            .remove(&round)
    }

    /// Take (remove) a pre-computed BLS leader partial signature, if available.
    pub fn take_precomputed_leader_sig(
        &self,
        leader_ref: &BlockReference,
    ) -> Option<BlsSignatureBytes> {
        self.dag_state_inner
            .write()
            .precomputed_leader_sigs
            .remove(leader_ref)
    }

    pub fn get_transmission_block(&self, reference: BlockReference) -> Option<Data<VerifiedBlock>> {
        self.dag_state_inner
            .read()
            .get_transmission_block(reference)
    }

    pub fn get_pending_acknowledgment(&self, round_number: RoundNumber) -> Vec<BlockReference> {
        self.dag_state_inner
            .write()
            .get_pending_acknowledgment(round_number)
    }

    pub fn requeue_pending_acknowledgment(&self, block_refs: Vec<BlockReference>) {
        self.dag_state_inner
            .write()
            .requeue_pending_acknowledgment(block_refs);
    }

    pub fn get_blocks_by_round(&self, round: RoundNumber) -> Vec<Data<VerifiedBlock>> {
        self.dag_state_inner.read().get_blocks_by_round(round)
    }

    /// Version-gated cached variant of `get_blocks_by_round`.
    /// Returns `Arc<[T]>` to avoid repeated Vec allocations for the same round.
    pub fn get_blocks_by_round_cached(&self, round: RoundNumber) -> Arc<[Data<VerifiedBlock>]> {
        let inner = self.dag_state_inner.read();
        let version = inner.round_version.get(&round).copied().unwrap_or(0);
        {
            let cache = self.round_block_cache.lock();
            if let Some((ver, blocks)) = cache.get(&round) {
                if *ver == version {
                    return blocks.clone();
                }
            }
        }
        let blocks: Arc<[_]> = inner.get_blocks_by_round(round).into();
        self.round_block_cache
            .lock()
            .insert(round, (version, blocks.clone()));
        blocks
    }

    pub fn get_blocks_at_authority_round(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Vec<Data<VerifiedBlock>> {
        self.dag_state_inner
            .read()
            .get_blocks_at_authority_round(authority, round)
    }

    pub fn block_exists_at_authority_round(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> bool {
        !self
            .dag_state_inner
            .read()
            .get_blocks_at_authority_round(authority, round)
            .is_empty()
    }

    pub fn all_blocks_exists_at_authority_round(
        &self,
        authorities: &[AuthorityIndex],
        round: RoundNumber,
    ) -> bool {
        let inner = self.dag_state_inner.read();
        let blocks = inner.get_blocks_by_round(round);
        if blocks.is_empty() {
            return false;
        }
        authorities
            .iter()
            .all(|auth| blocks.iter().any(|b| b.authority() == *auth))
    }

    pub fn has_block_quorum_at_round(&self, round: RoundNumber, committee: &Committee) -> bool {
        let inner = self.dag_state_inner.read();
        let blocks = inner.get_blocks_by_round(round);
        let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
        for block in &blocks {
            if aggregator.add(block.authority(), committee) {
                return true;
            }
        }
        false
    }

    /// Check if a quorum of blocks at `round` include the leader
    /// from `leader_round` in their references.
    pub fn has_votes_quorum_at_round(
        &self,
        round: RoundNumber,
        leader: AuthorityIndex,
        leader_round: RoundNumber,
        committee: &Committee,
    ) -> bool {
        let inner = self.dag_state_inner.read();
        let blocks = inner.get_blocks_by_round(round);
        let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
        for block in &blocks {
            let votes_for_leader = if self.consensus_protocol == ConsensusProtocol::StarfishBls {
                block
                    .header()
                    .voted_leader()
                    .is_some_and(|(leader_ref, _)| {
                        leader_ref.authority == leader && leader_ref.round == leader_round
                    })
            } else {
                block
                    .block_references()
                    .iter()
                    .any(|r| r.authority == leader && r.round == leader_round)
            };
            if votes_for_leader && aggregator.add(block.authority(), committee) {
                return true;
            }
        }
        false
    }

    /// Check if a quorum of blocks at `round` carry a StarfishSpeed strong
    /// vote.
    pub fn has_strong_votes_quorum_at_round(
        &self,
        round: RoundNumber,
        committee: &Committee,
    ) -> bool {
        let inner = self.dag_state_inner.read();
        let blocks = inner.get_blocks_by_round(round);
        let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
        for block in &blocks {
            if block.is_strong_vote() && aggregator.add(block.authority(), committee) {
                return true;
            }
        }
        false
    }

    /// Batched readiness check used by block creation to avoid repeatedly
    /// cloning the same round view under separate DAG read locks.
    pub fn is_ready_for_new_block(
        &self,
        quorum_round: RoundNumber,
        leaders: &[AuthorityIndex],
        relaxed: bool,
        authority: AuthorityIndex,
        committee: &Committee,
    ) -> bool {
        let inner = self.dag_state_inner.read();
        let leader_round = quorum_round - 1;
        let blocks = inner.get_blocks_by_round(leader_round);
        if blocks.is_empty() {
            return false;
        }
        if !leaders
            .iter()
            .all(|leader| blocks.iter().any(|block| block.authority() == *leader))
        {
            return false;
        }

        if leader_round >= 2 {
            let prev_leader = committee.elect_leader(leader_round - 1);
            let mut votes = StakeAggregator::<QuorumThreshold>::new();
            let mut strong_votes = StakeAggregator::<QuorumThreshold>::new();
            let count_strong_votes =
                !relaxed && self.consensus_protocol == ConsensusProtocol::StarfishSpeed;

            for block in &blocks {
                let votes_for_leader = if self.consensus_protocol == ConsensusProtocol::StarfishBls
                {
                    block
                        .header()
                        .voted_leader()
                        .is_some_and(|(leader_ref, _)| {
                            leader_ref.authority == prev_leader
                                && leader_ref.round == leader_round - 1
                        })
                } else {
                    block.block_references().iter().any(|reference| {
                        reference.authority == prev_leader && reference.round == leader_round - 1
                    })
                };
                if votes_for_leader {
                    votes.add(block.authority(), committee);
                }
                if count_strong_votes && block.is_strong_vote() {
                    strong_votes.add(block.authority(), committee);
                }
            }

            if !votes.is_quorum(committee) {
                return false;
            }
            if count_strong_votes && !strong_votes.is_quorum(committee) {
                return false;
            }
        }

        if self.consensus_protocol == ConsensusProtocol::StarfishBls {
            let prev_round = quorum_round.saturating_sub(1);
            if prev_round > 0 && !inner.round_certificates.contains_key(&prev_round) {
                return false;
            }
            if prev_round > 0 && committee.elect_leader(quorum_round) == authority {
                let mut block_votes = StakeAggregator::<QuorumThreshold>::new();
                for block in &blocks {
                    if block_votes.add(block.authority(), committee) {
                        break;
                    }
                }
                if !block_votes.is_quorum(committee) {
                    return false;
                }
            }
        }

        true
    }

    pub fn starfish_speed_excluded_ack_authorities(&self) -> u128 {
        if self.consensus_protocol != ConsensusProtocol::StarfishSpeed
            || !self.starfish_speed_adaptive_acknowledgments
        {
            return 0;
        }

        let inner = self.dag_state_inner.read();
        let mut scores = vec![0usize; self.committee.len()];
        for hints in inner.starfish_speed_leader_hints[inner.authority as usize]
            .iter()
            .rev()
            .take(STARFISH_SPEED_HINT_WINDOW_LEADER_ROUNDS)
            .map(|(_, hints)| hints)
        {
            for (authority, score) in scores.iter_mut().enumerate() {
                *score += hints.complaint_counts[authority] as usize;
            }
        }

        let blame_threshold = self.committee.validity_threshold() as usize;
        scores
            .into_iter()
            .enumerate()
            .filter(|(_, score)| *score >= blame_threshold)
            .fold(0u128, |mask, (authority, _)| mask | (1u128 << authority))
    }

    pub fn block_exists(&self, reference: BlockReference) -> bool {
        self.dag_state_inner.read().block_exists(reference)
    }

    /// A peer reports it has only synced up to `round`.
    /// Clear its known-by bit for newer blocks so they become eligible for
    /// re-dissemination.
    pub fn reset_peer_known_by_after_round(&self, peer: AuthorityIndex, round: RoundNumber) {
        self.dag_state_inner
            .write()
            .reset_peer_known_by_after_round(peer, round);
    }

    pub fn is_data_available(&self, reference: &BlockReference) -> bool {
        self.dag_state_inner.read().is_data_available(reference)
    }

    pub fn shard_count(&self, block_reference: &BlockReference) -> usize {
        self.dag_state_inner.read().shard_count(block_reference)
    }

    fn get_blocks_with_store_fallback(
        &self,
        refs: &[BlockReference],
    ) -> Vec<Option<Data<VerifiedBlock>>> {
        let mut blocks = vec![None; refs.len()];
        let mut missing_refs = Vec::new();
        let mut missing_indices = Vec::new();

        {
            let inner = self.dag_state_inner.read();
            for (index, reference) in refs.iter().enumerate() {
                if let Some(block) = inner.get_block(*reference) {
                    blocks[index] = Some(block);
                } else {
                    missing_refs.push(*reference);
                    missing_indices.push(index);
                }
            }
        }

        if !missing_refs.is_empty() {
            let fetched = self
                .store
                .get_blocks(&missing_refs)
                .expect("Storage batch read failed");
            for (index, block) in missing_indices.into_iter().zip(fetched) {
                blocks[index] = block;
            }
        }

        blocks
    }

    /// Batch variant of `get_storage_block` — single read lock for N lookups.
    pub fn get_storage_blocks(&self, refs: &[BlockReference]) -> Vec<Option<Data<VerifiedBlock>>> {
        self.get_blocks_with_store_fallback(refs)
    }

    /// Batch variant of `get_transmission_block` — single read lock for N
    /// lookups.
    pub fn get_transmission_blocks(
        &self,
        refs: &[BlockReference],
    ) -> Vec<Option<Data<VerifiedBlock>>> {
        self.get_blocks_with_store_fallback(refs)
    }

    /// Fetch blocks as header-only for the given references.
    pub fn get_header_only_blocks(&self, refs: &[BlockReference]) -> Vec<Data<VerifiedBlock>> {
        self.get_transmission_parts(refs, &[]).0
    }

    /// Fetch shard payloads for the given references from the shard sidecar
    /// index, with store fallback.
    pub fn get_shard_payloads(&self, refs: &[BlockReference]) -> Vec<ShardPayload> {
        self.get_transmission_parts(&[], refs).1
    }

    /// Fetch header-only blocks and shard payloads together to avoid repeated
    /// per-reference storage lookups on dissemination paths.
    pub fn get_transmission_parts(
        &self,
        header_refs: &[BlockReference],
        shard_refs: &[BlockReference],
    ) -> (Vec<Data<VerifiedBlock>>, Vec<ShardPayload>) {
        let mut header_slots = vec![None; header_refs.len()];
        let mut missing_header_refs = Vec::new();
        let mut missing_header_indices = Vec::new();

        let mut shard_slots = vec![None; shard_refs.len()];
        let mut missing_shard_refs = Vec::new();
        let mut missing_shard_indices = Vec::new();

        {
            let inner = self.dag_state_inner.read();

            for (index, reference) in header_refs.iter().enumerate() {
                if let Some(block) = inner.get_block(*reference) {
                    header_slots[index] = Some(Data::new(block.as_header_only()));
                } else {
                    missing_header_refs.push(*reference);
                    missing_header_indices.push(index);
                }
            }

            for (index, reference) in shard_refs.iter().enumerate() {
                let auth = reference.authority as usize;
                if let Some(shard) = inner.shard_index[auth]
                    .get(&reference.round)
                    .and_then(|m| m.get(&reference.digest))
                {
                    shard_slots[index] = Some(shard.clone());
                } else {
                    missing_shard_refs.push(*reference);
                    missing_shard_indices.push(index);
                }
            }
        }

        if !missing_header_refs.is_empty() {
            let fetched = self
                .store
                .get_blocks(&missing_header_refs)
                .expect("Storage batch read failed");
            for (index, block) in missing_header_indices.into_iter().zip(fetched) {
                header_slots[index] = block.map(|block| Data::new(block.as_header_only()));
            }
        }

        if !missing_shard_refs.is_empty() {
            let fetched = self
                .store
                .get_shard_data_batch(&missing_shard_refs)
                .expect("Failed to read shard batch from store");
            for (index, shard) in missing_shard_indices.into_iter().zip(fetched) {
                shard_slots[index] = shard;
            }
        }

        let headers = header_slots.into_iter().flatten().collect();
        let shards = shard_refs
            .iter()
            .copied()
            .zip(shard_slots)
            .filter_map(|(block_reference, shard)| {
                shard.map(|shard| ShardPayload {
                    block_reference,
                    shard,
                })
            })
            .collect();

        (headers, shards)
    }

    /// Insert a shard into the sidecar index and persist to store.
    /// Pre-serializes the shard internally.
    pub fn insert_shard(&self, block_ref: BlockReference, mut shard: ProvableShard) {
        shard.preserialize();
        let shard_bytes = shard
            .serialized_bytes()
            .expect("shard should be preserialized");
        self.store
            .store_shard_data_bytes(&block_ref, shard_bytes)
            .expect("Failed to store shard data");

        let mut inner = self.dag_state_inner.write();
        let auth = block_ref.authority as usize;
        inner.shard_index[auth]
            .entry(block_ref.round)
            .or_default()
            .insert(block_ref.digest, shard);
    }

    /// Batch-insert shard sidecars, persisting all bytes first and then
    /// updating the in-memory index under one DAG write lock.
    pub fn insert_shards_batch(&self, shards: Vec<(BlockReference, ProvableShard)>) {
        if shards.is_empty() {
            return;
        }

        let mut prepared = Vec::with_capacity(shards.len());
        for (block_ref, mut shard) in shards {
            shard.preserialize();
            let shard_bytes = shard
                .serialized_bytes()
                .expect("shard should be preserialized");
            self.store
                .store_shard_data_bytes(&block_ref, shard_bytes)
                .expect("Failed to store shard data");
            prepared.push((block_ref, shard));
        }

        let mut inner = self.dag_state_inner.write();
        for (block_ref, shard) in prepared {
            let auth = block_ref.authority as usize;
            inner.shard_index[auth]
                .entry(block_ref.round)
                .or_default()
                .insert(block_ref.digest, shard);
        }
    }

    /// Check whether the shard index contains a shard for this block.
    pub fn has_shard(&self, block_ref: &BlockReference) -> bool {
        let inner = self.dag_state_inner.read();
        let auth = block_ref.authority as usize;
        inner.shard_index[auth]
            .get(&block_ref.round)
            .is_some_and(|m| m.contains_key(&block_ref.digest))
    }

    /// Retrieve a shard from the in-memory index, falling back to store.
    pub fn get_shard(&self, block_ref: &BlockReference) -> Option<ProvableShard> {
        let inner = self.dag_state_inner.read();
        let auth = block_ref.authority as usize;
        if let Some(shard) = inner.shard_index[auth]
            .get(&block_ref.round)
            .and_then(|m| m.get(&block_ref.digest))
        {
            return Some(shard.clone());
        }
        drop(inner);
        self.store
            .get_shard_data(block_ref)
            .expect("Failed to read shard data from store")
    }

    /// Batch variant of `is_data_available` — single read lock for N lookups.
    pub fn are_data_available(&self, refs: &[BlockReference]) -> Vec<bool> {
        let inner = self.dag_state_inner.read();
        refs.iter().map(|r| inner.is_data_available(r)).collect()
    }

    pub fn contains_new_transactions(&self, block: &VerifiedBlock) -> bool {
        self.dag_state_inner.read().contains_new_transactions(block)
    }

    /// Attach recovered transaction data to an existing header-only block.
    /// Bypasses the block manager — the header is already accepted and
    /// connected. Components must carry pre-serialized bytes (via
    /// `preserialize()`).
    pub fn attach_transaction_data(
        &self,
        block_ref: BlockReference,
        transaction_data: &TransactionData,
        shard_data: &ProvableShard,
    ) -> bool {
        let auth = block_ref.authority as usize;

        // Phase 1: read lock — check block existence and get header.
        let header = {
            let inner = self.dag_state_inner.read();
            let existing = inner.index[auth]
                .get(&block_ref.round)
                .and_then(|m| m.get(&block_ref.digest));
            match existing {
                Some(b) if b.has_transaction_data() => return true,
                Some(b) => b.header().clone(),
                None => return false,
            }
        };

        // Phase 2: store writes outside any DAG lock.
        let tx_bytes = transaction_data
            .serialized_bytes()
            .expect("tx_data should be preserialized before attach");
        self.store
            .store_tx_data_bytes(&block_ref, tx_bytes)
            .expect("Failed to store transaction data");
        let shard_bytes = shard_data
            .serialized_bytes()
            .expect("shard_data should be preserialized before attach");
        self.store
            .store_shard_data_bytes(&block_ref, shard_bytes)
            .expect("Failed to store shard data");

        // Phase 3: write lock — update in-memory indexes only.
        let mut inner = self.dag_state_inner.write();

        // Re-check under write lock: another thread may have attached data
        // between our read lock release and write lock acquisition.
        if inner.index[auth]
            .get(&block_ref.round)
            .and_then(|m| m.get(&block_ref.digest))
            .is_some_and(|b| b.has_transaction_data())
        {
            return true;
        }
        // Block may have been evicted between phase 1 and phase 3.
        // Treat this as a terminal success: bytes are already persisted and
        // there is no in-memory block left to mutate.
        if !inner.index[auth]
            .get(&block_ref.round)
            .is_some_and(|m| m.contains_key(&block_ref.digest))
        {
            return true;
        }

        // Shard goes to the sidecar index, not into the block.
        inner.shard_index[auth]
            .entry(block_ref.round)
            .or_default()
            .insert(block_ref.digest, shard_data.clone());

        // Rebuild the in-memory block with tx only (shard is in shard_index).
        let updated = Data::new(VerifiedBlock::from_parts(
            header,
            Some(transaction_data.clone()),
        ));

        // Replace in index (short-lived mutable borrow).
        if let Some(round_map) = inner.index[auth].get_mut(&block_ref.round) {
            round_map.insert(block_ref.digest, updated);
        } else {
            return true;
        }

        // Mark data-available + conditionally queue acknowledgment.
        if !inner.data_availability[auth].contains(&block_ref) {
            inner.data_availability[auth].insert(block_ref);
            inner.maybe_queue_ack(block_ref);
        }
        *inner.round_version.entry(block_ref.round).or_insert(0) += 1;
        true
    }

    /// Attach a shard to the sidecar index for an existing DAG block.
    /// Pre-serializes the shard internally. Returns true if the shard was
    /// attached (or was already present), false if the block doesn't exist.
    pub fn attach_shard_data(&self, block_ref: BlockReference, shard_data: &ProvableShard) -> bool {
        let auth = block_ref.authority as usize;

        // Phase 1: read lock — check block and shard existence.
        {
            let inner = self.dag_state_inner.read();
            let exists = inner.index[auth]
                .get(&block_ref.round)
                .is_some_and(|m| m.contains_key(&block_ref.digest));
            if !exists {
                return false;
            }
            if inner.shard_index[auth]
                .get(&block_ref.round)
                .is_some_and(|m| m.contains_key(&block_ref.digest))
            {
                return true;
            }
        }

        // Phase 2: store write outside any DAG lock.
        let mut shard = shard_data.clone();
        shard.preserialize();
        let shard_bytes = shard
            .serialized_bytes()
            .expect("shard should be preserialized");
        self.store
            .store_shard_data_bytes(&block_ref, shard_bytes)
            .expect("Failed to store shard data");

        // Phase 3: write lock — update in-memory shard index only.
        let mut inner = self.dag_state_inner.write();
        // Block may have been evicted between phase 1 and phase 3.
        // Treat this as success: shard bytes are already persisted.
        if !inner.index[auth]
            .get(&block_ref.round)
            .is_some_and(|m| m.contains_key(&block_ref.digest))
        {
            return true;
        }
        // Another thread may have inserted shard data while we were writing to storage.
        if inner.shard_index[auth]
            .get(&block_ref.round)
            .is_some_and(|m| m.contains_key(&block_ref.digest))
        {
            return true;
        }
        inner.shard_index[auth]
            .entry(block_ref.round)
            .or_default()
            .insert(block_ref.digest, shard);
        true
    }

    pub fn len_expensive(&self) -> usize {
        let inner = self.dag_state_inner.read();
        inner
            .index
            .iter()
            .flat_map(|auth_map| auth_map.values())
            .map(HashMap::len)
            .sum()
    }

    pub fn highest_round(&self) -> RoundNumber {
        self.dag_state_inner.read().highest_round
    }

    /// Version counter for a round, incremented each time a block is added at
    /// that round. Used as cache invalidation key.
    pub fn round_version(&self, round: RoundNumber) -> u64 {
        self.dag_state_inner
            .read()
            .round_version
            .get(&round)
            .copied()
            .unwrap_or(0)
    }

    pub fn lowest_round(&self) -> RoundNumber {
        self.dag_state_inner.read().global_lowest_round()
    }

    pub fn update_last_available_commit(&self, round: RoundNumber) {
        let mut inner = self.dag_state_inner.write();
        inner.last_available_commit = inner.last_available_commit.max(round);
    }

    pub fn last_available_commit(&self) -> RoundNumber {
        self.dag_state_inner.read().last_available_commit
    }

    /// Update commit-related metadata under one write lock and return the new
    /// per-authority committed-round snapshot.
    pub fn update_commit_state(&self, commit: &CommittedSubDag) -> Vec<RoundNumber> {
        let mut inner = self.dag_state_inner.write();
        inner.last_available_commit = inner.last_available_commit.max(commit.anchor.round);
        for block in &commit.blocks {
            let auth = block.authority() as usize;
            inner.last_committed_rounds[auth] =
                inner.last_committed_rounds[auth].max(block.round());
        }
        inner.last_committed_rounds.clone()
    }

    /// Update last_committed_rounds for all authorities in a committed subdag.
    pub fn update_last_committed_rounds(&self, commit: &CommittedSubDag) {
        let mut inner = self.dag_state_inner.write();
        for block in &commit.blocks {
            let auth = block.authority() as usize;
            inner.last_committed_rounds[auth] =
                inner.last_committed_rounds[auth].max(block.round());
        }
    }

    /// Returns a snapshot of the per-authority last committed rounds.
    pub fn last_committed_rounds(&self) -> Vec<RoundNumber> {
        self.dag_state_inner.read().last_committed_rounds.clone()
    }

    pub fn cleanup(&self) {
        let _timer = self.metrics.dag_state_cleanup_util.utilization_timer();

        let (highest_round, lowest_round, block_count, max_evicted) = {
            let mut inner = self.dag_state_inner.write();
            inner.evict_per_authority();
            inner.prune_certificate_state();
            (
                inner.highest_round,
                inner.global_lowest_round(),
                inner
                    .index
                    .iter()
                    .flat_map(|m| m.values())
                    .map(|h| h.len() as i64)
                    .sum::<i64>(),
                inner.evicted_rounds.iter().copied().max().unwrap_or(0),
            )
        };

        // Invalidate cache below max evicted round (any partially-evicted round
        // is stale).
        self.round_block_cache
            .lock()
            .retain(|&r, _| r >= max_evicted);
        self.metrics.dag_highest_round.set(highest_round as i64);
        self.metrics.dag_lowest_round.set(lowest_round as i64);
        self.metrics.dag_blocks_in_memory.set(block_count);
    }

    pub fn get_own_transmission_blocks(
        &self,
        to_whom_authority_index: AuthorityIndex,
        from_excluded: RoundNumber,
        limit: usize,
    ) -> Vec<Data<VerifiedBlock>> {
        let inner = self.dag_state_inner.read();
        let references =
            inner.get_own_block_references(to_whom_authority_index, from_excluded, limit);
        references
            .into_iter()
            .filter_map(|reference| inner.get_transmission_block(reference))
            .collect()
    }

    pub fn get_unsent_own_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_own_block_size: usize,
    ) -> Vec<Data<VerifiedBlock>> {
        self.dag_state_inner
            .read()
            .get_unsent_own_blocks(sent, peer, batch_own_block_size)
    }

    /// Keep only block references whose headers are not already implied as
    /// known by `peer` via the DAG's `known_by` bitmask. References missing
    /// from the in-memory DAG are retained, since we cannot prove they are
    /// redundant.
    pub fn filter_block_refs_unknown_to_peer(
        &self,
        refs: &[BlockReference],
        peer: AuthorityIndex,
        limit: usize,
    ) -> Vec<BlockReference> {
        self.dag_state_inner
            .read()
            .filter_block_refs_unknown_to_peer(refs, peer, limit)
    }

    pub fn get_unsent_other_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_other_block_size: usize,
        max_round_own_blocks: Option<RoundNumber>,
    ) -> Vec<Data<VerifiedBlock>> {
        self.dag_state_inner.read().get_unsent_other_blocks(
            sent,
            peer,
            batch_other_block_size,
            max_round_own_blocks,
        )
    }

    pub fn get_unsent_causal_history(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
        authorities_with_missing_blocks: AHashSet<AuthorityIndex>,
    ) -> Vec<Data<VerifiedBlock>> {
        self.dag_state_inner.read().get_unsent_causal_history(
            sent,
            peer,
            batch_own_block_size,
            batch_other_block_size,
            authorities_with_missing_blocks,
        )
    }

    pub fn get_unsent_past_cone(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        block_reference: BlockReference,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
    ) -> Vec<Data<VerifiedBlock>> {
        self.dag_state_inner.read().get_unsent_past_cone(
            sent,
            peer,
            block_reference,
            batch_own_block_size,
            batch_other_block_size,
        )
    }

    pub fn last_seen_by_authority(&self, authority: AuthorityIndex) -> RoundNumber {
        self.dag_state_inner
            .read()
            .last_seen_by_authority(authority)
    }

    pub fn min_last_seen_round(&self) -> RoundNumber {
        self.dag_state_inner.read().min_last_seen_round()
    }

    /// Conservative global GC round (minimum across all authorities).
    /// Used by external callers that need a single safe threshold.
    pub fn gc_round(&self) -> RoundNumber {
        self.dag_state_inner.read().min_evicted_round()
    }

    /// Per-authority eviction rounds for fine-grained cleanup.
    pub fn evicted_rounds(&self) -> Vec<RoundNumber> {
        self.dag_state_inner.read().evicted_rounds.clone()
    }

    pub fn last_own_block_ref(&self) -> Option<BlockReference> {
        self.dag_state_inner.read().last_own_block()
    }

    /// Check whether `earlier_block` is an ancestor of `later_block`.
    pub fn linked(
        &self,
        later_block: &Data<VerifiedBlock>,
        earlier_block: &Data<VerifiedBlock>,
    ) -> bool {
        self.dag_state_inner
            .read()
            .linked(later_block, earlier_block)
    }

    /// Compute all block references reachable from `later_block` at
    /// `target_round`. Single BFS traversal replaces N separate `linked()`
    /// calls for the same anchor.
    pub fn reachable_at_round(
        &self,
        later_block: &Data<VerifiedBlock>,
        target_round: RoundNumber,
    ) -> AHashSet<BlockReference> {
        self.dag_state_inner
            .read()
            .reachable_at_round(later_block, target_round)
    }
}

impl DagStateInner {
    fn global_lowest_round(&self) -> RoundNumber {
        self.dag
            .iter()
            .filter_map(|m| m.keys().next().copied())
            .min()
            .unwrap_or(0)
    }

    fn min_evicted_round(&self) -> RoundNumber {
        self.evicted_rounds.iter().copied().min().unwrap_or(0)
    }

    pub fn block_exists(&self, reference: BlockReference) -> bool {
        let auth = reference.authority as usize;
        if let Some(blocks) = self.index[auth].get(&reference.round) {
            if blocks.contains_key(&reference.digest) {
                return true;
            }
        }
        // Storage fallback for evicted blocks
        self.store
            .get_block(&reference)
            .expect("Storage read failed")
            .is_some()
    }

    pub fn is_data_available(&self, reference: &BlockReference) -> bool {
        self.data_availability[reference.authority as usize].contains(reference)
    }

    pub fn shard_count(&self, block_reference: &BlockReference) -> usize {
        if self.data_availability[block_reference.authority as usize].contains(block_reference) {
            return self.committee_size;
        }
        0
    }

    pub fn read_pending_not_certified(&self) -> Vec<PendingSubDag> {
        self.pending_not_certified.clone()
    }

    pub fn update_pending_not_certified(&mut self, pending: Vec<PendingSubDag>) {
        self.pending_not_certified = pending;
    }

    pub fn read_pending_unavailable(&self) -> Vec<PendingSubDag> {
        self.pending_not_available.clone()
    }

    pub fn update_pending_unavailable(&mut self, pending: Vec<PendingSubDag>) {
        self.pending_not_available = pending;
    }

    /// Check if the block has new transaction data we don't already have.
    pub fn contains_new_transactions(&self, block: &VerifiedBlock) -> bool {
        let block_reference = block.reference();
        if self.data_availability[block_reference.authority as usize].contains(block_reference) {
            return false;
        }
        block.transactions().is_some()
    }

    pub fn get_blocks_at_authority_round(
        &self,
        authority: AuthorityIndex,
        round: RoundNumber,
    ) -> Vec<Data<VerifiedBlock>> {
        self.index[authority as usize]
            .get(&round)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_blocks_by_round(&self, round: RoundNumber) -> Vec<Data<VerifiedBlock>> {
        self.index
            .iter()
            .flat_map(|auth_map| {
                auth_map
                    .get(&round)
                    .into_iter()
                    .flat_map(|m| m.values().cloned())
            })
            .collect()
    }

    pub fn get_block(&self, reference: BlockReference) -> Option<Data<VerifiedBlock>> {
        let auth = reference.authority as usize;
        self.index[auth]
            .get(&reference.round)?
            .get(&reference.digest)
            .cloned()
    }

    /// Get a block, with persistent store fallback for evicted blocks.
    fn get_storage_block(&self, reference: BlockReference) -> Option<Data<VerifiedBlock>> {
        if let Some(block) = self.get_block(reference) {
            return Some(block);
        }
        self.store
            .get_block(&reference)
            .expect("Storage read failed")
    }

    /// Get a block suitable for transmission to peers. Same as storage block
    /// since transmission views are now constructed at send time.
    fn get_transmission_block(&self, reference: BlockReference) -> Option<Data<VerifiedBlock>> {
        self.get_storage_block(reference)
    }

    /// Check whether `earlier_block` is an ancestor of `later_block`.
    fn linked(
        &self,
        later_block: &Data<VerifiedBlock>,
        earlier_block: &Data<VerifiedBlock>,
    ) -> bool {
        let mut parents = AHashSet::from([later_block.clone()]);
        for _round_number in (earlier_block.round()..later_block.round()).rev() {
            parents = parents
                .iter()
                .flat_map(|block| block.block_references())
                .map(|block_reference| {
                    self.get_storage_block(*block_reference)
                        .expect("Block should be in DagState")
                })
                .filter(|included_block| included_block.round() >= earlier_block.round())
                .collect();
        }
        parents.contains(earlier_block)
    }

    /// Compute all block references reachable from `later_block` at
    /// `target_round`. Single BFS traversal replaces N separate `linked()`
    /// calls for the same anchor.
    fn reachable_at_round(
        &self,
        later_block: &Data<VerifiedBlock>,
        target_round: RoundNumber,
    ) -> AHashSet<BlockReference> {
        let mut frontier = AHashSet::from([later_block.clone()]);
        for _ in (target_round..later_block.round()).rev() {
            frontier = frontier
                .iter()
                .flat_map(|block| block.block_references())
                .filter_map(|r| self.get_storage_block(*r))
                .filter(|b| b.round() >= target_round)
                .collect();
        }
        frontier.iter().map(|b| *b.reference()).collect()
    }

    /// Per-authority eviction using BTreeMap::split_off.
    fn evict_per_authority(&mut self) {
        for auth in 0..self.committee_size {
            let last_seen = self.last_seen_by_authority[auth];
            let threshold = last_seen.saturating_sub(CACHED_ROUNDS);
            if threshold == 0 || threshold <= self.evicted_rounds[auth] {
                continue;
            }
            self.evicted_rounds[auth] = threshold;

            self.index[auth] = self.index[auth].split_off(&threshold);
            self.shard_index[auth] = self.shard_index[auth].split_off(&threshold);
            self.dag[auth] = self.dag[auth].split_off(&threshold);
            if auth == self.authority as usize {
                for own_blocks_by_peer in &mut self.own_blocks {
                    *own_blocks_by_peer = own_blocks_by_peer.split_off(&threshold);
                }
            }

            let split_ref = BlockReference {
                authority: auth as AuthorityIndex,
                round: threshold,
                digest: BlockDigest::default(),
            };
            self.data_availability[auth] = self.data_availability[auth].split_off(&split_ref);
        }
        let min_evicted = self.min_evicted_round();
        self.round_version.retain(|&r, _| r >= min_evicted);
    }

    fn prune_certificate_state(&mut self) {
        let min_evicted = self.min_evicted_round();
        self.round_certificates = self.round_certificates.split_off(&min_evicted);
        for auth in 0..self.committee_size {
            let split_ref = BlockReference {
                authority: auth as AuthorityIndex,
                round: self.evicted_rounds[auth],
                digest: BlockDigest::default(),
            };
            self.leader_certificates[auth] = self.leader_certificates[auth].split_off(&split_ref);
            self.dac_certificates[auth] = self.dac_certificates[auth].split_off(&split_ref);
            self.rejected_dac_certificates[auth] =
                self.rejected_dac_certificates[auth].split_off(&split_ref);
        }
        self.precomputed_round_sigs = self.precomputed_round_sigs.split_off(&min_evicted);
        let leader_split_ref = BlockReference {
            authority: 0,
            round: min_evicted,
            digest: BlockDigest::default(),
        };
        self.precomputed_leader_sigs = self.precomputed_leader_sigs.split_off(&leader_split_ref);
    }

    pub fn add_block(
        &mut self,
        block: Data<VerifiedBlock>,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
        bfs_buffer: &mut Vec<BlockReference>,
    ) {
        let reference = block.reference();
        let auth = reference.authority as usize;
        self.highest_round = max(self.highest_round, reference.round());

        self.add_own_index(reference, authority_index_start, authority_index_end);
        self.update_last_seen_by_authority(reference);

        let map = self.index[auth].entry(reference.round()).or_default();
        map.insert(reference.digest, block.clone());

        *self.round_version.entry(reference.round()).or_insert(0) += 1;
        self.update_dag(*reference, block.block_references().clone(), bfs_buffer);
        self.update_data_availability(&block);
        self.update_starfish_speed_leader_hints(&block);
    }

    fn update_starfish_speed_leader_hints(&mut self, block: &VerifiedBlock) {
        if self.consensus_protocol != ConsensusProtocol::StarfishSpeed
            || !self.starfish_speed_adaptive_acknowledgments
        {
            return;
        }
        let Some(mask) = block.strong_vote() else {
            return;
        };
        let leader_round = block.round().saturating_sub(1);
        if leader_round == 0 {
            return;
        }
        let leader_authority =
            (leader_round % self.committee_size as RoundNumber) as AuthorityIndex;
        let Some(leader_ref) = block
            .block_references()
            .iter()
            .find(|r| r.round == leader_round && r.authority == leader_authority)
        else {
            return;
        };

        let leader_history = &mut self.starfish_speed_leader_hints[leader_ref.authority as usize];
        let entry = leader_history
            .entry(leader_ref.round)
            .or_insert_with(|| StarfishSpeedLeaderRoundHints::new(self.committee_size));
        entry.update_vote(block.authority(), mask);
        while leader_history.len() > STARFISH_SPEED_HINT_WINDOW_LEADER_ROUNDS {
            let Some(oldest_round) = leader_history.keys().next().copied() else {
                break;
            };
            leader_history.remove(&oldest_round);
        }
    }

    fn dag_get(&self, r: &BlockReference) -> Option<&(Vec<BlockReference>, AuthorityBitmask)> {
        self.dag[r.authority as usize].get(&r.round)?.get(&r.digest)
    }

    fn dag_get_mut(
        &mut self,
        r: &BlockReference,
    ) -> Option<&mut (Vec<BlockReference>, AuthorityBitmask)> {
        self.dag[r.authority as usize]
            .get_mut(&r.round)?
            .get_mut(&r.digest)
    }

    fn dag_contains(&self, r: &BlockReference) -> bool {
        self.dag_get(r).is_some()
    }

    fn dag_insert(&mut self, r: BlockReference, val: (Vec<BlockReference>, AuthorityBitmask)) {
        self.dag[r.authority as usize]
            .entry(r.round)
            .or_default()
            .insert(r.digest, val);
    }

    fn reset_peer_known_by_after_round(&mut self, peer: AuthorityIndex, round: RoundNumber) {
        let bit = !(1u128 << peer);
        for auth_dag in self.dag.iter_mut() {
            for (_, entries) in auth_dag.range_mut((round.saturating_add(1))..) {
                for (_, (_, known_by)) in entries.iter_mut() {
                    *known_by &= bit;
                }
            }
        }
    }

    /// Insert a block into the DAG and propagate "known-by" bits along the
    /// causal history. `known_by` tracks only header knowledge; shard/data
    /// availability is tracked separately in CordialKnowledge.
    ///
    /// `bfs_buffer` is a reusable work queue to avoid per-call allocation.
    /// It will be cleared before use.
    pub fn update_dag(
        &mut self,
        block_reference: BlockReference,
        parents: Vec<BlockReference>,
        bfs_buffer: &mut Vec<BlockReference>,
    ) {
        if block_reference.round == 0 {
            return;
        }
        if self.dag_contains(&block_reference) {
            return;
        }
        let known_by = (1u128 << block_reference.authority) | (1u128 << self.authority);
        self.dag_insert(block_reference, (parents, known_by));

        let authority = block_reference.authority;
        let bit = 1u128 << authority;

        bfs_buffer.clear();
        bfs_buffer.push(block_reference);
        // Reusable buffer to copy parent refs without cloning the Vec.
        let mut parents_buf = Vec::new();
        while let Some(r) = bfs_buffer.pop() {
            parents_buf.clear();
            if let Some((parents, _)) = self.dag_get(&r) {
                parents_buf.extend_from_slice(parents);
            } else {
                continue; // evicted
            }
            for &parent in &parents_buf {
                if parent.round == 0 {
                    continue;
                }
                let Some((_, known_by)) = self.dag_get_mut(&parent) else {
                    continue; // evicted
                };
                if *known_by & bit == 0 {
                    *known_by |= bit;
                    bfs_buffer.push(parent);
                }
            }
        }
    }

    pub fn update_data_availability(&mut self, block: &VerifiedBlock) {
        let r = block.reference();
        let auth = r.authority as usize;
        let is_empty_full_block = matches!(
            self.consensus_protocol,
            ConsensusProtocol::Mysticeti | ConsensusProtocol::CordialMiners
        ) && block.transactions().is_none()
            && block.merkle_root() == TransactionsCommitment::new_from_transactions(&Vec::new());
        if block.has_empty_payload() || is_empty_full_block {
            self.data_availability[auth].insert(*r);
            return;
        }
        if block.transactions().is_some() && !self.data_availability[auth].contains(r) {
            self.data_availability[auth].insert(*r);
            self.maybe_queue_ack(*r);
        }
    }

    /// Queue an acknowledgment for `block_ref` only when all prerequisites are
    /// met. For StarfishBls the block must be both data-available and
    /// DAC-certified; other protocols only require data availability.
    fn maybe_queue_ack(&mut self, block_ref: BlockReference) {
        let Some(pending) = self.pending_acknowledgment.as_mut() else {
            return;
        };
        let auth = block_ref.authority as usize;
        if !self.data_availability[auth].contains(&block_ref) {
            return;
        }
        if self.consensus_protocol == ConsensusProtocol::StarfishBls
            && (block_ref.authority != self.authority
                || !self.dac_certificates[auth].contains_key(&block_ref))
        {
            return;
        }
        pending.push(block_ref);
    }

    pub fn get_pending_acknowledgment(&mut self, round_number: RoundNumber) -> Vec<BlockReference> {
        let Some(pending_acknowledgment) = self.pending_acknowledgment.as_mut() else {
            return Vec::new();
        };
        let current_round = round_number;
        let (to_return, to_keep): (Vec<_>, Vec<_>) =
            pending_acknowledgment.drain(..).partition(|x| {
                if self.consensus_protocol == ConsensusProtocol::StarfishBls {
                    x.round < current_round
                } else {
                    x.round <= current_round
                }
            });
        *pending_acknowledgment = to_keep;
        to_return
    }

    pub fn requeue_pending_acknowledgment(&mut self, block_refs: Vec<BlockReference>) {
        let Some(pending_acknowledgment) = self.pending_acknowledgment.as_mut() else {
            return;
        };
        if block_refs.is_empty() {
            return;
        }
        pending_acknowledgment.extend(block_refs);
    }

    pub fn last_seen_by_authority(&self, authority: AuthorityIndex) -> RoundNumber {
        *self
            .last_seen_by_authority
            .get(authority as usize)
            .expect("last_seen_by_authority not found")
    }

    pub fn min_last_seen_round(&self) -> RoundNumber {
        self.last_seen_by_authority
            .iter()
            .copied()
            .min()
            .unwrap_or(0)
    }

    fn update_last_seen_by_authority(&mut self, reference: &BlockReference) {
        let last_seen = self
            .last_seen_by_authority
            .get_mut(reference.authority as usize)
            .expect("last_seen_by_authority not found");
        *last_seen = (*last_seen).max(reference.round());
    }

    pub fn get_own_block_references(
        &self,
        to_whom_index: AuthorityIndex,
        from_excluded: RoundNumber,
        limit: usize,
    ) -> Vec<BlockReference> {
        self.own_blocks
            .get(to_whom_index as usize)
            .into_iter()
            .flat_map(|blocks| blocks.range((from_excluded + 1)..))
            .take(limit)
            .map(|(round, digest)| BlockReference {
                authority: self.authority,
                round: *round,
                digest: *digest,
            })
            .collect()
    }

    /// Collect unsent blocks for a peer by iterating the DAG, skipping those in
    /// `sent`.
    fn collect_unsent_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        filter: impl Fn(&BlockReference) -> bool,
        limit: usize,
    ) -> Vec<(Data<VerifiedBlock>, RoundNumber)> {
        let peer_bit = 1u128 << peer;
        let mut candidates: Vec<(BlockReference, RoundNumber)> = self
            .dag
            .iter()
            .enumerate()
            .flat_map(|(auth_idx, auth_dag)| {
                auth_dag.iter().flat_map(move |(round, entries)| {
                    entries.iter().map(move |(digest, (_, known_by))| {
                        (
                            BlockReference {
                                authority: auth_idx as AuthorityIndex,
                                round: *round,
                                digest: *digest,
                            },
                            *known_by,
                        )
                    })
                })
            })
            .filter(|(r, known_by)| known_by & peer_bit == 0 && !sent.contains(r) && filter(r))
            .map(|(r, _)| (r, r.round))
            .collect();
        candidates.sort_by_key(|(_, round)| *round);
        candidates.truncate(limit);
        candidates
            .into_iter()
            .map(|(r, round)| {
                let block = self
                    .get_block(r)
                    .unwrap_or_else(|| panic!("Block index corrupted, not found: {r}"));
                (block, round)
            })
            .collect()
    }

    /// Collect unsent blocks with a round-first, authority-fair policy:
    /// within each round, drain approximately equally across authorities.
    fn collect_unsent_blocks_round_fair(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        filter: impl Fn(&BlockReference) -> bool,
        limit: usize,
    ) -> Vec<(Data<VerifiedBlock>, RoundNumber)> {
        if limit == 0 {
            return Vec::new();
        }

        let peer_bit = 1u128 << peer;
        let mut per_authority: Vec<Vec<BlockReference>> = vec![Vec::new(); self.committee_size];

        for (auth_idx, auth_dag) in self.dag.iter().enumerate() {
            for (round, entries) in auth_dag {
                for (digest, (_, known_by)) in entries {
                    let r = BlockReference {
                        authority: auth_idx as AuthorityIndex,
                        round: *round,
                        digest: *digest,
                    };
                    if known_by & peer_bit == 0 && !sent.contains(&r) && filter(&r) {
                        per_authority[auth_idx].push(r);
                    }
                }
            }
        }

        for refs in &mut per_authority {
            refs.sort_by_key(|r| r.round);
        }

        let mut positions = vec![0usize; per_authority.len()];
        let mut selected: Vec<(BlockReference, RoundNumber)> = Vec::with_capacity(limit);

        while selected.len() < limit {
            let min_round = per_authority
                .iter()
                .enumerate()
                .filter_map(|(auth, refs)| refs.get(positions[auth]).map(|r| r.round))
                .min();
            let Some(min_round) = min_round else {
                break;
            };

            loop {
                let mut made_progress = false;
                for auth in 0..per_authority.len() {
                    if selected.len() >= limit {
                        break;
                    }
                    let idx = positions[auth];
                    if let Some(next_ref) = per_authority[auth].get(idx) {
                        if next_ref.round == min_round {
                            selected.push((*next_ref, next_ref.round));
                            positions[auth] += 1;
                            made_progress = true;
                        }
                    }
                }

                if selected.len() >= limit {
                    break;
                }

                let round_has_more = per_authority.iter().enumerate().any(|(auth, refs)| {
                    refs.get(positions[auth])
                        .is_some_and(|next_ref| next_ref.round == min_round)
                });
                if !made_progress || !round_has_more {
                    break;
                }
            }
        }

        selected
            .into_iter()
            .map(|(r, round)| {
                let block = self
                    .get_block(r)
                    .unwrap_or_else(|| panic!("Block index corrupted, not found: {r}"));
                (block, round)
            })
            .collect()
    }

    fn into_sorted_blocks(
        mut blocks: Vec<(Data<VerifiedBlock>, RoundNumber)>,
    ) -> Vec<Data<VerifiedBlock>> {
        blocks.sort_by_key(|x| x.1);
        blocks.into_iter().map(|x| x.0).collect()
    }

    pub fn get_unsent_own_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_own_block_size: usize,
    ) -> Vec<Data<VerifiedBlock>> {
        let Some(own_blocks) = self.own_blocks.get(peer as usize) else {
            return Vec::new();
        };
        let peer_bit = 1u128 << peer;
        let mut result = Vec::with_capacity(batch_own_block_size);

        for (round, digest) in own_blocks {
            if result.len() >= batch_own_block_size {
                break;
            }

            let block_ref = BlockReference {
                authority: self.authority,
                round: *round,
                digest: *digest,
            };

            if sent.contains(&block_ref) {
                continue;
            }

            let Some((_, known_by)) = self.dag_get(&block_ref) else {
                // Preserve the old behavior: once the DAG metadata for this round
                // is evicted, this path stops considering it for unsent scans.
                continue;
            };
            if known_by & peer_bit != 0 {
                continue;
            }

            let block = self
                .get_transmission_block(block_ref)
                .unwrap_or_else(|| panic!("Block index corrupted, not found: {block_ref}"));
            result.push(block);
        }

        result
    }

    fn filter_block_refs_unknown_to_peer(
        &self,
        refs: &[BlockReference],
        peer: AuthorityIndex,
        limit: usize,
    ) -> Vec<BlockReference> {
        let peer_bit = 1u128 << peer;
        let mut result = Vec::with_capacity(limit.min(refs.len()));

        for block_ref in refs {
            if result.len() >= limit {
                break;
            }

            match self.dag_get(block_ref) {
                Some((_, known_by)) if known_by & peer_bit != 0 => {}
                _ => result.push(*block_ref),
            }
        }

        result
    }

    pub fn get_unsent_other_blocks(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_other_block_size: usize,
        max_round: Option<RoundNumber>,
    ) -> Vec<Data<VerifiedBlock>> {
        let auth = self.authority;
        let max = max_round.unwrap_or(RoundNumber::MAX);
        Self::into_sorted_blocks(self.collect_unsent_blocks(
            sent,
            peer,
            |r| r.authority != auth && r.round < max,
            batch_other_block_size,
        ))
    }

    pub fn get_unsent_causal_history(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
        authorities_with_missing_blocks: AHashSet<AuthorityIndex>,
    ) -> Vec<Data<VerifiedBlock>> {
        let auth = self.authority;
        let own =
            self.collect_unsent_blocks(sent, peer, |r| r.authority == auth, batch_own_block_size);
        let max = own.iter().map(|x| x.1).max().unwrap_or(RoundNumber::MAX);
        let other = self.collect_unsent_blocks(
            sent,
            peer,
            |r| authorities_with_missing_blocks.contains(&r.authority) && r.round < max,
            batch_other_block_size,
        );
        Self::into_sorted_blocks(own.into_iter().chain(other).collect())
    }

    pub fn get_unsent_past_cone(
        &self,
        sent: &AHashSet<BlockReference>,
        peer: AuthorityIndex,
        block_reference: BlockReference,
        batch_own_block_size: usize,
        batch_other_block_size: usize,
    ) -> Vec<Data<VerifiedBlock>> {
        let auth = self.authority;
        let max = block_reference.round;
        let own = self.collect_unsent_blocks(
            sent,
            peer,
            |r| r.authority == auth && r.round < max,
            batch_own_block_size,
        );
        let other = self.collect_unsent_blocks_round_fair(
            sent,
            peer,
            |r| r.authority != auth && r.round < max,
            batch_other_block_size,
        );
        Self::into_sorted_blocks(own.into_iter().chain(other).collect())
    }

    fn add_own_index(
        &mut self,
        reference: &BlockReference,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) {
        if reference.authority != self.authority {
            return;
        }
        if reference.round > self.last_own_block.map(|r| r.round).unwrap_or_default() {
            self.last_own_block = Some(*reference);
        }
        for authority_index in authority_index_start..authority_index_end {
            // Re-receiving our own block from the network should not replace the
            // originally indexed block for this recipient/round.
            self.own_blocks[authority_index as usize]
                .entry(reference.round)
                .or_insert(reference.digest);
        }
    }

    pub fn last_own_block(&self) -> Option<BlockReference> {
        self.last_own_block
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OwnBlockData {
    pub block: Data<VerifiedBlock>,
    pub authority_index_start: AuthorityIndex,
    pub authority_index_end: AuthorityIndex,
}

impl OwnBlockData {
    pub fn new(
        block: Data<VerifiedBlock>,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) -> Self {
        Self {
            block,
            authority_index_start,
            authority_index_end,
        }
    }

    pub fn from_bytes(bytes: Bytes) -> bincode::Result<Self> {
        bincode::deserialize(&bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization failed")
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommitData {
    pub leader: BlockReference,
    // All committed blocks, including the leader
    pub sub_dag: Vec<BlockReference>,
    /// Per-authority highest committed round at the time of this commit.
    /// Used for windowed recovery on restart.
    #[serde(default)]
    pub committed_rounds: Vec<RoundNumber>,
}

impl CommitData {
    pub fn new(commit: &CommittedSubDag, committed_rounds: Vec<RoundNumber>) -> Self {
        let sub_dag = commit.blocks.iter().map(|b| *b.reference()).collect();
        Self {
            leader: commit.anchor,
            sub_dag,
            committed_rounds,
        }
    }
}

#[cfg(test)]
mod tests {
    use prometheus::Registry;
    use tempfile::TempDir;

    use super::{CACHED_ROUNDS, ConsensusProtocol, DagState};
    use crate::{
        committee::Committee,
        config::{DisseminationMode, StorageBackend},
        crypto::{
            BLS_SIGNATURE_SIZE, BlockDigest, BlsSignatureBytes, SignatureBytes,
            TransactionsCommitment,
        },
        data::Data,
        metrics::Metrics,
        types::{
            AuthorityIndex, AuthoritySet, BlockReference, BlsAggregateCertificate, ProvableShard,
            RoundNumber, VerifiedBlock,
        },
    };

    fn open_test_dag_state() -> DagState {
        open_test_dag_state_for("starfish-bls", 0)
    }

    fn open_test_dag_state_for(consensus: &str, authority: AuthorityIndex) -> DagState {
        open_test_dag_state_for_with_feature(consensus, authority, false)
    }

    fn open_test_dag_state_for_with_feature(
        consensus: &str,
        authority: AuthorityIndex,
        enable_starfish_speed_adaptive_acknowledgments: bool,
    ) -> DagState {
        let committee = Committee::new_for_benchmarks(4);
        let registry = Registry::new();
        let (metrics, _reporter) =
            Metrics::new(&registry, Some(committee.as_ref()), Some(consensus), None);
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        std::mem::forget(dir);
        DagState::open(
            authority,
            path,
            metrics,
            committee,
            "honest".to_string(),
            consensus.to_string(),
            &StorageBackend::Rocksdb,
            enable_starfish_speed_adaptive_acknowledgments,
        )
        .dag_state
    }

    fn make_starfish_speed_vote_block(
        authority: AuthorityIndex,
        round: RoundNumber,
        leader_ref: BlockReference,
        strong_vote_mask: u128,
    ) -> Data<VerifiedBlock> {
        let own_previous = BlockReference::new_test(authority, round - 1);
        let mut block = VerifiedBlock::new(
            authority,
            round,
            vec![own_previous, leader_ref],
            Vec::new(),
            0,
            SignatureBytes::default(),
            Vec::new(),
            TransactionsCommitment::default(),
            Some(strong_vote_mask),
            None,
        );
        block.preserialize();
        Data::new(block)
    }

    fn make_empty_full_block(
        authority: AuthorityIndex,
        round: RoundNumber,
        consensus_protocol: ConsensusProtocol,
    ) -> Data<VerifiedBlock> {
        let block_refs = if round == 0 {
            Vec::new()
        } else {
            vec![BlockReference::new_test(authority, round - 1)]
        };
        let empty_transactions = Vec::new();
        let merkle_root = match consensus_protocol {
            ConsensusProtocol::Mysticeti | ConsensusProtocol::CordialMiners => {
                TransactionsCommitment::new_from_transactions(&empty_transactions)
            }
            ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishSpeed
            | ConsensusProtocol::StarfishBls => TransactionsCommitment::default(),
        };
        let mut block = VerifiedBlock::new(
            authority,
            round,
            block_refs,
            Vec::new(),
            0,
            SignatureBytes::default(),
            empty_transactions,
            merkle_root,
            None,
            None,
        );
        block.preserialize();
        Data::new(block)
    }

    #[test]
    fn acknowledgments_are_only_enabled_for_starfish_variants() {
        assert!(!ConsensusProtocol::Mysticeti.supports_acknowledgments());
        assert!(!ConsensusProtocol::CordialMiners.supports_acknowledgments());
        assert!(ConsensusProtocol::Starfish.supports_acknowledgments());
        assert!(ConsensusProtocol::StarfishSpeed.supports_acknowledgments());
        assert!(ConsensusProtocol::StarfishBls.supports_acknowledgments());
    }

    #[test]
    fn empty_full_blocks_are_data_available_for_mysticeti() {
        let dag_state = open_test_dag_state_for("mysticeti", 0);
        let block = make_empty_full_block(1, 1, ConsensusProtocol::Mysticeti);
        let reference = *block.reference();

        dag_state.insert_general_block(block);

        assert!(dag_state.is_data_available(&reference));
    }

    #[test]
    fn empty_full_blocks_are_data_available_for_cordial_miners() {
        let dag_state = open_test_dag_state_for("cordial-miners", 0);
        let block = make_empty_full_block(1, 1, ConsensusProtocol::CordialMiners);
        let reference = *block.reference();

        dag_state.insert_general_block(block);

        assert!(dag_state.is_data_available(&reference));
    }

    #[test]
    fn starfish_speed_adaptive_acknowledgments_only_uses_local_leader_history() {
        let dag_state = open_test_dag_state_for_with_feature("starfish-speed", 0, true);
        let own_leader_ref = BlockReference::new_test(0, 4);
        let other_leader_ref = BlockReference::new_test(1, 1);

        dag_state.insert_general_blocks(vec![
            make_starfish_speed_vote_block(1, 5, own_leader_ref, 1u128 << 1),
            make_starfish_speed_vote_block(2, 5, own_leader_ref, 1u128 << 1),
            make_starfish_speed_vote_block(3, 5, own_leader_ref, 1u128 << 0),
            make_starfish_speed_vote_block(0, 2, other_leader_ref, 1u128 << 2),
            make_starfish_speed_vote_block(2, 2, other_leader_ref, 1u128 << 2),
        ]);

        let excluded = dag_state.starfish_speed_excluded_ack_authorities();
        assert_ne!(excluded & (1u128 << 1), 0);
        assert_eq!(excluded & (1u128 << 0), 0);
        assert_eq!(excluded & (1u128 << 2), 0);
    }

    #[test]
    fn starfish_speed_adaptive_acknowledgments_keeps_only_recent_local_leader_rounds() {
        let dag_state = open_test_dag_state_for_with_feature("starfish-speed", 0, true);
        let leader_rounds = [4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44];
        let mut blocks = Vec::new();
        for leader_round in leader_rounds {
            let leader_ref = BlockReference::new_test(0, leader_round);
            let complaint_mask = if leader_round == 4 {
                1u128 << 1
            } else {
                1u128 << 2
            };
            blocks.push(make_starfish_speed_vote_block(
                1,
                leader_round + 1,
                leader_ref,
                complaint_mask,
            ));
        }
        dag_state.insert_general_blocks(blocks);

        let excluded = dag_state.starfish_speed_excluded_ack_authorities();
        assert_eq!(excluded & (1u128 << 1), 0);
        assert_ne!(excluded & (1u128 << 2), 0);
    }

    #[test]
    fn starfish_speed_adaptive_acknowledgments_can_be_disabled() {
        let dag_state = open_test_dag_state_for_with_feature("starfish-speed", 0, false);
        let own_leader_ref = BlockReference::new_test(0, 4);
        dag_state.insert_general_block(make_starfish_speed_vote_block(
            1,
            5,
            own_leader_ref,
            1u128 << 1,
        ));

        assert_eq!(dag_state.starfish_speed_excluded_ack_authorities(), 0);
    }

    #[test]
    fn cleanup_prunes_certificates_for_evicted_rounds() {
        let dag_state = open_test_dag_state();
        let leader_pruned = BlockReference {
            round: 9,
            authority: 0,
            digest: Default::default(),
        };
        let leader_kept = BlockReference {
            round: 10,
            authority: 0,
            digest: Default::default(),
        };
        let dac_pruned = BlockReference {
            round: 4,
            authority: 1,
            digest: Default::default(),
        };
        let dac_kept = BlockReference {
            round: 5,
            authority: 1,
            digest: Default::default(),
        };
        let authority_without_eviction = BlockReference {
            round: 1,
            authority: 2,
            digest: Default::default(),
        };
        let rejected_pruned = BlockReference {
            round: 4,
            authority: 3,
            digest: Default::default(),
        };
        let rejected_kept = BlockReference {
            round: 5,
            authority: 3,
            digest: Default::default(),
        };

        {
            let mut inner = dag_state.dag_state_inner.write();
            inner.last_seen_by_authority[0] = CACHED_ROUNDS + 10;
            inner.last_seen_by_authority[1] = CACHED_ROUNDS + 5;
            inner.last_seen_by_authority[2] = CACHED_ROUNDS;
            inner.last_seen_by_authority[3] = CACHED_ROUNDS + 5;
            inner.leader_certificates[0].insert(leader_pruned, BlsAggregateCertificate::default());
            inner.leader_certificates[0].insert(leader_kept, BlsAggregateCertificate::default());
            inner.leader_certificates[2].insert(
                authority_without_eviction,
                BlsAggregateCertificate::default(),
            );
            inner.dac_certificates[1].insert(dac_pruned, BlsAggregateCertificate::default());
            inner.dac_certificates[1].insert(dac_kept, BlsAggregateCertificate::default());
            inner.dac_certificates[2].insert(
                authority_without_eviction,
                BlsAggregateCertificate::default(),
            );
            inner.rejected_dac_certificates[3].insert(rejected_pruned);
            inner.rejected_dac_certificates[3].insert(rejected_kept);
        }

        dag_state.cleanup();

        assert!(!dag_state.has_leader_certificate(&leader_pruned));
        assert!(dag_state.has_leader_certificate(&leader_kept));
        assert!(dag_state.has_leader_certificate(&authority_without_eviction));
        assert!(!dag_state.has_dac_certificate(&dac_pruned));
        assert!(dag_state.has_dac_certificate(&dac_kept));
        assert!(dag_state.has_dac_certificate(&authority_without_eviction));
        assert!(!dag_state.has_rejected_dac_certificate(&rejected_pruned));
        assert!(dag_state.has_rejected_dac_certificate(&rejected_kept));
    }

    #[test]
    fn cleanup_prunes_own_block_indexes_for_evicted_rounds() {
        let dag_state = open_test_dag_state_for("starfish", 0);

        {
            let mut inner = dag_state.dag_state_inner.write();
            inner.last_seen_by_authority[0] = CACHED_ROUNDS + 10;
            for peer in 0..inner.committee_size {
                inner.own_blocks[peer].insert(4, BlockDigest::default());
                inner.own_blocks[peer].insert(10, BlockDigest::default());
                inner.own_blocks[peer].insert(12, BlockDigest::default());
            }
        }

        dag_state.cleanup();

        let inner = dag_state.dag_state_inner.read();
        for own_blocks_by_peer in &inner.own_blocks {
            assert!(!own_blocks_by_peer.contains_key(&4));
            assert!(own_blocks_by_peer.contains_key(&10));
            assert!(own_blocks_by_peer.contains_key(&12));
        }
    }

    #[test]
    fn transmission_parts_fetch_headers_and_shards_from_store_after_eviction() {
        let dag_state = open_test_dag_state_for("starfish", 0);
        let block = make_empty_full_block(1, 4, ConsensusProtocol::Starfish);
        let reference = *block.reference();
        let shard = ProvableShard::new(
            vec![1, 2, 3],
            0,
            Vec::new(),
            TransactionsCommitment::default(),
        );

        dag_state.insert_general_block(block);
        dag_state.insert_shard(reference, shard.clone());

        {
            let mut inner = dag_state.dag_state_inner.write();
            inner.last_seen_by_authority[1] = CACHED_ROUNDS + 10;
        }
        dag_state.cleanup();

        let (headers, shards) = dag_state.get_transmission_parts(&[reference], &[reference]);

        assert_eq!(headers.len(), 1);
        assert_eq!(*headers[0].reference(), reference);
        assert!(!headers[0].has_transaction_data());

        assert_eq!(shards.len(), 1);
        assert_eq!(shards[0].block_reference, reference);
        assert_eq!(shards[0].shard.shard(), shard.shard());
        assert_eq!(shards[0].shard.shard_index(), shard.shard_index());
        assert_eq!(shards[0].shard.merkle_proof(), shard.merkle_proof());
        assert_eq!(
            shards[0].shard.transactions_commitment(),
            shard.transactions_commitment()
        );
    }

    #[test]
    fn dac_certificate_state_tracks_unchecked_verified_and_rejected() {
        let dag_state = open_test_dag_state();
        let unchecked = BlockReference {
            round: 7,
            authority: 1,
            digest: Default::default(),
        };
        let rejected = BlockReference {
            round: 8,
            authority: 1,
            digest: Default::default(),
        };
        let verified = BlockReference {
            round: 9,
            authority: 1,
            digest: Default::default(),
        };
        let mut signers = AuthoritySet::default();
        signers.insert(0);
        let cert =
            BlsAggregateCertificate::new(BlsSignatureBytes([1u8; BLS_SIGNATURE_SIZE]), signers);

        assert_eq!(
            dag_state.dac_certificate_state(&unchecked),
            super::DacCertificateVerificationState::Unchecked
        );
        assert!(dag_state.mark_dac_rejected(rejected));
        assert_eq!(
            dag_state.dac_certificate_state(&rejected),
            super::DacCertificateVerificationState::Rejected
        );
        assert!(dag_state.mark_dac_certified(verified, cert));
        assert_eq!(
            dag_state.dac_certificate_state(&verified),
            super::DacCertificateVerificationState::Verified
        );
        assert!(!dag_state.mark_dac_certified(rejected, cert));
    }

    #[test]
    fn consensus_protocol_resolves_dissemination_defaults() {
        assert_eq!(
            ConsensusProtocol::Mysticeti.default_dissemination_mode(),
            DisseminationMode::Pull
        );
        assert_eq!(
            ConsensusProtocol::CordialMiners.default_dissemination_mode(),
            DisseminationMode::PushCausal
        );
        assert_eq!(
            ConsensusProtocol::Starfish.default_dissemination_mode(),
            DisseminationMode::PushCausal
        );
        assert_eq!(
            ConsensusProtocol::StarfishBls
                .resolve_dissemination_mode(DisseminationMode::ProtocolDefault),
            DisseminationMode::PushCausal
        );
        assert_eq!(
            ConsensusProtocol::Starfish.resolve_dissemination_mode(DisseminationMode::PushUseful),
            DisseminationMode::PushUseful
        );
    }
}
