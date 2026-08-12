// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    net::SocketAddr,
    ops::AddAssign,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

use prettytable::{Table as PrettyTable, format, row};
use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Registry, register_histogram_vec_with_registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_vec_with_registry, register_int_gauge_with_registry,
};
use tabled::{Table, Tabled};
use tokio::time::Instant;

use crate::{
    committee::Committee,
    data::{IN_MEMORY_BLOCKS, IN_MEMORY_BLOCKS_BYTES},
    runtime,
    starfish_rbc_dag::model::{
        EXECUTABLE_MODEL_ADMISSION_WINDOW_V1, EXECUTABLE_MODEL_BUFFER_WINDOW_V1,
    },
    stat::{DivUsize, HistogramSender, PreciseHistogram, histogram},
    types::{AuthorityIndex, format_authority_index},
};

/// Metrics collected by the benchmark.
pub const BENCHMARK_DURATION: &str = "benchmark_duration";

/// One absolute submission window shared by every local-benchmark generator.
/// The common epoch removes sequential-start and polling skew from offered
/// load, cutoff counters, and latency samples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BenchmarkTransactionWindow {
    pub start: Instant,
    pub end: Instant,
}

impl BenchmarkTransactionWindow {
    pub fn new(start: Instant, end: Instant) -> Option<Self> {
        (start < end).then_some(Self { start, end })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BenchmarkGeneratorState {
    Disabled = 0,
    Waiting = 1,
    Active = 2,
    Finished = 3,
    Failed = 4,
}

impl BenchmarkGeneratorState {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Waiting,
            2 => Self::Active,
            3 => Self::Finished,
            4 => Self::Failed,
            _ => Self::Disabled,
        }
    }
}

pub const TRANSACTION_CERTIFIED_LATENCY: &str = "transaction_certified_latency";
pub const TRANSACTION_CERTIFIED_LATENCY_SQUARED: &str = "latency_s";

/// Benchmark-only live-tail guards for the observational RBC-DAG shadow.
/// They are not asynchronous protocol or garbage-collection bounds.
pub const STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_FACTOR: i64 = 4;
pub const STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_ROUND_LAG: i64 = 4;

/// Local-benchmark guards for the autonomous RBC-DAG carrier clock. The
/// round-skew limit matches the executable model's bounded future
/// buffer. A healthy clock can transiently retain phase work, but its carrier
/// capacity exceeds the two RBC statements generated per admitted value; a
/// sixteen-committee backlog therefore leaves generous scheduling headroom
/// while still detecting an actor that is no longer draining work.
pub const STARFISH_RBC_DAG_AUTONOMOUS_MAX_ROUND_LAG: i64 = 4;
pub const STARFISH_RBC_DAG_AUTONOMOUS_MAX_PHASE_BACKLOG_FACTOR: i64 = 16;
/// Per-remote-author capacity of authenticated future slots that are inside
/// the executable retention window but outside its immediate admission
/// window. This is an asynchronous safety bound, not a healthy-tail target.
pub const STARFISH_RBC_DAG_AUTONOMOUS_BUFFERED_CAPACITY_PER_REMOTE: i64 =
    EXECUTABLE_MODEL_BUFFER_WINDOW_V1 as i64 - EXECUTABLE_MODEL_ADMISSION_WINDOW_V1 as i64;
/// With final honest round skew bounded by four and two future rounds admitted,
/// at most two slots per remote author remain buffered in a settled run.
pub const STARFISH_RBC_DAG_AUTONOMOUS_BUFFERED_SETTLED_PER_REMOTE: i64 =
    STARFISH_RBC_DAG_AUTONOMOUS_MAX_ROUND_LAG - EXECUTABLE_MODEL_ADMISSION_WINDOW_V1 as i64;

pub const fn starfish_rbc_dag_autonomous_buffered_capacity_bound(committee_size: i64) -> i64 {
    STARFISH_RBC_DAG_AUTONOMOUS_BUFFERED_CAPACITY_PER_REMOTE
        .saturating_mul(committee_size.saturating_sub(1))
}

pub const fn starfish_rbc_dag_autonomous_buffered_settled_bound(committee_size: i64) -> i64 {
    STARFISH_RBC_DAG_AUTONOMOUS_BUFFERED_SETTLED_PER_REMOTE
        .saturating_mul(committee_size.saturating_sub(1))
}

const LOCAL_BENCHMARK_NETWORK_MESSAGE_TYPES: &[&str] = &[
    "subscribe_broadcast",
    "batch",
    "missing_parents",
    "missing_tx_data",
    "partial_sig",
    "cert_echo",
    "cert_vote",
    "cert_ready",
    "cert_batch",
    "sailfish_timeout",
    "sailfish_no_vote",
    "unprovable_cert_request",
    "round_gap_request",
    "rbc_initial",
    "rbc_echo",
    "rbc_ready",
    "rbc_header_request",
    "rbc_header_response",
    "rbc_dag_shadow_carrier",
    "rbc_dag_shadow_carrier_request",
    "rbc_dag_shadow_carrier_response",
    "rbc_dag_shadow_carrier_sync_request",
    "rbc_dag_shadow_carrier_sync_response",
    "rbc_dag_application_payload_request",
    "rbc_dag_application_payload_response",
];

pub(crate) const RBC_DAG_LATENCY_CREATION_TO_ASSIGNMENT: &str = "creation_to_assignment";
pub(crate) const RBC_DAG_LATENCY_CREATION_TO_DELIVERY: &str = "creation_to_delivery";
pub(crate) const RBC_DAG_LATENCY_CREATION_TO_FRONTIER_GENERATED: &str =
    "creation_to_frontier_generated";
pub(crate) const RBC_DAG_LATENCY_CREATION_TO_FRONTIER_APPLIED: &str =
    "creation_to_frontier_applied";

const RBC_DAG_PIPELINE_LATENCY_STAGES: &[&str] = &[
    RBC_DAG_LATENCY_CREATION_TO_ASSIGNMENT,
    RBC_DAG_LATENCY_CREATION_TO_DELIVERY,
    RBC_DAG_LATENCY_CREATION_TO_FRONTIER_GENERATED,
    RBC_DAG_LATENCY_CREATION_TO_FRONTIER_APPLIED,
];
pub(crate) const RBC_DAG_COMMIT_DISTANCE_PHYSICAL_FORWARD: &str = "physical_forward";
pub(crate) const RBC_DAG_COMMIT_DISTANCE_PHYSICAL_BACKWARD: &str = "physical_backward";
const RBC_DAG_COMMIT_DISTANCE_KINDS: &[&str] = &[
    RBC_DAG_COMMIT_DISTANCE_PHYSICAL_FORWARD,
    RBC_DAG_COMMIT_DISTANCE_PHYSICAL_BACKWARD,
];
const RBC_DAG_PROJECTION_HOL_STATES: &[&str] = &[
    "insufficient_lookahead",
    "direct_evidence_pending",
    "awaiting_indirect_anchor",
    "ready",
];

#[derive(Clone)]
pub struct Metrics {
    pub benchmark_duration: IntCounter,
    pub committed_leaders_total: IntCounterVec,
    pub leader_timeout_total: IntCounter,
    pub proposal_wait_time_total_us: IntCounter,
    pub sequenced_transactions_total: IntCounter,
    /// Transactions committed before the coordinated benchmark's exact
    /// monotonic cutoff. The ordinary sequenced counter remains open through
    /// the bounded drain to measure eventual active-window throughput.
    pub sequenced_transactions_cutoff_total: IntCounter,
    pub sequenced_transactions_bytes: IntCounter,
    pub sailfish_rbc_fast_total: IntCounter,
    pub sailfish_rbc_slow_total: IntCounter,

    pub filtered_blocks_total: IntCounter,
    pub filtered_shards_total: IntCounter,
    pub processed_after_filtering_total: IntCounter,
    pub reconstructed_blocks_total: IntCounter,
    pub shard_reconstruction_jobs_total: IntCounter,
    pub shard_reconstruction_success_total: IntCounter,
    pub shard_reconstruction_failed_total: IntCounter,
    pub shard_reconstruction_cancelled_total: IntCounter,
    pub shard_reconstruction_pending_accumulators: IntGauge,
    pub shard_reconstruction_queued_jobs: IntGauge,
    pub shard_reconstruction_pending_decoded_blocks: IntGauge,
    pub shard_reconstruction_lag: Histogram,
    pub used_additional_blocks_total: IntCounter,

    pub dag_state_unloaded_blocks: IntCounter,
    pub dag_state_loaded_blocks: IntCounter,
    pub dag_state_entries: IntCounter,
    pub dag_state_cleanup_util: IntCounter,

    pub dag_highest_round: IntGauge,
    pub dag_lowest_round: IntGauge,
    pub dag_blocks_in_memory: IntGauge,

    pub wal_mappings: IntGauge,

    pub core_lock_util: IntCounter,
    pub core_lock_enqueued: IntCounter,
    pub core_lock_dequeued: IntCounter,
    pub core_queue_length: IntGauge,
    pub core_thread_tasks_total: IntCounterVec,

    pub block_handler_cleanup_util: IntCounter,

    pub missing_blocks: IntGaugeVec,
    pub block_manager_pending_blocks: IntGauge,
    pub core_pending_reconstructed_data: IntGauge,
    pub block_sync_requests_sent: IntCounterVec,
    pub block_sync_requests_received: IntCounterVec,
    pub tx_data_requests_sent: IntCounterVec,
    pub tx_data_requests_received: IntCounterVec,
    pub committed_blocks: IntCounterVec,

    pub block_committed_latency: HistogramSender<Duration>,
    pub block_committed_latency_squared_micros: IntCounter,

    pub transaction_committed_latency: HistogramSender<Duration>,
    pub transaction_committed_latency_squared_micros: IntCounter,

    pub proposed_block_size_bytes: HistogramSender<usize>,
    pub proposed_header_size_bytes: HistogramSender<usize>,
    pub proposed_transaction_size_bytes: HistogramSender<usize>,
    pub block_bundle_size_bytes: HistogramSender<usize>,
    pub proposed_block_refs: HistogramVec,
    pub proposed_block_acks: HistogramVec,
    pub created_own_blocks: IntCounterVec,
    pub previous_round_refs: Histogram,
    pub commit_gap: Histogram,

    pub connection_latency_sender: Vec<HistogramSender<Duration>>,

    pub commit_digest: IntGauge,
    pub commit_digest_latest: IntGauge,
    pub commit_index: IntGauge,
    pub commit_availability_gap: IntGauge,

    pub utilization_timer: IntCounterVec,
    pub submitted_transactions: IntCounter,
    pub submitted_transactions_bytes: IntCounter,

    // storage write metrics
    pub store_block_latency_us: IntCounter,
    pub store_block_count: IntCounter,
    pub store_commits_latency_us: IntCounter,
    pub store_commits_count: IntCounter,
    pub storage_backend_info: IntGauge,
    pub transaction_mode_info: IntGauge,

    // tracking total bytes sent and received
    pub bytes_sent_total: IntCounter,
    pub bytes_uncompressed_sent_total: IntCounter,
    pub bytes_received_total: IntCounter,

    // per-request-type network message counters
    pub network_requests_sent_total: IntCounterVec,
    pub network_requests_received_total: IntCounterVec,
    pub network_message_bytes_sent_total: IntCounterVec,
    pub network_message_bytes_received_total: IntCounterVec,

    // Starfish-RBC-DAG shadow instrumentation. These metrics are strictly
    // observational: the shadow path never feeds the authoritative DAG or
    // consensus state.
    pub starfish_rbc_dag_shadow_inputs_total: IntCounterVec,
    pub starfish_rbc_dag_shadow_delivery_comparisons_total: IntCounterVec,
    pub starfish_rbc_dag_shadow_wal_appended_batches_total: IntCounter,
    pub starfish_rbc_dag_shadow_wal_appended_records_total: IntCounter,
    pub starfish_rbc_dag_shadow_wal_durable_batches_total: IntCounter,
    pub starfish_rbc_dag_shadow_wal_durable_records_total: IntCounter,
    pub starfish_rbc_dag_shadow_wal_replayed_batches: IntGauge,
    pub starfish_rbc_dag_shadow_wal_discarded_tail_bytes_total: IntCounter,
    pub starfish_rbc_dag_shadow_pending_recovery: IntGauge,
    pub starfish_rbc_dag_shadow_unpaired_direct: IntGauge,
    pub starfish_rbc_dag_shadow_unpaired_shadow: IntGauge,
    pub starfish_rbc_dag_shadow_unpaired_max_round_lag: IntGauge,
    pub starfish_rbc_dag_shadow_comparison_valid: IntGauge,
    pub starfish_rbc_dag_shadow_clock_valid: IntGauge,
    pub starfish_rbc_dag_shadow_carrier_round: IntGauge,
    pub starfish_rbc_dag_shadow_phase_backlog: IntGauge,
    pub starfish_rbc_dag_shadow_admitted_authors: IntGauge,
    pub starfish_rbc_dag_shadow_admitted_stake: IntGauge,
    pub starfish_rbc_dag_shadow_buffered_authenticated: IntGauge,
    pub starfish_rbc_dag_projected_vertices_total: IntCounter,
    pub starfish_rbc_dag_projection_decisions_total: IntCounterVec,
    /// Active-window application latency decomposed by one of four fixed
    /// pipeline stages. Keeping sum/count/max avoids per-block labels and the
    /// cost of a high-volume histogram on the carrier actor's hot path.
    pub starfish_rbc_dag_pipeline_latency_ns_total: IntCounterVec,
    pub starfish_rbc_dag_pipeline_latency_samples_total: IntCounterVec,
    pub starfish_rbc_dag_pipeline_latency_ns_max: IntGaugeVec,
    /// Diagnostic-only round distances for first-committed applications.
    /// Physical deltas use separate forward/backward magnitude labels so
    /// cross-author clock skew is not hidden by unsigned saturation.
    pub starfish_rbc_dag_commit_distance_rounds_total: IntCounterVec,
    pub starfish_rbc_dag_commit_distance_samples_total: IntCounterVec,
    pub starfish_rbc_dag_commit_distance_rounds_max: IntGaugeVec,
    /// Current and process-high-water queue depths, with the bounded labels
    /// `local` and `projection`.
    pub starfish_rbc_dag_pipeline_queue_depth: IntGaugeVec,
    pub starfish_rbc_dag_pipeline_queue_depth_max: IntGaugeVec,
    pub starfish_rbc_dag_highest_projected_consensus_round: IntGauge,
    pub starfish_rbc_dag_next_undecided_consensus_round: IntGauge,
    pub starfish_rbc_dag_next_undecided_projected_stake: IntGauge,
    pub starfish_rbc_dag_last_committed_consensus_round: IntGauge,
    /// One-hot current projection head-of-line state. The label vocabulary is
    /// fixed in `set_starfish_rbc_dag_pipeline_state`.
    pub starfish_rbc_dag_projection_hol_state: IntGaugeVec,
    /// Frontier lifecycle counters plus the current/high-water number created
    /// by the synchronous carrier actor but not yet applied by the core
    /// dispatcher.
    pub starfish_rbc_dag_frontier_events_total: IntCounterVec,
    pub starfish_rbc_dag_frontiers_inflight: IntGauge,
    pub starfish_rbc_dag_frontiers_inflight_max: IntGauge,
    /// Sequenced-transaction total observed by the frontier bridge only after
    /// it records the corresponding final application-latency samples. The
    /// local benchmark uses this release/acquire acknowledgement before
    /// closing its post-cutoff transaction-observation gate.
    starfish_rbc_dag_frontier_applied_sequenced_transactions: Arc<AtomicU64>,

    // subscription tracking
    pub subscribed_to_peers: IntGauge,
    pub subscribed_by_peers: IntGauge,

    // per-peer useful-authorities counts by kind
    pub useful_authorities: IntGaugeVec,

    // BLS certificate aggregation metrics
    pub bls_certificates_total: IntCounterVec,
    pub bls_dac_rejections_total: IntCounter,
    pub bls_blocks_processed_total: IntCounter,
    pub bls_standalone_dac_sigs_total: IntCounter,
    pub bls_service_util: IntCounter,
    pub bls_batch_verification_failures_total: IntCounter,
    pub bls_presign_total: IntCounterVec,
    pub bls_presign_hit_total: IntCounter,
    pub bls_presign_miss_total: IntCounter,
    pub bls_dac_sigs_deferred_total: IntCounter,

    // DataSource provenance counters
    pub accepted_blocks_by_source: IntCounterVec,
    pub accepted_headers_by_source: IntCounterVec,
    pub accepted_transactions_by_source: IntCounterVec,

    // CordialKnowledge collection-size gauges
    pub ck_known_headers: IntGauge,
    pub ck_known_shards: IntGauge,
    pub ck_pending_headers: IntGauge,
    pub ck_pending_shards: IntGauge,
    pub ck_peer_known_headers: IntGaugeVec,
    pub ck_peer_known_shards: IntGaugeVec,

    /// True iff the validator is inside the active transaction-submission
    /// window. Outside this window — during the warmup before the first
    /// transaction is generated, and after the generator stops — protocol
    /// throughput/latency metrics and the `benchmark_duration` clock are
    /// skipped. Transaction commits use `transaction_metrics_active` so the
    /// offered window can be followed through a bounded drain.
    pub metrics_active: Arc<AtomicBool>,
    /// Transaction and application-pipeline observations remain enabled
    /// during the bounded post-window drain, while all ordinary
    /// protocol/window metrics close exactly at the shared cutoff. This makes
    /// active-window latency uncensored without charging drain traffic to
    /// block/RBC throughput.
    pub transaction_metrics_active: Arc<AtomicBool>,
    /// Runtime-only coordinated generator lifecycle for local benchmarks.
    pub benchmark_generator_state: Arc<AtomicU8>,
    /// Common benchmark cutoff expressed in microseconds since this
    /// validator's `validator_start`; zero outside coordinated benchmarks.
    pub benchmark_transaction_cutoff_micros: Arc<AtomicU64>,
    /// Wall-clock instant the validator's metrics were first activated, in
    /// microseconds since `validator_start`. Used by the
    /// `benchmark_duration` Prometheus counter so its denominator counts
    /// only active-window seconds (not warmup or drain).
    pub active_start_micros: Arc<AtomicU64>,
    /// Reference instant against which `active_start_micros` is measured.
    /// Set once at validator boot and shared across the block handler and
    /// the transaction generator.
    pub validator_start: tokio::time::Instant,
}

pub struct MetricReporter {
    pub transaction_committed_latency: parking_lot::Mutex<HistogramReporter<Duration>>,
    pub block_committed_latency: parking_lot::Mutex<HistogramReporter<Duration>>,
    pub proposed_block_size_bytes: parking_lot::Mutex<HistogramReporter<usize>>,
    pub proposed_header_size_bytes: parking_lot::Mutex<HistogramReporter<usize>>,
    pub proposed_transaction_size_bytes: parking_lot::Mutex<HistogramReporter<usize>>,
    pub block_bundle_size_bytes: parking_lot::Mutex<HistogramReporter<usize>>,
    pub connection_latency: parking_lot::Mutex<VecHistogramReporter<Duration>>,
    pub global_in_memory_blocks: IntGauge,
    pub global_in_memory_blocks_bytes: IntGauge,
}

/// Per-validator counters captured after the autonomous shadow becomes ready
/// and immediately before the measured local-benchmark interval begins.
#[derive(Clone, Copy, Debug, Default)]
pub struct AutonomousClockBenchmarkBaseline {
    accepted_local_carriers: u64,
    delivered_carriers: u64,
    delivered_applications: u64,
    committed_frontiers: u64,
    frontier_applications: u64,
    projected_vertices: u64,
    projection_decisions: u64,
    wal_batches: u64,
    wal_records: u64,
    carrier_round: i64,
}

/// Immutable per-validator RBC-DAG state sampled at the common transaction
/// cutoff. The bounded post-window transaction drain may improve or worsen
/// live gauges, but it must never rewrite the verdict for the measured
/// interval.
#[derive(Clone, Copy, Debug, Default)]
pub struct AutonomousClockBenchmarkSnapshot {
    accepted_heartbeats: u64,
    accepted_application_carriers: u64,
    delivered_carriers: u64,
    delivered_applications: u64,
    committed_frontiers: u64,
    frontier_applications: u64,
    projected_vertices: u64,
    projection_decisions: u64,
    wal_batches: u64,
    wal_records: u64,
    clock_valid: i64,
    carrier_round: i64,
    phase_backlog: i64,
    admitted_authors: i64,
    admitted_stake: i64,
    buffered_authenticated: i64,
    pending_recovery: i64,
}

impl AutonomousClockBenchmarkSnapshot {
    fn accepted_local_carriers(self) -> u64 {
        self.accepted_heartbeats
            .saturating_add(self.accepted_application_carriers)
    }
}

/// Per-validator cumulative counters sampled at the exact start of a local
/// benchmark's active transaction window. Rates subtract this snapshot so
/// connection warmup and shadow-WAL replay are not charged to the protocol.
#[derive(Clone, Debug, Default)]
pub struct LocalBenchmarkCounterBaseline {
    sequenced_transactions: u64,
    dag_state_entries: u64,
    bytes_sent: u64,
    bytes_received: u64,
    outbound_messages: Vec<(u64, u64)>,
}

#[derive(Clone, Copy, Debug)]
pub struct LocalBenchmarkTransactionOutcome {
    /// Exact successful sends across all honest local generators in the
    /// shared active window. Byzantine generators are disabled by the local
    /// harness, so this is the global set every honest validator must drain.
    pub offered_transactions: u64,
    /// Mean per-honest-validator commits observed at the common cutoff.
    pub cutoff_committed_transactions: u64,
    /// Mean per-honest-validator commits after the bounded drain.
    pub eventual_committed_transactions: u64,
    pub drain_elapsed: Duration,
    pub drain_complete: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct AutonomousClockBenchmarkSummary {
    valid_nodes: usize,
    progress_nodes: usize,
    bounded_nodes: usize,
    accepted_heartbeats: u64,
    delivered_carriers: u64,
    delivered_applications: u64,
    committed_frontiers: u64,
    frontier_applications: u64,
    projected_vertices: u64,
    projection_decisions: u64,
    wal_batches: u64,
    wal_records: u64,
    pending_recovery: i64,
    minimum_round: i64,
    maximum_round: i64,
    maximum_phase_backlog: i64,
    maximum_admitted_authors: i64,
    maximum_admitted_stake: i64,
    maximum_buffered_authenticated: i64,
    maximum_phase_backlog_bound: i64,
    maximum_buffered_authenticated_bound: i64,
    verdict_valid: bool,
}

fn summarize_autonomous_clock_benchmark(
    metrics: &[Arc<Metrics>],
    committee_size: usize,
    baselines: Option<&[AutonomousClockBenchmarkBaseline]>,
    cutoff_snapshots: Option<&[AutonomousClockBenchmarkSnapshot]>,
    embedded_rbc_authority: bool,
) -> AutonomousClockBenchmarkSummary {
    let committee_size = i64::try_from(committee_size).unwrap_or(i64::MAX);
    let maximum_phase_backlog_bound =
        STARFISH_RBC_DAG_AUTONOMOUS_MAX_PHASE_BACKLOG_FACTOR.saturating_mul(committee_size);
    let maximum_buffered_authenticated_bound =
        starfish_rbc_dag_autonomous_buffered_settled_bound(committee_size);

    // A supplied cutoff vector is authoritative. Missing entries fail closed
    // to the all-zero default rather than falling back to mutable drain-time
    // gauges and accidentally turning an invalid measured run into VALID.
    let observations = metrics
        .iter()
        .enumerate()
        .map(|(index, metrics)| match cutoff_snapshots {
            Some(snapshots) => snapshots.get(index).copied().unwrap_or_default(),
            None => metrics.autonomous_clock_benchmark_snapshot(),
        })
        .collect::<Vec<_>>();

    let valid_nodes = observations
        .iter()
        .filter(|snapshot| snapshot.clock_valid == 1)
        .count();
    let progress_nodes = observations
        .iter()
        .enumerate()
        .filter(|(index, snapshot)| {
            let baseline = baselines
                .and_then(|baselines| baselines.get(*index))
                .copied()
                .unwrap_or_default();
            snapshot.accepted_local_carriers() > baseline.accepted_local_carriers
                && snapshot.delivered_carriers > baseline.delivered_carriers
                && (!embedded_rbc_authority
                    || snapshot.delivered_applications > baseline.delivered_applications
                        && snapshot.committed_frontiers > baseline.committed_frontiers
                        && snapshot.frontier_applications > baseline.frontier_applications)
                && snapshot.projected_vertices > baseline.projected_vertices
                && snapshot.projection_decisions > baseline.projection_decisions
                && snapshot.wal_batches > baseline.wal_batches
                && snapshot.wal_records > baseline.wal_records
                && snapshot.carrier_round > baseline.carrier_round
        })
        .count();
    let bounded_nodes = observations
        .iter()
        .filter(|snapshot| {
            snapshot.phase_backlog >= 0
                && snapshot.phase_backlog <= maximum_phase_backlog_bound
                && snapshot.admitted_authors >= 0
                && snapshot.admitted_authors <= committee_size
                && snapshot.admitted_stake >= 0
                && snapshot.buffered_authenticated >= 0
                && snapshot.buffered_authenticated <= maximum_buffered_authenticated_bound
                && snapshot.pending_recovery == 0
        })
        .count();

    let accepted_heartbeats = observations
        .iter()
        .map(|snapshot| snapshot.accepted_heartbeats)
        .sum();
    let delivered_carriers = observations
        .iter()
        .map(|snapshot| snapshot.delivered_carriers)
        .sum();
    let delivered_applications = observations
        .iter()
        .map(|snapshot| snapshot.delivered_applications)
        .sum();
    let committed_frontiers = observations
        .iter()
        .map(|snapshot| snapshot.committed_frontiers)
        .sum();
    let frontier_applications = observations
        .iter()
        .map(|snapshot| snapshot.frontier_applications)
        .sum();
    let projected_vertices = observations
        .iter()
        .map(|snapshot| snapshot.projected_vertices)
        .sum();
    let projection_decisions = observations
        .iter()
        .map(|snapshot| snapshot.projection_decisions)
        .sum();
    let wal_batches = observations
        .iter()
        .map(|snapshot| snapshot.wal_batches)
        .sum();
    let wal_records = observations
        .iter()
        .map(|snapshot| snapshot.wal_records)
        .sum();
    let pending_recovery = observations
        .iter()
        .map(|snapshot| snapshot.pending_recovery)
        .sum();
    let minimum_round = observations
        .iter()
        .map(|snapshot| snapshot.carrier_round)
        .min()
        .unwrap_or_default();
    let maximum_round = observations
        .iter()
        .map(|snapshot| snapshot.carrier_round)
        .max()
        .unwrap_or_default();
    let maximum_phase_backlog = observations
        .iter()
        .map(|snapshot| snapshot.phase_backlog)
        .max()
        .unwrap_or_default();
    let maximum_admitted_authors = observations
        .iter()
        .map(|snapshot| snapshot.admitted_authors)
        .max()
        .unwrap_or_default();
    let maximum_admitted_stake = observations
        .iter()
        .map(|snapshot| snapshot.admitted_stake)
        .max()
        .unwrap_or_default();
    let maximum_buffered_authenticated = observations
        .iter()
        .map(|snapshot| snapshot.buffered_authenticated)
        .max()
        .unwrap_or_default();
    let round_lag = maximum_round.saturating_sub(minimum_round);
    let every_node_valid = valid_nodes == metrics.len();
    let every_node_progressed = progress_nodes == metrics.len();
    let every_node_bounded = bounded_nodes == metrics.len();
    let verdict_valid = !metrics.is_empty()
        && every_node_valid
        && every_node_progressed
        && every_node_bounded
        && round_lag <= STARFISH_RBC_DAG_AUTONOMOUS_MAX_ROUND_LAG;

    AutonomousClockBenchmarkSummary {
        valid_nodes,
        progress_nodes,
        bounded_nodes,
        accepted_heartbeats,
        delivered_carriers,
        delivered_applications,
        committed_frontiers,
        frontier_applications,
        projected_vertices,
        projection_decisions,
        wal_batches,
        wal_records,
        pending_recovery,
        minimum_round,
        maximum_round,
        maximum_phase_backlog,
        maximum_admitted_authors,
        maximum_admitted_stake,
        maximum_buffered_authenticated,
        maximum_phase_backlog_bound,
        maximum_buffered_authenticated_bound,
        verdict_valid,
    }
}

pub struct HistogramReporter<T> {
    pub histogram: PreciseHistogram<T>,
    gauge: IntGaugeVec,
}

pub struct VecHistogramReporter<T> {
    histograms: Vec<(PreciseHistogram<T>, String)>,
    gauge: IntGaugeVec,
}

fn set_gauge_max(gauge: &IntGauge, value: i64) {
    if value > gauge.get() {
        gauge.set(value);
    }
}

fn format_rbc_dag_round_distance(total: u64, samples: u64, maximum: i64) -> String {
    let average = if samples == 0 {
        0.0
    } else {
        total as f64 / samples as f64
    };
    format!("{average:.2}/{maximum} rounds (n={samples})")
}

impl Metrics {
    pub(crate) fn observe_starfish_rbc_dag_pipeline_latency_ns(
        &self,
        stage: &'static str,
        total_ns: u64,
        samples: u64,
        max_ns: u64,
    ) {
        debug_assert!(RBC_DAG_PIPELINE_LATENCY_STAGES.contains(&stage));
        // These stages follow the finite set of applications offered during
        // the common transaction window. Keep them open through the bounded
        // drain so delivery/frontier latency is not right-censored at the
        // submission cutoff. Protocol rates and round-distance observations
        // remain scoped by `metrics_active` below.
        if samples == 0 || !self.transaction_metrics_active.load(Ordering::Relaxed) {
            return;
        }
        self.starfish_rbc_dag_pipeline_latency_ns_total
            .with_label_values(&[stage])
            .inc_by(total_ns);
        self.starfish_rbc_dag_pipeline_latency_samples_total
            .with_label_values(&[stage])
            .inc_by(samples);
        set_gauge_max(
            &self
                .starfish_rbc_dag_pipeline_latency_ns_max
                .with_label_values(&[stage]),
            i64::try_from(max_ns).unwrap_or(i64::MAX),
        );
    }

    pub(crate) fn observe_starfish_rbc_dag_commit_round_distance(
        &self,
        kind: &'static str,
        total_rounds: u64,
        samples: u64,
        max_rounds: u64,
    ) {
        debug_assert!(RBC_DAG_COMMIT_DISTANCE_KINDS.contains(&kind));
        if samples == 0 || !self.metrics_active.load(Ordering::Relaxed) {
            return;
        }
        self.starfish_rbc_dag_commit_distance_rounds_total
            .with_label_values(&[kind])
            .inc_by(total_rounds);
        self.starfish_rbc_dag_commit_distance_samples_total
            .with_label_values(&[kind])
            .inc_by(samples);
        set_gauge_max(
            &self
                .starfish_rbc_dag_commit_distance_rounds_max
                .with_label_values(&[kind]),
            i64::try_from(max_rounds).unwrap_or(i64::MAX),
        );
    }

    pub(crate) fn set_starfish_rbc_dag_pipeline_state(
        &self,
        pending_local: usize,
        pending_projection: usize,
        highest_projected_round: u32,
        next_undecided_round: u32,
        next_undecided_projected_stake: u64,
        last_committed_round: u32,
        hol_state: &'static str,
    ) {
        debug_assert!(RBC_DAG_PROJECTION_HOL_STATES.contains(&hol_state));
        for (queue, depth) in [("local", pending_local), ("projection", pending_projection)] {
            let depth = i64::try_from(depth).unwrap_or(i64::MAX);
            self.starfish_rbc_dag_pipeline_queue_depth
                .with_label_values(&[queue])
                .set(depth);
            set_gauge_max(
                &self
                    .starfish_rbc_dag_pipeline_queue_depth_max
                    .with_label_values(&[queue]),
                depth,
            );
        }
        self.starfish_rbc_dag_highest_projected_consensus_round
            .set(i64::from(highest_projected_round));
        self.starfish_rbc_dag_next_undecided_consensus_round
            .set(i64::from(next_undecided_round));
        self.starfish_rbc_dag_next_undecided_projected_stake
            .set(i64::try_from(next_undecided_projected_stake).unwrap_or(i64::MAX));
        self.starfish_rbc_dag_last_committed_consensus_round
            .set(i64::from(last_committed_round));
        for state in RBC_DAG_PROJECTION_HOL_STATES {
            self.starfish_rbc_dag_projection_hol_state
                .with_label_values(&[state])
                .set(i64::from(*state == hol_state));
        }
    }

    pub(crate) fn starfish_rbc_dag_frontier_generated(&self) {
        self.starfish_rbc_dag_frontier_events_total
            .with_label_values(&["generated"])
            .inc();
        self.starfish_rbc_dag_frontiers_inflight.inc();
        set_gauge_max(
            &self.starfish_rbc_dag_frontiers_inflight_max,
            self.starfish_rbc_dag_frontiers_inflight.get(),
        );
    }

    pub(crate) fn starfish_rbc_dag_frontier_applied(&self) {
        self.starfish_rbc_dag_frontier_events_total
            .with_label_values(&["applied"])
            .inc();
        if self.starfish_rbc_dag_frontiers_inflight.get() > 0 {
            self.starfish_rbc_dag_frontiers_inflight.dec();
        }
        // `RbcDagAppliedFrontierObservationV1::observe` calls this only after
        // recording creation-to-frontier-applied latency. Publishing the
        // sequenced count last gives the benchmark an ordered drain barrier,
        // without confusing application samples (blocks) with transactions.
        self.starfish_rbc_dag_frontier_applied_sequenced_transactions
            .store(self.sequenced_transactions_total.get(), Ordering::Release);
    }

    pub(crate) fn starfish_rbc_dag_frontier_ignored(&self) {
        self.starfish_rbc_dag_frontier_events_total
            .with_label_values(&["ignored"])
            .inc();
        if self.starfish_rbc_dag_frontiers_inflight.get() > 0 {
            self.starfish_rbc_dag_frontiers_inflight.dec();
        }
    }

    pub fn autonomous_clock_benchmark_baseline(&self) -> AutonomousClockBenchmarkBaseline {
        let snapshot = self.autonomous_clock_benchmark_snapshot();
        AutonomousClockBenchmarkBaseline {
            accepted_local_carriers: snapshot.accepted_local_carriers(),
            delivered_carriers: snapshot.delivered_carriers,
            delivered_applications: snapshot.delivered_applications,
            committed_frontiers: snapshot.committed_frontiers,
            frontier_applications: snapshot.frontier_applications,
            projected_vertices: snapshot.projected_vertices,
            projection_decisions: snapshot.projection_decisions,
            wal_batches: snapshot.wal_batches,
            wal_records: snapshot.wal_records,
            carrier_round: snapshot.carrier_round,
        }
    }

    pub fn autonomous_clock_benchmark_snapshot(&self) -> AutonomousClockBenchmarkSnapshot {
        AutonomousClockBenchmarkSnapshot {
            accepted_heartbeats: self
                .starfish_rbc_dag_shadow_inputs_total
                .with_label_values(&["heartbeat", "accepted"])
                .get(),
            accepted_application_carriers: self
                .starfish_rbc_dag_shadow_inputs_total
                .with_label_values(&["application_carrier", "accepted"])
                .get(),
            delivered_carriers: self
                .starfish_rbc_dag_shadow_inputs_total
                .with_label_values(&["delivery", "shadow"])
                .get(),
            delivered_applications: self
                .starfish_rbc_dag_shadow_inputs_total
                .with_label_values(&["delivery", "embedded_application"])
                .get(),
            committed_frontiers: self
                .starfish_rbc_dag_shadow_inputs_total
                .with_label_values(&["frontier", "committed"])
                .get(),
            frontier_applications: self
                .starfish_rbc_dag_shadow_inputs_total
                .with_label_values(&["frontier", "application"])
                .get(),
            projected_vertices: self.starfish_rbc_dag_projected_vertices_total.get(),
            projection_decisions: self
                .starfish_rbc_dag_projection_decisions_total
                .with_label_values(&["direct_commit"])
                .get(),
            wal_batches: self
                .starfish_rbc_dag_shadow_wal_appended_batches_total
                .get(),
            wal_records: self
                .starfish_rbc_dag_shadow_wal_appended_records_total
                .get(),
            clock_valid: self.starfish_rbc_dag_shadow_clock_valid.get(),
            carrier_round: self.starfish_rbc_dag_shadow_carrier_round.get(),
            phase_backlog: self.starfish_rbc_dag_shadow_phase_backlog.get(),
            admitted_authors: self.starfish_rbc_dag_shadow_admitted_authors.get(),
            admitted_stake: self.starfish_rbc_dag_shadow_admitted_stake.get(),
            buffered_authenticated: self.starfish_rbc_dag_shadow_buffered_authenticated.get(),
            pending_recovery: self.starfish_rbc_dag_shadow_pending_recovery.get(),
        }
    }

    /// Number of offered applications whose authoritative RBC-DAG frontier
    /// has been applied locally and whose final pipeline-latency sample has
    /// therefore already been recorded.
    pub fn starfish_rbc_dag_frontier_applied_latency_samples(&self) -> u64 {
        self.starfish_rbc_dag_pipeline_latency_samples_total
            .with_label_values(&[RBC_DAG_LATENCY_CREATION_TO_FRONTIER_APPLIED])
            .get()
    }

    pub fn starfish_rbc_dag_frontier_applied_sequenced_transactions(&self) -> u64 {
        self.starfish_rbc_dag_frontier_applied_sequenced_transactions
            .load(Ordering::Acquire)
    }

    pub fn local_benchmark_counter_baseline(&self) -> LocalBenchmarkCounterBaseline {
        LocalBenchmarkCounterBaseline {
            sequenced_transactions: self.sequenced_transactions_total.get(),
            dag_state_entries: self.dag_state_entries.get(),
            bytes_sent: self.bytes_sent_total.get(),
            bytes_received: self.bytes_received_total.get(),
            outbound_messages: LOCAL_BENCHMARK_NETWORK_MESSAGE_TYPES
                .iter()
                .map(|request_type| {
                    (
                        self.network_message_bytes_sent_total
                            .with_label_values(&[request_type])
                            .get(),
                        self.network_requests_sent_total
                            .with_label_values(&[request_type])
                            .get(),
                    )
                })
                .collect(),
        }
    }

    pub fn new(
        registry: &Registry,
        committee: Option<&Committee>,
        consensus_protocol: Option<&str>,
        dissemination_mode: Option<&str>,
    ) -> (Arc<Self>, Arc<MetricReporter>) {
        // Write-once info gauges (kept alive by the registry).
        let committee_size_gauge = register_int_gauge_with_registry!(
            "committee_size",
            "Number of validators in the committee",
            registry,
        )
        .unwrap();
        committee_size_gauge.set(committee.map(Committee::len).unwrap_or(0) as i64);

        let protocol_info = register_int_gauge_vec_with_registry!(
            "consensus_protocol_info",
            "Active consensus protocol (label carries the name)",
            &["protocol"],
            registry,
        )
        .unwrap();
        if let Some(name) = consensus_protocol {
            protocol_info.with_label_values(&[name]).set(1);
        }

        let dissemination_info = register_int_gauge_vec_with_registry!(
            "dissemination_mode_info",
            "Active dissemination mode (label carries the name)",
            &["mode"],
            registry,
        )
        .unwrap();
        if let Some(name) = dissemination_mode {
            dissemination_info.with_label_values(&[name]).set(1);
        }
        let (transaction_committed_latency_hist, transaction_committed_latency) = histogram();
        let (block_committed_latency_hist, block_committed_latency) = histogram();

        let (proposed_block_size_bytes_hist, proposed_block_size_bytes) = histogram();
        let (proposed_header_size_bytes_hist, proposed_header_size_bytes) = histogram();
        let (proposed_transaction_size_bytes_hist, proposed_transaction_size_bytes) = histogram();
        let (block_bundle_size_bytes_hist, block_bundle_size_bytes) = histogram();

        let committee_size = committee.map(Committee::len).unwrap_or_default();
        let (connection_latency_hist, connection_latency_sender) = (0..committee_size)
            .map(|peer| {
                let (hist, sender) = histogram();
                ((hist, format!("node-{peer}")), sender)
            })
            .unzip();
        let reporter = MetricReporter {
            transaction_committed_latency: parking_lot::Mutex::new(
                HistogramReporter::new_in_registry(
                    transaction_committed_latency_hist,
                    registry,
                    "transaction_committed_latency",
                ),
            ),

            block_committed_latency: parking_lot::Mutex::new(HistogramReporter::new_in_registry(
                block_committed_latency_hist,
                registry,
                "block_committed_latency",
            )),

            proposed_block_size_bytes: parking_lot::Mutex::new(HistogramReporter::new_in_registry(
                proposed_block_size_bytes_hist,
                registry,
                "proposed_block_size_bytes",
            )),

            proposed_header_size_bytes: parking_lot::Mutex::new(
                HistogramReporter::new_in_registry(
                    proposed_header_size_bytes_hist,
                    registry,
                    "proposed_header_size_bytes",
                ),
            ),

            proposed_transaction_size_bytes: parking_lot::Mutex::new(
                HistogramReporter::new_in_registry(
                    proposed_transaction_size_bytes_hist,
                    registry,
                    "proposed_transaction_size_bytes",
                ),
            ),

            block_bundle_size_bytes: parking_lot::Mutex::new(HistogramReporter::new_in_registry(
                block_bundle_size_bytes_hist,
                registry,
                "block_bundle_size_bytes",
            )),

            connection_latency: parking_lot::Mutex::new(VecHistogramReporter::new_in_registry(
                connection_latency_hist,
                "peer",
                registry,
                "connection_latency",
            )),

            global_in_memory_blocks: register_int_gauge_with_registry!(
                "global_in_memory_blocks",
                "Number of blocks loaded in memory",
                registry,
            )
            .unwrap(),
            global_in_memory_blocks_bytes: register_int_gauge_with_registry!(
                "global_in_memory_blocks_bytes",
                "Total size of blocks loaded in memory",
                registry,
            )
            .unwrap(),
        };
        let metrics = Self {
            benchmark_duration: register_int_counter_with_registry!(
                BENCHMARK_DURATION,
                "Duration of the benchmark",
                registry,
            )
            .unwrap(),
            committed_leaders_total: register_int_counter_vec_with_registry!(
                "committed_leaders_total",
                "Total number of (direct or indirect) committed leaders per authority",
                &["authority", "commit_type"],
                registry,
            )
            .unwrap(),
            filtered_blocks_total: register_int_counter_with_registry!(
                "filtered_blocks_total",
                "Total number of filtered blocks per authority",
                registry,
            )
            .unwrap(),
            filtered_shards_total: register_int_counter_with_registry!(
                "filtered_shards_total",
                "Total number of filtered standalone shards",
                registry,
            )
            .unwrap(),
            processed_after_filtering_total: register_int_counter_with_registry!(
                "processed_after_filtering_total",
                "Total number of blocks processed after filtering",
                registry,
            )
            .unwrap(),
            reconstructed_blocks_total: register_int_counter_with_registry!(
                "reconstructed_blocks_total",
                "Total number of reconstructed blocks",
                registry,
            )
            .unwrap(),
            shard_reconstruction_jobs_total: register_int_counter_with_registry!(
                "shard_reconstruction_jobs_total",
                "Total number of shard reconstruction jobs queued",
                registry,
            )
            .unwrap(),
            shard_reconstruction_success_total: register_int_counter_with_registry!(
                "shard_reconstruction_success_total",
                "Total number of successfully reconstructed blocks",
                registry,
            )
            .unwrap(),
            shard_reconstruction_failed_total: register_int_counter_with_registry!(
                "shard_reconstruction_failed_total",
                "Total number of failed shard reconstruction attempts",
                registry,
            )
            .unwrap(),
            shard_reconstruction_cancelled_total: register_int_counter_with_registry!(
                "shard_reconstruction_cancelled_total",
                "Total number of shard reconstruction cancellations due to full blocks",
                registry,
            )
            .unwrap(),
            shard_reconstruction_pending_accumulators: register_int_gauge_with_registry!(
                "shard_reconstruction_pending_accumulators",
                "Current number of blocks accumulating shards",
                registry,
            )
            .unwrap(),
            shard_reconstruction_queued_jobs: register_int_gauge_with_registry!(
                "shard_reconstruction_queued_jobs",
                "Current number of queued/in-flight shard reconstruction jobs",
                registry,
            )
            .unwrap(),
            shard_reconstruction_pending_decoded_blocks: register_int_gauge_with_registry!(
                "shard_reconstruction_pending_decoded_blocks",
                "Current number of decoded blocks pending flush to core",
                registry,
            )
            .unwrap(),
            shard_reconstruction_lag: {
                let buckets = vec![
                    0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0,
                ];
                register_histogram_with_registry!(
                    HistogramOpts::new(
                        "shard_reconstruction_lag",
                        "Round lag between DAG head and reconstructed block",
                    )
                    .buckets(buckets),
                    registry,
                )
                .unwrap()
            },
            used_additional_blocks_total: register_int_counter_with_registry!(
                "used_additional_blocks_total",
                "Total number of times additional blocks that were used in batches",
                registry,
            )
            .unwrap(),
            submitted_transactions: register_int_counter_with_registry!(
                "submitted_transactions",
                "Total number of submitted transactions",
                registry,
            )
            .unwrap(),
            submitted_transactions_bytes: register_int_counter_with_registry!(
                "submitted_transactions_bytes",
                "Total bytes of submitted transactions",
                registry,
            )
            .unwrap(),
            store_block_latency_us: register_int_counter_with_registry!(
                "store_block_latency_us",
                "Cumulative store_block latency in microseconds",
                registry,
            )
            .unwrap(),
            store_block_count: register_int_counter_with_registry!(
                "store_block_count",
                "Total number of store_block calls",
                registry,
            )
            .unwrap(),
            store_commits_latency_us: register_int_counter_with_registry!(
                "store_commits_latency_us",
                "Cumulative store_commits latency in microseconds",
                registry,
            )
            .unwrap(),
            store_commits_count: register_int_counter_with_registry!(
                "store_commits_count",
                "Total number of store_commits calls",
                registry,
            )
            .unwrap(),
            storage_backend_info: register_int_gauge_with_registry!(
                "storage_backend_info",
                "Storage backend: 0 = RocksDB, 1 = TideHunter",
                registry,
            )
            .unwrap(),
            transaction_mode_info: register_int_gauge_with_registry!(
                "transaction_mode_info",
                "Transaction mode: 0 = AllZero, 1 = Random",
                registry,
            )
            .unwrap(),
            bytes_sent_total: register_int_counter_with_registry!(
                "bytes_sent_total",
                "Total number of bytes sent",
                registry,
            )
            .unwrap(),
            bytes_uncompressed_sent_total: register_int_counter_with_registry!(
                "bytes_uncompressed_sent_total",
                "Total pre-compression bytes sent (for compression ratio)",
                registry,
            )
            .unwrap(),
            bytes_received_total: register_int_counter_with_registry!(
                "bytes_received_total",
                "Total number of bytes received",
                registry,
            )
            .unwrap(),
            network_requests_sent_total: register_int_counter_vec_with_registry!(
                "network_requests_sent_total",
                "Total network requests sent, by type",
                &["request_type"],
                registry,
            )
            .unwrap(),
            network_requests_received_total: register_int_counter_vec_with_registry!(
                "network_requests_received_total",
                "Total network requests received, by type",
                &["request_type"],
                registry,
            )
            .unwrap(),
            network_message_bytes_sent_total: register_int_counter_vec_with_registry!(
                "network_message_bytes_sent_total",
                "Total framed network-message bytes sent, by type",
                &["request_type"],
                registry,
            )
            .unwrap(),
            network_message_bytes_received_total: register_int_counter_vec_with_registry!(
                "network_message_bytes_received_total",
                "Total framed network-message bytes received, by type",
                &["request_type"],
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_inputs_total: register_int_counter_vec_with_registry!(
                "starfish_rbc_dag_shadow_inputs_total",
                "Starfish-RBC-DAG shadow inputs, by bounded input kind and processing outcome",
                &["kind", "outcome"],
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_delivery_comparisons_total:
                register_int_counter_vec_with_registry!(
                    "starfish_rbc_dag_shadow_delivery_comparisons_total",
                    "Non-authoritative current-process paired direct-vs-shadow delivery observations, by outcome; unmatched observations are not mismatches",
                    &["outcome"],
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_shadow_wal_appended_batches_total:
                register_int_counter_with_registry!(
                    "starfish_rbc_dag_shadow_wal_appended_batches_total",
                    "Starfish-RBC-DAG shadow WAL batches appended to the framed log",
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_shadow_wal_appended_records_total:
                register_int_counter_with_registry!(
                    "starfish_rbc_dag_shadow_wal_appended_records_total",
                    "Starfish-RBC-DAG shadow WAL records appended to the framed log",
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_shadow_wal_durable_batches_total: register_int_counter_with_registry!(
                "starfish_rbc_dag_shadow_wal_durable_batches_total",
                "Starfish-RBC-DAG shadow WAL batches synchronized before event exposure",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_wal_durable_records_total: register_int_counter_with_registry!(
                "starfish_rbc_dag_shadow_wal_durable_records_total",
                "Starfish-RBC-DAG shadow WAL records synchronized before event exposure",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_wal_replayed_batches: register_int_gauge_with_registry!(
                "starfish_rbc_dag_shadow_wal_replayed_batches",
                "Starfish-RBC-DAG shadow WAL batches replayed during this process startup",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_wal_discarded_tail_bytes_total:
                register_int_counter_with_registry!(
                    "starfish_rbc_dag_shadow_wal_discarded_tail_bytes_total",
                    "Physically incomplete final Starfish-RBC-DAG shadow WAL bytes discarded during recovery",
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_shadow_pending_recovery: register_int_gauge_with_registry!(
                "starfish_rbc_dag_shadow_pending_recovery",
                "Current Starfish-RBC-DAG shadow carrier-content recoveries pending",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_unpaired_direct: register_int_gauge_with_registry!(
                "starfish_rbc_dag_shadow_unpaired_direct",
                "Current direct-delivery slots without an observed shadow-delivery slot, including recovered shadow state",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_unpaired_shadow: register_int_gauge_with_registry!(
                "starfish_rbc_dag_shadow_unpaired_shadow",
                "Current shadow-delivery slots first observed in this process without a direct-delivery slot observed in this process",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_unpaired_max_round_lag: register_int_gauge_with_registry!(
                "starfish_rbc_dag_shadow_unpaired_max_round_lag",
                "Maximum round lag from a current unpaired direct or current-epoch shadow delivery slot to the newest current-process observation",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_comparison_valid: register_int_gauge_with_registry!(
                "starfish_rbc_dag_shadow_comparison_valid",
                "State of the non-authoritative shadow observation stream (1 valid, 0 disabled/invalid, -1 starting)",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_clock_valid: register_int_gauge_with_registry!(
                "starfish_rbc_dag_shadow_clock_valid",
                "State of the autonomous RBC-DAG carrier clock and projection runtime (1 valid, 0 disabled/invalid, -1 starting)",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_carrier_round: register_int_gauge_with_registry!(
                "starfish_rbc_dag_shadow_carrier_round",
                "Currently open sequential Starfish-RBC-DAG shadow carrier round",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_phase_backlog: register_int_gauge_with_registry!(
                "starfish_rbc_dag_shadow_phase_backlog",
                "Pending embedded ECHO/READY statements in the autonomous carrier actor",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_admitted_authors: register_int_gauge_with_registry!(
                "starfish_rbc_dag_shadow_admitted_authors",
                "Distinct authors admitted in the currently open carrier round",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_admitted_stake: register_int_gauge_with_registry!(
                "starfish_rbc_dag_shadow_admitted_stake",
                "Stake admitted in the currently open carrier round",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_shadow_buffered_authenticated: register_int_gauge_with_registry!(
                "starfish_rbc_dag_shadow_buffered_authenticated",
                "Authenticated future carrier slots buffered outside the current admission window",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_projected_vertices_total: register_int_counter_with_registry!(
                "starfish_rbc_dag_projected_vertices_total",
                "RBC-delivered, data-available consensus vertices admitted to the certified carrier projection",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_projection_decisions_total:
                register_int_counter_vec_with_registry!(
                    "starfish_rbc_dag_projection_decisions_total",
                    "Clean-only Starfish leader decisions produced by the certified carrier projection",
                    &["outcome"],
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_pipeline_latency_ns_total:
                register_int_counter_vec_with_registry!(
                    "starfish_rbc_dag_pipeline_latency_ns_total",
                    "Active-window application latency nanoseconds accumulated by bounded RBC-DAG pipeline stage",
                    &["stage"],
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_pipeline_latency_samples_total:
                register_int_counter_vec_with_registry!(
                    "starfish_rbc_dag_pipeline_latency_samples_total",
                    "Active-window application latency sample count by bounded RBC-DAG pipeline stage",
                    &["stage"],
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_pipeline_latency_ns_max: register_int_gauge_vec_with_registry!(
                "starfish_rbc_dag_pipeline_latency_ns_max",
                "Maximum active-window application latency nanoseconds by bounded RBC-DAG pipeline stage",
                &["stage"],
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_commit_distance_rounds_total:
                register_int_counter_vec_with_registry!(
                    "starfish_rbc_dag_commit_distance_rounds_total",
                    "Active-window round-distance magnitude accumulated for first-committed RBC-DAG applications",
                    &["kind"],
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_commit_distance_samples_total:
                register_int_counter_vec_with_registry!(
                    "starfish_rbc_dag_commit_distance_samples_total",
                    "Active-window first-committed RBC-DAG application sample count by round-distance kind",
                    &["kind"],
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_commit_distance_rounds_max:
                register_int_gauge_vec_with_registry!(
                    "starfish_rbc_dag_commit_distance_rounds_max",
                    "Maximum active-window first-committed RBC-DAG application round-distance magnitude",
                    &["kind"],
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_pipeline_queue_depth: register_int_gauge_vec_with_registry!(
                "starfish_rbc_dag_pipeline_queue_depth",
                "Current RBC-DAG pipeline queue depth by bounded queue name",
                &["queue"],
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_pipeline_queue_depth_max: register_int_gauge_vec_with_registry!(
                "starfish_rbc_dag_pipeline_queue_depth_max",
                "Process-high-water RBC-DAG pipeline queue depth by bounded queue name",
                &["queue"],
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_highest_projected_consensus_round:
                register_int_gauge_with_registry!(
                    "starfish_rbc_dag_highest_projected_consensus_round",
                    "Highest clean consensus round projected by this RBC-DAG runtime",
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_next_undecided_consensus_round:
                register_int_gauge_with_registry!(
                    "starfish_rbc_dag_next_undecided_consensus_round",
                    "Oldest clean projected consensus round not yet decided",
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_next_undecided_projected_stake:
                register_int_gauge_with_registry!(
                    "starfish_rbc_dag_next_undecided_projected_stake",
                    "Projected distinct-author stake at the oldest undecided consensus round",
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_last_committed_consensus_round:
                register_int_gauge_with_registry!(
                    "starfish_rbc_dag_last_committed_consensus_round",
                    "Highest consensus round whose committed frontier was generated",
                    registry,
                )
                .unwrap(),
            starfish_rbc_dag_projection_hol_state: register_int_gauge_vec_with_registry!(
                "starfish_rbc_dag_projection_hol_state",
                "One-hot current certified-projection head-of-line state",
                &["reason"],
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_frontier_events_total: register_int_counter_vec_with_registry!(
                "starfish_rbc_dag_frontier_events_total",
                "Committed RBC-DAG frontier lifecycle events by bounded stage",
                &["stage"],
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_frontiers_inflight: register_int_gauge_with_registry!(
                "starfish_rbc_dag_frontiers_inflight",
                "Committed RBC-DAG frontiers generated but not yet applied or ignored",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_frontiers_inflight_max: register_int_gauge_with_registry!(
                "starfish_rbc_dag_frontiers_inflight_max",
                "Process-high-water committed RBC-DAG frontiers awaiting event application",
                registry,
            )
            .unwrap(),
            starfish_rbc_dag_frontier_applied_sequenced_transactions: Arc::new(AtomicU64::new(0)),
            subscribed_to_peers: register_int_gauge_with_registry!(
                "subscribed_to_peers",
                "Number of peers this validator is subscribed to",
                registry,
            )
            .unwrap(),
            subscribed_by_peers: register_int_gauge_with_registry!(
                "subscribed_by_peers",
                "Number of peers subscribed to this validator",
                registry,
            )
            .unwrap(),
            useful_authorities: register_int_gauge_vec_with_registry!(
                "useful_authorities",
                "Number of useful authorities per peer by kind",
                &["peer", "kind"],
                registry,
            )
            .unwrap(),
            bls_certificates_total: register_int_counter_vec_with_registry!(
                "bls_certificates_total",
                "Total completed BLS certificates by type",
                &["type"],
                registry,
            )
            .unwrap(),
            bls_dac_rejections_total: register_int_counter_with_registry!(
                "bls_dac_rejections_total",
                "Total DAC certificates that failed verification",
                registry,
            )
            .unwrap(),
            bls_blocks_processed_total: register_int_counter_with_registry!(
                "bls_blocks_processed_total",
                "Total blocks processed by BLS service",
                registry,
            )
            .unwrap(),
            bls_standalone_dac_sigs_total: register_int_counter_with_registry!(
                "bls_standalone_dac_sigs_total",
                "Total standalone DAC partial signatures processed",
                registry,
            )
            .unwrap(),
            bls_service_util: register_int_counter_with_registry!(
                "bls_service_util",
                "BLS service utilization timer (microseconds)",
                registry,
            )
            .unwrap(),
            bls_batch_verification_failures_total: register_int_counter_with_registry!(
                "bls_batch_verification_failures_total",
                "Total partial signatures that failed batch verification",
                registry,
            )
            .unwrap(),
            bls_presign_total: register_int_counter_vec_with_registry!(
                "bls_presign_total",
                "Total pre-computed BLS partial signatures by kind",
                &["kind"],
                registry,
            )
            .unwrap(),
            bls_presign_hit_total: register_int_counter_with_registry!(
                "bls_presign_hit_total",
                "Pre-computed BLS sig available at block creation",
                registry,
            )
            .unwrap(),
            bls_presign_miss_total: register_int_counter_with_registry!(
                "bls_presign_miss_total",
                "Pre-computed BLS sig not available at block creation",
                registry,
            )
            .unwrap(),
            bls_dac_sigs_deferred_total: register_int_counter_with_registry!(
                "bls_dac_sigs_deferred_total",
                "Ticks where DAC sigs were deferred due to consensus backlog",
                registry,
            )
            .unwrap(),
            leader_timeout_total: register_int_counter_with_registry!(
                "leader_timeout_total",
                "Total number of leader timeouts",
                registry,
            )
            .unwrap(),
            proposal_wait_time_total_us: register_int_counter_with_registry!(
                "proposal_wait_time_total_us",
                "Cumulative proposal wait time (microseconds)",
                registry,
            )
            .unwrap(),
            sequenced_transactions_total: register_int_counter_with_registry!(
                "sequenced_transactions_total",
                "Total number of sequenced transactions",
                registry,
            )
            .unwrap(),
            sequenced_transactions_cutoff_total: register_int_counter_with_registry!(
                "sequenced_transactions_cutoff_total",
                "Transactions sequenced before the coordinated benchmark cutoff",
                registry,
            )
            .unwrap(),
            sequenced_transactions_bytes: register_int_counter_with_registry!(
                "sequenced_transactions_bytes",
                "Total bytes of sequenced transactions",
                registry,
            )
            .unwrap(),
            sailfish_rbc_fast_total: register_int_counter_with_registry!(
                "sailfish_rbc_fast_total",
                "Sailfish++ RBC certifications via fast path (echo quorum)",
                registry,
            )
            .unwrap(),
            sailfish_rbc_slow_total: register_int_counter_with_registry!(
                "sailfish_rbc_slow_total",
                "Sailfish++ RBC certifications via slow path (ready quorum)",
                registry,
            )
            .unwrap(),

            dag_state_loaded_blocks: register_int_counter_with_registry!(
                "dag_state_loaded_blocks",
                "Blocks loaded from wal position in the DAG state",
                registry,
            )
            .unwrap(),
            dag_state_unloaded_blocks: register_int_counter_with_registry!(
                "dag_state_unloaded_blocks",
                "Blocks unloaded from wal position during cleanup",
                registry,
            )
            .unwrap(),
            dag_state_entries: register_int_counter_with_registry!(
                "dag_state_entries",
                "Number of entries in DAG state",
                registry,
            )
            .unwrap(),
            dag_state_cleanup_util: register_int_counter_with_registry!(
                "dag_state_cleanup_util",
                "dag_state_cleanup_util",
                registry,
            )
            .unwrap(),

            dag_highest_round: register_int_gauge_with_registry!(
                "dag_highest_round",
                "Highest round in the in-memory DAG",
                registry,
            )
            .unwrap(),
            dag_lowest_round: register_int_gauge_with_registry!(
                "dag_lowest_round",
                "Lowest round retained in the in-memory DAG",
                registry,
            )
            .unwrap(),
            dag_blocks_in_memory: register_int_gauge_with_registry!(
                "dag_blocks_in_memory",
                "Number of block entries in the in-memory DAG",
                registry,
            )
            .unwrap(),

            wal_mappings: register_int_gauge_with_registry!(
                "wal_mappings",
                "Number of mappings retained by the wal",
                registry,
            )
            .unwrap(),

            core_lock_util: register_int_counter_with_registry!(
                "core_lock_util",
                "Utilization of core write lock",
                registry,
            )
            .unwrap(),
            core_lock_enqueued: register_int_counter_with_registry!(
                "core_lock_enqueued",
                "Number of enqueued core requests",
                registry,
            )
            .unwrap(),
            core_lock_dequeued: register_int_counter_with_registry!(
                "core_lock_dequeued",
                "Number of dequeued core requests",
                registry,
            )
            .unwrap(),
            core_queue_length: register_int_gauge_with_registry!(
                "core_queue_length",
                "Current number of tasks in the core thread channel",
                registry,
            )
            .unwrap(),
            core_thread_tasks_total: register_int_counter_vec_with_registry!(
                "core_thread_tasks_total",
                "Total core thread commands processed, by task type",
                &["task_type"],
                registry,
            )
            .unwrap(),
            block_handler_cleanup_util: register_int_counter_with_registry!(
                "block_handler_cleanup_util",
                "block_handler_cleanup_util",
                registry,
            )
            .unwrap(),
            missing_blocks: register_int_gauge_vec_with_registry!(
                "missing_blocks",
                "Number of missing blocks per authority",
                &["authority"],
                registry,
            )
            .unwrap(),
            block_manager_pending_blocks: register_int_gauge_with_registry!(
                "block_manager_pending_blocks",
                "Blocks in BlockManager waiting for parent dependencies",
                registry,
            )
            .unwrap(),
            core_pending_reconstructed_data: register_int_gauge_with_registry!(
                "core_pending_reconstructed_data",
                "Reconstructed transaction data buffered waiting for headers",
                registry,
            )
            .unwrap(),
            block_sync_requests_sent: register_int_counter_vec_with_registry!(
                "block_sync_requests_sent",
                "Number of block sync requests sent per authority",
                &["authority"],
                registry,
            )
            .unwrap(),
            block_sync_requests_received: register_int_counter_vec_with_registry!(
                "block_sync_requests_received",
                "Number of block sync requests received per peer",
                &["peer"],
                registry,
            )
            .unwrap(),
            tx_data_requests_sent: register_int_counter_vec_with_registry!(
                "tx_data_requests_sent",
                "Number of transaction-data sync requests sent per authority",
                &["authority"],
                registry,
            )
            .unwrap(),
            tx_data_requests_received: register_int_counter_vec_with_registry!(
                "tx_data_requests_received",
                "Number of transaction-data sync requests received per peer",
                &["peer"],
                registry,
            )
            .unwrap(),
            committed_blocks: register_int_counter_vec_with_registry!(
                "committed_blocks",
                "Total number of committed blocks proposed by authorities",
                &["authority"],
                registry,
            )
            .unwrap(),
            utilization_timer: register_int_counter_vec_with_registry!(
                "utilization_timer",
                "Utilization timer",
                &["proc"],
                registry,
            )
            .unwrap(),
            block_committed_latency,
            block_committed_latency_squared_micros: register_int_counter_with_registry!(
                "block_committed_latency_squared_micros",
                "Square of total end-to-end latency of a block commitment in seconds",
                registry,
            )
            .unwrap(),
            transaction_committed_latency,
            transaction_committed_latency_squared_micros: register_int_counter_with_registry!(
                "transaction_committed_latency_squared_micros",
                "Square of total end-to-end latency of a transaction commitment in seconds",
                registry,
            )
            .unwrap(),

            proposed_block_size_bytes,
            proposed_header_size_bytes,
            proposed_transaction_size_bytes,
            block_bundle_size_bytes,
            proposed_block_refs: {
                let buckets: Vec<f64> = (0..=200).map(|i| i as f64).collect();
                register_histogram_vec_with_registry!(
                    HistogramOpts::new(
                        "proposed_block_refs",
                        "Number of block references in proposed blocks",
                    )
                    .buckets(buckets),
                    &["role"],
                    registry,
                )
                .unwrap()
            },
            proposed_block_acks: {
                let buckets: Vec<f64> = (0..=200).map(|i| i as f64).collect();
                register_histogram_vec_with_registry!(
                    HistogramOpts::new(
                        "proposed_block_acks",
                        "Number of acknowledgment references in proposed blocks \
                         (including virtual acknowledgments from block \
                         references)", // editorconfig-checker-disable-line
                    )
                    .buckets(buckets),
                    &["role"],
                    registry,
                )
                .unwrap()
            },
            created_own_blocks: register_int_counter_vec_with_registry!(
                "created_own_blocks",
                "Total number of blocks created by this validator",
                &["reason"],
                registry,
            )
            .unwrap(),
            previous_round_refs: {
                let mut buckets: Vec<f64> = (1..=100).map(|i| i as f64).collect();
                let mut v = 200.0;
                while v <= 10000.0 {
                    buckets.push(v);
                    v *= 2.0;
                }
                register_histogram_with_registry!(
                    HistogramOpts::new(
                        "previous_round_refs",
                        "Number of references from the previous round in proposed blocks",
                    )
                    .buckets(buckets),
                    registry,
                )
                .unwrap()
            },

            commit_gap: {
                let buckets = vec![
                    0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0,
                ];
                register_histogram_with_registry!(
                    HistogramOpts::new(
                        "commit_gap",
                        "Round gap between committed leader and sequenced data block",
                    )
                    .buckets(buckets),
                    registry,
                )
                .unwrap()
            },

            connection_latency_sender,

            commit_digest: register_int_gauge_with_registry!(
                "commit_digest",
                "Rolling hash of committed leader sequence (sampled every 100 commits)",
                registry,
            )
            .unwrap(),
            commit_digest_latest: register_int_gauge_with_registry!(
                "commit_digest_latest",
                "Rolling hash of committed leader sequence (updated every commit)",
                registry,
            )
            .unwrap(),
            commit_index: register_int_gauge_with_registry!(
                "commit_index",
                "Number of committed leaders",
                registry,
            )
            .unwrap(),
            commit_availability_gap: register_int_gauge_with_registry!(
                "commit_availability_gap",
                "Gap between last commit and last commit with available transactions",
                registry,
            )
            .unwrap(),

            accepted_blocks_by_source: register_int_counter_vec_with_registry!(
                "accepted_blocks_by_source",
                "Total accepted full blocks by data source",
                &["source"],
                registry,
            )
            .unwrap(),
            accepted_headers_by_source: register_int_counter_vec_with_registry!(
                "accepted_headers_by_source",
                "Total accepted header-only blocks by data source",
                &["source"],
                registry,
            )
            .unwrap(),
            accepted_transactions_by_source: register_int_counter_vec_with_registry!(
                "accepted_transactions_by_source",
                "Total accepted transaction data attachments by data source",
                &["source"],
                registry,
            )
            .unwrap(),

            ck_known_headers: register_int_gauge_with_registry!(
                "ck_known_headers",
                "Global CordialKnowledge header dedup set size",
                registry,
            )
            .unwrap(),
            ck_known_shards: register_int_gauge_with_registry!(
                "ck_known_shards",
                "Global CordialKnowledge shard dedup set size",
                registry,
            )
            .unwrap(),
            ck_pending_headers: register_int_gauge_with_registry!(
                "ck_pending_headers",
                "Total queued headers across all authorities",
                registry,
            )
            .unwrap(),
            ck_pending_shards: register_int_gauge_with_registry!(
                "ck_pending_shards",
                "Total queued shards across all authorities",
                registry,
            )
            .unwrap(),
            ck_peer_known_headers: register_int_gauge_vec_with_registry!(
                "ck_peer_known_headers",
                "Per-peer header dedup set size",
                &["peer"],
                registry,
            )
            .unwrap(),
            ck_peer_known_shards: register_int_gauge_vec_with_registry!(
                "ck_peer_known_shards",
                "Per-peer shard dedup set size",
                &["peer"],
                registry,
            )
            .unwrap(),
            // Default to active=true for production (no benchmark_duration
            // bound). The transaction generator overrides to false during
            // its warmup when the orchestrator sets a finite duration.
            metrics_active: Arc::new(AtomicBool::new(true)),
            transaction_metrics_active: Arc::new(AtomicBool::new(true)),
            benchmark_generator_state: Arc::new(AtomicU8::new(
                BenchmarkGeneratorState::Disabled as u8,
            )),
            benchmark_transaction_cutoff_micros: Arc::new(AtomicU64::new(0)),
            active_start_micros: Arc::new(AtomicU64::new(0)),
            validator_start: tokio::time::Instant::now(),
        };

        (Arc::new(metrics), Arc::new(reporter))
    }

    pub fn aggregate_and_display(
        metrics: Vec<Arc<Metrics>>,
        reporters: Vec<Arc<MetricReporter>>,
        duration_secs: u64,
        committee_size: usize,
        starfish_rbc_dag_shadow_expected: bool,
        starfish_rbc_dag_autonomous_clock_expected: bool,
        starfish_rbc_dag_embedded_rbc_authority_expected: bool,
        autonomous_clock_baselines: Option<Vec<AutonomousClockBenchmarkBaseline>>,
        autonomous_clock_cutoffs: Option<Vec<AutonomousClockBenchmarkSnapshot>>,
        counter_baselines: Option<Vec<LocalBenchmarkCounterBaseline>>,
        counter_cutoffs: Option<Vec<LocalBenchmarkCounterBaseline>>,
        transaction_outcome: Option<LocalBenchmarkTransactionOutcome>,
    ) {
        let num_validators = metrics.len() as u64;

        // Calculate overall statistics
        let average_transactions: u64 = metrics
            .iter()
            .enumerate()
            .map(|(index, metrics)| {
                metrics.sequenced_transactions_total.get().saturating_sub(
                    counter_baselines
                        .as_ref()
                        .and_then(|baselines| baselines.get(index))
                        .map(|baseline| baseline.sequenced_transactions)
                        .unwrap_or_default(),
                )
            })
            .sum::<u64>()
            / num_validators;
        let cutoff_transactions = transaction_outcome
            .map(|outcome| outcome.cutoff_committed_transactions)
            .unwrap_or(average_transactions);
        let average_tps = cutoff_transactions as f64 / duration_secs as f64;

        let average_blocks_submitted = metrics
            .iter()
            .enumerate()
            .map(|(index, metrics)| {
                counter_cutoffs
                    .as_ref()
                    .and_then(|cutoffs| cutoffs.get(index))
                    .map(|cutoff| cutoff.dag_state_entries)
                    .unwrap_or_else(|| metrics.dag_state_entries.get())
                    .saturating_sub(
                        counter_baselines
                            .as_ref()
                            .and_then(|baselines| baselines.get(index))
                            .map(|baseline| baseline.dag_state_entries)
                            .unwrap_or_default(),
                    )
            })
            .sum::<u64>()
            / num_validators;
        let average_bps = average_blocks_submitted as f64 / duration_secs as f64;

        let average_bytes_sent: u64 = metrics
            .iter()
            .enumerate()
            .map(|(index, metrics)| {
                counter_cutoffs
                    .as_ref()
                    .and_then(|cutoffs| cutoffs.get(index))
                    .map(|cutoff| cutoff.bytes_sent)
                    .unwrap_or_else(|| metrics.bytes_sent_total.get())
                    .saturating_sub(
                        counter_baselines
                            .as_ref()
                            .and_then(|baselines| baselines.get(index))
                            .map(|baseline| baseline.bytes_sent)
                            .unwrap_or_default(),
                    )
            })
            .sum::<u64>()
            / num_validators;
        let average_bytes_received: u64 = metrics
            .iter()
            .enumerate()
            .map(|(index, metrics)| {
                counter_cutoffs
                    .as_ref()
                    .and_then(|cutoffs| cutoffs.get(index))
                    .map(|cutoff| cutoff.bytes_received)
                    .unwrap_or_else(|| metrics.bytes_received_total.get())
                    .saturating_sub(
                        counter_baselines
                            .as_ref()
                            .and_then(|baselines| baselines.get(index))
                            .map(|baseline| baseline.bytes_received)
                            .unwrap_or_default(),
                    )
            })
            .sum::<u64>()
            / num_validators;
        let average_reconstructed_sent_to_core: u64 = metrics
            .iter()
            .map(|m| m.reconstructed_blocks_total.get())
            .sum::<u64>()
            / num_validators;
        let average_reconstruction_jobs: u64 = metrics
            .iter()
            .map(|m| m.shard_reconstruction_jobs_total.get())
            .sum::<u64>()
            / num_validators;
        let average_reconstruction_success: u64 = metrics
            .iter()
            .map(|m| m.shard_reconstruction_success_total.get())
            .sum::<u64>()
            / num_validators;
        let average_reconstruction_failures: u64 = metrics
            .iter()
            .map(|m| m.shard_reconstruction_failed_total.get())
            .sum::<u64>()
            / num_validators;
        let average_reconstruction_cancelled: u64 = metrics
            .iter()
            .map(|m| m.shard_reconstruction_cancelled_total.get())
            .sum::<u64>()
            / num_validators;
        let average_pending_accumulators: i64 = metrics
            .iter()
            .map(|m| m.shard_reconstruction_pending_accumulators.get())
            .sum::<i64>()
            / num_validators as i64;
        let average_queued_jobs: i64 = metrics
            .iter()
            .map(|m| m.shard_reconstruction_queued_jobs.get())
            .sum::<i64>()
            / num_validators as i64;
        let average_pending_decoded_blocks: i64 = metrics
            .iter()
            .map(|m| m.shard_reconstruction_pending_decoded_blocks.get())
            .sum::<i64>()
            / num_validators as i64;

        // The periodic reporter drains every ten seconds. Pull the final tail
        // synchronously so a benchmark cutoff never drops its last samples.
        for reporter in &reporters {
            reporter
                .block_committed_latency
                .lock()
                .histogram
                .receive_all();
            reporter
                .transaction_committed_latency
                .lock()
                .histogram
                .receive_all();
        }

        let p50_block_committed_latency = reporters
            .iter()
            .filter_map(|r| r.block_committed_latency.lock().histogram.pcts([500]))
            .filter_map(|pcts| pcts.first().copied())
            .sum::<Duration>()
            .as_millis() as f64
            / num_validators as f64;
        let p50_transaction_committed_latency = reporters
            .iter()
            .filter_map(|r| r.transaction_committed_latency.lock().histogram.pcts([500]))
            .filter_map(|pcts| pcts.first().copied())
            .sum::<Duration>()
            .as_millis() as f64
            / num_validators as f64;

        let mut table = PrettyTable::new();
        table.set_format(default_table_format());

        // Display basic metrics
        table.set_titles(row![bH2->"Metrics Summary Across Honest Validators"]);
        table.add_row(row![b->"Number of honest validators:", num_validators]);
        table.add_row(row![b->"Duration:", format!("{} s", duration_secs)]);

        // Performance metrics
        table.add_row(row![bH2->""]);
        table.add_row(row![bH2->"Performance Metrics"]);
        table.add_row(
            row![b->"p50 block latency:", format!("{:.2} millis", p50_block_committed_latency)],
        );
        table.add_row(row![
            b->"p50 e2e latency:",
            format!("{:.2} millis", p50_transaction_committed_latency)
        ]);
        if let Some(outcome) = transaction_outcome {
            table.add_row(row![
                b->"Offered TPS:",
                format!(
                    "{:.2} tx/s ({} exact successful submissions)",
                    outcome.offered_transactions as f64 / duration_secs as f64,
                    outcome.offered_transactions,
                )
            ]);
            table.add_row(row![
                b->"Committed TPS at cutoff:",
                format!("{:.2} tx/s", outcome.cutoff_committed_transactions as f64 / duration_secs as f64)
            ]);
            table.add_row(row![
                b->"Eventual active-window TPS:",
                format!(
                    "{:.2} tx/s ({}, drain {:.2}s)",
                    outcome.eventual_committed_transactions as f64 / duration_secs as f64,
                    if outcome.drain_complete { "complete" } else { "INCOMPLETE" },
                    outcome.drain_elapsed.as_secs_f64(),
                )
            ]);
            table.add_row(row![
                b->"Cutoff backlog:",
                outcome
                    .offered_transactions
                    .saturating_sub(outcome.cutoff_committed_transactions)
            ]);
        } else {
            table.add_row(row![b->"Average TPS:", format!("{:.2} tx/s", average_tps)]);
        }
        table.add_row(row![b->"Average BPS:", format!("{:.2} blocks/s", average_bps)]);

        // Network metrics
        table.add_row(row![bH2->""]);
        table.add_row(row![bH2->"Network Metrics"]);
        let bw_out = average_bytes_sent as f64 / duration_secs as f64 / 1024.0 / 1024.0;
        let bw_in = average_bytes_received as f64 / duration_secs as f64 / 1024.0 / 1024.0;
        table.add_row(row![
            b->"Average bandwidth out:",
            format!("{:.2} MB/s", bw_out)
        ]);
        table.add_row(row![
            b->"Average bandwidth in:",
            format!("{:.2} MB/s", bw_in)
        ]);
        let outbound_message_breakdown = LOCAL_BENCHMARK_NETWORK_MESSAGE_TYPES
            .iter()
            .enumerate()
            .filter_map(|(message_index, request_type)| {
                let average_bytes = metrics
                    .iter()
                    .enumerate()
                    .map(|(validator_index, metrics)| {
                        let current = counter_cutoffs
                            .as_ref()
                            .and_then(|cutoffs| cutoffs.get(validator_index))
                            .and_then(|cutoff| cutoff.outbound_messages.get(message_index))
                            .map(|(bytes, _)| *bytes)
                            .unwrap_or_else(|| {
                                metrics
                                    .network_message_bytes_sent_total
                                    .with_label_values(&[request_type])
                                    .get()
                            });
                        let baseline = counter_baselines
                            .as_ref()
                            .and_then(|baselines| baselines.get(validator_index))
                            .and_then(|baseline| baseline.outbound_messages.get(message_index))
                            .map(|(bytes, _)| *bytes)
                            .unwrap_or_default();
                        current.saturating_sub(baseline)
                    })
                    .sum::<u64>() as f64
                    / num_validators as f64;
                if average_bytes == 0.0 {
                    return None;
                }
                let average_requests = metrics
                    .iter()
                    .enumerate()
                    .map(|(validator_index, metrics)| {
                        let current = counter_cutoffs
                            .as_ref()
                            .and_then(|cutoffs| cutoffs.get(validator_index))
                            .and_then(|cutoff| cutoff.outbound_messages.get(message_index))
                            .map(|(_, requests)| *requests)
                            .unwrap_or_else(|| {
                                metrics
                                    .network_requests_sent_total
                                    .with_label_values(&[request_type])
                                    .get()
                            });
                        let baseline = counter_baselines
                            .as_ref()
                            .and_then(|baselines| baselines.get(validator_index))
                            .and_then(|baseline| baseline.outbound_messages.get(message_index))
                            .map(|(_, requests)| *requests)
                            .unwrap_or_default();
                        current.saturating_sub(baseline)
                    })
                    .sum::<u64>() as f64
                    / num_validators as f64;
                Some((*request_type, average_bytes, average_requests))
            })
            .collect::<Vec<_>>();
        if !outbound_message_breakdown.is_empty() {
            table.add_row(row![bH2->""]);
            table.add_row(row![bH2->"Average Outbound Message Breakdown"]);
            for (request_type, average_bytes, average_requests) in outbound_message_breakdown {
                let bandwidth = average_bytes / duration_secs as f64 / 1024.0 / 1024.0;
                let share = if average_bytes_sent == 0 {
                    0.0
                } else {
                    average_bytes / average_bytes_sent as f64 * 100.0
                };
                let requests_per_second = average_requests / duration_secs as f64;
                table.add_row(row![
                    b->format!("{request_type}:"),
                    format!("{bandwidth:.3} MB/s ({share:.1}%, {requests_per_second:.1} msg/s)")
                ]);
            }
        }
        let total_average_transactions = (average_tps * duration_secs as f64) as u64;
        // Every honest validator sequences the same global offered set, so
        // its bandwidth denominator is the aggregate submissions across all
        // generators—not one generator's local share.
        let offered_global = transaction_outcome
            .map(|outcome| outcome.offered_transactions as f64)
            .unwrap_or(total_average_transactions as f64);
        let bandwidth_efficiency = if offered_global > 0.0 {
            average_bytes_sent as f64 / offered_global / 512.0
        } else {
            0.0
        };
        table.add_row(row![b->"Bandwidth efficiency:", format!("{:.2}", bandwidth_efficiency)]);

        if starfish_rbc_dag_autonomous_clock_expected {
            let summary = summarize_autonomous_clock_benchmark(
                &metrics,
                committee_size,
                autonomous_clock_baselines.as_deref(),
                autonomous_clock_cutoffs.as_deref(),
                starfish_rbc_dag_embedded_rbc_authority_expected,
            );
            let round_lag = summary.maximum_round.saturating_sub(summary.minimum_round);

            table.add_row(row![bH2->""]);
            table.add_row(row![
                bH2->if starfish_rbc_dag_embedded_rbc_authority_expected {
                    "RBC-DAG Embedded RBC Authority Verification"
                } else {
                    "RBC-DAG Autonomous Clock Verification"
                }
            ]);
            table.add_row(row![
                b->"Cutoff clock verdict:",
                if summary.verdict_valid {
                    "VALID".to_owned()
                } else {
                    "INVALID — DISCARD THIS AUTONOMOUS-CLOCK RUN".to_owned()
                }
            ]);
            table.add_row(row![
                b->"Cutoff valid/progress/bounded validators:",
                format!(
                    "{}/{}, {}/{}, {}/{}",
                    summary.valid_nodes,
                    metrics.len(),
                    summary.progress_nodes,
                    metrics.len(),
                    summary.bounded_nodes,
                    metrics.len(),
                )
            ]);
            table.add_row(row![
                b->"Cutoff clock/WAL progress:",
                format!(
                    "heartbeats={}, carrier deliveries={}, application deliveries={}, committed frontiers={}, frontier applications={}, projected vertices={}, projected commits={}, WAL batches={}, records={}, open rounds={}..{}",
                    summary.accepted_heartbeats,
                    summary.delivered_carriers,
                    summary.delivered_applications,
                    summary.committed_frontiers,
                    summary.frontier_applications,
                    summary.projected_vertices,
                    summary.projection_decisions,
                    summary.wal_batches,
                    summary.wal_records,
                    summary.minimum_round,
                    summary.maximum_round,
                )
            ]);
            table.add_row(row![
                b->"Cutoff bounded state:",
                format!(
                    "round skew={round_lag}/{}, max phase backlog={}/{}, admitted authors={}/{}, stake={}, max buffered={}/{}, pending recovery={}",
                    STARFISH_RBC_DAG_AUTONOMOUS_MAX_ROUND_LAG,
                    summary.maximum_phase_backlog,
                    summary.maximum_phase_backlog_bound,
                    summary.maximum_admitted_authors,
                    committee_size,
                    summary.maximum_admitted_stake,
                    summary.maximum_buffered_authenticated,
                    summary.maximum_buffered_authenticated_bound,
                    summary.pending_recovery,
                )
            ]);
            let cutoff_per_validator_progress = metrics
                .iter()
                .enumerate()
                .map(|(index, metrics)| {
                    let baseline = autonomous_clock_baselines
                        .as_deref()
                        .and_then(|baselines| baselines.get(index))
                        .copied()
                        .unwrap_or_default();
                    let snapshot = autonomous_clock_cutoffs
                        .as_deref()
                        .and_then(|snapshots| snapshots.get(index))
                        .copied()
                        .unwrap_or_else(|| metrics.autonomous_clock_benchmark_snapshot());
                    let applications = snapshot
                        .delivered_applications
                        .saturating_sub(baseline.delivered_applications);
                    let frontiers = snapshot
                        .committed_frontiers
                        .saturating_sub(baseline.committed_frontiers);
                    format!(
                        "{index}:r{}/a{applications}/f{frontiers}/v{}",
                        snapshot.carrier_round, snapshot.clock_valid,
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            table.add_row(row![
                b->"Cutoff per-validator round/app/frontier/valid:",
                cutoff_per_validator_progress,
            ]);
            let final_per_validator_state = metrics
                .iter()
                .enumerate()
                .map(|(index, metrics)| {
                    let snapshot = metrics.autonomous_clock_benchmark_snapshot();
                    format!(
                        "{index}:r{}/q{}/b{}/rec{}/v{}",
                        snapshot.carrier_round,
                        snapshot.phase_backlog,
                        snapshot.buffered_authenticated,
                        snapshot.pending_recovery,
                        snapshot.clock_valid,
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            table.add_row(row![
                b->"Final/drain state (diagnostic only):",
                final_per_validator_state,
            ]);
            let shadow_input_count = |kind: &str, outcome: &str| {
                metrics
                    .iter()
                    .map(|metrics| {
                        metrics
                            .starfish_rbc_dag_shadow_inputs_total
                            .with_label_values(&[kind, outcome])
                            .get()
                    })
                    .sum::<u64>()
            };
            table.add_row(row![
                b->"Carrier transport/ingress:",
                format!(
                    "network sent/disconnected/dropped={}/{}/{}, carriers authenticated/retained/rejected={}/{}/{}, sync requests sent/served={}/{}, sync responses authenticated/rejected={}/{}, subscriptions to/by peers={}..{}/{}..{}",
                    shadow_input_count("network", "sent"),
                    shadow_input_count("network", "disconnected"),
                    shadow_input_count("network", "dropped_backpressure"),
                    shadow_input_count("carrier", "authenticated"),
                    shadow_input_count("carrier", "retained_unauthenticated"),
                    shadow_input_count("carrier", "rejected"),
                    shadow_input_count("carrier_sync_request", "sent"),
                    shadow_input_count("carrier_sync_request", "served"),
                    shadow_input_count("carrier_sync_response", "authenticated"),
                    shadow_input_count("carrier_sync_response", "rejected"),
                    metrics
                        .iter()
                        .map(|metrics| metrics.subscribed_to_peers.get())
                        .min()
                        .unwrap_or_default(),
                    metrics
                        .iter()
                        .map(|metrics| metrics.subscribed_to_peers.get())
                        .max()
                        .unwrap_or_default(),
                    metrics
                        .iter()
                        .map(|metrics| metrics.subscribed_by_peers.get())
                        .min()
                        .unwrap_or_default(),
                    metrics
                        .iter()
                        .map(|metrics| metrics.subscribed_by_peers.get())
                        .max()
                        .unwrap_or_default(),
                )
            ]);
            table.add_row(row![
                b->"Logical vertex creation:",
                format!(
                    "bootstrap/C1/C2/C3/omitted={}/{}/{}/{}/{}",
                    shadow_input_count("consensus_vertex", "bootstrap"),
                    shadow_input_count("consensus_vertex", "c1"),
                    shadow_input_count("consensus_vertex", "c2"),
                    shadow_input_count("consensus_vertex", "c3"),
                    shadow_input_count("consensus_vertex", "omitted"),
                )
            ]);
            let consensus_carrier_breakdown = |kind: &str| {
                format!(
                    "bootstrap/C1/C2/C3/omitted={}/{}/{}/{}/{}",
                    shadow_input_count(kind, "bootstrap"),
                    shadow_input_count(kind, "c1"),
                    shadow_input_count(kind, "c2"),
                    shadow_input_count(kind, "c3"),
                    shadow_input_count(kind, "omitted"),
                )
            };
            table.add_row(row![
                b->"Logical vertices by carrier kind:",
                format!(
                    "application [{}], control/phase [{}]",
                    consensus_carrier_breakdown("application_consensus_vertex"),
                    consensus_carrier_breakdown("control_consensus_vertex"),
                )
            ]);
            let stage_latency = RBC_DAG_PIPELINE_LATENCY_STAGES
                .iter()
                .map(|stage| {
                    let total = metrics
                        .iter()
                        .map(|metrics| {
                            metrics
                                .starfish_rbc_dag_pipeline_latency_ns_total
                                .with_label_values(&[stage])
                                .get()
                        })
                        .sum::<u64>();
                    let samples = metrics
                        .iter()
                        .map(|metrics| {
                            metrics
                                .starfish_rbc_dag_pipeline_latency_samples_total
                                .with_label_values(&[stage])
                                .get()
                        })
                        .sum::<u64>();
                    let maximum = metrics
                        .iter()
                        .map(|metrics| {
                            metrics
                                .starfish_rbc_dag_pipeline_latency_ns_max
                                .with_label_values(&[stage])
                                .get()
                        })
                        .max()
                        .unwrap_or_default();
                    let average_ms = if samples == 0 {
                        0.0
                    } else {
                        total as f64 / samples as f64 / 1_000_000.0
                    };
                    format!(
                        "{}={average_ms:.1}/{:.1}ms(n={samples})",
                        stage.strip_prefix("creation_to_").unwrap_or(stage),
                        maximum as f64 / 1_000_000.0,
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            table.add_row(row![
                b->"Pipeline latency avg/max:",
                stage_latency
            ]);

            let commit_distance = |kind: &str| {
                let total = metrics
                    .iter()
                    .map(|metrics| {
                        metrics
                            .starfish_rbc_dag_commit_distance_rounds_total
                            .with_label_values(&[kind])
                            .get()
                    })
                    .sum::<u64>();
                let samples = metrics
                    .iter()
                    .map(|metrics| {
                        metrics
                            .starfish_rbc_dag_commit_distance_samples_total
                            .with_label_values(&[kind])
                            .get()
                    })
                    .sum::<u64>();
                let maximum = metrics
                    .iter()
                    .map(|metrics| {
                        metrics
                            .starfish_rbc_dag_commit_distance_rounds_max
                            .with_label_values(&[kind])
                            .get()
                    })
                    .max()
                    .unwrap_or_default();
                format_rbc_dag_round_distance(total, samples, maximum)
            };
            table.add_row(row![
                b->"Commit distance avg/max:",
                format!(
                    "physical forward={}, backward={}",
                    commit_distance(RBC_DAG_COMMIT_DISTANCE_PHYSICAL_FORWARD),
                    commit_distance(RBC_DAG_COMMIT_DISTANCE_PHYSICAL_BACKWARD),
                )
            ]);

            let queue_depth = |queue: &str, maximum: bool| {
                metrics
                    .iter()
                    .map(|metrics| {
                        if maximum {
                            metrics
                                .starfish_rbc_dag_pipeline_queue_depth_max
                                .with_label_values(&[queue])
                                .get()
                        } else {
                            metrics
                                .starfish_rbc_dag_pipeline_queue_depth
                                .with_label_values(&[queue])
                                .get()
                        }
                    })
                    .max()
                    .unwrap_or_default()
            };
            let highest_projected = metrics
                .iter()
                .map(|metrics| {
                    metrics
                        .starfish_rbc_dag_highest_projected_consensus_round
                        .get()
                })
                .max()
                .unwrap_or_default();
            let next_undecided = metrics
                .iter()
                .map(|metrics| {
                    metrics
                        .starfish_rbc_dag_next_undecided_consensus_round
                        .get()
                })
                .min()
                .unwrap_or_default();
            let next_undecided_stake = metrics
                .iter()
                .map(|metrics| {
                    metrics
                        .starfish_rbc_dag_next_undecided_projected_stake
                        .get()
                })
                .min()
                .unwrap_or_default();
            let last_committed = metrics
                .iter()
                .map(|metrics| {
                    metrics
                        .starfish_rbc_dag_last_committed_consensus_round
                        .get()
                })
                .min()
                .unwrap_or_default();
            let hol = RBC_DAG_PROJECTION_HOL_STATES
                .iter()
                .filter_map(|reason| {
                    let nodes = metrics
                        .iter()
                        .filter(|metrics| {
                            metrics
                                .starfish_rbc_dag_projection_hol_state
                                .with_label_values(&[reason])
                                .get()
                                == 1
                        })
                        .count();
                    (nodes != 0).then(|| format!("{reason}:{nodes}"))
                })
                .collect::<Vec<_>>()
                .join(",");
            table.add_row(row![
                b->"Projection/HOL state:",
                format!(
                    "pending local={}/{}, projection={}/{}, highest projected={highest_projected}, oldest undecided={next_undecided} (lag={}, projected stake={next_undecided_stake}), last committed={last_committed} (lag={}), HOL=[{hol}]",
                    queue_depth("local", false),
                    queue_depth("local", true),
                    queue_depth("projection", false),
                    queue_depth("projection", true),
                    highest_projected.saturating_sub(next_undecided),
                    highest_projected.saturating_sub(last_committed),
                )
            ]);
            let decision_count = |outcome: &str| {
                metrics
                    .iter()
                    .map(|metrics| {
                        metrics
                            .starfish_rbc_dag_projection_decisions_total
                            .with_label_values(&[outcome])
                            .get()
                    })
                    .sum::<u64>()
            };
            table.add_row(row![
                b->"Projection decisions:",
                format!(
                    "direct commit/skip={}/{}, indirect commit/skip={}/{}, undecided={}",
                    decision_count("direct_commit"),
                    decision_count("direct_skip"),
                    decision_count("indirect_commit"),
                    decision_count("indirect_skip"),
                    decision_count("undecided"),
                )
            ]);
            let frontier_count = |stage: &str| {
                metrics
                    .iter()
                    .map(|metrics| {
                        metrics
                            .starfish_rbc_dag_frontier_events_total
                            .with_label_values(&[stage])
                            .get()
                    })
                    .sum::<u64>()
            };
            table.add_row(row![
                b->"Frontier event application:",
                format!(
                    "generated={}, applied={}, ignored={}, inflight current/max={}/{}",
                    frontier_count("generated"),
                    frontier_count("applied"),
                    frontier_count("ignored"),
                    metrics
                        .iter()
                        .map(|metrics| metrics.starfish_rbc_dag_frontiers_inflight.get())
                        .sum::<i64>(),
                    metrics
                        .iter()
                        .map(|metrics| metrics.starfish_rbc_dag_frontiers_inflight_max.get())
                        .max()
                        .unwrap_or_default(),
                )
            ]);
        } else if starfish_rbc_dag_shadow_expected {
            let valid_nodes = metrics
                .iter()
                .filter(|metrics| metrics.starfish_rbc_dag_shadow_comparison_valid.get() == 1)
                .count();
            let matches = metrics
                .iter()
                .map(|metrics| {
                    metrics
                        .starfish_rbc_dag_shadow_delivery_comparisons_total
                        .with_label_values(&["match"])
                        .get()
                })
                .sum::<u64>();
            let mismatches = metrics
                .iter()
                .map(|metrics| {
                    ["mismatch", "direct_only", "shadow_only"]
                        .into_iter()
                        .map(|outcome| {
                            metrics
                                .starfish_rbc_dag_shadow_delivery_comparisons_total
                                .with_label_values(&[outcome])
                                .get()
                        })
                        .sum::<u64>()
                })
                .sum::<u64>();
            let ambiguous = metrics
                .iter()
                .map(|metrics| {
                    metrics
                        .starfish_rbc_dag_shadow_delivery_comparisons_total
                        .with_label_values(&["ambiguous"])
                        .get()
                })
                .sum::<u64>();
            let shadow_deliveries = metrics
                .iter()
                .map(|metrics| {
                    metrics
                        .starfish_rbc_dag_shadow_inputs_total
                        .with_label_values(&["delivery", "shadow"])
                        .get()
                })
                .sum::<u64>();
            let direct_deliveries = metrics
                .iter()
                .map(|metrics| {
                    metrics
                        .starfish_rbc_dag_shadow_inputs_total
                        .with_label_values(&["delivery", "direct"])
                        .get()
                })
                .sum::<u64>();
            let wal_records = metrics
                .iter()
                .map(|metrics| {
                    metrics
                        .starfish_rbc_dag_shadow_wal_durable_records_total
                        .get()
                })
                .sum::<u64>();
            let pending_recovery = metrics
                .iter()
                .map(|metrics| metrics.starfish_rbc_dag_shadow_pending_recovery.get())
                .sum::<i64>();
            let maximum_unpaired = STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_FACTOR
                .saturating_mul(i64::try_from(committee_size).unwrap_or(i64::MAX));
            let every_node_has_exact_coverage = metrics.iter().all(|metrics| {
                let direct = metrics
                    .starfish_rbc_dag_shadow_inputs_total
                    .with_label_values(&["delivery", "direct"])
                    .get();
                let shadow = metrics
                    .starfish_rbc_dag_shadow_inputs_total
                    .with_label_values(&["delivery", "shadow"])
                    .get();
                let matched = metrics
                    .starfish_rbc_dag_shadow_delivery_comparisons_total
                    .with_label_values(&["match"])
                    .get();
                direct > 0
                    && shadow > 0
                    && matched > 0
                    && metrics
                        .starfish_rbc_dag_shadow_wal_durable_records_total
                        .get()
                        > 0
                    && metrics.starfish_rbc_dag_shadow_unpaired_direct.get() <= maximum_unpaired
                    && metrics.starfish_rbc_dag_shadow_unpaired_shadow.get() <= maximum_unpaired
                    && metrics.starfish_rbc_dag_shadow_unpaired_max_round_lag.get()
                        <= STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_ROUND_LAG
            });
            let comparison_valid = valid_nodes == metrics.len()
                && every_node_has_exact_coverage
                && mismatches == 0
                && ambiguous == 0
                && wal_records > 0
                && pending_recovery == 0;

            table.add_row(row![bH2->""]);
            table.add_row(row![bH2->"RBC-DAG Shadow Verification"]);
            table.add_row(row![
                b->"Comparison verdict:",
                if comparison_valid {
                    "VALID".to_owned()
                } else {
                    "INVALID — DISCARD THIS SHADOW COMPARISON".to_owned()
                }
            ]);
            table.add_row(row![
                b->"Valid validators:",
                format!("{valid_nodes}/{}", metrics.len())
            ]);
            table.add_row(row![
                b->"Paired deliveries:",
                format!(
                    "direct={direct_deliveries}, shadow={shadow_deliveries}, matches={matches}, \
                     mismatches={mismatches}, ambiguous={ambiguous}"
                )
            ]);
            table.add_row(row![
                b->"Durability/recovery:",
                format!("WAL records={wal_records}, pending recovery={pending_recovery}")
            ]);
            let unpaired_direct = metrics
                .iter()
                .map(|metrics| metrics.starfish_rbc_dag_shadow_unpaired_direct.get())
                .sum::<i64>();
            let unpaired_shadow = metrics
                .iter()
                .map(|metrics| metrics.starfish_rbc_dag_shadow_unpaired_shadow.get())
                .sum::<i64>();
            let max_unpaired_lag = metrics
                .iter()
                .map(|metrics| metrics.starfish_rbc_dag_shadow_unpaired_max_round_lag.get())
                .max()
                .unwrap_or_default();
            table.add_row(row![
                b->"Live comparison tail:",
                format!(
                    "unpaired direct/shadow={unpaired_direct}/{unpaired_shadow}, \
                     max lag={max_unpaired_lag} rounds"
                )
            ]);
        }

        // Shard reconstruction metrics
        table.add_row(row![bH2->""]);
        table.add_row(row![bH2->"Shard Reconstruction"]);
        table.add_row(row![b->"Average queued jobs:", average_reconstruction_jobs]);
        table.add_row(
            row![b->"Average successful reconstructions:", average_reconstruction_success],
        );
        table.add_row(row![b->"Average failed reconstructions:", average_reconstruction_failures]);
        table.add_row(
            row![b->"Average cancelled reconstructions:", average_reconstruction_cancelled],
        );
        table.add_row(row![b->"Average blocks sent to core:", average_reconstructed_sent_to_core]);
        table.add_row(row![b->"Pending shard accumulators:", average_pending_accumulators]);
        table.add_row(row![b->"Queued/in-flight jobs:", average_queued_jobs]);
        table.add_row(row![b->"Pending decoded blocks:", average_pending_decoded_blocks]);
        println!("\n");
        table.printstd();
        println!("\n");
    }
}

pub fn default_table_format() -> format::TableFormat {
    format::FormatBuilder::new()
        .separators(
            &[
                format::LinePosition::Top,
                format::LinePosition::Bottom,
                format::LinePosition::Title,
            ],
            format::LineSeparator::new('-', '-', '-', '-'),
        )
        .padding(1, 1)
        .build()
}

pub trait AsPrometheusMetric {
    fn as_prometheus_metric(&self) -> i64;
}

impl<T: Ord + AddAssign + DivUsize + Copy + Default + AsPrometheusMetric> HistogramReporter<T> {
    pub fn new_in_registry(
        histogram: PreciseHistogram<T>,
        registry: &Registry,
        name: &str,
    ) -> Self {
        let gauge = register_int_gauge_vec_with_registry!(name, name, &["v"], registry).unwrap();

        Self { histogram, gauge }
    }

    pub fn report(&mut self) -> Option<()> {
        let [p25, p50, p75, p90, p99] = self.histogram.pcts([250, 500, 750, 900, 990])?;
        self.gauge
            .with_label_values(&["p25"])
            .set(p25.as_prometheus_metric());
        self.gauge
            .with_label_values(&["p50"])
            .set(p50.as_prometheus_metric());
        self.gauge
            .with_label_values(&["p75"])
            .set(p75.as_prometheus_metric());
        self.gauge
            .with_label_values(&["p90"])
            .set(p90.as_prometheus_metric());
        self.gauge
            .with_label_values(&["p99"])
            .set(p99.as_prometheus_metric());
        self.gauge
            .with_label_values(&["sum"])
            .set(self.histogram.total_sum().as_prometheus_metric());
        self.gauge
            .with_label_values(&["count"])
            .set(self.histogram.total_count() as i64);
        None
    }

    pub fn clear_receive_all(&mut self) {
        self.histogram.clear_receive_all();
    }
}

impl<T: Ord + AddAssign + DivUsize + Copy + Default + AsPrometheusMetric> VecHistogramReporter<T> {
    pub fn new_in_registry(
        histograms: Vec<(PreciseHistogram<T>, String)>,
        label: &str,
        registry: &Registry,
        name: &str,
    ) -> Self {
        let gauge =
            register_int_gauge_vec_with_registry!(name, name, &[label, "v"], registry).unwrap();

        Self { histograms, gauge }
    }

    pub fn report(&mut self) {
        for (histogram, label) in self.histograms.iter_mut() {
            let Some([p50, p90, p99]) = histogram.pcts([500, 900, 990]) else {
                continue;
            };
            self.gauge
                .with_label_values(&[label, "p50"])
                .set(p50.as_prometheus_metric());
            self.gauge
                .with_label_values(&[label, "p90"])
                .set(p90.as_prometheus_metric());
            self.gauge
                .with_label_values(&[label, "p99"])
                .set(p99.as_prometheus_metric());
            self.gauge
                .with_label_values(&[label, "sum"])
                .set(histogram.total_sum().as_prometheus_metric());
            self.gauge
                .with_label_values(&[label, "count"])
                .set(histogram.total_count() as i64);
        }
    }

    pub fn clear_receive_all(&mut self) {
        self.histograms
            .iter_mut()
            .for_each(|(hist, _)| hist.clear_receive_all());
    }

    pub fn receive_all(&mut self) {
        self.histograms
            .iter_mut()
            .for_each(|(hist, _)| hist.receive_all());
    }
}

impl AsPrometheusMetric for Duration {
    fn as_prometheus_metric(&self) -> i64 {
        self.as_micros() as i64
    }
}

impl AsPrometheusMetric for usize {
    fn as_prometheus_metric(&self) -> i64 {
        *self as i64
    }
}

impl MetricReporter {
    pub fn start(self: Arc<Self>) {
        runtime::Handle::current().spawn(self.run());
    }

    async fn run(self: Arc<Self>) {
        const REPORT_INTERVAL: Duration = Duration::from_secs(10);
        let mut deadline = Instant::now();
        loop {
            deadline += REPORT_INTERVAL;
            tokio::time::sleep_until(deadline).await;
            self.run_report().await;
        }
    }

    async fn run_report(&self) {
        self.global_in_memory_blocks
            .set(IN_MEMORY_BLOCKS.load(Ordering::Relaxed) as i64);
        self.global_in_memory_blocks_bytes
            .set(IN_MEMORY_BLOCKS_BYTES.load(Ordering::Relaxed) as i64);

        // Latency histograms accumulate across the whole run so reported
        // quantiles reflect the entire benchmark, not just the most recent
        // 10-second window (which would be dominated by warm-down noise).
        {
            let mut latency = self.transaction_committed_latency.lock();
            latency.histogram.receive_all();
            latency.report();
        }

        {
            let mut block_latency = self.block_committed_latency.lock();
            block_latency.histogram.receive_all();
            block_latency.report();
        }

        {
            let mut conn_latency = self.connection_latency.lock();
            conn_latency.receive_all();
            conn_latency.report();
        }

        // Size histograms remain windowed: the per-window distribution of
        // block / header / transaction / bundle sizes is more informative
        // than a cumulative one, because it tracks how sizes evolve over
        // the run.
        {
            let mut block_size = self.proposed_block_size_bytes.lock();
            block_size.clear_receive_all();
            block_size.report();
        }

        {
            let mut header_size = self.proposed_header_size_bytes.lock();
            header_size.clear_receive_all();
            header_size.report();
        }

        {
            let mut tx_size = self.proposed_transaction_size_bytes.lock();
            tx_size.clear_receive_all();
            tx_size.report();
        }

        {
            let mut bundle_size = self.block_bundle_size_bytes.lock();
            bundle_size.clear_receive_all();
            bundle_size.report();
        }
    }

    pub fn clear_receive_all(&self) {
        self.transaction_committed_latency
            .lock()
            .clear_receive_all();
        self.block_committed_latency.lock().clear_receive_all();
        self.proposed_block_size_bytes.lock().clear_receive_all();
        self.proposed_header_size_bytes.lock().clear_receive_all();
        self.proposed_transaction_size_bytes
            .lock()
            .clear_receive_all();
        self.block_bundle_size_bytes.lock().clear_receive_all();
        self.connection_latency.lock().clear_receive_all();
    }

    /// Discard every sample produced before a coordinated benchmark window.
    /// `clear_receive_all` intentionally preserves newly received points for
    /// periodic reporting; a benchmark reset needs the opposite order.
    pub fn reset_for_benchmark_window(&self) {
        fn drain_then_clear<T>(histogram: &mut PreciseHistogram<T>)
        where
            T: Ord + AddAssign + DivUsize + Copy + Default,
        {
            histogram.receive_all();
            histogram.reset();
        }

        drain_then_clear(&mut self.transaction_committed_latency.lock().histogram);
        drain_then_clear(&mut self.block_committed_latency.lock().histogram);
        drain_then_clear(&mut self.proposed_block_size_bytes.lock().histogram);
        drain_then_clear(&mut self.proposed_header_size_bytes.lock().histogram);
        drain_then_clear(&mut self.proposed_transaction_size_bytes.lock().histogram);
        drain_then_clear(&mut self.block_bundle_size_bytes.lock().histogram);
        for (histogram, _) in &mut self.connection_latency.lock().histograms {
            drain_then_clear(histogram);
        }
    }
}

pub fn print_network_address_table(addresses: &[SocketAddr]) {
    let table: Vec<_> = addresses
        .iter()
        .enumerate()
        .map(|(peer, address)| NetworkAddressTable {
            peer: format_authority_index(peer as AuthorityIndex),
            address: address.to_string(),
        })
        .collect();
    tracing::info!("Network address table:\n{}", Table::new(table));
}

pub trait UtilizationTimerExt {
    fn utilization_timer(&self) -> UtilizationTimer<'_>;
    fn owned_utilization_timer(&self) -> OwnedUtilizationTimer;
}

pub trait UtilizationTimerVecExt {
    fn utilization_timer(&self, label: &str) -> OwnedUtilizationTimer;
}

impl UtilizationTimerExt for IntCounter {
    fn utilization_timer(&self) -> UtilizationTimer<'_> {
        UtilizationTimer {
            metric: self,
            start: Instant::now(),
        }
    }

    fn owned_utilization_timer(&self) -> OwnedUtilizationTimer {
        OwnedUtilizationTimer {
            metric: self.clone(),
            start: Instant::now(),
        }
    }
}

impl UtilizationTimerVecExt for IntCounterVec {
    fn utilization_timer(&self, label: &str) -> OwnedUtilizationTimer {
        self.with_label_values(&[label]).owned_utilization_timer()
    }
}

pub struct UtilizationTimer<'a> {
    metric: &'a IntCounter,
    start: Instant,
}

pub struct OwnedUtilizationTimer {
    metric: IntCounter,
    start: Instant,
}

impl<'a> Drop for UtilizationTimer<'a> {
    fn drop(&mut self) {
        self.metric.inc_by(self.start.elapsed().as_micros() as u64);
    }
}

impl Drop for OwnedUtilizationTimer {
    fn drop(&mut self) {
        self.metric.inc_by(self.start.elapsed().as_micros() as u64);
    }
}

#[derive(Tabled)]
struct NetworkAddressTable {
    peer: String,
    address: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_starfish_rbc_dag_shadow_metrics() {
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(&registry, None, None, None);

        metrics
            .starfish_rbc_dag_shadow_inputs_total
            .with_label_values(&["authenticated_ingress", "accepted"])
            .inc();
        metrics
            .starfish_rbc_dag_shadow_delivery_comparisons_total
            .with_label_values(&["match"])
            .inc();
        metrics
            .starfish_rbc_dag_shadow_wal_appended_batches_total
            .inc();
        metrics
            .starfish_rbc_dag_shadow_wal_appended_records_total
            .inc_by(3);
        metrics
            .starfish_rbc_dag_shadow_wal_durable_batches_total
            .inc();
        metrics
            .starfish_rbc_dag_shadow_wal_durable_records_total
            .inc_by(3);
        metrics.starfish_rbc_dag_shadow_wal_replayed_batches.set(4);
        metrics
            .starfish_rbc_dag_shadow_wal_discarded_tail_bytes_total
            .inc_by(5);
        metrics.starfish_rbc_dag_shadow_pending_recovery.set(2);
        metrics.starfish_rbc_dag_shadow_unpaired_direct.set(6);
        metrics.starfish_rbc_dag_shadow_unpaired_shadow.set(7);
        metrics
            .starfish_rbc_dag_shadow_unpaired_max_round_lag
            .set(8);
        metrics.starfish_rbc_dag_shadow_comparison_valid.set(1);
        metrics.starfish_rbc_dag_shadow_clock_valid.set(1);
        metrics.starfish_rbc_dag_shadow_carrier_round.set(9);
        metrics.starfish_rbc_dag_shadow_phase_backlog.set(10);
        metrics.starfish_rbc_dag_shadow_admitted_authors.set(3);
        metrics.starfish_rbc_dag_shadow_admitted_stake.set(3);
        metrics
            .starfish_rbc_dag_shadow_buffered_authenticated
            .set(2);
        metrics.starfish_rbc_dag_projected_vertices_total.inc();
        metrics
            .starfish_rbc_dag_projection_decisions_total
            .with_label_values(&["direct_commit"])
            .inc();
        metrics.metrics_active.store(true, Ordering::Relaxed);
        metrics.observe_starfish_rbc_dag_pipeline_latency_ns(
            RBC_DAG_LATENCY_CREATION_TO_ASSIGNMENT,
            12,
            2,
            8,
        );
        metrics.observe_starfish_rbc_dag_commit_round_distance(
            RBC_DAG_COMMIT_DISTANCE_PHYSICAL_FORWARD,
            7,
            2,
            5,
        );
        metrics.set_starfish_rbc_dag_pipeline_state(2, 3, 9, 7, 3, 6, "awaiting_indirect_anchor");
        metrics.starfish_rbc_dag_frontier_generated();
        metrics.starfish_rbc_dag_frontier_applied();

        let gathered = registry.gather();
        for name in [
            "starfish_rbc_dag_shadow_inputs_total",
            "starfish_rbc_dag_shadow_delivery_comparisons_total",
            "starfish_rbc_dag_shadow_wal_appended_batches_total",
            "starfish_rbc_dag_shadow_wal_appended_records_total",
            "starfish_rbc_dag_shadow_wal_durable_batches_total",
            "starfish_rbc_dag_shadow_wal_durable_records_total",
            "starfish_rbc_dag_shadow_wal_replayed_batches",
            "starfish_rbc_dag_shadow_wal_discarded_tail_bytes_total",
            "starfish_rbc_dag_shadow_pending_recovery",
            "starfish_rbc_dag_shadow_unpaired_direct",
            "starfish_rbc_dag_shadow_unpaired_shadow",
            "starfish_rbc_dag_shadow_unpaired_max_round_lag",
            "starfish_rbc_dag_shadow_comparison_valid",
            "starfish_rbc_dag_shadow_clock_valid",
            "starfish_rbc_dag_shadow_carrier_round",
            "starfish_rbc_dag_shadow_phase_backlog",
            "starfish_rbc_dag_shadow_admitted_authors",
            "starfish_rbc_dag_shadow_admitted_stake",
            "starfish_rbc_dag_shadow_buffered_authenticated",
            "starfish_rbc_dag_projected_vertices_total",
            "starfish_rbc_dag_projection_decisions_total",
            "starfish_rbc_dag_pipeline_latency_ns_total",
            "starfish_rbc_dag_pipeline_latency_samples_total",
            "starfish_rbc_dag_pipeline_latency_ns_max",
            "starfish_rbc_dag_commit_distance_rounds_total",
            "starfish_rbc_dag_commit_distance_samples_total",
            "starfish_rbc_dag_commit_distance_rounds_max",
            "starfish_rbc_dag_pipeline_queue_depth",
            "starfish_rbc_dag_pipeline_queue_depth_max",
            "starfish_rbc_dag_highest_projected_consensus_round",
            "starfish_rbc_dag_next_undecided_consensus_round",
            "starfish_rbc_dag_next_undecided_projected_stake",
            "starfish_rbc_dag_last_committed_consensus_round",
            "starfish_rbc_dag_projection_hol_state",
            "starfish_rbc_dag_frontier_events_total",
            "starfish_rbc_dag_frontiers_inflight",
            "starfish_rbc_dag_frontiers_inflight_max",
        ] {
            assert!(
                gathered.iter().any(|family| family.get_name() == name),
                "metric family {name} was not registered",
            );
        }
    }

    #[test]
    fn rbc_dag_pipeline_latency_drains_while_protocol_distance_closes_at_cutoff() {
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(&registry, None, None, None);

        metrics.metrics_active.store(false, Ordering::Relaxed);
        metrics
            .transaction_metrics_active
            .store(false, Ordering::Relaxed);
        metrics.observe_starfish_rbc_dag_pipeline_latency_ns(
            RBC_DAG_LATENCY_CREATION_TO_DELIVERY,
            99,
            1,
            99,
        );
        metrics.observe_starfish_rbc_dag_commit_round_distance(
            RBC_DAG_COMMIT_DISTANCE_PHYSICAL_FORWARD,
            99,
            1,
            99,
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_pipeline_latency_samples_total
                .with_label_values(&[RBC_DAG_LATENCY_CREATION_TO_DELIVERY])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_commit_distance_samples_total
                .with_label_values(&[RBC_DAG_COMMIT_DISTANCE_PHYSICAL_FORWARD])
                .get(),
            0
        );

        // The submission window is closed but application observation remains
        // open for the bounded drain. Only application pipeline latency may
        // advance; protocol round-distance rates stay frozen at cutoff.
        metrics
            .transaction_metrics_active
            .store(true, Ordering::Relaxed);
        metrics.observe_starfish_rbc_dag_pipeline_latency_ns(
            RBC_DAG_LATENCY_CREATION_TO_DELIVERY,
            11,
            1,
            11,
        );
        metrics.observe_starfish_rbc_dag_commit_round_distance(
            RBC_DAG_COMMIT_DISTANCE_PHYSICAL_FORWARD,
            99,
            1,
            99,
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_pipeline_latency_samples_total
                .with_label_values(&[RBC_DAG_LATENCY_CREATION_TO_DELIVERY])
                .get(),
            1
        );
        metrics.observe_starfish_rbc_dag_pipeline_latency_ns(
            RBC_DAG_LATENCY_CREATION_TO_FRONTIER_APPLIED,
            13,
            1,
            13,
        );
        assert_eq!(
            metrics.starfish_rbc_dag_frontier_applied_latency_samples(),
            1
        );
        assert_eq!(
            metrics.starfish_rbc_dag_frontier_applied_sequenced_transactions(),
            0,
            "latency alone must not publish the ordered drain acknowledgement"
        );
        metrics.sequenced_transactions_total.inc_by(17);
        metrics.starfish_rbc_dag_frontier_applied();
        assert_eq!(
            metrics.starfish_rbc_dag_frontier_applied_sequenced_transactions(),
            17,
            "frontier application must acknowledge all transactions sequenced before its final latency observation"
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_commit_distance_samples_total
                .with_label_values(&[RBC_DAG_COMMIT_DISTANCE_PHYSICAL_FORWARD])
                .get(),
            0
        );

        metrics.metrics_active.store(true, Ordering::Relaxed);
        metrics.observe_starfish_rbc_dag_pipeline_latency_ns(
            RBC_DAG_LATENCY_CREATION_TO_DELIVERY,
            30,
            2,
            20,
        );
        metrics.observe_starfish_rbc_dag_pipeline_latency_ns(
            RBC_DAG_LATENCY_CREATION_TO_DELIVERY,
            4,
            1,
            4,
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_pipeline_latency_ns_total
                .with_label_values(&[RBC_DAG_LATENCY_CREATION_TO_DELIVERY])
                .get(),
            45
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_pipeline_latency_samples_total
                .with_label_values(&[RBC_DAG_LATENCY_CREATION_TO_DELIVERY])
                .get(),
            4
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_pipeline_latency_ns_max
                .with_label_values(&[RBC_DAG_LATENCY_CREATION_TO_DELIVERY])
                .get(),
            20
        );

        metrics.observe_starfish_rbc_dag_commit_round_distance(
            RBC_DAG_COMMIT_DISTANCE_PHYSICAL_FORWARD,
            7,
            2,
            5,
        );
        metrics.observe_starfish_rbc_dag_commit_round_distance(
            RBC_DAG_COMMIT_DISTANCE_PHYSICAL_BACKWARD,
            3,
            1,
            3,
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_commit_distance_rounds_total
                .with_label_values(&[RBC_DAG_COMMIT_DISTANCE_PHYSICAL_FORWARD])
                .get(),
            7
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_commit_distance_samples_total
                .with_label_values(&[RBC_DAG_COMMIT_DISTANCE_PHYSICAL_BACKWARD])
                .get(),
            1
        );
        assert_eq!(
            format_rbc_dag_round_distance(11, 2, 6),
            "5.50/6 rounds (n=2)"
        );

        metrics.set_starfish_rbc_dag_pipeline_state(4, 5, 12, 10, 2, 8, "insufficient_lookahead");
        metrics.set_starfish_rbc_dag_pipeline_state(1, 2, 13, 11, 4, 9, "ready");
        assert_eq!(
            metrics
                .starfish_rbc_dag_pipeline_queue_depth_max
                .with_label_values(&["local"])
                .get(),
            4
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_projection_hol_state
                .with_label_values(&["ready"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .starfish_rbc_dag_projection_hol_state
                .with_label_values(&["insufficient_lookahead"])
                .get(),
            0
        );

        metrics.starfish_rbc_dag_frontier_generated();
        metrics.starfish_rbc_dag_frontier_generated();
        metrics.starfish_rbc_dag_frontier_applied();
        assert_eq!(metrics.starfish_rbc_dag_frontiers_inflight.get(), 1);
        assert_eq!(metrics.starfish_rbc_dag_frontiers_inflight_max.get(), 2);
    }

    fn autonomous_clock_metrics(
        round: i64,
        phase_backlog: i64,
        buffered_authenticated: i64,
    ) -> Arc<Metrics> {
        let registry = Registry::new();
        let (metrics, _reporter) = Metrics::new(&registry, None, None, None);
        metrics.starfish_rbc_dag_shadow_clock_valid.set(1);
        metrics
            .starfish_rbc_dag_shadow_inputs_total
            .with_label_values(&["heartbeat", "accepted"])
            .inc();
        metrics
            .starfish_rbc_dag_shadow_inputs_total
            .with_label_values(&["delivery", "shadow"])
            .inc();
        metrics
            .starfish_rbc_dag_shadow_wal_appended_batches_total
            .inc();
        metrics
            .starfish_rbc_dag_shadow_wal_appended_records_total
            .inc_by(2);
        metrics
            .starfish_rbc_dag_shadow_wal_durable_batches_total
            .inc();
        metrics
            .starfish_rbc_dag_shadow_wal_durable_records_total
            .inc_by(2);
        metrics.starfish_rbc_dag_shadow_carrier_round.set(round);
        metrics
            .starfish_rbc_dag_shadow_phase_backlog
            .set(phase_backlog);
        metrics.starfish_rbc_dag_shadow_admitted_authors.set(2);
        metrics.starfish_rbc_dag_shadow_admitted_stake.set(2);
        metrics
            .starfish_rbc_dag_shadow_buffered_authenticated
            .set(buffered_authenticated);
        metrics.starfish_rbc_dag_projected_vertices_total.inc();
        metrics
            .starfish_rbc_dag_projection_decisions_total
            .with_label_values(&["direct_commit"])
            .inc();
        metrics
    }

    #[test]
    fn autonomous_clock_summary_requires_every_node_to_make_bounded_wal_progress() {
        let metrics = vec![
            autonomous_clock_metrics(8, 3, 1),
            autonomous_clock_metrics(9, 4, 2),
            autonomous_clock_metrics(10, 5, 0),
            autonomous_clock_metrics(11, 6, 1),
        ];

        let summary = summarize_autonomous_clock_benchmark(&metrics, 4, None, None, false);

        assert!(summary.verdict_valid);
        assert_eq!(summary.valid_nodes, 4);
        assert_eq!(summary.progress_nodes, 4);
        assert_eq!(summary.bounded_nodes, 4);
        assert_eq!(summary.accepted_heartbeats, 4);
        assert_eq!(summary.delivered_carriers, 4);
        assert_eq!(summary.wal_batches, 4);
        assert_eq!(summary.wal_records, 8);
        assert_eq!(summary.minimum_round, 8);
        assert_eq!(summary.maximum_round, 11);
    }

    #[test]
    fn autonomous_clock_verdict_uses_cutoff_snapshot_not_drain_state() {
        let metrics = vec![
            autonomous_clock_metrics(8, 0, 0),
            autonomous_clock_metrics(20, 0, 0),
        ];
        let invalid_cutoff = metrics
            .iter()
            .map(|metrics| metrics.autonomous_clock_benchmark_snapshot())
            .collect::<Vec<_>>();

        // A later drain-time convergence is useful diagnostic state, but it
        // cannot repair the measured interval's twelve-round cutoff skew.
        metrics[1].starfish_rbc_dag_shadow_carrier_round.set(9);
        assert!(summarize_autonomous_clock_benchmark(&metrics, 2, None, None, false).verdict_valid);
        assert!(
            !summarize_autonomous_clock_benchmark(&metrics, 2, None, Some(&invalid_cutoff), false,)
                .verdict_valid
        );

        let valid_cutoff = metrics
            .iter()
            .map(|metrics| metrics.autonomous_clock_benchmark_snapshot())
            .collect::<Vec<_>>();
        metrics[1].starfish_rbc_dag_shadow_clock_valid.set(0);
        metrics[1].starfish_rbc_dag_shadow_pending_recovery.set(1);
        assert!(
            summarize_autonomous_clock_benchmark(&metrics, 2, None, Some(&valid_cutoff), false,)
                .verdict_valid,
            "drain-time invalidity must remain diagnostic rather than rewriting cutoff validity"
        );
    }

    #[test]
    fn autonomous_clock_summary_requires_progress_after_the_benchmark_baseline() {
        let metrics = vec![
            autonomous_clock_metrics(8, 0, 0),
            autonomous_clock_metrics(8, 0, 0),
        ];
        let baselines = metrics
            .iter()
            .map(|metrics| metrics.autonomous_clock_benchmark_baseline())
            .collect::<Vec<_>>();

        assert!(
            !summarize_autonomous_clock_benchmark(&metrics, 2, Some(&baselines), None, false)
                .verdict_valid
        );

        for metrics in &metrics {
            metrics
                .starfish_rbc_dag_shadow_inputs_total
                .with_label_values(&["heartbeat", "accepted"])
                .inc();
            metrics
                .starfish_rbc_dag_shadow_inputs_total
                .with_label_values(&["delivery", "shadow"])
                .inc();
            metrics
                .starfish_rbc_dag_shadow_wal_appended_batches_total
                .inc();
            metrics
                .starfish_rbc_dag_shadow_wal_appended_records_total
                .inc();
            metrics
                .starfish_rbc_dag_shadow_wal_durable_batches_total
                .inc();
            metrics
                .starfish_rbc_dag_shadow_wal_durable_records_total
                .inc();
            metrics.starfish_rbc_dag_shadow_carrier_round.inc();
            metrics.starfish_rbc_dag_projected_vertices_total.inc();
            metrics
                .starfish_rbc_dag_projection_decisions_total
                .with_label_values(&["direct_commit"])
                .inc();
        }

        assert!(
            summarize_autonomous_clock_benchmark(&metrics, 2, Some(&baselines), None, false)
                .verdict_valid
        );
    }

    #[test]
    fn embedded_authority_summary_requires_application_delivery_progress() {
        let metrics = [autonomous_clock_metrics(8, 0, 0)];
        let baselines = metrics
            .iter()
            .map(|metrics| metrics.autonomous_clock_benchmark_baseline())
            .collect::<Vec<_>>();
        let metrics = &metrics[0];
        metrics
            .starfish_rbc_dag_shadow_inputs_total
            .with_label_values(&["application_carrier", "accepted"])
            .inc();
        metrics
            .starfish_rbc_dag_shadow_inputs_total
            .with_label_values(&["delivery", "shadow"])
            .inc();
        metrics
            .starfish_rbc_dag_shadow_wal_appended_batches_total
            .inc();
        metrics
            .starfish_rbc_dag_shadow_wal_appended_records_total
            .inc();
        metrics.starfish_rbc_dag_shadow_carrier_round.inc();
        metrics.starfish_rbc_dag_projected_vertices_total.inc();
        metrics
            .starfish_rbc_dag_projection_decisions_total
            .with_label_values(&["direct_commit"])
            .inc();

        assert!(
            !summarize_autonomous_clock_benchmark(
                &[Arc::clone(metrics)],
                2,
                Some(&baselines),
                None,
                true,
            )
            .verdict_valid
        );

        metrics
            .starfish_rbc_dag_shadow_inputs_total
            .with_label_values(&["delivery", "embedded_application"])
            .inc();
        metrics
            .starfish_rbc_dag_shadow_inputs_total
            .with_label_values(&["frontier", "committed"])
            .inc();
        metrics
            .starfish_rbc_dag_shadow_inputs_total
            .with_label_values(&["frontier", "application"])
            .inc();
        assert!(
            summarize_autonomous_clock_benchmark(
                &[Arc::clone(metrics)],
                2,
                Some(&baselines),
                None,
                true,
            )
            .verdict_valid
        );
    }

    #[test]
    fn autonomous_clock_summary_rejects_invalid_progress_and_unbounded_state() {
        let no_progress = autonomous_clock_metrics(1, 0, 0);
        no_progress
            .starfish_rbc_dag_shadow_inputs_total
            .with_label_values(&["heartbeat", "accepted"])
            .reset();
        let invalid_clock = autonomous_clock_metrics(12, 0, 0);
        invalid_clock.starfish_rbc_dag_shadow_clock_valid.set(0);
        let unbounded = autonomous_clock_metrics(
            20,
            STARFISH_RBC_DAG_AUTONOMOUS_MAX_PHASE_BACKLOG_FACTOR * 4 + 1,
            starfish_rbc_dag_autonomous_buffered_settled_bound(4) + 1,
        );
        let metrics = vec![no_progress, invalid_clock, unbounded];

        let summary = summarize_autonomous_clock_benchmark(&metrics, 4, None, None, false);

        assert!(!summary.verdict_valid);
        assert_eq!(summary.valid_nodes, 2);
        assert_eq!(summary.progress_nodes, 2);
        assert_eq!(summary.bounded_nodes, 2);
        assert!(
            summary.maximum_round - summary.minimum_round
                > STARFISH_RBC_DAG_AUTONOMOUS_MAX_ROUND_LAG
        );
    }
}
