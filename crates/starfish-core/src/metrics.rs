// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    committee::Committee,
    data::{IN_MEMORY_BLOCKS, IN_MEMORY_BLOCKS_BYTES},
    runtime,
    stat::{histogram, DivUsize, HistogramSender, PreciseHistogram},
    types::{format_authority_index, AuthorityIndex},
};
use prettytable::{format, row, Table as PrettyTable};
use prometheus::{
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_vec_with_registry, register_int_gauge_with_registry, IntCounter,
    IntCounterVec, IntGauge, IntGaugeVec, Registry,
};
use std::{
    net::SocketAddr,
    ops::AddAssign,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tabled::{Table, Tabled};
use tokio::time::Instant;

/// Metrics collected by the benchmark.
pub const BENCHMARK_DURATION: &str = "benchmark_duration";

pub const TRANSACTION_CERTIFIED_LATENCY: &str = "transaction_certified_latency";
pub const TRANSACTION_CERTIFIED_LATENCY_SQUARED: &str = "latency_s";

#[derive(Clone)]
pub struct Metrics {
    pub benchmark_duration: IntCounter,
    pub committed_leaders_total: IntCounterVec,
    pub leader_timeout_total: IntCounter,
    pub sequenced_transactions_total: IntCounter,

    pub filtered_blocks_total: IntCounter,
    pub processed_after_filtering_total: IntCounter,
    pub reconstructed_blocks_total: IntCounterVec,
    pub used_additional_blocks_total: IntCounter,

    pub block_store_unloaded_blocks: IntCounter,
    pub block_store_loaded_blocks: IntCounter,
    pub block_store_entries: IntCounter,
    pub block_store_cleanup_util: IntCounter,

    pub wal_mappings: IntGauge,

    pub core_lock_util: IntCounter,
    pub core_lock_enqueued: IntCounter,
    pub core_lock_dequeued: IntCounter,

    pub block_handler_cleanup_util: IntCounter,

    pub missing_blocks: IntGaugeVec,
    pub block_sync_requests_sent: IntCounterVec,
    pub committed_blocks: IntCounterVec,

    pub block_committed_latency: HistogramSender<Duration>,
    pub block_committed_latency_squared_micros: IntCounter,

    pub transaction_committed_latency: HistogramSender<Duration>,
    pub transaction_committed_latency_squared_micros: IntCounter,

    pub proposed_block_size_bytes: HistogramSender<usize>,

    pub connection_latency_sender: Vec<HistogramSender<Duration>>,

    pub utilization_timer: IntCounterVec,
    pub submitted_transactions: IntCounter,

    // tracking total bytes sent and received
    pub bytes_sent_total: IntCounter,
    pub bytes_received_total: IntCounter,
}

pub struct MetricReporter {
    pub transaction_committed_latency: parking_lot::Mutex<HistogramReporter<Duration>>,
    pub block_committed_latency: parking_lot::Mutex<HistogramReporter<Duration>>,
    pub proposed_block_size_bytes: parking_lot::Mutex<HistogramReporter<usize>>,
    pub connection_latency: parking_lot::Mutex<VecHistogramReporter<Duration>>,
    pub global_in_memory_blocks: IntGauge,
    pub global_in_memory_blocks_bytes: IntGauge,
}

pub struct HistogramReporter<T> {
    pub histogram: PreciseHistogram<T>,
    gauge: IntGaugeVec,
}

pub struct VecHistogramReporter<T> {
    histograms: Vec<(PreciseHistogram<T>, String)>,
    gauge: IntGaugeVec,
}

impl Metrics {
    pub fn new(
        registry: &Registry,
        committee: Option<&Committee>,
    ) -> (Arc<Self>, Arc<MetricReporter>) {
        let (transaction_committed_latency_hist, transaction_committed_latency) = histogram();
        let (block_committed_latency_hist, block_committed_latency) = histogram();

        let (proposed_block_size_bytes_hist, proposed_block_size_bytes) = histogram();

        let committee_size = committee.map(Committee::len).unwrap_or_default();
        let (connection_latency_hist, connection_latency_sender) = (0..committee_size)
            .map(|peer| {
                let (hist, sender) = histogram();
                (
                    (
                        hist,
                        format_authority_index(peer as AuthorityIndex).to_string(),
                    ),
                    sender,
                )
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
            processed_after_filtering_total: register_int_counter_with_registry!(
                "processed_after_filtering_total",
                "Total number of blocks processed after filtering",
                registry,
            )
            .unwrap(),
            reconstructed_blocks_total: register_int_counter_vec_with_registry!(
                "reconstructed_blocks_total",
                "Total number of reconstructed blocks per authority",
                &["reconstruction_place"],
                registry,
            )
            .unwrap(),
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
            bytes_sent_total: register_int_counter_with_registry!(
                "bytes_sent_total",
                "Total number of bytes sent",
                registry,
            )
            .unwrap(),
            bytes_received_total: register_int_counter_with_registry!(
                "bytes_received_total",
                "Total number of bytes sent",
                registry,
            )
            .unwrap(),
            leader_timeout_total: register_int_counter_with_registry!(
                "leader_timeout_total",
                "Total number of leader timeouts",
                registry,
            )
            .unwrap(),
            sequenced_transactions_total: register_int_counter_with_registry!(
                "sequenced_transactions_total",
                "Total number of sequenced transactions",
                registry,
            )
            .unwrap(),

            block_store_loaded_blocks: register_int_counter_with_registry!(
                "block_store_loaded_blocks",
                "Blocks loaded from wal position in the block store",
                registry,
            )
            .unwrap(),
            block_store_unloaded_blocks: register_int_counter_with_registry!(
                "block_store_unloaded_blocks",
                "Blocks unloaded from wal position during cleanup",
                registry,
            )
            .unwrap(),
            block_store_entries: register_int_counter_with_registry!(
                "block_store_entries",
                "Number of entries in block store",
                registry,
            )
            .unwrap(),
            block_store_cleanup_util: register_int_counter_with_registry!(
                "block_store_cleanup_util",
                "block_store_cleanup_util",
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
            block_sync_requests_sent: register_int_counter_vec_with_registry!(
                "block_sync_requests_sent",
                "Number of block sync requests sent per authority",
                &["authority"],
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

            connection_latency_sender,
        };

        (Arc::new(metrics), Arc::new(reporter))
    }

    pub fn aggregate_and_display(
        metrics: Vec<Arc<Metrics>>,
        reporters: Vec<Arc<MetricReporter>>,
        duration_secs: u64,
    ) {
        let mut table = PrettyTable::new();
        table.set_format(default_table_format());

        let num_validators = metrics.len() as u64;

        // Calculate overall statistics
        let average_transactions: u64 = metrics
            .iter()
            .map(|m| m.sequenced_transactions_total.get())
            .sum::<u64>()
            / num_validators;
        let average_tps = average_transactions as f64 / duration_secs as f64;

        let average_blocks_submitted = metrics
            .iter()
            .map(|m| m.block_store_entries.get())
            .sum::<u64>()
            / num_validators;
        let average_bps = average_blocks_submitted as f64 / duration_secs as f64;

        let average_bytes_sent: u64 = metrics
            .iter()
            .map(|m| m.bytes_sent_total.get())
            .sum::<u64>()
            / num_validators;
        let average_bytes_received: u64 = metrics
            .iter()
            .map(|m| m.bytes_received_total.get())
            .sum::<u64>()
            / num_validators;

        let p50_block_committed_latency = reporters
            .iter()
            .filter_map(|r| r.block_committed_latency.lock().histogram.pcts([500]))
            .filter_map(|pcts| pcts.first().copied())
            .sum::<Duration>()
            .as_millis()
            / num_validators as u128;
        let p50_transaction_committed_latency = reporters
            .iter()
            .filter_map(|r| r.transaction_committed_latency.lock().histogram.pcts([500]))
            .filter_map(|pcts| pcts.first().copied())
            .sum::<Duration>()
            .as_millis()
            / num_validators as u128;
        // Display basic metrics
        table.set_titles(row![bH2->"Metrics Summary Across Honest Validators"]);
        table.add_row(row![b->"Number of honest validators:", num_validators]);
        table.add_row(row![b->"Duration:", format!("{} s", duration_secs)]);

        // Performance metrics
        table.add_row(row![bH2->""]);
        table.add_row(row![bH2->"Performance Metrics"]);
        table.add_row(
            row![b->"Average block latency:", format!("{:.2} millis", p50_block_committed_latency)],
        );
        table.add_row(row![b->"Average e2e latency:", format!("{:.2} millis", p50_transaction_committed_latency)]);
        table.add_row(row![b->"Average TPS:", format!("{:.2} tx/s", average_tps)]);
        table.add_row(row![b->"Average BPS:", format!("{:.2} blocks/s", average_bps)]);

        // Network metrics
        table.add_row(row![bH2->""]);
        table.add_row(row![bH2->"Network Metrics"]);
        table.add_row(row![b->"Average bandwidth out:", format!("{:.2} MB/s", average_bytes_sent as f64 / duration_secs as f64 / 1024.0 / 1024.0)]);
        table.add_row(row![b->"Average bandwidth in:", format!("{:.2} MB/s", average_bytes_received as f64 / duration_secs as f64/ 1024.0 / 1024.0)]);
        table.add_row(row![b->"Bandwidth efficiency:", format!("{:.2}", average_bytes_sent as f64 / average_transactions as f64 / 512.0)]);
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

        // Clear and report all histograms
        {
            let mut latency = self.transaction_committed_latency.lock();
            latency.clear_receive_all();
            latency.report();
        }

        {
            let mut block_latency = self.block_committed_latency.lock();
            block_latency.clear_receive_all();
            block_latency.report();
        }

        {
            let mut block_size = self.proposed_block_size_bytes.lock();
            block_size.clear_receive_all();
            block_size.report();
        }

        {
            let mut conn_latency = self.connection_latency.lock();
            conn_latency.clear_receive_all();
            conn_latency.report();
        }
    }

    pub fn clear_receive_all(&self) {
        self.transaction_committed_latency
            .lock()
            .clear_receive_all();
        self.block_committed_latency.lock().clear_receive_all();
        self.proposed_block_size_bytes.lock().clear_receive_all();
        self.connection_latency.lock().clear_receive_all();
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
    fn utilization_timer(&self) -> UtilizationTimer;
    fn owned_utilization_timer(&self) -> OwnedUtilizationTimer;
}

pub trait UtilizationTimerVecExt {
    fn utilization_timer(&self, label: &str) -> OwnedUtilizationTimer;
}

impl UtilizationTimerExt for IntCounter {
    fn utilization_timer(&self) -> UtilizationTimer {
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
    peer: char,
    address: String,
}
