// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeSet, HashMap},
    fmt::Debug,
    fs,
    io::BufRead,
    path::{Path, PathBuf},
    time::Duration,
};

use itertools::Itertools;
use prettytable::{Table, row};
use prometheus_parse::Scrape;
use serde::{Deserialize, Serialize};
use starfish_core::metrics::{
    STARFISH_RBC_DAG_AUTONOMOUS_MAX_BUFFERED_FACTOR,
    STARFISH_RBC_DAG_AUTONOMOUS_MAX_PHASE_BACKLOG_FACTOR,
    STARFISH_RBC_DAG_AUTONOMOUS_MAX_ROUND_LAG, STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_FACTOR,
    STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_ROUND_LAG,
};

use crate::{
    benchmark::{BenchmarkParameters, BenchmarkRunSummary, PercentileSummary},
    display,
    protocol::ProtocolMetrics,
};

/// The identifier of prometheus latency buckets.
type BucketId = String;
/// The identifier of a measurement type.
type Label = String;

pub(crate) const SHADOW_COMPARISON_VALID_METRIC: &str = "starfish_rbc_dag_shadow_comparison_valid";
pub(crate) const SHADOW_AUTONOMOUS_CLOCK_VALID_METRIC: &str = "starfish_rbc_dag_shadow_clock_valid";

/// Select the validity gauge for the configured observational mode. Mirror
/// mode compares direct and embedded RBC deliveries; autonomous mode has no
/// one-to-one direct stream and therefore owns a separate clock verdict.
pub(crate) fn shadow_validity_metric(parameters: &BenchmarkParameters) -> Option<&'static str> {
    if parameters.consensus_protocol != "starfish-rbc"
        || !parameters.node_parameters.starfish_rbc_dag_shadow
    {
        return None;
    }

    Some(
        if parameters.node_parameters.starfish_rbc_dag_autonomous_clock {
            SHADOW_AUTONOMOUS_CLOCK_VALID_METRIC
        } else {
            SHADOW_COMPARISON_VALID_METRIC
        },
    )
}

/// A snapshot measurement at a given time.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct Measurement {
    /// Duration since the beginning of the benchmark.
    timestamp: Duration,
    /// Latency buckets.
    buckets: HashMap<BucketId, Duration>,
    /// Count buckets.
    count_buckets: HashMap<BucketId, usize>,
    /// Sum of the latencies of all finalized transactions.
    sum: Duration,
    /// Total number of finalized transactions
    count: usize,
    /// Sum of the squares of the latencies of all finalized transactions
    squared_sum: f64,
    /// Scalar value for simple counters or gauges.
    #[serde(default)]
    scalar: f64,
}

impl Measurement {
    /// Make new measurements from the text exposed by prometheus.
    /// Every measurement is identified by a unique label.
    pub fn from_prometheus<M: ProtocolMetrics>(text: &str) -> HashMap<Label, Self> {
        let br = std::io::BufReader::new(text.as_bytes());
        let parsed = Scrape::parse(br.lines()).unwrap();

        let mut measurements = HashMap::new();
        for sample in &parsed.samples {
            let label = sample
                .labels
                .values()
                .cloned()
                .sorted()
                .collect::<Vec<_>>()
                .join(",");
            let histogram_bucket = sample.labels.get("v").unwrap_or(label.as_str());
            let count_bucket_label = match (
                sample.labels.get("authority"),
                sample.labels.get("commit_type"),
            ) {
                (Some(authority), Some(commit_type)) => format!("{authority},{commit_type}"),
                _ => label.clone(),
            };

            let measurement = measurements
                .entry(
                    sample
                        .metric
                        .clone()
                        .trim_end_matches("_squared_micros")
                        .to_string(),
                )
                .or_insert_with(Self::default);

            match &sample.metric {
                x if x == "transaction_committed_latency_squared_micros" => {
                    measurement.squared_sum = match sample.value {
                        prometheus_parse::Value::Counter(value) => value,
                        _ => panic!("Unexpected scraped value: '{x}'"),
                    }
                }
                x if x == "block_committed_latency_squared_micros" => {
                    measurement.squared_sum = match sample.value {
                        prometheus_parse::Value::Counter(value) => value,
                        _ => panic!("Unexpected scraped value: '{x}'"),
                    }
                }
                x if x == "transaction_committed_latency" => match histogram_bucket {
                    "count" => {
                        measurement.count = match sample.value {
                            prometheus_parse::Value::Gauge(value) => value as usize,
                            _ => panic!("Unexpected scraped value: '{x}'"),
                        }
                    }
                    "sum" => {
                        measurement.sum = match sample.value {
                            prometheus_parse::Value::Gauge(value) => {
                                Duration::from_micros(value as u64)
                            }
                            _ => panic!("Unexpected scraped value: '{x}'"),
                        }
                    }
                    bucket_id if bucket_id.starts_with('p') => match sample.value {
                        prometheus_parse::Value::Gauge(value) => {
                            let bucket_delay = Duration::from_micros(value as u64);
                            measurement
                                .buckets
                                .insert(bucket_id.to_string(), bucket_delay);
                        }
                        _ => panic!("Unexpected scraped value: '{bucket_id}'"),
                    },
                    _ => panic!("Unexpected scraped value: '{x}'"),
                },
                x if x == "sequenced_transactions_total" => {
                    measurement.count = match sample.value {
                        prometheus_parse::Value::Counter(value) => value as usize,
                        _ => panic!("Unexpected scraped value: '{x}'"),
                    };
                }
                x if x == "block_committed_latency" => match histogram_bucket {
                    "count" => {
                        measurement.count = match sample.value {
                            prometheus_parse::Value::Gauge(value) => value as usize,
                            _ => panic!("Unexpected scraped value: '{x}'"),
                        }
                    }
                    "sum" => {
                        measurement.sum = match sample.value {
                            prometheus_parse::Value::Gauge(value) => {
                                Duration::from_micros(value as u64)
                            }
                            _ => panic!("Unexpected scraped value: '{x}'"),
                        }
                    }
                    bucket_id if bucket_id.starts_with('p') => match sample.value {
                        prometheus_parse::Value::Gauge(value) => {
                            let bucket_delay = Duration::from_micros(value as u64);
                            measurement
                                .buckets
                                .insert(bucket_id.to_string(), bucket_delay);
                        }
                        _ => panic!("Unexpected scraped value: '{bucket_id}'"),
                    },
                    _ => panic!("Unexpected scraped value: '{x}'"),
                },
                x if x == "committed_leaders_total" => match sample.value {
                    prometheus_parse::Value::Counter(value) => {
                        measurement
                            .count_buckets
                            .insert(count_bucket_label, value as usize);
                    }
                    _ => panic!("Unexpected scraped value: '{x}'"),
                },
                x if x == "bytes_received_total" => match sample.value {
                    prometheus_parse::Value::Counter(value) => {
                        measurement.count = value as usize;
                        measurement.scalar = value;
                    }
                    _ => panic!("Unexpected scraped value: '{x}'"),
                },
                x if x == "bytes_sent_total" => match sample.value {
                    prometheus_parse::Value::Counter(value) => {
                        measurement.count = value as usize;
                        measurement.scalar = value;
                    }
                    _ => panic!("Unexpected scraped value: '{x}'"),
                },
                x if x == "block_sync_requests_sent" => match sample.value {
                    prometheus_parse::Value::Counter(value) => {
                        measurement.scalar += value;
                    }
                    _ => panic!("Unexpected scraped value: '{x}'"),
                },
                x if x == "process_cpu_seconds_total" => match sample.value {
                    prometheus_parse::Value::Counter(value) => {
                        measurement.scalar = value;
                    }
                    _ => panic!("Unexpected scraped value: '{x}'"),
                },
                x if x == "process_resident_memory_bytes" => match sample.value {
                    prometheus_parse::Value::Gauge(value) => {
                        measurement.scalar = value;
                    }
                    _ => panic!("Unexpected scraped value: '{x}'"),
                },
                x if x == "process_virtual_memory_bytes" => match sample.value {
                    prometheus_parse::Value::Gauge(value) => {
                        measurement.scalar = value;
                    }
                    _ => panic!("Unexpected scraped value: '{x}'"),
                },
                x if x == "proposed_header_size_bytes" => match histogram_bucket {
                    "count" => {
                        measurement.count = match sample.value {
                            prometheus_parse::Value::Gauge(value) => value as usize,
                            _ => panic!("Unexpected scraped value: '{x}'"),
                        }
                    }
                    "sum" => {
                        measurement.scalar = match sample.value {
                            prometheus_parse::Value::Gauge(value) => value,
                            _ => panic!("Unexpected scraped value: '{x}'"),
                        }
                    }
                    _ => {}
                },
                x if x == "global_in_memory_blocks_bytes" => match sample.value {
                    prometheus_parse::Value::Gauge(value) => {
                        measurement.scalar = value;
                    }
                    _ => panic!("Unexpected scraped value: '{x}'"),
                },
                x if x == "dag_highest_round" => match sample.value {
                    prometheus_parse::Value::Gauge(value) => {
                        measurement.scalar = value;
                    }
                    _ => panic!("Unexpected scraped value: '{x}'"),
                },
                x if matches!(
                    x.as_str(),
                    "starfish_rbc_dag_shadow_inputs_total"
                        | "starfish_rbc_dag_shadow_delivery_comparisons_total"
                        | "starfish_rbc_dag_projection_decisions_total"
                ) =>
                {
                    match sample.value {
                        prometheus_parse::Value::Counter(value) => {
                            let shadow_bucket = if matches!(
                                x.as_str(),
                                "starfish_rbc_dag_shadow_delivery_comparisons_total"
                                    | "starfish_rbc_dag_projection_decisions_total"
                            ) {
                                sample
                                    .labels
                                    .get("outcome")
                                    .map(str::to_owned)
                                    .unwrap_or(label)
                            } else {
                                match (sample.labels.get("kind"), sample.labels.get("outcome")) {
                                    (Some(kind), Some(outcome)) => format!("{kind},{outcome}"),
                                    _ => label,
                                }
                            };
                            measurement
                                .count_buckets
                                .insert(shadow_bucket, value as usize);
                            measurement.count = measurement.count_buckets.values().sum();
                        }
                        _ => panic!("Unexpected scraped value: '{x}'"),
                    }
                }
                x if matches!(
                    x.as_str(),
                    "starfish_rbc_dag_shadow_wal_appended_batches_total"
                        | "starfish_rbc_dag_shadow_wal_appended_records_total"
                        | "starfish_rbc_dag_shadow_wal_durable_batches_total"
                        | "starfish_rbc_dag_shadow_wal_durable_records_total"
                        | "starfish_rbc_dag_shadow_wal_discarded_tail_bytes_total"
                        | "starfish_rbc_dag_projected_vertices_total"
                ) =>
                {
                    match sample.value {
                        prometheus_parse::Value::Counter(value) => {
                            measurement.count = value as usize;
                            measurement.scalar = value;
                        }
                        _ => panic!("Unexpected scraped value: '{x}'"),
                    }
                }
                x if matches!(
                    x.as_str(),
                    "starfish_rbc_dag_shadow_wal_replayed_batches"
                        | "starfish_rbc_dag_shadow_pending_recovery"
                        | "starfish_rbc_dag_shadow_comparison_valid"
                        | "starfish_rbc_dag_shadow_clock_valid"
                        | "starfish_rbc_dag_shadow_carrier_round"
                        | "starfish_rbc_dag_shadow_phase_backlog"
                        | "starfish_rbc_dag_shadow_admitted_authors"
                        | "starfish_rbc_dag_shadow_admitted_stake"
                        | "starfish_rbc_dag_shadow_buffered_authenticated"
                        | "starfish_rbc_dag_shadow_unpaired_direct"
                        | "starfish_rbc_dag_shadow_unpaired_shadow"
                        | "starfish_rbc_dag_shadow_unpaired_max_round_lag"
                ) =>
                {
                    match sample.value {
                        prometheus_parse::Value::Gauge(value) => {
                            measurement.scalar = value;
                        }
                        _ => panic!("Unexpected scraped value: '{x}'"),
                    }
                }
                _ => {
                    measurements.remove(&sample.metric);
                }
            }
        }

        // Apply the same timestamp to all measurements.
        let timestamp = parsed
            .samples
            .iter()
            .find(|x| x.metric == M::BENCHMARK_DURATION)
            .map(|x| match x.value {
                prometheus_parse::Value::Counter(value) => Duration::from_secs(value as u64),
                _ => panic!("Unexpected scraped value"),
            })
            .unwrap_or_default();
        for sample in measurements.values_mut() {
            sample.timestamp = timestamp;
        }

        measurements
    }

    /// Compute the average latency.
    #[cfg(test)]
    pub fn average_latency(&self) -> Duration {
        self.sum.checked_div(self.count as u32).unwrap_or_default()
    }

    pub fn count_value(&self) -> usize {
        self.count
    }

    pub fn scalar_value(&self) -> f64 {
        self.scalar
    }

    pub fn timestamp(&self) -> Duration {
        self.timestamp
    }

    pub fn bucket_ms(&self, bucket: &str) -> Option<f64> {
        self.buckets
            .get(bucket)
            .map(|duration| duration.as_secs_f64() * 1_000.0)
    }
}

/// The identifier of the scrapers collecting the prometheus metrics.
type ScraperId = usize;

#[derive(Serialize, Deserialize, Clone)]
pub struct MeasurementsCollection {
    /// The benchmark parameters of the current run.
    pub parameters: BenchmarkParameters,
    /// The data collected by each scraper.
    pub data: HashMap<Label, HashMap<ScraperId, Vec<Measurement>>>,
    /// Database sizes in bytes per validator, measured after the benchmark.
    #[serde(default)]
    pub db_sizes: Vec<u64>,
    /// Number of validators that exposed metrics during readiness checks and
    /// were treated as live from benchmark start.
    #[serde(default)]
    pub ready_nodes_at_boot: usize,
    /// Validators that contributed at least one parsed measurement sample.
    #[serde(default)]
    observed_scrapers: BTreeSet<ScraperId>,
    /// Validators represented only by a synthetic missing-final-scrape
    /// invalidation marker, not by a successfully parsed metrics response.
    #[serde(default)]
    synthetic_only_scrapers: BTreeSet<ScraperId>,
}

impl MeasurementsCollection {
    /// Create a new (empty) collection of measurements.
    pub fn new(mut parameters: BenchmarkParameters) -> Self {
        // Remove the access token from the parameters.
        parameters.settings.repository.remove_access_token();
        let ready_nodes_at_boot = parameters.nodes;

        Self {
            parameters,
            data: HashMap::new(),
            db_sizes: Vec::new(),
            ready_nodes_at_boot,
            observed_scrapers: BTreeSet::new(),
            synthetic_only_scrapers: BTreeSet::new(),
        }
    }

    /// Load a collection of measurement from a json file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let data = fs::read(path)?;
        let measurements: Self = serde_json::from_slice(data.as_slice())?;
        Ok(measurements)
    }

    /// Add a new measurement to the collection.
    pub fn add(&mut self, scraper_id: ScraperId, label: String, measurement: Measurement) {
        self.observed_scrapers.insert(scraper_id);
        self.synthetic_only_scrapers.remove(&scraper_id);
        self.data
            .entry(label)
            .or_default()
            .entry(scraper_id)
            .or_default()
            .push(measurement);
    }

    pub fn set_db_sizes(&mut self, db_sizes: Vec<u64>) {
        self.db_sizes = db_sizes;
    }

    pub fn set_ready_nodes_at_boot(&mut self, ready_nodes_at_boot: usize) {
        self.ready_nodes_at_boot = ready_nodes_at_boot.min(self.parameters.nodes);
    }

    /// Record that an initially-live validator did not provide a usable final
    /// shadow scrape. Appending an explicit invalid observation prevents an
    /// earlier successful scrape from being mistaken for fresh final evidence.
    pub fn mark_shadow_final_scrape_missing(&mut self, scraper_id: ScraperId) {
        let Some(validity_metric) = shadow_validity_metric(&self.parameters) else {
            return;
        };
        let timestamp = self
            .data
            .values()
            .filter_map(|by_scraper| by_scraper.get(&scraper_id))
            .filter_map(|series| series.last())
            .map(Measurement::timestamp)
            .max()
            .unwrap_or_default();
        if !self.observed_scrapers.contains(&scraper_id) {
            self.synthetic_only_scrapers.insert(scraper_id);
        }
        self.data
            .entry(validity_metric.to_owned())
            .or_default()
            .entry(scraper_id)
            .or_default()
            .push(Measurement {
                timestamp,
                scalar: 0.0,
                ..Measurement::default()
            });
    }

    /// Get all labels.
    pub fn labels(&self) -> impl Iterator<Item = &Label> {
        self.data.keys()
    }

    fn latest_measurements(&self, label: &str) -> Vec<&Measurement> {
        self.data
            .get(label)
            .map(|data| {
                data.keys()
                    .sorted()
                    .filter_map(|key| data.get(key).and_then(|samples| samples.last()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn latest_measurements_with_scraper_ids(&self, label: &str) -> Vec<(ScraperId, &Measurement)> {
        self.data
            .get(label)
            .map(|data| {
                data.keys()
                    .sorted()
                    .filter_map(|key| {
                        data.get(key)
                            .and_then(|samples| samples.last())
                            .map(|measurement| (*key, measurement))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn ready_nodes_at_boot(&self) -> usize {
        if self.ready_nodes_at_boot == 0 {
            self.parameters.nodes
        } else {
            self.ready_nodes_at_boot.min(self.parameters.nodes)
        }
    }

    fn metrics_contributors(&self) -> usize {
        if !self.observed_scrapers.is_empty() {
            return self.observed_scrapers.len();
        }

        self.data
            .values()
            .flat_map(|samples| samples.keys().copied())
            .filter(|scraper_id| !self.synthetic_only_scrapers.contains(scraper_id))
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Get the maximum result of a function applied to the measurements.
    fn max_result<T: Default + Ord>(&self, label: &str, function: impl Fn(&Measurement) -> T) -> T {
        self.latest_measurements(label)
            .into_iter()
            .map(function)
            .max()
            .unwrap_or_default()
    }

    /// Sum a Prometheus counter bucket across scrapers while preserving work
    /// observed before a process-local counter reset.
    fn sum_count_bucket_increments(&self, label: &str, bucket: &str) -> usize {
        self.data
            .get(label)
            .into_iter()
            .flat_map(|by_scraper| by_scraper.values())
            .map(|series| {
                let mut previous = 0;
                let mut total = 0;
                for measurement in series {
                    let current = measurement.count_buckets.get(bucket).copied().unwrap_or(0);
                    total += if current >= previous {
                        current - previous
                    } else {
                        current
                    };
                    previous = current;
                }
                total
            })
            .sum()
    }

    fn sum_latest_scalar_as_usize(&self, label: &str) -> usize {
        self.latest_measurements(label)
            .into_iter()
            .map(|measurement| measurement.scalar.max(0.0) as usize)
            .sum()
    }

    fn min_latest_scalar_as_usize(&self, label: &str) -> usize {
        self.latest_measurements(label)
            .into_iter()
            .map(|measurement| measurement.scalar.max(0.0) as usize)
            .min()
            .unwrap_or_default()
    }

    /// Sum scalar Prometheus counter increments across scrapers and resets.
    fn sum_scalar_counter_increments(&self, label: &str) -> usize {
        self.data
            .get(label)
            .into_iter()
            .flat_map(|by_scraper| by_scraper.values())
            .map(|series| {
                let mut previous = 0.0;
                let mut total = 0.0;
                for measurement in series {
                    let current = measurement.scalar.max(0.0);
                    total += if current >= previous {
                        current - previous
                    } else {
                        current
                    };
                    previous = current;
                }
                total as usize
            })
            .sum()
    }

    fn scraper_series(&self, label: &str, scraper_id: ScraperId) -> Option<&[Measurement]> {
        self.data.get(label)?.get(&scraper_id).map(Vec::as_slice)
    }

    fn active_window_series(&self, label: &str, scraper_id: ScraperId) -> Option<&[Measurement]> {
        let series = self.scraper_series(label, scraper_id)?;
        if !series
            .windows(2)
            .all(|window| window[1].timestamp >= window[0].timestamp)
        {
            return None;
        }
        let start = series
            .iter()
            .position(|measurement| !measurement.timestamp.is_zero())?;
        let maximum_timestamp = series.iter().map(Measurement::timestamp).max()?;
        let end = series
            .iter()
            .position(|measurement| measurement.timestamp == maximum_timestamp)?;
        let active = series.get(start..=end)?;
        let first = active.first()?;
        let last = active.last()?;
        (active.len() >= 2 && last.timestamp > first.timestamp).then_some(active)
    }

    fn gauge_always_equals(&self, label: &str, scraper_id: ScraperId, expected: f64) -> bool {
        self.scraper_series(label, scraper_id)
            .is_some_and(|series| {
                !series.is_empty()
                    && series
                        .iter()
                        .all(|measurement| measurement.scalar == expected)
            })
    }

    fn scalar_counter_is_monotonic_and_positive(&self, label: &str, scraper_id: ScraperId) -> bool {
        let Some(series) = self.scraper_series(label, scraper_id) else {
            return false;
        };
        let monotonic = series
            .windows(2)
            .all(|window| window[1].scalar >= window[0].scalar);
        monotonic
            && series
                .last()
                .is_some_and(|measurement| measurement.scalar > 0.0)
    }

    fn scalar_counter_increased(&self, label: &str, scraper_id: ScraperId) -> bool {
        let Some(series) = self.active_window_series(label, scraper_id) else {
            return false;
        };
        series.len() >= 2
            && series
                .windows(2)
                .all(|window| window[1].scalar >= window[0].scalar)
            && series
                .last()
                .zip(series.first())
                .is_some_and(|(last, first)| last.scalar > first.scalar)
    }

    fn count_bucket_is_monotonic_and_positive(
        &self,
        label: &str,
        scraper_id: ScraperId,
        bucket: &str,
    ) -> bool {
        let Some(series) = self.scraper_series(label, scraper_id) else {
            return false;
        };
        let values = series
            .iter()
            .map(|measurement| measurement.count_buckets.get(bucket).copied().unwrap_or(0))
            .collect::<Vec<_>>();
        values.windows(2).all(|window| window[1] >= window[0])
            && values.last().is_some_and(|value| *value > 0)
    }

    fn count_bucket_increased(&self, label: &str, scraper_id: ScraperId, bucket: &str) -> bool {
        let Some(series) = self.active_window_series(label, scraper_id) else {
            return false;
        };
        let values = series
            .iter()
            .map(|measurement| measurement.count_buckets.get(bucket).copied().unwrap_or(0))
            .collect::<Vec<_>>();
        values.len() >= 2
            && values.windows(2).all(|window| window[1] >= window[0])
            && values
                .last()
                .zip(values.first())
                .is_some_and(|(last, first)| last > first)
    }

    fn count_bucket_sum_increased(
        &self,
        label: &str,
        scraper_id: ScraperId,
        buckets: &[&str],
    ) -> bool {
        let Some(series) = self.active_window_series(label, scraper_id) else {
            return false;
        };
        let bucket_is_monotonic = buckets.iter().all(|bucket| {
            series.windows(2).all(|window| {
                window[1].count_buckets.get(*bucket).copied().unwrap_or(0)
                    >= window[0].count_buckets.get(*bucket).copied().unwrap_or(0)
            })
        });
        let totals = series
            .iter()
            .map(|measurement| {
                buckets.iter().fold(0usize, |total, bucket| {
                    total.saturating_add(
                        measurement.count_buckets.get(*bucket).copied().unwrap_or(0),
                    )
                })
            })
            .collect::<Vec<_>>();
        bucket_is_monotonic
            && totals
                .last()
                .zip(totals.first())
                .is_some_and(|(last, first)| last > first)
    }

    fn count_bucket_is_always_zero(
        &self,
        label: &str,
        scraper_id: ScraperId,
        bucket: &str,
    ) -> bool {
        self.scraper_series(label, scraper_id).is_none_or(|series| {
            series
                .iter()
                .all(|measurement| measurement.count_buckets.get(bucket).copied().unwrap_or(0) == 0)
        })
    }

    fn latest_scalar_equals(&self, label: &str, scraper_id: ScraperId, expected: f64) -> bool {
        self.scraper_series(label, scraper_id)
            .and_then(|series| series.last())
            .is_some_and(|measurement| measurement.scalar == expected)
    }

    fn latest_scalar_greater_than(&self, label: &str, scraper_id: ScraperId, minimum: f64) -> bool {
        self.scraper_series(label, scraper_id)
            .and_then(|series| series.last())
            .is_some_and(|measurement| measurement.scalar > minimum)
    }

    fn scalar_gauge_increased(&self, label: &str, scraper_id: ScraperId) -> bool {
        self.active_window_series(label, scraper_id)
            .is_some_and(|series| {
                series.len() >= 2
                    && series
                        .windows(2)
                        .all(|window| window[1].scalar >= window[0].scalar)
                    && series
                        .last()
                        .zip(series.first())
                        .is_some_and(|(last, first)| last.scalar > first.scalar)
            })
    }

    fn gauge_always_at_most(&self, label: &str, scraper_id: ScraperId, maximum: f64) -> bool {
        self.scraper_series(label, scraper_id)
            .is_some_and(|series| {
                !series.is_empty()
                    && series.iter().all(|measurement| {
                        measurement.scalar >= 0.0 && measurement.scalar <= maximum
                    })
            })
    }

    /// Aggregate the benchmark duration of multiple data points by taking the
    /// max.
    pub fn benchmark_duration(&self) -> Duration {
        self.labels()
            .map(|label| self.max_result(label, |x| x.timestamp))
            .max()
            .unwrap_or_default()
    }

    fn aggregate_rate(&self, label: &str) -> f64 {
        let duration_secs = self.max_result(label, |x| x.timestamp).as_secs_f64();
        if duration_secs == 0.0 {
            return 0.0;
        }

        self.max_result(label, |x| x.count) as f64 / duration_secs
    }

    /// Aggregate the per-scraper bandwidth in bytes per second over the
    /// active submission window only.
    ///
    /// The validator's `benchmark_duration` Prometheus counter is gated so
    /// it stays at zero during warmup; the first scrape with a non-zero
    /// timestamp therefore marks the start of the active window. This
    /// function takes the delta of the cumulative `bytes_sent_total`
    /// (or `count`) counter between that baseline scrape and the latest
    /// scrape, dividing by the same delta in timestamps. For old runs
    /// where `benchmark_duration` ticked from boot, `timestamp > 0` from
    /// the first scrape onwards and the formula degenerates to today's
    /// behavior.
    pub fn aggregate_bandwidth(&self, label: &str) -> Vec<f64> {
        let Some(scraper_data) = self.data.get(label) else {
            return Vec::new();
        };
        scraper_data
            .values()
            .filter_map(|samples| {
                let baseline = samples
                    .iter()
                    .find(|s| s.timestamp.as_secs() > 0)
                    .or_else(|| samples.first())?;
                let last = samples.last()?;
                let dt = last.timestamp.as_secs_f64() - baseline.timestamp.as_secs_f64();
                if dt <= 0.0 {
                    return None;
                }
                let pick = |m: &Measurement| {
                    if m.scalar > 0.0 {
                        m.scalar
                    } else {
                        m.count as f64
                    }
                };
                Some((pick(last) - pick(baseline)) / dt)
            })
            .collect()
    }

    fn percentile(values: &[f64], percentile: f64) -> f64 {
        if values.is_empty() {
            return 0.0;
        }

        let mut sorted = values.to_vec();
        sorted.sort_by(f64::total_cmp);

        let last_index = sorted.len() - 1;
        if last_index == 0 {
            return sorted[0];
        }

        let position = percentile.clamp(0.0, 1.0) * last_index as f64;
        let lower = position.floor() as usize;
        let upper = position.ceil() as usize;
        if lower == upper {
            return sorted[lower];
        }

        let weight = position - lower as f64;
        sorted[lower] + (sorted[upper] - sorted[lower]) * weight
    }

    fn percentile_summary(values: &[f64]) -> PercentileSummary {
        PercentileSummary {
            p25: Self::percentile(values, 0.25),
            p50: Self::percentile(values, 0.50),
            p75: Self::percentile(values, 0.75),
            p90: Self::percentile(values, 0.90),
            p99: Self::percentile(values, 0.99),
        }
    }

    fn median_latency_bucket_ms(&self, label: &str, bucket: &str) -> f64 {
        let values: Vec<_> = self
            .latest_measurements(label)
            .into_iter()
            .filter_map(|measurement| measurement.buckets.get(bucket))
            .map(|duration| duration.as_secs_f64() * 1_000.0)
            .collect();
        Self::percentile(&values, 0.50)
    }

    fn tps(&self) -> f64 {
        let rate = self.aggregate_rate("transaction_committed_latency");
        if rate > 0.0 {
            rate
        } else {
            self.aggregate_rate("sequenced_transactions_total")
        }
    }

    fn bps(&self) -> f64 {
        self.aggregate_rate("block_committed_latency")
    }

    fn highest_dag_round_by_scraper(&self) -> HashMap<ScraperId, f64> {
        self.latest_measurements_with_scraper_ids("dag_highest_round")
            .into_iter()
            .map(|(scraper_id, measurement)| (scraper_id, measurement.scalar))
            .collect()
    }

    fn total_bandwidth_samples(&self) -> Vec<f64> {
        self.aggregate_bandwidth("bytes_sent_total")
    }

    /// Per-validator CPU usage in cores, averaged over the active window.
    ///
    /// `process_cpu_seconds_total` is exposed by Prometheus's process
    /// collector and ticks from validator boot, so we compute the rate as a
    /// delta between the first in-window scrape (the earliest with a
    /// non-zero `benchmark_duration` timestamp) and the latest scrape.
    /// For old runs without active-window gating this falls back to the
    /// first sample in the series and produces today's "boot-to-end" rate.
    fn cpu_samples(&self) -> Vec<f64> {
        let Some(scraper_data) = self.data.get("process_cpu_seconds_total") else {
            return Vec::new();
        };
        scraper_data
            .values()
            .filter_map(|samples| {
                let baseline = samples
                    .iter()
                    .find(|s| s.timestamp.as_secs() > 0)
                    .or_else(|| samples.first())?;
                let last = samples.last()?;
                let dt = last.timestamp.as_secs_f64() - baseline.timestamp.as_secs_f64();
                if dt <= 0.0 {
                    return None;
                }
                Some((last.scalar - baseline.scalar) / dt)
            })
            .collect()
    }

    fn db_size_samples(&self) -> Vec<f64> {
        self.db_sizes.iter().map(|size| *size as f64).collect()
    }

    fn average_latest_weighted_scalar(&self, label: &str) -> f64 {
        let measurements = self.latest_measurements(label);
        let total_sum: f64 = measurements
            .iter()
            .map(|measurement| measurement.scalar)
            .sum();
        let total_count: usize = measurements
            .iter()
            .map(|measurement| measurement.count)
            .sum();
        if total_count == 0 {
            0.0
        } else {
            total_sum / total_count as f64
        }
    }

    fn average_latest_scalar_per_round(&self, label: &str) -> f64 {
        let highest_dag_rounds = self.highest_dag_round_by_scraper();
        let values: Vec<_> = self
            .latest_measurements_with_scraper_ids(label)
            .into_iter()
            .filter_map(|(scraper_id, measurement)| {
                let highest_dag_round = highest_dag_rounds.get(&scraper_id).copied().unwrap_or(0.0);
                (highest_dag_round > 0.0).then_some(measurement.scalar / highest_dag_round)
            })
            .collect();
        if values.is_empty() {
            0.0
        } else {
            values.iter().sum::<f64>() / values.len() as f64
        }
    }

    pub fn benchmark_run_summary(&self) -> BenchmarkRunSummary {
        let duration_secs = self.benchmark_duration().as_secs_f64();
        let tps = self.tps();
        let bps = self.bps();
        let bandwidth_samples = self.total_bandwidth_samples();
        let db_size_samples = self.db_size_samples();
        let highest_dag_rounds = self.highest_dag_round_by_scraper();
        let transaction_size = self.parameters.client_parameters.transaction_size.max(1) as f64;
        let efficiency_samples: Vec<_> = bandwidth_samples
            .iter()
            .map(|bytes_per_sec| {
                if tps == 0.0 {
                    0.0
                } else {
                    bytes_per_sec / (tps * transaction_size)
                }
            })
            .collect();
        let bandwidth_per_round_samples: Vec<_> = self
            .latest_measurements_with_scraper_ids("bytes_sent_total")
            .iter()
            .map(|(scraper_id, measurement)| {
                let highest_dag_round = highest_dag_rounds.get(scraper_id).copied().unwrap_or(0.0);
                if highest_dag_round == 0.0 {
                    0.0
                } else {
                    measurement.scalar / highest_dag_round
                }
            })
            .collect();
        let db_size_per_round_samples: Vec<_> = db_size_samples
            .iter()
            .enumerate()
            .map(|(scraper_id, db_size)| {
                let highest_dag_round = highest_dag_rounds.get(&scraper_id).copied().unwrap_or(0.0);
                if highest_dag_round == 0.0 {
                    0.0
                } else {
                    db_size / highest_dag_round
                }
            })
            .collect();
        let shadow_enabled = self.parameters.consensus_protocol == "starfish-rbc"
            && self.parameters.node_parameters.starfish_rbc_dag_shadow;
        let shadow_autonomous_clock_enabled = shadow_enabled
            && self
                .parameters
                .node_parameters
                .starfish_rbc_dag_autonomous_clock;
        let embedded_rbc_authority = self
            .parameters
            .node_parameters
            .starfish_rbc_dag_embedded_rbc_authority;
        let shadow_comparison_enabled = shadow_enabled && !shadow_autonomous_clock_enabled;
        let shadow_valid_scrapers = self
            .data
            .get("starfish_rbc_dag_shadow_comparison_valid")
            .map(|by_scraper| {
                by_scraper
                    .keys()
                    .copied()
                    .filter(|scraper_id| {
                        self.gauge_always_equals(
                            "starfish_rbc_dag_shadow_comparison_valid",
                            *scraper_id,
                            1.0,
                        )
                    })
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let shadow_comparison_valid_nodes = shadow_valid_scrapers.len();
        let shadow_delivery_matches = self.sum_count_bucket_increments(
            "starfish_rbc_dag_shadow_delivery_comparisons_total",
            "match",
        );
        let shadow_delivery_mismatches = ["mismatch", "direct_only", "shadow_only"]
            .into_iter()
            .map(|bucket| {
                self.sum_count_bucket_increments(
                    "starfish_rbc_dag_shadow_delivery_comparisons_total",
                    bucket,
                )
            })
            .sum();
        let shadow_delivery_ambiguous = self.sum_count_bucket_increments(
            "starfish_rbc_dag_shadow_delivery_comparisons_total",
            "ambiguous",
        );
        let shadow_direct_deliveries = self
            .sum_count_bucket_increments("starfish_rbc_dag_shadow_inputs_total", "delivery,direct");
        let shadow_deliveries = self
            .sum_count_bucket_increments("starfish_rbc_dag_shadow_inputs_total", "delivery,shadow");
        let shadow_wal_durable_records =
            self.sum_scalar_counter_increments("starfish_rbc_dag_shadow_wal_durable_records_total");
        let shadow_wal_appended_records = self
            .sum_scalar_counter_increments("starfish_rbc_dag_shadow_wal_appended_records_total");
        let shadow_pending_recovery =
            self.sum_latest_scalar_as_usize("starfish_rbc_dag_shadow_pending_recovery");
        let shadow_unpaired_direct =
            self.sum_latest_scalar_as_usize("starfish_rbc_dag_shadow_unpaired_direct");
        let shadow_unpaired_shadow =
            self.sum_latest_scalar_as_usize("starfish_rbc_dag_shadow_unpaired_shadow");
        let shadow_unpaired_max_round_lag = self.max_result(
            "starfish_rbc_dag_shadow_unpaired_max_round_lag",
            |measurement| measurement.scalar.max(0.0) as usize,
        );
        let maximum_unpaired_per_node = STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_FACTOR
            .saturating_mul(i64::try_from(self.parameters.nodes).unwrap_or(i64::MAX));
        let every_shadow_scraper_has_coverage = shadow_valid_scrapers.iter().all(|scraper_id| {
            self.count_bucket_is_monotonic_and_positive(
                "starfish_rbc_dag_shadow_inputs_total",
                *scraper_id,
                "delivery,direct",
            ) && self.count_bucket_is_monotonic_and_positive(
                "starfish_rbc_dag_shadow_inputs_total",
                *scraper_id,
                "delivery,shadow",
            ) && self.count_bucket_is_monotonic_and_positive(
                "starfish_rbc_dag_shadow_delivery_comparisons_total",
                *scraper_id,
                "match",
            ) && self.count_bucket_is_always_zero(
                "starfish_rbc_dag_shadow_delivery_comparisons_total",
                *scraper_id,
                "mismatch",
            ) && self.count_bucket_is_always_zero(
                "starfish_rbc_dag_shadow_delivery_comparisons_total",
                *scraper_id,
                "direct_only",
            ) && self.count_bucket_is_always_zero(
                "starfish_rbc_dag_shadow_delivery_comparisons_total",
                *scraper_id,
                "shadow_only",
            ) && self.count_bucket_is_always_zero(
                "starfish_rbc_dag_shadow_delivery_comparisons_total",
                *scraper_id,
                "ambiguous",
            ) && self.count_bucket_is_monotonic_and_positive(
                "starfish_rbc_dag_shadow_inputs_total",
                *scraper_id,
                "delivery,shadow",
            ) && self.scalar_counter_is_monotonic_and_positive(
                "starfish_rbc_dag_shadow_wal_appended_records_total",
                *scraper_id,
            ) && self.latest_scalar_equals(
                "starfish_rbc_dag_shadow_pending_recovery",
                *scraper_id,
                0.0,
            ) && self.gauge_always_at_most(
                "starfish_rbc_dag_shadow_unpaired_direct",
                *scraper_id,
                maximum_unpaired_per_node as f64,
            ) && self.gauge_always_at_most(
                "starfish_rbc_dag_shadow_unpaired_shadow",
                *scraper_id,
                maximum_unpaired_per_node as f64,
            ) && self.gauge_always_at_most(
                "starfish_rbc_dag_shadow_unpaired_max_round_lag",
                *scraper_id,
                STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_ROUND_LAG as f64,
            )
        });
        let expected_shadow_nodes = self.ready_nodes_at_boot();
        let shadow_comparison_valid = shadow_comparison_enabled
            && shadow_comparison_valid_nodes == expected_shadow_nodes
            && every_shadow_scraper_has_coverage
            && shadow_delivery_mismatches == 0
            && shadow_delivery_ambiguous == 0;
        let shadow_autonomous_clock_valid_scrapers = self
            .data
            .get(SHADOW_AUTONOMOUS_CLOCK_VALID_METRIC)
            .map(|by_scraper| {
                by_scraper
                    .keys()
                    .copied()
                    .filter(|scraper_id| {
                        self.gauge_always_equals(
                            SHADOW_AUTONOMOUS_CLOCK_VALID_METRIC,
                            *scraper_id,
                            1.0,
                        )
                    })
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let shadow_autonomous_clock_valid_nodes = shadow_autonomous_clock_valid_scrapers.len();
        let (
            shadow_autonomous_clock_carrier_round_min,
            shadow_autonomous_clock_carrier_round_max,
            shadow_autonomous_clock_phase_backlog_total,
            shadow_autonomous_clock_admitted_authors_min,
            shadow_autonomous_clock_admitted_stake_min,
            shadow_autonomous_clock_buffered_authenticated_total,
        ) = if shadow_autonomous_clock_enabled {
            (
                self.min_latest_scalar_as_usize("starfish_rbc_dag_shadow_carrier_round"),
                self.max_result("starfish_rbc_dag_shadow_carrier_round", |measurement| {
                    measurement.scalar.max(0.0) as usize
                }),
                self.sum_latest_scalar_as_usize("starfish_rbc_dag_shadow_phase_backlog"),
                self.min_latest_scalar_as_usize("starfish_rbc_dag_shadow_admitted_authors"),
                self.min_latest_scalar_as_usize("starfish_rbc_dag_shadow_admitted_stake"),
                self.sum_latest_scalar_as_usize("starfish_rbc_dag_shadow_buffered_authenticated"),
            )
        } else {
            (0, 0, 0, 0, 0, 0)
        };
        let autonomous_phase_backlog_bound = STARFISH_RBC_DAG_AUTONOMOUS_MAX_PHASE_BACKLOG_FACTOR
            .saturating_mul(i64::try_from(self.parameters.nodes).unwrap_or(i64::MAX));
        let autonomous_buffered_bound = STARFISH_RBC_DAG_AUTONOMOUS_MAX_BUFFERED_FACTOR
            .saturating_mul(i64::try_from(self.parameters.nodes).unwrap_or(i64::MAX));
        let every_autonomous_scraper_has_progress = shadow_autonomous_clock_valid_scrapers
            .iter()
            .all(|scraper_id| {
                self.count_bucket_sum_increased(
                    "starfish_rbc_dag_shadow_inputs_total",
                    *scraper_id,
                    &["heartbeat,accepted", "application_carrier,accepted"],
                ) && self.count_bucket_increased(
                    "starfish_rbc_dag_shadow_inputs_total",
                    *scraper_id,
                    "delivery,shadow",
                ) && self.scalar_counter_increased(
                    "starfish_rbc_dag_shadow_wal_appended_batches_total",
                    *scraper_id,
                ) && self.scalar_counter_increased(
                    "starfish_rbc_dag_shadow_wal_appended_records_total",
                    *scraper_id,
                ) && self.scalar_counter_increased(
                    "starfish_rbc_dag_projected_vertices_total",
                    *scraper_id,
                ) && self.count_bucket_increased(
                    "starfish_rbc_dag_projection_decisions_total",
                    *scraper_id,
                    "direct_commit",
                ) && (!embedded_rbc_authority
                    || self.count_bucket_increased(
                        "starfish_rbc_dag_shadow_inputs_total",
                        *scraper_id,
                        "frontier,committed",
                    ) && self.count_bucket_increased(
                        "starfish_rbc_dag_shadow_inputs_total",
                        *scraper_id,
                        "frontier,application",
                    ))
                    && self.scalar_gauge_increased(
                        "starfish_rbc_dag_shadow_carrier_round",
                        *scraper_id,
                    )
                    && self.latest_scalar_greater_than(
                        "starfish_rbc_dag_shadow_carrier_round",
                        *scraper_id,
                        1.0,
                    )
                    && self.latest_scalar_equals(
                        "starfish_rbc_dag_shadow_pending_recovery",
                        *scraper_id,
                        0.0,
                    )
                    && self.gauge_always_at_most(
                        "starfish_rbc_dag_shadow_phase_backlog",
                        *scraper_id,
                        autonomous_phase_backlog_bound as f64,
                    )
                    && self.gauge_always_at_most(
                        "starfish_rbc_dag_shadow_admitted_authors",
                        *scraper_id,
                        self.parameters.nodes as f64,
                    )
                    && self.gauge_always_at_most(
                        "starfish_rbc_dag_shadow_admitted_stake",
                        *scraper_id,
                        f64::MAX,
                    )
                    && self.gauge_always_at_most(
                        "starfish_rbc_dag_shadow_buffered_authenticated",
                        *scraper_id,
                        autonomous_buffered_bound as f64,
                    )
            });
        let shadow_autonomous_clock_valid = shadow_autonomous_clock_enabled
            && expected_shadow_nodes != 0
            && shadow_autonomous_clock_valid_nodes == expected_shadow_nodes
            && every_autonomous_scraper_has_progress
            && shadow_autonomous_clock_carrier_round_max
                .saturating_sub(shadow_autonomous_clock_carrier_round_min)
                <= usize::try_from(STARFISH_RBC_DAG_AUTONOMOUS_MAX_ROUND_LAG).unwrap_or(usize::MAX);

        BenchmarkRunSummary {
            protocol: self.parameters.consensus_protocol.clone(),
            committee: self.parameters.nodes,
            load: self.parameters.load,
            transaction_size_bytes: self.parameters.client_parameters.transaction_size,
            duration_secs,
            tps,
            bps,
            transaction_latency_ms: PercentileSummary {
                p25: self.median_latency_bucket_ms("transaction_committed_latency", "p25"),
                p50: self.median_latency_bucket_ms("transaction_committed_latency", "p50"),
                p75: self.median_latency_bucket_ms("transaction_committed_latency", "p75"),
                p90: self.median_latency_bucket_ms("transaction_committed_latency", "p90"),
                p99: self.median_latency_bucket_ms("transaction_committed_latency", "p99"),
            },
            block_latency_ms: PercentileSummary {
                p25: self.median_latency_bucket_ms("block_committed_latency", "p25"),
                p50: self.median_latency_bucket_ms("block_committed_latency", "p50"),
                p75: self.median_latency_bucket_ms("block_committed_latency", "p75"),
                p90: self.median_latency_bucket_ms("block_committed_latency", "p90"),
                p99: self.median_latency_bucket_ms("block_committed_latency", "p99"),
            },
            bandwidth_efficiency: Self::percentile_summary(&efficiency_samples),
            bandwidth_per_round_bytes: Self::percentile_summary(&bandwidth_per_round_samples),
            cpu_cores: Self::percentile_summary(&self.cpu_samples()),
            db_size_per_round_bytes: Self::percentile_summary(&db_size_per_round_samples),
            block_sync_requests_sent_per_round_avg: self
                .average_latest_scalar_per_round("block_sync_requests_sent"),
            block_header_size_avg_bytes: self
                .average_latest_weighted_scalar("proposed_header_size_bytes"),
            ready_nodes_at_boot: self.ready_nodes_at_boot(),
            metrics_contributors: self.metrics_contributors(),
            shadow_comparison_enabled,
            shadow_comparison_valid,
            shadow_comparison_valid_nodes,
            shadow_direct_deliveries,
            shadow_deliveries,
            shadow_delivery_matches,
            shadow_delivery_mismatches,
            shadow_delivery_ambiguous,
            shadow_wal_appended_records,
            shadow_wal_durable_records,
            shadow_pending_recovery,
            shadow_unpaired_direct,
            shadow_unpaired_shadow,
            shadow_unpaired_max_round_lag,
            shadow_autonomous_clock_enabled,
            shadow_autonomous_clock_valid,
            shadow_autonomous_clock_valid_nodes,
            shadow_autonomous_clock_carrier_round_min,
            shadow_autonomous_clock_carrier_round_max,
            shadow_autonomous_clock_phase_backlog_total,
            shadow_autonomous_clock_admitted_authors_min,
            shadow_autonomous_clock_admitted_stake_min,
            shadow_autonomous_clock_buffered_authenticated_total,
        }
    }

    /// Save the collection of measurements as a json file.
    pub fn save<P: AsRef<Path>>(&self, path: P) {
        let json = serde_json::to_string_pretty(self).expect("Cannot serialize metrics");
        let mut file = PathBuf::from(path.as_ref());
        let file_name = if self.parameters.benchmark_run_id.is_empty() {
            format!("measurements-{:?}.json", self.parameters)
        } else {
            format!("measurements-{}.json", self.parameters.benchmark_run_id)
        };
        file.push(file_name);
        fs::write(file, json).unwrap();
    }

    /// Display a summary of the measurements.
    pub fn display_summary(&self) {
        let mut table = Table::new();
        table.set_format(display::default_table_format());

        let duration = self.benchmark_duration();
        let summary = self.benchmark_run_summary();
        table.set_titles(row![bH2->"Benchmark Summary"]);
        table.add_row(row![b->"Benchmark type:", self.parameters.node_parameters]);
        table.add_row(row![bH2->""]);
        table.add_row(row![b->"Protocol:", self.parameters.consensus_protocol]);
        table.add_row(row![b->"Nodes:", self.parameters.nodes]);
        table.add_row(row![
            b->"Ready at boot:",
            format!("{}/{} validators", summary.ready_nodes_at_boot, summary.committee)
        ]);
        table.add_row(row![
            b->"Metrics coverage:",
            format!(
                "{}/{} validators",
                summary.metrics_contributors, summary.committee
            )
        ]);
        table.add_row(row![b->"Byzantine strategy:", self.parameters.byzantine_strategy]);
        table.add_row(row![b->"Byzantine nodes:", self.parameters.byzantine_nodes]);
        table.add_row(
            row![b->"Use internal IPs:", format!("{}", self.parameters.use_internal_ip_address)],
        );
        table.add_row(row![b->"Faults:", self.parameters.settings.faults]);
        table.add_row(row![b->"Load:", format!("{} tx/s", self.parameters.load)]);
        table.add_row(row![b->"Duration:", format!("{:.1} s", duration.as_secs_f64())]);
        table.add_row(row![b->"TPS:", format!("{:.2} tx/s", summary.tps)]);
        table.add_row(row![b->"BPS:", format!("{:.2} blocks/s", summary.bps)]);
        if summary.shadow_comparison_enabled {
            table.add_row(row![
                b->"RBC-DAG shadow:",
                format!(
                    "valid={} ({}/{} validators), direct={}, shadow={}, matches={}, \
                     mismatches={}, ambiguous={}, WAL appended/durable records={}/{}, pending recovery={}, \
                     unpaired direct/shadow={}/{}, max unpaired lag={} rounds",
                    summary.shadow_comparison_valid,
                    summary.shadow_comparison_valid_nodes,
                    summary.ready_nodes_at_boot,
                    summary.shadow_direct_deliveries,
                    summary.shadow_deliveries,
                    summary.shadow_delivery_matches,
                    summary.shadow_delivery_mismatches,
                    summary.shadow_delivery_ambiguous,
                    summary.shadow_wal_appended_records,
                    summary.shadow_wal_durable_records,
                    summary.shadow_pending_recovery,
                    summary.shadow_unpaired_direct,
                    summary.shadow_unpaired_shadow,
                    summary.shadow_unpaired_max_round_lag,
                )
            ]);
        }
        if summary.shadow_autonomous_clock_enabled {
            table.add_row(row![
                b->"RBC-DAG autonomous clock:",
                format!(
                    "valid={} ({}/{} validators), carrier rounds={}..={}, embedded deliveries={}, phase backlog={}, \
                     admitted authors/stake min={}/{}, buffered authenticated={}, WAL appended/durable records={}/{}, \
                     pending recovery={}",
                    summary.shadow_autonomous_clock_valid,
                    summary.shadow_autonomous_clock_valid_nodes,
                    summary.ready_nodes_at_boot,
                    summary.shadow_autonomous_clock_carrier_round_min,
                    summary.shadow_autonomous_clock_carrier_round_max,
                    summary.shadow_deliveries,
                    summary.shadow_autonomous_clock_phase_backlog_total,
                    summary.shadow_autonomous_clock_admitted_authors_min,
                    summary.shadow_autonomous_clock_admitted_stake_min,
                    summary.shadow_autonomous_clock_buffered_authenticated_total,
                    summary.shadow_wal_appended_records,
                    summary.shadow_wal_durable_records,
                    summary.shadow_pending_recovery,
                )
            ]);
        }
        table.add_row(row![
            b->"End-to-end latency:",
            format!(
                "p25={:.2} ms, p50={:.2} ms, p75={:.2} ms",
                summary.transaction_latency_ms.p25,
                summary.transaction_latency_ms.p50,
                summary.transaction_latency_ms.p75
            )
        ]);
        table.add_row(row![
            b->"Block latency:",
            format!(
                "p25={:.2} ms, p50={:.2} ms, p75={:.2} ms",
                summary.block_latency_ms.p25,
                summary.block_latency_ms.p50,
                summary.block_latency_ms.p75
            )
        ]);
        table.add_row(row![
            b->"Bandwidth efficiency:",
            format!(
                "p25={:.4}, p50={:.4}, p75={:.4}",
                summary.bandwidth_efficiency.p25,
                summary.bandwidth_efficiency.p50,
                summary.bandwidth_efficiency.p75
            )
        ]);
        table.add_row(row![
            b->"Bandwidth / round:",
            format!(
                "p25={:.2} B, p50={:.2} B, p75={:.2} B",
                summary.bandwidth_per_round_bytes.p25,
                summary.bandwidth_per_round_bytes.p50,
                summary.bandwidth_per_round_bytes.p75
            )
        ]);
        table.add_row(row![
            b->"CPU usage:",
            format!(
                "p25={:.3}, p50={:.3}, p75={:.3} cores",
                summary.cpu_cores.p25,
                summary.cpu_cores.p50,
                summary.cpu_cores.p75
            )
        ]);
        table.add_row(row![
            b->"DB size / round:",
            format!(
                "p25={:.2} B, p50={:.2} B, p75={:.2} B",
                summary.db_size_per_round_bytes.p25,
                summary.db_size_per_round_bytes.p50,
                summary.db_size_per_round_bytes.p75
            )
        ]);
        table.add_row(row![
            b->"Block sync requests / round / node:",
            format!("{:.3} requests", summary.block_sync_requests_sent_per_round_avg)
        ]);
        table.add_row(row![
            b->"Block header size avg:",
            format!("{:.2} B", summary.block_header_size_avg_bytes)
        ]);

        display::newline();
        table.printstd();
        display::newline();
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, time::Duration};

    use super::{BenchmarkParameters, Measurement, MeasurementsCollection};
    use crate::protocol::test_protocol_metrics::TestProtocolMetrics;

    fn shadow_benchmark_parameters(nodes: usize) -> BenchmarkParameters {
        let mut parameters = BenchmarkParameters::new_for_tests();
        parameters.nodes = nodes;
        parameters.consensus_protocol = "starfish-rbc".to_owned();
        parameters.node_parameters.starfish_rbc_dag_shadow = true;
        parameters
    }

    fn autonomous_shadow_benchmark_parameters(nodes: usize) -> BenchmarkParameters {
        let mut parameters = shadow_benchmark_parameters(nodes);
        parameters.node_parameters.starfish_rbc_dag_autonomous_clock = true;
        parameters
    }

    #[allow(clippy::too_many_arguments)]
    fn add_shadow_snapshot(
        collection: &mut MeasurementsCollection,
        scraper_id: usize,
        comparison_valid: f64,
        direct_deliveries: usize,
        shadow_deliveries: usize,
        matches: usize,
        mismatches: usize,
        direct_only: usize,
        shadow_only: usize,
        ambiguous: usize,
        wal_durable_records: usize,
    ) {
        collection.add(
            scraper_id,
            "starfish_rbc_dag_shadow_comparison_valid".to_owned(),
            Measurement {
                scalar: comparison_valid,
                ..Measurement::default()
            },
        );
        collection.add(
            scraper_id,
            "starfish_rbc_dag_shadow_inputs_total".to_owned(),
            Measurement {
                count_buckets: HashMap::from([
                    ("delivery,direct".to_owned(), direct_deliveries),
                    ("delivery,shadow".to_owned(), shadow_deliveries),
                ]),
                count: direct_deliveries + shadow_deliveries,
                ..Measurement::default()
            },
        );
        collection.add(
            scraper_id,
            "starfish_rbc_dag_shadow_delivery_comparisons_total".to_owned(),
            Measurement {
                count_buckets: HashMap::from([
                    ("match".to_owned(), matches),
                    ("mismatch".to_owned(), mismatches),
                    ("direct_only".to_owned(), direct_only),
                    ("shadow_only".to_owned(), shadow_only),
                    ("ambiguous".to_owned(), ambiguous),
                ]),
                count: matches + mismatches + direct_only + shadow_only + ambiguous,
                ..Measurement::default()
            },
        );
        collection.add(
            scraper_id,
            "starfish_rbc_dag_shadow_wal_appended_records_total".to_owned(),
            Measurement {
                count: wal_durable_records,
                scalar: wal_durable_records as f64,
                ..Measurement::default()
            },
        );
        collection.add(
            scraper_id,
            "starfish_rbc_dag_shadow_wal_durable_records_total".to_owned(),
            Measurement {
                count: wal_durable_records,
                scalar: wal_durable_records as f64,
                ..Measurement::default()
            },
        );
        collection.add(
            scraper_id,
            "starfish_rbc_dag_shadow_pending_recovery".to_owned(),
            Measurement::default(),
        );
        add_shadow_backlog_snapshot(collection, scraper_id, 0, 0, 0);
    }

    fn add_shadow_backlog_snapshot(
        collection: &mut MeasurementsCollection,
        scraper_id: usize,
        unpaired_direct: usize,
        unpaired_shadow: usize,
        max_round_lag: usize,
    ) {
        for (label, value) in [
            ("starfish_rbc_dag_shadow_unpaired_direct", unpaired_direct),
            ("starfish_rbc_dag_shadow_unpaired_shadow", unpaired_shadow),
            (
                "starfish_rbc_dag_shadow_unpaired_max_round_lag",
                max_round_lag,
            ),
        ] {
            collection.add(
                scraper_id,
                label.to_owned(),
                Measurement {
                    scalar: value as f64,
                    ..Measurement::default()
                },
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_autonomous_clock_snapshot(
        collection: &mut MeasurementsCollection,
        scraper_id: usize,
        clock_valid: f64,
        carrier_round: usize,
        phase_backlog: usize,
        admitted_authors: usize,
        admitted_stake: usize,
        buffered_authenticated: usize,
        wal_durable_records: usize,
    ) {
        let timestamp = Duration::from_secs(carrier_round as u64);
        for (label, value) in [
            ("starfish_rbc_dag_shadow_clock_valid", clock_valid),
            (
                "starfish_rbc_dag_shadow_carrier_round",
                carrier_round as f64,
            ),
            (
                "starfish_rbc_dag_shadow_phase_backlog",
                phase_backlog as f64,
            ),
            (
                "starfish_rbc_dag_shadow_admitted_authors",
                admitted_authors as f64,
            ),
            (
                "starfish_rbc_dag_shadow_admitted_stake",
                admitted_stake as f64,
            ),
            (
                "starfish_rbc_dag_shadow_buffered_authenticated",
                buffered_authenticated as f64,
            ),
        ] {
            collection.add(
                scraper_id,
                label.to_owned(),
                Measurement {
                    timestamp,
                    scalar: value,
                    ..Measurement::default()
                },
            );
        }
        collection.add(
            scraper_id,
            "starfish_rbc_dag_shadow_inputs_total".to_owned(),
            Measurement {
                timestamp,
                count_buckets: HashMap::from([
                    (
                        "application_carrier,accepted".to_owned(),
                        wal_durable_records,
                    ),
                    ("delivery,shadow".to_owned(), wal_durable_records),
                    ("frontier,committed".to_owned(), wal_durable_records),
                    ("frontier,application".to_owned(), wal_durable_records),
                ]),
                count: wal_durable_records.saturating_mul(4),
                ..Measurement::default()
            },
        );
        collection.add(
            scraper_id,
            "starfish_rbc_dag_shadow_wal_appended_batches_total".to_owned(),
            Measurement {
                timestamp,
                count: wal_durable_records,
                scalar: wal_durable_records as f64,
                ..Measurement::default()
            },
        );
        collection.add(
            scraper_id,
            "starfish_rbc_dag_shadow_wal_appended_records_total".to_owned(),
            Measurement {
                timestamp,
                count: wal_durable_records,
                scalar: wal_durable_records as f64,
                ..Measurement::default()
            },
        );
        collection.add(
            scraper_id,
            "starfish_rbc_dag_shadow_wal_durable_batches_total".to_owned(),
            Measurement {
                timestamp,
                count: wal_durable_records,
                scalar: wal_durable_records as f64,
                ..Measurement::default()
            },
        );
        collection.add(
            scraper_id,
            "starfish_rbc_dag_shadow_wal_durable_records_total".to_owned(),
            Measurement {
                timestamp,
                count: wal_durable_records,
                scalar: wal_durable_records as f64,
                ..Measurement::default()
            },
        );
        collection.add(
            scraper_id,
            "starfish_rbc_dag_projected_vertices_total".to_owned(),
            Measurement {
                timestamp,
                count: wal_durable_records,
                scalar: wal_durable_records as f64,
                ..Measurement::default()
            },
        );
        collection.add(
            scraper_id,
            "starfish_rbc_dag_projection_decisions_total".to_owned(),
            Measurement {
                timestamp,
                count_buckets: HashMap::from([("direct_commit".to_owned(), wal_durable_records)]),
                count: wal_durable_records,
                ..Measurement::default()
            },
        );
        collection.add(
            scraper_id,
            "starfish_rbc_dag_shadow_pending_recovery".to_owned(),
            Measurement {
                timestamp,
                ..Measurement::default()
            },
        );
    }

    #[test]
    fn average_latency() {
        let data = Measurement {
            timestamp: Duration::from_secs(10),
            buckets: HashMap::new(),
            count_buckets: HashMap::new(),
            sum: Duration::from_secs(2),
            count: 100,
            squared_sum: 0.0,
            scalar: 0.0,
        };

        assert_eq!(data.average_latency(), Duration::from_millis(20));
    }

    #[test]
    fn prometheus_parse() {
        let report = r#"
# HELP benchmark_duration Duration of the benchmark
# TYPE benchmark_duration counter
benchmark_duration 300
# HELP block_committed_latency block_committed_latency
# TYPE block_committed_latency gauge
block_committed_latency{v="count"} 28547
block_committed_latency{v="p50"} 487770
block_committed_latency{v="p90"} 719253
block_committed_latency{v="p99"} 848723
block_committed_latency{v="sum"} 17374616335344112
# HELP block_committed_latency_squared_micros Squared latency
# TYPE block_committed_latency_squared_micros counter
block_committed_latency_squared_micros 13465046685909033000
# HELP sequenced_transactions_total Total sequenced txs
# TYPE sequenced_transactions_total counter
sequenced_transactions_total 2310200
# HELP submitted_transactions Total submitted transactions
# TYPE submitted_transactions counter
submitted_transactions 100000
# HELP transaction_committed_latency transaction latency
# TYPE transaction_committed_latency gauge
transaction_committed_latency{v="count"} 2065300
transaction_committed_latency{v="p50"} 522793
transaction_committed_latency{v="p90"} 740793
transaction_committed_latency{v="p99"} 857100
transaction_committed_latency{v="sum"} 1147380944831
# HELP transaction_committed_latency_squared_micros Squared latency
# TYPE transaction_committed_latency_squared_micros counter
transaction_committed_latency_squared_micros 745207728837251500
# HELP bytes_received_total Total number of bytes sent
# TYPE bytes_received_total counter
bytes_received_total 86639456
# HELP bytes_sent_total Total number of bytes sent
# TYPE bytes_sent_total counter
bytes_sent_total 6284648
        "#;

        let measurements = Measurement::from_prometheus::<TestProtocolMetrics>(report);
        let mut aggregator = MeasurementsCollection::new(BenchmarkParameters::new_for_tests());
        let scraper_id = 1;
        for (label, measurement) in measurements {
            aggregator.add(scraper_id, label, measurement);
        }

        assert_eq!(aggregator.data.keys().filter(|x| !x.is_empty()).count(), 5);

        let transaction_committed_latency = aggregator
            .data
            .get("transaction_committed_latency")
            .expect("The `transaction_committed_latency` label is defined above")
            .get(&scraper_id)
            .unwrap();
        assert_eq!(transaction_committed_latency.len(), 1);

        let data = &transaction_committed_latency[0];
        assert_eq!(
            data.buckets,
            ([
                ("p50".into(), Duration::from_micros(522793)),
                ("p90".into(), Duration::from_micros(740793)),
                ("p99".into(), Duration::from_micros(857100)),
            ])
            .iter()
            .cloned()
            .collect()
        );
        assert_eq!(data.sum, Duration::from_micros(1147380944831));
        assert_eq!(data.count, 2065300);
        assert_eq!(data.timestamp.as_secs(), 300);
        assert_eq!(data.squared_sum, 745207728837251500.0);

        let block_committed_latency = aggregator
            .data
            .get("block_committed_latency")
            .expect("The `block_committed_latency` label is defined above")
            .get(&scraper_id)
            .unwrap();
        assert_eq!(block_committed_latency.len(), 1);

        let data = &block_committed_latency[0];
        assert_eq!(
            data.buckets,
            ([
                ("p50".into(), Duration::from_micros(487770)),
                ("p90".into(), Duration::from_micros(719253)),
                ("p99".into(), Duration::from_micros(848723)),
            ])
            .iter()
            .cloned()
            .collect()
        );
        assert_eq!(data.sum, Duration::from_micros(17374616335344112));
        assert_eq!(data.count, 28547);
        assert_eq!(data.timestamp.as_secs(), 300);
        assert_eq!(data.squared_sum, 13465046685909033000.0);

        let sequenced_transactions_total = aggregator
            .data
            .get("sequenced_transactions_total")
            .expect("Unable to find label")
            .get(&scraper_id)
            .unwrap();
        assert_eq!(sequenced_transactions_total.len(), 1);
        let data = &sequenced_transactions_total[0];
        assert_eq!(data.count, 2310200);

        let bytes_received_total = aggregator
            .data
            .get("bytes_received_total")
            .expect("The `bytes_received_total` label is defined above")
            .get(&scraper_id)
            .unwrap();
        assert_eq!(bytes_received_total.len(), 1);

        let data = &bytes_received_total[0];
        assert_eq!(data.count, 86639456);
        assert_eq!(data.timestamp.as_secs(), 300);

        let bytes_sent_total = aggregator
            .data
            .get("bytes_sent_total")
            .expect("The `bytes_sent_total` label is defined above")
            .get(&scraper_id)
            .unwrap();
        assert_eq!(bytes_sent_total.len(), 1);

        let data = &bytes_sent_total[0];
        assert_eq!(data.count, 6284648);
        assert_eq!(data.timestamp.as_secs(), 300);
    }

    #[test]
    fn prometheus_parse_preserves_shadow_verdict_and_coverage() {
        let report = r#"
# TYPE benchmark_duration counter
benchmark_duration 30
# TYPE starfish_rbc_dag_shadow_comparison_valid gauge
starfish_rbc_dag_shadow_comparison_valid{node="node-0"} 1
# TYPE starfish_rbc_dag_shadow_delivery_comparisons_total counter
starfish_rbc_dag_shadow_delivery_comparisons_total{node="node-0",outcome="match"} 7
starfish_rbc_dag_shadow_delivery_comparisons_total{node="node-0",outcome="mismatch"} 0
starfish_rbc_dag_shadow_delivery_comparisons_total{node="node-0",outcome="ambiguous"} 0
# TYPE starfish_rbc_dag_shadow_inputs_total counter
starfish_rbc_dag_shadow_inputs_total{kind="delivery",node="node-0",outcome="shadow"} 7
starfish_rbc_dag_shadow_inputs_total{kind="delivery",node="node-0",outcome="direct"} 7
# TYPE starfish_rbc_dag_shadow_wal_appended_records_total counter
starfish_rbc_dag_shadow_wal_appended_records_total{node="node-0"} 42
# TYPE starfish_rbc_dag_shadow_wal_durable_records_total counter
starfish_rbc_dag_shadow_wal_durable_records_total{node="node-0"} 42
# TYPE starfish_rbc_dag_shadow_wal_replayed_batches gauge
starfish_rbc_dag_shadow_wal_replayed_batches{node="node-0"} 3
# TYPE starfish_rbc_dag_shadow_pending_recovery gauge
starfish_rbc_dag_shadow_pending_recovery{node="node-0"} 0
# TYPE starfish_rbc_dag_shadow_unpaired_direct gauge
starfish_rbc_dag_shadow_unpaired_direct{node="node-0"} 2
# TYPE starfish_rbc_dag_shadow_unpaired_shadow gauge
starfish_rbc_dag_shadow_unpaired_shadow{node="node-0"} 1
# TYPE starfish_rbc_dag_shadow_unpaired_max_round_lag gauge
starfish_rbc_dag_shadow_unpaired_max_round_lag{node="node-0"} 1
"#;

        let measurements = Measurement::from_prometheus::<TestProtocolMetrics>(report);
        assert_eq!(
            measurements["starfish_rbc_dag_shadow_comparison_valid"].scalar,
            1.0
        );
        assert_eq!(
            measurements["starfish_rbc_dag_shadow_delivery_comparisons_total"].count_buckets["match"],
            7
        );
        assert_eq!(
            measurements["starfish_rbc_dag_shadow_inputs_total"].count_buckets["delivery,shadow"],
            7
        );
        assert_eq!(
            measurements["starfish_rbc_dag_shadow_wal_appended_records_total"].scalar,
            42.0
        );
        assert_eq!(
            measurements["starfish_rbc_dag_shadow_wal_durable_records_total"].scalar,
            42.0
        );
        assert_eq!(
            measurements["starfish_rbc_dag_shadow_wal_replayed_batches"].scalar,
            3.0
        );

        let mut parameters = BenchmarkParameters::new_for_tests();
        parameters.nodes = 1;
        parameters.consensus_protocol = "starfish-rbc".to_owned();
        parameters.node_parameters.starfish_rbc_dag_shadow = true;
        let mut collection = MeasurementsCollection::new(parameters);
        for (label, measurement) in measurements {
            collection.add(0, label, measurement);
        }
        let summary = collection.benchmark_run_summary();
        assert!(summary.shadow_comparison_enabled);
        assert!(summary.shadow_comparison_valid);
        assert_eq!(summary.shadow_comparison_valid_nodes, 1);
        assert_eq!(summary.shadow_direct_deliveries, 7);
        assert_eq!(summary.shadow_deliveries, 7);
        assert_eq!(summary.shadow_delivery_matches, 7);
        assert_eq!(summary.shadow_wal_appended_records, 42);
        assert_eq!(summary.shadow_wal_durable_records, 42);
        assert_eq!(summary.shadow_unpaired_direct, 2);
        assert_eq!(summary.shadow_unpaired_shadow, 1);
        assert_eq!(summary.shadow_unpaired_max_round_lag, 1);
    }

    #[test]
    fn prometheus_parse_preserves_autonomous_clock_state() {
        let report = r#"
# TYPE benchmark_duration counter
benchmark_duration 30
# TYPE starfish_rbc_dag_shadow_clock_valid gauge
starfish_rbc_dag_shadow_clock_valid 1
# TYPE starfish_rbc_dag_shadow_carrier_round gauge
starfish_rbc_dag_shadow_carrier_round 12
# TYPE starfish_rbc_dag_shadow_phase_backlog gauge
starfish_rbc_dag_shadow_phase_backlog 3
# TYPE starfish_rbc_dag_shadow_admitted_authors gauge
starfish_rbc_dag_shadow_admitted_authors 4
# TYPE starfish_rbc_dag_shadow_admitted_stake gauge
starfish_rbc_dag_shadow_admitted_stake 7
# TYPE starfish_rbc_dag_shadow_buffered_authenticated gauge
starfish_rbc_dag_shadow_buffered_authenticated 2
"#;

        let measurements = Measurement::from_prometheus::<TestProtocolMetrics>(report);
        for (label, expected) in [
            ("starfish_rbc_dag_shadow_clock_valid", 1.0),
            ("starfish_rbc_dag_shadow_carrier_round", 12.0),
            ("starfish_rbc_dag_shadow_phase_backlog", 3.0),
            ("starfish_rbc_dag_shadow_admitted_authors", 4.0),
            ("starfish_rbc_dag_shadow_admitted_stake", 7.0),
            ("starfish_rbc_dag_shadow_buffered_authenticated", 2.0),
        ] {
            assert_eq!(measurements[label].scalar, expected, "metric {label}");
        }
    }

    #[test]
    fn autonomous_clock_has_a_distinct_sticky_summary() {
        let mut collection = MeasurementsCollection::new(autonomous_shadow_benchmark_parameters(2));
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 8, 1, 2, 7, 1, 5);
        add_autonomous_clock_snapshot(&mut collection, 1, 1.0, 8, 1, 2, 6, 1, 6);
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 12, 3, 2, 7, 2, 10);
        add_autonomous_clock_snapshot(&mut collection, 1, 1.0, 10, 4, 2, 6, 3, 11);

        let summary = collection.benchmark_run_summary();
        assert!(!summary.shadow_comparison_enabled);
        assert!(!summary.shadow_comparison_valid);
        assert!(summary.shadow_autonomous_clock_enabled);
        assert!(summary.shadow_autonomous_clock_valid);
        assert_eq!(summary.shadow_autonomous_clock_valid_nodes, 2);
        assert_eq!(summary.shadow_autonomous_clock_carrier_round_min, 10);
        assert_eq!(summary.shadow_autonomous_clock_carrier_round_max, 12);
        assert_eq!(summary.shadow_autonomous_clock_phase_backlog_total, 7);
        assert_eq!(summary.shadow_autonomous_clock_admitted_authors_min, 2);
        assert_eq!(summary.shadow_autonomous_clock_admitted_stake_min, 6);
        assert_eq!(
            summary.shadow_autonomous_clock_buffered_authenticated_total,
            5
        );
        assert_eq!(summary.shadow_wal_durable_records, 21);

        // A later healthy scrape must not erase an earlier invalid verdict.
        add_autonomous_clock_snapshot(&mut collection, 0, 0.0, 13, 0, 3, 7, 0, 12);
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 14, 0, 3, 7, 0, 13);
        let summary = collection.benchmark_run_summary();
        assert_eq!(summary.shadow_autonomous_clock_valid_nodes, 1);
        assert!(!summary.shadow_autonomous_clock_valid);
    }

    #[test]
    fn autonomous_clock_buffered_wal_uses_appended_progress_without_claiming_durability() {
        let mut collection = MeasurementsCollection::new(autonomous_shadow_benchmark_parameters(1));
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 8, 0, 1, 1, 0, 3);
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 10, 0, 1, 1, 0, 5);
        collection
            .data
            .remove("starfish_rbc_dag_shadow_wal_durable_batches_total");
        collection
            .data
            .remove("starfish_rbc_dag_shadow_wal_durable_records_total");

        let summary = collection.benchmark_run_summary();
        assert!(summary.shadow_autonomous_clock_valid);
        assert_eq!(summary.shadow_wal_appended_records, 5);
        assert_eq!(summary.shadow_wal_durable_records, 0);
    }

    #[test]
    fn missing_final_autonomous_scrape_invalidates_only_clock_verdict() {
        let mut collection = MeasurementsCollection::new(autonomous_shadow_benchmark_parameters(1));
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 8, 0, 1, 7, 0, 5);
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 12, 0, 1, 7, 0, 10);
        assert!(
            collection
                .benchmark_run_summary()
                .shadow_autonomous_clock_valid
        );

        collection.mark_shadow_final_scrape_missing(0);

        let validity = collection
            .scraper_series("starfish_rbc_dag_shadow_clock_valid", 0)
            .unwrap();
        assert_eq!(validity.last().unwrap().scalar_value(), 0.0);
        assert!(
            collection
                .scraper_series("starfish_rbc_dag_shadow_comparison_valid", 0)
                .is_none()
        );
        let summary = collection.benchmark_run_summary();
        assert_eq!(summary.shadow_autonomous_clock_valid_nodes, 0);
        assert!(!summary.shadow_autonomous_clock_valid);
    }

    #[test]
    fn shadow_verdict_remains_invalid_after_historical_failure_and_counter_reset() {
        let mut collection = MeasurementsCollection::new(shadow_benchmark_parameters(1));

        // The first scrape records an invalid gauge and every non-match
        // comparison category. The second scrape deliberately looks clean,
        // including reset comparison counters, so a latest-value-only verdict
        // would incorrectly accept the run.
        add_shadow_snapshot(&mut collection, 0, 0.0, 1, 1, 1, 1, 1, 1, 1, 1);
        add_shadow_snapshot(&mut collection, 0, 1.0, 2, 2, 2, 0, 0, 0, 0, 2);

        assert!(!collection.gauge_always_equals(
            "starfish_rbc_dag_shadow_comparison_valid",
            0,
            1.0,
        ));
        for bucket in ["mismatch", "direct_only", "shadow_only", "ambiguous"] {
            assert!(!collection.count_bucket_is_always_zero(
                "starfish_rbc_dag_shadow_delivery_comparisons_total",
                0,
                bucket,
            ));
        }

        let summary = collection.benchmark_run_summary();
        assert_eq!(summary.shadow_delivery_mismatches, 3);
        assert_eq!(summary.shadow_delivery_ambiguous, 1);
        assert!(!summary.shadow_comparison_valid);
    }

    #[test]
    fn autonomous_clock_valid_gauge_without_wal_progress_is_invalid() {
        let mut collection = MeasurementsCollection::new(autonomous_shadow_benchmark_parameters(1));
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 8, 0, 1, 1, 0, 3);
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 8, 0, 1, 1, 0, 3);

        let summary = collection.benchmark_run_summary();
        assert_eq!(summary.shadow_autonomous_clock_valid_nodes, 1);
        assert!(!summary.shadow_autonomous_clock_valid);
    }

    #[test]
    fn autonomous_clock_warmup_only_progress_is_invalid() {
        let mut collection = MeasurementsCollection::new(autonomous_shadow_benchmark_parameters(1));
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 2, 0, 1, 1, 0, 3);
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 4, 0, 1, 1, 0, 6);
        for by_scraper in collection.data.values_mut() {
            for measurement in by_scraper.get_mut(&0).into_iter().flatten() {
                measurement.timestamp = Duration::ZERO;
            }
        }
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 4, 0, 1, 1, 0, 6);
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 4, 0, 1, 1, 0, 6);
        for by_scraper in collection.data.values_mut() {
            if let Some(last) = by_scraper.get_mut(&0).and_then(|series| series.last_mut()) {
                last.timestamp = Duration::from_secs(5);
            }
        }

        assert!(
            !collection
                .benchmark_run_summary()
                .shadow_autonomous_clock_valid
        );
    }

    #[test]
    fn autonomous_clock_verdict_requires_in_window_rbc_delivery() {
        let mut collection = MeasurementsCollection::new(autonomous_shadow_benchmark_parameters(1));
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 8, 0, 1, 1, 0, 3);
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 10, 0, 1, 1, 0, 6);
        collection
            .data
            .get_mut("starfish_rbc_dag_shadow_inputs_total")
            .and_then(|by_scraper| by_scraper.get_mut(&0))
            .and_then(|series| series.last_mut())
            .unwrap()
            .count_buckets
            .insert("delivery,shadow".to_owned(), 3);

        assert!(
            !collection
                .benchmark_run_summary()
                .shadow_autonomous_clock_valid
        );
    }

    #[test]
    fn autonomous_clock_verdict_rejects_observed_round_rollback() {
        let mut collection = MeasurementsCollection::new(autonomous_shadow_benchmark_parameters(1));
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 8, 0, 1, 1, 0, 3);
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 1, 0, 1, 1, 0, 4);
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 9, 0, 1, 1, 0, 5);

        assert!(
            !collection
                .benchmark_run_summary()
                .shadow_autonomous_clock_valid
        );
    }

    #[test]
    fn autonomous_clock_verdict_rejects_benchmark_timestamp_reset() {
        let mut collection = MeasurementsCollection::new(autonomous_shadow_benchmark_parameters(1));
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 8, 0, 1, 1, 0, 3);
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 10, 0, 1, 1, 0, 5);
        add_autonomous_clock_snapshot(&mut collection, 0, 1.0, 12, 0, 1, 1, 0, 7);
        for by_scraper in collection.data.values_mut() {
            if let Some(last) = by_scraper.get_mut(&0).and_then(|series| series.last_mut()) {
                last.timestamp = Duration::from_secs(1);
            }
        }

        assert!(
            !collection
                .benchmark_run_summary()
                .shadow_autonomous_clock_valid
        );
    }

    #[test]
    fn missing_final_shadow_scrape_invalidates_a_previously_valid_snapshot() {
        let mut collection = MeasurementsCollection::new(shadow_benchmark_parameters(1));
        add_shadow_snapshot(&mut collection, 0, 1.0, 4, 4, 4, 0, 0, 0, 0, 8);
        assert!(collection.benchmark_run_summary().shadow_comparison_valid);

        collection.mark_shadow_final_scrape_missing(0);

        let validity = collection
            .scraper_series("starfish_rbc_dag_shadow_comparison_valid", 0)
            .unwrap();
        assert_eq!(validity.last().unwrap().scalar_value(), 0.0);
        assert!(!collection.benchmark_run_summary().shadow_comparison_valid);
    }

    #[test]
    fn synthetic_missing_final_marker_is_not_a_metrics_contributor() {
        let mut collection = MeasurementsCollection::new(shadow_benchmark_parameters(1));

        collection.mark_shadow_final_scrape_missing(0);

        assert_eq!(collection.metrics_contributors(), 0);
        let summary = collection.benchmark_run_summary();
        assert_eq!(summary.shadow_comparison_valid_nodes, 0);
        assert!(!summary.shadow_comparison_valid);
    }

    #[test]
    fn shadow_verdict_requires_delivery_and_wal_coverage_from_every_scraper() {
        let mut collection = MeasurementsCollection::new(shadow_benchmark_parameters(2));
        add_shadow_snapshot(&mut collection, 0, 1.0, 4, 4, 4, 0, 0, 0, 0, 8);
        add_shadow_snapshot(&mut collection, 1, 1.0, 0, 0, 0, 0, 0, 0, 0, 0);

        let summary = collection.benchmark_run_summary();
        assert_eq!(summary.shadow_comparison_valid_nodes, 2);
        assert_eq!(summary.shadow_direct_deliveries, 4);
        assert_eq!(summary.shadow_deliveries, 4);
        assert_eq!(summary.shadow_delivery_matches, 4);
        assert_eq!(summary.shadow_wal_durable_records, 8);
        assert!(!summary.shadow_comparison_valid);
    }

    #[test]
    fn shadow_verdict_accepts_a_bounded_live_pipeline_tail() {
        for (direct_deliveries, shadow_deliveries, matches) in [(5, 4, 4), (5, 5, 4)] {
            let mut collection = MeasurementsCollection::new(shadow_benchmark_parameters(1));
            add_shadow_snapshot(
                &mut collection,
                0,
                1.0,
                direct_deliveries,
                shadow_deliveries,
                matches,
                0,
                0,
                0,
                0,
                8,
            );
            add_shadow_backlog_snapshot(
                &mut collection,
                0,
                direct_deliveries - matches,
                shadow_deliveries - matches,
                1,
            );

            let summary = collection.benchmark_run_summary();
            assert_eq!(summary.shadow_direct_deliveries, direct_deliveries);
            assert_eq!(summary.shadow_deliveries, shadow_deliveries);
            assert_eq!(summary.shadow_delivery_matches, matches);
            assert!(summary.shadow_comparison_valid);
        }
    }

    #[test]
    fn shadow_verdict_rejects_excessive_or_old_unpaired_work() {
        for (unpaired_direct, unpaired_shadow, max_round_lag) in [(5, 0, 1), (0, 5, 1), (1, 0, 5)] {
            let mut collection = MeasurementsCollection::new(shadow_benchmark_parameters(1));
            add_shadow_snapshot(&mut collection, 0, 1.0, 8, 7, 7, 0, 0, 0, 0, 8);
            add_shadow_backlog_snapshot(
                &mut collection,
                0,
                unpaired_direct,
                unpaired_shadow,
                max_round_lag,
            );

            assert!(!collection.benchmark_run_summary().shadow_comparison_valid);
        }
    }

    #[test]
    fn benchmark_run_summary_includes_cpu_and_percentiles() {
        let report = r#"
# HELP benchmark_duration Duration of the benchmark
# TYPE benchmark_duration counter
benchmark_duration 200
# HELP block_committed_latency block_committed_latency
# TYPE block_committed_latency gauge
block_committed_latency{v="count"} 1000
block_committed_latency{v="p25"} 200000
block_committed_latency{v="p50"} 300000
block_committed_latency{v="p75"} 400000
block_committed_latency{v="sum"} 300000000
# HELP block_committed_latency_squared_micros Squared latency
# TYPE block_committed_latency_squared_micros counter
block_committed_latency_squared_micros 90000000000
# HELP transaction_committed_latency transaction latency
# TYPE transaction_committed_latency gauge
transaction_committed_latency{v="count"} 40000
transaction_committed_latency{v="p25"} 500000
transaction_committed_latency{v="p50"} 750000
transaction_committed_latency{v="p75"} 1000000
transaction_committed_latency{v="sum"} 28000000000
# HELP transaction_committed_latency_squared_micros Squared latency
# TYPE transaction_committed_latency_squared_micros counter
transaction_committed_latency_squared_micros 20000000000000
# HELP bytes_sent_total Total number of bytes sent
# TYPE bytes_sent_total counter
bytes_sent_total 6000000
# HELP bytes_received_total Total number of bytes received
# TYPE bytes_received_total counter
bytes_received_total 14000000
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 320
# HELP block_sync_requests_sent Number of block sync requests sent per authority
# TYPE block_sync_requests_sent counter
block_sync_requests_sent{authority="0"} 40
block_sync_requests_sent{authority="1"} 20
# HELP proposed_header_size_bytes proposed_header_size_bytes
# TYPE proposed_header_size_bytes gauge
proposed_header_size_bytes{v="count"} 10
proposed_header_size_bytes{v="sum"} 6400
# HELP dag_highest_round Highest round in the in-memory DAG
# TYPE dag_highest_round gauge
dag_highest_round 1000
        "#;

        let measurements = Measurement::from_prometheus::<TestProtocolMetrics>(report);

        // The CPU and bandwidth rates are computed as deltas between the
        // first in-window scrape and the latest scrape (introduced by
        // 96b04ca to avoid warmup inflation). A single-scrape test input
        // therefore degenerates to dt=0 and produces 0-valued rates,
        // which would mask any regression in the percentile pipeline.
        // We synthesize an earlier "baseline" scrape at timestamp=100
        // with half the cumulative counter values so the delta over the
        // 100-second active window matches the cumulative-divide-by-
        // duration semantic the assertions were originally written for.
        let mut baseline_cpu = measurements["process_cpu_seconds_total"].clone();
        baseline_cpu.scalar = 160.0;
        baseline_cpu.timestamp = Duration::from_secs(100);
        let mut baseline_sent = measurements["bytes_sent_total"].clone();
        baseline_sent.scalar = 3_000_000.0;
        baseline_sent.count = 3_000_000;
        baseline_sent.timestamp = Duration::from_secs(100);

        let mut aggregator = MeasurementsCollection::new(BenchmarkParameters::new_for_tests());
        for scraper_id in 0..3 {
            // Insert the earlier baselines FIRST so the delta calculation
            // resolves to (last - baseline) / (200 - 100) per scraper.
            aggregator.add(
                scraper_id,
                "process_cpu_seconds_total".to_string(),
                baseline_cpu.clone(),
            );
            aggregator.add(
                scraper_id,
                "bytes_sent_total".to_string(),
                baseline_sent.clone(),
            );
            for (label, measurement) in measurements.clone() {
                aggregator.add(scraper_id, label, measurement);
            }
        }
        aggregator.set_db_sizes(vec![10_000, 20_000, 30_000]);

        let summary = aggregator.benchmark_run_summary();
        assert_eq!(summary.protocol, "starfish");
        assert_eq!(summary.load, 500);
        assert_eq!(summary.ready_nodes_at_boot, 4);
        assert_eq!(summary.metrics_contributors, 3);
        assert_eq!(summary.transaction_latency_ms.p25, 500.0);
        assert_eq!(summary.transaction_latency_ms.p50, 750.0);
        assert_eq!(summary.transaction_latency_ms.p75, 1000.0);
        assert_eq!(summary.block_latency_ms.p25, 200.0);
        assert_eq!(summary.block_latency_ms.p50, 300.0);
        assert_eq!(summary.block_latency_ms.p75, 400.0);
        assert_eq!(summary.cpu_cores.p50, 1.6);
        assert_eq!(summary.tps, 200.0);
        assert_eq!(summary.bps, 5.0);
        assert_eq!(summary.bandwidth_per_round_bytes.p50, 6_000.0);
        assert_eq!(summary.db_size_per_round_bytes.p25, 15.0);
        assert_eq!(summary.db_size_per_round_bytes.p50, 20.0);
        assert_eq!(summary.db_size_per_round_bytes.p75, 25.0);
        assert_eq!(summary.block_sync_requests_sent_per_round_avg, 0.06);
        assert_eq!(summary.block_header_size_avg_bytes, 640.0);
        let expected_efficiency = 30_000.0 / (summary.tps * summary.transaction_size_bytes as f64);
        assert!((summary.bandwidth_efficiency.p50 - expected_efficiency).abs() < 1e-9);
    }

    #[test]
    fn prometheus_parse_includes_memory_gauges() {
        let report = r#"
# HELP benchmark_duration Duration of the benchmark
# TYPE benchmark_duration counter
benchmark_duration 60
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 123456
# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 654321
# HELP global_in_memory_blocks_bytes Total block bytes in memory
# TYPE global_in_memory_blocks_bytes gauge
global_in_memory_blocks_bytes 777
        "#;

        let measurements = Measurement::from_prometheus::<TestProtocolMetrics>(report);
        assert_eq!(
            measurements
                .get("process_resident_memory_bytes")
                .expect("resident memory metric is parsed")
                .scalar,
            123456.0
        );
        assert_eq!(
            measurements
                .get("process_virtual_memory_bytes")
                .expect("virtual memory metric is parsed")
                .scalar,
            654321.0
        );
        assert_eq!(
            measurements
                .get("global_in_memory_blocks_bytes")
                .expect("protocol memory metric is parsed")
                .scalar,
            777.0
        );
    }

    #[test]
    fn benchmark_run_summary_reports_ready_nodes_at_boot() {
        let report = r#"
# HELP benchmark_duration Duration of the benchmark
# TYPE benchmark_duration counter
benchmark_duration 120
# HELP bytes_sent_total Total number of bytes sent
# TYPE bytes_sent_total counter
bytes_sent_total 1000
        "#;

        let measurements = Measurement::from_prometheus::<TestProtocolMetrics>(report);
        let mut aggregator = MeasurementsCollection::new(BenchmarkParameters::new_for_tests());
        aggregator.set_ready_nodes_at_boot(3);
        for scraper_id in 0..2 {
            for (label, measurement) in measurements.clone() {
                aggregator.add(scraper_id, label, measurement);
            }
        }

        let summary = aggregator.benchmark_run_summary();
        assert_eq!(summary.ready_nodes_at_boot, 3);
        assert_eq!(summary.metrics_contributors, 2);
    }

    #[test]
    fn prometheus_parse_with_validator_label() {
        let report = r#"
# HELP benchmark_duration Duration of the benchmark
# TYPE benchmark_duration counter
benchmark_duration{validator="node-44"} 300
# HELP block_committed_latency block_committed_latency
# TYPE block_committed_latency gauge
block_committed_latency{validator="node-44",v="count"} 28547
block_committed_latency{v="p50",validator="node-44"} 487770
block_committed_latency{validator="node-44",v="sum"} 17374616335344112
# HELP block_committed_latency_squared_micros Squared latency
# TYPE block_committed_latency_squared_micros counter
block_committed_latency_squared_micros{validator="node-44"} 13465046685909033000
# HELP committed_leaders_total Total committed leaders
# TYPE committed_leaders_total counter
committed_leaders_total{commit_type="direct-commit",validator="node-44",authority="0"} 1
        "#;

        let measurements = Measurement::from_prometheus::<TestProtocolMetrics>(report);
        let mut aggregator = MeasurementsCollection::new(BenchmarkParameters::new_for_tests());
        let scraper_id = 44;
        for (label, measurement) in measurements {
            aggregator.add(scraper_id, label, measurement);
        }

        let block_committed_latency = aggregator
            .data
            .get("block_committed_latency")
            .expect("The `block_committed_latency` label is defined above")
            .get(&scraper_id)
            .unwrap();
        assert_eq!(block_committed_latency.len(), 1);

        let data = &block_committed_latency[0];
        assert_eq!(data.count, 28547);
        assert_eq!(data.sum, Duration::from_micros(17374616335344112));
        assert_eq!(data.timestamp.as_secs(), 300);
        assert_eq!(
            data.buckets.get("p50"),
            Some(&Duration::from_micros(487770))
        );

        let committed_leaders_total = aggregator
            .data
            .get("committed_leaders_total")
            .expect("The `committed_leaders_total` label is defined above")
            .get(&scraper_id)
            .unwrap();
        assert_eq!(committed_leaders_total.len(), 1);
        assert_eq!(
            committed_leaders_total[0]
                .count_buckets
                .get("0,direct-commit"),
            Some(&1)
        );
    }

    #[test]
    fn prometheus_parse_large() {
        let report = r#"
# HELP benchmark_duration Duration of the benchmark
# TYPE benchmark_duration counter
benchmark_duration 300
# HELP block_committed_latency block_committed_latency
# TYPE block_committed_latency gauge
block_committed_latency{v="count"} 28547
block_committed_latency{v="p50"} 487770
block_committed_latency{v="p90"} 719253
block_committed_latency{v="p99"} 848723
block_committed_latency{v="sum"} 17374616335344112
# HELP block_committed_latency_squared_micros Squared latency
# TYPE block_committed_latency_squared_micros counter
block_committed_latency_squared_micros 13465046685909033000
# HELP block_handler_cleanup_util block_handler_cleanup_util
# TYPE block_handler_cleanup_util counter
block_handler_cleanup_util 0
# HELP dag_state_cleanup_util dag_state_cleanup_util
# TYPE dag_state_cleanup_util counter
dag_state_cleanup_util 451078
# HELP dag_state_entries Number of entries in DAG state
# TYPE dag_state_entries counter
dag_state_entries 33238
# HELP dag_state_loaded_blocks Blocks loaded from wal
# TYPE dag_state_loaded_blocks counter
dag_state_loaded_blocks 0
# HELP dag_state_unloaded_blocks Blocks unloaded during cleanup
# TYPE dag_state_unloaded_blocks counter
dag_state_unloaded_blocks 31228
# HELP committed_leaders_total Total committed leaders
# TYPE committed_leaders_total counter
committed_leaders_total{authority="0",commit_type="direct-commit"} 1
committed_leaders_total{authority="0",commit_type="indirect-skip"} 301
committed_leaders_total{authority="1",commit_type="direct-commit"} 302
committed_leaders_total{authority="2",commit_type="direct-commit"} 301
committed_leaders_total{authority="2",commit_type="indirect-commit"} 1
committed_leaders_total{authority="3",commit_type="direct-commit"} 302
committed_leaders_total{authority="4",commit_type="direct-commit"} 302
committed_leaders_total{authority="5",commit_type="direct-commit"} 301
committed_leaders_total{authority="6",commit_type="direct-commit"} 301
committed_leaders_total{authority="7",commit_type="direct-commit"} 301
committed_leaders_total{authority="8",commit_type="direct-commit"} 301
committed_leaders_total{authority="9",commit_type="direct-commit"} 301
# HELP connection_latency connection_latency
# TYPE connection_latency gauge
connection_latency{peer="B",v="count"} 7
connection_latency{peer="B",v="p50"} 86312
connection_latency{peer="B",v="p90"} 86312
connection_latency{peer="B",v="p99"} 86312
connection_latency{peer="B",v="sum"} 608659
connection_latency{peer="C",v="count"} 7
connection_latency{peer="C",v="p50"} 256175
connection_latency{peer="C",v="p90"} 256175
connection_latency{peer="C",v="p99"} 256175
connection_latency{peer="C",v="sum"} 1647236
connection_latency{peer="D",v="count"} 7
connection_latency{peer="D",v="p50"} 11215
connection_latency{peer="D",v="p90"} 11215
connection_latency{peer="D",v="p99"} 11215
connection_latency{peer="D",v="sum"} 93637
connection_latency{peer="E",v="count"} 7
connection_latency{peer="E",v="p50"} 82607
connection_latency{peer="E",v="p90"} 82607
connection_latency{peer="E",v="p99"} 82607
connection_latency{peer="E",v="sum"} 575597
connection_latency{peer="F",v="count"} 7
connection_latency{peer="F",v="p50"} 73969
connection_latency{peer="F",v="p90"} 73969
connection_latency{peer="F",v="p99"} 73969
connection_latency{peer="F",v="sum"} 509440
connection_latency{peer="G",v="count"} 7
connection_latency{peer="G",v="p50"} 82956
connection_latency{peer="G",v="p90"} 82956
connection_latency{peer="G",v="p99"} 82956
connection_latency{peer="G",v="sum"} 575995
connection_latency{peer="H",v="count"} 7
connection_latency{peer="H",v="p50"} 142971
connection_latency{peer="H",v="p90"} 142971
connection_latency{peer="H",v="p99"} 142971
connection_latency{peer="H",v="sum"} 775515
connection_latency{peer="I",v="count"} 7
connection_latency{peer="I",v="p50"} 220944
connection_latency{peer="I",v="p90"} 220944
connection_latency{peer="I",v="p99"} 220944
connection_latency{peer="I",v="sum"} 1532119
connection_latency{peer="J",v="count"} 7
connection_latency{peer="J",v="p50"} 244825
connection_latency{peer="J",v="p90"} 244825
connection_latency{peer="J",v="p99"} 244825
connection_latency{peer="J",v="sum"} 1715661
# HELP core_lock_dequeued Number of dequeued core requests
# TYPE core_lock_dequeued counter
core_lock_dequeued 27234
# HELP core_lock_enqueued Number of enqueued core requests
# TYPE core_lock_enqueued counter
core_lock_enqueued 27234
# HELP core_lock_util Utilization of core write lock
# TYPE core_lock_util counter
core_lock_util 15917462
# HELP global_in_memory_blocks Blocks loaded in memory
# TYPE global_in_memory_blocks gauge
global_in_memory_blocks 4194
# HELP global_in_memory_blocks_bytes Total block bytes in memory
# TYPE global_in_memory_blocks_bytes gauge
global_in_memory_blocks_bytes 137022992
# HELP leader_timeout_total Total number of leader timeouts
# TYPE leader_timeout_total counter
leader_timeout_total 2
# HELP proposed_block_size_bytes proposed_block_size_bytes
# TYPE proposed_block_size_bytes gauge
proposed_block_size_bytes{v="count"} 5416
proposed_block_size_bytes{v="p50"} 1220
proposed_block_size_bytes{v="p90"} 1612
proposed_block_size_bytes{v="p99"} 1724
proposed_block_size_bytes{v="sum"} 6906560
# HELP sequenced_transactions_total Total sequenced txs
# TYPE sequenced_transactions_total counter
sequenced_transactions_total 2310200
# HELP submitted_transactions Total submitted transactions
# TYPE submitted_transactions counter
submitted_transactions 100000
# HELP transaction_committed_latency transaction latency
# TYPE transaction_committed_latency gauge
transaction_committed_latency{v="count"} 2065300
transaction_committed_latency{v="p50"} 522793
transaction_committed_latency{v="p90"} 740793
transaction_committed_latency{v="p99"} 857100
transaction_committed_latency{v="sum"} 1147380944831
# HELP transaction_committed_latency_squared_micros Squared latency
# TYPE transaction_committed_latency_squared_micros counter
transaction_committed_latency_squared_micros 745207728837251500
# HELP utilization_timer Utilization timer
# TYPE utilization_timer counter
utilization_timer{proc="BlockManager::add_blocks"} 4799566
utilization_timer{proc="Committer::direct_decide"} 2645510
utilization_timer{proc="Committer::indirect_decide"} 693165
utilization_timer{proc="Core::add_blocks"} 5694911
utilization_timer{proc="Core::run_block_handler"} 198119
utilization_timer{proc="Core::try_new_block"} 1285400
utilization_timer{proc="Core::try_new_commit"} 6288004
utilization_timer{proc="Network: verify blocks"} 41800099
utilization_timer{proc="Syncer::try_new_commit"} 8128094
# HELP wal_mappings Number of mappings retained by the wal
# TYPE wal_mappings gauge
wal_mappings 0
        "#;

        let measurements = Measurement::from_prometheus::<TestProtocolMetrics>(report);
        let mut aggregator = MeasurementsCollection::new(BenchmarkParameters::new_for_tests());
        let scraper_id = 1;
        for (label, measurement) in measurements {
            aggregator.add(scraper_id, label, measurement);
        }

        let block_committed_latency_data_points = aggregator
            .data
            .get("block_committed_latency")
            .expect("Unable to find label")
            .get(&scraper_id)
            .unwrap();

        let data =
            &block_committed_latency_data_points[block_committed_latency_data_points.len() - 1];
        assert_ne!(data, &Measurement::default());

        let committed_leaders_data_points = aggregator
            .data
            .get("committed_leaders_total")
            .expect("Unable to find label")
            .get(&scraper_id)
            .unwrap();

        let data = &committed_leaders_data_points[committed_leaders_data_points.len() - 1];
        assert_eq!(
            data.count_buckets,
            [
                ("9,direct-commit".into(), 301),
                ("0,direct-commit".into(), 1),
                ("1,direct-commit".into(), 302),
                ("5,direct-commit".into(), 301),
                ("3,direct-commit".into(), 302),
                ("4,direct-commit".into(), 302),
                ("2,direct-commit".into(), 301),
                ("2,indirect-commit".into(), 1),
                ("7,direct-commit".into(), 301),
                ("6,direct-commit".into(), 301),
                ("8,direct-commit".into(), 301),
                ("0,indirect-skip".into(), 301),
            ]
            .iter()
            .cloned()
            .collect()
        );
    }
}
