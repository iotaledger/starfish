// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
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

use crate::{
    benchmark::{BenchmarkParameters, BenchmarkRunSummary, PercentileSummary},
    display,
    protocol::ProtocolMetrics,
};

/// The identifier of prometheus latency buckets.
type BucketId = String;
/// The identifier of a measurement type.
type Label = String;

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
                x if x == "process_cpu_seconds_total" => match sample.value {
                    prometheus_parse::Value::Counter(value) => {
                        measurement.scalar = value;
                    }
                    _ => panic!("Unexpected scraped value: '{x}'"),
                },
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
    pub fn average_latency(&self) -> Duration {
        self.sum.checked_div(self.count as u32).unwrap_or_default()
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
}

impl MeasurementsCollection {
    /// Create a new (empty) collection of measurements.
    pub fn new(mut parameters: BenchmarkParameters) -> Self {
        // Remove the access token from the parameters.
        parameters.settings.repository.remove_access_token();

        Self {
            parameters,
            data: HashMap::new(),
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
        self.data
            .entry(label)
            .or_default()
            .entry(scraper_id)
            .or_default()
            .push(measurement);
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

    /// Get the maximum result of a function applied to the measurements.
    fn max_result<T: Default + Ord>(&self, label: &str, function: impl Fn(&Measurement) -> T) -> T {
        self.latest_measurements(label)
            .into_iter()
            .map(function)
            .max()
            .unwrap_or_default()
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

    /// Aggregate the per-scraper bandwidth in bytes per second.
    pub fn aggregate_bandwidth(&self, label: &str) -> Vec<f64> {
        let duration_secs = self.max_result(label, |x| x.timestamp).as_secs_f64();
        if duration_secs == 0.0 {
            return Vec::new();
        }

        self.latest_measurements(label)
            .into_iter()
            .map(|measurement| {
                let total = if measurement.scalar > 0.0 {
                    measurement.scalar
                } else {
                    measurement.count as f64
                };
                total / duration_secs
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

    fn total_bandwidth_samples(&self) -> Vec<f64> {
        let sent = self.aggregate_bandwidth("bytes_sent_total");
        let received = self.aggregate_bandwidth("bytes_received_total");
        if sent.is_empty() {
            return received;
        }
        if received.is_empty() {
            return sent;
        }

        sent.into_iter()
            .zip(received)
            .map(|(sent, received)| sent + received)
            .collect()
    }

    fn cpu_samples(&self) -> Vec<f64> {
        self.latest_measurements("process_cpu_seconds_total")
            .into_iter()
            .filter_map(|measurement| {
                let duration_secs = measurement.timestamp.as_secs_f64();
                (duration_secs > 0.0).then_some(measurement.scalar / duration_secs)
            })
            .collect()
    }

    pub fn benchmark_run_summary(&self) -> BenchmarkRunSummary {
        let duration_secs = self.benchmark_duration().as_secs_f64();
        let tps = self.tps();
        let bps = self.bps();
        let bandwidth_samples = self.total_bandwidth_samples();
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
        let bandwidth_per_round_samples: Vec<_> = bandwidth_samples
            .iter()
            .map(|bytes_per_sec| if bps == 0.0 { 0.0 } else { bytes_per_sec / bps })
            .collect();

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
            },
            block_latency_ms: PercentileSummary {
                p25: self.median_latency_bucket_ms("block_committed_latency", "p25"),
                p50: self.median_latency_bucket_ms("block_committed_latency", "p50"),
                p75: self.median_latency_bucket_ms("block_committed_latency", "p75"),
            },
            bandwidth_efficiency: Self::percentile_summary(&efficiency_samples),
            bandwidth_per_round_bytes: Self::percentile_summary(&bandwidth_per_round_samples),
            cpu_cores: Self::percentile_summary(&self.cpu_samples()),
        }
    }

    /// Save the collection of measurements as a json file.
    pub fn save<P: AsRef<Path>>(&self, path: P) {
        let json = serde_json::to_string_pretty(self).expect("Cannot serialize metrics");
        let mut file = PathBuf::from(path.as_ref());
        file.push(format!("measurements-{:?}.json", self.parameters));
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
        "#;

        let measurements = Measurement::from_prometheus::<TestProtocolMetrics>(report);
        let mut aggregator = MeasurementsCollection::new(BenchmarkParameters::new_for_tests());
        for (label, measurement) in measurements {
            aggregator.add(0, label, measurement);
        }

        let summary = aggregator.benchmark_run_summary();
        assert_eq!(summary.protocol, "starfish");
        assert_eq!(summary.load, 500);
        assert_eq!(summary.transaction_latency_ms.p25, 500.0);
        assert_eq!(summary.transaction_latency_ms.p50, 750.0);
        assert_eq!(summary.transaction_latency_ms.p75, 1000.0);
        assert_eq!(summary.block_latency_ms.p25, 200.0);
        assert_eq!(summary.block_latency_ms.p50, 300.0);
        assert_eq!(summary.block_latency_ms.p75, 400.0);
        assert_eq!(summary.cpu_cores.p50, 1.6);
        assert_eq!(summary.tps, 200.0);
        assert_eq!(summary.bps, 5.0);
        assert_eq!(summary.bandwidth_per_round_bytes.p50, 20_000.0);
        let expected_efficiency = 100_000.0 / (summary.tps * summary.transaction_size_bytes as f64);
        assert!((summary.bandwidth_efficiency.p50 - expected_efficiency).abs() < 1e-9);
    }

    #[test]
    fn prometheus_parse_with_validator_label() {
        let report = r#"
# HELP benchmark_duration Duration of the benchmark
# TYPE benchmark_duration counter
benchmark_duration{validator="validator-44"} 300
# HELP block_committed_latency block_committed_latency
# TYPE block_committed_latency gauge
block_committed_latency{validator="validator-44",v="count"} 28547
block_committed_latency{v="p50",validator="validator-44"} 487770
block_committed_latency{validator="validator-44",v="sum"} 17374616335344112
# HELP block_committed_latency_squared_micros Squared latency
# TYPE block_committed_latency_squared_micros counter
block_committed_latency_squared_micros{validator="validator-44"} 13465046685909033000
# HELP committed_leaders_total Total committed leaders
# TYPE committed_leaders_total counter
committed_leaders_total{commit_type="direct-commit",validator="validator-44",authority="0"} 1
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
utilization_timer{proc="Core::try_new_block::build block"} 674913
utilization_timer{proc="Core::try_new_block::encoding"} 31602
utilization_timer{proc="Core::try_new_block::serialize block"} 11766
utilization_timer{proc="Core::try_new_block::writing to disk"} 188706
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
