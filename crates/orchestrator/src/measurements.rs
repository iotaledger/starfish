// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fmt::Debug,
    fs,
    io::BufRead,
    path::{Path, PathBuf},
    time::Duration,
};

use prettytable::{row, Table};
use prometheus_parse::Scrape;
use serde::{Deserialize, Serialize};

use crate::{benchmark::BenchmarkParameters, display, protocol::ProtocolMetrics};

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
    /// Sum of the latencies of all finalized transactions.
    sum: Duration,
    /// Total number of finalized transactions
    count: usize,
    /// Sum of the squares of the latencies of all finalized transactions
    squared_sum: f64,
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
                .collect::<Vec<_>>()
                .join(",");

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
                x if x == "transaction_committed_latency" => match label.as_str() {
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
                    bucket_id if bucket_id.starts_with("p") => match sample.value {
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
                x if x == "block_committed_latency" => match label.as_str() {
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
                    bucket_id if bucket_id.starts_with("p") => match sample.value {
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

    /// Compute the standard deviation from the sum of squared latencies:
    /// `stdev = sqrt( (squared_sum / count) - avg^2 )`
    pub fn stdev_latency(&self) -> Duration {
        // Compute `squared_sum / count`.
        let first_term = if self.count == 0 {
            return Duration::from_secs(0);
        } else {
            self.squared_sum / self.count as f64
        };

        // Compute `avg^2`.
        let squared_avg = self.average_latency().as_secs_f64().powi(2_i32);

        // Compute `squared_sum / count - avg^2`.
        let variance = if squared_avg > first_term {
            0.0
        } else {
            first_term - squared_avg
        };

        // Compute `sqrt( squared_sum / count - avg^2 )`.
        let stdev = variance.sqrt();
        Duration::from_secs_f64(stdev)
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

    /// Get all measurements associated with the specified label.
    pub fn all_measurements(&self, label: &Label) -> Vec<Vec<Measurement>> {
        self.data
            .get(label)
            .map(|data| data.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Get all labels.
    pub fn labels(&self) -> impl Iterator<Item=&Label> {
        self.data.keys()
    }

    /// Get the maximum result of a function applied to the measurements.
    fn max_result<T: Default + Ord>(
        &self,
        label: &Label,
        function: impl Fn(&Measurement) -> T,
    ) -> T {
        self.all_measurements(label)
            .iter()
            .filter_map(|x| x.last())
            .map(function)
            .max()
            .unwrap_or_default()
    }

    /// Aggregate the benchmark duration of multiple data points by taking the max.
    pub fn benchmark_duration(&self) -> Duration {
        self.labels()
            .map(|label| self.max_result(label, |x| x.timestamp))
            .max()
            .unwrap_or_default()
    }

    /// Aggregate the tps of multiple data points.
    pub fn aggregate_tps(&self, label: &Label) -> u64 {
        self.max_result(label, |x| x.count)
            .checked_div(self.max_result(label, |x| x.timestamp.as_secs_f64() as usize))
            .unwrap_or_default() as u64
    }

    /// Aggregate the average latency of multiple data points by taking the average.
    pub fn aggregate_average_latency(&self, label: &Label) -> Duration {
        let all_measurements = self.all_measurements(label);
        let last_data_points: Vec<_> = all_measurements.iter().filter_map(|x| x.last()).collect();
        last_data_points
            .iter()
            .map(|x| x.average_latency())
            .sum::<Duration>()
            .checked_div(last_data_points.len() as u32)
            .unwrap_or_default()
    }

    /// Aggregate the stdev latency of multiple data points by taking the max.
    pub fn max_stdev_latency(&self, label: &Label) -> Duration {
        self.max_result(label, |x| x.stdev_latency())
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

        table.set_titles(row![bH2->"Benchmark Summary"]);
        table.add_row(row![b->"Benchmark type:", self.parameters.node_parameters]);
        table.add_row(row![bH2->""]);
        table.add_row(row![b->"Nodes:", self.parameters.nodes]);
        table.add_row(
            row![b->"Use internal IPs:", format!("{}", self.parameters.use_internal_ip_address)],
        );
        table.add_row(row![b->"Faults:", self.parameters.settings.faults]);
        table.add_row(row![b->"Load:", format!("{} tx/s", self.parameters.load)]);
        table.add_row(row![b->"Duration:", format!("{} s", duration.as_secs())]);

        let mut labels: Vec<_> = self.labels().collect();
        labels.sort();
        for label in labels {
            let total_tps = self.aggregate_tps(label);
            let average_latency = self.aggregate_average_latency(label);
            let stdev_latency = self.max_stdev_latency(label);

            table.add_row(row![bH2->""]);
            table.add_row(row![b->"Workload:", label]);
            match label.as_str() {
                "block_committed_latency" => {
                    table.add_row(row![b->"BPS:", format!("{total_tps} blocks/s")]);
                    table.add_row(row![b->"Block latency (avg):", format!("{} ms", average_latency.as_millis())]);
                    table.add_row(row![b->"Block latency (stdev):", format!("{} ms", stdev_latency.as_millis())]);
                }
                "transaction_committed_latency" => {
                    table.add_row(row![b->"TPS:", format!("{total_tps} tx/s")]);
                    table.add_row(row![b->"Transaction latency (avg):", format!("{} ms", average_latency.as_millis())]);
                    table.add_row(row![b->"Transaction latency (stdev):", format!("{} ms", stdev_latency.as_millis())]);
                }
                "sequenced_transactions_total" => {
                    table.add_row(row![b->"TPS:", format!("{total_tps} tx/s")]);
                }
                _ => {
                    table.add_row(row![b->"Unknown metric", ""]);
                }
            }
        }

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
            sum: Duration::from_secs(2),
            count: 100,
            squared_sum: 0.0,
        };

        assert_eq!(data.average_latency(), Duration::from_millis(20));
    }

    #[test]
    fn stdev_latency() {
        let data = Measurement {
            timestamp: Duration::from_secs(10),
            buckets: HashMap::new(),
            sum: Duration::from_secs(50),
            count: 100,
            squared_sum: 75.0,
        };

        // squared_sum / count
        assert_eq!(data.squared_sum / data.count as f64, 0.75);
        // avg^2
        assert_eq!(data.average_latency().as_secs_f64().powf(2.0), 0.25);
        // sqrt( squared_sum / count - avg^2 )
        let stdev = data.stdev_latency();
        assert_eq!((stdev.as_secs_f64() * 10.0).round(), 7.0);
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
            # HELP block_committed_latency_squared_micros Square of total end-to-end latency of a block commitment in seconds
            # TYPE block_committed_latency_squared_micros counter
            block_committed_latency_squared_micros 13465046685909033000
            # HELP sequenced_transactions_total Total number of sequenced transactions
            # TYPE sequenced_transactions_total counter
            sequenced_transactions_total 2310200
            # HELP submitted_transactions Total number of submitted transactions
            # TYPE submitted_transactions counter
            submitted_transactions 100000
            # HELP transaction_committed_latency transaction_committed_latency
            # TYPE transaction_committed_latency gauge
            transaction_committed_latency{v="count"} 2065300
            transaction_committed_latency{v="p50"} 522793
            transaction_committed_latency{v="p90"} 740793
            transaction_committed_latency{v="p99"} 857100
            transaction_committed_latency{v="sum"} 1147380944831
            # HELP transaction_committed_latency_squared_micros Square of total end-to-end latency of a transaction commitment in seconds
            # TYPE transaction_committed_latency_squared_micros counter
            transaction_committed_latency_squared_micros 745207728837251500
        "#;

        let measurements = Measurement::from_prometheus::<TestProtocolMetrics>(report);
        let mut aggregator = MeasurementsCollection::new(BenchmarkParameters::new_for_tests());
        let scraper_id = 1;
        for (label, measurement) in measurements {
            aggregator.add(scraper_id, label, measurement);
        }

        assert_eq!(aggregator.data.keys().filter(|x| !x.is_empty()).count(), 3);

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
            # HELP block_committed_latency_squared_micros Square of total end-to-end latency of a block commitment in seconds
            # TYPE block_committed_latency_squared_micros counter
            block_committed_latency_squared_micros 13465046685909033000
            # HELP block_handler_cleanup_util block_handler_cleanup_util
            # TYPE block_handler_cleanup_util counter
            block_handler_cleanup_util 0
            # HELP block_store_cleanup_util block_store_cleanup_util
            # TYPE block_store_cleanup_util counter
            block_store_cleanup_util 451078
            # HELP block_store_entries Number of entries in block store
            # TYPE block_store_entries counter
            block_store_entries 33238
            # HELP block_store_loaded_blocks Blocks loaded from wal position in the block store
            # TYPE block_store_loaded_blocks counter
            block_store_loaded_blocks 0
            # HELP block_store_unloaded_blocks Blocks unloaded from wal position during cleanup
            # TYPE block_store_unloaded_blocks counter
            block_store_unloaded_blocks 31228
            # HELP committed_leaders_total Total number of (direct or indirect) committed leaders per authority
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
            # HELP global_in_memory_blocks Number of blocks loaded in memory
            # TYPE global_in_memory_blocks gauge
            global_in_memory_blocks 4194
            # HELP global_in_memory_blocks_bytes Total size of blocks loaded in memory
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
            # HELP sequenced_transactions_total Total number of sequenced transactions
            # TYPE sequenced_transactions_total counter
            sequenced_transactions_total 2310200
            # HELP submitted_transactions Total number of submitted transactions
            # TYPE submitted_transactions counter
            submitted_transactions 100000
            # HELP transaction_committed_latency transaction_committed_latency
            # TYPE transaction_committed_latency gauge
            transaction_committed_latency{v="count"} 2065300
            transaction_committed_latency{v="p50"} 522793
            transaction_committed_latency{v="p90"} 740793
            transaction_committed_latency{v="p99"} 857100
            transaction_committed_latency{v="sum"} 1147380944831
            # HELP transaction_committed_latency_squared_micros Square of total end-to-end latency of a transaction commitment in seconds
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
            println!("{:?} - {:?}", label, measurement);
            aggregator.add(scraper_id, label, measurement);
        }

        let shared_workload_data_points = aggregator
            .data
            .get("block_committed_latency")
            .expect("Unable to find label")
            .get(&scraper_id)
            .unwrap();

        let data = &shared_workload_data_points[shared_workload_data_points.len() - 1];
        assert_ne!(data, &Measurement::default());
    }
}
