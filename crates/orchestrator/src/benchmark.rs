// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::{Debug, Display},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use eyre::ensure;
use serde::{Deserialize, Serialize};

use crate::{ClientParameters, NodeParameters, protocol::ProtocolParameters, settings::Settings};

/// Shortcut avoiding to use the generic version of the benchmark parameters.
pub type BenchmarkParameters = BenchmarkParametersGeneric<NodeParameters, ClientParameters>;

static BENCHMARK_RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_benchmark_run_id(consensus_protocol: &str, nodes: usize, load: usize) -> String {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let sequence = BENCHMARK_RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let protocol = consensus_protocol.replace('/', "_");
    format!("{protocol}-committee-{nodes}-load-{load}-{timestamp_ms}-{sequence}")
}

/// The benchmark parameters for a run. These parameters are stored along with
/// the performance data and should be used to reproduce the results.
#[derive(Serialize, Deserialize, Clone)]
pub struct BenchmarkParametersGeneric<N, C> {
    /// The testbed settings.
    pub settings: Settings,
    /// The node's configuration parameters.
    pub node_parameters: N,
    /// The client's configuration parameters.
    pub client_parameters: C,
    /// The committee size.
    pub nodes: usize,
    /// The total load (tx/s) to submit to the system.
    pub load: usize,
    /// Unique identifier for this benchmark run, used to keep sequential runs
    /// and their saved artifacts distinct.
    #[serde(default)]
    pub benchmark_run_id: String,
    /// Flag indicating whether nodes should advertise their
    /// internal or public IP address for inter-node
    /// communication. When running the simulation in multiple
    /// regions, nodes need to use their public IPs to correctly
    /// communicate, however when a simulation is running in a
    /// single VPC, they should use their internal IPs to avoid
    /// paying for data sent between the nodes.
    pub use_internal_ip_address: bool,
    // Consensus protocol to deploy
    // (starfish | starfish-speed | starfish-bls | mysticeti |
    // cordial-miners | bluestreak)
    pub consensus_protocol: String,
    /// number Byzantine nodes
    pub byzantine_nodes: usize,
    /// Byzantine strategy
    pub byzantine_strategy: String,
    /// Enable tracing
    pub enable_tracing: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PercentileSummary {
    pub p25: f64,
    pub p50: f64,
    pub p75: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct BenchmarkRunSummary {
    pub protocol: String,
    pub committee: usize,
    pub load: usize,
    pub transaction_size_bytes: usize,
    pub duration_secs: f64,
    pub tps: f64,
    pub bps: f64,
    pub transaction_latency_ms: PercentileSummary,
    pub block_latency_ms: PercentileSummary,
    pub bandwidth_efficiency: PercentileSummary,
    pub bandwidth_per_round_bytes: PercentileSummary,
    pub cpu_cores: PercentileSummary,
    pub db_size_per_round_bytes: PercentileSummary,
    pub block_sync_requests_sent_per_round_avg: f64,
    pub block_header_size_avg_bytes: f64,
}

impl BenchmarkRunSummary {
    pub fn csv_header() -> &'static str {
        "protocol,committee,load,transaction_size_bytes,duration_secs,\
         tps,bps,\
         transaction_latency_p25_ms,transaction_latency_p50_ms,\
         transaction_latency_p75_ms,\
         block_latency_p25_ms,block_latency_p50_ms,\
         block_latency_p75_ms,\
         bandwidth_efficiency_p25,bandwidth_efficiency_p50,\
         bandwidth_efficiency_p75,\
         bandwidth_per_round_p25_bytes,bandwidth_per_round_p50_bytes,\
         bandwidth_per_round_p75_bytes,\
         cpu_p25_cores,cpu_p50_cores,cpu_p75_cores,\
         db_size_per_round_p25_bytes,db_size_per_round_p50_bytes,\
         db_size_per_round_p75_bytes,\
         block_sync_requests_sent_per_round_avg,block_header_size_avg_bytes"
    }

    pub fn csv_record(&self) -> String {
        [
            self.protocol.clone(),
            self.committee.to_string(),
            self.load.to_string(),
            self.transaction_size_bytes.to_string(),
            format!("{:.3}", self.duration_secs),
            format!("{:.3}", self.tps),
            format!("{:.3}", self.bps),
            format!("{:.3}", self.transaction_latency_ms.p25),
            format!("{:.3}", self.transaction_latency_ms.p50),
            format!("{:.3}", self.transaction_latency_ms.p75),
            format!("{:.3}", self.block_latency_ms.p25),
            format!("{:.3}", self.block_latency_ms.p50),
            format!("{:.3}", self.block_latency_ms.p75),
            format!("{:.6}", self.bandwidth_efficiency.p25),
            format!("{:.6}", self.bandwidth_efficiency.p50),
            format!("{:.6}", self.bandwidth_efficiency.p75),
            format!("{:.3}", self.bandwidth_per_round_bytes.p25),
            format!("{:.3}", self.bandwidth_per_round_bytes.p50),
            format!("{:.3}", self.bandwidth_per_round_bytes.p75),
            format!("{:.6}", self.cpu_cores.p25),
            format!("{:.6}", self.cpu_cores.p50),
            format!("{:.6}", self.cpu_cores.p75),
            format!("{:.3}", self.db_size_per_round_bytes.p25),
            format!("{:.3}", self.db_size_per_round_bytes.p50),
            format!("{:.3}", self.db_size_per_round_bytes.p75),
            format!("{:.3}", self.block_sync_requests_sent_per_round_avg),
            format!("{:.3}", self.block_header_size_avg_bytes),
        ]
        .join(",")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LatencyThroughputSweepPlan {
    pub protocols: Vec<String>,
    pub initial_load: usize,
    pub latency_goal_ms: u64,
    pub refine_latency_ms: u64,
    pub coarse_load_multiplier: f64,
    pub fine_load_multiplier: f64,
    pub max_points_per_protocol: usize,
}

impl LatencyThroughputSweepPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocols: Vec<String>,
        initial_load: usize,
        latency_goal: Duration,
        refine_latency: Duration,
        coarse_load_multiplier: f64,
        fine_load_multiplier: f64,
        max_points_per_protocol: usize,
    ) -> eyre::Result<Self> {
        ensure!(
            !protocols.is_empty(),
            "Latency-throughput sweep requires at least one protocol",
        );
        ensure!(initial_load > 0, "Initial load must be greater than zero");
        ensure!(
            latency_goal > Duration::ZERO,
            "Latency goal must be greater than zero",
        );
        ensure!(
            refine_latency > Duration::ZERO,
            "Refinement latency must be greater than zero",
        );
        ensure!(
            refine_latency < latency_goal,
            "Refinement latency must be lower than the latency goal",
        );
        ensure!(
            coarse_load_multiplier > 1.0,
            "Coarse load multiplier must be greater than 1",
        );
        ensure!(
            fine_load_multiplier > 1.0,
            "Fine load multiplier must be greater than 1",
        );
        ensure!(
            max_points_per_protocol > 0,
            "Sweep needs at least one point per protocol",
        );

        Ok(Self {
            protocols,
            initial_load,
            latency_goal_ms: latency_goal.as_millis() as u64,
            refine_latency_ms: refine_latency.as_millis() as u64,
            coarse_load_multiplier,
            fine_load_multiplier,
            max_points_per_protocol,
        })
    }

    pub fn reached_latency_goal(&self, observed_latency_ms: f64) -> bool {
        observed_latency_ms >= self.latency_goal_ms as f64
    }

    pub fn next_load(&self, current_load: usize, observed_latency_ms: f64) -> Option<usize> {
        if self.reached_latency_goal(observed_latency_ms) {
            return None;
        }

        let multiplier = if observed_latency_ms >= self.refine_latency_ms as f64 {
            self.fine_load_multiplier
        } else {
            self.coarse_load_multiplier
        };
        let next = ((current_load as f64) * multiplier).ceil() as usize;
        Some(next.max(current_load.saturating_add(1)))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CommitteeScalingPlan {
    pub protocols: Vec<String>,
    pub committee_sizes: Vec<usize>,
    pub spare_instances: usize,
}

impl CommitteeScalingPlan {
    pub fn new(
        protocols: Vec<String>,
        mut committee_sizes: Vec<usize>,
        spare_instances: usize,
    ) -> eyre::Result<Self> {
        ensure!(
            !protocols.is_empty(),
            "Committee scaling sweep requires at least one protocol",
        );
        ensure!(
            !committee_sizes.is_empty(),
            "Committee scaling sweep requires at least one committee size",
        );
        ensure!(
            committee_sizes.iter().all(|size| *size > 0),
            "Committee sizes must be greater than zero",
        );

        committee_sizes.sort_unstable();
        committee_sizes.dedup();

        Ok(Self {
            protocols,
            committee_sizes,
            spare_instances,
        })
    }

    pub fn max_committee_size(&self) -> usize {
        self.committee_sizes
            .last()
            .copied()
            .expect("committee scaling plan is non-empty")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LatencyThroughputSweepReport {
    pub generated_at_unix_secs: u64,
    pub plan: LatencyThroughputSweepPlan,
    pub points: Vec<BenchmarkRunSummary>,
}

impl LatencyThroughputSweepReport {
    pub fn to_csv(&self) -> String {
        std::iter::once(BenchmarkRunSummary::csv_header().to_string())
            .chain(self.points.iter().map(BenchmarkRunSummary::csv_record))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl<N: Debug, C: Debug> Debug for BenchmarkParametersGeneric<N, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}-{:?}-{:?}-{}-{}-{}-{}-{}-{}-{}",
            self.node_parameters,
            self.client_parameters,
            self.settings.faults,
            self.nodes,
            self.consensus_protocol,
            self.byzantine_nodes,
            self.byzantine_strategy,
            self.load,
            self.use_internal_ip_address,
            self.enable_tracing,
        )
    }
}

impl<N, C> Display for BenchmarkParametersGeneric<N, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Consensus choice: {}. Settings:{} nodes, \
            {} Byzantine, {} strategy ({}) - {} tx/s \
            (use internal IPs: {}); enable tracing: {}",
            self.consensus_protocol,
            self.nodes,
            self.byzantine_nodes,
            self.byzantine_strategy,
            self.settings.faults,
            self.load,
            self.use_internal_ip_address,
            self.enable_tracing,
        )
    }
}

impl<N: ProtocolParameters, C: ProtocolParameters> BenchmarkParametersGeneric<N, C> {
    /// Make a new benchmark parameter set for a single run.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        settings: Settings,
        node_parameters: N,
        client_parameters: C,
        nodes: usize,
        use_internal_ip_address: bool,
        load: usize,
        consensus_protocol: String,
        byzantine_nodes: usize,
        byzantine_strategy: String,
        enable_tracing: bool,
    ) -> Self {
        let benchmark_run_id = next_benchmark_run_id(&consensus_protocol, nodes, load);
        Self {
            settings,
            node_parameters,
            client_parameters,
            use_internal_ip_address,
            nodes,
            load,
            benchmark_run_id,
            consensus_protocol,
            byzantine_nodes,
            byzantine_strategy,
            enable_tracing,
        }
    }

    /// Make benchmark parameters for multiple protocols and loads.
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_protocols_and_loads(
        settings: Settings,
        node_parameters: N,
        client_parameters: C,
        nodes: usize,
        use_internal_ip_address: bool,
        protocols: Vec<String>,
        loads: Vec<usize>,
        byzantine_nodes: usize,
        byzantine_strategy: String,
        enable_tracing: bool,
    ) -> Vec<Self> {
        protocols
            .into_iter()
            .flat_map(|consensus_protocol| {
                loads.iter().copied().map({
                    let settings = settings.clone();
                    let node_parameters = node_parameters.clone();
                    let client_parameters = client_parameters.clone();
                    let byzantine_strategy = byzantine_strategy.clone();
                    move |load| {
                        Self::new(
                            settings.clone(),
                            node_parameters.clone(),
                            client_parameters.clone(),
                            nodes,
                            use_internal_ip_address,
                            load,
                            consensus_protocol.clone(),
                            byzantine_nodes,
                            byzantine_strategy.clone(),
                            enable_tracing,
                        )
                    }
                })
            })
            .collect()
    }

    /// Make benchmark parameters for multiple protocols and committee sizes at
    /// a fixed load.
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_protocols_and_committees(
        settings: Settings,
        node_parameters: N,
        client_parameters: C,
        committee_sizes: Vec<usize>,
        use_internal_ip_address: bool,
        protocols: Vec<String>,
        load: usize,
        byzantine_nodes: usize,
        byzantine_strategy: String,
        enable_tracing: bool,
    ) -> Vec<Self> {
        protocols
            .into_iter()
            .flat_map(|consensus_protocol| {
                committee_sizes.iter().copied().map({
                    let settings = settings.clone();
                    let node_parameters = node_parameters.clone();
                    let client_parameters = client_parameters.clone();
                    let byzantine_strategy = byzantine_strategy.clone();
                    move |nodes| {
                        Self::new(
                            settings.clone(),
                            node_parameters.clone(),
                            client_parameters.clone(),
                            nodes,
                            use_internal_ip_address,
                            load,
                            consensus_protocol.clone(),
                            byzantine_nodes,
                            byzantine_strategy.clone(),
                            enable_tracing,
                        )
                    }
                })
            })
            .collect()
    }

    pub fn with_load_and_consensus(&self, load: usize, consensus_protocol: String) -> Self {
        Self::new(
            self.settings.clone(),
            self.node_parameters.clone(),
            self.client_parameters.clone(),
            self.nodes,
            self.use_internal_ip_address,
            load,
            consensus_protocol,
            self.byzantine_nodes,
            self.byzantine_strategy.clone(),
            self.enable_tracing,
        )
    }

    #[cfg(test)]
    pub fn new_for_tests() -> Self {
        Self::new(
            Settings::new_for_test(),
            N::default(),
            C::default(),
            4,
            false,
            500,
            "starfish".to_string(),
            0,
            "honest".to_string(),
            true,
        )
    }
}

#[cfg(test)]
pub mod test {
    use std::{fmt::Display, str::FromStr};

    use serde::{Deserialize, Serialize};

    use crate::settings::Settings;

    use super::{
        BenchmarkParametersGeneric, CommitteeScalingPlan, LatencyThroughputSweepPlan,
        ProtocolParameters,
    };

    /// Mock benchmark type for unit tests.
    #[allow(dead_code)]
    #[derive(
        Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash, Default,
    )]
    pub struct TestNodeConfig;

    impl Display for TestNodeConfig {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestNodeConfig")
        }
    }

    impl FromStr for TestNodeConfig {
        type Err = ();

        fn from_str(_s: &str) -> Result<Self, Self::Err> {
            Ok(Self {})
        }
    }

    impl ProtocolParameters for TestNodeConfig {}

    type TestBenchmarkParameters = BenchmarkParametersGeneric<TestNodeConfig, TestNodeConfig>;

    #[test]
    fn latency_throughput_sweep_switches_to_fine_grained_steps() {
        let plan = LatencyThroughputSweepPlan::new(
            vec!["mysticeti".into()],
            2_000,
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(1),
            4.0,
            1.25,
            10,
        )
        .unwrap();

        assert_eq!(plan.next_load(2_000, 750.0), Some(8_000));
        assert_eq!(plan.next_load(8_000, 1_250.0), Some(10_000));
        assert_eq!(plan.next_load(10_000, 2_000.0), None);
    }

    #[test]
    fn committee_scaling_plan_sorts_and_deduplicates_committee_sizes() {
        let plan = CommitteeScalingPlan::new(
            vec!["starfish".into(), "mysticeti".into()],
            vec![16, 4, 10, 4],
            2,
        )
        .unwrap();

        assert_eq!(plan.committee_sizes, vec![4, 10, 16]);
        assert_eq!(plan.max_committee_size(), 16);
        assert_eq!(plan.spare_instances, 2);
    }

    #[test]
    fn protocol_committee_generation_preserves_protocol_order() {
        let parameters = TestBenchmarkParameters::new_from_protocols_and_committees(
            Settings::new_for_test(),
            TestNodeConfig,
            TestNodeConfig,
            vec![4, 10],
            true,
            vec!["starfish".into(), "mysticeti".into()],
            0,
            0,
            "timeout".into(),
            false,
        );

        let generated: Vec<_> = parameters
            .into_iter()
            .map(|parameter| {
                (
                    parameter.consensus_protocol,
                    parameter.nodes,
                    parameter.load,
                )
            })
            .collect();

        assert_eq!(
            generated,
            vec![
                ("starfish".into(), 4, 0),
                ("starfish".into(), 10, 0),
                ("mysticeti".into(), 4, 0),
                ("mysticeti".into(), 10, 0),
            ]
        );
    }
}
