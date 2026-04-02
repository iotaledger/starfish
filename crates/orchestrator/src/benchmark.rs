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
    #[serde(default)]
    pub ready_nodes_at_boot: usize,
    #[serde(default)]
    pub metrics_contributors: usize,
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
         block_sync_requests_sent_per_round_avg,block_header_size_avg_bytes,\
         ready_nodes_at_boot,metrics_contributors"
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
            self.ready_nodes_at_boot.to_string(),
            self.metrics_contributors.to_string(),
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
    /// When set, the sweep clamps the load to this value instead of jumping
    /// past it, then uses additive `focus_load_step` increments until
    /// `focus_load_end`.
    #[serde(default)]
    pub focus_load_start: Option<usize>,
    #[serde(default)]
    pub focus_load_end: Option<usize>,
    #[serde(default)]
    pub focus_load_step: Option<usize>,
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
        focus_load_start: Option<usize>,
        focus_load_end: Option<usize>,
        focus_load_step: Option<usize>,
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

        let focus_fields = [
            focus_load_start.is_some(),
            focus_load_end.is_some(),
            focus_load_step.is_some(),
        ];
        let focus_set = focus_fields.iter().filter(|v| **v).count();
        ensure!(
            focus_set == 0 || focus_set == 3,
            "Focus zone requires all three of --sweep-focus-start, \
             --sweep-focus-end, and --sweep-focus-step",
        );
        if let (Some(start), Some(end), Some(step)) =
            (focus_load_start, focus_load_end, focus_load_step)
        {
            ensure!(start < end, "Focus start must be less than focus end");
            ensure!(step > 0, "Focus step must be greater than zero");
            ensure!(
                step <= end - start,
                "Focus step must not exceed the focus range",
            );
        }

        Ok(Self {
            protocols,
            initial_load,
            latency_goal_ms: latency_goal.as_millis() as u64,
            refine_latency_ms: refine_latency.as_millis() as u64,
            coarse_load_multiplier,
            fine_load_multiplier,
            max_points_per_protocol,
            focus_load_start,
            focus_load_end,
            focus_load_step,
        })
    }

    pub fn reached_latency_goal(&self, observed_latency_ms: f64) -> bool {
        observed_latency_ms >= self.latency_goal_ms as f64
    }

    pub fn next_load(&self, current_load: usize, observed_latency_ms: f64) -> Option<usize> {
        if self.reached_latency_goal(observed_latency_ms) {
            return None;
        }

        // Inside focus zone: additive steps.
        if let (Some(start), Some(end), Some(step)) = (
            self.focus_load_start,
            self.focus_load_end,
            self.focus_load_step,
        ) {
            if current_load >= start && current_load < end {
                return Some((current_load + step).min(end));
            }
        }

        let multiplier = if observed_latency_ms >= self.refine_latency_ms as f64 {
            self.fine_load_multiplier
        } else {
            self.coarse_load_multiplier
        };
        let next = ((current_load as f64) * multiplier).ceil() as usize;

        // Clamp to focus zone start if the jump would overshoot it.
        if let Some(start) = self.focus_load_start {
            if current_load < start && next > start {
                return Some(start);
            }
        }

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

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct StabilitySample {
    pub minute: usize,
    pub elapsed_secs: u64,
    #[serde(default)]
    pub expected_live_nodes: usize,
    #[serde(default)]
    pub outage_active: bool,
    pub metrics_contributors: usize,
    pub storage_contributors: usize,
    pub tps: f64,
    pub bps: f64,
    pub transaction_latency_p50_ms: f64,
    pub transaction_latency_p75_ms: f64,
    pub block_latency_p50_ms: f64,
    pub block_latency_p75_ms: f64,
    pub cpu_total_cores: f64,
    pub cpu_p50_cores: f64,
    pub cpu_p75_cores: f64,
    pub bandwidth_sent_total_mib_per_s: f64,
    pub bandwidth_received_total_mib_per_s: f64,
    pub bandwidth_total_mib_per_s: f64,
    pub bandwidth_per_node_p50_mib_per_s: f64,
    pub bandwidth_per_node_p75_mib_per_s: f64,
    pub resident_mem_total_bytes: f64,
    pub resident_mem_p50_bytes: f64,
    pub resident_mem_p75_bytes: f64,
    pub virtual_mem_total_bytes: f64,
    pub virtual_mem_p50_bytes: f64,
    pub virtual_mem_p75_bytes: f64,
    pub protocol_mem_total_bytes: f64,
    pub protocol_mem_p50_bytes: f64,
    pub protocol_mem_p75_bytes: f64,
    pub storage_total_bytes: u64,
    pub storage_p50_bytes: f64,
    pub storage_p75_bytes: f64,
}

impl StabilitySample {
    pub fn csv_header() -> &'static str {
        "minute,elapsed_secs,expected_live_nodes,outage_active,\
         metrics_contributors,storage_contributors,\
         tps,bps,\
         transaction_latency_p50_ms,transaction_latency_p75_ms,\
         block_latency_p50_ms,block_latency_p75_ms,\
         cpu_total_cores,cpu_p50_cores,cpu_p75_cores,\
         bandwidth_sent_total_mib_per_s,bandwidth_received_total_mib_per_s,\
         bandwidth_total_mib_per_s,bandwidth_per_node_p50_mib_per_s,\
         bandwidth_per_node_p75_mib_per_s,\
         resident_mem_total_bytes,resident_mem_p50_bytes,resident_mem_p75_bytes,\
         virtual_mem_total_bytes,virtual_mem_p50_bytes,virtual_mem_p75_bytes,\
         protocol_mem_total_bytes,protocol_mem_p50_bytes,protocol_mem_p75_bytes,\
         storage_total_bytes,storage_p50_bytes,storage_p75_bytes"
    }

    pub fn csv_record(&self) -> String {
        [
            self.minute.to_string(),
            self.elapsed_secs.to_string(),
            self.expected_live_nodes.to_string(),
            self.outage_active.to_string(),
            self.metrics_contributors.to_string(),
            self.storage_contributors.to_string(),
            format!("{:.3}", self.tps),
            format!("{:.3}", self.bps),
            format!("{:.3}", self.transaction_latency_p50_ms),
            format!("{:.3}", self.transaction_latency_p75_ms),
            format!("{:.3}", self.block_latency_p50_ms),
            format!("{:.3}", self.block_latency_p75_ms),
            format!("{:.6}", self.cpu_total_cores),
            format!("{:.6}", self.cpu_p50_cores),
            format!("{:.6}", self.cpu_p75_cores),
            format!("{:.6}", self.bandwidth_sent_total_mib_per_s),
            format!("{:.6}", self.bandwidth_received_total_mib_per_s),
            format!("{:.6}", self.bandwidth_total_mib_per_s),
            format!("{:.6}", self.bandwidth_per_node_p50_mib_per_s),
            format!("{:.6}", self.bandwidth_per_node_p75_mib_per_s),
            format!("{:.3}", self.resident_mem_total_bytes),
            format!("{:.3}", self.resident_mem_p50_bytes),
            format!("{:.3}", self.resident_mem_p75_bytes),
            format!("{:.3}", self.virtual_mem_total_bytes),
            format!("{:.3}", self.virtual_mem_p50_bytes),
            format!("{:.3}", self.virtual_mem_p75_bytes),
            format!("{:.3}", self.protocol_mem_total_bytes),
            format!("{:.3}", self.protocol_mem_p50_bytes),
            format!("{:.3}", self.protocol_mem_p75_bytes),
            self.storage_total_bytes.to_string(),
            format!("{:.3}", self.storage_p50_bytes),
            format!("{:.3}", self.storage_p75_bytes),
        ]
        .join(",")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StabilityOutage {
    pub start_secs: u64,
    pub duration_secs: u64,
    pub start_authority: usize,
    pub count: usize,
}

impl StabilityOutage {
    pub fn selection_stride(&self, committee: usize) -> usize {
        if committee == 0 {
            1
        } else {
            (committee / self.count.max(1)).max(1)
        }
    }

    pub fn selected_authorities(&self, committee: usize) -> Vec<usize> {
        if committee == 0 || self.count == 0 {
            return Vec::new();
        }

        let cyclic_order: Vec<_> = (0..committee)
            .map(|offset| (self.start_authority + offset) % committee)
            .collect();
        let stride = self.selection_stride(committee);

        (0..self.count)
            .filter_map(|index| cyclic_order.get(index.saturating_mul(stride)).copied())
            .collect()
    }

    pub fn selected_authorities_label(&self, committee: usize) -> String {
        let selected = self.selected_authorities(committee);
        if selected.is_empty() {
            return "0 validators".to_string();
        }

        let preview = selected
            .iter()
            .take(3)
            .map(|authority| authority.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let ellipsis = if selected.len() > 3 { ",..." } else { "" };
        format!(
            "authorities {preview}{ellipsis} ({} total, stride {})",
            selected.len(),
            self.selection_stride(committee),
        )
    }

    pub fn selection_description(&self, committee: usize) -> String {
        format!(
            "{} for {}s at {}s",
            self.selected_authorities_label(committee),
            self.duration_secs,
            self.start_secs,
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StabilityReport {
    pub generated_at_unix_secs: u64,
    pub protocol: String,
    pub committee: usize,
    pub load: usize,
    pub duration_secs: u64,
    pub sample_interval_secs: u64,
    #[serde(default)]
    pub outage: Option<StabilityOutage>,
    pub points: Vec<StabilitySample>,
}

impl StabilityReport {
    pub fn to_csv(&self) -> String {
        std::iter::once(StabilitySample::csv_header().to_string())
            .chain(self.points.iter().map(StabilitySample::csv_record))
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
        ProtocolParameters, StabilityOutage,
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
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(plan.next_load(2_000, 750.0), Some(8_000));
        assert_eq!(plan.next_load(8_000, 1_250.0), Some(10_000));
        assert_eq!(plan.next_load(10_000, 2_000.0), None);
    }

    #[test]
    fn focus_zone_clamps_and_steps() {
        let plan = LatencyThroughputSweepPlan::new(
            vec!["starfish".into()],
            2_000,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(2),
            4.0,
            1.25,
            20,
            Some(200_000),
            Some(280_000),
            Some(20_000),
        )
        .unwrap();

        // Coarse jump from 50k would be 200k → clamped to focus start.
        assert_eq!(plan.next_load(50_000, 100.0), Some(200_000));

        // Inside focus zone: additive 20k steps.
        assert_eq!(plan.next_load(200_000, 500.0), Some(220_000));
        assert_eq!(plan.next_load(220_000, 600.0), Some(240_000));
        assert_eq!(plan.next_load(240_000, 700.0), Some(260_000));
        assert_eq!(plan.next_load(260_000, 800.0), Some(280_000));

        // At focus_end, normal multiplier resumes (coarse: 280k * 4 = 1_120k).
        assert_eq!(plan.next_load(280_000, 900.0), Some(1_120_000));

        // Latency goal still stops the sweep inside the focus zone.
        assert_eq!(plan.next_load(240_000, 5_000.0), None);
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

    #[test]
    fn stability_outage_selects_distributed_authorities() {
        let outage = StabilityOutage {
            start_secs: 120,
            duration_secs: 60,
            start_authority: 0,
            count: 33,
        };

        assert_eq!(outage.selection_stride(100), 3);
        assert_eq!(
            outage.selected_authorities(100),
            vec![
                0, 3, 6, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 45, 48, 51, 54, 57, 60, 63,
                66, 69, 72, 75, 78, 81, 84, 87, 90, 93, 96
            ]
        );
    }
}
