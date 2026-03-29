// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Orchestrator entry point.

use std::{collections::HashSet, fs, path::PathBuf, process::Command, time::Duration};

use benchmark::{BenchmarkParameters, CommitteeScalingPlan, LatencyThroughputSweepPlan};
use clap::Parser;
use client::{Instance, ServerProviderClient, aws::AwsClient, vultr::VultrClient};
use eyre::Context;
use measurements::MeasurementsCollection;
use monitor::MonitoringCollector;
use orchestrator::Orchestrator;
use protocol::ProtocolParameters;
use settings::{CloudProvider, Settings};
use ssh::{CommandContext, SshConnectionManager};
use testbed::Testbed;

use starfish_core::config::DisseminationMode;

mod benchmark;
mod client;
mod display;
mod error;
mod faults;
mod logs;
mod measurements;
mod monitor;
mod orchestrator;
mod protocol;
mod settings;
mod ssh;
mod testbed;

/// NOTE: Link these types to the correct protocol.
type Protocol = protocol::starfish::StarfishProtocol;
type NodeParameters = protocol::starfish::StarfishNodeParameters;
type ClientParameters = protocol::starfish::StarfishParameters;

/// The orchestrator command line options.
#[derive(Parser, Debug)]
#[command(author, version, about = "Testbed orchestrator", long_about = None)]
#[clap(rename_all = "kebab-case")]
pub struct Opts {
    /// The path to the settings file. This file contains basic information to
    /// deploy testbeds and run benchmarks such as the url of the git repo,
    /// the commit to deploy, etc.
    #[clap(
        long,
        value_name = "FILE",
        default_value = "crates/orchestrator/assets/settings.yml",
        global = true
    )]
    settings_path: String,

    /// The type of operation to run.
    #[clap(subcommand)]
    operation: Operation,
}

/// The type of operation to run.
#[derive(Parser, Debug)]
#[clap(rename_all = "kebab-case")]
pub enum Operation {
    /// Read or modify the status of the testbed.
    Testbed {
        /// The action to perform on the testbed.
        #[clap(subcommand)]
        action: TestbedAction,
    },
    /// Build the starfish binary inside Docker for Linux x86_64 deployment.
    /// Run this before `testbed deploy` to avoid paying for idle machines
    /// during compilation.
    Build,
    /// Deploy nodes and run a benchmark on the specified testbed.
    Benchmark {
        /// The committee size to deploy.
        #[clap(long, value_name = "INT", default_value_t = 4, global = true)]
        committee: usize,

        /// The number of byzantine nodes to deploy.
        #[clap(long, value_name = "INT", default_value_t = 0, global = true)]
        byzantine_nodes: usize,

        /// The Byzantine strategy to deploy on byzantine nodes.
        #[clap(long, value_name = "STRING", default_value = "timeout", global = true)]
        byzantine_strategy: String,

        /// Overlay 10s latency on the f farthest peers (circular distance).
        #[clap(long, action, default_value_t = false, global = true)]
        adversarial_latency: bool,

        /// The set of loads to submit to the system (tx/s). Each load triggers
        /// a separate benchmark run. Setting a load to zero will not
        /// deploy any benchmark clients (useful to boot testbeds
        /// designed to run with external clients and load generators).
        #[clap(
            long,
            value_name = "INT",
            default_value = "200",
            num_args = 1..,
            global = true
        )]
        loads: Vec<usize>,

        /// Whether to skip testbed updates before running benchmarks. This is a
        /// dangerous operation as it may lead to running benchmarks on
        /// outdated nodes. It is however useful when debugging in some
        /// specific scenarios.
        #[clap(long, action, default_value_t = false, global = true)]
        skip_testbed_update: bool,

        /// Whether to skip testbed configuration before running benchmarks.
        /// This is a dangerous operation as it may lead to running
        /// benchmarks on misconfigured nodes. It is however useful when
        /// debugging in some specific scenarios.
        #[clap(long, action, default_value_t = false, global = true)]
        skip_testbed_configuration: bool,

        /// Protocols to benchmark in order. Available options:
        /// starfish | starfish-speed | starfish-bls | mysticeti |
        /// cordial-miners | bluestreak
        #[clap(
            long,
            value_name = "STRING",
            num_args = 1..,
            required = true
        )]
        protocols: Vec<String>,

        /// Automatically destroy the testbed after a successful benchmark or
        /// benchmark sequence.
        #[clap(long, action, default_value_t = false, global = true)]
        destroy_testbed_after: bool,

        /// Flag indicating whether nodes use log traces or not, this is useful
        /// for debugging
        #[clap(long, action, default_value_t = false, global = true)]
        enable_tracing: bool,

        /// Storage backend for the DAG. Overrides the value from the
        /// parameters file. Available options: rocksdb | tidehunter
        #[clap(long, value_name = "STRING", global = true)]
        storage_backend: Option<String>,

        /// Transaction payload mode. Overrides the value from the
        /// parameters file. Available options: all_zero | random
        #[clap(long, value_name = "STRING", default_value = "random", global = true)]
        transaction_mode: Option<String>,

        /// Dissemination mode override. Overrides the value from the
        /// node parameters file. Available options:
        /// protocol-default | pull | push-causal | push-useful
        #[clap(long, value_name = "STRING", global = true)]
        dissemination_mode: Option<String>,

        /// Enable lz4 network compression. Auto-enabled for random
        /// transaction mode unless explicitly set to false via
        /// --no-compress-network.
        #[clap(long, global = true)]
        compress_network: Option<bool>,

        /// Number of parallel threads for BLS batch verification (default: 5).
        #[clap(long, value_name = "INT", global = true)]
        bls_workers: Option<usize>,
    },
    /// One-click adaptive latency-throughput sweep. This command ensures the
    /// required testbed capacity, then benchmarks each protocol until the
    /// end-to-end p50 latency reaches the target.
    BenchmarkSweep {
        /// The committee size to deploy.
        #[clap(long, value_name = "INT", default_value_t = 4, global = true)]
        committee: usize,

        /// The number of byzantine nodes to deploy.
        #[clap(long, value_name = "INT", default_value_t = 0, global = true)]
        byzantine_nodes: usize,

        /// The Byzantine strategy to deploy on byzantine nodes.
        #[clap(long, value_name = "STRING", default_value = "timeout", global = true)]
        byzantine_strategy: String,

        /// Overlay 10s latency on the f farthest peers (circular distance).
        #[clap(long, action, default_value_t = false, global = true)]
        adversarial_latency: bool,

        /// Whether to skip testbed updates before running benchmarks.
        #[clap(long, action, default_value_t = false, global = true)]
        skip_testbed_update: bool,

        /// Whether to skip testbed configuration before running benchmarks.
        #[clap(long, action, default_value_t = false, global = true)]
        skip_testbed_configuration: bool,

        /// Protocols to benchmark in order.
        #[clap(
            long,
            value_name = "STRING",
            num_args = 1..,
            required = true
        )]
        protocols: Vec<String>,

        /// Initial load for latency-throughput sweep mode.
        #[clap(long, value_name = "INT", default_value_t = 2_000, global = true)]
        sweep_initial_load: usize,

        /// Stop a protocol sweep when end-to-end p50 latency reaches this
        /// target.
        #[clap(long, value_name = "INT", default_value_t = 2_000, global = true)]
        sweep_latency_goal_ms: u64,

        /// Switch from coarse to fine load increases when end-to-end p50
        /// latency reaches this threshold.
        #[clap(long, value_name = "INT", default_value_t = 1_000, global = true)]
        sweep_refine_latency_ms: u64,

        /// Multiplicative load increase while latency is still comfortably
        /// below the refinement threshold.
        #[clap(long, value_name = "FLOAT", default_value_t = 4.0, global = true)]
        sweep_coarse_multiplier: f64,

        /// Multiplicative load increase once latency approaches the target.
        #[clap(long, value_name = "FLOAT", default_value_t = 1.25, global = true)]
        sweep_fine_multiplier: f64,

        /// Safety cap on the number of points collected for each protocol in
        /// sweep mode.
        #[clap(long, value_name = "INT", default_value_t = 12, global = true)]
        sweep_max_points: usize,

        /// Start of the focus zone. When the load would jump past this
        /// value, it is clamped here and subsequent increases use the
        /// additive --sweep-focus-step instead.
        #[clap(long, value_name = "INT", global = true)]
        sweep_focus_start: Option<usize>,

        /// End of the focus zone. Once the load reaches this value, the
        /// normal multiplicative strategy resumes.
        #[clap(long, value_name = "INT", global = true)]
        sweep_focus_end: Option<usize>,

        /// Additive load step inside the focus zone (tx/s).
        #[clap(long, value_name = "INT", global = true)]
        sweep_focus_step: Option<usize>,

        /// Automatically destroy the testbed after a successful sweep.
        #[clap(long, action, default_value_t = false, global = true)]
        destroy_testbed_after: bool,

        /// Flag indicating whether nodes use log traces or not.
        #[clap(long, action, default_value_t = false, global = true)]
        enable_tracing: bool,

        /// Storage backend for the DAG. Overrides the value from the
        /// parameters file. Available options: rocksdb | tidehunter
        #[clap(long, value_name = "STRING", global = true)]
        storage_backend: Option<String>,

        /// Transaction payload mode. Overrides the value from the
        /// parameters file. Available options: all_zero | random
        #[clap(long, value_name = "STRING", default_value = "random", global = true)]
        transaction_mode: Option<String>,

        /// Dissemination mode override. Overrides the value from the
        /// node parameters file. Available options:
        /// protocol-default | pull | push-causal | push-useful
        #[clap(long, value_name = "STRING", global = true)]
        dissemination_mode: Option<String>,

        /// Enable lz4 network compression. Auto-enabled for random
        /// transaction mode unless explicitly set to false via
        /// --no-compress-network.
        #[clap(long, global = true)]
        compress_network: Option<bool>,

        /// Number of parallel threads for BLS batch verification (default: 5).
        #[clap(long, value_name = "INT", global = true)]
        bls_workers: Option<usize>,
    },
    /// Benchmark multiple committee sizes at zero load for a fixed set of
    /// protocols. This mode requires a single-region testbed and always uses
    /// internal IPs with synthetic latency enabled.
    BenchmarkCommitteeSweep {
        /// Committee sizes to benchmark. Values are sorted and deduplicated
        /// before execution.
        #[clap(long, value_name = "INT", num_args = 1.., required = true)]
        committee_sizes: Vec<usize>,

        /// Protocols to benchmark in order.
        #[clap(
            long,
            value_name = "STRING",
            num_args = 1..,
            required = true
        )]
        protocols: Vec<String>,

        /// Keep this many extra validator instances active in reserve so the
        /// sweep can tolerate spot interruptions without reallocating.
        #[clap(long, value_name = "INT", default_value_t = 0, global = true)]
        spare_instances: usize,

        /// The number of byzantine nodes to deploy.
        #[clap(long, value_name = "INT", default_value_t = 0, global = true)]
        byzantine_nodes: usize,

        /// The Byzantine strategy to deploy on byzantine nodes.
        #[clap(long, value_name = "STRING", default_value = "timeout", global = true)]
        byzantine_strategy: String,

        /// Overlay 10s latency on the f farthest peers (circular distance).
        #[clap(long, action, default_value_t = false, global = true)]
        adversarial_latency: bool,

        /// Whether to skip testbed updates before running benchmarks.
        #[clap(long, action, default_value_t = false, global = true)]
        skip_testbed_update: bool,

        /// Whether to skip testbed configuration before running benchmarks.
        #[clap(long, action, default_value_t = false, global = true)]
        skip_testbed_configuration: bool,

        /// Automatically destroy the testbed after a successful sweep.
        #[clap(long, action, default_value_t = false, global = true)]
        destroy_testbed_after: bool,

        /// Flag indicating whether nodes use log traces or not.
        #[clap(long, action, default_value_t = false, global = true)]
        enable_tracing: bool,

        /// Storage backend for the DAG. Overrides the value from the
        /// parameters file. Available options: rocksdb | tidehunter
        #[clap(long, value_name = "STRING", global = true)]
        storage_backend: Option<String>,

        /// Transaction payload mode. Overrides the value from the
        /// parameters file. Available options: all_zero | random
        #[clap(long, value_name = "STRING", default_value = "random", global = true)]
        transaction_mode: Option<String>,

        /// Dissemination mode override. Overrides the value from the
        /// node parameters file. Available options:
        /// protocol-default | pull | push-causal | push-useful
        #[clap(long, value_name = "STRING", global = true)]
        dissemination_mode: Option<String>,

        /// Enable lz4 network compression. Auto-enabled for random
        /// transaction mode unless explicitly set to false via
        /// --no-compress-network.
        #[clap(long, global = true)]
        compress_network: Option<bool>,

        /// Number of parallel threads for BLS batch verification (default: 5).
        #[clap(long, value_name = "INT", global = true)]
        bls_workers: Option<usize>,
    },
    /// Print a summary of the specified measurements collection.
    Summarize {
        /// The path to the settings file.
        #[clap(long, value_name = "FILE")]
        path: PathBuf,
    },
    /// Download monitoring data from the remote testbed, start a local
    /// Prometheus + Grafana stack, and destroy the remote monitoring instance.
    CollectMonitoring,
}

/// The action to perform on the testbed.
#[derive(Parser, Debug)]
#[clap(rename_all = "kebab-case")]
pub enum TestbedAction {
    /// Display the testbed status.
    Status,

    /// Deploy the specified number of instances in all regions specified by in
    /// the setting file.
    Deploy {
        /// Number of instances to deploy.
        #[clap(long)]
        instances: usize,

        /// The region where to deploy the instances. If this parameter is not
        /// specified, the command deploys the specified number of
        /// instances in all regions listed in the setting file.
        #[clap(long)]
        region: Option<String>,
    },

    /// Start at most the specified number of instances per region on an
    /// existing testbed.
    Start {
        /// Number of instances to deploy.
        #[clap(long, default_value_t = 10)]
        instances: usize,
    },

    /// Stop an existing testbed (without destroying the instances).
    Stop,

    /// Destroy the testbed and terminate all instances.
    Destroy {
        /// Download monitoring data locally before destroying the monitoring
        /// instance. Validators are destroyed in parallel with the download.
        #[clap(long, action, default_value_t = false)]
        collect_monitoring: bool,
    },
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    let opts: Opts = Opts::parse();

    // Load the settings files.
    let settings = Settings::load(&opts.settings_path).wrap_err("Failed to load settings")?;

    match &settings.cloud_provider {
        CloudProvider::Aws => {
            // Create the client for the cloud provider.
            let client = AwsClient::new(settings.clone()).await;

            // Execute the command.
            run(settings, client, opts).await
        }
        CloudProvider::Vultr => {
            // Create the client for the cloud provider.
            let token = settings
                .load_token()
                .wrap_err("Failed to load cloud provider's token")?;
            let client = VultrClient::new(token, settings.clone());

            // Execute the command.
            run(settings, client, opts).await
        }
    }
}

const DOCKER_BINARY_OUTPUT: &str = "./target/starfish-linux-amd64";

/// Build the starfish binary inside Docker and extract the resulting Linux
/// x86_64 binary.
fn docker_build_and_extract() -> eyre::Result<PathBuf> {
    display::action("Building starfish binary via Docker");

    // Build the Docker image.
    let status = Command::new("docker")
        .args(["build", "-t", "starfish-build", "."])
        .status()
        .wrap_err("Failed to invoke docker build")?;
    eyre::ensure!(
        status.success(),
        "Docker build failed (exit code: {status})"
    );

    // Extract the binary from the image.
    let _ = Command::new("docker")
        .args(["rm", "-f", "starfish-extract"])
        .status();
    let status = Command::new("docker")
        .args(["create", "--name", "starfish-extract", "starfish-build"])
        .status()
        .wrap_err("Failed to create container for extraction")?;
    eyre::ensure!(
        status.success(),
        "docker create failed (exit code: {status})"
    );

    let status = Command::new("docker")
        .args([
            "cp",
            "starfish-extract:/usr/local/bin/starfish",
            DOCKER_BINARY_OUTPUT,
        ])
        .status()
        .wrap_err("Failed to copy binary from container")?;

    // Cleanup container regardless of cp result.
    let _ = Command::new("docker")
        .args(["rm", "starfish-extract"])
        .status();

    eyre::ensure!(status.success(), "docker cp failed (exit code: {status})");

    display::done();
    Ok(PathBuf::from(DOCKER_BINARY_OUTPUT))
}

fn maybe_auto_detect_prebuilt_binary(settings: &mut Settings) {
    if settings.pre_built_binary.is_none() && std::path::Path::new(DOCKER_BINARY_OUTPUT).exists() {
        display::config("Auto-detected pre-built binary", DOCKER_BINARY_OUTPUT);
        settings.pre_built_binary = Some(DOCKER_BINARY_OUTPUT.into());
    }
}

fn required_benchmark_instances(settings: &Settings, committee: usize) -> usize {
    let cloud_monitoring = usize::from(settings.monitoring && !settings.is_external_monitoring());
    committee + cloud_monitoring
}

fn required_benchmark_instances_with_spares(
    settings: &Settings,
    committee: usize,
    spare_instances: usize,
) -> usize {
    required_benchmark_instances(settings, committee).saturating_add(spare_instances)
}

fn join_usize_list(values: &[usize]) -> String {
    values
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn load_benchmark_configs(
    settings: &Settings,
    mimic_extra_latency: bool,
    adversarial_latency: bool,
    storage_backend: &Option<String>,
    transaction_mode: &Option<String>,
    dissemination_mode: &Option<String>,
    compress_network: Option<bool>,
    bls_workers: Option<usize>,
) -> eyre::Result<(NodeParameters, ClientParameters)> {
    let mut node_parameters = match &settings.node_parameters_path {
        Some(path) => NodeParameters::load(path).wrap_err("Failed to load node's parameters")?,
        None => NodeParameters::default_with_latency(mimic_extra_latency),
    };
    node_parameters.adversarial_latency = adversarial_latency;
    if let Some(workers) = bls_workers {
        node_parameters.bls_verification_workers = workers;
    }
    if let Some(ref mode) = dissemination_mode {
        node_parameters.dissemination_mode = parse_dissemination_mode(mode)?;
    }
    let mut client_parameters = match &settings.parameters_path {
        Some(path) => ClientParameters::load(path).wrap_err("Failed to load parameters")?,
        None => ClientParameters::default(),
    };
    if let Some(ref backend) = storage_backend {
        client_parameters.storage_backend = match backend.as_str() {
            "rocksdb" => starfish_core::config::StorageBackend::Rocksdb,
            "tidehunter" => starfish_core::config::StorageBackend::Tidehunter,
            other => {
                eyre::bail!("Unknown storage backend '{other}'. Use 'rocksdb' or 'tidehunter'.")
            }
        };
    }
    if let Some(ref mode) = transaction_mode {
        client_parameters.transaction_mode = match mode.as_str() {
            "all_zero" => starfish_core::config::TransactionMode::AllZero,
            "random" => starfish_core::config::TransactionMode::Random,
            other => eyre::bail!("Unknown transaction mode '{other}'. Use 'all_zero' or 'random'."),
        };
    }

    // Auto-enable compression for random transactions unless explicitly
    // overridden, mirroring the dryrun.sh convention.
    node_parameters.compress_network = compress_network.unwrap_or(
        client_parameters.transaction_mode == starfish_core::config::TransactionMode::Random,
    );

    Ok((node_parameters, client_parameters))
}

fn parse_dissemination_mode(mode: &str) -> eyre::Result<DisseminationMode> {
    match mode {
        "protocol-default" => Ok(DisseminationMode::ProtocolDefault),
        "pull" => Ok(DisseminationMode::Pull),
        "push-causal" => Ok(DisseminationMode::PushCausal),
        "push-useful" => Ok(DisseminationMode::PushUseful),
        other => eyre::bail!(
            "Unknown dissemination mode '{other}'. \
             Use 'protocol-default', 'pull', 'push-causal', or 'push-useful'."
        ),
    }
}

fn protocol_uses_bls(protocol: &str) -> bool {
    matches!(
        protocol,
        "starfish-bls" | "starfish-l" | "mysticeti-bls" | "mysticeti-l"
    )
}

#[derive(Default)]
struct ResolvedBlsWorkers {
    override_workers: Option<usize>,
    source: Option<String>,
}

fn auto_bls_workers_for_vcpus(vcpus: usize) -> usize {
    vcpus.saturating_sub(5).clamp(5, 50)
}

async fn resolve_bls_workers<C: ServerProviderClient>(
    testbed: &Testbed<C>,
    uses_bls: bool,
    requested_workers: Option<usize>,
) -> eyre::Result<ResolvedBlsWorkers> {
    if let Some(workers) = requested_workers {
        return Ok(ResolvedBlsWorkers {
            override_workers: Some(workers),
            source: uses_bls.then_some("manual".into()),
        });
    }

    if !uses_bls {
        return Ok(ResolvedBlsWorkers::default());
    }

    let Some(vcpus) = testbed
        .instance_vcpus()
        .await
        .wrap_err("Failed to determine instance vCPU count for automatic BLS worker sizing")?
    else {
        return Ok(ResolvedBlsWorkers::default());
    };

    Ok(ResolvedBlsWorkers {
        override_workers: Some(auto_bls_workers_for_vcpus(vcpus)),
        source: Some(format!("auto from {vcpus} vCPU")),
    })
}

fn format_bls_workers(workers: usize, source: Option<&str>) -> String {
    match source {
        Some(source) => format!("{workers} ({source})"),
        None => workers.to_string(),
    }
}

/// Returns `true` when the settings file lists at most one region,
/// indicating a single-VPC deployment where internal IPs and synthetic
/// latency should be used.
fn single_region(settings: &Settings) -> bool {
    settings.regions.len() <= 1
}

async fn maybe_destroy_after_result<C: ServerProviderClient>(
    testbed: &mut Testbed<C>,
    destroy_testbed_after: bool,
    result: eyre::Result<()>,
    operation_name: &str,
) -> eyre::Result<()> {
    if !destroy_testbed_after {
        return result;
    }

    match result {
        Ok(()) => testbed
            .destroy()
            .await
            .wrap_err_with(|| format!("Failed to destroy testbed after {operation_name}")),
        Err(err) => match testbed.destroy().await {
            Ok(()) => Err(err)
                .wrap_err_with(|| format!("{operation_name} failed; the testbed was destroyed")),
            Err(destroy_err) => Err(err).wrap_err_with(|| {
                format!(
                    "{operation_name} failed, and destroying the testbed also failed: {destroy_err}"
                )
            }),
        },
    }
}

fn select_monitoring_instance(
    instances: &[Instance],
    settings: &Settings,
) -> eyre::Result<Option<Instance>> {
    // Prefer external monitoring server if configured.
    if let Some(instance) = settings.external_monitoring_instance()? {
        return Ok(Some(instance));
    }

    let Some(region) = settings.regions.first() else {
        return Ok(None);
    };
    let mut candidates: Vec<_> = instances
        .iter()
        .filter(|instance| instance.is_active() && &instance.region == region)
        .cloned()
        .collect();
    candidates.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(candidates.into_iter().next())
}

async fn run<C: ServerProviderClient>(
    settings: Settings,
    client: C,
    opts: Opts,
) -> eyre::Result<()> {
    // Create a new testbed.
    let mut testbed = Testbed::new(settings.clone(), client)
        .await
        .wrap_err("Failed to crate testbed")?;

    match opts.operation {
        Operation::Testbed { action } => match action {
            // Display the current status of the testbed.
            TestbedAction::Status => testbed.status(),

            // Deploy the specified number of instances on the testbed.
            TestbedAction::Deploy { instances, region } => testbed
                .deploy(instances, region)
                .await
                .wrap_err("Failed to deploy testbed")?,

            // Start the specified number of instances on an existing testbed.
            TestbedAction::Start { instances } => testbed
                .start(instances)
                .await
                .wrap_err("Failed to start testbed")?,

            // Stop an existing testbed.
            TestbedAction::Stop => testbed.stop().await.wrap_err("Failed to stop testbed")?,

            // Destroy the testbed and terminate all instances.
            TestbedAction::Destroy { collect_monitoring } => {
                if let Some(age) = testbed.testbed_age() {
                    display::config("Testbed age", display::format_duration(age));
                }
                if collect_monitoring && settings.monitoring_enabled() {
                    // Stop conflicting local stacks first.
                    display::action("Stopping conflicting local monitoring stacks");
                    MonitoringCollector::stop_conflicting_stacks();
                    display::done();

                    // Separate monitoring instance from the rest.
                    let instances = testbed.instances();
                    let monitoring_instance = select_monitoring_instance(&instances, &settings)?;

                    if let Some(monitoring_instance) = monitoring_instance {
                        let username = testbed.username();
                        let private_key_file = settings.ssh_private_key_file.clone();
                        let ssh_manager =
                            SshConnectionManager::new(username.into(), private_key_file)
                                .with_timeout(settings.ssh_timeout)
                                .with_retries(settings.ssh_retries);

                        // Kill all remote processes.
                        display::action("Stopping all remote processes");
                        let all_active = instances.iter().filter(|x| x.is_active()).cloned();
                        ssh_manager
                            .execute(
                                all_active,
                                "(tmux kill-server || true)",
                                CommandContext::default(),
                            )
                            .await
                            .wrap_err("Failed to stop remote processes")?;
                        display::done();

                        // Prepare local directory for monitoring data.
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        let local_dir = PathBuf::from(format!("monitoring-data/{timestamp}"));
                        fs::create_dir_all(&local_dir)
                            .wrap_err("Failed to create monitoring data directory")?;

                        // Parallel: destroy non-monitoring instances + download
                        // monitoring data.
                        let non_monitoring: Vec<_> = instances
                            .into_iter()
                            .filter(|i| i.id != monitoring_instance.id)
                            .collect();
                        // Use a dedicated SSH manager for the monitoring server
                        // when it specifies a custom user (e.g. root@host).
                        let monitoring_ssh = if let Some(user) = settings.monitoring_ssh_user() {
                            SshConnectionManager::new(
                                user.into(),
                                settings.ssh_private_key_file.clone(),
                            )
                            .with_timeout(settings.ssh_timeout)
                            .with_retries(settings.ssh_retries)
                        } else {
                            ssh_manager
                        };
                        let collector =
                            MonitoringCollector::new(monitoring_ssh, monitoring_instance.clone());

                        display::action("Destroying validators and downloading monitoring data");
                        tokio::try_join!(
                            async {
                                testbed
                                    .destroy_instances(non_monitoring)
                                    .await
                                    .map_err(|e| eyre::eyre!(e))
                            },
                            async {
                                collector
                                    .download_prometheus_data(&local_dir)
                                    .await
                                    .map_err(|e| eyre::eyre!(e))
                            },
                        )?;
                        display::done();

                        // Generate config and start local stack.
                        display::action("Generating local monitoring configuration");
                        MonitoringCollector::generate_local_config(&local_dir)
                            .wrap_err("Failed to generate local monitoring config")?;
                        display::done();

                        display::action("Starting local Prometheus + Grafana");
                        MonitoringCollector::start_local_stack(&local_dir)
                            .wrap_err("Failed to start local monitoring stack")?;
                        display::done();

                        // Destroy the monitoring instance last (skip for
                        // external servers).
                        if !settings.is_external_monitoring() {
                            display::action("Destroying remote monitoring instance");
                            testbed
                                .destroy_instance(monitoring_instance)
                                .await
                                .wrap_err("Failed to destroy monitoring instance")?;
                            display::done();
                        }
                        display::print_timeline();
                    } else {
                        // No monitoring instance found, just destroy everything.
                        testbed
                            .destroy()
                            .await
                            .wrap_err("Failed to destroy testbed")?;
                    }
                } else {
                    testbed
                        .destroy()
                        .await
                        .wrap_err("Failed to destroy testbed")?;
                }
            }
        },

        // Build the starfish binary via Docker (run before deploying machines).
        Operation::Build => {
            docker_build_and_extract().wrap_err("Docker build failed")?;
            let msg = format!(
                "Set pre_built_binary: \"{DOCKER_BINARY_OUTPUT}\" \
                in settings or it will be auto-detected"
            );
            display::config("Binary ready", msg);
            return Ok(());
        }

        // Run benchmarks.
        Operation::Benchmark {
            committee,
            byzantine_nodes,
            byzantine_strategy,
            protocols,
            destroy_testbed_after,
            adversarial_latency,
            loads,
            skip_testbed_update,
            skip_testbed_configuration,
            enable_tracing,
            storage_backend,
            transaction_mode,
            dissemination_mode,
            compress_network,
            bls_workers,
        } => {
            // Auto-detect binary from a previous `build` command.
            let mut settings = settings;
            maybe_auto_detect_prebuilt_binary(&mut settings);

            // Derive network mode from region topology.
            let is_single_region = single_region(&settings);
            let mimic_extra_latency = is_single_region;
            let use_internal_ip_addresses = is_single_region;

            let required_instances = required_benchmark_instances(&settings, committee);
            let uses_bls = protocols.iter().any(|protocol| protocol_uses_bls(protocol));
            let resolved_bls_workers = resolve_bls_workers(&testbed, uses_bls, bls_workers).await?;

            let (node_parameters, client_parameters) = load_benchmark_configs(
                &settings,
                mimic_extra_latency,
                adversarial_latency,
                &storage_backend,
                &transaction_mode,
                &dissemination_mode,
                compress_network,
                resolved_bls_workers.override_workers,
            )?;

            display::newline();
            display::header("Benchmark configuration");
            display::config("Regions", settings.regions.join(", "));
            display::config("Instance specs", &settings.specs);
            let cloud_mon = usize::from(settings.monitoring && !settings.is_external_monitoring());
            display::config(
                "Instances",
                format!("{required_instances} ({committee} nodes + {cloud_mon} monitoring)"),
            );
            display::config(
                "Network mode",
                if is_single_region {
                    "single-region (internal IPs, mimic latency)"
                } else {
                    "multi-region (public IPs, real latency)"
                },
            );
            display::config("Protocols", protocols.join(", "));
            display::config("Load (tx/s)", join_usize_list(&loads));
            display::config(
                "Byzantine nodes",
                format!("{byzantine_nodes} ({byzantine_strategy})"),
            );
            display::config("Dissemination mode", node_parameters.dissemination_mode);
            display::config("Storage backend", &client_parameters.storage_backend);
            display::config("Transaction mode", &client_parameters.transaction_mode);
            display::config("Compress network", node_parameters.compress_network);
            if uses_bls {
                display::config(
                    "BLS workers (BLS protocols only)",
                    format_bls_workers(
                        node_parameters.bls_verification_workers,
                        resolved_bls_workers.source.as_deref(),
                    ),
                );
            }
            display::config("Adversarial latency", node_parameters.adversarial_latency);
            display::config("Enable tracing", enable_tracing);
            display::newline();

            let set_of_benchmark_parameters = BenchmarkParameters::new_from_protocols_and_loads(
                settings.clone(),
                node_parameters,
                client_parameters,
                committee,
                use_internal_ip_addresses,
                protocols,
                loads,
                byzantine_nodes,
                byzantine_strategy,
                enable_tracing,
            );
            let suite_results_dir =
                Orchestrator::<Protocol>::suite_results_dir(&settings, "benchmark");

            let benchmark_result: eyre::Result<()> = async {
                let username = testbed.username();
                let private_key_file = settings.ssh_private_key_file.clone();
                let ssh_manager = SshConnectionManager::new(username.into(), private_key_file)
                    .with_timeout(settings.ssh_timeout)
                    .with_retries(settings.ssh_retries);

                let instances = testbed
                    .select_active_instances(required_instances)
                    .wrap_err("Not enough active instances for benchmark")?;

                let setup_commands = testbed
                    .setup_commands()
                    .await
                    .wrap_err("Failed to load testbed setup commands")?;

                let protocol_commands = Protocol::new(&settings);
                Orchestrator::new(
                    settings,
                    instances,
                    setup_commands,
                    protocol_commands,
                    ssh_manager,
                    suite_results_dir,
                )
                .skip_testbed_update(skip_testbed_update)
                .skip_testbed_configuration(skip_testbed_configuration)
                .run_benchmarks(set_of_benchmark_parameters)
                .await
                .wrap_err("Failed to run benchmarks")
            }
            .await;

            maybe_destroy_after_result(
                &mut testbed,
                destroy_testbed_after,
                benchmark_result,
                "Benchmark",
            )
            .await?;
        }

        Operation::BenchmarkSweep {
            committee,
            byzantine_nodes,
            byzantine_strategy,
            protocols,
            sweep_initial_load,
            sweep_latency_goal_ms,
            sweep_refine_latency_ms,
            sweep_coarse_multiplier,
            sweep_fine_multiplier,
            sweep_max_points,
            sweep_focus_start,
            sweep_focus_end,
            sweep_focus_step,
            destroy_testbed_after,
            adversarial_latency,
            skip_testbed_update,
            skip_testbed_configuration,
            enable_tracing,
            storage_backend,
            transaction_mode,
            dissemination_mode,
            compress_network,
            bls_workers,
        } => {
            let mut settings = settings;
            maybe_auto_detect_prebuilt_binary(&mut settings);

            // Derive network mode from region topology.
            let is_single_region = single_region(&settings);
            let mimic_extra_latency = is_single_region;
            let use_internal_ip_addresses = is_single_region;

            let required_instances = required_benchmark_instances(&settings, committee);
            let uses_bls = protocols.iter().any(|protocol| protocol_uses_bls(protocol));
            let resolved_bls_workers = resolve_bls_workers(&testbed, uses_bls, bls_workers).await?;
            let (node_parameters, client_parameters) = load_benchmark_configs(
                &settings,
                mimic_extra_latency,
                adversarial_latency,
                &storage_backend,
                &transaction_mode,
                &dissemination_mode,
                compress_network,
                resolved_bls_workers.override_workers,
            )?;

            display::newline();
            display::header("Benchmark sweep configuration");
            display::config("Regions", settings.regions.join(", "));
            display::config("Instance specs", &settings.specs);
            let cloud_mon = usize::from(settings.monitoring && !settings.is_external_monitoring());
            display::config(
                "Instances",
                format!("{required_instances} ({committee} nodes + {cloud_mon} monitoring)"),
            );
            display::config(
                "Network mode",
                if is_single_region {
                    "single-region (internal IPs, mimic latency)"
                } else {
                    "multi-region (public IPs, real latency)"
                },
            );
            display::config("Protocols", protocols.join(", "));
            display::config(
                "Sweep",
                format!(
                    "initial {sweep_initial_load} tx/s, goal {sweep_latency_goal_ms} ms, \
                     max {sweep_max_points} points"
                ),
            );
            if let (Some(start), Some(end), Some(step)) =
                (sweep_focus_start, sweep_focus_end, sweep_focus_step)
            {
                display::config(
                    "Focus zone",
                    format!("{start}..{end} tx/s, step {step} tx/s"),
                );
            }
            display::config(
                "Byzantine nodes",
                format!("{byzantine_nodes} ({byzantine_strategy})"),
            );
            display::config("Dissemination mode", node_parameters.dissemination_mode);
            display::config("Storage backend", &client_parameters.storage_backend);
            display::config("Transaction mode", &client_parameters.transaction_mode);
            display::config("Compress network", node_parameters.compress_network);
            if uses_bls {
                display::config(
                    "BLS workers (BLS protocols only)",
                    format_bls_workers(
                        node_parameters.bls_verification_workers,
                        resolved_bls_workers.source.as_deref(),
                    ),
                );
            }
            display::config("Adversarial latency", node_parameters.adversarial_latency);
            display::config("Enable tracing", enable_tracing);
            display::newline();

            let base_parameters = BenchmarkParameters::new(
                settings.clone(),
                node_parameters,
                client_parameters,
                committee,
                use_internal_ip_addresses,
                sweep_initial_load,
                protocols
                    .first()
                    .cloned()
                    .expect("protocol list is non-empty"),
                byzantine_nodes,
                byzantine_strategy,
                enable_tracing,
            );

            eyre::ensure!(
                base_parameters.settings.benchmark_duration > Duration::ZERO,
                "Latency-throughput sweep requires a non-zero benchmark_duration",
            );

            let sweep_plan = LatencyThroughputSweepPlan::new(
                protocols,
                sweep_initial_load,
                Duration::from_millis(sweep_latency_goal_ms),
                Duration::from_millis(sweep_refine_latency_ms),
                sweep_coarse_multiplier,
                sweep_fine_multiplier,
                sweep_max_points,
                sweep_focus_start,
                sweep_focus_end,
                sweep_focus_step,
            )
            .wrap_err("Invalid latency-throughput sweep configuration")?;
            let suite_results_dir =
                Orchestrator::<Protocol>::suite_results_dir(&settings, "benchmark-sweep");

            let sweep_result: eyre::Result<()> = async {
                testbed
                    .ensure_active_instances(required_instances)
                    .await
                    .wrap_err("Failed to ensure benchmark capacity")?;

                let username = testbed.username();
                let private_key_file = settings.ssh_private_key_file.clone();
                let ssh_manager = SshConnectionManager::new(username.into(), private_key_file)
                    .with_timeout(settings.ssh_timeout)
                    .with_retries(settings.ssh_retries);

                let instances = testbed
                    .select_active_instances(required_instances)
                    .wrap_err("Failed to reserve instances for benchmark sweep")?;

                let setup_commands = testbed
                    .setup_commands()
                    .await
                    .wrap_err("Failed to load testbed setup commands")?;

                let protocol_commands = Protocol::new(&settings);
                Orchestrator::new(
                    settings,
                    instances,
                    setup_commands,
                    protocol_commands,
                    ssh_manager,
                    suite_results_dir,
                )
                .skip_testbed_update(skip_testbed_update)
                .skip_testbed_configuration(skip_testbed_configuration)
                .run_latency_throughput_sweep(base_parameters, sweep_plan)
                .await
                .wrap_err("Failed to run latency-throughput sweep")
            }
            .await;

            maybe_destroy_after_result(
                &mut testbed,
                destroy_testbed_after,
                sweep_result,
                "Benchmark sweep",
            )
            .await?;
        }

        Operation::BenchmarkCommitteeSweep {
            committee_sizes,
            protocols,
            spare_instances,
            byzantine_nodes,
            byzantine_strategy,
            adversarial_latency,
            skip_testbed_update,
            skip_testbed_configuration,
            destroy_testbed_after,
            enable_tracing,
            storage_backend,
            transaction_mode,
            dissemination_mode,
            compress_network,
            bls_workers,
        } => {
            let mut settings = settings;
            maybe_auto_detect_prebuilt_binary(&mut settings);

            eyre::ensure!(
                single_region(&settings),
                "Committee scaling sweep requires exactly one region so it can run \
                 with internal IPs and synthetic latency",
            );

            let plan = CommitteeScalingPlan::new(protocols, committee_sizes, spare_instances)
                .wrap_err("Invalid committee scaling configuration")?;
            let mimic_extra_latency = true;
            let use_internal_ip_addresses = true;
            let initial_required_instances = required_benchmark_instances_with_spares(
                &settings,
                plan.committee_sizes[0],
                plan.spare_instances,
            );
            let max_required_instances = required_benchmark_instances_with_spares(
                &settings,
                plan.max_committee_size(),
                plan.spare_instances,
            );
            let uses_bls = plan
                .protocols
                .iter()
                .any(|protocol| protocol_uses_bls(protocol));
            let resolved_bls_workers = resolve_bls_workers(&testbed, uses_bls, bls_workers).await?;
            let (node_parameters, client_parameters) = load_benchmark_configs(
                &settings,
                mimic_extra_latency,
                adversarial_latency,
                &storage_backend,
                &transaction_mode,
                &dissemination_mode,
                compress_network,
                resolved_bls_workers.override_workers,
            )?;

            display::newline();
            display::header("Benchmark committee sweep configuration");
            display::config("Regions", settings.regions.join(", "));
            display::config("Instance specs", &settings.specs);
            let cloud_mon = usize::from(settings.monitoring && !settings.is_external_monitoring());
            display::config(
                "Instances",
                format!(
                    "grow from {initial_required_instances} to {max_required_instances} \
                     (committee + {cloud_mon} monitoring + {} spare)",
                    plan.spare_instances,
                ),
            );
            display::config(
                "Network mode",
                "single-region (internal IPs, mimic latency)",
            );
            display::config("Protocols", plan.protocols.join(", "));
            display::config("Committee sizes", join_usize_list(&plan.committee_sizes));
            display::config("Load (tx/s)", "0");
            display::config(
                "Byzantine nodes",
                format!("{byzantine_nodes} ({byzantine_strategy})"),
            );
            display::config("Dissemination mode", node_parameters.dissemination_mode);
            display::config("Storage backend", &client_parameters.storage_backend);
            display::config("Transaction mode", &client_parameters.transaction_mode);
            display::config("Compress network", node_parameters.compress_network);
            if uses_bls {
                display::config(
                    "BLS workers (BLS protocols only)",
                    format_bls_workers(
                        node_parameters.bls_verification_workers,
                        resolved_bls_workers.source.as_deref(),
                    ),
                );
            }
            display::config("Adversarial latency", node_parameters.adversarial_latency);
            display::config("Enable tracing", enable_tracing);
            display::newline();

            let set_of_benchmark_parameters =
                BenchmarkParameters::new_from_protocols_and_committees(
                    settings.clone(),
                    node_parameters.clone(),
                    client_parameters.clone(),
                    plan.committee_sizes.clone(),
                    use_internal_ip_addresses,
                    plan.protocols.clone(),
                    0,
                    byzantine_nodes,
                    byzantine_strategy.clone(),
                    enable_tracing,
                );
            let suite_results_dir =
                Orchestrator::<Protocol>::suite_results_dir(&settings, "benchmark-committee-sweep");

            let benchmark_result: eyre::Result<()> = async {
                let mut prepared_instance_ids = HashSet::new();

                for committee in &plan.committee_sizes {
                    let required_instances = required_benchmark_instances_with_spares(
                        &settings,
                        *committee,
                        plan.spare_instances,
                    );
                    let committee_parameters: Vec<_> = set_of_benchmark_parameters
                        .iter()
                        .filter(|parameters| parameters.nodes == *committee)
                        .cloned()
                        .collect();

                    display::header(format!("Committee size {committee}"));
                    display::config(
                        "Reserved instances",
                        format!(
                            "{required_instances} \
                             ({} validators + {cloud_mon} monitoring + {} spare)",
                            committee, plan.spare_instances,
                        ),
                    );
                    display::newline();

                    testbed
                        .ensure_active_instances(required_instances)
                        .await
                        .wrap_err("Failed to ensure committee sweep capacity")?;

                    let instances = testbed
                        .select_active_instances(required_instances)
                        .wrap_err("Failed to reserve instances for committee sweep")?;

                    if skip_testbed_update {
                        let bootstrap_instances: Vec<_> = instances
                            .iter()
                            .filter(|instance| !prepared_instance_ids.contains(&instance.id))
                            .cloned()
                            .collect();

                        if !bootstrap_instances.is_empty() {
                            let username = testbed.username();
                            let private_key_file = settings.ssh_private_key_file.clone();
                            let ssh_manager =
                                SshConnectionManager::new(username.into(), private_key_file)
                                    .with_timeout(settings.ssh_timeout)
                                    .with_retries(settings.ssh_retries);
                            let setup_commands = testbed
                                .setup_commands()
                                .await
                                .wrap_err("Failed to load testbed setup commands")?;
                            let protocol_commands = Protocol::new(&settings);
                            let bootstrap_results_dir = suite_results_dir.join("bootstrap");
                            let bootstrap_orchestrator = Orchestrator::new(
                                settings.clone(),
                                bootstrap_instances.clone(),
                                setup_commands,
                                protocol_commands,
                                ssh_manager,
                                bootstrap_results_dir,
                            );

                            bootstrap_orchestrator.install().await.wrap_err(
                                "Failed to install dependencies on newly allocated instances",
                            )?;
                            bootstrap_orchestrator
                                .update()
                                .await
                                .wrap_err("Failed to update newly allocated instances")?;

                            prepared_instance_ids.extend(
                                bootstrap_instances.into_iter().map(|instance| instance.id),
                            );
                        }
                    }

                    let username = testbed.username();
                    let private_key_file = settings.ssh_private_key_file.clone();
                    let ssh_manager = SshConnectionManager::new(username.into(), private_key_file)
                        .with_timeout(settings.ssh_timeout)
                        .with_retries(settings.ssh_retries);

                    let setup_commands = testbed
                        .setup_commands()
                        .await
                        .wrap_err("Failed to load testbed setup commands")?;

                    let protocol_commands = Protocol::new(&settings);
                    Orchestrator::new(
                        settings.clone(),
                        instances,
                        setup_commands,
                        protocol_commands,
                        ssh_manager,
                        suite_results_dir.clone(),
                    )
                    .skip_testbed_update(skip_testbed_update)
                    .skip_testbed_configuration(skip_testbed_configuration)
                    .run_benchmarks(committee_parameters)
                    .await
                    .wrap_err_with(|| {
                        format!("Failed to run committee scaling sweep for committee {committee}")
                    })?;
                }

                Ok(())
            }
            .await;

            maybe_destroy_after_result(
                &mut testbed,
                destroy_testbed_after,
                benchmark_result,
                "Benchmark committee sweep",
            )
            .await?;
        }

        // Print a summary of the specified measurements collection.
        Operation::Summarize { path } => MeasurementsCollection::load(path)?.display_summary(),

        // Collect monitoring data and run it locally.
        Operation::CollectMonitoring => {
            eyre::ensure!(
                settings.monitoring_enabled(),
                "Monitoring is not enabled in settings \
                 (set monitoring: true or monitoring_server: <ip>)"
            );

            // Stop any conflicting local monitoring stacks.
            display::action("Stopping conflicting local monitoring stacks");
            MonitoringCollector::stop_conflicting_stacks();
            display::done();

            // Identify the monitoring instance (first active in regions[0]).
            let instances = testbed.instances();
            let monitoring_region = settings
                .regions
                .first()
                .cloned()
                .unwrap_or_else(|| "<none>".to_string());
            let monitoring_instance = select_monitoring_instance(&instances, &settings)?
                .ok_or_else(|| {
                    eyre::eyre!(
                        "No active instance found in region '{}' for monitoring",
                        monitoring_region
                    )
                })?;

            let username = testbed.username();
            let private_key_file = settings.ssh_private_key_file.clone();
            let ssh_manager = SshConnectionManager::new(username.into(), private_key_file)
                .with_timeout(settings.ssh_timeout)
                .with_retries(settings.ssh_retries);

            // Kill all remote processes (validators, clients, etc.).
            display::action("Stopping all remote processes");
            let all_active = instances.iter().filter(|x| x.is_active()).cloned();
            ssh_manager
                .execute(
                    all_active,
                    "(tmux kill-server || true)",
                    CommandContext::default(),
                )
                .await
                .wrap_err("Failed to stop remote processes")?;
            display::done();

            // Download Prometheus data.
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let local_dir = PathBuf::from(format!("monitoring-data/{timestamp}"));
            fs::create_dir_all(&local_dir)
                .wrap_err("Failed to create monitoring data directory")?;

            // Use a dedicated SSH manager for the monitoring server when it
            // specifies a custom user (e.g. root@host).
            let monitoring_ssh = if let Some(user) = settings.monitoring_ssh_user() {
                SshConnectionManager::new(user.into(), settings.ssh_private_key_file.clone())
                    .with_timeout(settings.ssh_timeout)
                    .with_retries(settings.ssh_retries)
            } else {
                ssh_manager
            };

            display::action("Downloading Prometheus data from monitoring instance");
            let collector = MonitoringCollector::new(monitoring_ssh, monitoring_instance.clone());
            collector
                .download_prometheus_data(&local_dir)
                .await
                .wrap_err("Failed to download Prometheus data")?;
            display::done();

            // Generate local docker-compose configuration.
            display::action("Generating local monitoring configuration");
            MonitoringCollector::generate_local_config(&local_dir)
                .wrap_err("Failed to generate local monitoring config")?;
            display::done();

            // Start the local stack.
            display::action("Starting local Prometheus + Grafana");
            MonitoringCollector::start_local_stack(&local_dir)
                .wrap_err("Failed to start local monitoring stack")?;
            display::done();

            // Destroy the remote monitoring instance (skip for external
            // servers).
            if !settings.is_external_monitoring() {
                display::action("Destroying remote monitoring instance");
                testbed
                    .destroy_instance(monitoring_instance)
                    .await
                    .wrap_err("Failed to destroy monitoring instance")?;
                display::done();
            }

            display::print_timeline();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Operation, Opts, auto_bls_workers_for_vcpus};

    #[test]
    fn benchmark_requires_protocols() {
        assert!(Opts::try_parse_from(["orchestrator", "benchmark"]).is_err());
    }

    #[test]
    fn benchmark_parses_grouped_protocols_and_loads() {
        let opts = Opts::try_parse_from([
            "orchestrator",
            "benchmark",
            "--protocols",
            "starfish",
            "mysticeti",
            "--loads",
            "0",
            "200",
        ])
        .unwrap();

        match opts.operation {
            Operation::Benchmark {
                protocols, loads, ..
            } => {
                assert_eq!(protocols, vec!["starfish", "mysticeti"]);
                assert_eq!(loads, vec![0, 200]);
            }
            other => panic!("unexpected operation: {other:?}"),
        }
    }

    #[test]
    fn committee_sweep_parses_grouped_protocols_and_sizes() {
        let opts = Opts::try_parse_from([
            "orchestrator",
            "benchmark-committee-sweep",
            "--protocols",
            "starfish",
            "mysticeti",
            "--committee-sizes",
            "4",
            "10",
            "16",
            "--spare-instances",
            "3",
        ])
        .unwrap();

        match opts.operation {
            Operation::BenchmarkCommitteeSweep {
                protocols,
                committee_sizes,
                spare_instances,
                ..
            } => {
                assert_eq!(protocols, vec!["starfish", "mysticeti"]);
                assert_eq!(committee_sizes, vec![4, 10, 16]);
                assert_eq!(spare_instances, 3);
            }
            other => panic!("unexpected operation: {other:?}"),
        }
    }

    #[test]
    fn auto_bls_workers_reserves_cores_and_caps_upper_bound() {
        assert_eq!(auto_bls_workers_for_vcpus(4), 5);
        assert_eq!(auto_bls_workers_for_vcpus(10), 5);
        assert_eq!(auto_bls_workers_for_vcpus(16), 11);
        assert_eq!(auto_bls_workers_for_vcpus(80), 50);
    }
}
