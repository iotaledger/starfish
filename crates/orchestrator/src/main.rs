// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Orchestrator entry point.

use benchmark::BenchmarkParameters;
use clap::Parser;
use client::{Instance, ServerProviderClient, aws::AwsClient, vultr::VultrClient};
use eyre::Context;
use measurements::MeasurementsCollection;
use monitor::MonitoringCollector;
use orchestrator::Orchestrator;
use protocol::ProtocolParameters;
use settings::{CloudProvider, Settings};
use ssh::{CommandContext, SshConnectionManager};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use testbed::Testbed;

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
type ClientParameters = protocol::starfish::StarfishClientParameters;

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

        /// The Byzantine strategy to deploy on byzantine nodes.
        #[clap(long, action, default_value_t = false, global = true)]
        mimic_extra_latency: bool,

        /// The set of loads to submit to the system (tx/s). Each load triggers
        /// a separate benchmark run. Setting a load to zero will not
        /// deploy any benchmark clients (useful to boot testbeds
        /// designed to run with external clients and load generators).
        #[clap(long, value_name = "[INT]", default_value = "200", global = true)]
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

        /// Consensus to deploy. Available options:
        /// starfish | starfish-s | starfish-pull |
        /// mysticeti | cordial-miners
        #[clap(long, value_name = "STRING", default_value = "starfish", global = true)]
        consensus: String,

        /// Flag indicating whether nodes should advertise
        /// their internal or public IP address for inter-node
        /// communication. When running the simulation in
        /// multiple regions, nodes need to use their public
        /// IPs to correctly communicate, however when a
        /// simulation is running in a single VPC, they should
        /// use their internal IPs to avoid paying for data
        /// sent between the nodes.
        #[clap(long, action, default_value_t = false, global = true)]
        use_internal_ip_addresses: bool,

        /// Flag indicating whether nodes use log traces or not, this is useful
        /// for debugging
        #[clap(long, action, default_value_t = false, global = true)]
        enable_tracing: bool,
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

const DOCKER_BINARY_OUTPUT: &str = "./starfish-linux-amd64";

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

fn select_monitoring_instance(instances: &[Instance], settings: &Settings) -> Option<Instance> {
    let region = settings.regions.first()?;
    let mut candidates: Vec<_> = instances
        .iter()
        .filter(|instance| instance.is_active() && &instance.region == region)
        .cloned()
        .collect();
    candidates.sort_by(|a, b| a.id.cmp(&b.id));
    candidates.into_iter().next()
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
                if collect_monitoring && settings.monitoring {
                    // Stop conflicting local stacks first.
                    display::action("Stopping conflicting local monitoring stacks");
                    MonitoringCollector::stop_conflicting_stacks();
                    display::done();

                    // Separate monitoring instance from the rest.
                    let instances = testbed.instances();
                    let monitoring_instance = select_monitoring_instance(&instances, &settings);

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
                        let collector =
                            MonitoringCollector::new(ssh_manager, monitoring_instance.clone());

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

                        // Destroy the monitoring instance last.
                        display::action("Destroying remote monitoring instance");
                        testbed
                            .destroy_instance(monitoring_instance)
                            .await
                            .wrap_err("Failed to destroy monitoring instance")?;
                        display::done();
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
            consensus: consensus_protocol,
            mimic_extra_latency,
            use_internal_ip_addresses,
            loads,
            skip_testbed_update,
            skip_testbed_configuration,
            enable_tracing,
        } => {
            // Auto-detect binary from a previous `build` command.
            let mut settings = settings;
            if settings.pre_built_binary.is_none()
                && std::path::Path::new(DOCKER_BINARY_OUTPUT).exists()
            {
                display::config("Auto-detected pre-built binary", DOCKER_BINARY_OUTPUT);
                settings.pre_built_binary = Some(DOCKER_BINARY_OUTPUT.into());
            }

            // Create a new orchestrator to instruct the testbed.
            let username = testbed.username();
            let private_key_file = settings.ssh_private_key_file.clone();
            let ssh_manager = SshConnectionManager::new(username.into(), private_key_file)
                .with_timeout(settings.ssh_timeout)
                .with_retries(settings.ssh_retries);

            let instances = testbed.instances();

            let setup_commands = testbed
                .setup_commands()
                .await
                .wrap_err("Failed to load testbed setup commands")?;

            let protocol_commands = Protocol::new(&settings);
            let node_parameters = match &settings.node_parameters_path {
                Some(path) => {
                    NodeParameters::load(path).wrap_err("Failed to load node's parameters")?
                }
                None => NodeParameters::default_with_latency(mimic_extra_latency),
            };
            let client_parameters = match &settings.client_parameters_path {
                Some(path) => {
                    ClientParameters::load(path).wrap_err("Failed to load client's parameters")?
                }
                None => ClientParameters::default(),
            };

            let set_of_benchmark_parameters = BenchmarkParameters::new_from_loads(
                settings.clone(),
                node_parameters,
                client_parameters,
                committee,
                use_internal_ip_addresses,
                loads,
                consensus_protocol,
                byzantine_nodes,
                byzantine_strategy,
                enable_tracing,
            );

            Orchestrator::new(
                settings,
                instances,
                setup_commands,
                protocol_commands,
                ssh_manager,
            )
            .skip_testbed_update(skip_testbed_update)
            .skip_testbed_configuration(skip_testbed_configuration)
            .run_benchmarks(set_of_benchmark_parameters)
            .await
            .wrap_err("Failed to run benchmarks")?;
        }

        // Print a summary of the specified measurements collection.
        Operation::Summarize { path } => MeasurementsCollection::load(path)?.display_summary(),

        // Collect monitoring data and run it locally.
        Operation::CollectMonitoring => {
            eyre::ensure!(
                settings.monitoring,
                "Monitoring is not enabled in settings (set monitoring: true)"
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
            let monitoring_instance = select_monitoring_instance(&instances, &settings)
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

            display::action("Downloading Prometheus data from monitoring instance");
            let collector = MonitoringCollector::new(ssh_manager, monitoring_instance.clone());
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

            // Destroy the remote monitoring instance.
            display::action("Destroying remote monitoring instance");
            testbed
                .destroy_instance(monitoring_instance)
                .await
                .wrap_err("Failed to destroy monitoring instance")?;
            display::done();
        }
    }
    Ok(())
}
