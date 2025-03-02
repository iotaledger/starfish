// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use clap::{command, Parser};
use eyre::{eyre, Context, Result};
use prettytable::format;
use starfish_core::metrics::Metrics;
use starfish_core::{
    committee::Committee,
    config::{ClientParameters, ImportExport, NodeParameters, NodePrivateConfig, NodePublicConfig},
    types::AuthorityIndex,
    validator::Validator,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::Arc,
    thread,
};
use tokio::time::Instant;
use tracing_subscriber::{filter::LevelFilter, fmt, EnvFilter};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    operation: Operation,
}

#[derive(Parser)]
enum Operation {
    /// Generate a committee file, parameters files and the private config files of all validators
    /// from a list of initial peers. This is only suitable for benchmarks as it exposes all keys.
    BenchmarkGenesis {
        #[clap(long, value_name = "ADDR", value_delimiter = ' ', num_args(4..))]
        ips: Vec<IpAddr>,
        #[clap(long, value_name = "FILE", default_value = "genesis")]
        working_directory: PathBuf,
        #[clap(long, value_name = "FILE")]
        node_parameters_path: Option<PathBuf>,
    },
    /// Run a validator node.
    Run {
        #[clap(long, value_name = "INT")]
        authority: AuthorityIndex,
        #[clap(long, value_name = "FILE")]
        committee_path: String,
        #[clap(long, value_name = "FILE")]
        public_config_path: String,
        #[clap(long, value_name = "FILE")]
        private_config_path: String,
        #[clap(long, value_name = "FILE")]
        client_parameters_path: String,
        #[clap(long, value_name = "STRING", default_value = "")]
        byzantine_strategy: String,
        #[clap(long, value_name = "STRING", default_value = "starfish")]
        consensus: String,
    },
    /// Deploy a local validator for test. Dryrun mode uses default keys and committee configurations.
    DryRun {
        #[clap(long, value_name = "INT")]
        authority: AuthorityIndex,
        #[clap(long, value_name = "INT")]
        committee_size: usize,
        #[clap(long, value_name = "INT", default_value_t = 10)]
        load: usize,
        #[clap(long, value_name = "STRING", default_value = "")]
        byzantine_strategy: String,
        #[clap(long, default_value_t = false)]
        mimic_extra_latency: bool,
        #[clap(long, value_name = "STRING", default_value = "starfish")]
        consensus: String,
    },
    // Deploy all validators
    LocalBenchmark {
        #[clap(long, value_name = "INT")]
        committee_size: usize,
        #[clap(long, value_name = "INT", default_value_t = 1000)]
        load: usize,
        #[clap(long, value_name = "INT", default_value_t = 0)]
        num_byzantine_nodes: usize,
        #[clap(long, value_name = "STRING", default_value = "")]
        byzantine_strategy: String,
        #[clap(long, default_value_t = true)]
        mimic_extra_latency: bool,
        #[clap(long, value_name = "STRING", default_value = "starfish")]
        consensus: String,
        #[clap(long, value_name = "INT", default_value_t = 600)]
        duration_secs: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Nice colored error messages.
    color_eyre::install()?;
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::ERROR.into())
        .from_env_lossy();
    fmt().with_env_filter(filter).init();

    // Parse the command line arguments.
    match Args::parse().operation {
        Operation::BenchmarkGenesis {
            ips,
            working_directory,
            node_parameters_path,
        } => benchmark_genesis(ips, working_directory, node_parameters_path)?,
        Operation::Run {
            authority,
            committee_path,
            public_config_path,
            private_config_path,
            client_parameters_path,
            byzantine_strategy,
            consensus: consensus_protocol,
        } => {
            run(
                authority,
                committee_path,
                public_config_path,
                private_config_path,
                client_parameters_path,
                byzantine_strategy,
                consensus_protocol,
            )
            .await?
        }
        Operation::DryRun {
            authority,
            committee_size,
            load,
            byzantine_strategy,
            mimic_extra_latency: mimic_latency,
            consensus: consensus_protocol,
        } => {
            dryrun(
                authority,
                committee_size,
                load,
                byzantine_strategy,
                mimic_latency,
                consensus_protocol,
            )
            .await?
        }
        Operation::LocalBenchmark {
            committee_size,
            load,
            num_byzantine_nodes,
            byzantine_strategy,
            mimic_extra_latency,
            consensus: consensus_protocol,
            duration_secs,
        } => {
            local_benchmark(
                committee_size,
                load,
                num_byzantine_nodes,
                byzantine_strategy,
                mimic_extra_latency,
                consensus_protocol,
                duration_secs,
            )
            .await?
        }
    }

    Ok(())
}

fn benchmark_genesis(
    ips: Vec<IpAddr>,
    working_directory: PathBuf,
    node_parameters_path: Option<PathBuf>,
) -> Result<()> {
    tracing::info!("Generating benchmark genesis files");
    fs::create_dir_all(&working_directory).wrap_err(format!(
        "Failed to create directory '{}'",
        working_directory.display()
    ))?;

    // Generate the committee file.
    let committee_size = ips.len();
    let mut committee_path = working_directory.clone();
    committee_path.push(Committee::DEFAULT_FILENAME);
    Committee::new_for_benchmarks(committee_size)
        .print(&committee_path)
        .wrap_err("Failed to print committee file")?;
    tracing::info!("Generated committee file: {}", committee_path.display());

    // Generate the public node config file.
    let node_parameters = match node_parameters_path {
        Some(path) => NodeParameters::load(&path).wrap_err(format!(
            "Failed to load parameters file '{}'",
            path.display()
        ))?,
        None => NodeParameters::default(),
    };

    let node_public_config = NodePublicConfig::new_for_benchmarks(ips, Some(node_parameters));
    let mut node_public_config_path = working_directory.clone();
    node_public_config_path.push(NodePublicConfig::DEFAULT_FILENAME);
    node_public_config
        .print(&node_public_config_path)
        .wrap_err("Failed to print parameters file")?;
    tracing::info!(
        "Generated public node config file: {}",
        node_public_config_path.display()
    );

    // Generate the private node config files.
    let node_private_configs =
        NodePrivateConfig::new_for_benchmarks(&working_directory, committee_size);
    for (i, private_config) in node_private_configs.into_iter().enumerate() {
        fs::create_dir_all(&private_config.storage_path)
            .expect("Failed to create storage directory");
        let path = working_directory.join(NodePrivateConfig::default_filename(i as AuthorityIndex));
        private_config
            .print(&path)
            .wrap_err("Failed to print private config file")?;
        tracing::info!("Generated private config file: {}", path.display());
    }

    Ok(())
}

async fn local_benchmark(
    committee_size: usize,
    mut load: usize,
    num_byzantine_nodes: usize,
    byzantine_strategy: String,
    mimic_latency: bool,
    consensus_protocol: String,
    duration_secs: u64,
) -> Result<()> {
    println!("\n=== Benchmark Configuration ===");
    println!("Committee Size: {}", committee_size);
    println!("Byzantine Nodes: {}", num_byzantine_nodes);
    if num_byzantine_nodes != 0 {
        println!("Byzantine Strategy: {}", byzantine_strategy);
    }
    println!("Transaction Load: {} tx/s", load);
    println!("Consensus Protocol: {}", consensus_protocol);
    println!(
        "Network Latency: {}",
        if mimic_latency { "Enabled" } else { "Disabled" }
    );
    println!("Duration: {} seconds", duration_secs);
    println!("===========================\n");
    let ips = vec![IpAddr::V4(Ipv4Addr::LOCALHOST); committee_size];
    let committee = Committee::new_for_benchmarks(committee_size);
    load /= committee.len();
    let client_parameters = ClientParameters::almost_default(load);
    let node_parameters = NodeParameters::default_with_latency(mimic_latency);
    let public_config = NodePublicConfig::new_for_benchmarks(ips, Some(node_parameters));

    // Create temporary directories for each validator
    let base_dir = PathBuf::from("local-benchmark");
    fs::create_dir_all(&base_dir)?;

    let mut handles = Vec::with_capacity(committee_size);
    let mut abort_handles = Vec::with_capacity(committee_size);
    let mut metrics_of_honest_validators = Vec::new();
    let mut reporters_of_honest_validators = Vec::new();

    // Create a flag to signal when the benchmark is complete
    let running = Arc::new(AtomicBool::new(true));
    // Create a counter for elapsed seconds
    let elapsed_seconds = Arc::new(AtomicU64::new(0));

    // Start the progress display in a separate thread
    run_with_progress(running.clone(), elapsed_seconds.clone());

    // Start all validators
    for authority in 0..committee_size {
        tracing::warn!(
        "Starting validator {authority} in local benchmark mode (committee size: {committee_size})"
    );
        let working_dir = base_dir.join(format!("validator-{}", authority));
        fs::create_dir_all(&working_dir)?;
        match fs::remove_dir_all(&working_dir) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).wrap_err(format!(
                    "Failed to remove directory '{}'",
                    working_dir.display()
                ))
            }
        }
        let mut private_configs =
            NodePrivateConfig::new_for_benchmarks(&working_dir, committee_size);
        let private_config = private_configs.remove(authority);
        match fs::create_dir_all(&private_config.storage_path) {
            Ok(_) => {}
            Err(e) => {
                return Err(e).wrap_err(format!(
                    "Failed to create directory '{}'",
                    working_dir.display()
                ))
            }
        }
        let is_byzantine = authority % 3 == 0 && authority / 3 < num_byzantine_nodes;
        let validator = if is_byzantine {
            Validator::start(
                authority as AuthorityIndex,
                committee.clone(),
                public_config.clone(),
                private_config,
                client_parameters.clone(),
                byzantine_strategy.clone(),
                consensus_protocol.clone(),
            )
            .await?
        } else {
            Validator::start(
                authority as AuthorityIndex,
                committee.clone(),
                public_config.clone(),
                private_config,
                client_parameters.clone(),
                "honest".to_string(),
                consensus_protocol.clone(),
            )
            .await?
        };
        if !is_byzantine {
            metrics_of_honest_validators.push(validator.metrics());
            reporters_of_honest_validators.push(validator.reporter())
        }

        // Use the same pattern as the run method
        let handle = tokio::spawn(async move {
            let (network_result, _metrics_result) = validator.await_completion().await;
            network_result
        });
        abort_handles.push(handle.abort_handle());
        handles.push(handle);
    }

    // Run for specified duration
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(duration_secs)) => {
            // Signal the progress display to stop
            running.store(false, Ordering::SeqCst);
            println!();
            println!("Benchmark completed after {} seconds", duration_secs);
            // Display metrics before exiting
            Metrics::aggregate_and_display(metrics_of_honest_validators,reporters_of_honest_validators, duration_secs);

            // Abort all tasks
            for abort_handle in abort_handles {
                abort_handle.abort();
            }

            // Clean up
            fs::remove_dir_all(base_dir)?;
            Ok(())
        }
        _ = async {
            for handle in handles {
                if let Err(e) = handle.await {
                    tracing::warn!("Validator terminated with error: {}", e);
                }
            }
        } => {
            println!("All validators completed before timeout");
            Metrics::aggregate_and_display(metrics_of_honest_validators, reporters_of_honest_validators, duration_secs);
            fs::remove_dir_all(base_dir)?;
            Ok(())
        }
    }
}

/// Boot a single validator node.
async fn run(
    authority: AuthorityIndex,
    committee_path: String,
    public_config_path: String,
    private_config_path: String,
    client_parameters_path: String,
    byzantine_strategy: String,
    consensus_protocol: String,
) -> Result<()> {
    tracing::info!("Starting validator {authority}");

    let committee = Committee::load(&committee_path)
        .wrap_err(format!("Failed to load committee file '{committee_path}'"))?;
    let public_config = NodePublicConfig::load(&public_config_path).wrap_err(format!(
        "Failed to load parameters file '{public_config_path}'"
    ))?;
    let private_config = NodePrivateConfig::load(&private_config_path).wrap_err(format!(
        "Failed to load private configuration file '{private_config_path}'"
    ))?;
    let client_parameters = ClientParameters::load(&client_parameters_path).wrap_err(format!(
        "Failed to load client parameters file '{client_parameters_path}'"
    ))?;

    let committee = Arc::new(committee);

    let network_address = public_config
        .network_address(authority)
        .ok_or(eyre!("No network address for authority {authority}"))
        .wrap_err("Unknown authority")?;
    let mut binding_network_address = network_address;
    binding_network_address.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    let metrics_address = public_config
        .metrics_address(authority)
        .ok_or(eyre!("No metrics address for authority {authority}"))
        .wrap_err("Unknown authority")?;
    let mut binding_metrics_address = metrics_address;
    binding_metrics_address.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    // Boot the validator node.
    let validator = Validator::start(
        authority,
        committee,
        public_config.clone(),
        private_config,
        client_parameters,
        byzantine_strategy,
        consensus_protocol,
    )
    .await?;
    let (network_result, _metrics_result) = validator.await_completion().await;
    network_result.expect("Validator crashed");
    Ok(())
}

async fn dryrun(
    authority: AuthorityIndex,
    committee_size: usize,
    load: usize,
    byzantine_strategy: String,
    mimic_latency: bool,
    consensus_protocol: String,
) -> Result<()> {
    tracing::warn!(
        "Starting validator {authority} in dryrun mode (committee size: {committee_size})"
    );
    let ips = vec![IpAddr::V4(Ipv4Addr::LOCALHOST); committee_size];
    let committee = Committee::new_for_benchmarks(committee_size);
    let client_parameters = ClientParameters::almost_default(load);
    let node_parameters = NodeParameters::default_with_latency(mimic_latency);
    let public_config = NodePublicConfig::new_for_benchmarks(ips, Some(node_parameters));

    let working_dir = PathBuf::from(format!("dryrun-validator-{authority}"));
    let mut all_private_config =
        NodePrivateConfig::new_for_benchmarks(&working_dir, committee_size);
    let private_config = all_private_config.remove(authority as usize);
    match fs::remove_dir_all(&working_dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).wrap_err(format!(
                "Failed to remove directory '{}'",
                working_dir.display()
            ))
        }
    }
    match fs::create_dir_all(&private_config.storage_path) {
        Ok(_) => {}
        Err(e) => {
            return Err(e).wrap_err(format!(
                "Failed to create directory '{}'",
                working_dir.display()
            ))
        }
    }

    let validator = Validator::start(
        authority,
        committee,
        public_config,
        private_config,
        client_parameters,
        byzantine_strategy,
        consensus_protocol,
    )
    .await?;
    let (network_result, _metrics_result) = validator.await_completion().await;
    network_result.expect("Validator crashed");

    Ok(())
}

fn run_with_progress(
    running: Arc<AtomicBool>,
    elapsed_seconds: Arc<AtomicU64>,
) -> thread::JoinHandle<()> {
    // Spawn a separate thread for the timer display
    thread::spawn(move || {
        let start = Instant::now();

        while running.load(Ordering::SeqCst) {
            let elapsed = start.elapsed().as_secs();
            elapsed_seconds.store(elapsed, Ordering::SeqCst);

            print!("\r{} seconds elapsed", elapsed);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();

            thread::sleep(Duration::from_millis(100));
        }
    })
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
