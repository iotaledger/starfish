// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

use clap::Parser;
use eyre::{Context, Result};
use prettytable::format;
use starfish_core::{
    ByzantineStrategy,
    committee::Committee,
    config::{
        DisseminationMode, ImportExport, NodeParameters, NodePrivateConfig, NodePublicConfig,
        Parameters, StorageBackend, TransactionMode,
    },
    metrics::Metrics,
    types::AuthorityIndex,
    validator::Validator,
};
use tokio::time::Instant;
use tracing_subscriber::{EnvFilter, filter::LevelFilter, fmt};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    operation: Operation,
}

#[derive(Parser)]
enum Operation {
    /// Generate a committee file, parameters files and the private config files
    /// of all validators from a list of initial peers. This is only
    /// suitable for benchmarks as it exposes all keys.
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
        parameters_path: String,
        #[clap(long, value_name = "STRING", default_value = "")]
        byzantine_strategy: String,
        #[clap(long, value_name = "STRING", default_value = "starfish")]
        consensus: String,
        /// Pushgateway URL for push-based metrics collection.
        #[clap(long, value_name = "URL")]
        pushgateway_url: Option<String>,
        /// Optional testbed identifier used to namespace Pushgateway metrics.
        #[clap(long, value_name = "STRING")]
        testbed_id: Option<String>,
        /// Optional benchmark run identifier used to namespace Pushgateway metrics.
        #[clap(long, value_name = "STRING")]
        benchmark_run_id: Option<String>,
    },
    /// Deploy a local validator for test. Dryrun mode uses
    /// default keys and committee configurations.
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
        #[clap(long, value_name = "FLOAT")]
        uniform_latency_ms: Option<f64>,
        /// Overlay 10s latency on the f farthest peers (circular distance).
        #[clap(long, default_value_t = false)]
        adversarial_latency: bool,
        #[clap(long, value_name = "STRING", default_value = "starfish")]
        consensus: String,
        /// Directory to store validator data (default: current directory)
        #[clap(long, value_name = "PATH")]
        data_dir: Option<PathBuf>,
        /// Base IP for validators (assigned by incrementing the IPv4 address).
        /// Default: 127.0.0.1
        #[clap(long, value_name = "IP")]
        base_ip: Option<IpAddr>,
        /// Storage backend for the DAG: rocksdb | tidehunter
        #[clap(long, value_name = "STRING")]
        storage_backend: Option<String>,
        /// Transaction payload mode: all_zero | random
        #[clap(long, value_name = "STRING", default_value = "random")]
        transaction_mode: Option<String>,
        /// Dissemination mode override:
        /// protocol-default | pull | push-causal | push-useful
        #[clap(long, value_name = "STRING")]
        dissemination_mode: Option<String>,
        /// Enable lz4 network compression.
        #[clap(long, default_value_t = false)]
        compress_network: bool,
        /// Number of parallel threads for BLS batch verification (default: 5).
        #[clap(long, value_name = "INT")]
        bls_workers: Option<usize>,
        /// Pushgateway URL for push-based metrics collection.
        #[clap(long, value_name = "URL")]
        pushgateway_url: Option<String>,
        /// Optional testbed identifier used to namespace Pushgateway metrics.
        #[clap(long, value_name = "STRING")]
        testbed_id: Option<String>,
        /// Optional benchmark run identifier used to namespace Pushgateway metrics.
        #[clap(long, value_name = "STRING")]
        benchmark_run_id: Option<String>,
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
        #[clap(long, value_name = "FLOAT")]
        uniform_latency_ms: Option<f64>,
        /// Overlay 10s latency on the f farthest peers (circular distance).
        #[clap(long, default_value_t = false)]
        adversarial_latency: bool,
        #[clap(long, value_name = "STRING", default_value = "starfish")]
        consensus: String,
        #[clap(long, value_name = "INT", default_value_t = 600)]
        duration_secs: u64,
        /// Dissemination mode override:
        /// protocol-default | pull | push-causal | push-useful
        #[clap(long, value_name = "STRING")]
        dissemination_mode: Option<String>,
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
            parameters_path,
            byzantine_strategy,
            consensus: consensus_protocol,
            pushgateway_url,
            testbed_id,
            benchmark_run_id,
        } => {
            run(
                authority,
                committee_path,
                public_config_path,
                private_config_path,
                parameters_path,
                byzantine_strategy,
                consensus_protocol,
                pushgateway_url,
                testbed_id,
                benchmark_run_id,
            )
            .await?
        }
        Operation::DryRun {
            authority,
            committee_size,
            load,
            byzantine_strategy,
            mimic_extra_latency: mimic_latency,
            uniform_latency_ms,
            adversarial_latency,
            consensus: consensus_protocol,
            data_dir,
            base_ip,
            storage_backend,
            transaction_mode,
            dissemination_mode,
            compress_network,
            bls_workers,
            pushgateway_url,
            testbed_id,
            benchmark_run_id,
        } => {
            dryrun(
                authority,
                committee_size,
                load,
                byzantine_strategy,
                mimic_latency,
                uniform_latency_ms,
                adversarial_latency,
                consensus_protocol,
                data_dir,
                base_ip,
                storage_backend,
                transaction_mode,
                dissemination_mode,
                compress_network,
                bls_workers,
                pushgateway_url,
                testbed_id,
                benchmark_run_id,
            )
            .await?
        }
        Operation::LocalBenchmark {
            committee_size,
            load,
            num_byzantine_nodes,
            byzantine_strategy,
            mimic_extra_latency,
            uniform_latency_ms,
            adversarial_latency,
            consensus: consensus_protocol,
            duration_secs,
            dissemination_mode,
        } => {
            let mut node_parameters = NodeParameters::default_with_latency(mimic_extra_latency);
            if let Some(latency) = uniform_latency_ms {
                node_parameters.uniform_latency_ms = Some(latency);
            }
            node_parameters.adversarial_latency = adversarial_latency;
            if let Some(ref mode) = dissemination_mode {
                node_parameters.dissemination_mode = parse_dissemination_mode(mode)?;
            }
            local_benchmark(
                committee_size,
                load,
                num_byzantine_nodes,
                byzantine_strategy,
                node_parameters,
                consensus_protocol,
                duration_secs,
            )
            .await?;
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
    node_parameters: NodeParameters,
    consensus_protocol: String,
    duration_secs: u64,
) -> Result<()> {
    println!("\n=== Benchmark Configuration ===");
    println!("Committee Size: {committee_size}");
    println!("Byzantine Nodes: {num_byzantine_nodes}");
    if num_byzantine_nodes != 0 {
        println!("Byzantine Strategy: {byzantine_strategy}");
    }
    println!("Transaction Load: {load} tx/s");
    println!("Consensus Protocol: {consensus_protocol}");
    if let Some(latency) = node_parameters.uniform_latency_ms {
        println!("Network Latency: {latency} ms (uniform)");
    } else {
        println!(
            "Network Latency: {}",
            if node_parameters.mimic_latency {
                "AWS RTT Table"
            } else {
                "Disabled"
            }
        );
    }
    if node_parameters.adversarial_latency {
        println!("Adversarial Latency: 10s on f farthest peers");
    }
    println!("Duration: {duration_secs} seconds");
    println!("===========================\n");
    let ips = vec![IpAddr::V4(Ipv4Addr::LOCALHOST); committee_size];
    let committee = Committee::new_for_benchmarks(committee_size);
    load /= committee.len();
    let parameters = Parameters::almost_default(load);
    // Equivocating Byzantine strategies must not generate transactions.
    let byzantine_parameters = if ByzantineStrategy::from_strategy_str(&byzantine_strategy)
        .is_some_and(|s| s.is_equivocating())
    {
        Parameters::almost_default(0)
    } else {
        parameters.clone()
    };
    let public_config = NodePublicConfig::new_for_benchmarks(ips, Some(node_parameters.clone()));

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
            "Starting node {authority} in local \
            benchmark mode (committee size: {committee_size})"
        );
        let working_dir = base_dir.join(format!("node-{authority}"));
        fs::create_dir_all(&working_dir)?;
        match fs::remove_dir_all(&working_dir) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).wrap_err(format!(
                    "Failed to remove directory '{}'",
                    working_dir.display()
                ));
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
                ));
            }
        }
        let is_byzantine = authority.is_multiple_of(3) && authority / 3 < num_byzantine_nodes;
        let validator = if is_byzantine {
            Validator::start(
                authority as AuthorityIndex,
                committee.clone(),
                public_config.clone(),
                private_config,
                byzantine_parameters.clone(),
                byzantine_strategy.clone(),
                consensus_protocol.clone(),
                None,
                None,
                None,
            )
            .await?
        } else {
            Validator::start(
                authority as AuthorityIndex,
                committee.clone(),
                public_config.clone(),
                private_config,
                parameters.clone(),
                "honest".to_string(),
                consensus_protocol.clone(),
                None,
                None,
                None,
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
            println!("Benchmark completed after {duration_secs} seconds");
            // Display metrics
            Metrics::aggregate_and_display(
                metrics_of_honest_validators,
                reporters_of_honest_validators,
                duration_secs,
            );

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
            Metrics::aggregate_and_display(
                metrics_of_honest_validators,
                reporters_of_honest_validators,
                duration_secs,
            );
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
    parameters_path: String,
    byzantine_strategy: String,
    consensus_protocol: String,
    pushgateway_url: Option<String>,
    testbed_id: Option<String>,
    benchmark_run_id: Option<String>,
) -> Result<()> {
    tracing::info!("Starting node {authority}");

    let committee = Committee::load(&committee_path)
        .wrap_err(format!("Failed to load committee file '{committee_path}'"))?;
    let public_config = NodePublicConfig::load(&public_config_path).wrap_err(format!(
        "Failed to load parameters file '{public_config_path}'"
    ))?;
    let private_config = NodePrivateConfig::load(&private_config_path).wrap_err(format!(
        "Failed to load private configuration file '{private_config_path}'"
    ))?;
    let parameters = Parameters::load(&parameters_path).wrap_err(format!(
        "Failed to load parameters file '{parameters_path}'"
    ))?;

    let committee = Arc::new(committee);

    // Boot the validator node.
    let validator = Validator::start(
        authority,
        committee,
        public_config,
        private_config,
        parameters,
        byzantine_strategy,
        consensus_protocol,
        pushgateway_url,
        testbed_id,
        benchmark_run_id,
    )
    .await?;
    let (network_result, _metrics_result) = validator.await_completion().await;
    network_result.expect("Validator crashed");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn dryrun(
    authority: AuthorityIndex,
    committee_size: usize,
    load: usize,
    byzantine_strategy: String,
    mimic_latency: bool,
    uniform_latency_ms: Option<f64>,
    adversarial_latency: bool,
    consensus_protocol: String,
    data_dir: Option<PathBuf>,
    base_ip: Option<IpAddr>,
    storage_backend: Option<String>,
    transaction_mode: Option<String>,
    dissemination_mode: Option<String>,
    compress_network: bool,
    bls_workers: Option<usize>,
    pushgateway_url: Option<String>,
    testbed_id: Option<String>,
    benchmark_run_id: Option<String>,
) -> Result<()> {
    tracing::warn!("Starting node {authority} in dryrun mode (committee size: {committee_size})");
    let ips: Vec<IpAddr> = match base_ip {
        Some(IpAddr::V4(v4)) => (0..committee_size)
            .map(|i| ipv4_add_offset(v4, i).map(IpAddr::V4))
            .collect::<Result<_>>()?,
        Some(_) => eyre::bail!("--base-ip must be an IPv4 address"),
        None => vec![IpAddr::V4(Ipv4Addr::LOCALHOST); committee_size],
    };
    let committee = Committee::new_for_benchmarks(committee_size);
    let mut parameters = Parameters::almost_default(load);
    if let Some(ref backend) = storage_backend {
        parameters.storage_backend = match backend.as_str() {
            "rocksdb" => StorageBackend::Rocksdb,
            "tidehunter" => StorageBackend::Tidehunter,
            other => {
                eyre::bail!("Unknown storage backend '{other}'. Use 'rocksdb' or 'tidehunter'.")
            }
        };
    }
    if let Some(ref mode) = transaction_mode {
        parameters.transaction_mode = match mode.as_str() {
            "all_zero" => TransactionMode::AllZero,
            "random" => TransactionMode::Random,
            other => eyre::bail!("Unknown transaction mode '{other}'. Use 'all_zero' or 'random'."),
        };
    }
    let mut node_parameters = NodeParameters::default_with_latency(mimic_latency);
    if let Some(latency) = uniform_latency_ms {
        node_parameters.uniform_latency_ms = Some(latency);
    }
    node_parameters.adversarial_latency = adversarial_latency;
    node_parameters.compress_network = compress_network;
    if let Some(workers) = bls_workers {
        node_parameters.bls_verification_workers = workers;
    }
    if let Some(ref mode) = dissemination_mode {
        node_parameters.dissemination_mode = parse_dissemination_mode(mode)?;
    }
    let public_config = NodePublicConfig::new_for_benchmarks(ips, Some(node_parameters));

    let base = data_dir.unwrap_or_default();
    let working_dir = base.join(format!("dryrun-node-{authority}"));
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
            ));
        }
    }
    match fs::create_dir_all(&private_config.storage_path) {
        Ok(_) => {}
        Err(e) => {
            return Err(e).wrap_err(format!(
                "Failed to create directory '{}'",
                working_dir.display()
            ));
        }
    }

    let validator = Validator::start(
        authority,
        committee,
        public_config,
        private_config,
        parameters,
        byzantine_strategy,
        consensus_protocol,
        pushgateway_url,
        testbed_id,
        benchmark_run_id,
    )
    .await?;
    let (network_result, _metrics_result) = validator.await_completion().await;
    network_result.expect("Validator crashed");

    Ok(())
}

fn ipv4_add_offset(base: Ipv4Addr, offset: usize) -> Result<Ipv4Addr> {
    let offset = u32::try_from(offset).context("validator count exceeds IPv4 offset range")?;
    let next = u32::from(base)
        .checked_add(offset)
        .ok_or_else(|| eyre::eyre!("base-ip overflow: too many validators for IPv4 range"))?;
    Ok(Ipv4Addr::from(next))
}

fn parse_dissemination_mode(mode: &str) -> Result<DisseminationMode> {
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

            print!("\r{elapsed} seconds elapsed");
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::ipv4_add_offset;

    #[test]
    fn ipv4_add_offset_crosses_octet_boundary() {
        let base = Ipv4Addr::new(172, 28, 0, 10);
        assert_eq!(
            ipv4_add_offset(base, 255).unwrap(),
            Ipv4Addr::new(172, 28, 1, 9)
        );
    }

    #[test]
    fn ipv4_add_offset_errors_on_overflow() {
        let base = Ipv4Addr::new(255, 255, 255, 255);
        assert!(ipv4_add_offset(base, 1).is_err());
    }
}
