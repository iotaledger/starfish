// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    fs,
    net::{IpAddr, Ipv4Addr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

use clap::Parser;
use eyre::{Context, Result};
use futures::future::try_join_all;
use prettytable::format;
use starfish_core::{
    committee::Committee,
    config::{
        DisseminationMode, ImportExport, NodeParameters, NodePrivateConfig, NodePublicConfig,
        Parameters, StorageBackend, TransactionMode,
    },
    metrics::{
        AutonomousClockBenchmarkSnapshot, BenchmarkGeneratorState, BenchmarkTransactionWindow,
        LocalBenchmarkTransactionOutcome, Metrics,
    },
    types::AuthorityIndex,
    validator::{Validator, ValidatorStartOptions},
};
use tokio::{sync::watch, time::Instant};
use tracing_subscriber::{EnvFilter, filter::LevelFilter, fmt};

// Network workers bind active sockets at `listener_port * 10`. Keep those
// derived ports below the conventional Linux ephemeral range so repeated
// local experiments cannot collide with an unrelated outbound connection.
const LOCAL_BENCHMARK_MAX_ACTIVE_BIND_PORT: u16 = 32_767;

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
        /// Consensus protocol. The `*-mac` names are experimental protocols.
        #[clap(long, value_name = "STRING", default_value = "starfish")]
        consensus: String,
        /// Block signature scheme. Defaults to Ed25519 and is not applicable
        /// to the experimental `*-mac` protocols.
        #[clap(long, value_name = "ed25519|ml-dsa-44|ml-dsa-65|mac")]
        block_authentication: Option<String>,
        /// Enable the persisted RBC-DAG research runtime alongside
        /// `starfish-rbc` (comparison-only unless autonomous mode is enabled).
        #[clap(long, default_value_t = false)]
        starfish_rbc_dag_shadow: bool,
        /// Run the independent Starfish-RBC-DAG carrier clock and certified
        /// projection. Requires `--starfish-rbc-dag-shadow`.
        #[clap(long, default_value_t = false)]
        starfish_rbc_dag_autonomous_clock: bool,
        /// Let embedded carrier ECHO/READY delivery certify application
        /// headers. Requires the autonomous RBC-DAG mode.
        #[clap(long, default_value_t = false)]
        starfish_rbc_dag_embedded_rbc_authority: bool,
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
        /// Adversarial-latency ramp. Same-region peers (base latency < 5 ms)
        /// are kept stable. Of the remaining cross-region peers per row, a
        /// random `adversarial_latency_percent`% are scaled by `1 + t / 10`
        /// seconds (continuous ramp).
        #[clap(long, default_value_t = false)]
        adversarial_latency: bool,
        /// Percentage of cross-region peers per row that are scaled when
        /// `--adversarial-latency` is enabled (0-100).
        #[clap(long, value_name = "INT", default_value_t = 34)]
        adversarial_latency_percent: u32,
        /// Consensus protocol. The `*-mac` names are experimental protocols.
        #[clap(long, value_name = "STRING", default_value = "starfish")]
        consensus: String,
        /// Block signature scheme. Defaults to Ed25519 and is not applicable
        /// to the experimental `*-mac` protocols.
        #[clap(long, value_name = "ed25519|ml-dsa-44|ml-dsa-65|mac")]
        block_authentication: Option<String>,
        /// Enable the persisted RBC-DAG research runtime alongside
        /// `starfish-rbc` (comparison-only unless autonomous mode is enabled).
        #[clap(long, default_value_t = false)]
        starfish_rbc_dag_shadow: bool,
        /// Run the independent Starfish-RBC-DAG carrier clock and certified
        /// projection. Requires `--starfish-rbc-dag-shadow`.
        #[clap(long, default_value_t = false)]
        starfish_rbc_dag_autonomous_clock: bool,
        /// Let embedded carrier ECHO/READY delivery certify application
        /// headers. Requires the autonomous RBC-DAG mode.
        #[clap(long, default_value_t = false)]
        starfish_rbc_dag_embedded_rbc_authority: bool,
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
        /// Adversarial-latency ramp. Same-region peers (base latency < 5 ms)
        /// are kept stable. Of the remaining cross-region peers per row, a
        /// random `adversarial_latency_percent`% are scaled by `1 + t / 10`
        /// seconds (continuous ramp).
        #[clap(long, default_value_t = false)]
        adversarial_latency: bool,
        /// Percentage of cross-region peers per row that are scaled when
        /// `--adversarial-latency` is enabled (0-100).
        #[clap(long, value_name = "INT", default_value_t = 34)]
        adversarial_latency_percent: u32,
        /// Consensus protocol. The `*-mac` names are experimental protocols.
        #[clap(long, value_name = "STRING", default_value = "starfish")]
        consensus: String,
        /// Block signature scheme. Defaults to Ed25519 and is not applicable
        /// to the experimental `*-mac` protocols.
        #[clap(long, value_name = "ed25519|ml-dsa-44|ml-dsa-65|mac")]
        block_authentication: Option<String>,
        /// Enable the persisted RBC-DAG research runtime alongside
        /// `starfish-rbc` (comparison-only unless autonomous mode is enabled).
        #[clap(long, default_value_t = false)]
        starfish_rbc_dag_shadow: bool,
        /// Run the independent Starfish-RBC-DAG carrier clock and certified
        /// projection. Requires `--starfish-rbc-dag-shadow`.
        #[clap(long, default_value_t = false)]
        starfish_rbc_dag_autonomous_clock: bool,
        /// Let embedded carrier ECHO/READY delivery certify application
        /// headers. Requires the autonomous RBC-DAG mode.
        #[clap(long, default_value_t = false)]
        starfish_rbc_dag_embedded_rbc_authority: bool,
        /// Testbed-only: deliver a single-DAG RBC header after a receiver-local
        /// quorum ECHO. This preserves uniqueness but not Byzantine
        /// selective-withholding totality, so it is restricted to finite
        /// benchmark runs.
        #[clap(long, default_value_t = false)]
        starfish_rbc_single_dag_echo_qc_fast_path: bool,
        /// Benchmark-only: write ordered shadow-WAL frames but force them to
        /// stable storage only at clean shutdown. This run is not crash-safe.
        #[clap(long, default_value_t = false)]
        starfish_rbc_dag_shadow_buffered_wal: bool,
        #[clap(long, value_name = "INT", default_value_t = 600)]
        duration_secs: u64,
        /// Add an offset to the local benchmark's fixed network and metrics
        /// ports. This is useful for isolated repeated experiments and avoids
        /// silently sharing `SO_REUSEPORT` listeners with a stale run.
        #[clap(long, value_name = "INT", default_value_t = 0)]
        port_offset: u16,
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
            block_authentication,
            starfish_rbc_dag_shadow,
            starfish_rbc_dag_autonomous_clock,
            starfish_rbc_dag_embedded_rbc_authority,
        } => {
            run(
                authority,
                committee_path,
                public_config_path,
                private_config_path,
                parameters_path,
                byzantine_strategy,
                consensus_protocol,
                block_authentication,
                starfish_rbc_dag_shadow,
                starfish_rbc_dag_autonomous_clock,
                starfish_rbc_dag_embedded_rbc_authority,
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
            adversarial_latency_percent,
            consensus: consensus_protocol,
            block_authentication,
            starfish_rbc_dag_shadow,
            starfish_rbc_dag_autonomous_clock,
            starfish_rbc_dag_embedded_rbc_authority,
            data_dir,
            base_ip,
            storage_backend,
            transaction_mode,
            dissemination_mode,
            compress_network,
            bls_workers,
        } => {
            dryrun(
                authority,
                committee_size,
                load,
                byzantine_strategy,
                mimic_latency,
                uniform_latency_ms,
                adversarial_latency,
                adversarial_latency_percent,
                consensus_protocol,
                block_authentication,
                starfish_rbc_dag_shadow,
                starfish_rbc_dag_autonomous_clock,
                starfish_rbc_dag_embedded_rbc_authority,
                data_dir,
                base_ip,
                storage_backend,
                transaction_mode,
                dissemination_mode,
                compress_network,
                bls_workers,
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
            adversarial_latency_percent,
            consensus: consensus_protocol,
            block_authentication,
            starfish_rbc_dag_shadow,
            starfish_rbc_dag_autonomous_clock,
            starfish_rbc_dag_embedded_rbc_authority,
            starfish_rbc_single_dag_echo_qc_fast_path,
            starfish_rbc_dag_shadow_buffered_wal,
            duration_secs,
            port_offset,
            dissemination_mode,
        } => {
            let mut node_parameters = NodeParameters::default_with_latency(mimic_extra_latency);
            if let Some(latency) = uniform_latency_ms {
                node_parameters.uniform_latency_ms = Some(latency);
            }
            node_parameters.adversarial_latency = adversarial_latency;
            node_parameters.adversarial_latency_percent = adversarial_latency_percent;
            node_parameters.block_authentication = block_authentication;
            node_parameters.starfish_rbc_dag_shadow = starfish_rbc_dag_shadow;
            node_parameters.starfish_rbc_dag_autonomous_clock = starfish_rbc_dag_autonomous_clock;
            node_parameters.starfish_rbc_dag_embedded_rbc_authority =
                starfish_rbc_dag_embedded_rbc_authority;
            node_parameters.starfish_rbc_single_dag_echo_qc_fast_path =
                starfish_rbc_single_dag_echo_qc_fast_path;
            node_parameters.starfish_rbc_dag_shadow_buffered_wal =
                starfish_rbc_dag_shadow_buffered_wal;
            if is_starfish_rbc_selection(&consensus_protocol) {
                node_parameters.refresh_starfish_rbc_protocol_instance();
            }
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
                port_offset,
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
    let mut node_parameters = match node_parameters_path {
        Some(path) => NodeParameters::load(&path).wrap_err(format!(
            "Failed to load parameters file '{}'",
            path.display()
        ))?,
        None => NodeParameters::default(),
    };
    if node_parameters.starfish_rbc_protocol_instance.is_none() {
        node_parameters.refresh_starfish_rbc_protocol_instance();
    }

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

fn local_benchmark_private_configs(
    base_dir: &Path,
    committee_size: usize,
) -> Vec<NodePrivateConfig> {
    NodePrivateConfig::new_for_benchmarks(base_dir, committee_size)
        .into_iter()
        .enumerate()
        .map(|(authority, mut private_config)| {
            private_config.storage_path = base_dir.join(format!("node-{authority}")).join(
                NodePrivateConfig::default_storage_path(authority as AuthorityIndex),
            );
            private_config
        })
        .collect()
}

async fn stop_local_benchmark_validators(validators: Vec<Validator>) {
    let mut stops = tokio::task::JoinSet::new();
    for validator in validators {
        stops.spawn(validator.stop());
    }
    while let Some(result) = stops.join_next().await {
        if let Err(error) = result {
            tracing::warn!("Validator shutdown task failed: {error}");
        }
    }
}

fn local_benchmark_topology_ready(
    metrics: &[Arc<Metrics>],
    expected_peer_subscriptions: i64,
) -> Result<bool> {
    local_benchmark_topology_state(
        metrics.iter().map(|metrics| {
            (
                metrics.metrics_active.load(Ordering::Relaxed),
                metrics.subscribed_to_peers.get(),
                metrics.subscribed_by_peers.get(),
            )
        }),
        expected_peer_subscriptions,
    )
}

fn local_benchmark_topology_state(
    states: impl IntoIterator<Item = (bool, i64, i64)>,
    expected_peer_subscriptions: i64,
) -> Result<bool> {
    let states = states.into_iter().collect::<Vec<_>>();
    eyre::ensure!(
        !states.iter().any(|(active, _, _)| *active),
        "A transaction generator opened before the complete peer subscription mesh"
    );
    Ok(states.iter().all(|(_, subscribed_to, subscribed_by)| {
        *subscribed_to == expected_peer_subscriptions
            && *subscribed_by == expected_peer_subscriptions
    }))
}

/// Assign the configured aggregate transaction load exclusively to honest
/// validators. Byzantine validators exercise protocol behavior only: making
/// their deliberately withheld/dropped transactions part of the mandatory
/// drain target would conflate adversarial dissemination with lost honest
/// work. The remainder is distributed deterministically by authority order so
/// the per-validator rates sum to the exact requested aggregate load.
fn local_benchmark_generator_loads(
    committee_size: usize,
    aggregate_load: usize,
    num_byzantine_nodes: usize,
) -> Result<(BTreeSet<usize>, Vec<usize>)> {
    let byzantine_authorities = (0..committee_size)
        .filter(|authority| *authority % 3 == 0 && *authority / 3 < num_byzantine_nodes)
        .collect::<BTreeSet<_>>();
    eyre::ensure!(
        byzantine_authorities.len() == num_byzantine_nodes,
        "requested {num_byzantine_nodes} Byzantine validators, but the local benchmark layout can place only {} in a committee of {committee_size}",
        byzantine_authorities.len(),
    );
    let honest_count = committee_size.saturating_sub(byzantine_authorities.len());
    eyre::ensure!(
        honest_count > 0,
        "a local benchmark requires at least one honest transaction generator"
    );
    let base = aggregate_load / honest_count;
    let remainder = aggregate_load % honest_count;
    let mut honest_rank = 0usize;
    let loads = (0..committee_size)
        .map(|authority| {
            if byzantine_authorities.contains(&authority) {
                0
            } else {
                let load = base + usize::from(honest_rank < remainder);
                honest_rank += 1;
                load
            }
        })
        .collect::<Vec<_>>();
    debug_assert_eq!(loads.iter().sum::<usize>(), aggregate_load);
    Ok((byzantine_authorities, loads))
}

async fn local_benchmark(
    committee_size: usize,
    load: usize,
    num_byzantine_nodes: usize,
    byzantine_strategy: String,
    node_parameters: NodeParameters,
    consensus_protocol: String,
    duration_secs: u64,
    port_offset: u16,
) -> Result<()> {
    eyre::ensure!(
        duration_secs > 0,
        "benchmark duration must be greater than zero"
    );
    println!("\n=== Benchmark Configuration ===");
    println!("Committee Size: {committee_size}");
    println!("Byzantine Nodes: {num_byzantine_nodes}");
    if num_byzantine_nodes != 0 {
        println!("Byzantine Strategy: {byzantine_strategy}");
    }
    println!("Transaction Load: {load} tx/s");
    println!("Consensus Protocol: {consensus_protocol}");
    println!(
        "Block Authentication: {}",
        if consensus_protocol.ends_with("-mac") {
            "mac-vector (experimental)"
        } else {
            node_parameters
                .block_authentication
                .as_deref()
                .unwrap_or("ed25519")
        }
    );
    if node_parameters.starfish_rbc_dag_shadow {
        println!(
            "Shadow WAL: {}",
            if node_parameters.starfish_rbc_dag_shadow_buffered_wal {
                "buffered benchmark profile (sync on clean shutdown; not crash-safe)"
            } else {
                "sync every transition (crash-safe reference profile)"
            }
        );
    }
    if node_parameters.starfish_rbc_dag_autonomous_clock {
        println!(
            "Carrier idle timeout: {} ms (shared Starfish leader pacemaker)",
            node_parameters.leader_timeout.as_millis()
        );
    }
    if node_parameters.starfish_rbc_single_dag_echo_qc_fast_path {
        println!(
            "Single-DAG receiver-local quorum-ECHO: ENABLED (signature-free latency lower bound; Byzantine totality not provided)"
        );
    }
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
        println!(
            "Adversarial Latency: {}% of cross-region peers per row scaled \
             by mult = 1 + t/10s (continuous ramp); same-region peers \
             (base < 5ms) stay at base latency",
            node_parameters.adversarial_latency_percent
        );
    }
    println!("Duration: {duration_secs} seconds");
    println!("Local port offset: {port_offset}");
    println!("===========================\n");
    let ips = vec![IpAddr::V4(Ipv4Addr::LOCALHOST); committee_size];
    let committee = Committee::new_for_benchmarks(committee_size);
    let (byzantine_authorities, generator_loads) =
        local_benchmark_generator_loads(committee_size, load, num_byzantine_nodes)?;
    if !byzantine_authorities.is_empty() {
        println!(
            "Byzantine transaction generators: disabled; aggregate load redistributed across {} honest validators",
            committee_size.saturating_sub(byzantine_authorities.len()),
        );
    }
    let mut parameters = Parameters::almost_default(0);
    parameters.benchmark_duration = Some(Duration::from_secs(duration_secs));
    let public_config = NodePublicConfig::new_for_benchmarks(ips, Some(node_parameters.clone()));
    validate_local_benchmark_port_offset(&public_config, port_offset)?;
    let public_config = public_config.with_port_offset(port_offset);
    preflight_local_benchmark_ports(&public_config)?;
    let starfish_rbc_dag_shadow_expected = node_parameters.starfish_rbc_dag_shadow;
    let starfish_rbc_dag_autonomous_clock_expected =
        node_parameters.starfish_rbc_dag_autonomous_clock;
    let starfish_rbc_dag_embedded_rbc_authority_expected =
        node_parameters.starfish_rbc_dag_embedded_rbc_authority;
    let coordinated_rbc_dag_clock_start = starfish_rbc_dag_autonomous_clock_expected
        && starfish_rbc_dag_embedded_rbc_authority_expected;

    // Create temporary directories for each validator
    // Isolate storage by the same explicit run namespace as the sockets.
    // A stale or intentionally concurrent benchmark on another offset must
    // not keep RocksDB/WAL handles open underneath this run's cleanup.
    let base_dir = PathBuf::from(format!("local-benchmark-{port_offset}"));
    fs::create_dir_all(&base_dir)?;
    // Generate the benchmark key material before any validator starts. Doing
    // this inside the startup loop regenerates the entire committee keyset for
    // every authority; once the first quorum is live, that CPU work lets its
    // autonomous clock run far ahead of the validators still being prepared.
    let private_configs = local_benchmark_private_configs(&base_dir, committee_size);

    let mut validators = Vec::with_capacity(committee_size);
    let mut metrics_of_all_validators = Vec::with_capacity(committee_size);
    let mut metrics_of_honest_validators = Vec::new();
    let mut reporters_of_honest_validators = Vec::new();
    // Every local benchmark, not only RBC-DAG, uses one absolute offered-load
    // window. Production Validator::start remains ungated.
    let (transaction_generator_start_tx, transaction_generator_start_rx) =
        watch::channel(None::<BenchmarkTransactionWindow>);

    // Create a flag to signal when the benchmark is complete
    let running = Arc::new(AtomicBool::new(true));
    // Create a counter for elapsed seconds
    let elapsed_seconds = Arc::new(AtomicU64::new(0));

    // Start the progress display in a separate thread
    run_with_progress(running.clone(), elapsed_seconds.clone());

    // Start all validators
    for (authority, private_config) in private_configs.into_iter().enumerate() {
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
        match fs::create_dir_all(&private_config.storage_path) {
            Ok(_) => {}
            Err(e) => {
                return Err(e).wrap_err(format!(
                    "Failed to create directory '{}'",
                    working_dir.display()
                ));
            }
        }
        let is_byzantine = byzantine_authorities.contains(&authority);
        let mut generator_parameters = parameters.clone();
        generator_parameters.load = generator_loads[authority];
        let start_options = ValidatorStartOptions {
            rbc_dag_clock_start_paused: coordinated_rbc_dag_clock_start,
            transaction_generator_start: Some(transaction_generator_start_rx.clone()),
        };
        let validator = if is_byzantine {
            Validator::start_with_options(
                authority as AuthorityIndex,
                committee.clone(),
                public_config.clone(),
                private_config,
                generator_parameters,
                byzantine_strategy.clone(),
                consensus_protocol.clone(),
                start_options,
            )
            .await?
        } else {
            Validator::start_with_options(
                authority as AuthorityIndex,
                committee.clone(),
                public_config.clone(),
                private_config,
                generator_parameters,
                "honest".to_string(),
                consensus_protocol.clone(),
                start_options,
            )
            .await?
        };
        let validator_metrics = validator.metrics();
        metrics_of_all_validators.push(Arc::clone(&validator_metrics));
        if !is_byzantine {
            metrics_of_honest_validators.push(Arc::clone(&validator_metrics));
            reporters_of_honest_validators.push(validator.reporter())
        }

        validators.push(validator);
    }

    if starfish_rbc_dag_shadow_expected && !coordinated_rbc_dag_clock_start {
        let ready = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if metrics_of_honest_validators.iter().all(|metrics| {
                    if starfish_rbc_dag_autonomous_clock_expected {
                        metrics.starfish_rbc_dag_shadow_clock_valid.get() == 1
                    } else {
                        metrics.starfish_rbc_dag_shadow_comparison_valid.get() == 1
                    }
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        if ready.is_err() {
            running.store(false, Ordering::SeqCst);
            stop_local_benchmark_validators(validators).await;
            fs::remove_dir_all(&base_dir)?;
            let mode = if starfish_rbc_dag_autonomous_clock_expected {
                "autonomous clock"
            } else {
                "direct-comparison shadow"
            };
            eyre::bail!(
                "Starfish-RBC-DAG {mode} did not become ready on every honest validator; benchmark was not started"
            );
        }
    }

    // A ready protocol actor is not yet a ready benchmark network. Require
    // every honest validator to observe the complete logical subscription
    // mesh before recording baselines. This fails closed if an earlier core
    // failure leaves independent TCP workers alive or if startup is only
    // partially connected.
    let expected_peer_subscriptions =
        i64::try_from(committee_size.saturating_sub(1)).unwrap_or(i64::MAX);
    let topology_ready = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if local_benchmark_topology_ready(
                &metrics_of_all_validators,
                expected_peer_subscriptions,
            )? {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok::<(), eyre::Report>(())
    })
    .await;
    if !matches!(topology_ready, Ok(Ok(()))) {
        running.store(false, Ordering::SeqCst);
        stop_local_benchmark_validators(validators).await;
        fs::remove_dir_all(&base_dir)?;
        eyre::bail!(
            "Local benchmark did not establish the complete {expected_peer_subscriptions}-peer subscription mesh on every honest validator"
        );
    }

    if coordinated_rbc_dag_clock_start {
        let activated = tokio::time::timeout(
            Duration::from_secs(30),
            try_join_all(
                validators
                    .iter()
                    .map(Validator::activate_starfish_rbc_dag_clock),
            ),
        )
        .await;
        if let Ok(Err(error)) = &activated {
            tracing::error!("Failed to activate a coordinated RBC-DAG clock: {error}");
        }
        if !matches!(activated, Ok(Ok(_))) {
            running.store(false, Ordering::SeqCst);
            stop_local_benchmark_validators(validators).await;
            fs::remove_dir_all(&base_dir)?;
            eyre::bail!(
                "Local benchmark could not activate every RBC-DAG clock after full topology readiness"
            );
        }

        // The service activation acknowledgment only publishes the ordered
        // ClockActivated event. Wait until each event bridge has processed it,
        // released the authoritative Core producer, and marked the clock live.
        let clock_ready = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                local_benchmark_topology_ready(
                    &metrics_of_all_validators,
                    expected_peer_subscriptions,
                )?;
                if metrics_of_all_validators
                    .iter()
                    .all(|metrics| metrics.starfish_rbc_dag_shadow_clock_valid.get() == 1)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Ok::<(), eyre::Report>(())
        })
        .await;
        if !matches!(clock_ready, Ok(Ok(()))) {
            running.store(false, Ordering::SeqCst);
            stop_local_benchmark_validators(validators).await;
            fs::remove_dir_all(&base_dir)?;
            eyre::bail!("RBC-DAG clocks did not activate before the transaction window opened");
        }
    }

    let generators_waiting = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if metrics_of_all_validators.iter().all(|metrics| {
                BenchmarkGeneratorState::from_u8(
                    metrics.benchmark_generator_state.load(Ordering::Acquire),
                ) == BenchmarkGeneratorState::Waiting
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    if generators_waiting.is_err() {
        running.store(false, Ordering::SeqCst);
        stop_local_benchmark_validators(validators).await;
        fs::remove_dir_all(&base_dir)?;
        eyre::bail!("transaction generators did not reach the coordinated waiting state");
    }

    // Clear warmup samples and capture every baseline before publishing the
    // release. No generator can submit before the common absolute start.
    for reporter in &reporters_of_honest_validators {
        reporter.reset_for_benchmark_window();
    }
    let autonomous_clock_baselines = starfish_rbc_dag_autonomous_clock_expected.then(|| {
        metrics_of_honest_validators
            .iter()
            .map(|metrics| metrics.autonomous_clock_benchmark_baseline())
            .collect::<Vec<_>>()
    });
    let counter_baselines = metrics_of_honest_validators
        .iter()
        .map(|metrics| metrics.local_benchmark_counter_baseline())
        .collect::<Vec<_>>();
    let sequenced_baselines = metrics_of_honest_validators
        .iter()
        .map(|metrics| metrics.sequenced_transactions_total.get())
        .collect::<Vec<_>>();
    let cutoff_sequenced_baselines = metrics_of_honest_validators
        .iter()
        .map(|metrics| metrics.sequenced_transactions_cutoff_total.get())
        .collect::<Vec<_>>();
    let honest_submitted_baselines = metrics_of_honest_validators
        .iter()
        .map(|metrics| metrics.submitted_transactions.get())
        .collect::<Vec<_>>();
    let window_start = Instant::now() + Duration::from_millis(100);
    let window_end = window_start
        .checked_add(Duration::from_secs(duration_secs))
        .ok_or_else(|| eyre::eyre!("benchmark duration exceeds the monotonic clock range"))?;
    let transaction_window = BenchmarkTransactionWindow::new(window_start, window_end)
        .expect("positive local benchmark duration must form a valid window");
    for metrics in &metrics_of_all_validators {
        let cutoff_micros = window_end
            .saturating_duration_since(metrics.validator_start)
            .as_micros()
            .min(u64::MAX as u128) as u64;
        metrics
            .benchmark_transaction_cutoff_micros
            .store(cutoff_micros, Ordering::Release);
    }
    transaction_generator_start_tx.send_replace(Some(transaction_window));
    tokio::time::sleep_until(window_start).await;

    let active_window_ready = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let states = metrics_of_all_validators
                .iter()
                .map(|metrics| {
                    BenchmarkGeneratorState::from_u8(
                        metrics.benchmark_generator_state.load(Ordering::Acquire),
                    )
                })
                .collect::<Vec<_>>();
            eyre::ensure!(
                !states.contains(&BenchmarkGeneratorState::Failed),
                "a transaction generator failed while opening the common window"
            );
            if states
                .iter()
                .all(|state| *state == BenchmarkGeneratorState::Active)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        Ok::<(), eyre::Report>(())
    })
    .await;
    if !matches!(active_window_ready, Ok(Ok(()))) {
        running.store(false, Ordering::SeqCst);
        stop_local_benchmark_validators(validators).await;
        fs::remove_dir_all(&base_dir)?;
        eyre::bail!("transaction generators did not open the common active benchmark window");
    }
    println!("Active transaction window started ({duration_secs} seconds)");

    // Run for the requested active duration, but fail if any validator exits.
    // Keep ownership of the validators so the normal path can use their
    // graceful shutdown rather than aborting wrapper tasks and leaking socket
    // workers into subsequent latency experiments.
    let completed_full_duration = tokio::select! {
        _ = tokio::time::sleep_until(window_end) => true,
        _ = async {
            loop {
                if validators.iter().any(Validator::is_finished) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        } => false,
    };

    // Close protocol/window metrics at the exact common cutoff even if a
    // delayed generator task still has a scheduled pre-end batch to publish.
    for metrics in &metrics_of_all_validators {
        metrics.metrics_active.store(false, Ordering::Release);
    }
    let autonomous_clock_cutoffs: Option<Vec<AutonomousClockBenchmarkSnapshot>> =
        starfish_rbc_dag_autonomous_clock_expected.then(|| {
            metrics_of_honest_validators
                .iter()
                .map(|metrics| metrics.autonomous_clock_benchmark_snapshot())
                .collect()
        });
    let counter_cutoffs = metrics_of_honest_validators
        .iter()
        .map(|metrics| metrics.local_benchmark_counter_baseline())
        .collect::<Vec<_>>();
    let cutoff_committed_transactions = metrics_of_honest_validators
        .iter()
        .zip(&cutoff_sequenced_baselines)
        .map(|(metrics, baseline)| {
            metrics
                .sequenced_transactions_cutoff_total
                .get()
                .saturating_sub(*baseline)
        })
        .sum::<u64>()
        / metrics_of_honest_validators.len() as u64;

    let drain_started = Instant::now();
    let generators_finished = completed_full_duration
        && matches!(
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let states = metrics_of_all_validators
                        .iter()
                        .map(|metrics| {
                            BenchmarkGeneratorState::from_u8(
                                metrics.benchmark_generator_state.load(Ordering::Acquire),
                            )
                        })
                        .collect::<Vec<_>>();
                    eyre::ensure!(
                        !states.contains(&BenchmarkGeneratorState::Failed),
                        "a transaction generator failed during the active window"
                    );
                    if states
                        .iter()
                        .all(|state| *state == BenchmarkGeneratorState::Finished)
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                Ok::<(), eyre::Report>(())
            })
            .await,
            Ok(Ok(()))
        );

    // Byzantine generators have zero configured load, and offered work is
    // defined explicitly from honest generators so adversarial strategies can
    // neither inflate nor make the mandatory drain target unattainable.
    let offered_transactions = metrics_of_honest_validators
        .iter()
        .zip(&honest_submitted_baselines)
        .map(|(metrics, baseline)| {
            metrics
                .submitted_transactions
                .get()
                .saturating_sub(*baseline)
        })
        .sum::<u64>();
    let pipeline_observed_through_target = |metrics: &Metrics, sequenced_baseline: u64| {
        !starfish_rbc_dag_embedded_rbc_authority_expected
            || offered_transactions == 0
            || metrics.starfish_rbc_dag_frontier_applied_sequenced_transactions()
                >= sequenced_baseline.saturating_add(offered_transactions)
    };
    let drain_complete = generators_finished
        && tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if metrics_of_honest_validators
                    .iter()
                    .zip(&sequenced_baselines)
                    .all(|(metrics, baseline)| {
                        let sequenced = metrics
                            .sequenced_transactions_total
                            .get()
                            .saturating_sub(*baseline);
                        sequenced >= offered_transactions
                            && pipeline_observed_through_target(metrics, *baseline)
                    })
                {
                    break;
                }
                if validators.iter().any(Validator::is_finished) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok()
        && metrics_of_honest_validators
            .iter()
            .zip(&sequenced_baselines)
            .all(|(metrics, baseline)| {
                metrics
                    .sequenced_transactions_total
                    .get()
                    .saturating_sub(*baseline)
                    == offered_transactions
            })
        && metrics_of_honest_validators
            .iter()
            .zip(&sequenced_baselines)
            .all(|(metrics, baseline)| pipeline_observed_through_target(metrics, *baseline));
    let drain_elapsed = drain_started.elapsed();
    for metrics in &metrics_of_all_validators {
        metrics
            .transaction_metrics_active
            .store(false, Ordering::Release);
    }
    let eventual_committed_transactions = metrics_of_honest_validators
        .iter()
        .zip(&sequenced_baselines)
        .map(|(metrics, baseline)| {
            metrics
                .sequenced_transactions_total
                .get()
                .saturating_sub(*baseline)
        })
        .sum::<u64>()
        / metrics_of_honest_validators.len() as u64;
    let transaction_outcome = LocalBenchmarkTransactionOutcome {
        offered_transactions,
        cutoff_committed_transactions,
        eventual_committed_transactions,
        drain_elapsed,
        drain_complete,
    };

    running.store(false, Ordering::SeqCst);
    println!();
    if completed_full_duration {
        println!("Benchmark completed after {duration_secs} seconds");
    } else {
        println!("A validator completed before timeout");
    }
    Metrics::aggregate_and_display(
        metrics_of_honest_validators,
        reporters_of_honest_validators,
        duration_secs,
        committee_size,
        starfish_rbc_dag_shadow_expected,
        starfish_rbc_dag_autonomous_clock_expected,
        starfish_rbc_dag_embedded_rbc_authority_expected,
        autonomous_clock_baselines,
        autonomous_clock_cutoffs,
        Some(counter_baselines),
        Some(counter_cutoffs),
        Some(transaction_outcome),
    );
    stop_local_benchmark_validators(validators).await;
    fs::remove_dir_all(base_dir)?;
    eyre::ensure!(
        completed_full_duration,
        "A validator completed before the requested benchmark duration"
    );
    eyre::ensure!(
        generators_finished,
        "A transaction generator failed to finish the common active window"
    );
    eyre::ensure!(
        drain_complete,
        "Active-window transaction drain was incomplete: offered={offered_transactions}, eventual average committed={eventual_committed_transactions}"
    );
    Ok(())
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
    block_authentication: Option<String>,
    starfish_rbc_dag_shadow: bool,
    starfish_rbc_dag_autonomous_clock: bool,
    starfish_rbc_dag_embedded_rbc_authority: bool,
) -> Result<()> {
    tracing::info!("Starting node {authority}");

    let committee = Committee::load(&committee_path)
        .wrap_err(format!("Failed to load committee file '{committee_path}'"))?;
    let mut public_config = NodePublicConfig::load(&public_config_path).wrap_err(format!(
        "Failed to load parameters file '{public_config_path}'"
    ))?;
    if block_authentication.is_some() {
        public_config.parameters.block_authentication = block_authentication;
    }
    if starfish_rbc_dag_shadow {
        public_config.parameters.starfish_rbc_dag_shadow = true;
    }
    if starfish_rbc_dag_autonomous_clock {
        public_config.parameters.starfish_rbc_dag_autonomous_clock = true;
    }
    if starfish_rbc_dag_embedded_rbc_authority {
        public_config
            .parameters
            .starfish_rbc_dag_embedded_rbc_authority = true;
    }
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
    adversarial_latency_percent: u32,
    consensus_protocol: String,
    block_authentication: Option<String>,
    starfish_rbc_dag_shadow: bool,
    starfish_rbc_dag_autonomous_clock: bool,
    starfish_rbc_dag_embedded_rbc_authority: bool,
    data_dir: Option<PathBuf>,
    base_ip: Option<IpAddr>,
    storage_backend: Option<String>,
    transaction_mode: Option<String>,
    dissemination_mode: Option<String>,
    compress_network: bool,
    bls_workers: Option<usize>,
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
    node_parameters.adversarial_latency_percent = adversarial_latency_percent;
    node_parameters.compress_network = compress_network;
    node_parameters.block_authentication = block_authentication;
    node_parameters.starfish_rbc_dag_shadow = starfish_rbc_dag_shadow;
    node_parameters.starfish_rbc_dag_autonomous_clock = starfish_rbc_dag_autonomous_clock;
    node_parameters.starfish_rbc_dag_embedded_rbc_authority =
        starfish_rbc_dag_embedded_rbc_authority;
    ensure_starfish_rbc_protocol_instance(&consensus_protocol, &mut node_parameters);
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
    )
    .await?;
    let (network_result, _metrics_result) = validator.await_completion().await;
    network_result.expect("Validator crashed");

    Ok(())
}

fn ensure_starfish_rbc_protocol_instance(
    consensus_protocol: &str,
    node_parameters: &mut NodeParameters,
) {
    if is_starfish_rbc_selection(consensus_protocol)
        && node_parameters.starfish_rbc_protocol_instance.is_none()
    {
        node_parameters.refresh_starfish_rbc_protocol_instance();
    }
}

fn is_starfish_rbc_selection(consensus_protocol: &str) -> bool {
    matches!(
        consensus_protocol,
        "starfish-rbc" | "starfish-rbc-single-dag"
    )
}

fn validate_local_benchmark_port_offset(
    public_config: &NodePublicConfig,
    port_offset: u16,
) -> Result<()> {
    eyre::ensure!(
        public_config.all_network_addresses().all(|address| {
            address
                .port()
                .checked_add(port_offset)
                .is_some_and(|port| port <= LOCAL_BENCHMARK_MAX_ACTIVE_BIND_PORT / 10)
        }),
        "local benchmark port offset {port_offset} places a derived active-bind port in the OS ephemeral range; choose a smaller offset"
    );
    Ok(())
}

fn preflight_local_benchmark_ports(public_config: &NodePublicConfig) -> Result<()> {
    let mut addresses = BTreeSet::new();
    for address in public_config.all_network_addresses() {
        addresses.insert(address);
        let mut active = address;
        active.set_port(
            address
                .port()
                .checked_mul(10)
                .expect("validated local benchmark active port"),
        );
        addresses.insert(active);
    }
    addresses.extend(public_config.all_metric_addresses());

    // The network listeners enable SO_REUSEPORT. A plain bind probe can
    // therefore succeed even while a stale benchmark is still serving the
    // same address. Probe for an existing listener first, then reserve every
    // address for the duration of this check.
    for address in &addresses {
        eyre::ensure!(
            TcpStream::connect_timeout(address, Duration::from_millis(25)).is_err(),
            "local benchmark port {address} is already served by another process"
        );
    }

    let mut reservations = Vec::with_capacity(addresses.len());
    for address in addresses {
        reservations.push(
            TcpListener::bind(address)
                .wrap_err_with(|| format!("local benchmark port {address} is already in use"))?,
        );
    }
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
    use std::{
        net::{IpAddr, Ipv4Addr, TcpListener},
        path::PathBuf,
    };

    use clap::Parser;

    use super::{
        Args, Operation, ensure_starfish_rbc_protocol_instance, ipv4_add_offset,
        local_benchmark_generator_loads, local_benchmark_private_configs,
        local_benchmark_topology_state, preflight_local_benchmark_ports,
        validate_local_benchmark_port_offset,
    };
    use starfish_core::{
        config::{NodeParameters, NodePrivateConfig, NodePublicConfig},
        types::AuthorityIndex,
    };

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

    #[test]
    fn local_benchmark_disables_byzantine_generators_and_preserves_aggregate_load() {
        let (byzantine, loads) = local_benchmark_generator_loads(10, 1_003, 2).unwrap();

        assert_eq!(byzantine.into_iter().collect::<Vec<_>>(), vec![0, 3]);
        assert_eq!(loads[0], 0);
        assert_eq!(loads[3], 0);
        assert_eq!(loads.iter().sum::<usize>(), 1_003);
        assert_eq!(loads, vec![0, 126, 126, 0, 126, 125, 125, 125, 125, 125]);
    }

    #[test]
    fn local_benchmark_rejects_unplaceable_byzantine_count() {
        assert!(local_benchmark_generator_loads(4, 100, 3).is_err());
    }

    #[test]
    fn dry_run_parses_block_authentication_separately_from_consensus() {
        let args = Args::try_parse_from([
            "starfish",
            "dry-run",
            "--authority",
            "0",
            "--committee-size",
            "4",
            "--consensus",
            "mysticeti",
            "--block-authentication",
            "ml-dsa-65",
        ])
        .unwrap();

        let Operation::DryRun {
            consensus,
            block_authentication,
            ..
        } = args.operation
        else {
            panic!("expected dry-run operation");
        };
        assert_eq!(consensus, "mysticeti");
        assert_eq!(block_authentication.as_deref(), Some("ml-dsa-65"));
    }

    #[test]
    fn local_benchmark_parses_starfish_rbc_mac_authentication() {
        let args = Args::try_parse_from([
            "starfish",
            "local-benchmark",
            "--committee-size",
            "4",
            "--consensus",
            "starfish-rbc",
            "--block-authentication",
            "mac",
            "--starfish-rbc-dag-shadow",
            "--starfish-rbc-dag-autonomous-clock",
            "--starfish-rbc-dag-embedded-rbc-authority",
            "--starfish-rbc-single-dag-echo-qc-fast-path",
            "--starfish-rbc-dag-shadow-buffered-wal",
            "--port-offset",
            "2500",
        ])
        .unwrap();

        let Operation::LocalBenchmark {
            consensus,
            block_authentication,
            starfish_rbc_dag_shadow,
            starfish_rbc_dag_autonomous_clock,
            starfish_rbc_dag_embedded_rbc_authority,
            starfish_rbc_single_dag_echo_qc_fast_path,
            starfish_rbc_dag_shadow_buffered_wal,
            port_offset,
            ..
        } = args.operation
        else {
            panic!("expected local-benchmark operation");
        };
        assert_eq!(consensus, "starfish-rbc");
        assert_eq!(block_authentication.as_deref(), Some("mac"));
        assert!(starfish_rbc_dag_shadow);
        assert!(starfish_rbc_dag_autonomous_clock);
        assert!(starfish_rbc_dag_embedded_rbc_authority);
        assert!(starfish_rbc_single_dag_echo_qc_fast_path);
        assert!(starfish_rbc_dag_shadow_buffered_wal);
        assert_eq!(port_offset, 2500);
    }

    #[test]
    fn dry_run_starfish_rbc_configuration_gets_a_protocol_instance() {
        let mut parameters = NodeParameters {
            starfish_rbc_dag_shadow: true,
            starfish_rbc_dag_autonomous_clock: true,
            ..NodeParameters::default()
        };

        ensure_starfish_rbc_protocol_instance("starfish-rbc", &mut parameters);

        assert!(
            parameters
                .starfish_rbc_protocol_instance
                .is_some_and(|instance| instance != [0; 32])
        );
        assert!(parameters.starfish_rbc_dag_shadow);
        assert!(parameters.starfish_rbc_dag_autonomous_clock);
    }

    #[test]
    fn local_benchmark_port_offset_stays_below_ephemeral_active_ports() {
        let safe =
            NodePublicConfig::new_for_benchmarks(vec![IpAddr::V4(Ipv4Addr::LOCALHOST); 10], None);
        validate_local_benchmark_port_offset(&safe, 200).unwrap();

        let ephemeral =
            NodePublicConfig::new_for_benchmarks(vec![IpAddr::V4(Ipv4Addr::LOCALHOST); 10], None);
        assert!(validate_local_benchmark_port_offset(&ephemeral, 3_500).is_err());
        assert!(validate_local_benchmark_port_offset(&ephemeral, u16::MAX).is_err());
    }

    #[test]
    fn local_benchmark_private_configs_preserve_per_authority_storage_layout() {
        let base_dir = PathBuf::from("local-benchmark-config-test");
        let committee_size = 4;
        let private_configs = local_benchmark_private_configs(&base_dir, committee_size);

        assert_eq!(private_configs.len(), committee_size);
        for (authority, private_config) in private_configs.into_iter().enumerate() {
            assert_eq!(private_config.mac_keys.len(), committee_size);
            assert_eq!(
                private_config.storage_path,
                base_dir.join(format!("node-{authority}")).join(
                    NodePrivateConfig::default_storage_path(authority as AuthorityIndex)
                )
            );
        }
    }

    #[test]
    fn local_benchmark_preflight_rejects_an_existing_listener() {
        let public_config =
            NodePublicConfig::new_for_benchmarks(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], None)
                .with_port_offset(1_400);
        let address = public_config.network_address(0).unwrap();
        let _listener = match TcpListener::bind(address) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind preflight test listener: {error}"),
        };

        assert!(preflight_local_benchmark_ports(&public_config).is_err());
    }

    #[test]
    fn local_benchmark_topology_readiness_fails_closed_before_baselining() {
        assert!(!local_benchmark_topology_state([(false, 2, 3)], 3).unwrap());
        assert!(local_benchmark_topology_state([(false, 3, 3)], 3).unwrap());
        assert!(local_benchmark_topology_state([(true, 3, 3)], 3).is_err());
    }
}
