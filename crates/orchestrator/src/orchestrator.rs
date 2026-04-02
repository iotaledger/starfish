// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    io::Read,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::time::{self, Instant};

use crate::{
    benchmark::{
        BenchmarkParameters, LatencyThroughputSweepPlan, LatencyThroughputSweepReport,
        StabilityOutage, StabilityReport, StabilitySample,
    },
    client::{Instance, InstanceStatus},
    display, ensure,
    error::{SshError, TestbedError, TestbedResult},
    faults::{CrashRecoverySchedule, FaultsType},
    logs::LogsAnalyzer,
    measurements::{Measurement, MeasurementsCollection},
    monitor::Monitor,
    protocol::{ProtocolCommands, ProtocolMetrics},
    settings::Settings,
    ssh::{CommandContext, CommandStatus, SshConnectionManager},
};

#[derive(Clone, Default)]
struct StabilityCounterSample {
    timestamp_secs: f64,
    transaction_committed_count: Option<f64>,
    sequenced_transactions_count: Option<f64>,
    block_committed_count: Option<f64>,
    cpu_seconds: Option<f64>,
    bytes_sent: Option<f64>,
    bytes_received: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OneShotOutagePhase {
    Pending,
    Down,
    Completed,
}

struct OneShotOutageState {
    config: StabilityOutage,
    targets: Vec<Instance>,
    phase: OneShotOutagePhase,
    killed_by_outage: HashSet<String>,
}

impl OneShotOutageState {
    fn new(config: StabilityOutage, targets: Vec<Instance>) -> Self {
        Self {
            config,
            targets,
            phase: OneShotOutagePhase::Pending,
            killed_by_outage: HashSet::new(),
        }
    }

    fn next_deadline(&self, run_start: Instant) -> Option<Instant> {
        match self.phase {
            OneShotOutagePhase::Pending => {
                Some(run_start + Duration::from_secs(self.config.start_secs))
            }
            OneShotOutagePhase::Down if self.config.keep_down => None,
            OneShotOutagePhase::Down => Some(
                run_start
                    + Duration::from_secs(
                        self.config
                            .start_secs
                            .saturating_add(self.config.duration_secs),
                    ),
            ),
            OneShotOutagePhase::Completed => None,
        }
    }

    fn is_active(&self) -> bool {
        matches!(self.phase, OneShotOutagePhase::Down)
    }
}

/// An orchestrator to deploy nodes and run benchmarks on a testbed.
pub struct Orchestrator<P> {
    /// The testbed's settings.
    settings: Settings,
    /// The state of the testbed (reflecting accurately the state of the
    /// machines).
    instances: Vec<Instance>,
    /// Provider-specific commands to install on the instance.
    instance_setup_commands: Vec<String>,
    /// Protocol-specific commands generator to generate the protocol
    /// configuration files, boot clients and nodes, etc.
    protocol_commands: P,
    /// Handle ssh connections to instances.
    ssh_manager: SshConnectionManager,
    /// Directory where this benchmark suite writes its results.
    suite_results_dir: PathBuf,
    /// Skip the testbed update. Setting this value to true is dangerous and may
    /// lead to unexpected behavior.
    skip_testbed_update: bool,
    /// Skip the testbed configuration. Setting this value to true is dangerous
    /// and may lead to unexpected behavior.
    skip_testbed_configuration: bool,
}

impl<P> Orchestrator<P> {
    /// Make a new orchestrator.
    pub fn new(
        settings: Settings,
        instances: Vec<Instance>,
        instance_setup_commands: Vec<String>,
        protocol_commands: P,
        ssh_manager: SshConnectionManager,
        suite_results_dir: PathBuf,
    ) -> Self {
        Self {
            settings,
            instances,
            instance_setup_commands,
            protocol_commands,
            ssh_manager,
            suite_results_dir,
            skip_testbed_update: false,
            skip_testbed_configuration: false,
        }
    }

    pub fn suite_results_dir(settings: &Settings, suite_kind: &str) -> PathBuf {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let commit = &settings.repository.commit;
        settings
            .results_dir
            .join(format!("results-{commit}"))
            .join(format!("{suite_kind}-{timestamp_ms}"))
    }

    /// Skip the testbed update.
    pub fn skip_testbed_update(mut self, skip_testbed_update: bool) -> Self {
        if skip_testbed_update {
            display::warn("Skipping testbed update! Use with care!");
            self.settings.repository.set_unknown_commit();
        }
        self.skip_testbed_update = skip_testbed_update;
        self
    }

    /// Skip the testbed configuration.
    pub fn skip_testbed_configuration(mut self, skip_testbed_configuration: bool) -> Self {
        if skip_testbed_configuration {
            display::warn("Skipping testbed configuration! Use with care!");
        }
        self.skip_testbed_configuration = skip_testbed_configuration;
        self
    }

    async fn prebuilt_binary_updated_at(source: &str) -> Option<String> {
        if source.starts_with("http://") || source.starts_with("https://") {
            let client = reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(8))
                .build()
                .ok()?;
            let response = client.head(source).send().await.ok()?;
            let header = response
                .headers()
                .get(reqwest::header::LAST_MODIFIED)?
                .to_str()
                .ok()?;
            return Some(header.to_string());
        }

        let modified = fs::metadata(source).ok()?.modified().ok()?;
        let modified: DateTime<Utc> = modified.into();
        Some(modified.format("%Y-%m-%d %H:%M:%S UTC").to_string())
    }

    /// Returns the node and monitoring instances for the benchmark.
    pub fn select_instances(
        &self,
        parameters: &BenchmarkParameters,
    ) -> TestbedResult<(Vec<Instance>, Option<Instance>)> {
        // Ensure there are enough active instances.
        let mut available_instances: Vec<_> =
            self.instances.iter().filter(|x| x.is_active()).collect();
        available_instances.sort_by(|a, b| a.region.cmp(&b.region).then(a.id.cmp(&b.id)));
        // An external monitoring server does not consume a cloud instance.
        let needs_cloud_monitoring =
            self.settings.monitoring && !self.settings.is_external_monitoring();
        let minimum_instances = parameters.nodes + if needs_cloud_monitoring { 1 } else { 0 };
        ensure!(
            available_instances.len() >= minimum_instances,
            TestbedError::InsufficientCapacity(minimum_instances - available_instances.len())
        );

        // Sort the instances by region. This step ensures that the instances are
        // selected as equally as possible from all regions.
        let mut instances_by_regions = HashMap::new();
        for instance in available_instances {
            instances_by_regions
                .entry(&instance.region)
                .or_insert_with(VecDeque::new)
                .push_back(instance);
        }

        // Select the instance to host the monitoring stack.
        let monitoring_instance =
            if let Some(instance) = self.settings.external_monitoring_instance()? {
                Some(instance)
            } else if self.settings.monitoring {
                let region = &self.settings.regions[0];
                instances_by_regions
                    .get_mut(region)
                    .map(|instances| instances.pop_front().unwrap().clone())
            } else {
                None
            };

        // Select the instances to host the nodes.
        let mut nodes_instances = Vec::new();
        for region in self.settings.regions.iter().cycle() {
            if nodes_instances.len() == parameters.nodes {
                break;
            }
            if let Some(regional_instances) = instances_by_regions.get_mut(region) {
                if let Some(instance) = regional_instances.pop_front() {
                    nodes_instances.push(instance.clone());
                }
            }
        }

        Ok((nodes_instances, monitoring_instance))
    }
}

impl<P: ProtocolCommands + ProtocolMetrics> Orchestrator<P> {
    const NODE_BOOT_POLL_INTERVAL: Duration = Duration::from_secs(5);
    const NODE_BOOT_TIMEOUT: Duration = Duration::from_secs(60);
    const MAX_NODE_BOOT_LOG_SAMPLES: usize = 3;
    /// Maximum fraction of validators that may fail readiness and still allow
    /// the benchmark to proceed. The stalled instances are marked inactive.
    const MAX_TOLERATED_BOOT_FAILURE_RATIO: f64 = 0.10;

    fn mark_instances_inactive(&mut self, instances: &[Instance]) {
        for failed in instances {
            if let Some(instance) = self
                .instances
                .iter_mut()
                .find(|instance| instance.id == failed.id)
            {
                instance.status = InstanceStatus::Inactive;
            }
        }
    }

    async fn execute_per_instance_best_effort<S>(
        &mut self,
        instances: Vec<(Instance, S)>,
        context: CommandContext,
        stage: &str,
    ) -> Vec<(Instance, (String, String))>
    where
        S: Into<String> + Send + 'static + Clone,
    {
        let handles = self
            .ssh_manager
            .run_per_instance(instances.clone(), context);
        let mut successes = Vec::new();
        let mut lost_instances = Vec::new();

        let mut pending: FuturesUnordered<_> = instances
            .into_iter()
            .zip(handles)
            .map(|((instance, _), handle)| async move { (instance, handle.await) })
            .collect();

        while let Some((instance, join_result)) = pending.next().await {
            match join_result {
                Ok(Ok(output)) => successes.push((instance, output)),
                Ok(Err(error)) => {
                    display::error(format!("{stage} failed on {}: {error}", instance.main_ip));
                    if matches!(
                        error,
                        SshError::ConnectionError { .. } | SshError::SessionError { .. }
                    ) {
                        lost_instances.push(instance);
                    }
                }
                Err(error) => {
                    display::error(format!(
                        "{stage} join failed on {}: {error}",
                        instance.main_ip
                    ));
                }
            }
        }

        if !lost_instances.is_empty() {
            self.mark_instances_inactive(&lost_instances);
        }

        successes
    }

    async fn probe_instances_best_effort<S>(
        &mut self,
        instances: Vec<(Instance, S)>,
        context: CommandContext,
    ) -> Vec<Instance>
    where
        S: Into<String> + Send + 'static + Clone,
    {
        let handles = self
            .ssh_manager
            .run_per_instance(instances.clone(), context);
        let mut successes = Vec::new();
        let mut lost_instances = Vec::new();

        let mut pending: FuturesUnordered<_> = instances
            .into_iter()
            .zip(handles)
            .map(|((instance, _), handle)| async move { (instance, handle.await) })
            .collect();

        while let Some((instance, join_result)) = pending.next().await {
            match join_result {
                Ok(Ok(_)) => successes.push(instance),
                Ok(Err(error)) => {
                    if matches!(
                        error,
                        SshError::ConnectionError { .. } | SshError::SessionError { .. }
                    ) {
                        lost_instances.push(instance);
                    }
                }
                Err(_) => {}
            }
        }

        if !lost_instances.is_empty() {
            self.mark_instances_inactive(&lost_instances);
        }

        successes
    }

    fn node_boot_timeout(_node_count: usize) -> Duration {
        Self::NODE_BOOT_TIMEOUT
    }

    fn clamp_faults_to_available_nodes(faults: FaultsType, available_nodes: usize) -> FaultsType {
        match faults {
            FaultsType::Permanent { faults } => FaultsType::Permanent {
                faults: faults.min(available_nodes),
            },
            FaultsType::CrashRecovery {
                max_faults,
                interval,
            } => FaultsType::CrashRecovery {
                max_faults: max_faults.min(available_nodes),
                interval,
            },
        }
    }

    fn startup_permanent_faults(faults: FaultsType, nodes: &[Instance]) -> Vec<Instance> {
        match Self::clamp_faults_to_available_nodes(faults, nodes.len()) {
            FaultsType::Permanent { faults } if faults > 0 => {
                CrashRecoverySchedule::new(FaultsType::Permanent { faults }, nodes.to_vec())
                    .update()
                    .kill
            }
            _ => Vec::new(),
        }
    }

    fn runtime_faults_type(faults: FaultsType, available_nodes: usize) -> FaultsType {
        match Self::clamp_faults_to_available_nodes(faults, available_nodes) {
            FaultsType::Permanent { .. } => FaultsType::default(),
            faults => faults,
        }
    }

    fn max_tolerated_boot_failures(node_count: usize) -> usize {
        (node_count as f64 * Self::MAX_TOLERATED_BOOT_FAILURE_RATIO).floor() as usize
    }

    fn apt_get_noninteractive(args: &str) -> String {
        format!("sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get {args}")
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

    fn stability_counter_sample(
        measurements: &HashMap<String, Measurement>,
    ) -> StabilityCounterSample {
        let timestamp_secs = measurements
            .values()
            .next()
            .map(|measurement| measurement.timestamp().as_secs_f64())
            .unwrap_or_default();

        StabilityCounterSample {
            timestamp_secs,
            transaction_committed_count: measurements
                .get("transaction_committed_latency")
                .map(|measurement| measurement.count_value() as f64),
            sequenced_transactions_count: measurements
                .get("sequenced_transactions_total")
                .map(|measurement| measurement.count_value() as f64),
            block_committed_count: measurements
                .get("block_committed_latency")
                .map(|measurement| measurement.count_value() as f64),
            cpu_seconds: measurements
                .get("process_cpu_seconds_total")
                .map(Measurement::scalar_value),
            bytes_sent: measurements
                .get("bytes_sent_total")
                .map(Measurement::scalar_value),
            bytes_received: measurements
                .get("bytes_received_total")
                .map(Measurement::scalar_value),
        }
    }

    fn non_negative_delta(current: Option<f64>, previous: Option<f64>) -> Option<f64> {
        match (current, previous) {
            (Some(current), Some(previous)) if current >= previous => Some(current - previous),
            _ => None,
        }
    }

    fn scalar_metric(measurements: &HashMap<String, Measurement>, label: &str) -> Option<f64> {
        measurements.get(label).map(Measurement::scalar_value)
    }

    fn latency_bucket_ms(
        measurements: &HashMap<String, Measurement>,
        label: &str,
        bucket: &str,
    ) -> Option<f64> {
        measurements
            .get(label)
            .and_then(|measurement| measurement.bucket_ms(bucket))
    }

    async fn sample_node_startup_logs(&mut self, instances: &[Instance]) -> String {
        let samples: Vec<_> = instances
            .iter()
            .take(Self::MAX_NODE_BOOT_LOG_SAMPLES)
            .cloned()
            .collect();
        if samples.is_empty() {
            return String::new();
        }

        let commands = samples
            .clone()
            .into_iter()
            .map(|instance| {
                (
                    instance,
                    "tail -n 40 ~/node.log 2>/dev/null || echo '(node.log unavailable)'",
                )
            })
            .collect();
        let outputs = self
            .execute_per_instance_best_effort(
                commands,
                CommandContext::default(),
                "Startup log fetch",
            )
            .await;
        if outputs.is_empty() {
            return "No startup log samples available.".into();
        }

        outputs
            .into_iter()
            .map(|(instance, (stdout, stderr))| {
                let snippet = if stdout.trim().is_empty() {
                    stderr.trim()
                } else {
                    stdout.trim()
                };
                format!("{}:\n{}", instance.main_ip, snippet)
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    async fn wait_for_nodes_ready(
        &mut self,
        instances: Vec<Instance>,
        skipped_node_ids: &HashSet<String>,
        parameters: &BenchmarkParameters,
    ) -> TestbedResult<Vec<Instance>> {
        let total = instances.len().saturating_sub(skipped_node_ids.len());
        if total == 0 {
            return Ok(Vec::new());
        }

        let timeout = Self::node_boot_timeout(total);
        let max_failures = Self::max_tolerated_boot_failures(total);
        let start = Instant::now();
        display::status(format!("ready 0/{total}"));

        let mut pending: HashMap<_, _> = self
            .protocol_commands
            .nodes_readiness_command(instances, parameters)
            .into_iter()
            .filter(|(instance, _)| !skipped_node_ids.contains(&instance.id))
            .map(|(instance, command)| (instance.id.clone(), (instance, command)))
            .collect();

        while start.elapsed() < timeout {
            let probes: Vec<_> = pending
                .values()
                .map(|(instance, command)| (instance.clone(), command.clone()))
                .collect();
            let ready = self
                .probe_instances_best_effort(probes, CommandContext::default())
                .await;
            for instance in ready {
                pending.remove(&instance.id);
            }

            let completed = total - pending.len();
            display::status(format!(
                "ready {completed}/{total} {}s",
                start.elapsed().as_secs()
            ));

            if pending.is_empty() {
                return Ok(Vec::new());
            }
            if pending.len() <= max_failures {
                let stalled: Vec<_> = pending
                    .values()
                    .map(|(instance, _)| instance.clone())
                    .collect();
                display::warn(format!(
                    "{} of {} validators did not expose metrics during readiness checks \
                     but are within the tolerated failure budget — marking inactive, \
                     keeping the original committee, and treating them as crashed from \
                     startup",
                    stalled.len(),
                    total,
                ));
                self.mark_instances_inactive(&stalled);
                return Ok(stalled);
            }

            time::sleep(Self::NODE_BOOT_POLL_INTERVAL).await;
        }

        let stalled: Vec<_> = pending
            .into_values()
            .map(|(instance, _)| instance)
            .collect();

        if stalled.len() <= max_failures {
            display::warn(format!(
                "{} of {} validators did not start in time — marking inactive, \
                 keeping the original committee, and treating them as crashed from startup",
                stalled.len(),
                total,
            ));
            self.mark_instances_inactive(&stalled);
            return Ok(stalled);
        }

        let sample_logs = self.sample_node_startup_logs(&stalled).await;
        Err(TestbedError::NodeBootError(format!(
            "{} of {} validators did not expose metrics within {}s.\n\
             Startup log samples:\n{}",
            stalled.len(),
            total,
            timeout.as_secs(),
            sample_logs
        )))
    }

    fn log_download_ssh_manager(&self) -> SshConnectionManager {
        self.ssh_manager.clone().with_retries(0)
    }

    async fn download_compressed_log(
        &self,
        ssh_manager: &SshConnectionManager,
        instance: &Instance,
        remote_log_path: &str,
    ) -> TestbedResult<Vec<u8>> {
        let connection = ssh_manager.connect(instance.ssh_address()).await?;
        let remote_archive_path = format!(
            "/tmp/orchestrator-{}-{}.gz",
            instance.id,
            remote_log_path.replace('/', "-")
        );

        connection.execute(format!(
            "rm -f {remote_archive_path} && gzip -c {remote_log_path} > {remote_archive_path}"
        ))?;
        let compressed_log = connection.download_bytes(&remote_archive_path)?;
        let _ = connection.execute(format!("rm -f {remote_archive_path}"));

        Ok(compressed_log)
    }

    fn decompress_log(&self, compressed_log: &[u8], log_label: &str) -> TestbedResult<String> {
        let mut decoder = GzDecoder::new(compressed_log);
        let mut log_content = String::new();
        decoder.read_to_string(&mut log_content).map_err(|error| {
            TestbedError::LogProcessingError(format!("failed to decompress {log_label}: {error}"))
        })?;
        Ok(log_content)
    }

    /// Install the codebase and its dependencies on the testbed.
    pub async fn install(&self) -> TestbedResult<()> {
        display::action("Installing dependencies on all machines");

        let working_dir = self.settings.working_dir.display();
        let url = &self.settings.repository.url;
        let repo_name = self.settings.repository_name();

        let basic_commands: Vec<String> = if self.settings.pre_built_binary.is_some() {
            // Pre-built binary mode: minimal runtime dependencies only.
            // Directory at $HOME/{repo_name} to match protocol commands (cd {repo_name}).
            vec![
                Self::apt_get_noninteractive("update"),
                Self::apt_get_noninteractive("-y remove needrestart"),
                Self::apt_get_noninteractive("-y upgrade"),
                Self::apt_get_noninteractive("-y autoremove"),
                Self::apt_get_noninteractive("-y install sysstat libssl3 ca-certificates curl"),
                format!("mkdir -p $HOME/{repo_name}/target/release"),
                // Create empty cargo env so `source $HOME/.cargo/env` in protocol
                // commands is a harmless no-op.
                "mkdir -p $HOME/.cargo && touch $HOME/.cargo/env".into(),
            ]
        } else {
            // Build from source: full toolchain and dependencies.
            vec![
                Self::apt_get_noninteractive("update"),
                Self::apt_get_noninteractive("-y remove needrestart"),
                Self::apt_get_noninteractive("-y upgrade"),
                Self::apt_get_noninteractive("-y autoremove"),
                Self::apt_get_noninteractive(
                    "-y install build-essential sysstat libssl-dev clang libclang-dev \
                    libclang1 llvm",
                ),
                Self::apt_get_noninteractive(
                    "-y install linux-tools-common linux-tools-generic pkg-config",
                ),
                "curl --proto \"=https\" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y".into(),
                "echo \"source $HOME/.cargo/env\" | tee -a ~/.bashrc".into(),
                "source $HOME/.cargo/env".into(),
                "rustup default stable".into(),
                "rustup toolchain install 1.78".into(),
                format!("mkdir -p {working_dir}"),
                format!("(git clone {url} || true)"),
            ]
        };

        let command = [
            &basic_commands
                .iter()
                .map(|x| x.as_str())
                .collect::<Vec<_>>()[..],
            &Monitor::dependencies()
                .iter()
                .map(|x| x.as_str())
                .collect::<Vec<_>>()[..],
            &self
                .instance_setup_commands
                .iter()
                .map(|x| x.as_str())
                .collect::<Vec<_>>()[..],
            &self.protocol_commands.protocol_dependencies()[..],
        ]
        .concat()
        .join(" && ");

        let active = self.instances.iter().filter(|x| x.is_active()).cloned();
        let context = CommandContext::default();
        self.ssh_manager.execute(active, command, context).await?;

        display::done();
        Ok(())
    }

    /// Update all instances to use the version of the codebase specified in the
    /// setting file.
    pub async fn update(&self) -> TestbedResult<()> {
        display::action("Updating all instances");

        let active: Vec<_> = self
            .instances
            .iter()
            .filter(|x| x.is_active())
            .cloned()
            .collect();
        let repo_name = self.settings.repository_name();

        match &self.settings.pre_built_binary {
            Some(source) if source.starts_with("http://") || source.starts_with("https://") => {
                // Download pre-built binary from URL on each remote machine.
                let command = format!(
                    "curl -fSL -o target/release/starfish \
                    '{source}' && \
                    chmod +x target/release/starfish"
                );
                let id = "update";
                let context = CommandContext::new()
                    .run_background(id.into())
                    .with_execute_from_path(repo_name.into());
                self.ssh_manager
                    .execute(active.clone().into_iter(), command, context)
                    .await?;
                self.ssh_manager
                    .wait_for_command(active.into_iter(), id, CommandStatus::Terminated)
                    .await?;
            }
            Some(source) => {
                // SCP local binary to all remote machines.
                let local_path = PathBuf::from(source);
                let remote_path: PathBuf = format!("{repo_name}/target/release/starfish").into();
                self.ssh_manager
                    .upload_to_all(active.into_iter(), &local_path, &remote_path)
                    .await?;
            }
            None => {
                // Build from source (current behavior).
                let commit = &self.settings.repository.commit;
                let command = [
                    "git fetch origin",
                    &format!("git checkout -B {commit} origin/{commit}"),
                    "source $HOME/.cargo/env",
                    "RUSTFLAGS=-Ctarget-cpu=native \
                    cargo build --release --all-features --workspace \
                    --exclude orchestrator",
                ]
                .join(" && ");

                let id = "update";
                let context = CommandContext::new()
                    .run_background(id.into())
                    .with_execute_from_path(repo_name.into());
                self.ssh_manager
                    .execute(active.clone().into_iter(), command, context)
                    .await?;
                self.ssh_manager
                    .wait_for_command(active.into_iter(), id, CommandStatus::Terminated)
                    .await?;
            }
        }

        display::done();
        Ok(())
    }

    /// Configure the instances with the appropriate configuration files.
    async fn configure_nodes(
        &self,
        nodes: Vec<Instance>,
        parameters: &BenchmarkParameters,
    ) -> TestbedResult<()> {
        display::action(format!("Configuring {} nodes", nodes.len()));

        let command = self
            .protocol_commands
            .genesis_command(nodes.iter(), parameters)
            .await;

        let id = "configure";
        let repo_name = self.settings.repository_name();
        let context = CommandContext::new()
            .run_background(id.into())
            .with_log_file(format!("~/{id}.log").into())
            .with_execute_from_path(repo_name.into());

        self.ssh_manager
            .execute(nodes.clone(), command, context)
            .await?;
        self.ssh_manager
            .wait_for_command(nodes, id, CommandStatus::Terminated)
            .await?;

        display::done();
        Ok(())
    }

    /// Cleanup all instances and optionally delete their log files.
    pub async fn cleanup(
        &mut self,
        delete_logs: bool,
        _parameters: Option<&BenchmarkParameters>,
    ) -> TestbedResult<()> {
        display::action("Cleaning up testbed");

        // Kill all tmux servers and delete the nodes dbs. Optionally clear logs.
        let mut command = vec!["(tmux kill-server || true)".into()];
        for path in self.protocol_commands.db_directories() {
            command.push(format!("(rm -rf {} || true)", path.display()));
        }
        if delete_logs {
            command.push("(rm -rf ~/*log* || true)".into());
        }
        let command = command.join(" ; ");

        // Execute the deletion on all machines.
        let active: Vec<_> = self
            .instances
            .iter()
            .filter(|x| x.is_active())
            .cloned()
            .map(|instance| (instance, command.clone()))
            .collect();
        let cleaned = self
            .execute_per_instance_best_effort(active, CommandContext::default(), "Cleanup")
            .await;
        if cleaned.is_empty() {
            display::warn("Cleanup could not reach any active instance; continuing");
        }

        display::done();
        Ok(())
    }

    /// Return the SSH manager for the monitoring server. Uses a custom
    /// username when the external `monitoring_server` specifies one
    /// (e.g. `root@host`), otherwise falls back to the default manager.
    fn monitoring_ssh_manager(&self) -> SshConnectionManager {
        if let Some(user) = self.settings.monitoring_ssh_user() {
            SshConnectionManager::new(user.into(), self.settings.ssh_private_key_file.clone())
                .with_timeout(self.settings.ssh_timeout)
                .with_retries(self.settings.ssh_retries)
        } else {
            self.ssh_manager.clone()
        }
    }

    /// Reload prometheus and grafana.
    async fn start_monitoring_nodes(
        &self,
        nodes: Vec<Instance>,
        instance: Option<Instance>,
        parameters: &BenchmarkParameters,
    ) -> TestbedResult<()> {
        if let Some(instance) = instance {
            display::action("Configuring monitoring instance");

            let ssh_manager = self.monitoring_ssh_manager();
            let monitor = Monitor::new(
                instance,
                nodes,
                ssh_manager,
                self.settings.monitoring_working_dir(),
                self.settings.monitoring_scrape_over_public_ip(),
            );
            let commands = &self.protocol_commands;
            monitor.start_prometheus(commands, parameters).await?;
            monitor.start_grafana().await?;

            display::done();
            display::config("Grafana address", monitor.grafana_address());
            display::newline();
        }
        Ok(())
    }

    /// Install monitoring dependencies on the external monitoring server.
    async fn install_external_monitoring(&self) -> TestbedResult<()> {
        if let Some(instance) = self.settings.external_monitoring_instance()? {
            // Newline so the message doesn't collide with the concurrent
            // "Installing dependencies on all machines ..." progress line.
            display::newline();
            display::action("Installing monitoring dependencies on external server");

            let ssh_manager = self.monitoring_ssh_manager();
            let command = [
                Monitor::dependencies().join(" && "),
                format!(
                    "mkdir -p {}",
                    self.settings.monitoring_working_dir().display()
                ),
            ]
            .join(" && ");
            let context = CommandContext::default();
            ssh_manager
                .execute(std::iter::once(instance), command, context)
                .await?;

            display::done();
        }
        Ok(())
    }

    /// Boot a node on the specified instances.
    async fn boot_nodes(
        &self,
        instances: Vec<Instance>,
        skipped_node_ids: &HashSet<String>,
        parameters: &BenchmarkParameters,
    ) -> TestbedResult<()> {
        // Run one node per instance.
        let mut targets = self
            .protocol_commands
            .node_command(instances.clone(), parameters);
        targets.retain(|(instance, _)| !skipped_node_ids.contains(&instance.id));
        if targets.is_empty() {
            return Ok(());
        }

        let repo = self.settings.repository_name();
        let context = CommandContext::new()
            .run_background("node".into())
            .with_log_file("~/node.log".into())
            .with_execute_from_path(repo.into());
        self.ssh_manager
            .execute_per_instance(targets, context)
            .await?;

        Ok(())
    }

    /// Stop the validators without deleting logs or storage so post-run
    /// inspection can proceed against a quiescent state.
    async fn stop_nodes(&mut self, instances: &[Instance]) {
        display::action("Stopping validators");

        let command = "(tmux kill-session -t node || true)";
        let targets = instances
            .iter()
            .cloned()
            .map(|instance| (instance, command.to_string()))
            .collect();
        let stopped = self
            .execute_per_instance_best_effort(targets, CommandContext::default(), "Stop")
            .await;
        if stopped.is_empty() {
            display::warn("Stop could not reach any selected validator; continuing");
        }

        display::done();
    }

    /// Deploy the nodes.
    pub async fn run_nodes(
        &mut self,
        nodes: Vec<Instance>,
        parameters: &BenchmarkParameters,
    ) -> TestbedResult<HashSet<String>> {
        display::action("\nDeploying validators");

        let startup_faulted =
            Self::startup_permanent_faults(parameters.settings.faults.clone(), &nodes);
        let startup_faulted_ids: HashSet<_> = startup_faulted
            .iter()
            .map(|instance| instance.id.clone())
            .collect();
        if !startup_faulted.is_empty() {
            display::warn(format!(
                "Leaving {} validators down from startup due to permanent faults",
                startup_faulted.len()
            ));
        }

        self.boot_nodes(nodes.clone(), &startup_faulted_ids, parameters)
            .await?;
        let stalled = self
            .wait_for_nodes_ready(nodes, &startup_faulted_ids, parameters)
            .await?;

        display::done();
        Ok(startup_faulted_ids
            .into_iter()
            .chain(stalled.into_iter().map(|instance| instance.id))
            .collect())
    }

    /// Collect metrics from the nodes.
    pub async fn run(
        &mut self,
        nodes: Vec<Instance>,
        mut killed_node_ids: HashSet<String>,
        parameters: &BenchmarkParameters,
    ) -> TestbedResult<MeasurementsCollection> {
        display::action(format!(
            "Collecting metrics (at least {}s)",
            self.settings.benchmark_duration.as_secs()
        ));

        let node_indices: HashMap<_, _> = nodes
            .iter()
            .enumerate()
            .map(|(i, node)| (node.id.clone(), i))
            .collect();
        let metrics_commands = self
            .protocol_commands
            .nodes_metrics_command(nodes.clone(), parameters);
        let final_metrics_commands = self
            .protocol_commands
            .nodes_final_metrics_command(nodes.clone(), parameters);

        let mut aggregator = MeasurementsCollection::new(parameters.clone());
        aggregator.set_ready_nodes_at_boot(nodes.len().saturating_sub(killed_node_ids.len()));
        let scrape_interval = crate::monitor::Prometheus::scaled_metrics_interval(parameters.nodes);
        let mut metrics_interval = time::interval(scrape_interval);
        metrics_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        metrics_interval.tick().await; // The first tick returns immediately.

        let ready_nodes: Vec<_> = nodes
            .iter()
            .filter(|node| !killed_node_ids.contains(&node.id))
            .cloned()
            .collect();
        let faults_type =
            Self::runtime_faults_type(parameters.settings.faults.clone(), ready_nodes.len());
        let faults_interval_duration = faults_type.crash_interval();
        let mut faults_schedule = CrashRecoverySchedule::new(faults_type, ready_nodes);
        let mut faults_interval = time::interval(faults_interval_duration);
        faults_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        faults_interval.tick().await; // The first tick returns immediately.

        let start = Instant::now();
        loop {
            tokio::select! {
                // Scrape metrics.
                _ = metrics_interval.tick() => {
                    let elapsed = start.elapsed().as_secs_f64().ceil() as u64;
                    display::status(format!("{elapsed}s"));

                    let mut instances = metrics_commands.clone();
                    instances.retain(|(instance, _)| !killed_node_ids.contains(&instance.id));

                    let stdio = self
                        .execute_per_instance_best_effort(
                            instances,
                            CommandContext::default(),
                            "Metrics scrape",
                        )
                        .await;
                    if stdio.is_empty() {
                        display::warn(
                            "All metrics scrapes failed for this \
                             interval; continuing benchmark",
                        );
                    }

                    for (instance, (stdout, _stderr)) in &stdio {
                        let Some(i) = node_indices.get(&instance.id).copied() else {
                            continue;
                        };
                        for (label, measurement) in Measurement::from_prometheus::<P>(stdout) {
                            aggregator.add(i, label, measurement);
                        }
                    }

                    aggregator.save(&self.suite_results_dir);

                    let benchmark_duration = parameters.settings.benchmark_duration.as_secs();
                    if elapsed > benchmark_duration {
                        break;
                    }
                },

                // Kill and recover nodes according to the input schedule.
                _ = faults_interval.tick() => {
                    let action = faults_schedule.update();
                    if !action.kill.is_empty() {
                        killed_node_ids.extend(action.kill.iter().map(|instance| instance.id.clone()));
                        self.ssh_manager.kill(action.kill.clone(), "node").await?;
                    }
                    if !action.boot.is_empty() {
                        // Monitor not yet supported for this
                        for instance in &action.boot {
                            killed_node_ids.remove(&instance.id);
                        }
                        self.boot_nodes(action.boot.clone(), &HashSet::new(), parameters)
                            .await?;
                    }
                    if !action.kill.is_empty() || !action.boot.is_empty() {
                        display::newline();
                        display::config("Testbed update", action);
                    }
                }
            }
        }

        let mut final_instances = final_metrics_commands;
        final_instances.retain(|(instance, _)| !killed_node_ids.contains(&instance.id));
        if !final_instances.is_empty() {
            let expected_nodes = final_instances.len();
            let stdio = self
                .execute_per_instance_best_effort(
                    final_instances.clone(),
                    CommandContext::default(),
                    "Final metrics scrape",
                )
                .await;

            if stdio.is_empty() {
                display::warn(
                    "Final metrics scrape failed for all reachable nodes; \
                     reporting the last successful samples",
                );
            } else {
                let successful_ids: HashSet<_> = stdio
                    .iter()
                    .map(|(instance, _)| instance.id.clone())
                    .collect();
                let missed = expected_nodes.saturating_sub(successful_ids.len());
                if missed != 0 {
                    display::warn(format!(
                        "Final metrics scrape missed {missed} of {expected_nodes} nodes; \
                         reporting partial results",
                    ));
                }

                for (instance, (stdout, _stderr)) in &stdio {
                    let Some(i) = node_indices.get(&instance.id).copied() else {
                        continue;
                    };
                    for (label, measurement) in Measurement::from_prometheus::<P>(stdout) {
                        aggregator.add(i, label, measurement);
                    }
                }
                aggregator.save(&self.suite_results_dir);
            }
        }

        display::done();
        Ok(aggregator)
    }

    fn build_stability_sample(
        minute: usize,
        elapsed_secs: u64,
        expected_live_nodes: usize,
        outage_active: bool,
        metrics_by_scraper: &HashMap<usize, HashMap<String, Measurement>>,
        previous_counters: &mut HashMap<usize, StabilityCounterSample>,
        db_sizes: &[Option<u64>],
    ) -> StabilitySample {
        let mut tx_rate_candidates = Vec::new();
        let mut block_rate_candidates = Vec::new();
        let mut cpu_samples = Vec::new();
        let mut bandwidth_samples = Vec::new();
        let mut bandwidth_sent_total = 0.0;
        let mut bandwidth_received_total = 0.0;
        let mut tx_latency_p50 = Vec::new();
        let mut tx_latency_p75 = Vec::new();
        let mut block_latency_p50 = Vec::new();
        let mut block_latency_p75 = Vec::new();
        let mut resident_mem = Vec::new();
        let mut virtual_mem = Vec::new();
        let mut protocol_mem = Vec::new();

        for (scraper_id, measurements) in metrics_by_scraper {
            if let Some(value) =
                Self::latency_bucket_ms(measurements, "transaction_committed_latency", "p50")
            {
                tx_latency_p50.push(value);
            }
            if let Some(value) =
                Self::latency_bucket_ms(measurements, "transaction_committed_latency", "p75")
            {
                tx_latency_p75.push(value);
            }
            if let Some(value) =
                Self::latency_bucket_ms(measurements, "block_committed_latency", "p50")
            {
                block_latency_p50.push(value);
            }
            if let Some(value) =
                Self::latency_bucket_ms(measurements, "block_committed_latency", "p75")
            {
                block_latency_p75.push(value);
            }
            if let Some(value) = Self::scalar_metric(measurements, "process_resident_memory_bytes")
            {
                resident_mem.push(value);
            }
            if let Some(value) = Self::scalar_metric(measurements, "process_virtual_memory_bytes") {
                virtual_mem.push(value);
            }
            if let Some(value) = Self::scalar_metric(measurements, "global_in_memory_blocks_bytes")
            {
                protocol_mem.push(value);
            }

            let current = Self::stability_counter_sample(measurements);
            if let Some(previous) = previous_counters.insert(*scraper_id, current.clone()) {
                let dt = current.timestamp_secs - previous.timestamp_secs;
                if dt > 0.0 {
                    let current_tx = current
                        .transaction_committed_count
                        .or(current.sequenced_transactions_count);
                    let previous_tx = previous
                        .transaction_committed_count
                        .or(previous.sequenced_transactions_count);
                    if let Some(delta) = Self::non_negative_delta(current_tx, previous_tx) {
                        tx_rate_candidates.push(delta / dt);
                    }
                    if let Some(delta) = Self::non_negative_delta(
                        current.block_committed_count,
                        previous.block_committed_count,
                    ) {
                        block_rate_candidates.push(delta / dt);
                    }
                    if let Some(delta) =
                        Self::non_negative_delta(current.cpu_seconds, previous.cpu_seconds)
                    {
                        cpu_samples.push(delta / dt);
                    }

                    let sent_rate =
                        Self::non_negative_delta(current.bytes_sent, previous.bytes_sent)
                            .map(|delta| delta / dt / (1024.0 * 1024.0))
                            .unwrap_or_default();
                    let recv_rate =
                        Self::non_negative_delta(current.bytes_received, previous.bytes_received)
                            .map(|delta| delta / dt / (1024.0 * 1024.0))
                            .unwrap_or_default();
                    let total_rate = sent_rate + recv_rate;
                    bandwidth_sent_total += sent_rate;
                    bandwidth_received_total += recv_rate;
                    bandwidth_samples.push(total_rate);
                }
            }
        }

        let storage_samples: Vec<f64> = db_sizes
            .iter()
            .filter_map(|size| size.map(|value| value as f64))
            .collect();
        let storage_total_bytes = db_sizes.iter().filter_map(|size| *size).sum::<u64>();

        StabilitySample {
            minute,
            elapsed_secs,
            expected_live_nodes,
            outage_active,
            metrics_contributors: metrics_by_scraper.len(),
            storage_contributors: storage_samples.len(),
            tps: tx_rate_candidates
                .into_iter()
                .max_by(f64::total_cmp)
                .unwrap_or_default(),
            bps: block_rate_candidates
                .into_iter()
                .max_by(f64::total_cmp)
                .unwrap_or_default(),
            transaction_latency_p50_ms: Self::percentile(&tx_latency_p50, 0.50),
            transaction_latency_p75_ms: Self::percentile(&tx_latency_p75, 0.50),
            block_latency_p50_ms: Self::percentile(&block_latency_p50, 0.50),
            block_latency_p75_ms: Self::percentile(&block_latency_p75, 0.50),
            cpu_total_cores: cpu_samples.iter().sum(),
            cpu_p50_cores: Self::percentile(&cpu_samples, 0.50),
            cpu_p75_cores: Self::percentile(&cpu_samples, 0.75),
            bandwidth_sent_total_mib_per_s: bandwidth_sent_total,
            bandwidth_received_total_mib_per_s: bandwidth_received_total,
            bandwidth_total_mib_per_s: bandwidth_sent_total + bandwidth_received_total,
            bandwidth_per_node_p50_mib_per_s: Self::percentile(&bandwidth_samples, 0.50),
            bandwidth_per_node_p75_mib_per_s: Self::percentile(&bandwidth_samples, 0.75),
            resident_mem_total_bytes: resident_mem.iter().sum(),
            resident_mem_p50_bytes: Self::percentile(&resident_mem, 0.50),
            resident_mem_p75_bytes: Self::percentile(&resident_mem, 0.75),
            virtual_mem_total_bytes: virtual_mem.iter().sum(),
            virtual_mem_p50_bytes: Self::percentile(&virtual_mem, 0.50),
            virtual_mem_p75_bytes: Self::percentile(&virtual_mem, 0.75),
            protocol_mem_total_bytes: protocol_mem.iter().sum(),
            protocol_mem_p50_bytes: Self::percentile(&protocol_mem, 0.50),
            protocol_mem_p75_bytes: Self::percentile(&protocol_mem, 0.75),
            storage_total_bytes,
            storage_p50_bytes: Self::percentile(&storage_samples, 0.50),
            storage_p75_bytes: Self::percentile(&storage_samples, 0.75),
        }
    }

    async fn run_stability(
        &mut self,
        nodes: Vec<Instance>,
        mut killed_node_ids: HashSet<String>,
        parameters: &BenchmarkParameters,
        sample_interval: Duration,
        outage: Option<StabilityOutage>,
    ) -> TestbedResult<(MeasurementsCollection, StabilityReport)> {
        display::action(format!(
            "Collecting stability samples every {}s for {}s",
            sample_interval.as_secs(),
            self.settings.benchmark_duration.as_secs()
        ));

        let node_indices: HashMap<_, _> = nodes
            .iter()
            .enumerate()
            .map(|(i, node)| (node.id.clone(), i))
            .collect();
        let metrics_commands = self
            .protocol_commands
            .nodes_metrics_command(nodes.clone(), parameters);
        let final_metrics_commands = self
            .protocol_commands
            .nodes_final_metrics_command(nodes.clone(), parameters);

        let mut aggregator = MeasurementsCollection::new(parameters.clone());
        aggregator.set_ready_nodes_at_boot(nodes.len().saturating_sub(killed_node_ids.len()));

        let ready_nodes: Vec<_> = nodes
            .iter()
            .filter(|node| !killed_node_ids.contains(&node.id))
            .cloned()
            .collect();
        let faults_type =
            Self::runtime_faults_type(parameters.settings.faults.clone(), ready_nodes.len());
        let faults_interval_duration = faults_type.crash_interval();
        let mut faults_schedule = CrashRecoverySchedule::new(faults_type, ready_nodes);
        let mut faults_interval = time::interval(faults_interval_duration);
        faults_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        faults_interval.tick().await;

        let mut sample_timer = time::interval(sample_interval);
        sample_timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        sample_timer.tick().await;

        let generated_at_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut report = StabilityReport {
            generated_at_unix_secs,
            protocol: parameters.consensus_protocol.clone(),
            committee: parameters.nodes,
            load: parameters.load,
            duration_secs: self.settings.benchmark_duration.as_secs(),
            sample_interval_secs: sample_interval.as_secs(),
            outage: outage.clone(),
            points: Vec::new(),
        };
        let mut previous_counters = HashMap::new();
        let mut baseline_instances = metrics_commands.clone();
        baseline_instances.retain(|(instance, _)| !killed_node_ids.contains(&instance.id));
        let baseline_stdio = self
            .execute_per_instance_best_effort(
                baseline_instances,
                CommandContext::default(),
                "Stability baseline scrape",
            )
            .await;
        for (instance, (stdout, _stderr)) in &baseline_stdio {
            let Some(i) = node_indices.get(&instance.id).copied() else {
                continue;
            };
            let parsed = Measurement::from_prometheus::<P>(stdout);
            if parsed.is_empty() {
                continue;
            }
            previous_counters.insert(i, Self::stability_counter_sample(&parsed));
        }
        let start = Instant::now();
        let outage_targets = outage.as_ref().map(|config| {
            config
                .selected_authorities(nodes.len())
                .into_iter()
                .filter_map(|authority| nodes.get(authority).cloned())
                .collect()
        });
        let mut outage_state = outage
            .map(|config| OneShotOutageState::new(config, outage_targets.unwrap_or_default()));

        loop {
            let next_outage_deadline = outage_state
                .as_ref()
                .and_then(|state| state.next_deadline(start));

            if let Some(deadline) = next_outage_deadline {
                tokio::select! {
                    _ = sample_timer.tick() => {
                        let elapsed_secs = start.elapsed().as_secs_f64().ceil() as u64;
                        display::status(format!("{elapsed_secs}s"));

                        let mut instances = metrics_commands.clone();
                        instances.retain(|(instance, _)| !killed_node_ids.contains(&instance.id));
                        let stdio = self
                            .execute_per_instance_best_effort(
                                instances,
                                CommandContext::default(),
                                "Stability metrics scrape",
                            )
                            .await;
                        if stdio.is_empty() {
                            display::warn(
                                "All stability metrics scrapes failed for this interval; continuing run",
                            );
                        }

                        let mut metrics_by_scraper = HashMap::new();
                        for (instance, (stdout, _stderr)) in &stdio {
                            let Some(i) = node_indices.get(&instance.id).copied() else {
                                continue;
                            };
                            let parsed = Measurement::from_prometheus::<P>(stdout);
                            if parsed.is_empty() {
                                continue;
                            }
                            for (label, measurement) in &parsed {
                                aggregator.add(i, label.clone(), measurement.clone());
                            }
                            metrics_by_scraper.insert(i, parsed);
                        }
                        aggregator.save(&self.suite_results_dir);

                        let active_nodes: Vec<_> = nodes
                            .iter()
                            .filter(|node| !killed_node_ids.contains(&node.id))
                            .cloned()
                            .collect();
                        let active_db_sizes = self
                            .measure_db_sizes_with_coverage(&active_nodes, "Stability DB size")
                            .await;
                        let mut db_sizes = vec![None; nodes.len()];
                        for (node, size) in active_nodes.into_iter().zip(active_db_sizes) {
                            if let Some(index) = node_indices.get(&node.id).copied() {
                                db_sizes[index] = size;
                            }
                        }
                        let sample = Self::build_stability_sample(
                            report.points.len() + 1,
                            elapsed_secs,
                            nodes.len().saturating_sub(killed_node_ids.len()),
                            outage_state
                                .as_ref()
                                .map(OneShotOutageState::is_active)
                                .unwrap_or(false),
                            &metrics_by_scraper,
                            &mut previous_counters,
                            &db_sizes,
                        );
                        aggregator.set_db_sizes(
                            db_sizes
                                .iter()
                                .map(|size| size.unwrap_or(0))
                                .collect(),
                        );
                        report.points.push(sample);
                        self.save_stability_report(&report, &parameters.benchmark_run_id);

                        if elapsed_secs >= self.settings.benchmark_duration.as_secs() {
                            break;
                        }
                    },

                    _ = faults_interval.tick() => {
                        let action = faults_schedule.update();
                        if !action.kill.is_empty() {
                            killed_node_ids.extend(action.kill.iter().map(|instance| instance.id.clone()));
                            for instance in &action.kill {
                                if let Some(index) = node_indices.get(&instance.id).copied() {
                                    previous_counters.remove(&index);
                                }
                            }
                            self.ssh_manager.kill(action.kill.clone(), "node").await?;
                        }
                        if !action.boot.is_empty() {
                            for instance in &action.boot {
                                killed_node_ids.remove(&instance.id);
                                if let Some(index) = node_indices.get(&instance.id).copied() {
                                    previous_counters.remove(&index);
                                }
                            }
                            self.boot_nodes(action.boot.clone(), &HashSet::new(), parameters)
                                .await?;
                        }
                        if !action.kill.is_empty() || !action.boot.is_empty() {
                            display::newline();
                            display::config("Testbed update", action);
                        }
                    }

                    _ = time::sleep_until(deadline) => {
                        if let Some(state) = outage_state.as_mut() {
                            match state.phase {
                                OneShotOutagePhase::Pending => {
                                    let to_kill: Vec<_> = state
                                        .targets
                                        .iter()
                                        .filter(|instance| !killed_node_ids.contains(&instance.id))
                                        .cloned()
                                        .collect();
                                    if to_kill.is_empty() {
                                        display::warn("Scheduled outage started but all targeted validators were already down");
                                    } else {
                                        display::newline();
                                        display::config(
                                            "Scheduled outage",
                                            if state.config.keep_down {
                                                format!(
                                                    "Stopping {} and keeping them down",
                                                    state.config.selected_authorities_label(
                                                        nodes.len()
                                                    ),
                                                )
                                            } else {
                                                format!(
                                                    "Stopping {} for {}s",
                                                    state.config.selected_authorities_label(
                                                        nodes.len()
                                                    ),
                                                    state.config.duration_secs,
                                                )
                                            },
                                        );
                                        state.killed_by_outage = to_kill
                                            .iter()
                                            .map(|instance| instance.id.clone())
                                            .collect();
                                        for instance in &to_kill {
                                            killed_node_ids.insert(instance.id.clone());
                                            if let Some(index) = node_indices.get(&instance.id).copied() {
                                                previous_counters.remove(&index);
                                            }
                                        }
                                        self.ssh_manager.kill(to_kill, "node").await?;
                                    }
                                    state.phase = OneShotOutagePhase::Down;
                                }
                                OneShotOutagePhase::Down => {
                                    let to_boot: Vec<_> = state
                                        .targets
                                        .iter()
                                        .filter(|instance| state.killed_by_outage.contains(&instance.id))
                                        .cloned()
                                        .collect();
                                    if !to_boot.is_empty() {
                                        display::newline();
                                        display::config(
                                            "Scheduled outage",
                                            format!(
                                                "Recovering {} validators from {}",
                                                to_boot.len(),
                                                state.config.selected_authorities_label(nodes.len()),
                                            ),
                                        );
                                        for instance in &to_boot {
                                            killed_node_ids.remove(&instance.id);
                                            if let Some(index) = node_indices.get(&instance.id).copied() {
                                                previous_counters.remove(&index);
                                            }
                                        }
                                        self.boot_nodes(to_boot, &HashSet::new(), parameters)
                                            .await?;
                                    }
                                    state.killed_by_outage.clear();
                                    state.phase = OneShotOutagePhase::Completed;
                                }
                                OneShotOutagePhase::Completed => {}
                            }
                        }
                    }
                }
            } else {
                tokio::select! {
                        _ = sample_timer.tick() => {
                        let elapsed_secs = start.elapsed().as_secs_f64().ceil() as u64;
                        display::status(format!("{elapsed_secs}s"));

                        let mut instances = metrics_commands.clone();
                        instances.retain(|(instance, _)| !killed_node_ids.contains(&instance.id));
                        let stdio = self
                            .execute_per_instance_best_effort(
                                instances,
                                CommandContext::default(),
                                "Stability metrics scrape",
                            )
                            .await;
                        if stdio.is_empty() {
                            display::warn(
                                "All stability metrics scrapes failed for this interval; continuing run",
                            );
                        }

                        let mut metrics_by_scraper = HashMap::new();
                        for (instance, (stdout, _stderr)) in &stdio {
                            let Some(i) = node_indices.get(&instance.id).copied() else {
                                continue;
                            };
                            let parsed = Measurement::from_prometheus::<P>(stdout);
                            if parsed.is_empty() {
                                continue;
                            }
                            for (label, measurement) in &parsed {
                                aggregator.add(i, label.clone(), measurement.clone());
                            }
                            metrics_by_scraper.insert(i, parsed);
                        }
                        aggregator.save(&self.suite_results_dir);

                        let active_nodes: Vec<_> = nodes
                            .iter()
                            .filter(|node| !killed_node_ids.contains(&node.id))
                            .cloned()
                            .collect();
                        let active_db_sizes = self
                            .measure_db_sizes_with_coverage(&active_nodes, "Stability DB size")
                            .await;
                        let mut db_sizes = vec![None; nodes.len()];
                        for (node, size) in active_nodes.into_iter().zip(active_db_sizes) {
                            if let Some(index) = node_indices.get(&node.id).copied() {
                                db_sizes[index] = size;
                            }
                        }
                        let sample = Self::build_stability_sample(
                            report.points.len() + 1,
                            elapsed_secs,
                            nodes.len().saturating_sub(killed_node_ids.len()),
                            outage_state
                                .as_ref()
                                .map(OneShotOutageState::is_active)
                                .unwrap_or(false),
                            &metrics_by_scraper,
                            &mut previous_counters,
                            &db_sizes,
                        );
                        aggregator.set_db_sizes(
                            db_sizes
                                .iter()
                                .map(|size| size.unwrap_or(0))
                                .collect(),
                        );
                        report.points.push(sample);
                        self.save_stability_report(&report, &parameters.benchmark_run_id);

                        if elapsed_secs >= self.settings.benchmark_duration.as_secs() {
                            break;
                        }
                    },

                    _ = faults_interval.tick() => {
                        let action = faults_schedule.update();
                        if !action.kill.is_empty() {
                            killed_node_ids.extend(action.kill.iter().map(|instance| instance.id.clone()));
                            for instance in &action.kill {
                                if let Some(index) = node_indices.get(&instance.id).copied() {
                                    previous_counters.remove(&index);
                                }
                            }
                            self.ssh_manager.kill(action.kill.clone(), "node").await?;
                        }
                        if !action.boot.is_empty() {
                            for instance in &action.boot {
                                killed_node_ids.remove(&instance.id);
                                if let Some(index) = node_indices.get(&instance.id).copied() {
                                    previous_counters.remove(&index);
                                }
                            }
                            self.boot_nodes(action.boot.clone(), &HashSet::new(), parameters)
                                .await?;
                        }
                        if !action.kill.is_empty() || !action.boot.is_empty() {
                            display::newline();
                            display::config("Testbed update", action);
                        }
                    }
                }
            }
        }

        let mut final_instances = final_metrics_commands;
        final_instances.retain(|(instance, _)| !killed_node_ids.contains(&instance.id));
        if !final_instances.is_empty() {
            let stdio = self
                .execute_per_instance_best_effort(
                    final_instances,
                    CommandContext::default(),
                    "Final stability metrics scrape",
                )
                .await;
            for (instance, (stdout, _stderr)) in &stdio {
                let Some(i) = node_indices.get(&instance.id).copied() else {
                    continue;
                };
                for (label, measurement) in Measurement::from_prometheus::<P>(stdout) {
                    aggregator.add(i, label, measurement);
                }
            }
            aggregator.save(&self.suite_results_dir);
        }

        display::done();
        Ok((aggregator, report))
    }

    async fn measure_db_sizes_with_coverage(
        &mut self,
        nodes: &[Instance],
        stage: &str,
    ) -> Vec<Option<u64>> {
        let db_dirs = self.protocol_commands.db_directories();
        if db_dirs.is_empty() {
            return vec![Some(0); nodes.len()];
        }

        let pattern = db_dirs
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let cmd = format!("du -sb {pattern} 2>/dev/null | awk '{{s+=$1}} END {{print s+0}}'");
        let commands: Vec<_> = nodes
            .iter()
            .map(|node| (node.clone(), cmd.clone()))
            .collect();

        let stdio = self
            .execute_per_instance_best_effort(commands, CommandContext::default(), stage)
            .await;

        let node_indices: HashMap<_, _> = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.id.clone(), index))
            .collect();
        let mut sizes = vec![None; nodes.len()];
        for (instance, (stdout, _)) in stdio {
            let Some(index) = node_indices.get(&instance.id).copied() else {
                continue;
            };
            sizes[index] = Some(stdout.trim().parse::<u64>().unwrap_or(0));
        }
        sizes
    }

    /// Measure total database size on each node (in bytes).
    async fn measure_db_sizes(&mut self, nodes: &[Instance]) -> Vec<u64> {
        display::action("Measuring database sizes");
        let sizes = self.measure_db_sizes_with_coverage(nodes, "DB size").await;
        display::done();
        sizes.into_iter().map(|size| size.unwrap_or(0)).collect()
    }

    /// Download the log files from the nodes.
    async fn download_logs_from_instances(
        &mut self,
        parameters: &BenchmarkParameters,
        nodes: &[Instance],
    ) -> TestbedResult<LogsAnalyzer> {
        // Create a log sub-directory for this run.
        let commit = &self.settings.repository.commit;
        let path: PathBuf = [
            &self.settings.logs_dir,
            &format!("logs-{commit}").into(),
            &format!("logs-{parameters:?}").into(),
        ]
        .iter()
        .collect();
        fs::create_dir_all(&path).expect("Failed to create log directory");

        // NOTE: Our ssh library does not seem to be able to transfers files in parallel
        // reliably.
        let mut log_parsers = Vec::new();
        let ssh_manager = self.log_download_ssh_manager();

        display::action("Downloading nodes logs");
        for (i, instance) in nodes.iter().enumerate() {
            display::status(format!("{}/{}", i + 1, nodes.len()));

            match self
                .download_compressed_log(&ssh_manager, instance, "node.log")
                .await
            {
                Err(e) => {
                    display::error(format!(
                        "Failed to download node logs from {} - {}",
                        instance.main_ip, e
                    ));
                    self.mark_instances_inactive(std::slice::from_ref(instance));
                }
                Ok(compressed_log) => {
                    let node_log_file = [path.clone(), format!("node-{i}.log.gz").into()]
                        .iter()
                        .collect::<PathBuf>();
                    fs::write(&node_log_file, &compressed_log).map_err(|error| {
                        TestbedError::LogProcessingError(format!(
                            "failed to write {}: {error}",
                            node_log_file.display()
                        ))
                    })?;

                    let node_log_content = match self.decompress_log(
                        &compressed_log,
                        &format!("node log from {}", instance.main_ip),
                    ) {
                        Ok(content) => content,
                        Err(error) => {
                            display::error(error.to_string());
                            continue;
                        }
                    };

                    let mut log_parser = LogsAnalyzer::default();
                    log_parser.set_node_errors(&node_log_content);
                    log_parsers.push(log_parser)
                }
            }
        }
        display::done();

        if log_parsers.is_empty() {
            display::warn("No logs could be downloaded; skipping log analysis");
        }

        Ok(log_parsers.into_iter().max().unwrap_or_default())
    }

    async fn prepare_benchmark_suite(&mut self) -> TestbedResult<()> {
        display::clear_timeline();
        display::header("Preparing testbed");
        if let Some(binary) = &self.settings.pre_built_binary {
            display::config("Pre-built binary", binary);
            if let Some(updated_at) = Self::prebuilt_binary_updated_at(binary).await {
                display::config("Pre-built updated", updated_at);
            }
        } else {
            display::config("Commit", format!("'{}'", &self.settings.repository.commit));
        }
        fs::create_dir_all(&self.suite_results_dir).expect("Failed to create results directory");
        display::config("Results directory", self.suite_results_dir.display());
        display::newline();

        // Cleanup the testbed (in case the previous run was not completed).
        self.cleanup(true, None).await?;

        // Update the software on all instances.
        if !self.skip_testbed_update {
            tokio::try_join!(
                async {
                    self.install().await?;
                    self.update().await
                },
                self.install_external_monitoring(),
            )?;
        }

        Ok(())
    }

    async fn run_benchmark_once(
        &mut self,
        parameters: &BenchmarkParameters,
    ) -> TestbedResult<Option<MeasurementsCollection>> {
        // Cleanup the testbed (in case the previous run was not completed).
        self.cleanup(true, Some(parameters)).await?;
        let (selected_nodes, monitoring_instance) = self.select_instances(parameters)?;
        // Start the instance monitoring tools.
        self.start_monitoring_nodes(selected_nodes.clone(), monitoring_instance, parameters)
            .await?;

        // Reconfigure before each run because benchmark parameters such as
        // per-node load are written into the generated config files.
        if !self.skip_testbed_configuration {
            self.configure_nodes(selected_nodes.clone(), parameters)
                .await?;
        }

        // Deploy the validators.
        let stalled_node_ids = self.run_nodes(selected_nodes.clone(), parameters).await?;
        if parameters.settings.benchmark_duration.as_secs() == 0 {
            return Ok(None);
        }

        // Wait for the benchmark to terminate. Then save the results.
        let mut aggregator = self
            .run(selected_nodes.clone(), stalled_node_ids, parameters)
            .await?;

        // Stop validators before post-processing so DB sizing and log access
        // are not competing with live validator activity.
        self.stop_nodes(&selected_nodes).await;

        // Measure database sizes before cleanup deletes the storage.
        let db_sizes = self.measure_db_sizes(&selected_nodes).await;
        aggregator.set_db_sizes(db_sizes);

        // Download the log files.
        if self.settings.log_processing {
            let error_counter = self
                .download_logs_from_instances(parameters, &selected_nodes)
                .await?;
            error_counter.print_summary();
        }

        // Clear remaining processes and remove storage, but keep logs for
        // debugging or later cleanup.
        self.cleanup(false, Some(parameters)).await?;

        Ok(Some(aggregator))
    }

    async fn run_stability_regime(
        &mut self,
        parameters: BenchmarkParameters,
        sample_interval: Duration,
        outage: Option<StabilityOutage>,
        regime_label: &str,
    ) -> TestbedResult<()> {
        self.prepare_benchmark_suite().await?;

        display::header(format!("Starting {regime_label}"));
        display::config("Protocol", &parameters.consensus_protocol);
        display::config("Load", format!("{} tx/s", parameters.load));
        display::config(
            "Duration",
            format!("{}s", parameters.settings.benchmark_duration.as_secs()),
        );
        display::config("Sample interval", format!("{}s", sample_interval.as_secs()));
        if let Some(outage) = &outage {
            display::config("Outage", outage.selection_description(parameters.nodes));
        }
        display::newline();

        self.cleanup(true, Some(&parameters)).await?;
        let (selected_nodes, monitoring_instance) = self.select_instances(&parameters)?;
        self.start_monitoring_nodes(selected_nodes.clone(), monitoring_instance, &parameters)
            .await?;
        if !self.skip_testbed_configuration {
            self.configure_nodes(selected_nodes.clone(), &parameters)
                .await?;
        }

        let stalled_node_ids = self.run_nodes(selected_nodes.clone(), &parameters).await?;
        let (mut aggregator, report) = self
            .run_stability(
                selected_nodes.clone(),
                stalled_node_ids,
                &parameters,
                sample_interval,
                outage,
            )
            .await?;

        self.stop_nodes(&selected_nodes).await;

        let db_sizes = self.measure_db_sizes(&selected_nodes).await;
        aggregator.set_db_sizes(db_sizes);

        if self.settings.log_processing {
            let error_counter = self
                .download_logs_from_instances(&parameters, &selected_nodes)
                .await?;
            error_counter.print_summary();
        }

        self.cleanup(false, Some(&parameters)).await?;

        aggregator.display_summary();
        let report_path = self.save_stability_report(&report, &parameters.benchmark_run_id);
        display::config("Stability report", report_path.display());
        display::config("Stability points", report.points.len());
        display::print_timeline();
        display::header(format!("{regime_label} completed"));
        Ok(())
    }

    pub async fn run_stability_benchmark(
        &mut self,
        parameters: BenchmarkParameters,
        sample_interval: Duration,
    ) -> TestbedResult<()> {
        self.run_stability_regime(parameters, sample_interval, None, "Benchmark stability")
            .await
    }

    pub async fn run_outage_benchmark(
        &mut self,
        parameters: BenchmarkParameters,
        sample_interval: Duration,
        outage: StabilityOutage,
    ) -> TestbedResult<()> {
        self.run_stability_regime(
            parameters,
            sample_interval,
            Some(outage),
            "Benchmark outage",
        )
        .await
    }

    fn save_sweep_report(&self, report: &LatencyThroughputSweepReport, stem: &str) {
        let path = self.suite_results_dir.join("sweeps");
        fs::create_dir_all(&path).expect("Failed to create sweep results directory");

        let json = serde_json::to_string_pretty(report).expect("Cannot serialize sweep report");
        fs::write(path.join(format!("{stem}.json")), json).expect("Failed to write sweep report");
        fs::write(path.join(format!("{stem}.csv")), report.to_csv())
            .expect("Failed to write sweep CSV report");
    }

    fn save_stability_report(&self, report: &StabilityReport, benchmark_run_id: &str) -> PathBuf {
        let path = self.suite_results_dir.join("stability");
        fs::create_dir_all(&path).expect("Failed to create stability results directory");

        let json = serde_json::to_string_pretty(report).expect("Cannot serialize stability report");
        let json_path = path.join(format!("stability-{benchmark_run_id}.json"));
        let csv_path = path.join(format!("stability-{benchmark_run_id}.csv"));
        fs::write(&json_path, json).expect("Failed to write stability JSON report");
        fs::write(&csv_path, report.to_csv()).expect("Failed to write stability CSV report");
        json_path
    }

    /// Run all the benchmarks specified by the benchmark generator.
    pub async fn run_benchmarks(
        &mut self,
        set_of_parameters: Vec<BenchmarkParameters>,
    ) -> TestbedResult<()> {
        self.prepare_benchmark_suite().await?;

        // Run all benchmarks.
        let mut i = 1;
        for parameters in set_of_parameters {
            display::header(format!("Starting benchmark {i}"));
            display::config("Protocol", &parameters.consensus_protocol);
            display::config("Load", format!("{} tx/s", parameters.load));
            display::newline();

            let Some(aggregator) = self.run_benchmark_once(&parameters).await? else {
                return Ok(());
            };
            aggregator.display_summary();

            i += 1;
        }

        display::print_timeline();
        display::header("Benchmark completed");
        Ok(())
    }

    pub async fn run_latency_throughput_sweep(
        &mut self,
        base_parameters: BenchmarkParameters,
        plan: LatencyThroughputSweepPlan,
    ) -> TestbedResult<()> {
        self.prepare_benchmark_suite().await?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let stem = format!("latency-throughput-sweep-{timestamp}");
        let mut summaries = Vec::new();

        for protocol in &plan.protocols {
            let mut current_load = plan.initial_load;
            let mut point_index = 0;

            loop {
                point_index += 1;
                let parameters =
                    base_parameters.with_load_and_consensus(current_load, protocol.clone());
                display::header(format!("Sweep {} point {}", protocol, point_index));
                display::config("Protocol", &parameters.consensus_protocol);
                display::config("Load", format!("{} tx/s", parameters.load));
                display::newline();

                let Some(aggregator) = self.run_benchmark_once(&parameters).await? else {
                    return Ok(());
                };
                aggregator.display_summary();

                let summary = aggregator.benchmark_run_summary();
                let reached_goal = plan.reached_latency_goal(summary.transaction_latency_ms.p50);
                summaries.push(summary.clone());

                let report = LatencyThroughputSweepReport {
                    generated_at_unix_secs: timestamp,
                    plan: plan.clone(),
                    points: summaries.clone(),
                };
                self.save_sweep_report(&report, &stem);

                if reached_goal {
                    display::config(
                        "Sweep progress",
                        format!(
                            "{} reached the {} ms goal at load {}",
                            protocol, plan.latency_goal_ms, current_load
                        ),
                    );
                    break;
                }

                if point_index >= plan.max_points_per_protocol {
                    display::warn(format!(
                        "Stopping {} after {} points without hitting the {} ms goal",
                        protocol, plan.max_points_per_protocol, plan.latency_goal_ms
                    ));
                    break;
                }

                current_load = plan
                    .next_load(current_load, summary.transaction_latency_ms.p50)
                    .unwrap_or(current_load);
            }
        }

        display::print_timeline();
        display::header("Latency-throughput sweep completed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Orchestrator;
    use crate::protocol::starfish::StarfishProtocol;
    use crate::{client::Instance, faults::FaultsType};

    #[test]
    fn node_boot_timeout_has_sane_floor() {
        assert_eq!(
            Orchestrator::<StarfishProtocol>::node_boot_timeout(10),
            std::time::Duration::from_secs(60)
        );
    }

    #[test]
    fn node_boot_timeout_is_constant_for_large_committees() {
        assert_eq!(
            Orchestrator::<StarfishProtocol>::node_boot_timeout(400),
            std::time::Duration::from_secs(60)
        );
    }

    #[test]
    fn max_tolerated_boot_failures_allows_ten_percent() {
        assert_eq!(
            Orchestrator::<StarfishProtocol>::max_tolerated_boot_failures(250),
            25
        );
        assert_eq!(
            Orchestrator::<StarfishProtocol>::max_tolerated_boot_failures(400),
            40
        );
    }

    #[test]
    fn startup_permanent_faults_are_left_down_from_boot() {
        let nodes = (0..100)
            .map(|i| Instance::new_for_test(i.to_string()))
            .collect::<Vec<_>>();

        let startup_faulted = Orchestrator::<StarfishProtocol>::startup_permanent_faults(
            FaultsType::Permanent { faults: 33 },
            &nodes,
        );
        let ids = startup_faulted
            .into_iter()
            .map(|instance| instance.id)
            .collect::<Vec<_>>();

        assert_eq!(
            ids,
            vec![
                "0", "3", "6", "9", "12", "15", "18", "21", "24", "27", "30", "33", "36", "39",
                "42", "45", "48", "51", "54", "57", "60", "63", "66", "69", "72", "75", "78", "81",
                "84", "87", "90", "93", "96"
            ]
        );
    }

    #[test]
    fn runtime_faults_disable_permanent_fault_timer_after_startup() {
        assert_eq!(
            Orchestrator::<StarfishProtocol>::runtime_faults_type(
                FaultsType::Permanent { faults: 33 },
                67,
            ),
            FaultsType::default()
        );
    }
}
