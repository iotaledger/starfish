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
    benchmark::{BenchmarkParameters, LatencyThroughputSweepPlan, LatencyThroughputSweepReport},
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

    fn max_tolerated_boot_failures(node_count: usize) -> usize {
        (node_count as f64 * Self::MAX_TOLERATED_BOOT_FAILURE_RATIO).floor() as usize
    }

    fn apt_get_noninteractive(args: &str) -> String {
        format!("sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get {args}")
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
        parameters: &BenchmarkParameters,
    ) -> TestbedResult<Vec<Instance>> {
        let total = instances.len();
        let timeout = Self::node_boot_timeout(total);
        let max_failures = Self::max_tolerated_boot_failures(total);
        let mut pending_indices: HashSet<usize> = (0..total).collect();

        // Keep a lookup vec so we can recover Instance for stalled indices
        // after the polling loop (which may consume `instances` in the SSH
        // fallback path).
        let all_instances = instances.clone();

        let start = Instant::now();
        display::status(format!("ready 0/{total}"));

        if start.elapsed() < timeout {
            // Preserve the original authority ordering. The protocol derives
            // per-node ports from iterator position, so iterating the
            // `HashSet` directly can mismatch instances to metrics ports.
            let remaining: Vec<Instance> = all_instances
                .iter()
                .enumerate()
                .filter(|(i, _)| pending_indices.contains(i))
                .map(|(_, instance)| instance.clone())
                .collect();

            let mut pending: HashMap<_, _> = self
                .protocol_commands
                .nodes_readiness_command(remaining, parameters)
                .into_iter()
                .map(|(instance, command)| {
                    let idx = all_instances
                        .iter()
                        .position(|inst| inst.id == instance.id)
                        .unwrap();
                    (instance.id.clone(), (idx, instance, command))
                })
                .collect();

            loop {
                let probes: Vec<_> = pending
                    .values()
                    .map(|(_, inst, cmd)| (inst.clone(), cmd.clone()))
                    .collect();
                let ready = self
                    .probe_instances_best_effort(probes, CommandContext::default())
                    .await;
                for instance in ready {
                    if let Some((idx, ..)) = pending.remove(&instance.id) {
                        pending_indices.remove(&idx);
                    }
                }

                let completed = total - pending_indices.len();
                display::status(format!(
                    "ready {completed}/{total} {}s",
                    start.elapsed().as_secs()
                ));

                if pending_indices.is_empty() {
                    return Ok(Vec::new());
                }
                if pending_indices.len() <= max_failures {
                    let stalled: Vec<_> = pending_indices
                        .iter()
                        .filter_map(|&i| all_instances.get(i).cloned())
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
                if start.elapsed() >= timeout {
                    break;
                }

                time::sleep(Self::NODE_BOOT_POLL_INTERVAL).await;
            }
        }

        let stalled: Vec<_> = pending_indices
            .iter()
            .filter_map(|&i| all_instances.get(i).cloned())
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
        parameters: &BenchmarkParameters,
    ) -> TestbedResult<()> {
        // Run one node per instance.
        let targets = self
            .protocol_commands
            .node_command(instances.clone(), parameters);

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

        self.boot_nodes(nodes.clone(), parameters).await?;
        let stalled = self.wait_for_nodes_ready(nodes, parameters).await?;

        display::done();
        Ok(stalled.into_iter().map(|instance| instance.id).collect())
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
        let faults_type = Self::clamp_faults_to_available_nodes(
            parameters.settings.faults.clone(),
            ready_nodes.len(),
        );
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
                        self.boot_nodes(action.boot.clone(), parameters).await?;
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

    /// Measure total database size on each node (in bytes).
    async fn measure_db_sizes(&mut self, nodes: &[Instance]) -> Vec<u64> {
        display::action("Measuring database sizes");

        let db_dirs = self.protocol_commands.db_directories();
        if db_dirs.is_empty() {
            display::done();
            return vec![0; nodes.len()];
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
            .execute_per_instance_best_effort(commands, CommandContext::default(), "DB size")
            .await;

        let node_indices: HashMap<_, _> = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.id.clone(), index))
            .collect();
        let mut sizes = vec![0; nodes.len()];
        for (instance, (stdout, _)) in stdio {
            let Some(index) = node_indices.get(&instance.id).copied() else {
                continue;
            };
            sizes[index] = stdout.trim().parse::<u64>().unwrap_or(0);
        }

        display::done();
        sizes
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

    fn save_sweep_report(&self, report: &LatencyThroughputSweepReport, stem: &str) {
        let path = self.suite_results_dir.join("sweeps");
        fs::create_dir_all(&path).expect("Failed to create sweep results directory");

        let json = serde_json::to_string_pretty(report).expect("Cannot serialize sweep report");
        fs::write(path.join(format!("{stem}.json")), json).expect("Failed to write sweep report");
        fs::write(path.join(format!("{stem}.csv")), report.to_csv())
            .expect("Failed to write sweep CSV report");
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
}
