// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    benchmark::BenchmarkParameters,
    client::Instance,
    display,
    error::{MonitorError, MonitorResult},
    protocol::ProtocolMetrics,
    ssh::{CommandContext, SshConnectionManager},
};

pub struct Monitor {
    instance: Instance,
    nodes: Vec<Instance>,
    ssh_manager: SshConnectionManager,
    working_dir: PathBuf,
    scrape_over_public_ip: bool,
}

impl Monitor {
    /// Create a new monitor.
    pub fn new(
        instance: Instance,
        nodes: Vec<Instance>,
        ssh_manager: SshConnectionManager,
        working_dir: PathBuf,
        scrape_over_public_ip: bool,
    ) -> Self {
        Self {
            instance,
            nodes,
            ssh_manager,
            working_dir,
            scrape_over_public_ip,
        }
    }

    async fn ensure_working_dir(&self) -> MonitorResult<()> {
        let command = format!("mkdir -p {}", self.working_dir.display());
        self.ssh_manager
            .execute(
                std::iter::once(self.instance.clone()),
                command,
                CommandContext::default(),
            )
            .await?;
        Ok(())
    }

    /// Dependencies to install.
    pub fn dependencies() -> Vec<String> {
        let mut commands: Vec<String> = Vec::new();
        commands.extend(Prometheus::install_commands().into_iter().map(String::from));
        commands.extend(Grafana::install_commands().into_iter().map(String::from));
        commands.extend(NodeExporter::install_commands());
        commands
    }

    /// Start a prometheus instance on the dedicated motoring machine.
    pub async fn start_prometheus<P: ProtocolMetrics>(
        &self,
        protocol_commands: &P,
        parameters: &BenchmarkParameters,
    ) -> MonitorResult<()> {
        self.ensure_working_dir().await?;

        let mut scrape_parameters = parameters.clone();
        if self.scrape_over_public_ip {
            scrape_parameters.use_internal_ip_address = false;
        }

        let config =
            Prometheus::configuration(self.nodes.clone(), protocol_commands, &scrape_parameters);
        let remote_config: PathBuf = "prometheus.yml".into();
        let remote_config_path = self.working_dir.join(&remote_config);

        // Upload the config separately so large committees do not overflow the
        // SSH exec request size.
        self.ssh_manager
            .upload_bytes_to_all(
                std::iter::once(self.instance.clone()),
                config.into_bytes(),
                &remote_config_path,
            )
            .await?;

        // Upload recording rules for pre-aggregated dashboard queries.
        let rules = Prometheus::recording_rules();
        let remote_rules_file: PathBuf = "recording_rules.yml".into();
        let remote_rules_path = self.working_dir.join(&remote_rules_file);
        self.ssh_manager
            .upload_bytes_to_all(
                std::iter::once(self.instance.clone()),
                rules.into_bytes(),
                &remote_rules_path,
            )
            .await?;

        let commands = Prometheus::reload_commands(&remote_config, &remote_rules_file);
        let context = CommandContext::new().with_execute_from_path(self.working_dir.clone());
        self.ssh_manager
            .execute(std::iter::once(self.instance.clone()), commands, context)
            .await?;

        Ok(())
    }

    /// Start grafana on the dedicated motoring machine.
    pub async fn start_grafana(&self) -> MonitorResult<()> {
        self.ensure_working_dir().await?;

        let local_dashboard: PathBuf = [
            env!("CARGO_MANIFEST_DIR"),
            "..",
            "..",
            "monitoring",
            "grafana",
            "grafana-dashboard.json",
        ]
        .iter()
        .collect();
        if !local_dashboard.exists() {
            return Err(MonitorError::GrafanaError(format!(
                "Dashboard file not found at {}",
                local_dashboard.display()
            )));
        }

        let remote_dashboard_file: PathBuf = "grafana-dashboard.json".into();
        let remote_dashboard = self.working_dir.join(&remote_dashboard_file);
        self.ssh_manager
            .upload_to_all(
                std::iter::once(self.instance.clone()),
                &local_dashboard,
                &remote_dashboard,
            )
            .await?;

        // Configure and reload grafana.
        let instance = std::iter::once(self.instance.clone());
        let commands = Grafana::setup_commands();
        let context = CommandContext::new().with_execute_from_path(self.working_dir.clone());
        self.ssh_manager
            .execute(instance, commands, context)
            .await?;

        Ok(())
    }

    /// Deep link to the consensus dashboard in kiosk mode.
    pub fn grafana_address(&self) -> String {
        let base = format!("http://{}:{}", self.instance.main_ip, Grafana::DEFAULT_PORT);
        format!(
            "{base}/d/{}/consensus?from=now-5m&to=now&refresh=5s&kiosk",
            Grafana::DASHBOARD_UID
        )
    }
}

/// Generate the commands to setup prometheus on the given instances.
pub struct Prometheus;

impl Prometheus {
    /// The default prometheus configuration path.
    const DEFAULT_PROMETHEUS_CONFIG_PATH: &'static str = "/etc/prometheus/prometheus.yml";
    #[cfg(test)]
    /// The default prometheus environment file path.
    const DEFAULT_PROMETHEUS_ENV_PATH: &'static str = "/etc/default/prometheus";
    /// The path for recording rules on the remote machine.
    const RECORDING_RULES_PATH: &'static str = "/etc/prometheus/recording_rules.yml";
    /// The default prometheus port.
    pub const DEFAULT_PORT: u16 = 9090;

    fn ensure_runtime_flags_command() -> &'static str {
        "sudo sh -c 'file=/etc/default/prometheus; touch \"$file\"; \
            current=$(sed -n \"s/^ARGS=\\\"\\(.*\\)\\\"$/\\1/p\" \"$file\"); \
            for flag in --web.enable-lifecycle --storage.tsdb.retention.time=30d --storage.tsdb.retention.size=100GB; do \
                case \" $current \" in *\" $flag \"*) ;; *) current=\"${current:+$current }$flag\" ;; esac; \
            done; \
            awk \"!/^ARGS=/\" \"$file\" > \"$file.tmp\"; \
            printf \"ARGS=\\\"%s\\\"\\n\" \"$current\" >> \"$file.tmp\"; \
            mv \"$file.tmp\" \"$file\"'"
    }

    /// The commands to install prometheus.
    pub fn install_commands() -> Vec<&'static str> {
        vec![
            "sudo apt-get -y install prometheus",
            "sudo chmod 777 -R /var/lib/prometheus/ /etc/prometheus/",
            // Preserve unrelated distro defaults while ensuring Prometheus has
            // the flags needed for fast config reloads and larger retained TSDBs.
            Self::ensure_runtime_flags_command(),
            "sudo service prometheus restart",
        ]
    }

    /// Generate the prometheus configuration.
    pub fn configuration<I, P>(nodes: I, protocol: &P, parameters: &BenchmarkParameters) -> String
    where
        I: IntoIterator<Item = Instance>,
        P: ProtocolMetrics,
    {
        let nodes_metrics_path = protocol.nodes_metrics_path(nodes, parameters);
        let mut config = vec![Self::global_configuration(nodes_metrics_path.len())];

        for (i, (_, nodes_metrics_path)) in nodes_metrics_path.into_iter().enumerate() {
            let id = format!("node-{i}");
            let scrape_config = Self::scrape_configuration(&id, &nodes_metrics_path);
            config.push(scrape_config);
        }

        config.join("\n")
    }

    /// Generate the commands to install the uploaded configuration and
    /// hot-reload prometheus (falls back to a full restart when the
    /// lifecycle API is unavailable).
    pub fn reload_commands<P: AsRef<Path>>(remote_config_path: P, remote_rules_path: P) -> String {
        format!(
            "{} && sudo cp {} {} && sudo cp {} {} && \
             (curl --silent --show-error --fail --connect-timeout 1 --max-time 2 \
              -X POST http://127.0.0.1:{}/-/reload \
              || {{ (sudo fuser -k {}/tcp || true) && \
              sudo service prometheus restart; }})",
            Self::ensure_runtime_flags_command(),
            remote_config_path.as_ref().display(),
            Self::DEFAULT_PROMETHEUS_CONFIG_PATH,
            remote_rules_path.as_ref().display(),
            Self::RECORDING_RULES_PATH,
            Self::DEFAULT_PORT,
            Self::DEFAULT_PORT,
        )
    }

    /// Generate the global prometheus configuration.
    /// NOTE: The configuration file is a yaml file so spaces are important.
    fn global_configuration(nodes: usize) -> String {
        let scrape_secs = (nodes / 6).max(5);
        let timeout_secs = (scrape_secs / 2).max(3);
        [
            "global:".to_string(),
            format!("  scrape_interval: {scrape_secs}s"),
            format!("  scrape_timeout: {timeout_secs}s"),
            format!("  evaluation_interval: {scrape_secs}s"),
            "rule_files:".to_string(),
            format!("  - {}", Self::RECORDING_RULES_PATH),
            "scrape_configs:".to_string(),
        ]
        .join("\n")
    }

    /// Pre-computed recording rules so Grafana queries hit pre-aggregated
    /// metrics instead of scanning raw data on every refresh.
    pub fn recording_rules() -> String {
        // editorconfig-checker-disable
        "\
groups:
  - name: starfish
    rules:
      - record: starfish:tx_throughput:rate1m
        expr: rate(sequenced_transactions_total[1m])
      - record: starfish:bytes_sent:rate1m
        expr: rate(bytes_sent_total[1m])
      - record: starfish:bytes_received:rate1m
        expr: rate(bytes_received_total[1m])
      - record: starfish:bandwidth:rate1m
        expr: rate(bytes_sent_total[1m]) + rate(bytes_received_total[1m])
      - record: starfish:committed_leaders:rate1m
        expr: rate(committed_leaders_total[1m])
      - record: starfish:network_requests_sent:rate1m
        expr: rate(network_requests_sent_total[1m])
      - record: starfish:network_requests_received:rate1m
        expr: rate(network_requests_received_total[1m])
"
        // editorconfig-checker-enable
        .to_string()
    }

    /// Generate the prometheus configuration from the given metrics path.
    /// NOTE: The configuration file is a yaml file so spaces are important.
    fn scrape_configuration(id: &str, nodes_metrics_path: &str) -> String {
        let parts: Vec<_> = nodes_metrics_path.split('/').collect();
        let address = parts[0].parse::<SocketAddr>().unwrap();
        let ip = address.ip();
        let port = address.port();
        let path = parts[1];

        [
            &format!("  - job_name: instance-{id}"),
            &format!("    metrics_path: /{path}"),
            "    honor_labels: true",
            "    static_configs:",
            "      - targets:",
            &format!("        - {ip}:{port}"),
            "        labels:",
            &format!("          validator: {id}"),
            &format!("  - job_name: instance-node-exporter-{id}"),
            "    static_configs:",
            "      - targets:",
            &format!("        - {ip}:9200"),
            "        labels:",
            &format!("          validator: {id}"),
        ]
        .join("\n")
    }
}

pub struct Grafana;

impl Grafana {
    /// The path to the datasources directory.
    const DATASOURCES_PATH: &'static str = "/etc/grafana/provisioning/datasources";
    /// The path to the dashboards directory.
    const DASHBOARDS_PATH: &'static str = "/etc/grafana/provisioning/dashboards";

    /// The default grafana port.
    pub const DEFAULT_PORT: u16 = 3100;
    /// The UID of the provisioned consensus dashboard.
    pub const DASHBOARD_UID: &'static str = "bdd54ee7-84de-4018-8bb7-92af2defc041";

    /// The commands to install grafana.
    pub fn install_commands() -> Vec<&'static str> {
        vec![
            "sudo apt-get install -y apt-transport-https software-properties-common wget",
            "sudo wget -q -O /etc/apt/keyrings/grafana.key https://apt.grafana.com/gpg.key",
            "(sudo rm /etc/apt/sources.list.d/grafana.list || true)",
            "echo \
                \"deb [signed-by=/etc/apt/keyrings/grafana.key] \
                https://apt.grafana.com stable main\" \
                | sudo tee -a /etc/apt/sources.list.d/grafana.list",
            "sudo apt-get update",
            "sudo apt-get install -y grafana",
            "sudo chmod 777 -R /etc/grafana/",
        ]
    }

    /// Generate the commands to update the grafana datasource and restart
    /// grafana.
    pub fn setup_commands() -> String {
        [
            &format!("(rm -r {} || true)", Self::DATASOURCES_PATH),
            &format!("mkdir -p {}", Self::DATASOURCES_PATH),
            &format!(
                "sudo echo \"{}\" > {}/testbed.yml",
                Self::datasource(),
                Self::DATASOURCES_PATH
            ),
            // setup dashboards
            &format!("(rm -r {} || true)", Self::DASHBOARDS_PATH),
            &format!("mkdir -p {}", Self::DASHBOARDS_PATH),
            &format!(
                "echo \"{}\" | sudo tee {}/provider.yml",
                Self::dashboard_provider(),
                Self::DASHBOARDS_PATH
            ),
            // copy your default dashboard yaml/json
            &format!("sudo cp grafana-dashboard.json {}", Self::DASHBOARDS_PATH),
            // Set custom port and free it in case another process occupies it.
            &format!(
                "sudo sed -i 's/^;\\?http_port = .*/http_port = {}/' /etc/grafana/grafana.ini",
                Self::DEFAULT_PORT
            ),
            &format!("(sudo fuser -k {}/tcp || true)", Self::DEFAULT_PORT),
            "sudo service grafana-server restart",
        ]
        .join(" && ")
    }

    /// Generate the content of the datasource file for the given instance.
    /// NOTE: The datasource file is a yaml file so spaces are important.
    fn datasource() -> String {
        [
            "apiVersion: 1",
            "deleteDatasources:",
            "  - name: testbed",
            "    orgId: 1",
            "datasources:",
            "  - name: testbed",
            "    type: prometheus",
            "    access: proxy",
            "    orgId: 1",
            &format!("    url: http://localhost:{}", Prometheus::DEFAULT_PORT),
            "    editable: true",
            "    uid: Fixed-UID-testbed",
        ]
        .join("\n")
    }

    /// Generate the dashboard provider definition.
    fn dashboard_provider() -> String {
        [
            "apiVersion: 1",
            "providers:",
            "  - name: 'default'",
            "    orgId: 1",
            "    folder: ''",
            "    type: file",
            "    disableDeletion: false",
            "    updateIntervalSeconds: 5",
            "    options:",
            &format!("      path: {}", Self::DASHBOARDS_PATH),
        ]
        .join("\n")
    }
}

/// Collects monitoring data from a remote instance and runs it locally via
/// docker-compose.
pub struct MonitoringCollector {
    ssh_manager: SshConnectionManager,
    monitoring_instance: Instance,
}

impl MonitoringCollector {
    pub fn new(ssh_manager: SshConnectionManager, monitoring_instance: Instance) -> Self {
        Self {
            ssh_manager,
            monitoring_instance,
        }
    }

    /// Stop Prometheus on the remote instance, archive the TSDB data, and
    /// download it locally.
    pub async fn download_prometheus_data(&self, local_dir: &Path) -> MonitorResult<()> {
        let instance = std::iter::once(self.monitoring_instance.clone());

        // Stop prometheus for a clean TSDB snapshot.
        self.ssh_manager
            .execute(
                instance.clone(),
                "sudo service prometheus stop",
                CommandContext::default(),
            )
            .await?;

        // Tar the data directory.
        self.ssh_manager
            .execute(
                instance,
                "tar -czf /tmp/prometheus-data.tar.gz -C /var/lib/prometheus .",
                CommandContext::default(),
            )
            .await?;

        // Download via SCP.
        let connection = self
            .ssh_manager
            .connect(self.monitoring_instance.ssh_address())
            .await?;
        let data = tokio::runtime::Handle::current()
            .spawn_blocking(move || connection.download_bytes("/tmp/prometheus-data.tar.gz"))
            .await
            .unwrap()?;

        // Write and extract locally.
        let archive_path = local_dir.join("prometheus-data.tar.gz");
        fs::write(&archive_path, &data)
            .map_err(|e| MonitorError::Prometheus(format!("Failed to write archive: {e}")))?;

        let prometheus_dir = local_dir.join("prometheus-data");
        fs::create_dir_all(&prometheus_dir).map_err(|e| {
            MonitorError::Prometheus(format!("Failed to create prometheus-data dir: {e}"))
        })?;

        let status = Command::new("tar")
            .args(["xzf"])
            .arg(&archive_path)
            .arg("-C")
            .arg(&prometheus_dir)
            .status()
            .map_err(|e| MonitorError::Prometheus(format!("Failed to run tar: {e}")))?;
        if !status.success() {
            return Err(MonitorError::Prometheus("tar extraction failed".into()));
        }

        // Clean up the archive.
        let _ = fs::remove_file(&archive_path);

        Ok(())
    }

    /// Generate docker-compose.yml, prometheus.yml, and datasource.yaml in the
    /// given directory for local monitoring.
    pub fn generate_local_config(local_dir: &Path) -> MonitorResult<()> {
        let grafana_dir = Self::grafana_dir();
        let grafana_dir = grafana_dir.canonicalize().map_err(|e| {
            MonitorError::GrafanaError(format!(
                "Cannot resolve grafana dir {}: {e}",
                grafana_dir.display()
            ))
        })?;

        let dashboard_provider = grafana_dir.join("dashboard.yaml");
        let dashboard_json = grafana_dir.join("grafana-dashboard.json");

        // Minimal prometheus config — no scrape targets (remote IPs are gone),
        // the TSDB data is already on disk and fully queryable.
        // editorconfig-checker-disable
        let prometheus_yml = "\
global:
  scrape_interval: 15s
  evaluation_interval: 15s
";
        fs::write(local_dir.join("prometheus.yml"), prometheus_yml).map_err(|e| {
            MonitorError::Prometheus(format!("Failed to write prometheus.yml: {e}"))
        })?;

        // Datasource pointing to the docker prometheus service with the UID
        // that the dashboard JSON references.
        let datasource_yml = format!(
            "\
apiVersion: 1
datasources:
  - name: testbed
    type: prometheus
    access: proxy
    orgId: 1
    url: http://prometheus:{}
    editable: true
    uid: Fixed-UID-testbed
",
            Prometheus::DEFAULT_PORT
        );
        fs::write(local_dir.join("datasource.yaml"), datasource_yml).map_err(|e| {
            MonitorError::GrafanaError(format!("Failed to write datasource.yaml: {e}"))
        })?;

        let compose = format!(
            "\
services:
  prometheus:
    image: prom/prometheus
    ports:
      - \"{prom_port}:{prom_port}\"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./prometheus-data:/var/lib/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/var/lib/prometheus/metrics2'
      - '--storage.tsdb.retention.time=90d'
    restart: unless-stopped

  grafana:
    image: grafana/grafana
    ports:
      - \"{grafana_port}:{grafana_port}\"
    depends_on:
      - prometheus
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
    volumes:
      - ./datasource.yaml:/etc/grafana/provisioning/datasources/main.yaml:ro
      - {dashboard_provider}:/etc/grafana/provisioning/dashboards/main.yaml:ro
      - {dashboard_json}:/var/lib/grafana/dashboards/grafana-dashboard.json:ro
    restart: unless-stopped
",
            prom_port = Prometheus::DEFAULT_PORT,
            grafana_port = Grafana::DEFAULT_PORT,
            dashboard_provider = dashboard_provider.display(),
            dashboard_json = dashboard_json.display(),
        );
        // editorconfig-checker-enable
        fs::write(local_dir.join("docker-compose.yml"), compose).map_err(|e| {
            MonitorError::GrafanaError(format!("Failed to write docker-compose.yml: {e}"))
        })?;

        Ok(())
    }

    /// Stop any local docker-compose stacks that may conflict on ports
    /// 3000/9090 (previous collect-monitoring runs or the dry-run stack).
    pub fn stop_conflicting_stacks() {
        // Stop the dry-run stack if running.
        let dryrun_compose: PathBuf = [
            env!("CARGO_MANIFEST_DIR"),
            "..",
            "..",
            "scripts",
            "data",
            "docker-compose.yml",
        ]
        .iter()
        .collect();
        if dryrun_compose.exists() {
            let _ = Command::new("docker")
                .args(["compose", "-f"])
                .arg(&dryrun_compose)
                .arg("down")
                .status();
        }

        // Stop previous collect-monitoring stacks.
        let monitoring_data = PathBuf::from("monitoring-data");
        if monitoring_data.is_dir() {
            if let Ok(entries) = fs::read_dir(&monitoring_data) {
                for entry in entries.flatten() {
                    let compose = entry.path().join("docker-compose.yml");
                    if compose.exists() {
                        let _ = Command::new("docker")
                            .args(["compose", "-f"])
                            .arg(&compose)
                            .arg("down")
                            .status();
                    }
                }
            }
        }
    }

    /// Start the local docker-compose stack.
    pub fn start_local_stack(local_dir: &Path) -> MonitorResult<()> {
        let status = Command::new("docker")
            .args(["compose", "up", "-d"])
            .current_dir(local_dir)
            .status()
            .map_err(|e| {
                MonitorError::GrafanaError(format!("Failed to run docker compose: {e}"))
            })?;
        if !status.success() {
            return Err(MonitorError::GrafanaError(
                "docker compose up -d failed".into(),
            ));
        }

        display::newline();
        display::config(
            "Grafana",
            format!("http://localhost:{}", Grafana::DEFAULT_PORT),
        );
        display::config(
            "Prometheus",
            format!("http://localhost:{}", Prometheus::DEFAULT_PORT),
        );
        display::config("Data directory", local_dir.display());
        display::newline();

        Ok(())
    }

    /// Path to the monitoring/grafana directory in the repo.
    fn grafana_dir() -> PathBuf {
        [
            env!("CARGO_MANIFEST_DIR"),
            "..",
            "..",
            "monitoring",
            "grafana",
        ]
        .iter()
        .collect()
    }
}

/// Generate the commands to setup node exporter on the given instances.
struct NodeExporter;

impl NodeExporter {
    const RELEASE: &'static str = "0.18.1";
    const DEFAULT_PORT: u16 = 9200;
    const SERVICE_PATH: &'static str = "/etc/systemd/system/node_exporter.service";

    pub fn install_commands() -> Vec<String> {
        let build = format!("node_exporter-{}.linux-amd64", Self::RELEASE);
        let source = format!(
            "https://github.com/prometheus/node_exporter/releases/download/v{}/{build}.tar.gz",
            Self::RELEASE
        );

        [
            "(sudo systemctl is-active --quiet node_exporter || exit 0)",
            &format!("curl -LO {source}"),
            &format!(
                "tar -xvf node_exporter-{}.linux-amd64.tar.gz",
                Self::RELEASE
            ),
            &format!(
                "sudo mv node_exporter-{}.linux-amd64/node_exporter /usr/local/bin/",
                Self::RELEASE
            ),
            "sudo useradd -rs /bin/false node_exporter || true",
            "sudo chmod 777 -R /etc/systemd/system/",
            &format!(
                "sudo echo \"{}\" > {}",
                Self::service_config(),
                Self::SERVICE_PATH
            ),
            "sudo systemctl daemon-reload",
            "sudo systemctl start node_exporter",
            "sudo systemctl enable node_exporter",
        ]
        .map(|x| x.to_string())
        .to_vec()
    }

    fn service_config() -> String {
        [
            "[Unit]",
            "Description=Node Exporter",
            "After=network.target",
            "[Service]",
            "User=node_exporter",
            "Group=node_exporter",
            "Type=simple",
            &format!(
                "ExecStart=/usr/local/bin/node_exporter --web.listen-address=:{}",
                Self::DEFAULT_PORT
            ),
            "[Install]",
            "WantedBy=multi-user.target",
        ]
        .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::Prometheus;

    #[test]
    fn prometheus_reload_commands_copy_rules_and_reload() {
        let commands = Prometheus::reload_commands("prometheus.yml", "recording_rules.yml");

        assert!(commands.contains("sudo cp prometheus.yml /etc/prometheus/prometheus.yml"));
        assert!(
            commands.contains("sudo cp recording_rules.yml /etc/prometheus/recording_rules.yml")
        );
        assert!(commands.contains(Prometheus::DEFAULT_PROMETHEUS_ENV_PATH));
        assert!(commands.contains("http://127.0.0.1:9090/-/reload"));
        assert!(commands.contains("--connect-timeout 1"));
        assert!(commands.contains("--max-time 2"));
        assert!(commands.contains("sudo service prometheus restart"));
    }

    #[test]
    fn prometheus_global_configuration_references_recording_rules() {
        let config = Prometheus::global_configuration(60);

        assert!(config.contains("scrape_interval: 10s"));
        assert!(config.contains("scrape_timeout: 5s"));
        assert!(config.contains("evaluation_interval: 10s"));
        assert!(config.contains("rule_files:"));
        assert!(config.contains("/etc/prometheus/recording_rules.yml"));
    }

    #[test]
    fn prometheus_recording_rules_cover_dashboard_series() {
        let rules = Prometheus::recording_rules();

        for metric in [
            "starfish:tx_throughput:rate1m",
            "starfish:bytes_sent:rate1m",
            "starfish:bytes_received:rate1m",
            "starfish:bandwidth:rate1m",
            "starfish:committed_leaders:rate1m",
        ] {
            assert!(
                rules.contains(metric),
                "missing recording rule for {metric}"
            );
        }
    }

    #[test]
    fn prometheus_install_commands_preserve_default_file_and_enable_lifecycle() {
        let commands = Prometheus::install_commands();

        assert!(
            commands
                .iter()
                .any(|c| c.contains(Prometheus::DEFAULT_PROMETHEUS_ENV_PATH))
        );
        assert!(commands.iter().any(|c| c.contains("--web.enable-lifecycle")
            && c.contains("--storage.tsdb.retention.time=30d")
            && c.contains("--storage.tsdb.retention.size=100GB")));
    }
}
