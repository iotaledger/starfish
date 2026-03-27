// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    env,
    fmt::Display,
    fs,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    time::Duration,
};

use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{DisplayFromStr, DurationSeconds, serde_as};

use crate::{
    client::{Instance, InstanceStatus},
    error::{SettingsError, SettingsResult},
    faults::FaultsType,
};

/// The git repository holding the codebase.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Repository {
    /// The url of the repository.
    #[serde_as(as = "DisplayFromStr")]
    pub url: Url,
    /// The commit (or branch name) to deploy.
    pub commit: String,
}

impl Default for Repository {
    fn default() -> Self {
        Self {
            url: Url::parse("https://example.com/author/repo").unwrap(),
            commit: "main".into(),
        }
    }
}

impl Repository {
    /// Set the commit to 'unknown'. This options is useful when the
    /// orchestrator cannot be certain of the commit that is running on the
    /// instances. This is a failsafe against reporting wrong commit values
    /// in the measurements.
    pub fn set_unknown_commit(&mut self) {
        self.commit = "unknown".into();
    }

    /// Remove the Github access token from the repository url.
    pub fn remove_access_token(&mut self) {
        self.url.set_password(None).unwrap();
        self.url.set_username("").unwrap();
    }
}

/// The list of supported cloud providers.
#[derive(Serialize, Deserialize, Clone, Default)]
pub enum CloudProvider {
    #[default]
    #[serde(alias = "aws")]
    Aws,
    #[serde(alias = "vultr")]
    Vultr,
}

/// Controls EC2 instance purchasing strategy.
#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SpotPolicy {
    /// Always use on-demand instances.
    #[default]
    OnDemand,
    /// Always use spot instances (cheapest but may be interrupted).
    Spot,
    /// Try spot first; fall back to on-demand if capacity is unavailable.
    Mixed,
}

impl<'de> Deserialize<'de> for SpotPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bool(bool),
            Str(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Bool(true) => Ok(SpotPolicy::Spot),
            Raw::Bool(false) => Ok(SpotPolicy::OnDemand),
            Raw::Str(s) => match s.to_lowercase().as_str() {
                "on_demand" | "ondemand" | "false" => Ok(SpotPolicy::OnDemand),
                "spot" | "true" => Ok(SpotPolicy::Spot),
                "mixed" => Ok(SpotPolicy::Mixed),
                _ => Err(serde::de::Error::custom(format!(
                    "unknown spot policy '{s}', expected on_demand | spot | mixed"
                ))),
            },
        }
    }
}

/// The testbed settings. Those are topically specified in a file.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Settings {
    /// The testbed unique id. This allows multiple users to run concurrent
    /// testbeds on the same cloud provider's account without interference
    /// with each others.
    pub testbed_id: String,
    /// The cloud provider hosting the testbed.
    pub cloud_provider: CloudProvider,
    /// The path to the secret token for authentication with the cloud provider.
    pub token_file: PathBuf,
    /// The ssh private key to access the instances.
    pub ssh_private_key_file: PathBuf,
    /// The corresponding ssh public key registered on the instances. If not
    /// specified. the public key defaults the same path as the private key
    /// with an added extension 'pub'.
    pub ssh_public_key_file: Option<PathBuf>,
    /// The list of cloud provider regions to deploy the testbed.
    pub regions: Vec<String>,
    /// The specs of the instances to deploy. Those are dependent on the cloud
    /// provider, e.g., specifying 't3.medium' creates instances with 2 vCPU
    /// and 4GBo of ram on AWS.
    pub specs: String,
    /// The details of the git reposit to deploy.
    pub repository: Repository,
    /// The path to the node's configuration file. If not specified, the
    /// orchestrator uses the default configurations.
    pub node_parameters_path: Option<String>,
    /// Path to the unified parameters file (`parameters.yaml`). If not
    /// specified, the orchestrator uses the default configurations.
    pub parameters_path: Option<String>,
    /// The duration of the benchmark. The orchestrator stops the benchmark
    /// after this duration. If this value is set to zero, the orchestrator
    /// runs the benchmark indefinitely.
    #[serde(default = "defaults::default_benchmark_duration")]
    #[serde_as(as = "DurationSeconds")]
    pub benchmark_duration: Duration,
    /// The default faults type to apply to the testbed's nodes.
    #[serde(default = "defaults::default_faults_type")]
    pub faults: FaultsType,
    /// The working directory on the remote instance (containing all
    /// configuration files).
    #[serde(default = "defaults::default_working_dir")]
    pub working_dir: PathBuf,
    /// The directory (on the local machine) where to save benchmarks
    /// measurements.
    #[serde(default = "defaults::default_results_dir")]
    pub results_dir: PathBuf,
    /// The directory (on the local machine) where to download logs files from
    /// the instances.
    #[serde(default = "defaults::default_logs_dir")]
    pub logs_dir: PathBuf,
    /// Whether to use NVMe drives for data storage (if available).
    #[serde(default = "defaults::default_use_nvme")]
    pub nvme: bool,
    /// Whether to downloading and analyze the client and node log files.
    #[serde(default = "defaults::default_log_processing")]
    pub log_processing: bool,
    /// Number of instances running only load generators (not nodes). If this
    /// value is set to zero, the orchestrator runs a load generate
    /// collocated with each node.
    #[serde(default = "defaults::default_dedicated_clients")]
    pub dedicated_clients: usize,
    /// Whether to start a grafana and prometheus instance on a dedicate
    /// machine.
    #[serde(default = "defaults::default_monitoring")]
    pub monitoring: bool,
    /// External monitoring server in `[user@]host` format (e.g.,
    /// `root@10.0.1.50` or `monitor.example.com`). When set, the
    /// orchestrator uses this server for Prometheus and Grafana instead
    /// of allocating a cloud instance. The server must authorize the
    /// same public key as `ssh_private_key_file`.
    #[serde(default)]
    pub monitoring_server: Option<String>,
    /// Override whether the monitoring Prometheus should scrape validator
    /// public IPs. When unset, external monitoring servers default to public
    /// IPs while orchestrator-managed monitoring instances follow the
    /// benchmark's network mode.
    #[serde(default)]
    pub monitoring_scrape_public_ip: Option<bool>,
    /// The timeout duration for ssh commands (in seconds).
    #[serde(default = "defaults::default_ssh_timeout")]
    #[serde_as(as = "DurationSeconds")]
    pub ssh_timeout: Duration,
    /// The number of times the orchestrator should retry an ssh command.
    #[serde(default = "defaults::default_ssh_retries")]
    pub ssh_retries: usize,
    /// Pre-built starfish binary. When set, skips git clone + cargo
    /// build on remote machines. If the value starts with "http://" or
    /// "https://", remote machines download it via curl. Otherwise, the
    /// orchestrator treats it as a local path and SCPs it to each machine.
    #[serde(default)]
    pub pre_built_binary: Option<String>,
    /// EC2 instance purchasing strategy: on_demand, spot, or mixed.
    /// Accepts booleans for backwards compatibility (true → spot, false →
    /// on_demand).
    #[serde(default)]
    pub spot: SpotPolicy,
}

mod defaults {
    use std::{path::PathBuf, time::Duration};

    use crate::faults::FaultsType;

    pub fn default_benchmark_duration() -> Duration {
        Duration::from_secs(0)
    }

    pub fn default_faults_type() -> FaultsType {
        FaultsType::default()
    }

    pub fn default_working_dir() -> PathBuf {
        ["~", "working_dir"].iter().collect()
    }

    pub fn default_results_dir() -> PathBuf {
        [".", "results"].iter().collect()
    }

    pub fn default_logs_dir() -> PathBuf {
        [".", "logs"].iter().collect()
    }

    pub fn default_use_nvme() -> bool {
        true
    }

    pub fn default_log_processing() -> bool {
        false
    }

    pub fn default_dedicated_clients() -> usize {
        0
    }

    pub fn default_monitoring() -> bool {
        true
    }

    pub fn default_ssh_timeout() -> Duration {
        Duration::from_secs(30)
    }

    pub fn default_ssh_retries() -> usize {
        3
    }
}

/// Sentinel instance ID for external monitoring servers.
pub const EXTERNAL_MONITORING_ID: &str = "external-monitoring-server";

impl Settings {
    /// Whether monitoring is enabled (either via a cloud instance or an
    /// external server).
    pub fn monitoring_enabled(&self) -> bool {
        self.monitoring || self.monitoring_server.is_some()
    }

    /// Whether the monitoring server is externally managed (not a cloud
    /// instance).
    pub fn is_external_monitoring(&self) -> bool {
        self.monitoring_server.is_some()
    }

    /// Parse `monitoring_server` into `(optional_user, host)`.
    fn parse_monitoring_server(&self) -> Option<(Option<&str>, &str)> {
        self.monitoring_server.as_ref().map(|s| {
            if let Some((user, host)) = s.split_once('@') {
                (Some(user), host)
            } else {
                (None, s.as_str())
            }
        })
    }

    /// Return the SSH username for the external monitoring server, if one
    /// was specified in the `user@host` format.
    pub fn monitoring_ssh_user(&self) -> Option<&str> {
        self.parse_monitoring_server().and_then(|(user, _)| user)
    }

    /// Derive the Pushgateway URL from the external monitoring server, if
    /// configured. For cloud-managed monitoring the URL is derived later
    /// from the allocated instance IP.
    pub fn external_pushgateway_url(&self) -> Option<String> {
        let (_, host) = self.parse_monitoring_server()?;
        Some(format!(
            "http://{}:{}",
            host,
            crate::monitor::Pushgateway::DEFAULT_PORT
        ))
    }

    /// Whether Prometheus should scrape validator public IPs from the
    /// monitoring host.
    pub fn monitoring_scrape_over_public_ip(&self) -> bool {
        self.monitoring_scrape_public_ip
            .unwrap_or(self.is_external_monitoring())
    }

    /// Return the isolated working directory for monitoring assets on the
    /// remote monitoring host. This is a relative path under the SSH user's
    /// home so SCP uploads remain isolated from any existing repository clone.
    pub fn monitoring_working_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(".orchestrator-monitoring");
        path.push(&self.testbed_id);
        path
    }

    /// Resolve the configured external monitoring server to an IPv4 socket
    /// address.
    fn resolve_external_monitoring_address(&self) -> SettingsResult<Option<SocketAddr>> {
        let Some((_, host)) = self.parse_monitoring_server() else {
            return Ok(None);
        };
        if host.is_empty() {
            return Err(SettingsError::MonitoringServerError {
                message: "host is empty".into(),
            });
        }

        let addr = (host, 22u16)
            .to_socket_addrs()
            .map_err(|e| SettingsError::MonitoringServerError {
                message: format!("Failed to resolve '{host}': {e}"),
            })?
            .find(|a| a.is_ipv4())
            .ok_or_else(|| SettingsError::MonitoringServerError {
                message: format!("'{host}' did not resolve to an IPv4 address"),
            })?;

        Ok(Some(addr))
    }

    /// Build a synthetic [`Instance`] representing the external monitoring
    /// server. Returns `None` if `monitoring_server` is not set. Resolves
    /// hostnames via DNS.
    pub fn external_monitoring_instance(&self) -> SettingsResult<Option<Instance>> {
        let Some(addr) = self.resolve_external_monitoring_address()? else {
            return Ok(None);
        };
        let ip = match addr.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => unreachable!(),
        };
        Ok(Some(Instance {
            id: EXTERNAL_MONITORING_ID.into(),
            region: "external".into(),
            main_ip: ip,
            private_ip: ip,
            tags: vec!["monitoring".into()],
            specs: "external".into(),
            status: InstanceStatus::Active,
            spot: false,
            created_at: None,
        }))
    }

    /// Load the settings from a json file.
    pub fn load<P>(path: P) -> SettingsResult<Self>
    where
        P: AsRef<Path> + Display + Clone,
    {
        let invalid = |message: String| SettingsError::InvalidSettings {
            file: path.to_string(),
            message,
        };

        let data = fs::read(path.clone()).map_err(|e| invalid(e.to_string()))?;
        let data = std::str::from_utf8(&data).map_err(|e| invalid(e.to_string()))?;
        let data = Self::resolve_env(&path, data)?;
        let settings: Settings =
            serde_yaml::from_slice(data.as_bytes()).map_err(|e| invalid(e.to_string()))?;

        fs::create_dir_all(&settings.results_dir).map_err(|e| invalid(e.to_string()))?;
        fs::create_dir_all(&settings.logs_dir).map_err(|e| invalid(e.to_string()))?;
        settings
            .resolve_external_monitoring_address()
            .map_err(|e| invalid(e.to_string()))?;

        Ok(settings)
    }

    // Resolves ${ENV} into it's value for each env variable.
    fn resolve_env<P>(path: P, s: &str) -> SettingsResult<String>
    where
        P: AsRef<Path> + Display + Clone,
    {
        let mut s = s.to_string();
        for (name, value) in env::vars() {
            s = s.replace(&format!("${{{}}}", name), &value);
        }
        if s.contains("${") {
            return Err(SettingsError::InvalidSettings {
                file: path.to_string(),
                message: format!("Unresolved env variables {s} in the settings file"),
            });
        }
        Ok(s)
    }

    /// Get the name of the repository (from its url).
    pub fn repository_name(&self) -> String {
        self.repository
            .url
            .path_segments()
            .expect("Url should already be checked when loading settings")
            .collect::<Vec<_>>()[1]
            .split('.')
            .next()
            .unwrap()
            .to_string()
    }

    /// Load the secret token to authenticate with the cloud provider.
    pub fn load_token(&self) -> SettingsResult<String> {
        match fs::read_to_string(&self.token_file) {
            Ok(token) => Ok(token.trim_end_matches('\n').to_string()),
            Err(e) => Err(SettingsError::TokenFileError {
                file: self.token_file.display().to_string(),
                message: e.to_string(),
            }),
        }
    }

    /// Load the ssh public key from file.
    pub fn load_ssh_public_key(&self) -> SettingsResult<String> {
        let ssh_public_key_file = self.ssh_public_key_file.clone().unwrap_or_else(|| {
            let mut private = self.ssh_private_key_file.clone();
            private.set_extension("pub");
            private
        });
        match fs::read_to_string(&ssh_public_key_file) {
            Ok(token) => Ok(token.trim_end_matches('\n').to_string()),
            Err(e) => Err(SettingsError::SshPublicKeyFileError {
                file: ssh_public_key_file.display().to_string(),
                message: e.to_string(),
            }),
        }
    }

    /// Check whether the input instance matches the criteria described in the
    /// settings.
    pub fn filter_instances(&self, instance: &Instance) -> bool {
        self.regions.contains(&instance.region)
            && instance.specs.to_lowercase().replace('.', "")
                == self.specs.to_lowercase().replace('.', "")
    }

    /// The number of regions specified in the settings.
    #[cfg(test)]
    pub fn number_of_regions(&self) -> usize {
        self.regions.len()
    }

    /// Test settings for unit tests.
    #[cfg(test)]
    pub fn new_for_test() -> Self {
        // Create a temporary public key file.
        #[allow(deprecated)] // keep() not available in tempfile 3.6
        let mut path = tempfile::tempdir().unwrap().into_path();
        path.push("test_public_key.pub");
        let public_key = "This is a fake public key for tests";
        fs::write(&path, public_key).unwrap();

        // Return set settings.
        Self {
            testbed_id: "testbed".into(),
            token_file: "/path/to/token/file".into(),
            ssh_private_key_file: "/path/to/private/key/file".into(),
            ssh_public_key_file: Some(path),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use reqwest::Url;

    use crate::settings::{EXTERNAL_MONITORING_ID, Settings};

    #[test]
    fn load_ssh_public_key() {
        let settings = Settings::new_for_test();
        let public_key = settings.load_ssh_public_key().unwrap();
        assert_eq!(public_key, "This is a fake public key for tests");
    }

    #[test]
    fn repository_name() {
        let mut settings = Settings::new_for_test();
        settings.repository.url = Url::parse("https://example.com/author/name").unwrap();
        assert_eq!(settings.repository_name(), "name");
    }

    #[test]
    fn remove_access_token() {
        let mut settings = Settings::new_for_test();
        settings.repository.url = Url::parse("https://TOKEN@example.com/author/name").unwrap();
        settings.repository.remove_access_token();
        assert_eq!(
            settings.repository.url,
            Url::parse("https://example.com/author/name").unwrap()
        );
    }

    #[test]
    fn monitoring_working_dir() {
        let settings = Settings::new_for_test();
        assert_eq!(
            settings.monitoring_working_dir(),
            PathBuf::from(".orchestrator-monitoring/testbed")
        );
    }

    #[test]
    fn external_monitoring_instance() {
        let mut settings = Settings::new_for_test();
        settings.monitoring_server = Some("root@127.0.0.1".into());

        let instance = settings
            .external_monitoring_instance()
            .unwrap()
            .expect("The external monitoring instance is configured");
        assert_eq!(instance.id, EXTERNAL_MONITORING_ID);
        assert_eq!(instance.main_ip.to_string(), "127.0.0.1");
        assert_eq!(settings.monitoring_ssh_user(), Some("root"));
    }

    #[test]
    fn external_monitoring_scrapes_public_ips_by_default() {
        let mut settings = Settings::new_for_test();
        settings.monitoring_server = Some("root@127.0.0.1".into());

        assert!(settings.monitoring_scrape_over_public_ip());
    }

    #[test]
    fn monitoring_scrape_public_ip_override_is_respected() {
        let mut settings = Settings::new_for_test();
        settings.monitoring_server = Some("root@127.0.0.1".into());
        settings.monitoring_scrape_public_ip = Some(false);

        assert!(!settings.monitoring_scrape_over_public_ip());
    }
}
