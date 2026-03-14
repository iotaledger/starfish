// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    crypto::{BlsPublicKey, BlsSigner, Signer, dummy_bls_signer, dummy_signer},
    types::{AuthorityIndex, PublicKey, RoundNumber},
};

pub trait ImportExport: Serialize + DeserializeOwned {
    fn load<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        let content = fs::read_to_string(&path)?;
        let object = serde_yaml::from_str(&content).map_err(io::Error::other)?;
        Ok(object)
    }

    fn print<P: AsRef<Path>>(&self, path: P) -> Result<(), io::Error> {
        let content =
            serde_yaml::to_string(self).expect("Failed to serialize object to YAML string");
        fs::write(&path, content)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeParameters {
    #[serde(default = "node_defaults::default_wave_length")]
    pub wave_length: RoundNumber,
    #[serde(default = "param_defaults::default_leader_timeout")]
    pub leader_timeout: Duration,
    #[serde(default = "node_defaults::default_max_block_size")]
    pub max_block_size: usize,
    #[serde(default = "node_defaults::default_enable_broadcaster")]
    pub enable_broadcaster: bool,
    #[serde(default = "node_defaults::default_mimic_latency")]
    pub mimic_latency: bool,
    #[serde(default = "node_defaults::default_uniform_latency_ms")]
    pub uniform_latency_ms: Option<f64>,
    #[serde(default = "node_defaults::default_adversarial_latency")]
    pub adversarial_latency: bool,
    #[serde(default = "node_defaults::default_compress_network")]
    pub compress_network: bool,
    #[serde(default = "node_defaults::default_bls_verification_workers")]
    pub bls_verification_workers: usize,
    #[serde(default)]
    pub dissemination_mode: DisseminationMode,
    #[serde(default = "node_defaults::default_causal_push_shard_round_lag")]
    pub causal_push_shard_round_lag: RoundNumber,
    #[serde(
        default = "node_defaults::default_enable_starfish_speed_adaptive_acknowledgments",
        alias = "enable_starfish_s_adaptive_acknowledgments"
    )]
    pub enable_starfish_speed_adaptive_acknowledgments: bool,
    #[serde(default = "param_defaults::default_soft_block_timeout")]
    pub soft_block_timeout: Duration,
}

pub mod node_defaults {
    use crate::types::RoundNumber;

    pub fn default_wave_length() -> RoundNumber {
        3
    }

    pub fn default_max_block_size() -> usize {
        4 * 1024 * 1024
    }

    pub fn default_enable_broadcaster() -> bool {
        false
    }
    pub fn default_mimic_latency() -> bool {
        true
    }

    pub fn default_uniform_latency_ms() -> Option<f64> {
        None
    }

    pub fn default_adversarial_latency() -> bool {
        false
    }

    pub fn default_compress_network() -> bool {
        false
    }

    pub fn default_bls_verification_workers() -> usize {
        5
    }

    pub fn default_causal_push_shard_round_lag() -> RoundNumber {
        0
    }

    pub fn default_enable_starfish_speed_adaptive_acknowledgments() -> bool {
        true
    }
}

impl Default for NodeParameters {
    fn default() -> Self {
        Self {
            wave_length: node_defaults::default_wave_length(),
            leader_timeout: param_defaults::default_leader_timeout(),
            max_block_size: node_defaults::default_max_block_size(),
            enable_broadcaster: node_defaults::default_enable_broadcaster(),
            mimic_latency: node_defaults::default_mimic_latency(),
            uniform_latency_ms: node_defaults::default_uniform_latency_ms(),
            adversarial_latency: node_defaults::default_adversarial_latency(),
            compress_network: node_defaults::default_compress_network(),
            bls_verification_workers: node_defaults::default_bls_verification_workers(),
            dissemination_mode: DisseminationMode::default(),
            causal_push_shard_round_lag: node_defaults::default_causal_push_shard_round_lag(),
            enable_starfish_speed_adaptive_acknowledgments:
                node_defaults::default_enable_starfish_speed_adaptive_acknowledgments(),
            soft_block_timeout: param_defaults::default_soft_block_timeout(),
        }
    }
}

impl NodeParameters {
    pub fn default_with_latency(mimic_latency: bool) -> Self {
        Self {
            mimic_latency,
            ..Self::default()
        }
    }
}

impl ImportExport for NodeParameters {}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DisseminationMode {
    #[default]
    ProtocolDefault,
    Pull,
    PushCausal,
    PushUseful,
}

impl std::fmt::Display for DisseminationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtocolDefault => write!(f, "protocol-default"),
            Self::Pull => write!(f, "pull"),
            Self::PushCausal => write!(f, "push-causal"),
            Self::PushUseful => write!(f, "push-useful"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeIdentifier {
    pub public_key: PublicKey,
    pub bls_public_key: BlsPublicKey,
    pub network_address: SocketAddr,
    pub metrics_address: SocketAddr,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodePublicConfig {
    pub identifiers: Vec<NodeIdentifier>,
    pub parameters: NodeParameters,
}

impl NodePublicConfig {
    pub const DEFAULT_FILENAME: &'static str = "public-config.yaml";
    pub const PORT_OFFSET_FOR_TESTS: u16 = 1500;

    pub fn new_for_tests(committee_size: usize) -> Self {
        let keys = Signer::new_for_test(committee_size);
        let bls_keys = BlsSigner::new_for_test(committee_size);
        let ips = vec![IpAddr::V4(Ipv4Addr::LOCALHOST); committee_size];
        let benchmark_port_offset = ips.len() as u16;
        let mut identifiers = Vec::new();
        for (i, ((ip, key), bls_key)) in ips
            .into_iter()
            .zip(keys.into_iter())
            .zip(bls_keys.into_iter())
            .enumerate()
        {
            let public_key = key.public_key();
            let bls_public_key = bls_key.public_key();
            let network_port = Self::PORT_OFFSET_FOR_TESTS + i as u16;
            let metrics_port = benchmark_port_offset + network_port;
            let network_address = SocketAddr::new(ip, network_port);
            let metrics_address = SocketAddr::new(ip, metrics_port);
            identifiers.push(NodeIdentifier {
                public_key,
                bls_public_key,
                network_address,
                metrics_address,
            });
        }

        Self {
            identifiers,
            parameters: NodeParameters::default(),
        }
    }

    pub fn new_for_benchmarks(ips: Vec<IpAddr>, node_parameters: Option<NodeParameters>) -> Self {
        let default_with_ips = Self::new_for_tests(ips.len()).with_ips(ips);
        Self {
            identifiers: default_with_ips.identifiers,
            parameters: node_parameters.unwrap_or_default(),
        }
    }

    pub fn with_ips(mut self, ips: Vec<IpAddr>) -> Self {
        for (id, ip) in self.identifiers.iter_mut().zip(ips) {
            id.network_address.set_ip(ip);
            id.metrics_address.set_ip(ip);
        }
        self
    }

    pub fn with_port_offset(mut self, port_offset: u16) -> Self {
        for id in self.identifiers.iter_mut() {
            id.network_address
                .set_port(id.network_address.port() + port_offset);
            id.metrics_address
                .set_port(id.metrics_address.port() + port_offset);
        }
        self
    }

    /// Return all network addresses (including our own) in the order of the
    /// authority index.
    pub fn all_network_addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.identifiers.iter().map(|id| id.network_address)
    }

    /// Return all metric addresses (including our own) in the order of the
    /// authority index.
    pub fn all_metric_addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.identifiers.iter().map(|id| id.metrics_address)
    }

    pub fn network_address(&self, authority: AuthorityIndex) -> Option<SocketAddr> {
        self.identifiers
            .get(authority as usize)
            .map(|id| id.network_address)
    }

    pub fn metrics_address(&self, authority: AuthorityIndex) -> Option<SocketAddr> {
        self.identifiers
            .get(authority as usize)
            .map(|id| id.metrics_address)
    }
}

impl ImportExport for NodePublicConfig {}

#[derive(Serialize, Deserialize)]
pub struct NodePrivateConfig {
    authority: AuthorityIndex,
    pub keypair: Signer,
    pub bls_keypair: BlsSigner,
    pub storage_path: PathBuf,
}

impl NodePrivateConfig {
    pub fn new_for_tests(index: AuthorityIndex) -> Self {
        Self {
            authority: index,
            keypair: dummy_signer(),
            bls_keypair: dummy_bls_signer(),
            storage_path: PathBuf::from("storage"),
        }
    }

    pub fn new_for_benchmarks(working_dir: &Path, committee_size: usize) -> Vec<Self> {
        let signers = Signer::new_for_test(committee_size);
        let bls_signers = BlsSigner::new_for_test(committee_size);
        signers
            .into_iter()
            .zip(bls_signers)
            .enumerate()
            .map(|(i, (keypair, bls_keypair))| {
                let authority = i as AuthorityIndex;
                let path = working_dir.join(NodePrivateConfig::default_storage_path(authority));
                Self {
                    authority,
                    keypair,
                    bls_keypair,
                    storage_path: path,
                }
            })
            .collect()
    }

    pub fn default_filename(authority: AuthorityIndex) -> PathBuf {
        format!("private-config-{authority}.yaml").into()
    }

    pub fn default_storage_path(authority: AuthorityIndex) -> PathBuf {
        format!("storage-{authority}").into()
    }

    pub fn certified_transactions_log(&self) -> PathBuf {
        self.storage_path.join("certified.txt")
    }

    pub fn committed_transactions_log(&self) -> PathBuf {
        self.storage_path.join("committed.txt")
    }

    pub fn rocksdb(&self) -> PathBuf {
        self.storage_path.join("rocksdb")
    }
}

impl ImportExport for NodePrivateConfig {}

/// How transaction payloads are filled by the generator.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionMode {
    /// 8 B timestamp + 8 B counter + zero-padded (current default).
    #[default]
    AllZero,
    /// 8 B timestamp + random bytes for the rest.
    Random,
}

/// Which storage backend to use for the DAG.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackend {
    #[default]
    Rocksdb,
    Tidehunter,
}

/// Unified experiment parameters — loaded from `parameters.yaml`.
///
/// Replaces the old `client-parameters.yaml`. Includes transaction generation
/// knobs, storage backend selection, and consensus tuning in a single file.
#[derive(Serialize, Deserialize, Clone)]
pub struct Parameters {
    /// Transactions per second (total; divided across nodes by the
    /// orchestrator).
    #[serde(default = "param_defaults::default_load")]
    pub load: usize,
    /// Size of each transaction in bytes.
    #[serde(default = "param_defaults::default_transaction_size")]
    pub transaction_size: usize,
    /// Delay before the generator starts sending transactions.
    #[serde(default = "param_defaults::default_initial_delay")]
    pub initial_delay: Duration,
    /// How to fill transaction payloads.
    #[serde(default)]
    pub transaction_mode: TransactionMode,
    /// Which storage backend to use for the DAG.
    #[serde(default)]
    pub storage_backend: StorageBackend,
    /// Leader timeout for the consensus protocol.
    #[serde(default = "param_defaults::default_leader_timeout")]
    pub leader_timeout: Duration,
    /// StarfishSpeed soft block-creation timeout (relaxed readiness).
    #[serde(default = "param_defaults::default_soft_block_timeout")]
    pub soft_block_timeout: Duration,
}

impl Parameters {
    pub const DEFAULT_FILENAME: &'static str = "parameters.yaml";

    pub fn almost_default(load: usize) -> Self {
        Self {
            load,
            ..Self::default()
        }
    }
}

pub(crate) mod param_defaults {
    use super::Duration;

    pub fn default_load() -> usize {
        10
    }

    pub fn default_transaction_size() -> usize {
        512
    }

    pub fn default_initial_delay() -> Duration {
        Duration::from_secs(10)
    }

    pub fn default_leader_timeout() -> Duration {
        Duration::from_millis(400)
    }

    pub fn default_soft_block_timeout() -> Duration {
        Duration::from_millis(200)
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            load: param_defaults::default_load(),
            transaction_size: param_defaults::default_transaction_size(),
            initial_delay: param_defaults::default_initial_delay(),
            transaction_mode: TransactionMode::default(),
            storage_backend: StorageBackend::default(),
            leader_timeout: param_defaults::default_leader_timeout(),
            soft_block_timeout: param_defaults::default_soft_block_timeout(),
        }
    }
}

impl ImportExport for Parameters {}
