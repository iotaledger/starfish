// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use ::prometheus::Registry;
use eyre::{Context, Result, eyre};

use tokio::sync::mpsc;

use crate::{
    block_handler::{RealBlockHandler, RealCommitHandler},
    committee::Committee,
    config::{NodePrivateConfig, NodePublicConfig, Parameters},
    core::Core,
    crypto::BlsSignatureBytes,
    dag_state::{ConsensusProtocol, DagState},
    metrics::{MetricReporter, Metrics},
    net_sync::NetworkSyncer,
    network::Network,
    prometheus,
    runtime::{JoinError, JoinHandle},
    transactions_generator::TransactionGenerator,
    types::{AuthorityIndex, BlockReference},
};

pub struct Validator {
    network_broadcaster: NetworkSyncer<RealBlockHandler, RealCommitHandler>,
    metrics_handle: JoinHandle<Result<(), std::io::Error>>,
    metrics: Arc<Metrics>,
    reporter: Arc<MetricReporter>,
}

impl Validator {
    pub async fn start(
        authority: AuthorityIndex,
        committee: Arc<Committee>,
        public_config: NodePublicConfig,
        private_config: NodePrivateConfig,
        parameters: Parameters,
        byzantine_strategy: String,
        consensus: String,
    ) -> Result<Self> {
        // Network and metrics setup remains the same
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

        // Boot the prometheus server.
        let registry = Registry::new_custom(
            None,
            Some(HashMap::from([(
                "validator".to_string(),
                format!("validator-{authority}"),
            )])),
        )
        .wrap_err("Failed to create prometheus registry")?;
        #[cfg(target_os = "linux")]
        {
            let pc = ::prometheus::process_collector::ProcessCollector::for_self();
            registry
                .register(Box::new(pc))
                .wrap_err("Failed to register ProcessCollector")?;
        }
        let (metrics, reporter) = Metrics::new(&registry, Some(&committee), Some(&consensus));
        reporter.clone().start();
        let metrics_handle =
            prometheus::start_prometheus_server(binding_metrics_address, &registry);

        // Apply leader_timeout from Parameters to the consensus config.
        let mut public_config = public_config;
        public_config.parameters.leader_timeout = parameters.leader_timeout;

        // Open the DAG state.
        let rocks_path = private_config.rocksdb();
        let recovered = DagState::open(
            authority,
            rocks_path,
            metrics.clone(),
            committee.clone(),
            byzantine_strategy,
            consensus,
            &parameters.storage_backend,
        );

        // Rest of the function remains the same
        let (block_handler, block_sender) = RealBlockHandler::new(&committee);

        TransactionGenerator::start(
            block_sender,
            authority,
            parameters,
            public_config.clone(),
            metrics.clone(),
        );

        let commit_handler =
            RealCommitHandler::new_with_handler(committee.clone(), metrics.clone());
        tracing::info!("Commit handler");

        let is_starfish_l = recovered.dag_state.consensus_protocol == ConsensusProtocol::StarfishL;
        let (dac_outbox_tx, dac_outbox_rx) = if is_starfish_l {
            let (tx, rx) = mpsc::unbounded_channel::<(BlockReference, BlsSignatureBytes)>();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let (core, bls_cert_aggregator) = Core::open(
            block_handler,
            authority,
            committee.clone(),
            private_config,
            metrics.clone(),
            recovered,
            dac_outbox_tx,
        );
        tracing::info!("Core");

        let network = Network::load(
            &public_config,
            authority,
            binding_network_address,
            metrics.clone(),
        )
        .await;
        tracing::info!("Network is created. Starting broadcaster");

        let network_broadcaster = NetworkSyncer::start(
            network,
            core,
            commit_handler,
            metrics.clone(),
            dac_outbox_rx,
            bls_cert_aggregator,
        );

        tracing::info!("Validator {authority} listening on {network_address}");
        tracing::info!("Validator {authority} exposing metrics on {metrics_address}");

        Ok(Self {
            network_broadcaster,
            metrics_handle,
            metrics,
            reporter,
        })
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }
    pub fn reporter(&self) -> Arc<MetricReporter> {
        self.reporter.clone()
    }

    pub async fn await_completion(
        self,
    ) -> (
        Result<(), JoinError>,
        Result<Result<(), std::io::Error>, JoinError>,
    ) {
        tokio::join!(
            self.network_broadcaster.await_completion(),
            self.metrics_handle
        )
    }

    pub async fn stop(self) {
        self.network_broadcaster.shutdown().await;
        self.metrics_handle.abort();
        // Give time for background Worker tasks to detect channel closures and exit,
        // and for TCP sockets to fully release.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod smoke_tests {
    use std::{
        collections::{HashMap, VecDeque},
        fs,
        net::SocketAddr,
        time::Duration,
    };

    use tempfile::TempDir;
    use test_case::test_case;
    use tokio::time;

    use super::Validator;
    use crate::{
        committee::Committee,
        config::{self, NodePrivateConfig, NodePublicConfig, Parameters},
        prometheus,
        types::AuthorityIndex,
    };

    /// Check whether the validator specified by its metrics address has
    /// committed at least once.
    async fn check_commit(address: &SocketAddr) -> Result<bool, reqwest::Error> {
        let route = prometheus::METRICS_ROUTE;
        let res = reqwest::get(format! {"http://{address}{route}"}).await?;
        let string = res.text().await?;
        let commit = string.contains("committed_leaders_total");
        Ok(commit)
    }

    /// Await for all the validators specified by their metrics addresses to
    /// commit.
    async fn await_for_commits(addresses: Vec<SocketAddr>) {
        let mut queue = VecDeque::from(addresses);
        while let Some(address) = queue.pop_front() {
            time::sleep(Duration::from_millis(100)).await;
            match check_commit(&address).await {
                Ok(commits) if commits => (),
                _ => queue.push_back(address),
            }
        }
    }

    async fn run_commit_test(consensus: &str, port_offset: u16) {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let public_config =
            NodePublicConfig::new_for_tests(committee_size).with_port_offset(port_offset);
        let parameters = Parameters::default();

        let dir = TempDir::new().unwrap();
        let private_configs = NodePrivateConfig::new_for_benchmarks(dir.as_ref(), committee_size);
        for pc in &private_configs {
            fs::create_dir_all(&pc.storage_path).unwrap();
        }

        let mut validators = Vec::new();
        for (i, private_config) in private_configs.into_iter().enumerate() {
            let validator = Validator::start(
                i as AuthorityIndex,
                committee.clone(),
                public_config.clone(),
                private_config,
                parameters.clone(),
                "honest".to_string(),
                consensus.to_string(),
            )
            .await
            .unwrap();
            validators.push(validator);
        }

        let addresses = public_config
            .all_metric_addresses()
            .map(|a| a.to_owned())
            .collect();
        let timeout = config::node_defaults::default_leader_timeout() * 5;

        tokio::select! {
            _ = await_for_commits(addresses) => (),
            _ = time::sleep(timeout) => panic!(
                "[{consensus}] Failed to gather commits \
                within a few timeouts"
            ),
        }

        for v in validators {
            v.stop().await;
        }
    }

    #[test_case("mysticeti", 0)]
    #[test_case("starfish-pull", 20)]
    #[test_case("cordial-miners", 40)]
    #[test_case("starfish", 60)]
    #[test_case("starfish-s", 80)]
    #[test_case("starfish-l", 100)]
    #[tokio::test]
    async fn validator_commit(consensus: &str, port_offset: u16) {
        run_commit_test(consensus, port_offset).await;
    }

    async fn run_sync_test(consensus: &str, port_offset: u16) {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let public_config =
            NodePublicConfig::new_for_tests(committee_size).with_port_offset(port_offset);
        let parameters = Parameters::default();

        let dir = TempDir::new().unwrap();
        let private_configs = NodePrivateConfig::new_for_benchmarks(dir.as_ref(), committee_size);
        for pc in &private_configs {
            fs::create_dir_all(&pc.storage_path).unwrap();
        }

        // Boot all validators but one.
        let mut validators = Vec::new();
        for (i, private_config) in private_configs.into_iter().enumerate() {
            if i == 0 {
                continue;
            }
            let validator = Validator::start(
                i as AuthorityIndex,
                committee.clone(),
                public_config.clone(),
                private_config,
                parameters.clone(),
                "honest".to_string(),
                consensus.to_string(),
            )
            .await
            .unwrap();
            validators.push(validator);
        }

        // Boot the last validator after the others commit.
        let addresses = public_config
            .all_metric_addresses()
            .skip(1)
            .map(|a| a.to_owned())
            .collect();
        let timeout = config::node_defaults::default_leader_timeout() * 20;
        tokio::select! {
            _ = await_for_commits(addresses) => (),
            _ = time::sleep(timeout) => panic!(
                "[{consensus}] Failed to gather commits \
                within a few timeouts"
            ),
        }

        // Boot the last validator.
        let private_config =
            NodePrivateConfig::new_for_benchmarks(dir.as_ref(), committee_size).remove(0);
        let validator = Validator::start(
            0 as AuthorityIndex,
            committee.clone(),
            public_config.clone(),
            private_config,
            parameters,
            "honest".to_string(),
            consensus.to_string(),
        )
        .await
        .unwrap();
        validators.push(validator);

        // Ensure the last validator commits.
        let address = public_config
            .all_metric_addresses()
            .next()
            .map(|a| a.to_owned())
            .unwrap();
        let timeout = config::node_defaults::default_leader_timeout() * 5;
        tokio::select! {
            _ = await_for_commits(vec![address]) => (),
            _ = time::sleep(timeout) => panic!("[{consensus}] Late validator failed to commit"),
        }

        for v in validators {
            v.stop().await;
        }
    }

    #[test_case("mysticeti", 100)]
    #[test_case("starfish-pull", 120)]
    #[test_case("cordial-miners", 140)]
    #[test_case("starfish", 160)]
    #[test_case("starfish-s", 180)]
    #[test_case("starfish-l", 200)]
    #[tokio::test]
    async fn validator_sync(consensus: &str, port_offset: u16) {
        run_sync_test(consensus, port_offset).await;
    }

    async fn run_crash_faults_test(consensus: &str, port_offset: u16) {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let public_config =
            NodePublicConfig::new_for_tests(committee_size).with_port_offset(port_offset);
        let parameters = Parameters::default();

        let dir = TempDir::new().unwrap();
        let private_configs = NodePrivateConfig::new_for_benchmarks(dir.as_ref(), committee_size);
        for pc in &private_configs {
            fs::create_dir_all(&pc.storage_path).unwrap();
        }

        let mut validators = Vec::new();
        for (i, private_config) in private_configs.into_iter().enumerate() {
            if i == 0 {
                continue;
            }
            let validator = Validator::start(
                i as AuthorityIndex,
                committee.clone(),
                public_config.clone(),
                private_config,
                parameters.clone(),
                "honest".to_string(),
                consensus.to_string(),
            )
            .await
            .unwrap();
            validators.push(validator);
        }

        let addresses = public_config
            .all_metric_addresses()
            .skip(1)
            .map(|a| a.to_owned())
            .collect();
        let timeout = config::node_defaults::default_leader_timeout() * 15;

        tokio::select! {
            _ = await_for_commits(addresses) => (),
            _ = time::sleep(timeout) => panic!(
                "[{consensus}] Failed to gather commits \
                within a few timeouts"
            ),
        }

        for v in validators {
            v.stop().await;
        }
    }

    #[test_case("mysticeti", 200)]
    #[test_case("starfish-pull", 220)]
    #[test_case("cordial-miners", 240)]
    #[test_case("starfish", 260)]
    #[test_case("starfish-s", 280)]
    #[test_case("starfish-l", 300)]
    #[tokio::test]
    async fn validator_crash_faults(consensus: &str, port_offset: u16) {
        run_crash_faults_test(consensus, port_offset).await;
    }

    /// Scrape commit_index and commit_digest from a validator's Prometheus
    /// endpoint.
    async fn scrape_metrics(address: &SocketAddr) -> Option<(i64, i64)> {
        let route = prometheus::METRICS_ROUTE;
        let text = reqwest::get(format!("http://{address}{route}"))
            .await
            .ok()?
            .text()
            .await
            .ok()?;
        let mut index = None;
        let mut digest = None;
        for line in text.lines() {
            // Handle both "metric VALUE" and "metric{labels} VALUE" formats.
            if line.starts_with("commit_index") {
                index = line
                    .split_whitespace()
                    .last()
                    .and_then(|v| v.parse::<i64>().ok());
            } else if line.starts_with("commit_digest") {
                digest = line
                    .split_whitespace()
                    .last()
                    .and_then(|v| v.parse::<i64>().ok());
            }
        }
        Some((index?, digest?))
    }

    /// Poll until all specified validators reach at least `min_index` commits.
    /// Returns a map from authority index to (commit_index, commit_digest).
    async fn await_min_commit_index(
        addresses: &[(usize, SocketAddr)],
        min_index: i64,
        timeout: Duration,
    ) -> HashMap<usize, (i64, i64)> {
        let deadline = time::Instant::now() + timeout;
        let mut result: HashMap<usize, (i64, i64)> = HashMap::new();
        loop {
            for &(auth, ref addr) in addresses {
                if result
                    .get(&auth)
                    .map(|(idx, _)| *idx >= min_index)
                    .unwrap_or(false)
                {
                    continue;
                }
                if let Some(metrics) = scrape_metrics(addr).await {
                    result.insert(auth, metrics);
                }
            }
            if result.len() == addresses.len() && result.values().all(|(idx, _)| *idx >= min_index)
            {
                return result;
            }
            if time::Instant::now() >= deadline {
                panic!(
                    "Timeout waiting for min_index {min_index}. Current: {:?}",
                    result
                );
            }
            time::sleep(Duration::from_millis(2000)).await;
        }
    }

    /// Among validators grouped by commit_index, verify that those at the
    /// same index have the same digest.
    fn verify_digest_consistency(metrics: &HashMap<usize, (i64, i64)>) {
        let mut by_index: HashMap<i64, Vec<(usize, i64)>> = HashMap::new();
        for (&auth, &(index, digest)) in metrics {
            by_index.entry(index).or_default().push((auth, digest));
        }
        for (index, entries) in &by_index {
            let first_digest = entries[0].1;
            for &(auth, digest) in &entries[1..] {
                assert_eq!(
                    first_digest, digest,
                    "Digest mismatch at commit_index {index}: \
                    authority {auth} has {digest}, \
                    expected {first_digest}",
                );
            }
        }
    }

    /// Start a single validator.
    async fn start_validator(
        authority: usize,
        committee: &std::sync::Arc<crate::committee::Committee>,
        public_config: &NodePublicConfig,
        dir: &std::path::Path,
        committee_size: usize,
        parameters: &Parameters,
        consensus: &str,
    ) -> Validator {
        let private_config =
            NodePrivateConfig::new_for_benchmarks(dir, committee_size).remove(authority);
        Validator::start(
            authority as AuthorityIndex,
            committee.clone(),
            public_config.clone(),
            private_config,
            parameters.clone(),
            "honest".to_string(),
            consensus.to_string(),
        )
        .await
        .unwrap()
    }

    /// Late-join test: start 4 of 5 validators, let them commit for 30s,
    /// then start the 5th. After 30 more seconds verify all 5 have
    /// consistent digests and commit indices within 20 of each other.
    async fn run_lifecycle_test(consensus: &str, port_offset: u16) {
        let committee_size = 5;
        let committee = Committee::new_for_benchmarks(committee_size);
        let public_config =
            NodePublicConfig::new_for_tests(committee_size).with_port_offset(port_offset);
        let parameters = Parameters::default();
        let dir = TempDir::new().unwrap();

        let private_configs = NodePrivateConfig::new_for_benchmarks(dir.as_ref(), committee_size);
        for pc in &private_configs {
            fs::create_dir_all(&pc.storage_path).unwrap();
        }

        let all_metrics_addrs: Vec<(usize, SocketAddr)> =
            public_config.all_metric_addresses().enumerate().collect();

        // ─── Start validators 0..3 (4 out of 5) ───
        let mut validators: Vec<Option<Validator>> = Vec::new();
        for (i, pc) in private_configs.into_iter().enumerate() {
            if i == 4 {
                validators.push(None);
                continue;
            }
            let v = Validator::start(
                i as AuthorityIndex,
                committee.clone(),
                public_config.clone(),
                pc,
                parameters.clone(),
                "honest".to_string(),
                consensus.to_string(),
            )
            .await
            .unwrap();
            validators.push(Some(v));
        }

        // ─── Phase 1: 4 validators run for 30s ───
        time::sleep(Duration::from_secs(30)).await;

        // ─── Start the 5th validator ───
        let v = start_validator(
            4,
            &committee,
            &public_config,
            dir.as_ref(),
            committee_size,
            &parameters,
            consensus,
        )
        .await;
        validators[4] = Some(v);

        // ─── Phase 2: All 5 run for 30s ───
        time::sleep(Duration::from_secs(30)).await;

        // ─── Verify: all 5 committed, consistent digests, indices within 20 ───
        let metrics = await_min_commit_index(&all_metrics_addrs, 1, Duration::from_secs(30)).await;
        verify_digest_consistency(&metrics);

        let indices: Vec<i64> = metrics.values().map(|(i, _)| *i).collect();
        let min_idx = *indices.iter().min().unwrap();
        let max_idx = *indices.iter().max().unwrap();
        assert!(
            max_idx - min_idx <= 20,
            "Commit index spread too large for {consensus}: \
             min={min_idx}, max={max_idx}, spread={}, metrics={metrics:?}", /* editorconfig-checker-disable-line */
            max_idx - min_idx
        );

        // ─── Cleanup ───
        for v in validators.into_iter().flatten() {
            v.stop().await;
        }
    }

    #[test_case("mysticeti", 500)]
    #[test_case("starfish-pull", 520)]
    #[test_case("cordial-miners", 540)]
    #[test_case("starfish", 560)]
    #[test_case("starfish-s", 580)]
    #[test_case("starfish-l", 600)]
    #[tokio::test(flavor = "multi_thread")]
    async fn validator_lifecycle_and_recovery(consensus: &str, port_offset: u16) {
        run_lifecycle_test(consensus, port_offset).await;
    }
}
