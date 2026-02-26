// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use ::prometheus::Registry;
use eyre::{Context, Result, eyre};

use crate::metrics::MetricReporter;
use crate::{
    block_handler::{RealBlockHandler, RealCommitHandler},
    committee::Committee,
    config::{ClientParameters, NodePrivateConfig, NodePublicConfig},
    core::{Core, CoreOptions},
    dag_state::DagState,
    metrics::Metrics,
    net_sync::NetworkSyncer,
    network::Network,
    prometheus,
    runtime::{JoinError, JoinHandle},
    transactions_generator::TransactionGenerator,
    types::AuthorityIndex,
};

pub struct Validator {
    network_synchronizer: NetworkSyncer<RealBlockHandler, RealCommitHandler>,
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
        client_parameters: ClientParameters,
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
        let registry = Registry::new();
        let (metrics, reporter) = Metrics::new(&registry, Some(&committee), Some(&consensus));
        reporter.clone().start();
        let metrics_handle =
            prometheus::start_prometheus_server(binding_metrics_address, &registry);

        // Open the DAG state with RocksDB
        let rocks_path = private_config.rocksdb(); // You'll need to add this to NodePrivateConfig
        let recovered = DagState::open(
            authority,
            rocks_path,
            metrics.clone(),
            &committee,
            byzantine_strategy,
            consensus,
        );

        // Rest of the function remains the same
        let (block_handler, block_sender) = RealBlockHandler::new(&committee);

        TransactionGenerator::start(
            block_sender,
            authority,
            client_parameters,
            public_config.clone(),
            metrics.clone(),
        );

        let commit_handler =
            RealCommitHandler::new_with_handler(committee.clone(), metrics.clone());
        tracing::info!("Commit handler");

        let core = Core::open(
            block_handler,
            authority,
            committee.clone(),
            private_config,
            &public_config,
            metrics.clone(),
            recovered,
            CoreOptions::default(),
        );
        tracing::info!("Core");

        let network = Network::load(
            &public_config,
            authority,
            binding_network_address,
            metrics.clone(),
        )
        .await;
        tracing::info!("Network is created. Starting synchronizer");

        let network_synchronizer = NetworkSyncer::start(
            network,
            core,
            commit_handler,
            public_config.parameters.shutdown_grace_period,
            metrics.clone(),
        );

        tracing::info!("Validator {authority} listening on {network_address}");
        tracing::info!("Validator {authority} exposing metrics on {metrics_address}");

        Ok(Self {
            network_synchronizer,
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
            self.network_synchronizer.await_completion(),
            self.metrics_handle
        )
    }

    pub async fn stop(self) {
        self.network_synchronizer.shutdown().await;
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
    use tokio::time;

    use super::Validator;
    use crate::{
        committee::Committee,
        config::{self, ClientParameters, NodePrivateConfig, NodePublicConfig},
        prometheus,
        types::AuthorityIndex,
    };

    const ALL_PROTOCOLS: &[&str] = &[
        "mysticeti",
        "starfish-pull",
        "cordial-miners",
        "starfish",
        "starfish-s",
    ];

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
        let client_parameters = ClientParameters::default();

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
                client_parameters.clone(),
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

    /// Ensure that a committee of honest validators commits for all protocols.
    #[tokio::test]
    async fn validator_commit() {
        for (i, &consensus) in ALL_PROTOCOLS.iter().enumerate() {
            run_commit_test(consensus, i as u16 * 20).await;
        }
    }

    async fn run_sync_test(consensus: &str, port_offset: u16) {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let public_config =
            NodePublicConfig::new_for_tests(committee_size).with_port_offset(port_offset);
        let client_parameters = ClientParameters::default();

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
                client_parameters.clone(),
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
            client_parameters,
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

    /// Ensure validators can sync missing blocks for all protocols.
    #[tokio::test]
    async fn validator_sync() {
        for (i, &consensus) in ALL_PROTOCOLS.iter().enumerate() {
            run_sync_test(consensus, 100 + i as u16 * 20).await;
        }
    }

    async fn run_crash_faults_test(consensus: &str, port_offset: u16) {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let public_config =
            NodePublicConfig::new_for_tests(committee_size).with_port_offset(port_offset);
        let client_parameters = ClientParameters::default();

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
                client_parameters.clone(),
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

    // Ensure that honest validators commit despite the presence
    // of a crash fault, for all protocols.
    #[tokio::test]
    async fn validator_crash_faults() {
        for (i, &consensus) in ALL_PROTOCOLS.iter().enumerate() {
            run_crash_faults_test(consensus, 200 + i as u16 * 20).await;
        }
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
            if let Some(rest) = line.strip_prefix("commit_index ") {
                index = rest.trim().parse::<i64>().ok();
            } else if let Some(rest) = line.strip_prefix("commit_digest ") {
                digest = rest.trim().parse::<i64>().ok();
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
        client_parameters: &ClientParameters,
        consensus: &str,
    ) -> Validator {
        let private_config =
            NodePrivateConfig::new_for_benchmarks(dir, committee_size).remove(authority);
        Validator::start(
            authority as AuthorityIndex,
            committee.clone(),
            public_config.clone(),
            private_config,
            client_parameters.clone(),
            "honest".to_string(),
            consensus.to_string(),
        )
        .await
        .unwrap()
    }

    /// Comprehensive lifecycle test: 5 nodes with digest agreement,
    /// stop/restart recovery, and fresh-DB recovery.
    async fn run_lifecycle_test(consensus: &str, port_offset: u16) {
        let committee_size = 5;
        let committee = Committee::new_for_benchmarks(committee_size);
        let public_config =
            NodePublicConfig::new_for_tests(committee_size).with_port_offset(port_offset);
        let client_parameters = ClientParameters::default();
        let dir = TempDir::new().unwrap();

        let private_configs = NodePrivateConfig::new_for_benchmarks(dir.as_ref(), committee_size);
        for pc in &private_configs {
            fs::create_dir_all(&pc.storage_path).unwrap();
        }

        let all_metrics_addrs: Vec<(usize, SocketAddr)> =
            public_config.all_metric_addresses().enumerate().collect();

        // ─── Start all 5 validators ───
        let mut validators: Vec<Option<Validator>> = Vec::new();
        for (i, pc) in private_configs.into_iter().enumerate() {
            let v = Validator::start(
                i as AuthorityIndex,
                committee.clone(),
                public_config.clone(),
                pc,
                client_parameters.clone(),
                "honest".to_string(),
                consensus.to_string(),
            )
            .await
            .unwrap();
            validators.push(Some(v));
        }

        // ─── Phase 1: All 5 run for 20s ───
        time::sleep(Duration::from_secs(20)).await;

        let phase1 = await_min_commit_index(&all_metrics_addrs, 5, Duration::from_secs(10)).await;
        verify_digest_consistency(&phase1);
        let phase1_min = phase1.values().map(|(i, _)| *i).min().unwrap();

        // ─── Phase 2: Stop node 3, wait 10s, restart, wait 10s ───
        let node_a = 3usize;
        validators[node_a].take().unwrap().stop().await;

        time::sleep(Duration::from_secs(10)).await;

        let running: Vec<_> = all_metrics_addrs
            .iter()
            .filter(|(i, _)| *i != node_a)
            .cloned()
            .collect();
        let phase2a =
            await_min_commit_index(&running, phase1_min + 1, Duration::from_secs(30)).await;
        verify_digest_consistency(&phase2a);
        let phase2a_min = phase2a.values().map(|(i, _)| *i).min().unwrap();

        let v = start_validator(
            node_a,
            &committee,
            &public_config,
            dir.as_ref(),
            committee_size,
            &client_parameters,
            consensus,
        )
        .await;
        validators[node_a] = Some(v);

        let node_a_addr = &[all_metrics_addrs[node_a]];
        await_min_commit_index(node_a_addr, phase2a_min, Duration::from_secs(60)).await;

        // ─── Phase 3: Stop node 1, wait 10s, restart, wait 10s ───
        let node_b = 1usize;
        validators[node_b].take().unwrap().stop().await;

        time::sleep(Duration::from_secs(10)).await;

        let running2: Vec<_> = all_metrics_addrs
            .iter()
            .filter(|(i, _)| *i != node_b && *i != node_a)
            .cloned()
            .collect();
        let phase3a =
            await_min_commit_index(&running2, phase2a_min + 1, Duration::from_secs(45)).await;
        let _phase3a_min = phase3a.values().map(|(i, _)| *i).min().unwrap();

        let v = start_validator(
            node_b,
            &committee,
            &public_config,
            dir.as_ref(),
            committee_size,
            &client_parameters,
            consensus,
        )
        .await;
        validators[node_b] = Some(v);

        time::sleep(Duration::from_secs(10)).await;

        let node_b_addr = &[all_metrics_addrs[node_b]];
        await_min_commit_index(node_b_addr, 1, Duration::from_secs(15)).await;

        // ─── Phase 4: Stop node 0, wipe DB, restart from scratch ───
        let node_c = 0usize;
        validators[node_c].take().unwrap().stop().await;

        let storage_path = dir.as_ref().join(NodePrivateConfig::default_storage_path(
            node_c as AuthorityIndex,
        ));
        let rocks_path = storage_path.join("rocksdb");
        if rocks_path.exists() {
            fs::remove_dir_all(&rocks_path).unwrap();
        }
        fs::create_dir_all(&storage_path).unwrap();

        let v = start_validator(
            node_c,
            &committee,
            &public_config,
            dir.as_ref(),
            committee_size,
            &client_parameters,
            consensus,
        )
        .await;
        validators[node_c] = Some(v);

        time::sleep(Duration::from_secs(20)).await;

        let node_c_addr = &[all_metrics_addrs[node_c]];
        await_min_commit_index(node_c_addr, 1, Duration::from_secs(20)).await;

        // ─── Cleanup ───
        for v in validators.into_iter().flatten() {
            v.stop().await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn validator_lifecycle_and_recovery() {
        for (i, &consensus) in ALL_PROTOCOLS.iter().enumerate() {
            run_lifecycle_test(consensus, 500 + i as u16 * 20).await;
        }
    }
}
