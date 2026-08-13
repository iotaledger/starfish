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
    dag_state::{DagState, ProtocolConfig},
    metrics::{MetricReporter, Metrics},
    net_sync::NetworkSyncer,
    network::Network,
    prometheus,
    runtime::{JoinError, JoinHandle},
    starfish_rbc::RbcProtocolInstanceId,
    transactions_generator::TransactionGenerator,
    types::{AuthorityIndex, BlockAuthenticationScheme, PartialSig},
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
        let protocol_config = ProtocolConfig::from_selection(
            &consensus,
            public_config.parameters.block_authentication.as_deref(),
        )
        .map_err(|error| eyre!(error))?;
        let is_starfish_rbc = protocol_config.consensus_protocol.is_starfish_rbc();
        if public_config.parameters.starfish_rbc_dag_autonomous_clock
            && !public_config.parameters.starfish_rbc_dag_shadow
        {
            return Err(eyre!(
                "Starfish-RBC-DAG autonomous clock requires the RBC-DAG shadow"
            ));
        }
        if public_config
            .parameters
            .starfish_rbc_single_dag_echo_qc_fast_path
            && !protocol_config
                .consensus_protocol
                .is_starfish_rbc_single_dag()
        {
            return Err(eyre!(
                "Starfish-RBC single-DAG ECHO-QC fast path requires consensus \
                 'starfish-rbc-single-dag'"
            ));
        }
        if public_config
            .parameters
            .starfish_rbc_single_dag_echo_qc_fast_path
            && parameters.benchmark_duration.is_none()
        {
            return Err(eyre!(
                "Starfish-RBC single-DAG ECHO-QC fast path is restricted to finite testbed \
                benchmarks"
            ));
        }
        if public_config.parameters.starfish_rbc_dag_autonomous_clock && !is_starfish_rbc {
            return Err(eyre!(
                "Starfish-RBC-DAG autonomous clock requires consensus 'starfish-rbc'"
            ));
        }
        if public_config.parameters.starfish_rbc_dag_shadow && !is_starfish_rbc {
            return Err(eyre!(
                "Starfish-RBC-DAG shadow mode requires consensus 'starfish-rbc'"
            ));
        }
        if public_config
            .parameters
            .starfish_rbc_dag_shadow_buffered_wal
            && !public_config.parameters.starfish_rbc_dag_shadow
        {
            return Err(eyre!(
                "Starfish-RBC-DAG buffered benchmark WAL requires the RBC-DAG shadow"
            ));
        }
        if is_starfish_rbc {
            let protocol_instance = public_config
                .parameters
                .starfish_rbc_protocol_instance
                .ok_or_else(|| eyre!("Starfish-RBC protocol instance is missing"))?;
            RbcProtocolInstanceId::new(protocol_instance).map_err(|error| eyre!(error))?;
        }
        if (is_starfish_rbc
            || protocol_config.block_authentication_scheme == BlockAuthenticationScheme::MacVector)
            && private_config.mac_keys.len() != committee.len()
        {
            return Err(eyre!(
                "MAC keyring length {} does not match committee size {}",
                private_config.mac_keys.len(),
                committee.len(),
            ));
        }
        match protocol_config.block_authentication_scheme {
            BlockAuthenticationScheme::Ed25519 => {
                if committee.get_public_key(authority) != Some(&private_config.keypair.public_key())
                {
                    return Err(eyre!(
                        "Ed25519 private key does not match committee authority {authority}"
                    ));
                }
            }
            BlockAuthenticationScheme::MacVector => {}
            BlockAuthenticationScheme::MlDsa44 => {
                if committee.get_ml_dsa_44_public_key(authority)
                    != Some(&private_config.ml_dsa_44_keypair.public_key())
                {
                    return Err(eyre!(
                        "ML-DSA-44 private key does not match committee authority {authority}"
                    ));
                }
            }
            BlockAuthenticationScheme::MlDsa65 => {
                if committee.get_ml_dsa_65_public_key(authority)
                    != Some(&private_config.ml_dsa_65_keypair.public_key())
                {
                    return Err(eyre!(
                        "ML-DSA-65 private key does not match committee authority {authority}"
                    ));
                }
            }
        }
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
                "node".to_string(),
                format!("node-{authority}"),
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
        let protocol = protocol_config.consensus_protocol;
        let resolved_dissemination =
            protocol.resolve_dissemination_mode(public_config.parameters.dissemination_mode);
        let dissemination_str = resolved_dissemination.to_string();
        let (metrics, reporter) = Metrics::new(
            &registry,
            Some(&committee),
            Some(&consensus),
            Some(&dissemination_str),
        );
        reporter.clone().start();
        let metrics_handle =
            prometheus::start_prometheus_server(binding_metrics_address, &registry);

        // Apply timeouts from Parameters to the consensus config. An explicit
        // leader timeout wins; otherwise use the protocol's pacemaker default
        // (2Δ for Push, 8Δ for Lazy-Push; see Table III).
        let mut public_config = public_config;
        public_config.parameters.leader_timeout = parameters
            .leader_timeout
            .unwrap_or_else(|| protocol.default_leader_timeout());
        public_config.parameters.soft_block_timeout = parameters.soft_block_timeout;

        // Open the DAG state.
        let rocks_path = private_config.rocksdb();
        let recovered = DagState::open_with_protocol_config(
            authority,
            rocks_path,
            metrics.clone(),
            committee.clone(),
            byzantine_strategy,
            protocol_config,
            &parameters.storage_backend,
            public_config
                .parameters
                .enable_strong_vote_adaptive_acknowledgments,
            resolved_dissemination,
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

        let is_starfish_l = recovered.dag_state.consensus_protocol.uses_bls();
        let (partial_sig_tx, partial_sig_rx) = if is_starfish_l {
            let (tx, rx) = mpsc::unbounded_channel::<PartialSig>();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let bls_signer_for_service = if is_starfish_l {
            Some(private_config.bls_keypair.clone())
        } else {
            None
        };
        let starfish_rbc_dag_shadow_wal = if public_config
            .parameters
            .starfish_rbc_dag_shadow_buffered_wal
            && public_config.parameters.starfish_rbc_dag_autonomous_clock
        {
            private_config.starfish_rbc_dag_autonomous_clock_buffered_benchmark_wal()
        } else if public_config
            .parameters
            .starfish_rbc_dag_shadow_buffered_wal
        {
            private_config.starfish_rbc_dag_shadow_buffered_benchmark_wal()
        } else if public_config.parameters.starfish_rbc_dag_autonomous_clock {
            private_config.starfish_rbc_dag_autonomous_clock_wal()
        } else {
            private_config.starfish_rbc_dag_shadow_wal()
        };

        let (core, bls_cert_aggregator) = Core::open(
            block_handler,
            authority,
            committee.clone(),
            private_config,
            metrics.clone(),
            recovered,
            partial_sig_tx,
        );
        let bls_cert_aggregator = bls_cert_aggregator.map(|mut agg| {
            agg.set_num_workers(public_config.parameters.bls_verification_workers);
            agg
        });
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
            public_config.parameters.clone(),
            starfish_rbc_dag_shadow_wal,
            partial_sig_rx,
            bls_cert_aggregator,
            bls_signer_for_service,
        )
        .await;

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
        metrics::{
            STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_FACTOR,
            STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_ROUND_LAG,
        },
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

    #[tokio::test]
    async fn starfish_rbc_dag_shadow_rejects_non_rbc_protocol() {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let mut public_config = NodePublicConfig::new_for_tests(committee_size);
        public_config.parameters.starfish_rbc_dag_shadow = true;
        let private_config =
            NodePrivateConfig::new_for_benchmarks(TempDir::new().unwrap().as_ref(), committee_size)
                .remove(0);

        let result = Validator::start(
            0,
            committee,
            public_config,
            private_config,
            Parameters::default(),
            "honest".to_string(),
            "starfish".to_string(),
        )
        .await;

        assert!(result.is_err_and(|error| {
            error
                .to_string()
                .contains("shadow mode requires consensus 'starfish-rbc'")
        }));
    }

    #[tokio::test]
    async fn autonomous_clock_requires_shadow_mode() {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let mut public_config = NodePublicConfig::new_for_tests(committee_size);
        public_config.parameters.starfish_rbc_dag_autonomous_clock = true;
        public_config
            .parameters
            .refresh_starfish_rbc_protocol_instance();
        let private_config =
            NodePrivateConfig::new_for_benchmarks(TempDir::new().unwrap().as_ref(), committee_size)
                .remove(0);

        let result = Validator::start(
            0,
            committee,
            public_config,
            private_config,
            Parameters::default(),
            "honest".to_string(),
            "starfish-rbc".to_string(),
        )
        .await;

        assert!(result.is_err_and(|error| {
            error
                .to_string()
                .contains("autonomous clock requires the RBC-DAG shadow")
        }));
    }

    #[tokio::test]
    async fn buffered_shadow_wal_requires_shadow_mode() {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let mut public_config = NodePublicConfig::new_for_tests(committee_size);
        public_config
            .parameters
            .starfish_rbc_dag_shadow_buffered_wal = true;
        let private_config =
            NodePrivateConfig::new_for_benchmarks(TempDir::new().unwrap().as_ref(), committee_size)
                .remove(0);

        let result = Validator::start(
            0,
            committee,
            public_config,
            private_config,
            Parameters::default(),
            "honest".to_string(),
            "starfish".to_string(),
        )
        .await;

        assert!(result.is_err_and(|error| {
            error
                .to_string()
                .contains("buffered benchmark WAL requires the RBC-DAG shadow")
        }));
    }

    #[tokio::test]
    async fn autonomous_clock_rejects_non_rbc_protocol() {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let mut public_config = NodePublicConfig::new_for_tests(committee_size);
        public_config.parameters.starfish_rbc_dag_shadow = true;
        public_config.parameters.starfish_rbc_dag_autonomous_clock = true;
        let private_config =
            NodePrivateConfig::new_for_benchmarks(TempDir::new().unwrap().as_ref(), committee_size)
                .remove(0);

        let result = Validator::start(
            0,
            committee,
            public_config,
            private_config,
            Parameters::default(),
            "honest".to_string(),
            "starfish".to_string(),
        )
        .await;

        assert!(result.is_err_and(|error| {
            error
                .to_string()
                .contains("autonomous clock requires consensus 'starfish-rbc'")
        }));
    }

    #[tokio::test]
    async fn autonomous_clock_rejects_zero_heartbeat_interval() {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let mut public_config = NodePublicConfig::new_for_tests(committee_size);
        public_config.parameters.starfish_rbc_dag_shadow = true;
        public_config.parameters.starfish_rbc_dag_autonomous_clock = true;
        public_config
            .parameters
            .starfish_rbc_dag_heartbeat_interval_ms = 0;
        public_config
            .parameters
            .refresh_starfish_rbc_protocol_instance();
        let private_config =
            NodePrivateConfig::new_for_benchmarks(TempDir::new().unwrap().as_ref(), committee_size)
                .remove(0);

        let result = Validator::start(
            0,
            committee,
            public_config,
            private_config,
            Parameters::default(),
            "honest".to_string(),
            "starfish-rbc".to_string(),
        )
        .await;

        assert!(result.is_err_and(|error| {
            error
                .to_string()
                .contains("autonomous heartbeat interval must be greater than zero")
        }));
    }

    async fn run_commit_test(
        consensus: &str,
        block_authentication: Option<&str>,
        port_offset: u16,
    ) {
        run_commit_test_with_shadow(consensus, block_authentication, port_offset, false).await;
    }

    async fn run_commit_test_with_shadow(
        consensus: &str,
        block_authentication: Option<&str>,
        port_offset: u16,
        starfish_rbc_dag_shadow: bool,
    ) {
        run_commit_test_with_shadow_mode(
            consensus,
            block_authentication,
            port_offset,
            starfish_rbc_dag_shadow,
            false,
        )
        .await;
    }

    async fn run_commit_test_with_shadow_mode(
        consensus: &str,
        block_authentication: Option<&str>,
        port_offset: u16,
        starfish_rbc_dag_shadow: bool,
        autonomous_clock: bool,
    ) {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let mut public_config =
            NodePublicConfig::new_for_tests(committee_size).with_port_offset(port_offset);
        public_config.parameters.block_authentication = block_authentication.map(str::to_string);
        public_config.parameters.starfish_rbc_dag_shadow = starfish_rbc_dag_shadow;
        public_config.parameters.starfish_rbc_dag_autonomous_clock = autonomous_clock;
        if autonomous_clock {
            public_config
                .parameters
                .starfish_rbc_dag_heartbeat_interval_ms = 50;
        }
        if consensus == "starfish-rbc" {
            public_config
                .parameters
                .refresh_starfish_rbc_protocol_instance();
        }
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
        // Four RBC authentication variants run in parallel in the full test
        // suite and include expensive ML-DSA signing. Give that composed flow
        // enough scheduling headroom without relaxing existing protocols.
        let timeout_multiplier = if consensus == "starfish-rbc" { 20 } else { 5 };
        let timeout = config::param_defaults::default_leader_timeout() * timeout_multiplier;

        tokio::select! {
            _ = await_for_commits(addresses) => (),
            _ = time::sleep(timeout) => panic!(
                "[{consensus}] Failed to gather commits \
                within a few timeouts"
            ),
        }

        if autonomous_clock {
            tokio::time::timeout(timeout, async {
                loop {
                    if validators.iter().all(|validator| {
                        let metrics = validator.metrics();
                        metrics.starfish_rbc_dag_shadow_clock_valid.get() == 1
                            && metrics.starfish_rbc_dag_shadow_carrier_round.get() > 3
                            && metrics
                                .starfish_rbc_dag_shadow_inputs_total
                                .with_label_values(&["heartbeat", "accepted"])
                                .get()
                                > 0
                            && metrics
                                .starfish_rbc_dag_shadow_wal_durable_records_total
                                .get()
                                > 0
                            && metrics
                                .starfish_rbc_dag_shadow_inputs_total
                                .with_label_values(&["delivery", "shadow"])
                                .get()
                                > 0
                            && metrics.starfish_rbc_dag_shadow_pending_recovery.get() == 0
                    }) {
                        break;
                    }
                    time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("autonomous carrier clock did not advance while direct RBC committed");

            for validator in &validators {
                let metrics = validator.metrics();
                assert_eq!(metrics.starfish_rbc_dag_shadow_clock_valid.get(), 1);
                assert!(metrics.starfish_rbc_dag_shadow_carrier_round.get() > 3);
                assert_eq!(
                    metrics.starfish_rbc_dag_shadow_comparison_valid.get(),
                    0,
                    "autonomous mode must not claim direct-round comparison"
                );
            }
        } else if starfish_rbc_dag_shadow {
            let maximum_unpaired = STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_FACTOR
                * i64::try_from(committee_size).unwrap();
            tokio::time::timeout(timeout, async {
                loop {
                    let complete = validators.iter().all(|validator| {
                        let metrics = validator.metrics();
                        let direct_deliveries = metrics
                            .starfish_rbc_dag_shadow_inputs_total
                            .with_label_values(&["delivery", "direct"])
                            .get();
                        let shadow_deliveries = metrics
                            .starfish_rbc_dag_shadow_inputs_total
                            .with_label_values(&["delivery", "shadow"])
                            .get();
                        let matches = metrics
                            .starfish_rbc_dag_shadow_delivery_comparisons_total
                            .with_label_values(&["match"])
                            .get();
                        metrics.starfish_rbc_dag_shadow_comparison_valid.get() == 1
                            && metrics
                                .starfish_rbc_dag_shadow_wal_durable_records_total
                                .get()
                                > 0
                            && direct_deliveries > 0
                            && shadow_deliveries > 0
                            && matches > 0
                            && metrics.starfish_rbc_dag_shadow_pending_recovery.get() == 0
                            && metrics.starfish_rbc_dag_shadow_unpaired_direct.get()
                                <= maximum_unpaired
                            && metrics.starfish_rbc_dag_shadow_unpaired_shadow.get()
                                <= maximum_unpaired
                            && metrics.starfish_rbc_dag_shadow_unpaired_max_round_lag.get()
                                <= STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_ROUND_LAG
                    });
                    if complete {
                        break;
                    }
                    time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("shadow did not durably deliver and match direct RBC before timeout");

            for validator in &validators {
                let metrics = validator.metrics();
                assert_eq!(
                    metrics.starfish_rbc_dag_shadow_comparison_valid.get(),
                    1,
                    "shadow observation stream shed work while direct RBC committed"
                );
                assert_eq!(
                    metrics
                        .starfish_rbc_dag_shadow_delivery_comparisons_total
                        .with_label_values(&["mismatch"])
                        .get(),
                    0
                );
                assert_eq!(
                    metrics
                        .starfish_rbc_dag_shadow_delivery_comparisons_total
                        .with_label_values(&["direct_only"])
                        .get(),
                    0
                );
                assert_eq!(
                    metrics
                        .starfish_rbc_dag_shadow_delivery_comparisons_total
                        .with_label_values(&["shadow_only"])
                        .get(),
                    0
                );
                assert_eq!(
                    metrics
                        .starfish_rbc_dag_shadow_delivery_comparisons_total
                        .with_label_values(&["ambiguous"])
                        .get(),
                    0
                );
                assert!(metrics.starfish_rbc_dag_shadow_unpaired_direct.get() <= maximum_unpaired);
                assert!(metrics.starfish_rbc_dag_shadow_unpaired_shadow.get() <= maximum_unpaired);
                assert!(
                    metrics.starfish_rbc_dag_shadow_unpaired_max_round_lag.get()
                        <= STARFISH_RBC_DAG_SHADOW_MAX_UNPAIRED_ROUND_LAG
                );
            }
        }

        for v in validators {
            v.stop().await;
        }
    }

    #[test_case("mysticeti", None, 0)]
    #[test_case("mysticeti", Some("ml-dsa-65"), 1280)]
    #[test_case("cordial-miners", None, 40)]
    #[test_case("cordial-miners", Some("ml-dsa-65"), 1300)]
    #[test_case("starfish", None, 60)]
    #[test_case("starfish-mac", None, 700)]
    #[test_case("starfish", Some("ml-dsa-44"), 720)]
    #[test_case("starfish", Some("ml-dsa-65"), 1000)]
    #[test_case("starfish-speed", None, 80)]
    #[test_case("starfish-speed-mac", None, 760)]
    #[test_case("starfish-speed", Some("ml-dsa-44"), 780)]
    #[test_case("starfish-speed", Some("ml-dsa-65"), 1040)]
    #[test_case("starfish-bls", None, 100)]
    #[test_case("starfish-bls", Some("ml-dsa-65"), 1320)]
    #[test_case("sailfish++", None, 120)]
    #[test_case("sailfish++", Some("ml-dsa-65"), 1340)]
    #[test_case("bluestreak", None, 140)]
    #[test_case("mysticeti-bls", None, 160)]
    #[test_case("mysticeti-bls", Some("ml-dsa-65"), 1360)]
    #[test_case("sparse-starfish-speed", None, 180)]
    #[test_case("sparse-starfish-speed-mac", None, 840)]
    #[test_case("sparse-starfish-speed", Some("ml-dsa-44"), 860)]
    #[test_case("sparse-starfish-speed", Some("ml-dsa-65"), 1080)]
    #[test_case("bluestreak-mac", None, 920)]
    #[test_case("bluestreak", Some("ml-dsa-44"), 940)]
    #[test_case("bluestreak", Some("ml-dsa-65"), 1120)]
    #[test_case("starfish-rbc", None, 1400)]
    #[test_case("starfish-rbc", Some("mac"), 1440)]
    #[test_case("starfish-rbc", Some("ml-dsa-44"), 1480)]
    #[test_case("starfish-rbc", Some("ml-dsa-65"), 1520)]
    #[tokio::test]
    async fn validator_commit(
        consensus: &str,
        block_authentication: Option<&str>,
        port_offset: u16,
    ) {
        run_commit_test(consensus, block_authentication, port_offset).await;
    }

    #[tokio::test]
    async fn validator_commit_bluestreak_basic() {
        run_commit_test("bluestreak", None, 150).await;
    }

    #[tokio::test]
    async fn starfish_rbc_dag_shadow_mac_keeps_direct_commits_live() {
        run_commit_test_with_shadow("starfish-rbc", Some("mac"), 1640, true).await;
    }

    #[tokio::test]
    async fn starfish_rbc_dag_autonomous_clock_advances_without_owning_consensus() {
        run_commit_test_with_shadow_mode("starfish-rbc", Some("mac"), 1700, true, true).await;
    }

    #[tokio::test]
    async fn starfish_rbc_single_validator_starts_on_current_thread_runtime() {
        let committee_size = 4;
        // Give the sole running validator quorum stake so startup immediately
        // exercises local RBC proposal construction before any peer connects.
        let committee = Committee::new_test(vec![100, 1, 1, 1]);
        let mut public_config =
            NodePublicConfig::new_for_tests(committee_size).with_port_offset(1600);
        public_config.parameters.block_authentication = Some("mac".to_string());
        public_config
            .parameters
            .refresh_starfish_rbc_protocol_instance();

        let dir = TempDir::new().unwrap();
        let private_config =
            NodePrivateConfig::new_for_benchmarks(dir.as_ref(), committee_size).remove(0);
        fs::create_dir_all(&private_config.storage_path).unwrap();

        let validator = time::timeout(
            Duration::from_secs(5),
            Validator::start(
                0,
                committee,
                public_config,
                private_config,
                Parameters::default(),
                "honest".to_string(),
                "starfish-rbc".to_string(),
            ),
        )
        .await
        .expect("Starfish-RBC startup must not block its async runtime")
        .unwrap();
        validator.stop().await;
    }

    async fn run_sync_test(consensus: &str, block_authentication: Option<&str>, port_offset: u16) {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let mut public_config =
            NodePublicConfig::new_for_tests(committee_size).with_port_offset(port_offset);
        public_config.parameters.block_authentication = block_authentication.map(str::to_string);
        if consensus == "starfish-rbc" {
            public_config
                .parameters
                .refresh_starfish_rbc_protocol_instance();
        }
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
        let timeout = config::param_defaults::default_leader_timeout() * 20;
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
        let timeout = config::param_defaults::default_leader_timeout() * 5;
        tokio::select! {
            _ = await_for_commits(vec![address]) => (),
            _ = time::sleep(timeout) => panic!("[{consensus}] Late validator failed to commit"),
        }

        for v in validators {
            v.stop().await;
        }
    }

    #[test_case("mysticeti", None, 100)]
    #[test_case("cordial-miners", None, 140)]
    #[test_case("starfish", None, 160)]
    #[test_case("starfish-mac", None, 740)]
    #[test_case("starfish", Some("ml-dsa-44"), 1020)]
    #[test_case("starfish", Some("ml-dsa-65"), 1200)]
    #[test_case("starfish-speed", None, 180)]
    #[test_case("starfish-speed-mac", None, 800)]
    #[test_case("starfish-speed", Some("ml-dsa-44"), 820)]
    #[test_case("starfish-speed", Some("ml-dsa-65"), 1220)]
    #[test_case("starfish-bls", None, 200)]
    #[test_case("sailfish++", None, 220)]
    #[test_case("bluestreak", None, 260)]
    #[test_case("mysticeti-bls", None, 280)]
    #[test_case("sparse-starfish-speed", None, 320)]
    #[test_case("sparse-starfish-speed-mac", None, 880)]
    #[test_case("sparse-starfish-speed", Some("ml-dsa-44"), 900)]
    #[test_case("sparse-starfish-speed", Some("ml-dsa-65"), 1240)]
    #[test_case("bluestreak-mac", None, 960)]
    #[test_case("bluestreak", Some("ml-dsa-44"), 980)]
    #[test_case("bluestreak", Some("ml-dsa-65"), 1260)]
    #[test_case("starfish-rbc", Some("mac"), 1560)]
    #[tokio::test]
    async fn validator_sync(consensus: &str, block_authentication: Option<&str>, port_offset: u16) {
        run_sync_test(consensus, block_authentication, port_offset).await;
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
        let timeout = config::param_defaults::default_leader_timeout() * 15;

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
    #[test_case("cordial-miners", 240)]
    #[test_case("starfish", 260)]
    #[test_case("starfish-speed", 280)]
    #[test_case("starfish-bls", 300)]
    #[test_case("sailfish++", 320)]
    #[test_case("bluestreak", 380)]
    #[test_case("mysticeti-bls", 400)]
    #[test_case("sparse-starfish-speed", 420)]
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
                if let Some(metrics) = scrape_metrics(addr).await {
                    // Commit index should be monotonic; keep the max we've
                    // observed to avoid transient scrape glitches from
                    // regressing the snapshot.
                    if result
                        .get(&auth)
                        .is_some_and(|(prev_idx, _)| metrics.0 < *prev_idx)
                    {
                        continue;
                    }
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
        committee: &std::sync::Arc<Committee>,
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
    #[test_case("cordial-miners", 540)]
    #[test_case("starfish", 560)]
    #[test_case("starfish-speed", 580)]
    #[test_case("starfish-bls", 600)]
    #[tokio::test(flavor = "multi_thread")]
    #[test_case("sailfish++", 620)]
    #[test_case("mysticeti-bls", 640)]
    #[test_case("sparse-starfish-speed", 660)]
    async fn validator_lifecycle_and_recovery(consensus: &str, port_offset: u16) {
        run_lifecycle_test(consensus, port_offset).await;
    }
}
