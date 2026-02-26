// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::{Debug, Display},
    net::IpAddr,
    ops::Deref,
    path::PathBuf,
};

use super::{BINARY_PATH, ProtocolCommands, ProtocolMetrics, ProtocolParameters};
use crate::{benchmark::BenchmarkParameters, client::Instance, settings::Settings};
use serde::{Deserialize, Serialize};
use starfish_core::{
    config::{self, ClientParameters, NodeParameters},
    types::AuthorityIndex,
};

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct StarfishNodeParameters(NodeParameters);

impl StarfishNodeParameters {
    pub fn default_with_latency(mimic_latency: bool) -> StarfishNodeParameters {
        StarfishNodeParameters(NodeParameters::default_with_latency(mimic_latency))
    }
}

impl Deref for StarfishNodeParameters {
    type Target = NodeParameters;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for StarfishNodeParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "c")
    }
}

impl Display for StarfishNodeParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Consensus-only mode")
    }
}

impl ProtocolParameters for StarfishNodeParameters {}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(transparent)]
pub struct StarfishClientParameters(ClientParameters);

impl Deref for StarfishClientParameters {
    type Target = ClientParameters;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for StarfishClientParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.transaction_size)
    }
}

impl Display for StarfishClientParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}B tx", self.transaction_size)
    }
}

impl ProtocolParameters for StarfishClientParameters {}

pub struct StarfishProtocol {
    working_dir: PathBuf,
}

impl ProtocolCommands for StarfishProtocol {
    fn protocol_dependencies(&self) -> Vec<&'static str> {
        vec!["sudo apt -y install libfontconfig1-dev"]
    }

    fn db_directories(&self) -> Vec<std::path::PathBuf> {
        vec![self.working_dir.join("storage-*")]
    }

    async fn genesis_command<'a, I>(&self, instances: I, parameters: &BenchmarkParameters) -> String
    where
        I: Iterator<Item = &'a Instance>,
    {
        let ips = instances
            .map(|x| {
                match parameters.use_internal_ip_address {
                    true => x.private_ip,
                    false => x.main_ip,
                }
                .to_string()
            })
            .collect::<Vec<_>>()
            .join(" ");

        let node_parameters = parameters.node_parameters.clone();
        let node_parameters_string = serde_yaml::to_string(&node_parameters).unwrap();
        let node_parameters_path = self.working_dir.join("node-parameters.yaml");
        let upload_node_parameters = format!(
            "echo -e '{node_parameters_string}' > {}",
            node_parameters_path.display()
        );

        let mut client_parameters = parameters.client_parameters.clone();
        client_parameters.0.load = parameters.load / parameters.nodes;
        let client_parameters_string = serde_yaml::to_string(&client_parameters).unwrap();
        let client_parameters_path = self.working_dir.join("client-parameters.yaml");
        let upload_client_parameters = format!(
            "echo -e '{client_parameters_string}' > {}",
            client_parameters_path.display()
        );

        let genesis = [
            &format!("./{BINARY_PATH}/starfish"),
            "benchmark-genesis",
            &format!(
                "--ips {ips} --working-directory {} --node-parameters-path {}",
                self.working_dir.display(),
                node_parameters_path.display(),
            ),
        ]
        .join(" ");

        [
            "source $HOME/.cargo/env",
            &upload_node_parameters,
            &upload_client_parameters,
            &genesis,
        ]
        .join(" && ")
    }

    fn node_command<I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        instances
            .into_iter()
            .enumerate()
            .map(|(i, instance)| {
                let authority = i as AuthorityIndex;
                let committee_path = self.working_dir.join("committee.yaml");
                let public_config_path = self.working_dir.join("public-config.yaml");
                let private_config_path = self
                    .working_dir
                    .join(format!("private-config-{authority}.yaml"));
                let client_parameters_path = self.working_dir.join("client-parameters.yaml");
                let byzantine_nodes = parameters.byzantine_nodes;
                let mut byzantine_strategy = "honest".to_string();
                if i % 3 == 0 && i / 3 < byzantine_nodes {
                    byzantine_strategy.clone_from(&parameters.byzantine_strategy);
                }
                let consensus_protocol = parameters.consensus_protocol.clone();

                // Build base command
                let mut command_parts = vec![
                    format!("./{BINARY_PATH}/starfish"),
                    "run".to_string(),
                    format!("--authority {authority}"),
                    format!("--consensus {consensus_protocol}"),
                    format!("--committee-path {}", committee_path.display()),
                    format!("--public-config-path {}", public_config_path.display()),
                    format!("--private-config-path {}", private_config_path.display()),
                    format!(
                        "--client-parameters-path {}",
                        client_parameters_path.display()
                    ),
                ];

                // Add byzantine strategy if needed
                if byzantine_strategy != "honest" {
                    command_parts.push(format!("--byzantine-strategy {}", byzantine_strategy));
                }

                // Add tracing if enabled
                if parameters.enable_tracing {
                    // Add environment variables for tracing
                    let env_vars =
                        "RUST_BACKTRACE=1 RUST_LOG=warn,starfish_core::block_manager=trace,\
                    starfish_core::block_handler=trace,starfish_core::consensus=trace,\
                    starfish_core::net_sync=DEBUG,starfish_core::core=DEBUG,\
                    starfish_core::synchronizer=DEBUG,starfish_core::transactions_generator=DEBUG,\
                    starfish_core::validator=trace,starfish_core::network=trace,\
                    starfish_core::dag_state=trace,starfish_core::threshold_core=trace,\
                    starfish_core::syncer=trace";

                    let run = command_parts.join(" ");
                    command_parts = vec![env_vars.to_string(), run];
                }

                let run = command_parts.join(" ");
                let command = ["source $HOME/.cargo/env", &run].join(" && ");
                (instance, command)
            })
            .collect()
    }

    fn client_command<I>(
        &self,
        _instances: I,
        _parameters: &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        // TODO: Isolate clients from the node (#9).
        vec![]
    }
}

impl ProtocolMetrics for StarfishProtocol {
    const BENCHMARK_DURATION: &'static str = starfish_core::metrics::BENCHMARK_DURATION;

    fn nodes_metrics_path<I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        let (ips, instances): (_, Vec<_>) = instances
            .into_iter()
            .map(|x| {
                (
                    match parameters.use_internal_ip_address {
                        true => IpAddr::V4(x.private_ip),
                        false => IpAddr::V4(x.main_ip),
                    },
                    x,
                )
            })
            .unzip();

        let node_parameters = Some(parameters.node_parameters.deref().clone());
        let node_config = config::NodePublicConfig::new_for_benchmarks(ips, node_parameters);
        let metrics_paths = node_config
            .all_metric_addresses()
            .map(|x| format!("{x}{}", starfish_core::prometheus::METRICS_ROUTE));

        instances.into_iter().zip(metrics_paths).collect()
    }

    fn clients_metrics_path<I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        // NOTE: Hack to avoid clients metrics.
        self.nodes_metrics_path(instances, parameters)
    }
}

impl StarfishProtocol {
    /// Make a new instance of the Mysticeti protocol commands generator.
    pub fn new(settings: &Settings) -> Self {
        Self {
            working_dir: settings.working_dir.clone(),
        }
    }
}
