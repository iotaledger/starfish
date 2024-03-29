// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    env,
    fmt::{Debug, Display},
    fs,
    net::IpAddr,
    num::ParseIntError,
    ops::Deref,
    path::PathBuf,
    str::FromStr,
};

use mysticeti_core::{
    committee::Committee,
    config::{self, NodeParameters, NodePrivateConfig, NodePublicConfig},
    types::AuthorityIndex,
};
use serde::{Deserialize, Serialize};

use super::{ProtocolCommands, ProtocolMetrics, CARGO_FLAGS, RUST_FLAGS};
use crate::{
    benchmark::{BenchmarkParameters, Config},
    client::Instance,
    error::SettingsError,
    settings::Settings,
};

const DEFAULT_NODE_CONFIG_PATH: &str = "orchestrator/assets/node-config.json";

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct MysticetiNodeParameters(NodeParameters);

impl Deref for MysticetiNodeParameters {
    type Target = NodeParameters;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for MysticetiNodeParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.consensus_only {
            write!(f, "c")
        } else {
            write!(f, "fpc")
        }
    }
}

impl Display for MysticetiNodeParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.consensus_only {
            write!(f, "Consensus-only mode")
        } else {
            write!(f, "FPC mode")
        }
    }
}

impl FromStr for MysticetiNodeParameters {
    type Err = SettingsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let reader = || -> Result<Self, std::io::Error> {
            let data = fs::read(s)?;
            let settings: MysticetiNodeParameters = serde_json::from_slice(&data)?;
            Ok(settings)
        };

        reader().map_err(|e| SettingsError::InvalidSettings {
            file: s.to_string(),
            message: e.to_string(),
        })
    }
}

impl Config for MysticetiNodeParameters {}

#[derive(Serialize, Deserialize, Clone)]
pub struct MysticetiClientParameters {
    /// The size of transactions to send to the network in bytes.
    pub transaction_size: usize,
}

impl Default for MysticetiClientParameters {
    fn default() -> Self {
        Self {
            transaction_size: 512,
        }
    }
}

impl Debug for MysticetiClientParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.transaction_size)
    }
}

impl Display for MysticetiClientParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}B transactions", self.transaction_size)
    }
}

impl FromStr for MysticetiClientParameters {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            transaction_size: s.parse()?,
        })
    }
}

impl Config for MysticetiClientParameters {}

/// All configurations information to run a Mysticeti client or validator.
pub struct MysticetiProtocol {
    working_dir: PathBuf,
}

impl ProtocolCommands<MysticetiNodeParameters, MysticetiClientParameters> for MysticetiProtocol {
    fn protocol_dependencies(&self) -> Vec<&'static str> {
        vec![]
    }

    fn db_directories(&self) -> Vec<PathBuf> {
        vec![self.working_dir.join("private/val-*/*")]
    }

    // TODO: Check if this is necessary
    fn cleanup_commands(&self) -> Vec<String> {
        vec!["killall mysticeti".to_string()]
    }

    fn genesis_command<'a, I>(&self, instances: I, parameters: &BenchmarkParameters) -> String
    where
        I: Iterator<Item = &'a Instance>,
    {
        // 1. Upload node config to all instances. Get them from file and add ip addresses.
        // 3. Run the genesis command on all instances to generate the private configuration file and committee file.

        let ips = instances
            .map(|x| x.main_ip.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let working_directory = self.working_dir.display();

        let enable_pipeline = if parameters.node_parameters.enable_pipelining {
            "--enable-pipeline"
        } else {
            ""
        };
        let number_of_leaders = parameters.node_parameters.number_of_leaders;

        let genesis = [
            &format!("{RUST_FLAGS} cargo run {CARGO_FLAGS} --bin mysticeti --"),
            "benchmark-genesis",
            &format!("--ips {ips} --working-directory {working_directory} {enable_pipeline} --number-of-leaders {number_of_leaders}"),
        ]
        .join(" ");

        ["source $HOME/.cargo/env", &genesis].join(" && ")
    }

    // TODO: remove this
    fn monitor_command<I>(&self, instances: I) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        instances
            .into_iter()
            .map(|i| {
                (
                    i,
                    "tail -f --pid=$(pidof mysticeti) -f /dev/null; tail -100 node.log".to_string(),
                )
            })
            .collect()
    }

    fn node_command<I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        todo!();

        // instances
        //     .into_iter()
        //     .enumerate()
        //     .map(|(i, instance)| {
        //         let authority = i as AuthorityIndex;
        //         let committee_path: PathBuf =
        //             [&self.working_dir, &Committee::DEFAULT_FILENAME.into()]
        //                 .iter()
        //                 .collect();
        //         let parameters_path: PathBuf =
        //             [&self.working_dir, &ValidatorPublicParameters::DEFAULT_FILENAME.into()]
        //                 .iter()
        //                 .collect();
        //         let private_configs_path: PathBuf = [
        //             &self.working_dir,
        //             &PrivateConfig::default_filename(authority),
        //         ]
        //         .iter()
        //         .collect();

        //         let env = env::var("ENV").unwrap_or_default();
        //         let run = [
        //             &env,
        //             &format!("{RUST_FLAGS} cargo run {CARGO_FLAGS} --bin mysticeti --"),
        //             "run",
        //             &format!(
        //                 "--authority {authority} --committee-path {}",
        //                 committee_path.display()
        //             ),
        //             &format!(
        //                 "--parameters-path {} --private-config-path {}",
        //                 parameters_path.display(),
        //                 private_configs_path.display()
        //             ),
        //         ]
        //         .join(" ");
        //         let tps = format!("export TPS={}", parameters.load / parameters.nodes);

        //         let tx_size = format!("export TRANSACTION_SIZE={}", parameters.node_config.benchmark_transaction_size);
        //         let consensus_only = if parameters.node_config.consensus_only {
        //             format!("export CONSENSUS_ONLY={}", 1)
        //         } else {
        //             "".to_string()
        //         };
        //         let syncer = format!("export USE_SYNCER={}", 1);
        //         let command = ["#!/bin/bash -e", "source $HOME/.cargo/env", &tps, &tx_size, &consensus_only, &syncer, &run].join("\\n");
        //         let command = format!("echo -e '{command}' > mysticeti-start.sh && chmod +x mysticeti-start.sh && ./mysticeti-start.sh");

        //         (instance, command)
        //     })
        //     .collect()
    }

    fn client_command<I>(
        &self,
        _instances: I,
        _parameters: &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        // TODO
        vec![]
    }
}

impl MysticetiProtocol {
    /// Make a new instance of the Mysticeti protocol commands generator.
    pub fn new(settings: &Settings) -> Self {
        Self {
            working_dir: settings.working_dir.clone(),
        }
    }
}

impl ProtocolMetrics for MysticetiProtocol {
    const BENCHMARK_DURATION: &'static str = "benchmark_duration";
    const TOTAL_TRANSACTIONS: &'static str = "latency_s_count";
    const LATENCY_BUCKETS: &'static str = "latency_s";
    const LATENCY_SUM: &'static str = "latency_s_sum";
    const LATENCY_SQUARED_SUM: &'static str = "latency_squared_s";

    fn nodes_metrics_path<I>(&self, instances: I) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        // let (ips, instances): (_, Vec<_>) = instances
        //     .into_iter()
        //     .map(|x| (IpAddr::V4(x.main_ip), x))
        //     .unzip();
        // let parameters = config::ValidatorPublicParameters::new_for_tests(ips);
        // let metrics_paths = parameters
        //     .all_metric_addresses()
        //     .map(|x| format!("{x}{}", mysticeti_core::prometheus::METRICS_ROUTE));

        // instances.into_iter().zip(metrics_paths).collect()
        todo!()
    }

    fn clients_metrics_path<I>(&self, instances: I) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        // TODO: hack until we have benchmark clients.
        self.nodes_metrics_path(instances)
    }
}
