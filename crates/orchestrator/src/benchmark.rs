// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Debug, Display};

use serde::{Deserialize, Serialize};

use crate::{ClientParameters, NodeParameters, protocol::ProtocolParameters, settings::Settings};

/// Shortcut avoiding to use the generic version of the benchmark parameters.
pub type BenchmarkParameters = BenchmarkParametersGeneric<NodeParameters, ClientParameters>;

/// The benchmark parameters for a run. These parameters are stored along with
/// the performance data and should be used to reproduce the results.
#[derive(Serialize, Deserialize, Clone)]
pub struct BenchmarkParametersGeneric<N, C> {
    /// The testbed settings.
    pub settings: Settings,
    /// The node's configuration parameters.
    pub node_parameters: N,
    /// The client's configuration parameters.
    pub client_parameters: C,
    /// The committee size.
    pub nodes: usize,
    /// The total load (tx/s) to submit to the system.
    pub load: usize,
    /// Flag indicating whether nodes should advertise their
    /// internal or public IP address for inter-node
    /// communication. When running the simulation in multiple
    /// regions, nodes need to use their public IPs to correctly
    /// communicate, however when a simulation is running in a
    /// single VPC, they should use their internal IPs to avoid
    /// paying for data sent between the nodes.
    pub use_internal_ip_address: bool,
    // Consensus protocol to deploy
    // (starfish | starfish-s | starfish-pull | mysticeti
    // | cordial-miners)
    pub consensus_protocol: String,
    /// number Byzantine nodes
    pub byzantine_nodes: usize,
    /// Byzantine strategy
    pub byzantine_strategy: String,
    /// Enable tracing
    pub enable_tracing: bool,
}

impl<N: Debug, C: Debug> Debug for BenchmarkParametersGeneric<N, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}-{:?}-{:?}-{}-{}-{}-{}-{}-{}-{}",
            self.node_parameters,
            self.client_parameters,
            self.settings.faults,
            self.nodes,
            self.consensus_protocol,
            self.byzantine_nodes,
            self.byzantine_strategy,
            self.load,
            self.use_internal_ip_address,
            self.enable_tracing,
        )
    }
}

impl<N, C> Display for BenchmarkParametersGeneric<N, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Consensus choice: {}. Settings:{} nodes, \
            {} Byzantine, {} strategy ({}) - {} tx/s \
            (use internal IPs: {}); enable tracing: {}",
            self.consensus_protocol,
            self.nodes,
            self.byzantine_nodes,
            self.byzantine_strategy,
            self.settings.faults,
            self.load,
            self.use_internal_ip_address,
            self.enable_tracing,
        )
    }
}

impl<N: ProtocolParameters, C: ProtocolParameters> BenchmarkParametersGeneric<N, C> {
    /// Make a new benchmark parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_loads(
        settings: Settings,
        node_parameters: N,
        client_parameters: C,
        nodes: usize,
        use_internal_ip_address: bool,
        loads: Vec<usize>,
        consensus_protocol: String,
        byzantine_nodes: usize,
        byzantine_strategy: String,
        enable_tracing: bool,
    ) -> Vec<Self> {
        loads
            .into_iter()
            .map(|load| Self {
                settings: settings.clone(),
                node_parameters: node_parameters.clone(),
                client_parameters: client_parameters.clone(),
                use_internal_ip_address,
                nodes,
                load,
                consensus_protocol: consensus_protocol.clone(),
                byzantine_nodes,
                byzantine_strategy: byzantine_strategy.clone(),
                enable_tracing,
            })
            .collect()
    }

    #[cfg(test)]
    pub fn new_for_tests() -> Self {
        Self {
            settings: Settings::new_for_test(),
            node_parameters: N::default(),
            client_parameters: C::default(),
            use_internal_ip_address: false,
            nodes: 4,
            consensus_protocol: "starfish".to_string(),
            byzantine_nodes: 0,
            byzantine_strategy: "honest".to_string(),
            load: 500,
            enable_tracing: true,
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::{fmt::Display, str::FromStr};

    use serde::{Deserialize, Serialize};

    use super::ProtocolParameters;

    /// Mock benchmark type for unit tests.
    #[derive(
        Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash, Default,
    )]
    pub struct TestNodeConfig;

    impl Display for TestNodeConfig {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestNodeConfig")
        }
    }

    impl FromStr for TestNodeConfig {
        type Err = ();

        fn from_str(_s: &str) -> Result<Self, Self::Err> {
            Ok(Self {})
        }
    }

    impl ProtocolParameters for TestNodeConfig {}
}
