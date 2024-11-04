// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Debug, Display};

use serde::{Deserialize, Serialize};

use crate::{protocol::ProtocolParameters, settings::Settings, ClientParameters, NodeParameters};

/// Shortcut avoiding to use the generic version of the benchmark parameters.
pub type BenchmarkParameters = BenchmarkParametersGeneric<NodeParameters, ClientParameters>;

/// The benchmark parameters for a run. These parameters are stored along with the performance data
/// and should be used to reproduce the results.
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
    /// number Byzantine nodes
    pub byzantine_nodes: usize,
    /// Byzantine strategy
    pub byzantine_strategy: String,
}

impl<N: Debug, C: Debug> Debug for BenchmarkParametersGeneric<N, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}-{:?}-{:?}-{}-{}-{}-{}",
            self.node_parameters,
            self.client_parameters,
            self.settings.faults,
            self.nodes,
            self.byzantine_nodes,
            self.byzantine_strategy,
            self.load
        )
    }
}

impl<N, C> Display for BenchmarkParametersGeneric<N, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} nodes, {} Byzantine, {} strategy ({}) - {} tx/s",
            self.nodes, self.byzantine_nodes, self.byzantine_strategy, self.settings.faults, self.load
        )
    }
}

impl<N: ProtocolParameters, C: ProtocolParameters> BenchmarkParametersGeneric<N, C> {
    /// Make a new benchmark parameters.
    pub fn new_from_loads(
        settings: Settings,
        node_parameters: N,
        client_parameters: C,
        nodes: usize,
        loads: Vec<usize>,
        byzantine_nodes: usize,
        byzantine_strategy: String,
    ) -> Vec<Self> {
        loads
            .into_iter()
            .map(|load| Self {
                settings: settings.clone(),
                node_parameters: node_parameters.clone(),
                client_parameters: client_parameters.clone(),
                nodes,
                load,
                byzantine_nodes: byzantine_nodes.clone(),
                byzantine_strategy: byzantine_strategy.clone(),
            })
            .collect()
    }

    #[cfg(test)]
    pub fn new_for_tests() -> Self {
        Self {
            settings: Settings::new_for_test(),
            node_parameters: N::default(),
            client_parameters: C::default(),
            nodes: 4,
            byzantine_nodes: 0,
            byzantine_strategy: "honest".to_string(),
            load: 500,
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
