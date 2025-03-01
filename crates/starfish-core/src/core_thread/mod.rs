// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "simulator")]
mod simulated;
#[cfg(not(feature = "simulator"))]
mod spawned;

#[cfg(feature = "simulator")]
pub use simulated::*;
#[cfg(not(feature = "simulator"))]
pub use spawned::*;
