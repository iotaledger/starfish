// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::data::Data;
use crate::types::VerifiedStatementBlock;
use crate::types::{format_authority_round, AuthorityIndex, RoundNumber};
use std::fmt::Display;

pub mod base_committer;
pub mod linearizer;
pub mod universal_committer;

/// Default wave length for all committers. A longer wave_length increases the chance of committing the leader
/// under asynchrony at the cost of latency in the common case.
pub const WAVE_LENGTH: RoundNumber = 3;

/// The status of every leader output by the committers. While the core only cares about committed
/// leaders, providing a richer status allows for easier debugging, testing, and composition with
/// advanced commit strategies.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum LeaderStatus {
    Commit(Data<VerifiedStatementBlock>),
    Skip(AuthorityIndex, RoundNumber),
    Undecided(AuthorityIndex, RoundNumber),
}

impl LeaderStatus {
    pub fn round(&self) -> RoundNumber {
        match self {
            Self::Commit(block) => block.round(),
            Self::Skip(_, round) => *round,
            Self::Undecided(_, round) => *round,
        }
    }

    pub fn authority(&self) -> AuthorityIndex {
        match self {
            Self::Commit(block) => block.author(),
            Self::Skip(authority, _) => *authority,
            Self::Undecided(authority, _) => *authority,
        }
    }

    pub fn is_decided(&self) -> bool {
        match self {
            Self::Commit(_) => true,
            Self::Skip(_, _) => true,
            Self::Undecided(_, _) => false,
        }
    }

    pub fn into_decided_block(self) -> Option<Data<VerifiedStatementBlock>> {
        match self {
            Self::Commit(block) => Some(block),
            Self::Skip(..) => None,
            Self::Undecided(..) => panic!("Decided block is either Commit or Skip"),
        }
    }
}

impl PartialOrd for LeaderStatus {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LeaderStatus {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.round(), self.authority()).cmp(&(other.round(), other.authority()))
    }
}

impl Display for LeaderStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Commit(block) => write!(f, "Commit({})", block.reference()),
            Self::Skip(a, r) => write!(f, "Skip({})", format_authority_round(*a, *r)),
            Self::Undecided(a, r) => write!(f, "Undecided({})", format_authority_round(*a, *r)),
        }
    }
}
