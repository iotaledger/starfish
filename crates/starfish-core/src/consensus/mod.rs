// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use ahash::{AHashMap, AHashSet};

use crate::data::Data;
use crate::types::VerifiedStatementBlock;
use crate::types::{format_authority_round, AuthorityIndex, BlockReference, RoundNumber};
use std::fmt::Display;

pub mod base_committer;
pub mod linearizer;
pub mod universal_committer;

/// Default wave length for all committers. A longer wave_length increases the chance of committing the leader
/// under asynchrony at the cost of latency in the common case.
pub const WAVE_LENGTH: RoundNumber = 3;

/// Cached per-leader voter information, built from scanning voting-round blocks.
#[derive(Clone)]
pub struct VoterInfo {
    /// Set of (leader_block_ref, voter_block_ref) pairs at the voting round.
    pub voters: AHashSet<(BlockReference, BlockReference)>,
    /// strong_vote value for each voter block (populated for StarfishS, empty otherwise).
    pub voter_strong_votes: AHashMap<BlockReference, Option<bool>>,
}

/// Metastate for Starfish-S committed leader slots.
/// Determines the sequencing action for committed leaders.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum CommitMetastate {
    /// Optimistic: strong vote quorum + StrongQC quorum at r+2.
    /// Sequence HistDA(L) then L.acks.
    Opt,
    /// Standard: strong blame quorum observed.
    /// Sequence HistDA(L) only.
    Std,
    /// Pending: neither strong vote nor strong blame quorum yet.
    /// Blocks sequencing until resolved via indirect rule.
    Pending,
}

/// The status of every leader output by the committers. While the core only cares about committed
/// leaders, providing a richer status allows for easier debugging, testing, and composition with
/// advanced commit strategies.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum LeaderStatus {
    /// Committed leader block with optional metastate (Some for StarfishS, None for others).
    Commit(Data<VerifiedStatementBlock>, Option<CommitMetastate>),
    Skip(AuthorityIndex, RoundNumber),
    Undecided(AuthorityIndex, RoundNumber),
}

impl LeaderStatus {
    pub fn round(&self) -> RoundNumber {
        match self {
            Self::Commit(block, _) => block.round(),
            Self::Skip(_, round) => *round,
            Self::Undecided(_, round) => *round,
        }
    }

    pub fn authority(&self) -> AuthorityIndex {
        match self {
            Self::Commit(block, _) => block.author(),
            Self::Skip(authority, _) => *authority,
            Self::Undecided(authority, _) => *authority,
        }
    }

    /// Whether the leader slot has a base decision (Commit or Skip).
    pub fn is_decided(&self) -> bool {
        match self {
            Self::Commit(..) => true,
            Self::Skip(..) => true,
            Self::Undecided(..) => false,
        }
    }

    /// Whether the leader slot is final for sequencing purposes.
    /// A Commit(Pending) is decided but NOT final — it blocks the sequencing prefix.
    /// For non-StarfishS protocols (metastate is None), is_final == is_decided.
    pub fn is_final(&self) -> bool {
        match self {
            Self::Commit(_, Some(CommitMetastate::Pending)) => false,
            Self::Commit(..) => true,
            Self::Skip(..) => true,
            Self::Undecided(..) => false,
        }
    }

    pub fn into_decided_block(
        self,
    ) -> Option<(Data<VerifiedStatementBlock>, Option<CommitMetastate>)> {
        match self {
            Self::Commit(block, meta) => Some((block, meta)),
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
            Self::Commit(block, Some(meta)) => {
                write!(f, "Commit({}, {:?})", block.reference(), meta)
            }
            Self::Commit(block, None) => write!(f, "Commit({})", block.reference()),
            Self::Skip(a, r) => write!(f, "Skip({})", format_authority_round(*a, *r)),
            Self::Undecided(a, r) => write!(f, "Undecided({})", format_authority_round(*a, *r)),
        }
    }
}
