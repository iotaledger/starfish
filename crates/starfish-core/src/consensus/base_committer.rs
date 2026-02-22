// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{CommitMetastate, LeaderStatus, WAVE_LENGTH};
use crate::block_store::ConsensusProtocol;
use crate::data::Data;
use crate::types::VerifiedStatementBlock;
use crate::{
    block_store::BlockStore,
    committee::{Committee, QuorumThreshold, StakeAggregator},
    types::{format_authority_round, AuthorityIndex, BlockReference, RoundNumber},
};
use std::collections::HashSet;
use std::{fmt::Display, sync::Arc};

/// The consensus protocol operates in 'waves'. Each wave is composed of a leader round, at least one
/// voting round, and one decision round.
type WaveNumber = u64;

#[derive(Clone)]
pub struct BaseCommitterOptions {
    /// The length of a wave (minimum 3)
    pub wave_length: u64,
    /// The offset of the first wave. This is used by the pipelined committer to ensure that each
    /// [`BaseCommitter`] instances operates on a different view of the dag.
    pub round_offset: u64,
}

impl Default for BaseCommitterOptions {
    fn default() -> Self {
        Self {
            wave_length: WAVE_LENGTH,
            round_offset: 0,
        }
    }
}

/// The [`BaseCommitter`] contains the bare bone commit logic. Once instantiated, the method `try_direct_decide`
/// and `try_indirect_decide` can be called at any time and any number of times (it is idempotent) to determine
/// whether a leader can be committed or skipped.
#[derive(Clone)]
pub struct BaseCommitter {
    /// The committee information
    committee: Arc<Committee>,
    /// Keep all block data
    block_store: BlockStore,
    /// The options used by this committer
    options: BaseCommitterOptions,
}

impl BaseCommitter {
    pub fn new(committee: Arc<Committee>, block_store: BlockStore) -> Self {
        Self {
            committee,
            block_store,
            options: BaseCommitterOptions::default(),
        }
    }

    pub fn with_options(mut self, options: BaseCommitterOptions) -> Self {
        assert!(options.wave_length >= WAVE_LENGTH);
        self.options = options;
        self
    }

    /// Return the wave in which the specified round belongs.
    fn wave_number(&self, round: RoundNumber) -> WaveNumber {
        round.saturating_sub(self.options.round_offset) / self.options.wave_length
    }

    /// Return the leader round of the specified wave number. The leader round is always the first
    /// round of the wave.
    fn leader_round(&self, wave: WaveNumber) -> RoundNumber {
        wave * self.options.wave_length + self.options.round_offset
    }

    /// Return the decision round of the specified wave. The decision round is always the last
    /// round of the wave.
    fn decision_round(&self, wave: WaveNumber) -> RoundNumber {
        let wave_length = self.options.wave_length;
        wave * wave_length + wave_length - 1 + self.options.round_offset
    }

    /// The leader-elect protocol is offset by `leader_offset` to ensure that different committers
    /// with different leader offsets elect different leaders for the same round number. This function
    /// returns `None` if there are no leaders for the specified round.
    pub fn elect_leader(&self, round: RoundNumber) -> Option<AuthorityIndex> {
        let wave = self.wave_number(round);
        if self.leader_round(wave) != round {
            return None;
        }
        Some(self.committee.elect_leader(round))
    }

    /// Check whether the specified block (`potential_certificate`) is a certificate for
    /// the specified leader (`leader_block`).
    fn is_certificate(
        &self,
        potential_certificate: &Data<VerifiedStatementBlock>,
        leader_block: &Data<VerifiedStatementBlock>,
        voters_for_leaders: &HashSet<(BlockReference, BlockReference)>,
    ) -> bool {
        let mut votes_stake_aggregator = StakeAggregator::<QuorumThreshold>::new();
        for reference in potential_certificate.includes() {
            let potential_vote = self
                .block_store
                .get_storage_block(*reference)
                .expect("We should have the whole sub-dag by now");

            if voters_for_leaders
                .contains(&(*leader_block.reference(), *potential_vote.reference()))
            {
                //tracing::trace!("[{self}] {potential_vote:?} is a vote for {leader_block:?}");
                if votes_stake_aggregator.add(reference.authority, &self.committee) {
                    return true;
                }
            }
        }
        false
    }

    /// Decide the status of a target leader from the specified anchor. We commit the target leader
    /// if it has a certified link to the anchor. Otherwise, we skip the target leader.
    fn decide_leader_from_anchor(
        &self,
        anchor: &Data<VerifiedStatementBlock>,
        leader: AuthorityIndex,
        leader_round: RoundNumber,
        voters_for_leaders: &HashSet<(BlockReference, BlockReference)>,
    ) -> LeaderStatus {
        // Get the block(s) proposed by the leader. There could be more than one leader block
        // per round (produced by a Byzantine leader).
        let leader_blocks = self
            .block_store
            .get_blocks_at_authority_round(leader, leader_round);

        // Get all blocks that could be potential certificates for the target leader. These blocks
        // are in the decision round of the target leader and are linked to the anchor.
        let wave = self.wave_number(leader_round);
        let decision_round = self.decision_round(wave);
        let decision_blocks = self.block_store.get_blocks_by_round(decision_round);
        let potential_certificates: Vec<_> = decision_blocks
            .iter()
            .filter(|block| self.block_store.linked(anchor, block))
            .collect();

        // Use those potential certificates to determine which (if any) of the target leader
        // blocks can be committed.
        let mut certified_leader_blocks: Vec<_> = leader_blocks
            .into_iter()
            .filter(|leader_block| {
                potential_certificates.iter().any(|potential_certificate| {
                    self.is_certificate(potential_certificate, leader_block, voters_for_leaders)
                })
            })
            .collect();

        // There can be at most one certified leader, otherwise it means the BFT assumption is broken.
        if certified_leader_blocks.len() > 1 {
            panic!("More than one certified block at wave {wave} from leader {leader}")
        }

        // We commit the target leader if it has a certificate that is an ancestor of the anchor.
        // Otherwise skip it.
        match certified_leader_blocks.pop() {
            Some(certified_leader_block) => {
                // For StarfishS: determine metastate via the anchor's path.
                // Paper §2.6 "Indirect rule": if path passes through StrongQC → Opt;
                // otherwise through QC → Std; no path → Skip (handled above).
                let metastate =
                    if self.block_store.consensus_protocol == ConsensusProtocol::StarfishS {
                        let has_strong = potential_certificates.iter().any(|cert| {
                            self.is_certificate(cert, &certified_leader_block, voters_for_leaders)
                                && self.carries_strong_qc(
                                    cert,
                                    &certified_leader_block,
                                    voters_for_leaders,
                                )
                        });
                        if has_strong {
                            Some(CommitMetastate::Opt)
                        } else {
                            Some(CommitMetastate::Std)
                        }
                    } else {
                        None
                    };
                LeaderStatus::Commit(certified_leader_block.clone(), metastate)
            }
            None => LeaderStatus::Skip(leader, leader_round),
        }
    }

    fn decide_skip_starfish(
        &self,
        voting_round: RoundNumber,
        leader: AuthorityIndex,
        voters_for_leaders: &HashSet<(BlockReference, BlockReference)>,
    ) -> bool {
        let voting_blocks = self.block_store.get_blocks_by_round(voting_round);
        let mut blame_stake_aggregator = StakeAggregator::<QuorumThreshold>::new();
        for voting_block in &voting_blocks {
            let voter = voting_block.reference().authority;
            blame_stake_aggregator.add(voter, &self.committee);
        }
        let all_stake_above_quorum =
            blame_stake_aggregator.get_stake_above_quorum_threshold(&self.committee);
        if all_stake_above_quorum == 0 {
            return false;
        }

        let leader_round = voting_round - 1;
        let leader_blocks = self
            .block_store
            .get_blocks_at_authority_round(leader, leader_round);
        let mut to_skip = true;
        for leader_block in &leader_blocks {
            let mut vote_stake_aggregator = StakeAggregator::<QuorumThreshold>::new();
            let leader_block_reference = leader_block.reference();
            for voting_block in &voting_blocks {
                let voter = voting_block.author();
                if voters_for_leaders
                    .contains(&(*leader_block_reference, *voting_block.reference()))
                {
                    //tracing::trace!(
                    //    "[{self}] {voting_block:?} is a blame for leader {}",
                    //    format_authority_round(leader, voting_round - 1)
                    //);
                    vote_stake_aggregator.add(voter, &self.committee);
                }
            }
            let current_stake = vote_stake_aggregator.get_stake();
            if current_stake >= all_stake_above_quorum {
                to_skip = false;
                break;
            }
        }
        to_skip
    }

    /// Check whether the specified leader has enough blames (that is, 2f+1 non-votes) to be
    /// directly skipped.
    fn decide_skip_mysticeti(&self, voting_round: RoundNumber, leader: AuthorityIndex) -> bool {
        let voting_blocks = self.block_store.get_blocks_by_round(voting_round);

        let mut blame_stake_aggregator = StakeAggregator::<QuorumThreshold>::new();
        for voting_block in &voting_blocks {
            let voter = voting_block.reference().authority;
            if voting_block
                .includes()
                .iter()
                .all(|include| include.authority != leader)
            {
                tracing::trace!(
                    "[{self}] {voting_block:?} is a blame for leader {}",
                    format_authority_round(leader, voting_round - 1)
                );
                if blame_stake_aggregator.add(voter, &self.committee) {
                    return true;
                }
            }
        }
        false
    }

    /// Check whether the specified leader has enough support (that is, 2f+1 certificates)
    /// to be directly committed.
    fn enough_leader_support(
        &self,
        decision_round: RoundNumber,
        leader_block: &Data<VerifiedStatementBlock>,
        voters_for_leaders: &HashSet<(BlockReference, BlockReference)>,
    ) -> bool {
        let decision_blocks = self.block_store.get_blocks_by_round(decision_round);

        let mut total_stake_aggregator = StakeAggregator::<QuorumThreshold>::new();
        // Quickly reject if there isn't enough stake to support the leader from
        // the potential certificates.
        let mut early_stop = true;
        for decision_block in &decision_blocks {
            if total_stake_aggregator.add(decision_block.author(), &self.committee) {
                early_stop = false;
                break;
            }
        }
        let total_stake = total_stake_aggregator.get_stake();
        if early_stop {
            tracing::debug!(
                "Not enough support for {leader_block}. Stake not enough: {total_stake} < {}",
                self.committee.quorum_threshold()
            );
            return false;
        }

        let mut certificate_stake_aggregator = StakeAggregator::<QuorumThreshold>::new();
        for decision_block in &decision_blocks {
            let authority = decision_block.reference().authority;
            if self.is_certificate(decision_block, leader_block, voters_for_leaders) {
                //tracing::trace!(
                //    "[{self}] {decision_block:?} is a certificate for leader {leader_block:?}"
                //);
                if certificate_stake_aggregator.add(authority, &self.committee) {
                    return true;
                }
            }
        }
        false
    }

    /// Check whether a single round-(r+2) block carries a StrongQC for the leader.
    /// A block carries StrongQC if its includes contain >=2f+1 round-(r+1) blocks that
    /// both vote for the leader AND carry `strong_vote == true`.
    fn carries_strong_qc(
        &self,
        decision_block: &Data<VerifiedStatementBlock>,
        leader_block: &Data<VerifiedStatementBlock>,
        voters_for_leaders: &HashSet<(BlockReference, BlockReference)>,
    ) -> bool {
        let leader_ref = *leader_block.reference();
        let mut strong_vote_aggregator = StakeAggregator::<QuorumThreshold>::new();
        for reference in decision_block.includes() {
            let voting_block = self
                .block_store
                .get_storage_block(*reference)
                .expect("We should have the whole sub-dag by now");

            if voters_for_leaders.contains(&(leader_ref, *voting_block.reference()))
                && voting_block.strong_vote() == Some(true)
            {
                if strong_vote_aggregator.add(reference.authority, &self.committee) {
                    return true;
                }
            }
        }
        false
    }

    /// For StarfishS direct decide: determine the commit metastate after confirming
    /// 2f+1 QCs exist. Returns `None` for non-StarfishS protocols.
    ///
    /// Paper §2.6 "Direct ToCommit":
    /// - Opt: 2f+1 round-(r+2) blocks each carrying a StrongQC
    /// - Std: strong blame quorum at round r+1
    /// - Pending: neither strong vote nor strong blame quorum
    fn determine_metastate(
        &self,
        leader_block: &Data<VerifiedStatementBlock>,
        voting_round: RoundNumber,
        voters_for_leaders: &HashSet<(BlockReference, BlockReference)>,
    ) -> Option<CommitMetastate> {
        if self.block_store.consensus_protocol != ConsensusProtocol::StarfishS {
            return None;
        }

        // Check for strong blame quorum at round r+1.
        let voting_blocks = self.block_store.get_blocks_by_round(voting_round);
        let leader_ref = *leader_block.reference();

        let mut strong_blame_aggregator = StakeAggregator::<QuorumThreshold>::new();
        let mut has_strong_blame_quorum = false;

        for voting_block in &voting_blocks {
            let voter = voting_block.reference().authority;
            if voters_for_leaders.contains(&(leader_ref, *voting_block.reference())) {
                if voting_block.strong_vote() == Some(false)
                    && strong_blame_aggregator.add(voter, &self.committee)
                {
                    has_strong_blame_quorum = true;
                }
            }
        }

        if has_strong_blame_quorum {
            return Some(CommitMetastate::Std);
        }

        // Check for quorum of StrongQCs at round r+2: count decision-round blocks
        // that each carry a StrongQC, and check if that count reaches 2f+1.
        let leader_round = voting_round - 1;
        let wave = self.wave_number(leader_round);
        let decision_round = self.decision_round(wave);
        let decision_blocks = self.block_store.get_blocks_by_round(decision_round);

        let mut strong_qc_aggregator = StakeAggregator::<QuorumThreshold>::new();
        for decision_block in &decision_blocks {
            if self.carries_strong_qc(decision_block, leader_block, voters_for_leaders) {
                if strong_qc_aggregator.add(decision_block.author(), &self.committee) {
                    return Some(CommitMetastate::Opt);
                }
            }
        }

        Some(CommitMetastate::Pending)
    }

    /// Apply the indirect decision rule to the specified leader to see whether we can indirect-commit
    /// or indirect-skip it.
    #[tracing::instrument(skip_all, fields(leader = %format_authority_round(leader, leader_round)))]
    pub fn try_indirect_decide<'a>(
        &self,
        leader: AuthorityIndex,
        leader_round: RoundNumber,
        leaders: impl Iterator<Item = &'a LeaderStatus>,
        voters_for_leaders: &HashSet<(BlockReference, BlockReference)>,
    ) -> LeaderStatus {
        // The anchor is the first committed leader with round higher than the decision round of the
        // target leader. We must stop the iteration upon encountering an undecided leader.
        let anchors = leaders.filter(|x| leader_round + self.options.wave_length <= x.round());

        for anchor in anchors {
            //tracing::trace!(
            //    "[{self}] Trying to indirect-decide {} using anchor {anchor}",
            //    format_authority_round(leader, leader_round),
            //);
            match anchor {
                LeaderStatus::Commit(anchor, _) => {
                    return self.decide_leader_from_anchor(
                        anchor,
                        leader,
                        leader_round,
                        voters_for_leaders,
                    );
                }
                LeaderStatus::Skip(..) => (),
                LeaderStatus::Undecided(..) => break,
            }
        }

        LeaderStatus::Undecided(leader, leader_round)
    }

    /// Apply the direct decision rule to the specified leader to see whether we can direct-commit or
    /// direct-skip it.
    #[tracing::instrument(skip_all, fields(leader = %format_authority_round(leader, leader_round)))]
    pub fn try_direct_decide(
        &self,
        leader: AuthorityIndex,
        leader_round: RoundNumber,
        voters_for_leaders: &HashSet<(BlockReference, BlockReference)>,
    ) -> LeaderStatus {
        // Check whether the leader has enough blame. That is, whether there are 2f+1 non-votes
        // for that leader (which ensure there will never be a certificate for that leader).
        let voting_round = leader_round + 1;
        match self.block_store.consensus_protocol {
            ConsensusProtocol::StarfishPull
            | ConsensusProtocol::Starfish
            | ConsensusProtocol::StarfishS => {
                if self.decide_skip_starfish(voting_round, leader, voters_for_leaders) {
                    return LeaderStatus::Skip(leader, leader_round);
                }
            }
            ConsensusProtocol::Mysticeti | ConsensusProtocol::CordialMiners => {
                if self.decide_skip_mysticeti(voting_round, leader) {
                    return LeaderStatus::Skip(leader, leader_round);
                }
            }
        }

        // Check whether the leader(s) has enough support. That is, whether there are 2f+1
        // certificates over the leader. Note that there could be more than one leader block
        // (created by Byzantine leaders).
        let wave = self.wave_number(leader_round);
        let decision_round = self.decision_round(wave);
        let leader_blocks = self
            .block_store
            .get_blocks_at_authority_round(leader, leader_round);

        let mut leaders_with_enough_support: Vec<_> = leader_blocks
            .into_iter()
            .filter(|l| self.enough_leader_support(decision_round, l, voters_for_leaders))
            .map(|l| {
                let metastate =
                    self.determine_metastate(&l, voting_round, voters_for_leaders);
                LeaderStatus::Commit(l, metastate)
            })
            .collect();

        // There can be at most one leader with enough support for each round, otherwise it means
        // the BFT assumption is broken.
        if leaders_with_enough_support.len() > 1 {
            panic!(
                "[{self}] More than one certified block for {}",
                format_authority_round(leader, leader_round)
            )
        }

        leaders_with_enough_support
            .pop()
            .unwrap_or_else(|| LeaderStatus::Undecided(leader, leader_round))
    }
}

impl Display for BaseCommitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Committer-Round-Offset{}", self.options.round_offset)
    }
}
