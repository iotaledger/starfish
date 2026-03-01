// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::cmp::Ordering;

use crate::{
    committee::{Committee, QuorumThreshold, StakeAggregator},
    types::{BlockReference, RoundNumber, VerifiedStatementBlock},
};

pub fn threshold_clock_valid_verified_block(
    block: &VerifiedStatementBlock,
    committee: &Committee,
) -> bool {
    // get a committee from the creator of the block
    let round_number = block.reference().round;
    assert!(round_number > 0);

    // Ensure all includes have a round number smaller than the block round number
    for include in block.block_references() {
        if include.round >= block.reference().round {
            return false;
        }
    }

    let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
    let mut is_quorum = false;
    // Collect the authorities with included blocks at round_number  - 1
    for include in block.block_references() {
        if include.round == round_number - 1 {
            is_quorum = aggregator.add(include.authority, committee);
        }
    }

    // Ensure the set of authorities with includes has a quorum in the current
    // committee
    is_quorum
}

pub struct ThresholdClockAggregator {
    aggregator: StakeAggregator<QuorumThreshold>,
    round: RoundNumber,
}

impl ThresholdClockAggregator {
    pub fn new(round: RoundNumber) -> Self {
        Self {
            aggregator: StakeAggregator::new(),
            round,
        }
    }

    pub fn add_block(&mut self, block: BlockReference, committee: &Committee) {
        match block.round.cmp(&self.round) {
            // Blocks with round less than what we currently build are irrelevant here
            Ordering::Less => {}
            // If we processed block for round r, we also have stored 2f+1 blocks from r-1
            Ordering::Greater => {
                self.aggregator.clear();
                self.aggregator.add(block.authority, committee);
                self.round = block.round;
            }
            Ordering::Equal => {
                if self.aggregator.add(block.authority, committee) {
                    self.aggregator.clear();
                    // We have seen 2f+1 blocks for current round, advance
                    self.round = block.round + 1;
                    tracing::debug!("Advanced round to {}", self.round);
                }
            }
        }
        if block.round > self.round {
            // If we processed block for round r, we also have stored 2f+1 blocks from r-1
            self.round = block.round;
        }
    }

    pub fn get_round(&self) -> RoundNumber {
        self.round
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{crypto::TransactionsCommitment, types::VerifiedStatementBlock};

    fn make_block(authority: u64, round: u64, refs: &[(u64, u64)]) -> VerifiedStatementBlock {
        let block_references: Vec<_> = refs
            .iter()
            .map(|&(a, r)| BlockReference::new_test(a, r))
            .collect();
        VerifiedStatementBlock::new(
            authority,
            round,
            block_references.clone(),
            block_references,
            0,
            false,
            Default::default(),
            vec![],
            None,
            None,
            TransactionsCommitment::default(),
            None,
        )
    }

    #[test]
    fn test_threshold_clock_valid() {
        let committee = Committee::new_test(vec![1, 1, 1, 1]);
        // No includes — not a quorum
        assert!(!threshold_clock_valid_verified_block(
            &make_block(0, 1, &[]),
            &committee
        ));
        // 2 includes at round 0 — below quorum (need 3 of 4)
        assert!(!threshold_clock_valid_verified_block(
            &make_block(0, 1, &[(0, 0), (1, 0)]),
            &committee
        ));
        // 3 includes at round 0 — quorum
        assert!(threshold_clock_valid_verified_block(
            &make_block(0, 1, &[(0, 0), (1, 0), (2, 0)]),
            &committee
        ));
        // 4 includes at round 0 — quorum
        assert!(threshold_clock_valid_verified_block(
            &make_block(0, 1, &[(0, 0), (1, 0), (2, 0), (3, 0)]),
            &committee
        ));
        // Round 2 block: only 2 includes at round 1 — below quorum
        assert!(!threshold_clock_valid_verified_block(
            &make_block(0, 2, &[(0, 1), (1, 1), (2, 0), (3, 0)]),
            &committee
        ));
        // Round 2 block: 3 includes at round 1 — quorum
        assert!(threshold_clock_valid_verified_block(
            &make_block(0, 2, &[(0, 1), (1, 1), (2, 1), (3, 0)]),
            &committee
        ));
    }

    #[test]
    fn test_threshold_clock_aggregator() {
        let committee = Committee::new_test(vec![1, 1, 1, 1]);
        let mut aggregator = ThresholdClockAggregator::new(0);

        aggregator.add_block(BlockReference::new_test(0, 0), &committee);
        assert_eq!(aggregator.get_round(), 0);
        aggregator.add_block(BlockReference::new_test(0, 1), &committee);
        assert_eq!(aggregator.get_round(), 1);
        aggregator.add_block(BlockReference::new_test(1, 0), &committee);
        assert_eq!(aggregator.get_round(), 1);
        aggregator.add_block(BlockReference::new_test(1, 1), &committee);
        assert_eq!(aggregator.get_round(), 1);
        aggregator.add_block(BlockReference::new_test(2, 1), &committee);
        assert_eq!(aggregator.get_round(), 2);
        aggregator.add_block(BlockReference::new_test(3, 1), &committee);
        assert_eq!(aggregator.get_round(), 2);
    }
}
