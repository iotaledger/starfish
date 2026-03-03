// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::cmp::Ordering;

use crate::{
    committee::{Committee, QuorumThreshold, StakeAggregator},
    types::{BlockHeader, BlockReference, RoundNumber},
};

pub fn threshold_clock_valid_block_header(header: &BlockHeader, committee: &Committee) -> bool {
    let round_number = header.reference().round;
    assert!(round_number > 0);

    // Ensure all includes have a round number smaller than the block round number
    for include in header.block_references() {
        if include.round >= header.reference().round {
            return false;
        }
    }

    let mut aggregator = StakeAggregator::<QuorumThreshold>::new();
    let mut is_quorum = false;
    // Collect the authorities with included blocks at round_number - 1
    for include in header.block_references() {
        if include.round == round_number - 1 {
            is_quorum = aggregator.add(include.authority, committee);
        }
    }

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
    use crate::{
        crypto::{SignatureBytes, TransactionsCommitment},
        types::BlockDigest,
    };

    fn make_header(authority: u64, round: u64, refs: &[(u64, u64)]) -> BlockHeader {
        let block_references: Vec<_> = refs
            .iter()
            .map(|&(a, r)| BlockReference::new_test(a, r))
            .collect();
        let ack_refs = block_references.clone();
        BlockHeader {
            reference: BlockReference {
                authority,
                round,
                digest: BlockDigest::new_without_transactions(
                    authority,
                    round,
                    &block_references,
                    &ack_refs,
                    0,
                    false,
                    &SignatureBytes::default(),
                    TransactionsCommitment::default(),
                    None,
                ),
            },
            block_references,
            acknowledgment_intersection: None,
            acknowledgment_references: ack_refs,
            meta_creation_time_ns: 0,
            epoch_marker: false,
            signature: SignatureBytes::default(),
            transactions_commitment: TransactionsCommitment::default(),
            strong_vote: None,
            serialized: None,
        }
    }

    #[test]
    fn test_threshold_clock_valid() {
        let committee = Committee::new_test(vec![1, 1, 1, 1]);
        assert!(!threshold_clock_valid_block_header(
            &make_header(0, 1, &[]),
            &committee
        ));
        assert!(!threshold_clock_valid_block_header(
            &make_header(0, 1, &[(0, 0), (1, 0)]),
            &committee
        ));
        assert!(threshold_clock_valid_block_header(
            &make_header(0, 1, &[(0, 0), (1, 0), (2, 0)]),
            &committee
        ));
        assert!(threshold_clock_valid_block_header(
            &make_header(0, 1, &[(0, 0), (1, 0), (2, 0), (3, 0)]),
            &committee
        ));
        assert!(!threshold_clock_valid_block_header(
            &make_header(0, 2, &[(0, 1), (1, 1), (2, 0), (3, 0)]),
            &committee
        ));
        assert!(threshold_clock_valid_block_header(
            &make_header(0, 2, &[(0, 1), (1, 1), (2, 1), (3, 0)]),
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
