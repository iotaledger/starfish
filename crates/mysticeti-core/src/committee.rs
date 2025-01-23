// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    fmt::Display,
    hash::Hash,
    marker::PhantomData,
    ops::Range,
    sync::Arc,
};

use minibytes::Bytes;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    config::ImportExport,
    crypto::{dummy_public_key, PublicKey, Signer},
    data::Data,
    range_map::RangeMap,
    types::{
        AuthorityIndex, AuthoritySet, BlockReference, Stake,
        TransactionLocator, TransactionLocatorRange,VerifiedStatementBlock,
    },
};


#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Committee {
    authorities: Vec<Authority>,
    validity_threshold: Stake, // The minimum stake required for validity
    quorum_threshold: Stake,   // The minimum stake required for quorum
    info_length: usize, // info length used for encoding
}

impl Committee {
    pub const DEFAULT_FILENAME: &'static str = "committee.yaml";

    pub fn new_test(stake: Vec<Stake>) -> Arc<Self> {
        let authorities = stake.into_iter().map(Authority::test_from_stake).collect();
        Self::new(authorities)
    }

    pub fn info_length(&self) -> usize {
        self.info_length
    }

    pub fn new(authorities: Vec<Authority>) -> Arc<Self> {
        // todo - check duplicate public keys
        // Ensure the list is not empty
        assert!(!authorities.is_empty());

        // Ensure all stakes are positive
        assert!(authorities.iter().all(|a| a.stake() > 0));
        assert!(authorities.len() <= 128); // For now AuthoritySet only supports up to 128 authorities

        let mut total_stake: Stake = 0;
        for a in authorities.iter() {
            total_stake = total_stake
                .checked_add(a.stake())
                .expect("Total stake overflow");
        }
        let validity_threshold = total_stake / 3;
        let quorum_threshold = 2 * total_stake / 3;


        let committee_size = authorities.len();
        let f = (committee_size - 1) / 3;
        let info_length = match committee_size % 3 {
            0 => {f+3},
            1 => {f+1},
            _ => {f+2},
        };

        Arc::new(Committee {
            authorities,
            validity_threshold,
            quorum_threshold,
            info_length,
        })
    }

    pub fn get_stake(&self, authority: AuthorityIndex) -> Option<Stake> {
        self.authorities
            .get(authority as usize)
            .map(Authority::stake)
    }

    pub fn validity_threshold(&self) -> Stake {
        self.validity_threshold + 1
    }

    pub fn quorum_threshold(&self) -> Stake {
        self.quorum_threshold + 1
    }

    pub fn get_public_key(&self, authority: AuthorityIndex) -> Option<&PublicKey> {
        self.authorities
            .get(authority as usize)
            .map(Authority::public_key)
    }

    pub fn known_authority(&self, authority: AuthorityIndex) -> bool {
        authority < self.len() as AuthorityIndex
    }

    pub fn authorities(&self) -> Range<AuthorityIndex> {
        0u64..(self.authorities.len() as AuthorityIndex)
    }

    /// Return own genesis block and other genesis blocks
    pub fn genesis_blocks(
        &self,
        for_authority: AuthorityIndex,
    ) -> (Data<VerifiedStatementBlock>, Vec<Data<VerifiedStatementBlock>>) {
        let other_blocks: Vec<_> = self
            .authorities()
            .filter_map(|a| {
                if a == for_authority {
                    None
                } else {
                    Some(VerifiedStatementBlock::new_genesis(a))
                }
            })
            .collect();
        let own_genesis_block = VerifiedStatementBlock::new_genesis(for_authority);
        (own_genesis_block, other_blocks)
    }

    pub fn is_valid(&self, amount: Stake) -> bool {
        amount > self.validity_threshold
    }

    pub fn is_quorum(&self, amount: Stake) -> bool {
        amount > self.quorum_threshold
    }

    pub fn get_total_stake<A: Borrow<AuthorityIndex>>(&self, authorities: &HashSet<A>) -> Stake {
        let mut total_stake = 0;
        for authority in authorities {
            total_stake += self.authorities[*authority.borrow() as usize].stake();
        }
        total_stake
    }

    // TODO: fix to select by stake
    pub fn elect_leader(&self, r: u64) -> AuthorityIndex {
        (r % self.authorities.len() as u64) as AuthorityIndex
    }

    pub fn random_authority(&self, rng: &mut impl Rng) -> AuthorityIndex {
        rng.gen_range(self.authorities())
    }

    pub fn len(&self) -> usize {
        self.authorities.len()
    }

    pub fn new_for_benchmarks(committee_size: usize) -> Arc<Self> {
        Self::new(
            Signer::new_for_test(committee_size)
                .into_iter()
                .map(|keypair| Authority {
                    stake: 1,
                    public_key: keypair.public_key(),
                })
                .collect(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authority {
    stake: Stake,
    public_key: PublicKey,
}

impl Authority {
    pub fn test_from_stake(stake: Stake) -> Self {
        Self {
            stake,
            public_key: dummy_public_key(),
        }
    }

    pub fn stake(&self) -> Stake {
        self.stake
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl ImportExport for Committee {}

pub trait CommitteeThreshold: Clone {
    fn is_threshold(committee: &Committee, amount: Stake) -> bool;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuorumThreshold;
#[derive(Serialize, Deserialize, Clone)]
pub struct ValidityThreshold;

impl CommitteeThreshold for QuorumThreshold {
    fn is_threshold(committee: &Committee, amount: Stake) -> bool {
        committee.is_quorum(amount)
    }
}

impl CommitteeThreshold for ValidityThreshold {
    fn is_threshold(committee: &Committee, amount: Stake) -> bool {
        committee.is_valid(amount)
    }
}

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct StakeAggregator<TH> {
    pub votes: AuthoritySet,
    stake: Stake,
    _phantom: PhantomData<TH>,
}

/// Tracks votes for pending transactions and outputs certified transactions to a handler
pub struct TransactionAggregator<TH, H = HashSet<TransactionLocator>> {
    pending: HashMap<BlockReference, RangeMap<u64, StakeAggregator<TH>>>,
    // todo - need to figure out serialization story with this
    // Currently we skip serialization for test handler,
    // but it also means some invariants wrt unknown_transaction might be potentially broken in some tests
    handler: H,
}

pub trait TransactionAggregatorKey:
    Hash + Eq + Copy + Display + Serialize + for<'a> Deserialize<'a>
{
}
impl<T> TransactionAggregatorKey for T where
    T: Hash + Eq + Copy + Display + Serialize + for<'a> Deserialize<'a>
{
}

pub trait ProcessedTransactionHandler<K> {
    fn transaction_processed(&mut self, k: K);
    fn duplicate_transaction(&mut self, _k: K, _from: AuthorityIndex) {}
    fn unknown_transaction(&mut self, _k: K, _from: AuthorityIndex) {}
}

impl<K: TransactionAggregatorKey> ProcessedTransactionHandler<K> for HashSet<K> {
    fn transaction_processed(&mut self, k: K) {
        self.insert(k);
    }

    fn duplicate_transaction(&mut self, k: K, from: AuthorityIndex) {
        if !self.contains(&k) {
            panic!("Duplicate transaction {k}: from {from}");
        }
    }

    fn unknown_transaction(&mut self, k: K, from: AuthorityIndex) {
        if !self.contains(&k) {
            panic!("Unexpected - got vote for unknown transaction {k} from {from}");
        }
    }
}

impl<TH: CommitteeThreshold> StakeAggregator<TH> {
    pub fn new() -> Self {
        Self {
            votes: Default::default(),
            stake: 0,
            _phantom: Default::default(),
        }
    }

    pub fn add(&mut self, vote: AuthorityIndex, committee: &Committee) -> bool {
        let stake = committee.get_stake(vote).expect("Authority not found");
        if self.votes.insert(vote) {
            self.stake += stake;
        }
        TH::is_threshold(committee, self.stake)
    }

    pub fn get_stake_above_quorum_threshold(&self, committee: &Committee) -> Stake {
        self.stake.saturating_sub(committee.quorum_threshold)
    }

    pub fn is_quorum(&self, committee: &Committee) -> bool {
        TH::is_threshold(committee, self.stake)
    }

    pub fn get_stake(&self) -> Stake {
        self.stake
    }

    pub fn clear(&mut self) {
        self.votes.clear();
        self.stake = 0;
    }

    pub fn voters(&self) -> impl Iterator<Item = AuthorityIndex> + '_ {
        self.votes.present()
    }
}

impl<TH: CommitteeThreshold, H: ProcessedTransactionHandler<TransactionLocator> + Default>
    TransactionAggregator<TH, H>
{
    pub fn new() -> Self {
        Self {
            pending: Default::default(),
            handler: Default::default(),
        }
    }
}

impl<TH: CommitteeThreshold, H: ProcessedTransactionHandler<TransactionLocator>>
    TransactionAggregator<TH, H>
{
    pub fn with_handler(handler: H) -> Self {
        Self {
            pending: Default::default(),
            handler,
        }
    }

    pub fn state(&self) -> Bytes {
        bincode::serialize(&self.pending)
            .expect("Serialization failed")
            .into()
    }

    pub fn with_state(&mut self, state: &Bytes) {
        assert!(self.pending.is_empty());
        self.pending = bincode::deserialize(state).expect("Deserialization failed");
    }

    /// Returns Ok(()) if this is first time we see transaction and Err otherwise
    /// When Err is returned transaction is ignored
    pub fn register(
        &mut self,
        locator_range: TransactionLocatorRange,
        vote: AuthorityIndex,
        committee: &Committee,
    ) {
        let range_map = self.pending.entry(*locator_range.block()).or_default();
        range_map.mutate_range(locator_range.range(), |range, aggregator_opt| {
            if aggregator_opt.is_some() {
                for l in range {
                    let k = TransactionLocator::new(*locator_range.block(), l);
                    // todo - make duplicate_transaction take TransactionLocatorRange instead
                    self.handler.duplicate_transaction(k, vote);
                }
            } else {
                let mut aggregator = StakeAggregator::<TH>::new();
                aggregator.add(vote, committee);
                *aggregator_opt = Some(aggregator);
            }
        });
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

impl<TH: CommitteeThreshold> TransactionAggregator<TH> {
    pub fn is_processed(&self, k: &TransactionLocator) -> bool {
        self.handler.contains(k)
    }
}

pub enum TransactionVoteResult {
    Processed,
    VoteAccepted,
}

impl<TH: CommitteeThreshold, H: ProcessedTransactionHandler<TransactionLocator>>
    TransactionAggregator<TH, H>
{

}

impl<TH: CommitteeThreshold> Default for StakeAggregator<TH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<TH: CommitteeThreshold, H: ProcessedTransactionHandler<TransactionLocator> + Default> Default
    for TransactionAggregator<TH, H>
{
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
pub struct VoteRangeBuilder {
    range: Option<Range<u64>>,
}

impl VoteRangeBuilder {
    #[must_use]
    pub fn add(&mut self, offset: u64) -> Option<Range<u64>> {
        if let Some(range) = &mut self.range {
            if range.end == offset {
                range.end = offset + 1;
                None
            } else {
                let result = self.range.take();
                self.range = Some(offset..offset + 1);
                result
            }
        } else {
            self.range = Some(offset..offset + 1);
            None
        }
    }

    pub fn finish(self) -> Option<Range<u64>> {
        self.range
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn vote_range_builder_test() {
        let mut b = VoteRangeBuilder::default();
        assert_eq!(None, b.add(1));
        assert_eq!(None, b.add(2));
        assert_eq!(Some(1..3), b.add(4));
        assert_eq!(Some(4..5), b.add(6));
        assert_eq!(Some(6..7), b.finish());
    }
}
