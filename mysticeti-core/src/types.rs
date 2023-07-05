// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub type AuthorityIndex = u64;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct Transaction {
    data: Vec<u8>,
}

pub type TransactionId = crate::crypto::TransactionDigest;
pub type RoundNumber = u64;
pub type BlockDigest = crate::crypto::BlockDigest;
pub type Stake = u64;
pub type KeyPair = u64;
pub type PublicKey = u64;

use crate::data::Data;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
#[cfg(test)]
pub use test::Dag;

#[allow(dead_code)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum Vote {
    Accept,
    Reject(Option<TransactionId>),
}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub struct BlockReference {
    pub authority: AuthorityIndex,
    pub round: RoundNumber,
    pub digest: BlockDigest,
}

#[allow(dead_code)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum BaseStatement {
    /// Authority Shares a transactions, without accepting it or not.
    Share(TransactionId, Transaction),
    /// Authority votes to accept or reject a transaction.
    Vote(TransactionId, Vote),
}

#[derive(Clone, Serialize, Deserialize)]
// Important. Adding fields here requires updating BlockDigest::new
pub struct StatementBlock {
    reference: BlockReference,

    //  A list of block references to other blocks that this block includes
    //  Note that the order matters: if a reference to two blocks from the same round and same authority
    //  are included, then the first reference is the one that this block conceptually votes for.
    includes: Vec<BlockReference>,

    // A list of base statements in order.
    statements: Vec<BaseStatement>,

    // Creation time of the block as reported by creator, currently not enforced
    meta_creation_time_ns: TimestampNs,
}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub struct AuthoritySet(u128); // todo - support more then 128 authorities

pub type TimestampNs = u128;
const NANOS_IN_SEC: u128 = Duration::from_secs(1).as_nanos();

const GENESIS_ROUND: RoundNumber = 0;

impl StatementBlock {
    pub fn new_genesis(authority: AuthorityIndex) -> Data<Self> {
        Data::new(Self::new(authority, GENESIS_ROUND, vec![], vec![], 0))
    }

    pub fn new(
        authority: AuthorityIndex,
        round: RoundNumber,
        includes: Vec<BlockReference>,
        statements: Vec<BaseStatement>,
        meta_creation_time_ns: TimestampNs,
    ) -> Self {
        Self {
            reference: BlockReference {
                authority,
                round,
                digest: BlockDigest::new(
                    authority,
                    round,
                    &includes,
                    &statements,
                    meta_creation_time_ns,
                ),
            },
            includes,
            statements,
            meta_creation_time_ns,
        }
    }

    pub fn reference(&self) -> &BlockReference {
        &self.reference
    }

    pub fn includes(&self) -> &Vec<BlockReference> {
        &self.includes
    }

    pub fn statements(&self) -> &Vec<BaseStatement> {
        &self.statements
    }

    pub fn author(&self) -> AuthorityIndex {
        self.reference.authority
    }

    pub fn round(&self) -> RoundNumber {
        self.reference.round
    }

    pub fn digest(&self) -> BlockDigest {
        self.reference.digest
    }

    pub fn author_round(&self) -> (AuthorityIndex, RoundNumber) {
        self.reference.author_round()
    }

    pub fn meta_creation_time(&self) -> Duration {
        // Some context: https://github.com/rust-lang/rust/issues/51107
        let secs = self.meta_creation_time_ns / NANOS_IN_SEC;
        let nanos = self.meta_creation_time_ns % NANOS_IN_SEC;
        Duration::new(secs as u64, nanos as u32)
    }
    // /// Reference to the parent block made by the same authority
    // pub fn own_parent(&self) -> Option<BlockReference> {
    //     self.includes.get(0).map(|r| {
    //         debug_assert_eq!(r.authority, self.author());
    //         *r
    //     })
    // }
}

impl BlockReference {
    #[cfg(test)]
    pub fn new_test(authority: AuthorityIndex, round: RoundNumber) -> Self {
        if round == 0 {
            StatementBlock::new_genesis(authority).reference
        } else {
            Self {
                authority,
                round,
                digest: Default::default(),
            }
        }
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn author_round(&self) -> (AuthorityIndex, RoundNumber) {
        (self.authority, self.round)
    }
}

impl fmt::Debug for BlockReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for BlockReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.authority < 26 {
            write!(
                f,
                "{}{}",
                format_authority_index(self.authority),
                self.round
            )
        } else {
            write!(f, "[{:02}]{}", self.authority, self.round)
        }
    }
}

impl AuthoritySet {
    #[inline]
    pub fn insert(&mut self, v: AuthorityIndex) -> bool {
        let bit = 1u128 << v;
        if self.0 & bit == bit {
            return false;
        }
        self.0 |= bit;
        true
    }

    #[inline]
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

pub fn format_authority_index(i: AuthorityIndex) -> char {
    ('A' as u64 + i) as u8 as char
}

impl fmt::Debug for StatementBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for StatementBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[", self.reference)?;
        for include in self.includes() {
            write!(f, "{},", include)?;
        }
        write!(f, "](")?;
        for statement in self.statements() {
            write!(f, "{},", statement)?;
        }
        write!(f, ")")
    }
}

impl PartialEq for StatementBlock {
    fn eq(&self, other: &Self) -> bool {
        self.reference == other.reference
    }
}

impl fmt::Debug for BaseStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for BaseStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseStatement::Share(id, _) => write!(f, "#{id:08}"),
            BaseStatement::Vote(id, Vote::Accept) => write!(f, "+{id:08}"),
            BaseStatement::Vote(id, Vote::Reject(_)) => write!(f, "-{id:08}"),
        }
    }
}

impl Transaction {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    #[allow(dead_code)]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[allow(dead_code)]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::prelude::SliceRandom;
    use rand::Rng;
    use std::collections::{HashMap, HashSet};

    pub struct Dag(HashMap<BlockReference, Data<StatementBlock>>);

    #[cfg(test)]
    impl Dag {
        /// Takes a string in form "Block:[Dependencies, ...]; ..."
        /// Where Block is one letter denoting a node and a number denoting a round
        /// For example B3 is a block for round 3 made by validator index 2
        /// Note that blocks are separated with semicolon(;) and dependencies within block are separated with coma(,)
        pub fn draw(s: &str) -> Self {
            let mut blocks = HashMap::new();
            for block in s.split(";") {
                let block = Self::draw_block(block);
                blocks.insert(*block.reference(), Data::new(block));
            }
            Self(blocks)
        }

        pub fn draw_block(block: &str) -> StatementBlock {
            let block = block.trim();
            assert!(block.ends_with(']'), "Invalid block definition: {}", block);
            let block = &block[..block.len() - 1];
            let Some((name, includes)) = block.split_once(":[") else {
                panic!("Invalid block definition: {}", block);
            };
            let reference = Self::parse_name(name);
            let includes = includes.trim();
            let includes = if includes.len() == 0 {
                vec![]
            } else {
                let includes = includes.split(',');
                includes.map(Self::parse_name).collect()
            };
            StatementBlock {
                reference,
                includes,
                statements: vec![],
                meta_creation_time_ns: 0,
            }
        }

        fn parse_name(s: &str) -> BlockReference {
            let s = s.trim();
            assert!(s.len() >= 2, "Invalid block: {}", s);
            let authority = s.as_bytes()[0];
            let authority = authority.wrapping_sub('A' as u8);
            assert!(authority < 26, "Invalid block: {}", s);
            let Ok(round): Result<u64, _> = s[1..].parse() else {
                panic!("Invalid block: {}", s);
            };
            BlockReference::new_test(authority as u64, round)
        }

        /// For each authority add a 0 round block if not present
        pub fn add_genesis_blocks(mut self) -> Self {
            for authority in self.authorities() {
                let block = StatementBlock::new_genesis(authority);
                let entry = self.0.entry(*block.reference());
                entry.or_insert_with(move || block);
            }
            self
        }

        pub fn random_iter(&self, rng: &mut impl Rng) -> RandomDagIter {
            let mut v: Vec<_> = self.0.keys().cloned().collect();
            v.shuffle(rng);
            RandomDagIter(self, v.into_iter())
        }

        pub fn len(&self) -> usize {
            self.0.len()
        }

        fn authorities(&self) -> HashSet<AuthorityIndex> {
            let mut authorities = HashSet::new();
            for (k, v) in &self.0 {
                authorities.insert(k.authority);
                for include in v.includes() {
                    authorities.insert(include.authority);
                }
            }
            authorities
        }
    }

    pub struct RandomDagIter<'a>(&'a Dag, std::vec::IntoIter<BlockReference>);

    impl<'a> Iterator for RandomDagIter<'a> {
        type Item = &'a Data<StatementBlock>;

        fn next(&mut self) -> Option<Self::Item> {
            let next = self.1.next()?;
            Some(self.0 .0.get(&next).unwrap())
        }
    }

    #[test]
    fn test_draw_dag() {
        let d = Dag::draw("A1:[A0, B1]; B2:[B1]").0;
        assert_eq!(d.len(), 2);
        let a0: BlockReference = BlockReference::new_test(0, 1);
        let b2: BlockReference = BlockReference::new_test(1, 2);
        assert_eq!(&d.get(&a0).unwrap().reference, &a0);
        assert_eq!(
            &d.get(&a0).unwrap().includes,
            &vec![
                BlockReference::new_test(0, 0),
                BlockReference::new_test(1, 1)
            ]
        );
        assert_eq!(&d.get(&b2).unwrap().reference, &b2);
        assert_eq!(
            &d.get(&b2).unwrap().includes,
            &vec![BlockReference::new_test(1, 1)]
        );
    }

    #[test]
    fn authority_set_test() {
        let mut a = AuthoritySet::default();
        assert!(a.insert(0));
        assert!(!a.insert(0));
        assert!(a.insert(1));
        assert!(a.insert(2));
        assert!(!a.insert(1));
        assert!(a.insert(127));
        assert!(!a.insert(127));
        assert!(a.insert(3));
        assert!(!a.insert(3));
        assert!(!a.insert(2));
    }
}
