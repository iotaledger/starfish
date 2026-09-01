// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{borrow::Borrow, marker::PhantomData, sync::Arc};

use ahash::AHashSet;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    block_authentication::{
        BlockAuthenticationScheme,
        BlockPublicKey,
        BlockSigningKey,
        benchmark_seed,
    },
    config::ImportExport,
    crypto::{BlsPublicKey, BlsSigner, PublicKey, Signer, dummy_bls_public_key, dummy_public_key},
    data::Data,
    types::{AuthorityIndex, AuthoritySet, RoundNumber, Stake, VerifiedBlock},
};

#[derive(Serialize, Deserialize, Clone)]
pub struct Committee {
    authorities: Vec<Authority>,
    validity_threshold: Stake, // The minimum stake required for validity
    quorum_threshold: Stake,   // The minimum stake required for quorum
    info_length: usize,        // info length used for encoding
    // Optimistic RBC thresholds (SailfishPlusPlus).
    // Precomputed from total_stake and validity_threshold.
    optimistic_fast_threshold: Stake,
    optimistic_vote_threshold: Stake,
    optimistic_ready_threshold: Stake,
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

        // Committee BLS public keys are static. Validate them once so that the
        // hot path can skip repeated `pk_validate` work during signature
        // verification.
        for (authority, info) in authorities.iter().enumerate() {
            info.bls_public_key().validate().unwrap_or_else(|e| {
                panic!("Invalid BLS public key for authority {authority}: {e:?}")
            });
            let mut schemes: Vec<_> = info
                .pq_public_keys
                .iter()
                .map(BlockPublicKey::scheme)
                .collect();
            schemes.sort_by_key(|scheme| scheme.name());
            schemes.dedup();
            assert_eq!(
                schemes.len(),
                info.pq_public_keys.len(),
                "Authority {authority} lists more than one public key for the same scheme"
            );
        }
        use crate::types::MAX_COMMITTEE_SIZE;
        assert!(
            authorities.len() <= MAX_COMMITTEE_SIZE as usize,
            "Committee size {} exceeds MAX_COMMITTEE_SIZE ({})",
            authorities.len(),
            MAX_COMMITTEE_SIZE
        );

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
            0 => f + 3,
            1 => f + 1,
            _ => f + 2,
        };

        // Optimistic RBC thresholds (N = total_stake, F = validity_threshold).
        // fast:  ceil((N + 2F - 2) / 2)   ≈ 5N/6
        // vote:  ceil(N / 2)
        // ready: ceil((N + F - 1) / 2)
        let n = total_stake;
        let f_stake = validity_threshold;
        let optimistic_fast_threshold = (n + 2 * f_stake - 2).div_ceil(2);
        let optimistic_vote_threshold = n.div_ceil(2);
        let optimistic_ready_threshold = (n + f_stake - 1).div_ceil(2);

        Arc::new(Committee {
            authorities,
            validity_threshold,
            quorum_threshold,
            info_length,
            optimistic_fast_threshold,
            optimistic_vote_threshold,
            optimistic_ready_threshold,
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

    /// Optimistic fast delivery threshold: ceil((N + 2F - 2) / 2).
    pub fn optimistic_fast_threshold(&self) -> Stake {
        self.optimistic_fast_threshold
    }

    /// Optimistic vote threshold: ceil(N / 2).
    pub fn optimistic_vote_threshold(&self) -> Stake {
        self.optimistic_vote_threshold
    }

    /// Optimistic ready threshold: ceil((N + F - 1) / 2).
    pub fn optimistic_ready_threshold(&self) -> Stake {
        self.optimistic_ready_threshold
    }

    pub fn get_public_key(&self, authority: AuthorityIndex) -> Option<&PublicKey> {
        self.authorities
            .get(authority as usize)
            .map(Authority::public_key)
    }

    /// Post-quantum public key of `authority` for `scheme`, if the committee
    /// file carries one. Always `None` for Ed25519, which uses
    /// [`Self::get_public_key`].
    pub fn block_public_key(
        &self,
        authority: AuthorityIndex,
        scheme: BlockAuthenticationScheme,
    ) -> Option<&BlockPublicKey> {
        self.authorities
            .get(authority as usize)
            .and_then(|info| info.pq_public_key(scheme))
    }

    /// `true` iff every authority can be verified under `scheme`.
    pub fn supports_block_authentication(&self, scheme: BlockAuthenticationScheme) -> bool {
        !scheme.is_post_quantum()
            || self
                .authorities
                .iter()
                .all(|info| info.pq_public_key(scheme).is_some())
    }

    pub fn get_bls_public_key(&self, authority: AuthorityIndex) -> Option<&BlsPublicKey> {
        self.authorities
            .get(authority as usize)
            .map(Authority::bls_public_key)
    }

    pub fn known_authority(&self, authority: AuthorityIndex) -> bool {
        (authority as usize) < self.len()
    }

    pub fn authorities(&self) -> impl Iterator<Item = AuthorityIndex> + Clone + '_ {
        (0..self.authorities.len()).map(|authority| authority as AuthorityIndex)
    }

    /// Return own genesis block and other genesis blocks
    pub fn genesis_blocks(
        &self,
        for_authority: AuthorityIndex,
    ) -> (Data<VerifiedBlock>, Vec<Data<VerifiedBlock>>) {
        let other_blocks: Vec<_> = self
            .authorities()
            .filter_map(|a| {
                if a == for_authority {
                    None
                } else {
                    Some(VerifiedBlock::new_genesis(a))
                }
            })
            .collect();
        let own_genesis_block = VerifiedBlock::new_genesis(for_authority);
        (own_genesis_block, other_blocks)
    }

    pub fn is_valid(&self, amount: Stake) -> bool {
        amount > self.validity_threshold
    }

    pub fn is_quorum(&self, amount: Stake) -> bool {
        amount > self.quorum_threshold
    }

    pub fn get_total_stake<A: Borrow<AuthorityIndex>>(&self, authorities: &AHashSet<A>) -> Stake {
        let mut total_stake = 0;
        for authority in authorities {
            total_stake += self.authorities[*authority.borrow() as usize].stake();
        }
        total_stake
    }

    // TODO: fix to select by stake
    pub fn elect_leader(&self, r: RoundNumber) -> AuthorityIndex {
        (r % self.authorities.len() as RoundNumber) as AuthorityIndex
    }

    pub fn random_authority(&self, rng: &mut impl Rng) -> AuthorityIndex {
        rng.gen_range(0..self.len()) as AuthorityIndex
    }

    pub fn len(&self) -> usize {
        self.authorities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn new_for_benchmarks(committee_size: usize) -> Arc<Self> {
        Self::new_for_benchmarks_with_authentication(
            committee_size,
            BlockAuthenticationScheme::Ed25519,
        )
    }

    /// Benchmark committee whose members additionally carry the public key of
    /// `block_authentication`, derived from the same deterministic seeds as
    /// [`crate::config::NodePrivateConfig::new_for_benchmarks_with_authentication`].
    pub fn new_for_benchmarks_with_authentication(
        committee_size: usize,
        block_authentication: BlockAuthenticationScheme,
    ) -> Arc<Self> {
        let signers = Signer::new_for_test(committee_size);
        let bls_signers = BlsSigner::new_for_test(committee_size);
        Self::new(
            signers
                .into_iter()
                .zip(bls_signers)
                .enumerate()
                .map(|(authority, (keypair, bls_keypair))| Authority {
                    stake: 1,
                    public_key: keypair.public_key(),
                    bls_public_key: bls_keypair.public_key(),
                    pq_public_keys: BlockSigningKey::from_seed(
                        block_authentication,
                        &benchmark_seed(block_authentication, authority as u64),
                    )
                    .map(|key| key.public_key())
                    .into_iter()
                    .collect(),
                })
                .collect(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authority {
    stake: Stake,
    public_key: PublicKey,
    bls_public_key: BlsPublicKey,
    /// Post-quantum block-authentication keys, at most one per scheme. Empty
    /// for committees that only run Ed25519.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pq_public_keys: Vec<BlockPublicKey>,
}

impl Authority {
    pub fn test_from_stake(stake: Stake) -> Self {
        Self {
            stake,
            public_key: dummy_public_key(),
            bls_public_key: dummy_bls_public_key(),
            pq_public_keys: Vec::new(),
        }
    }

    pub fn pq_public_key(&self, scheme: BlockAuthenticationScheme) -> Option<&BlockPublicKey> {
        self.pq_public_keys
            .iter()
            .find(|key| key.scheme() == scheme)
    }

    pub fn stake(&self) -> Stake {
        self.stake
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn bls_public_key(&self) -> &BlsPublicKey {
        &self.bls_public_key
    }
}

impl ImportExport for Committee {}

pub trait CommitteeThreshold: Clone {
    fn is_threshold(committee: &Committee, amount: Stake) -> bool;
}

#[derive(Serialize, Default, Deserialize, Debug, Clone)]
pub struct QuorumThreshold;
#[derive(Serialize, Default, Deserialize, Clone)]
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

#[derive(Serialize, Default, Deserialize, Debug, Clone)]
pub struct StakeAggregator<TH> {
    pub votes: AuthoritySet,
    stake: Stake,
    _phantom: PhantomData<TH>,
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

pub enum TransactionVoteResult {
    Processed,
    VoteAccepted,
}

#[cfg(test)]
mod tests {
    use super::{BlockAuthenticationScheme, BlockSigningKey, Committee, benchmark_seed};

    #[test]
    fn committee_yaml_round_trips_post_quantum_keys_and_accepts_legacy_files() {
        let ed_only = Committee::new_for_benchmarks(4);
        let yaml = serde_yaml::to_string(&*ed_only).unwrap();
        assert!(
            !yaml.contains("pq_public_keys"),
            "legacy layout must stay unchanged"
        );
        let decoded: Committee = serde_yaml::from_str(&yaml).unwrap();
        assert!(decoded.supports_block_authentication(BlockAuthenticationScheme::Ed25519));
        assert!(!decoded.supports_block_authentication(BlockAuthenticationScheme::MlDsa44));
        assert!(
            decoded
                .block_public_key(0, BlockAuthenticationScheme::MlDsa44)
                .is_none()
        );

        let scheme = BlockAuthenticationScheme::SlhDsaSha2_128f;
        let committee = Committee::new_for_benchmarks_with_authentication(4, scheme);
        let yaml = serde_yaml::to_string(&*committee).unwrap();
        assert!(yaml.contains("slh-dsa-sha2-128f"));
        let decoded: Committee = serde_yaml::from_str(&yaml).unwrap();
        assert!(decoded.supports_block_authentication(scheme));
        assert!(!decoded.supports_block_authentication(BlockAuthenticationScheme::MlDsa44));
        for authority in committee.authorities() {
            let expected =
                BlockSigningKey::from_seed(scheme, &benchmark_seed(scheme, authority as u64))
                    .unwrap()
                    .public_key();
            assert_eq!(decoded.block_public_key(authority, scheme), Some(&expected));
            assert_eq!(
                committee.block_public_key(authority, scheme),
                Some(&expected)
            );
        }
    }

    #[test]
    fn authorities_and_known_authority_support_more_than_255() {
        let committee = Committee::new_test(vec![1; 300]);

        let authorities: Vec<_> = committee.authorities().collect();
        assert_eq!(authorities.len(), 300);
        assert_eq!(authorities.first().copied(), Some(0));
        assert_eq!(authorities.last().copied(), Some(299));

        assert!(committee.known_authority(0));
        assert!(committee.known_authority(299));
    }
}
