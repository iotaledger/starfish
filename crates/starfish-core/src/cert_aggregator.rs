// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Signature-free RBC aggregation for SailfishPlusPlus.
//!
//! Tracks Echo, Vote, and Ready messages per block and emits certification
//! events when the optimistic thresholds are reached.

use std::{collections::BTreeMap, sync::Arc};

use ahash::AHashMap;

use crate::{
    committee::Committee,
    types::{AuthoritySet, BlockReference, CertMessage, CertMessageKind, RoundNumber, Stake},
};

/// Events emitted by the aggregator when thresholds are crossed.
#[derive(Debug, Clone)]
pub enum CertEvent {
    /// Block certified via fast path (enough echoes).
    FastDelivery(BlockReference),
    /// Enough echoes to trigger a Vote broadcast.
    SendVote(BlockReference),
    /// Enough echoes/votes/readys to trigger a Ready broadcast.
    SendReady(BlockReference),
    /// Block certified via slow path (enough readys).
    SlowDelivery(BlockReference),
}

/// Per-block RBC aggregation state.
struct BlockCertState {
    echo_stake: Stake,
    echo_seen: AuthoritySet,
    vote_sent: bool,
    fast_delivered: bool,
    vote_stake: Stake,
    vote_seen: AuthoritySet,
    ready_stake: Stake,
    ready_seen: AuthoritySet,
    ready_sent: bool,
    certified: bool,
}

impl BlockCertState {
    fn new() -> Self {
        Self {
            echo_stake: 0,
            echo_seen: AuthoritySet::default(),
            vote_sent: false,
            fast_delivered: false,
            vote_stake: 0,
            vote_seen: AuthoritySet::default(),
            ready_stake: 0,
            ready_seen: AuthoritySet::default(),
            ready_sent: false,
            certified: false,
        }
    }
}

pub struct CertificationAggregator {
    committee: Arc<Committee>,
    rounds: BTreeMap<RoundNumber, AHashMap<BlockReference, BlockCertState>>,
}

impl CertificationAggregator {
    pub fn new(committee: Arc<Committee>) -> Self {
        Self {
            committee,
            rounds: BTreeMap::new(),
        }
    }

    pub fn add_message(&mut self, message: &CertMessage) -> Vec<CertEvent> {
        match message.kind {
            CertMessageKind::Echo => self.add_echo(message),
            CertMessageKind::Vote => self.add_vote(message),
            CertMessageKind::Ready => self.add_ready(message),
        }
    }

    fn add_echo(&mut self, message: &CertMessage) -> Vec<CertEvent> {
        // The broadcaster/author can equivocate, so the optimistic Sailfish++
        // Echo thresholds count only non-broadcaster senders.
        if message.sender == message.block_ref.authority {
            return Vec::new();
        }
        let state = self
            .rounds
            .entry(message.block_ref.round)
            .or_default()
            .entry(message.block_ref)
            .or_insert_with(BlockCertState::new);
        let sender = message.sender;
        if state.echo_seen.contains(sender) {
            return Vec::new();
        }
        state.echo_seen.insert(sender);
        let stake = self.committee.get_stake(sender).unwrap_or(0);
        state.echo_stake += stake;

        let mut events = Vec::new();

        // Fast delivery: ceil((N + 2F - 2) / 2) echoes
        if !state.fast_delivered && state.echo_stake >= self.committee.optimistic_fast_threshold() {
            state.fast_delivered = true;
            state.certified = true;
            events.push(CertEvent::FastDelivery(message.block_ref));
        }

        // Vote trigger: ceil(N / 2) echoes
        if !state.vote_sent && state.echo_stake >= self.committee.optimistic_vote_threshold() {
            state.vote_sent = true;
            events.push(CertEvent::SendVote(message.block_ref));
        }

        // Ready trigger from echoes: ceil((N + F - 1) / 2) echoes
        if !state.ready_sent && state.echo_stake >= self.committee.optimistic_ready_threshold() {
            state.ready_sent = true;
            events.push(CertEvent::SendReady(message.block_ref));
        }

        events
    }

    fn add_vote(&mut self, message: &CertMessage) -> Vec<CertEvent> {
        // Votes inherit the same non-broadcaster counting rule as echoes.
        if message.sender == message.block_ref.authority {
            return Vec::new();
        }
        let state = self
            .rounds
            .entry(message.block_ref.round)
            .or_default()
            .entry(message.block_ref)
            .or_insert_with(BlockCertState::new);
        let sender = message.sender;
        if state.vote_seen.contains(sender) {
            return Vec::new();
        }
        state.vote_seen.insert(sender);
        let stake = self.committee.get_stake(sender).unwrap_or(0);
        state.vote_stake += stake;

        let mut events = Vec::new();

        // Ready trigger from votes: ceil((N + F - 1) / 2) votes
        if !state.ready_sent && state.vote_stake >= self.committee.optimistic_ready_threshold() {
            state.ready_sent = true;
            events.push(CertEvent::SendReady(message.block_ref));
        }

        events
    }

    fn add_ready(&mut self, message: &CertMessage) -> Vec<CertEvent> {
        let state = self
            .rounds
            .entry(message.block_ref.round)
            .or_default()
            .entry(message.block_ref)
            .or_insert_with(BlockCertState::new);
        let sender = message.sender;
        if state.ready_seen.contains(sender) {
            return Vec::new();
        }
        state.ready_seen.insert(sender);
        let stake = self.committee.get_stake(sender).unwrap_or(0);
        state.ready_stake += stake;

        let mut events = Vec::new();

        // Ready amplification: F+1 readys trigger a Ready broadcast
        if !state.ready_sent && state.ready_stake >= self.committee.validity_threshold() {
            state.ready_sent = true;
            events.push(CertEvent::SendReady(message.block_ref));
        }

        // Slow delivery: 2F+1 readys
        if !state.certified && state.ready_stake >= self.committee.quorum_threshold() {
            state.certified = true;
            events.push(CertEvent::SlowDelivery(message.block_ref));
        }

        events
    }

    #[allow(dead_code)]
    pub fn is_certified(&self, block_ref: &BlockReference) -> bool {
        self.rounds
            .get(&block_ref.round)
            .and_then(|m| m.get(block_ref))
            .is_some_and(|s| s.certified)
    }

    pub fn cleanup_below_round(&mut self, round: RoundNumber) {
        self.rounds = self.rounds.split_off(&round);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuthorityIndex;

    fn make_committee(n: usize) -> Arc<Committee> {
        Committee::new_test(vec![1; n])
    }

    fn message(
        block_ref: BlockReference,
        sender: AuthorityIndex,
        kind: CertMessageKind,
    ) -> CertMessage {
        CertMessage {
            block_ref,
            sender,
            kind,
        }
    }

    fn echo(block_ref: BlockReference, sender: AuthorityIndex) -> CertMessage {
        message(block_ref, sender, CertMessageKind::Echo)
    }

    fn vote(block_ref: BlockReference, sender: AuthorityIndex) -> CertMessage {
        message(block_ref, sender, CertMessageKind::Vote)
    }

    fn ready(block_ref: BlockReference, sender: AuthorityIndex) -> CertMessage {
        message(block_ref, sender, CertMessageKind::Ready)
    }

    #[test]
    fn fast_delivery_with_enough_echoes() {
        // N=4, F=1. fast_threshold = ceil((4 + 2 - 2) / 2) = 2
        let committee = make_committee(4);
        let mut agg = CertificationAggregator::new(committee);
        let block = BlockReference::new_test(0, 1);

        let events = agg.add_message(&echo(block, 0));
        assert!(!agg.is_certified(&block));
        assert!(events.is_empty());

        let events = agg.add_message(&echo(block, 1));
        assert!(
            events
                .iter()
                .all(|e| !matches!(e, CertEvent::FastDelivery(_)))
        );

        let events = agg.add_message(&echo(block, 2));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, CertEvent::FastDelivery(_)))
        );
        assert!(agg.is_certified(&block));
    }

    #[test]
    fn vote_trigger() {
        // N=4, F=1. vote_threshold = ceil(4/2) = 2
        let committee = make_committee(4);
        let mut agg = CertificationAggregator::new(committee);
        let block = BlockReference::new_test(0, 1);

        agg.add_message(&echo(block, 0));
        let events = agg.add_message(&echo(block, 1));
        assert!(!events.iter().any(|e| matches!(e, CertEvent::SendVote(_))));

        let events = agg.add_message(&echo(block, 2));
        assert!(events.iter().any(|e| matches!(e, CertEvent::SendVote(_))));
    }

    #[test]
    fn ready_trigger_from_votes() {
        // N=4, F=1. ready_threshold = ceil((4+1-1)/2) = 2
        let committee = make_committee(4);
        let mut agg = CertificationAggregator::new(committee);
        let block = BlockReference::new_test(0, 1);

        agg.add_message(&vote(block, 0));
        let events = agg.add_message(&vote(block, 1));
        assert!(!events.iter().any(|e| matches!(e, CertEvent::SendReady(_))));

        let events = agg.add_message(&vote(block, 2));
        assert!(events.iter().any(|e| matches!(e, CertEvent::SendReady(_))));
    }

    #[test]
    fn ready_trigger_from_echoes() {
        // N=4, F=1. ready_threshold = ceil((4+1-1)/2) = 2
        let committee = make_committee(4);
        let mut agg = CertificationAggregator::new(committee);
        let block = BlockReference::new_test(0, 1);

        let events = agg.add_message(&echo(block, 0));
        assert!(!events.iter().any(|e| matches!(e, CertEvent::SendReady(_))));

        let events = agg.add_message(&echo(block, 1));
        assert!(!events.iter().any(|e| matches!(e, CertEvent::SendReady(_))));

        let events = agg.add_message(&echo(block, 2));
        assert!(events.iter().any(|e| matches!(e, CertEvent::SendReady(_))));
    }

    #[test]
    fn slow_delivery_from_readys() {
        // N=4, F=1. validity = 2, quorum = 3
        let committee = make_committee(4);
        let mut agg = CertificationAggregator::new(committee);
        let block = BlockReference::new_test(0, 1);

        agg.add_message(&ready(block, 0));
        // F+1 = 2 readys triggers Ready amplification
        let events = agg.add_message(&ready(block, 1));
        assert!(events.iter().any(|e| matches!(e, CertEvent::SendReady(_))));

        // 2F+1 = 3 readys triggers slow delivery
        let events = agg.add_message(&ready(block, 2));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, CertEvent::SlowDelivery(_)))
        );
        assert!(agg.is_certified(&block));
    }

    #[test]
    fn duplicate_messages_ignored() {
        let committee = make_committee(4);
        let mut agg = CertificationAggregator::new(committee);
        let block = BlockReference::new_test(0, 1);

        agg.add_message(&echo(block, 1));
        let events = agg.add_message(&echo(block, 1));
        assert!(events.is_empty());
    }

    #[test]
    fn broadcaster_echo_does_not_count_toward_fast_delivery() {
        let committee = make_committee(4);
        let mut agg = CertificationAggregator::new(committee);
        let block = BlockReference::new_test(0, 1);

        agg.add_message(&echo(block, 0));
        let events = agg.add_message(&echo(block, 1));

        assert!(
            !events
                .iter()
                .any(|e| matches!(e, CertEvent::FastDelivery(_)))
        );
        assert!(!agg.is_certified(&block));
    }

    #[test]
    fn broadcaster_vote_does_not_count_toward_ready_trigger() {
        let committee = make_committee(4);
        let mut agg = CertificationAggregator::new(committee);
        let block = BlockReference::new_test(0, 1);

        agg.add_message(&vote(block, 0));
        let events = agg.add_message(&vote(block, 1));

        assert!(!events.iter().any(|e| matches!(e, CertEvent::SendReady(_))));
    }

    #[test]
    fn cleanup_via_split_off() {
        let committee = make_committee(4);
        let mut agg = CertificationAggregator::new(committee);
        let block_r1 = BlockReference::new_test(0, 1);
        let block_r5 = BlockReference::new_test(0, 5);

        agg.add_message(&echo(block_r1, 1));
        agg.add_message(&echo(block_r5, 1));

        agg.cleanup_below_round(3);
        assert!(!agg.rounds.contains_key(&1));
        assert!(agg.rounds.contains_key(&5));
    }
}
