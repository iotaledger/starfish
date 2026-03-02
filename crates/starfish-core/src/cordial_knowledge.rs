// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Per-peer knowledge tracking for cordial push dissemination.
//!
//! [`CordialKnowledge`] is a centralized actor that receives DAG events (new
//! headers, new shards, evictions) and fans them out to per-peer
//! [`ConnectionKnowledge`] trackers. Each connection task holds an
//! `Arc<RwLock<ConnectionKnowledge>>` to read when building batches.

use std::{collections::BTreeMap, sync::Arc};

use ahash::AHashSet;
use parking_lot::RwLock;
use tokio::sync::mpsc;

use crate::types::{AuthorityIndex, BlockReference, RoundNumber};

/// Maximum round gap beyond which a peer's data is no longer considered useful.
/// Headers/shards from an authority whose latest useful round is more than this
/// many rounds behind the current round will not be piggybacked.
const MAX_ROUND_GAP_FOR_USEFUL_PARTS: RoundNumber = 40;

/// Channel capacity for the cordial knowledge actor.
const CHANNEL_CAPACITY: usize = 10_000;

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Events sent to the [`CordialKnowledge`] actor.
pub enum CordialKnowledgeMessage {
    /// A new block header was added to the DAG.
    NewHeader(BlockReference),
    /// A new shard became available for a block.
    NewShard(BlockReference),
    /// A header was received FROM a specific peer — mark it as known for that
    /// peer.
    HeaderReceivedFrom {
        peer: AuthorityIndex,
        block_ref: BlockReference,
    },
    /// A shard was received FROM a specific peer — mark it as known for that
    /// peer.
    ShardReceivedFrom {
        peer: AuthorityIndex,
        block_ref: BlockReference,
    },
    /// Update useful-authors feedback from a peer's batch.
    UsefulAuthors {
        peer: AuthorityIndex,
        headers: u128,
        shards: u128,
    },
    /// Evict entries below these per-authority rounds.
    EvictBelow(Vec<RoundNumber>),
}

// ---------------------------------------------------------------------------
// ConnectionKnowledge — per-peer tracker
// ---------------------------------------------------------------------------

/// Per-peer tracker: what headers and shards this peer doesn't know about yet.
pub struct ConnectionKnowledge {
    peer: AuthorityIndex,
    committee_size: usize,
    /// `headers_not_known[authority]` = `{ round → set of block refs }`
    headers_not_known: Vec<BTreeMap<RoundNumber, AHashSet<BlockReference>>>,
    /// `shards_not_known[authority]` = `{ round → set of block refs }`
    shards_not_known: Vec<BTreeMap<RoundNumber, AHashSet<BlockReference>>>,
    /// Last round where this peer's headers were useful TO them (per
    /// authority).
    last_useful_headers_to_peer_round: Vec<Option<RoundNumber>>,
    /// Last round where this peer's shards were useful TO them (per authority).
    last_useful_shards_to_peer_round: Vec<Option<RoundNumber>>,
    /// Last round where headers FROM this peer were useful to us (per
    /// authority).
    last_useful_headers_from_peer_round: Vec<Option<RoundNumber>>,
    /// Last round where shards FROM this peer were useful to us (per
    /// authority).
    last_useful_shards_from_peer_round: Vec<Option<RoundNumber>>,
}

impl ConnectionKnowledge {
    pub fn new(peer: AuthorityIndex, committee_size: usize) -> Self {
        Self {
            peer,
            committee_size,
            headers_not_known: vec![BTreeMap::new(); committee_size],
            shards_not_known: vec![BTreeMap::new(); committee_size],
            last_useful_headers_to_peer_round: vec![None; committee_size],
            last_useful_shards_to_peer_round: vec![None; committee_size],
            last_useful_headers_from_peer_round: vec![None; committee_size],
            last_useful_shards_from_peer_round: vec![None; committee_size],
        }
    }

    /// Record that a new header exists that this peer may not know about.
    pub fn new_header(&mut self, block_ref: BlockReference) {
        // Don't track the peer's own blocks — they obviously know them.
        if block_ref.authority == self.peer {
            return;
        }
        let authority = block_ref.authority as usize;
        if authority < self.committee_size {
            self.headers_not_known[authority]
                .entry(block_ref.round)
                .or_default()
                .insert(block_ref);
        }
    }

    /// Record that a new shard exists that this peer may not know about.
    pub fn new_shard(&mut self, block_ref: BlockReference) {
        if block_ref.authority == self.peer {
            return;
        }
        let authority = block_ref.authority as usize;
        if authority < self.committee_size {
            self.shards_not_known[authority]
                .entry(block_ref.round)
                .or_default()
                .insert(block_ref);
        }
    }

    /// Mark a header as known by this peer (received from them or inferred).
    pub fn mark_header_known(&mut self, block_ref: BlockReference) {
        let authority = block_ref.authority as usize;
        if authority < self.committee_size {
            if let Some(round_set) = self.headers_not_known[authority].get_mut(&block_ref.round) {
                round_set.remove(&block_ref);
                if round_set.is_empty() {
                    self.headers_not_known[authority].remove(&block_ref.round);
                }
            }
        }
    }

    /// Mark a shard as known by this peer.
    pub fn mark_shard_known(&mut self, block_ref: BlockReference) {
        let authority = block_ref.authority as usize;
        if authority < self.committee_size {
            if let Some(round_set) = self.shards_not_known[authority].get_mut(&block_ref.round) {
                round_set.remove(&block_ref);
                if round_set.is_empty() {
                    self.shards_not_known[authority].remove(&block_ref.round);
                }
            }
        }
    }

    /// Drain the oldest unknown headers, up to `limit`, returning their block
    /// references.
    pub fn take_unsent_headers(&mut self, limit: usize) -> Vec<BlockReference> {
        let mut result = Vec::with_capacity(limit);
        for authority_map in &mut self.headers_not_known {
            let mut empty_rounds = Vec::new();
            for (&round, round_set) in authority_map.iter_mut() {
                if result.len() >= limit {
                    break;
                }
                let mut taken = Vec::new();
                for block_ref in round_set.iter() {
                    if result.len() >= limit {
                        break;
                    }
                    result.push(*block_ref);
                    taken.push(*block_ref);
                }
                for block_ref in &taken {
                    round_set.remove(block_ref);
                }
                if round_set.is_empty() {
                    empty_rounds.push(round);
                }
            }
            for round in empty_rounds {
                authority_map.remove(&round);
            }
            if result.len() >= limit {
                break;
            }
        }
        result
    }

    /// Drain the oldest unknown shards, up to `limit`, returning their block
    /// references.
    pub fn take_unsent_shards(&mut self, limit: usize) -> Vec<BlockReference> {
        let mut result = Vec::with_capacity(limit);
        for authority_map in &mut self.shards_not_known {
            let mut empty_rounds = Vec::new();
            for (&round, round_set) in authority_map.iter_mut() {
                if result.len() >= limit {
                    break;
                }
                let mut taken = Vec::new();
                for block_ref in round_set.iter() {
                    if result.len() >= limit {
                        break;
                    }
                    result.push(*block_ref);
                    taken.push(*block_ref);
                }
                for block_ref in &taken {
                    round_set.remove(block_ref);
                }
                if round_set.is_empty() {
                    empty_rounds.push(round);
                }
            }
            for round in empty_rounds {
                authority_map.remove(&round);
            }
            if result.len() >= limit {
                break;
            }
        }
        result
    }

    /// Evict all entries below the given per-authority rounds.
    pub fn evict_below(&mut self, rounds: &[RoundNumber]) {
        for (authority, threshold) in rounds.iter().enumerate() {
            if authority >= self.committee_size {
                break;
            }
            let split_round = threshold.saturating_add(1);
            self.headers_not_known[authority] =
                self.headers_not_known[authority].split_off(&split_round);
            self.shards_not_known[authority] =
                self.shards_not_known[authority].split_off(&split_round);
        }
    }

    /// Process useful-authors feedback received from this peer's batch.
    /// The bitmasks indicate which authorities the peer would find useful
    /// headers/shards from.
    pub fn update_useful_authors_from_peer(&mut self, headers_bitmask: u128, shards_bitmask: u128) {
        for i in 0..self.committee_size {
            if headers_bitmask & (1u128 << i) != 0 {
                // Peer tells us they want headers from authority i — record
                // the current frontier.
                if let Some(latest) = self.headers_not_known[i].keys().next_back() {
                    self.last_useful_headers_from_peer_round[i] = Some(*latest);
                }
            }
            if shards_bitmask & (1u128 << i) != 0 {
                if let Some(latest) = self.shards_not_known[i].keys().next_back() {
                    self.last_useful_shards_from_peer_round[i] = Some(*latest);
                }
            }
        }
    }

    /// Build bitmasks indicating which authorities' headers/shards we'd find
    /// useful FROM this peer. Used when constructing a batch to send to this
    /// peer.
    pub fn useful_authors_bitmasks(&self, current_round: RoundNumber) -> (u128, u128) {
        let mut headers_mask: u128 = 0;
        let mut shards_mask: u128 = 0;
        for i in 0..self.committee_size {
            if let Some(round) = self.last_useful_headers_to_peer_round[i] {
                if round.saturating_add(MAX_ROUND_GAP_FOR_USEFUL_PARTS) >= current_round {
                    headers_mask |= 1u128 << i;
                }
            }
            if let Some(round) = self.last_useful_shards_to_peer_round[i] {
                if round.saturating_add(MAX_ROUND_GAP_FOR_USEFUL_PARTS) >= current_round {
                    shards_mask |= 1u128 << i;
                }
            }
        }
        (headers_mask, shards_mask)
    }

    /// Number of unknown headers tracked for this peer (diagnostic).
    #[allow(dead_code)]
    pub fn unknown_headers_count(&self) -> usize {
        self.headers_not_known
            .iter()
            .map(|m| m.values().map(|s| s.len()).sum::<usize>())
            .sum()
    }

    /// Number of unknown shards tracked for this peer (diagnostic).
    #[allow(dead_code)]
    pub fn unknown_shards_count(&self) -> usize {
        self.shards_not_known
            .iter()
            .map(|m| m.values().map(|s| s.len()).sum::<usize>())
            .sum()
    }
}

// ---------------------------------------------------------------------------
// CordialKnowledge — central actor
// ---------------------------------------------------------------------------

/// Central actor that maintains all [`ConnectionKnowledge`] instances. Receives
/// DAG events and propagates them to per-peer trackers.
pub struct CordialKnowledge {
    committee_size: usize,
    /// One per peer, shared with connection tasks via `Arc<RwLock<>>`.
    connection_knowledges: Vec<Arc<RwLock<ConnectionKnowledge>>>,
    /// Receives events from DagState / core / shard reconstructor.
    receiver: mpsc::Receiver<CordialKnowledgeMessage>,
}

impl CordialKnowledge {
    /// Run the actor loop. Blocks until the channel is closed.
    pub async fn run(mut self) {
        while let Some(msg) = self.receiver.recv().await {
            match msg {
                CordialKnowledgeMessage::NewHeader(block_ref) => {
                    for ck in &self.connection_knowledges {
                        ck.write().new_header(block_ref);
                    }
                }
                CordialKnowledgeMessage::NewShard(block_ref) => {
                    for ck in &self.connection_knowledges {
                        ck.write().new_shard(block_ref);
                    }
                }
                CordialKnowledgeMessage::HeaderReceivedFrom { peer, block_ref } => {
                    let idx = peer as usize;
                    if idx < self.committee_size {
                        self.connection_knowledges[idx]
                            .write()
                            .mark_header_known(block_ref);
                    }
                }
                CordialKnowledgeMessage::ShardReceivedFrom { peer, block_ref } => {
                    let idx = peer as usize;
                    if idx < self.committee_size {
                        self.connection_knowledges[idx]
                            .write()
                            .mark_shard_known(block_ref);
                    }
                }
                CordialKnowledgeMessage::UsefulAuthors {
                    peer,
                    headers,
                    shards,
                } => {
                    let idx = peer as usize;
                    if idx < self.committee_size {
                        self.connection_knowledges[idx]
                            .write()
                            .update_useful_authors_from_peer(headers, shards);
                    }
                }
                CordialKnowledgeMessage::EvictBelow(rounds) => {
                    for ck in &self.connection_knowledges {
                        ck.write().evict_below(&rounds);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CordialKnowledgeHandle — used by network tasks
// ---------------------------------------------------------------------------

/// Handle for interacting with the [`CordialKnowledge`] actor.
/// Cloned and distributed to connection tasks and the core thread.
#[derive(Clone)]
pub struct CordialKnowledgeHandle {
    sender: mpsc::Sender<CordialKnowledgeMessage>,
    connection_knowledges: Vec<Arc<RwLock<ConnectionKnowledge>>>,
}

impl CordialKnowledgeHandle {
    /// Create the actor and its handle. Returns `(handle, actor)`.
    ///
    /// The caller should spawn `actor.run()` on a tokio runtime.
    pub fn new(committee_size: usize, own_id: AuthorityIndex) -> (Self, CordialKnowledge) {
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);

        let connection_knowledges: Vec<_> = (0..committee_size)
            .map(|i| {
                Arc::new(RwLock::new(ConnectionKnowledge::new(
                    i as AuthorityIndex,
                    committee_size,
                )))
            })
            .collect();

        let handle = Self {
            sender,
            connection_knowledges: connection_knowledges.clone(),
        };

        let actor = CordialKnowledge {
            committee_size,
            connection_knowledges,
            receiver,
        };

        let _ = own_id; // reserved for future use (skip own index in loops)
        (handle, actor)
    }

    /// Get the `ConnectionKnowledge` for a specific peer.
    pub fn connection_knowledge(
        &self,
        peer: AuthorityIndex,
    ) -> Option<Arc<RwLock<ConnectionKnowledge>>> {
        self.connection_knowledges.get(peer as usize).cloned()
    }

    /// Send a message to the actor. Non-blocking; drops on full channel.
    pub fn send(&self, msg: CordialKnowledgeMessage) {
        // Use try_send to avoid blocking the caller (core thread or connection
        // task). If the channel is full, we drop the message — the knowledge
        // tracker is best-effort and will self-correct via eviction.
        let _ = self.sender.try_send(msg);
    }

    /// Send a message to the actor, awaiting capacity.
    pub async fn send_async(&self, msg: CordialKnowledgeMessage) {
        let _ = self.sender.send(msg).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn block_ref(authority: u64, round: u64) -> BlockReference {
        BlockReference {
            authority,
            round,
            digest: Default::default(),
        }
    }

    #[test]
    fn test_new_header_and_take() {
        let mut ck = ConnectionKnowledge::new(1, 4);
        // Add headers from authority 0 at rounds 1, 2
        ck.new_header(block_ref(0, 1));
        ck.new_header(block_ref(0, 2));
        // Add header from authority 2 at round 1
        ck.new_header(block_ref(2, 1));
        // Header from peer 1 should be ignored
        ck.new_header(block_ref(1, 1));

        assert_eq!(ck.unknown_headers_count(), 3);

        let taken = ck.take_unsent_headers(2);
        assert_eq!(taken.len(), 2);
        assert_eq!(ck.unknown_headers_count(), 1);
    }

    #[test]
    fn test_mark_known_removes() {
        let mut ck = ConnectionKnowledge::new(1, 4);
        let r = block_ref(0, 5);
        ck.new_header(r);
        assert_eq!(ck.unknown_headers_count(), 1);
        ck.mark_header_known(r);
        assert_eq!(ck.unknown_headers_count(), 0);
    }

    #[test]
    fn test_evict_below() {
        let mut ck = ConnectionKnowledge::new(1, 4);
        for round in 1..=10 {
            ck.new_header(block_ref(0, round));
            ck.new_shard(block_ref(0, round));
        }
        assert_eq!(ck.unknown_headers_count(), 10);
        assert_eq!(ck.unknown_shards_count(), 10);

        // Evict authority 0 below round 5
        ck.evict_below(&[5, 0, 0, 0]);
        assert_eq!(ck.unknown_headers_count(), 5); // rounds 6..=10
        assert_eq!(ck.unknown_shards_count(), 5);
    }

    #[test]
    fn test_useful_authors_bitmask() {
        let mut ck = ConnectionKnowledge::new(1, 4);
        ck.last_useful_shards_to_peer_round[2] = Some(10);
        let (headers, shards) = ck.useful_authors_bitmasks(20);
        assert_eq!(headers, 0);
        // authority 2, round 10 + 40 >= 20 → still useful
        assert_ne!(shards & (1u128 << 2), 0);
    }

    #[tokio::test]
    async fn test_actor_propagates_new_header() {
        let (handle, actor) = CordialKnowledgeHandle::new(4, 0);
        let actor_task = tokio::spawn(actor.run());

        let r = block_ref(2, 5);
        handle.send(CordialKnowledgeMessage::NewHeader(r));

        // Give the actor a moment to process
        tokio::task::yield_now().await;

        // Peer 0 should see it (authority 2 != peer 0)
        let ck = handle.connection_knowledge(0).unwrap();
        assert_eq!(ck.read().unknown_headers_count(), 1);

        // Peer 2 should NOT see it (it's their own block)
        let ck2 = handle.connection_knowledge(2).unwrap();
        assert_eq!(ck2.read().unknown_headers_count(), 0);

        drop(handle);
        actor_task.await.ok();
    }
}
