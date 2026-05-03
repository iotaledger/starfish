// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Per-peer knowledge tracking for cordial push dissemination.
//!
//! [`CordialKnowledge`] is a centralized actor that receives DAG events (new
//! headers, new shards, evictions) and fans them out to per-peer
//! [`ConnectionKnowledge`] trackers. Each connection task holds an
//! `Arc<RwLock<ConnectionKnowledge>>` to read when building batches.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashSet;
use parking_lot::RwLock;
use tokio::sync::mpsc;

use crate::{
    metrics::Metrics,
    types::{AuthorityIndex, AuthoritySet, BlockReference, RoundNumber},
};

/// Maximum round gap beyond which a peer's data is no longer considered useful.
/// Headers/shards from an authority whose latest useful round is more than this
/// many rounds behind the current round will not be piggybacked.
const MAX_ROUND_GAP_FOR_USEFUL_PARTS: RoundNumber = 40;

/// Channel capacity for the cordial knowledge actor.
const CHANNEL_CAPACITY: usize = 100_000;
const METRICS_REPORT_INTERVAL: Duration = Duration::from_millis(500);

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

pub struct UsefulAuthorsMessage {
    pub peer: AuthorityIndex,
    pub headers: AuthoritySet,
    pub shards: AuthoritySet,
    pub round: RoundNumber,
}

/// Events sent to the [`CordialKnowledge`] actor.
pub enum CordialKnowledgeMessage {
    /// A new block header was added to the DAG.
    NewHeader(BlockReference),
    /// A new shard became available for a block.
    NewShard(BlockReference),
    /// A batch of new DAG parts entered local storage.
    DagParts {
        headers: Vec<BlockReference>,
        shards: Vec<BlockReference>,
    },
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
    UsefulAuthors(Box<UsefulAuthorsMessage>),
    /// A batch of newly useful shard authors was observed locally. Fan this
    /// demand out to all peers so they can proactively push shards for these
    /// authors to us.
    UsefulShardsFromPeers(Vec<BlockReference>),
    /// Evict entries below these per-authority rounds.
    EvictBelow(Vec<RoundNumber>),
}

// ---------------------------------------------------------------------------
// ConnectionKnowledge — per-peer tracker
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct RoundCursor {
    round: RoundNumber,
    index: usize,
}

struct SharedKnowledgeState {
    committee_size: usize,
    header_index: Vec<BTreeMap<RoundNumber, Vec<BlockReference>>>,
    shard_index: Vec<BTreeMap<RoundNumber, Vec<BlockReference>>>,
    known_headers: AHashSet<BlockReference>,
    known_shards: AHashSet<BlockReference>,
}

impl SharedKnowledgeState {
    fn new(committee_size: usize) -> Self {
        Self {
            committee_size,
            header_index: vec![BTreeMap::new(); committee_size],
            shard_index: vec![BTreeMap::new(); committee_size],
            known_headers: AHashSet::new(),
            known_shards: AHashSet::new(),
        }
    }

    fn insert_header(&mut self, block_ref: BlockReference) {
        let authority = block_ref.authority as usize;
        if authority >= self.committee_size || !self.known_headers.insert(block_ref) {
            return;
        }
        self.header_index[authority]
            .entry(block_ref.round)
            .or_default()
            .push(block_ref);
    }

    fn insert_shard(&mut self, block_ref: BlockReference) {
        let authority = block_ref.authority as usize;
        if authority >= self.committee_size || !self.known_shards.insert(block_ref) {
            return;
        }
        self.shard_index[authority]
            .entry(block_ref.round)
            .or_default()
            .push(block_ref);
    }

    fn insert_headers(&mut self, headers: &[BlockReference]) {
        for block_ref in headers {
            self.insert_header(*block_ref);
        }
    }

    fn insert_shards(&mut self, shards: &[BlockReference]) {
        for block_ref in shards {
            self.insert_shard(*block_ref);
        }
    }

    fn evict_below(&mut self, rounds: &[RoundNumber]) {
        for (authority, threshold) in rounds.iter().enumerate() {
            if authority >= self.committee_size {
                break;
            }
            let split_round = threshold.saturating_add(1);
            self.header_index[authority] = self.header_index[authority].split_off(&split_round);
            self.shard_index[authority] = self.shard_index[authority].split_off(&split_round);
        }
        self.known_headers.retain(|block_ref| {
            let authority = block_ref.authority as usize;
            authority >= rounds.len() || block_ref.round > rounds[authority]
        });
        self.known_shards.retain(|block_ref| {
            let authority = block_ref.authority as usize;
            authority >= rounds.len() || block_ref.round > rounds[authority]
        });
    }
}

/// Per-peer tracker: what headers and shards this peer doesn't know about yet.
pub struct ConnectionKnowledge {
    peer: AuthorityIndex,
    committee_size: usize,
    shared: Arc<RwLock<SharedKnowledgeState>>,
    header_cursors: Vec<RoundCursor>,
    shard_cursors: Vec<RoundCursor>,
    /// Headers we know this peer already has, so later `NewHeader` events do
    /// not re-queue them.
    known_headers: AHashSet<BlockReference>,
    /// Shards we know this peer already has, so later `NewShard` events do not
    /// re-queue them.
    known_shards: AHashSet<BlockReference>,
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
    fn update_last_useful_round(rounds: &mut [Option<RoundNumber>], block_ref: BlockReference) {
        let authority = block_ref.authority as usize;
        if authority >= rounds.len() {
            return;
        }
        let entry = &mut rounds[authority];
        match entry {
            Some(round) if block_ref.round > *round => *round = block_ref.round,
            None => *entry = Some(block_ref.round),
            _ => {}
        }
    }

    fn update_last_useful_rounds(
        rounds: &mut [Option<RoundNumber>],
        block_refs: &[BlockReference],
    ) {
        for block_ref in block_refs {
            Self::update_last_useful_round(rounds, *block_ref);
        }
    }

    fn recent_authors_bitmask(
        last_useful_rounds: &[Option<RoundNumber>],
        current_round: RoundNumber,
    ) -> AuthoritySet {
        let mut mask = AuthoritySet::default();
        for (authority, round) in last_useful_rounds.iter().enumerate() {
            if let Some(round) = round {
                if round.saturating_add(MAX_ROUND_GAP_FOR_USEFUL_PARTS) >= current_round {
                    mask.insert(authority as AuthorityIndex);
                }
            }
        }
        mask
    }

    fn next_from_cursor(
        index: &BTreeMap<RoundNumber, Vec<BlockReference>>,
        cursor: &mut RoundCursor,
        known: &mut AHashSet<BlockReference>,
        max_round: Option<RoundNumber>,
    ) -> Option<BlockReference> {
        let start_round = cursor.round.max(1);
        for (&round, refs) in index.range(start_round..) {
            if let Some(max_round) = max_round {
                if round > max_round {
                    return None;
                }
            }
            let start_index = if round == cursor.round {
                cursor.index
            } else {
                0
            };
            for (index_in_round, block_ref) in refs.iter().copied().enumerate().skip(start_index) {
                cursor.round = round;
                cursor.index = index_in_round + 1;
                if known.insert(block_ref) {
                    return Some(block_ref);
                }
            }
            cursor.round = round.saturating_add(1);
            cursor.index = 0;
        }
        None
    }

    fn take_from_cursors(
        &mut self,
        is_header: bool,
        limit: usize,
        excluded_authority: Option<AuthorityIndex>,
        allowed_authorities: AuthoritySet,
        max_round: Option<RoundNumber>,
    ) -> Vec<BlockReference> {
        if limit == 0 {
            return Vec::new();
        }

        let shared_handle = self.shared.clone();
        let shared = shared_handle.read();
        let indexes = if is_header {
            &shared.header_index
        } else {
            &shared.shard_index
        };
        let cursors = if is_header {
            &mut self.header_cursors
        } else {
            &mut self.shard_cursors
        };
        let known = if is_header {
            &mut self.known_headers
        } else {
            &mut self.known_shards
        };

        let mut result = Vec::with_capacity(limit);
        while result.len() < limit {
            let mut made_progress = false;
            for authority in 0..self.committee_size {
                let authority_index = authority as AuthorityIndex;
                if authority_index == self.peer
                    || excluded_authority == Some(authority_index)
                    || !allowed_authorities.contains(authority_index)
                {
                    continue;
                }
                let Some(block_ref) = Self::next_from_cursor(
                    &indexes[authority],
                    &mut cursors[authority],
                    known,
                    max_round,
                ) else {
                    continue;
                };
                result.push(block_ref);
                made_progress = true;
                if result.len() >= limit {
                    break;
                }
            }
            if !made_progress {
                break;
            }
        }
        result
    }

    fn take_from_exact_round(
        &mut self,
        is_header: bool,
        limit: usize,
        round: RoundNumber,
        excluded_authority: Option<AuthorityIndex>,
        allowed_authorities: AuthoritySet,
    ) -> Vec<BlockReference> {
        if limit == 0 {
            return Vec::new();
        }

        let shared_handle = self.shared.clone();
        let shared = shared_handle.read();
        let indexes = if is_header {
            &shared.header_index
        } else {
            &shared.shard_index
        };
        let known = if is_header {
            &mut self.known_headers
        } else {
            &mut self.known_shards
        };

        let mut result = Vec::with_capacity(limit);
        while result.len() < limit {
            let mut made_progress = false;
            for (authority, index_entry) in indexes.iter().enumerate().take(self.committee_size) {
                let authority_index = authority as AuthorityIndex;
                if authority_index == self.peer
                    || excluded_authority == Some(authority_index)
                    || !allowed_authorities.contains(authority_index)
                {
                    continue;
                }
                let Some(refs) = index_entry.get(&round) else {
                    continue;
                };
                let Some(block_ref) = refs
                    .iter()
                    .copied()
                    .find(|block_ref| known.insert(*block_ref))
                else {
                    continue;
                };
                result.push(block_ref);
                made_progress = true;
                if result.len() >= limit {
                    break;
                }
            }
            if !made_progress {
                break;
            }
        }
        result
    }

    pub fn new(peer: AuthorityIndex, committee_size: usize) -> Self {
        Self::new_with_shared(
            peer,
            committee_size,
            Arc::new(RwLock::new(SharedKnowledgeState::new(committee_size))),
        )
    }

    fn new_with_shared(
        peer: AuthorityIndex,
        committee_size: usize,
        shared: Arc<RwLock<SharedKnowledgeState>>,
    ) -> Self {
        Self {
            peer,
            committee_size,
            shared,
            header_cursors: vec![RoundCursor::default(); committee_size],
            shard_cursors: vec![RoundCursor::default(); committee_size],
            known_headers: AHashSet::new(),
            known_shards: AHashSet::new(),
            last_useful_headers_to_peer_round: vec![None; committee_size],
            last_useful_shards_to_peer_round: vec![None; committee_size],
            last_useful_headers_from_peer_round: vec![None; committee_size],
            last_useful_shards_from_peer_round: vec![None; committee_size],
        }
    }

    /// Record that a new header exists that this peer may not know about.
    pub fn new_header(&mut self, block_ref: BlockReference) {
        self.shared.write().insert_header(block_ref);
    }

    /// Record that a new shard exists that this peer may not know about.
    pub fn new_shard(&mut self, block_ref: BlockReference) {
        self.shared.write().insert_shard(block_ref);
    }

    /// Mark a header as known by this peer (received from them or inferred).
    pub fn mark_header_known(&mut self, block_ref: BlockReference) {
        let authority = block_ref.authority as usize;
        if authority < self.committee_size {
            self.known_headers.insert(block_ref);
        }
    }

    /// Mark a shard as known by this peer.
    pub fn mark_shard_known(&mut self, block_ref: BlockReference) {
        let authority = block_ref.authority as usize;
        if authority < self.committee_size {
            self.known_shards.insert(block_ref);
        }
    }

    pub fn knows_header(&self, block_ref: &BlockReference) -> bool {
        self.known_headers.contains(block_ref)
    }

    pub fn knows_shard(&self, block_ref: &BlockReference) -> bool {
        self.known_shards.contains(block_ref)
    }

    /// Drain the oldest unknown headers, up to `limit`, returning their block
    /// references.
    pub fn take_unsent_headers(&mut self, limit: usize) -> Vec<BlockReference> {
        self.take_from_cursors(
            true,
            limit,
            None,
            AuthoritySet::full(self.committee_size as AuthorityIndex),
            None,
        )
    }

    /// Drain the oldest unknown headers, excluding a single authority.
    pub fn take_unsent_headers_excluding_authority(
        &mut self,
        limit: usize,
        excluded_authority: AuthorityIndex,
    ) -> Vec<BlockReference> {
        self.take_from_cursors(
            true,
            limit,
            Some(excluded_authority),
            AuthoritySet::full(self.committee_size as AuthorityIndex),
            None,
        )
    }

    /// Drain the oldest unknown headers, but only for authorities currently
    /// considered useful to the peer.
    pub fn take_unsent_headers_for_authorities(
        &mut self,
        limit: usize,
        allowed_authorities: AuthoritySet,
    ) -> Vec<BlockReference> {
        self.take_from_cursors(true, limit, None, allowed_authorities, None)
    }

    pub fn take_unsent_headers_at_round_excluding_authority(
        &mut self,
        limit: usize,
        round: RoundNumber,
        excluded_authority: AuthorityIndex,
    ) -> Vec<BlockReference> {
        self.take_from_exact_round(
            true,
            limit,
            round,
            Some(excluded_authority),
            AuthoritySet::full(self.committee_size as AuthorityIndex),
        )
    }

    /// Drain the oldest unknown shards, up to `limit`, returning their block
    /// references.
    pub fn take_unsent_shards(&mut self, limit: usize) -> Vec<BlockReference> {
        self.take_from_cursors(
            false,
            limit,
            None,
            AuthoritySet::full(self.committee_size as AuthorityIndex),
            None,
        )
    }

    /// Drain the oldest unknown shards, but only for authorities currently
    /// considered useful to the peer.
    pub fn take_unsent_shards_for_authorities(
        &mut self,
        limit: usize,
        allowed_authorities: AuthoritySet,
    ) -> Vec<BlockReference> {
        self.take_from_cursors(false, limit, None, allowed_authorities, None)
    }

    pub fn take_unsent_shards_up_to_round(
        &mut self,
        limit: usize,
        round: RoundNumber,
    ) -> Vec<BlockReference> {
        self.take_from_cursors(
            false,
            limit,
            None,
            AuthoritySet::full(self.committee_size as AuthorityIndex),
            Some(round),
        )
    }

    pub fn take_unsent_shards_up_to_round_excluding_authority(
        &mut self,
        limit: usize,
        round: RoundNumber,
        excluded_authority: AuthorityIndex,
    ) -> Vec<BlockReference> {
        self.take_from_cursors(
            false,
            limit,
            Some(excluded_authority),
            AuthoritySet::full(self.committee_size as AuthorityIndex),
            Some(round),
        )
    }

    fn evict_local_below(&mut self, rounds: &[RoundNumber]) {
        for (authority, threshold) in rounds.iter().enumerate() {
            if authority >= self.committee_size {
                break;
            }
            let split_round = threshold.saturating_add(1);
            if self.header_cursors[authority].round < split_round {
                self.header_cursors[authority] = RoundCursor {
                    round: split_round,
                    index: 0,
                };
            }
            if self.shard_cursors[authority].round < split_round {
                self.shard_cursors[authority] = RoundCursor {
                    round: split_round,
                    index: 0,
                };
            }
        }
        self.known_headers.retain(|block_ref| {
            let authority = block_ref.authority as usize;
            authority >= rounds.len() || block_ref.round > rounds[authority]
        });
        self.known_shards.retain(|block_ref| {
            let authority = block_ref.authority as usize;
            authority >= rounds.len() || block_ref.round > rounds[authority]
        });
    }

    /// Evict all entries below the given per-authority rounds.
    pub fn evict_below(&mut self, rounds: &[RoundNumber]) {
        self.shared.write().evict_below(rounds);
        self.evict_local_below(rounds);
    }

    /// Record that a header received from this peer was useful to us.
    pub fn mark_header_useful_from_peer(&mut self, block_ref: BlockReference) {
        Self::update_last_useful_round(&mut self.last_useful_headers_from_peer_round, block_ref);
    }

    /// Batch variant: record that multiple headers from this peer were useful.
    pub fn mark_headers_useful_from_peer(&mut self, block_refs: &[BlockReference]) {
        Self::update_last_useful_rounds(&mut self.last_useful_headers_from_peer_round, block_refs);
    }

    /// Record that a header from this authority is currently useful to the
    /// peer, based on an explicit request they sent us.
    pub fn mark_header_useful_to_peer(&mut self, block_ref: BlockReference) {
        let authority = block_ref.authority as usize;
        if authority < self.committee_size {
            let entry = &mut self.last_useful_headers_to_peer_round[authority];
            match entry {
                Some(round) if block_ref.round > *round => *round = block_ref.round,
                None => *entry = Some(block_ref.round),
                _ => {}
            }
        }
    }

    /// Batch variant: record that multiple shards from this peer were useful.
    pub fn mark_shards_useful_from_peer(&mut self, block_refs: &[BlockReference]) {
        Self::update_last_useful_rounds(&mut self.last_useful_shards_from_peer_round, block_refs);
    }

    /// Record that a shard received from this peer was useful to us.
    pub fn mark_shard_useful_from_peer(&mut self, block_ref: BlockReference) {
        Self::update_last_useful_round(&mut self.last_useful_shards_from_peer_round, block_ref);
    }

    /// Global variant: shard-demand learned from one peer should be advertised
    /// back out to all peers that may be able to help.
    pub fn mark_shards_useful_from_peers(&mut self, block_refs: &[BlockReference]) {
        Self::update_last_useful_rounds(&mut self.last_useful_shards_from_peer_round, block_refs);
    }

    /// Record that a shard from this authority is currently useful to the
    /// peer, based on an explicit request they sent us.
    pub fn mark_shard_useful_to_peer(&mut self, block_ref: BlockReference) {
        let authority = block_ref.authority as usize;
        if authority < self.committee_size {
            let entry = &mut self.last_useful_shards_to_peer_round[authority];
            match entry {
                Some(round) if block_ref.round > *round => *round = block_ref.round,
                None => *entry = Some(block_ref.round),
                _ => {}
            }
        }
    }

    /// Update which authorities' data the peer wants from us. The bitmasks
    /// come from the peer's `BlockBatch` and `round` is the max round of that
    /// batch. Updates are monotonic — only applied if `round` exceeds the
    /// previously recorded value.
    pub fn update_useful_authors_to_peer(
        &mut self,
        headers_bitmask: AuthoritySet,
        shards_bitmask: AuthoritySet,
        round: RoundNumber,
    ) {
        for i in headers_bitmask.present() {
            let entry = &mut self.last_useful_headers_to_peer_round[i as usize];
            match entry {
                Some(r) if round > *r => *r = round,
                None => *entry = Some(round),
                _ => {}
            }
        }
        for i in shards_bitmask.present() {
            let entry = &mut self.last_useful_shards_to_peer_round[i as usize];
            match entry {
                Some(r) if round > *r => *r = round,
                None => *entry = Some(round),
                _ => {}
            }
        }
    }

    /// Build bitmasks indicating which authorities' headers/shards we'd find
    /// useful FROM this peer. Used when constructing a batch to send to this
    /// peer.
    pub fn useful_authors_bitmasks(
        &self,
        current_round: RoundNumber,
    ) -> (AuthoritySet, AuthoritySet) {
        (
            Self::recent_authors_bitmask(&self.last_useful_headers_from_peer_round, current_round),
            Self::recent_authors_bitmask(&self.last_useful_shards_from_peer_round, current_round),
        )
    }

    /// Build bitmasks indicating which authorities' headers/shards are still
    /// useful TO this peer. This gates which extra parts we piggyback.
    pub fn useful_authors_to_peer_bitmasks(
        &self,
        current_round: RoundNumber,
    ) -> (AuthoritySet, AuthoritySet) {
        (
            Self::recent_authors_bitmask(&self.last_useful_headers_to_peer_round, current_round),
            Self::recent_authors_bitmask(&self.last_useful_shards_to_peer_round, current_round),
        )
    }

    pub fn peer(&self) -> AuthorityIndex {
        self.peer
    }

    pub fn known_headers_len(&self) -> usize {
        self.known_headers.len()
    }

    pub fn known_shards_len(&self) -> usize {
        self.known_shards.len()
    }
}

#[cfg(test)]
impl ConnectionKnowledge {
    pub fn unknown_headers_count(&self) -> usize {
        let shared = self.shared.read();
        shared
            .header_index
            .iter()
            .enumerate()
            .filter(|(authority, _)| *authority as AuthorityIndex != self.peer)
            .map(|(_, rounds)| {
                rounds
                    .values()
                    .flat_map(|refs| refs.iter())
                    .filter(|block_ref| !self.known_headers.contains(block_ref))
                    .count()
            })
            .sum()
    }

    pub fn unknown_shards_count(&self) -> usize {
        let shared = self.shared.read();
        shared
            .shard_index
            .iter()
            .enumerate()
            .filter(|(authority, _)| *authority as AuthorityIndex != self.peer)
            .map(|(_, rounds)| {
                rounds
                    .values()
                    .flat_map(|refs| refs.iter())
                    .filter(|block_ref| !self.known_shards.contains(block_ref))
                    .count()
            })
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
    shared: Arc<RwLock<SharedKnowledgeState>>,
    /// One per peer, shared with connection tasks via `Arc<RwLock<>>`.
    connection_knowledges: Vec<Arc<RwLock<ConnectionKnowledge>>>,
    /// Receives events from DagState / core / shard reconstructor.
    receiver: mpsc::Receiver<CordialKnowledgeMessage>,
    metrics: Arc<Metrics>,
}

impl CordialKnowledge {
    /// Run the actor loop. Blocks until the channel is closed.
    pub async fn run(mut self) {
        let mut next_metrics_report = Instant::now();
        while let Some(msg) = self.receiver.recv().await {
            match msg {
                CordialKnowledgeMessage::NewHeader(block_ref) => {
                    self.shared.write().insert_header(block_ref);
                }
                CordialKnowledgeMessage::NewShard(block_ref) => {
                    self.shared.write().insert_shard(block_ref);
                }
                CordialKnowledgeMessage::DagParts { headers, shards } => {
                    let mut shared = self.shared.write();
                    shared.insert_headers(&headers);
                    shared.insert_shards(&shards);
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
                CordialKnowledgeMessage::UsefulAuthors(msg) => {
                    let UsefulAuthorsMessage {
                        peer,
                        headers,
                        shards,
                        round,
                    } = *msg;
                    let idx = peer as usize;
                    if idx < self.committee_size {
                        self.connection_knowledges[idx]
                            .write()
                            .update_useful_authors_to_peer(headers, shards, round);
                    }
                }
                CordialKnowledgeMessage::UsefulShardsFromPeers(block_refs) => {
                    for ck in &self.connection_knowledges {
                        ck.write().mark_shards_useful_from_peers(&block_refs);
                    }
                }
                CordialKnowledgeMessage::EvictBelow(rounds) => {
                    self.shared.write().evict_below(&rounds);
                    for ck in &self.connection_knowledges {
                        ck.write().evict_local_below(&rounds);
                    }
                }
            }
            let now = Instant::now();
            if now >= next_metrics_report {
                self.report_metrics();
                next_metrics_report = now + METRICS_REPORT_INTERVAL;
            }
        }
    }

    fn report_metrics(&self) {
        let shared = self.shared.read();
        self.metrics
            .ck_known_headers
            .set(shared.known_headers.len() as i64);
        self.metrics
            .ck_known_shards
            .set(shared.known_shards.len() as i64);

        let pending_h: usize = shared
            .header_index
            .iter()
            .flat_map(|m| m.values())
            .map(|v| v.len())
            .sum();
        let pending_s: usize = shared
            .shard_index
            .iter()
            .flat_map(|m| m.values())
            .map(|v| v.len())
            .sum();
        self.metrics.ck_pending_headers.set(pending_h as i64);
        self.metrics.ck_pending_shards.set(pending_s as i64);
        drop(shared);

        for ck in &self.connection_knowledges {
            let ck = ck.read();
            let peer = ck.peer().to_string();
            self.metrics
                .ck_peer_known_headers
                .with_label_values(&[&peer])
                .set(ck.known_headers_len() as i64);
            self.metrics
                .ck_peer_known_shards
                .with_label_values(&[&peer])
                .set(ck.known_shards_len() as i64);
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
    pub fn new(committee_size: usize, metrics: Arc<Metrics>) -> (Self, CordialKnowledge) {
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
        let shared = Arc::new(RwLock::new(SharedKnowledgeState::new(committee_size)));

        let connection_knowledges: Vec<_> = (0..committee_size)
            .map(|i| {
                Arc::new(RwLock::new(ConnectionKnowledge::new_with_shared(
                    i as AuthorityIndex,
                    committee_size,
                    shared.clone(),
                )))
            })
            .collect();

        let handle = Self {
            sender,
            connection_knowledges: connection_knowledges.clone(),
        };

        let actor = CordialKnowledge {
            committee_size,
            shared,
            connection_knowledges,
            receiver,
            metrics,
        };

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
    use prometheus::Registry;

    use super::*;

    fn test_metrics() -> Arc<Metrics> {
        let registry = Registry::new();
        let (metrics, _) = Metrics::new(&registry, None, None, None);
        metrics
    }

    fn block_ref(authority: AuthorityIndex, round: RoundNumber) -> BlockReference {
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
    fn test_mark_known_prevents_requeue() {
        let mut ck = ConnectionKnowledge::new(1, 4);
        let r = block_ref(0, 5);

        ck.new_header(r);
        ck.mark_header_known(r);
        ck.new_header(r);
        assert_eq!(ck.unknown_headers_count(), 0);

        ck.new_shard(r);
        ck.mark_shard_known(r);
        ck.new_shard(r);
        assert_eq!(ck.unknown_shards_count(), 0);
    }

    #[test]
    fn test_take_unsent_headers_excluding_authority() {
        let mut ck = ConnectionKnowledge::new(1, 4);
        let own = block_ref(0, 5);
        let other = block_ref(2, 5);

        ck.new_header(own);
        ck.new_header(other);

        let drained = ck.take_unsent_headers_excluding_authority(10, 0);
        assert_eq!(drained, vec![other]);
        assert_eq!(ck.unknown_headers_count(), 1);

        let remaining = ck.take_unsent_headers(10);
        assert_eq!(remaining, vec![own]);
    }

    #[test]
    fn test_take_unsent_headers_for_authorities() {
        let mut ck = ConnectionKnowledge::new(1, 4);
        let first = block_ref(0, 5);
        let second = block_ref(2, 5);

        ck.new_header(first);
        ck.new_header(second);

        let drained = ck.take_unsent_headers_for_authorities(10, AuthoritySet::singleton(2));
        assert_eq!(drained, vec![second]);
        assert_eq!(ck.unknown_headers_count(), 1);

        let remaining = ck.take_unsent_headers(10);
        assert_eq!(remaining, vec![first]);
    }

    #[test]
    fn test_take_unsent_headers_at_round_excluding_authority() {
        let mut ck = ConnectionKnowledge::new(1, 4);
        let round_four = block_ref(0, 4);
        let round_five_a = block_ref(0, 5);
        let round_five_b = block_ref(2, 5);

        ck.new_header(round_four);
        ck.new_header(round_five_a);
        ck.new_header(round_five_b);

        let drained = ck.take_unsent_headers_at_round_excluding_authority(10, 5, 0);
        assert_eq!(drained, vec![round_five_b]);

        let remaining = ck.take_unsent_headers(10);
        assert_eq!(remaining, vec![round_four, round_five_a]);
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
        ck.mark_header_useful_from_peer(block_ref(0, 10));
        ck.mark_shard_useful_from_peer(block_ref(2, 10));
        let (headers, shards) = ck.useful_authors_bitmasks(20);
        assert!(headers.contains(0));
        // authority 2, round 10 + 40 >= 20 → still useful
        assert!(shards.contains(2));
    }

    #[test]
    fn test_useful_authors_to_peer_bitmask() {
        let mut ck = ConnectionKnowledge::new(1, 4);
        ck.mark_header_useful_to_peer(block_ref(0, 10));
        ck.mark_shard_useful_to_peer(block_ref(2, 10));
        let (headers, shards) = ck.useful_authors_to_peer_bitmasks(20);
        assert!(headers.contains(0));
        assert!(shards.contains(2));
    }

    #[test]
    fn test_update_useful_authors_to_peer() {
        let mut ck = ConnectionKnowledge::new(1, 4);

        // Authority 0 and 2 are useful at round 10
        let bitmask = AuthoritySet::singleton(0) | AuthoritySet::singleton(2);
        ck.update_useful_authors_to_peer(bitmask, bitmask, 10);
        assert_eq!(ck.last_useful_headers_to_peer_round[0], Some(10));
        assert_eq!(ck.last_useful_headers_to_peer_round[2], Some(10));
        assert_eq!(ck.last_useful_shards_to_peer_round[0], Some(10));
        assert_eq!(ck.last_useful_shards_to_peer_round[2], Some(10));
        // Authority 1 untouched
        assert_eq!(ck.last_useful_headers_to_peer_round[1], None);

        // Monotonic: round 5 should NOT overwrite round 10
        ck.update_useful_authors_to_peer(bitmask, bitmask, 5);
        assert_eq!(ck.last_useful_headers_to_peer_round[0], Some(10));

        // Higher round updates
        ck.update_useful_authors_to_peer(AuthoritySet::singleton(0), AuthoritySet::default(), 15);
        assert_eq!(ck.last_useful_headers_to_peer_round[0], Some(15));
        // Shards for authority 0 unchanged (shards bitmask was 0)
        assert_eq!(ck.last_useful_shards_to_peer_round[0], Some(10));
    }

    #[test]
    fn test_mark_header_useful_to_peer() {
        let mut ck = ConnectionKnowledge::new(1, 4);

        ck.mark_header_useful_to_peer(block_ref(2, 10));
        assert_eq!(ck.last_useful_headers_to_peer_round[2], Some(10));

        ck.mark_header_useful_to_peer(block_ref(2, 7));
        assert_eq!(ck.last_useful_headers_to_peer_round[2], Some(10));

        ck.mark_header_useful_to_peer(block_ref(2, 12));
        assert_eq!(ck.last_useful_headers_to_peer_round[2], Some(12));
    }

    #[test]
    fn test_mark_shard_useful_to_peer() {
        let mut ck = ConnectionKnowledge::new(1, 4);

        ck.mark_shard_useful_to_peer(block_ref(2, 10));
        assert_eq!(ck.last_useful_shards_to_peer_round[2], Some(10));

        ck.mark_shard_useful_to_peer(block_ref(2, 7));
        assert_eq!(ck.last_useful_shards_to_peer_round[2], Some(10));

        ck.mark_shard_useful_to_peer(block_ref(2, 12));
        assert_eq!(ck.last_useful_shards_to_peer_round[2], Some(12));
    }

    #[test]
    fn test_take_unsent_shards_up_to_round() {
        let mut ck = ConnectionKnowledge::new(1, 4);
        let early = block_ref(0, 3);
        let middle = block_ref(2, 5);
        let late = block_ref(3, 7);

        ck.new_shard(early);
        ck.new_shard(middle);
        ck.new_shard(late);

        let drained = ck.take_unsent_shards_up_to_round(10, 5);
        assert_eq!(drained, vec![early, middle]);

        let remaining = ck.take_unsent_shards(10);
        assert_eq!(remaining, vec![late]);
    }

    #[test]
    fn test_take_unsent_shards_up_to_round_excluding_authority() {
        let mut ck = ConnectionKnowledge::new(1, 4);
        let excluded = block_ref(0, 3);
        let kept = block_ref(2, 5);
        let late = block_ref(3, 7);

        ck.new_shard(excluded);
        ck.new_shard(kept);
        ck.new_shard(late);

        let drained = ck.take_unsent_shards_up_to_round_excluding_authority(10, 5, 0);
        assert_eq!(drained, vec![kept]);

        let remaining = ck.take_unsent_shards(10);
        assert_eq!(remaining, vec![excluded, late]);
    }

    #[tokio::test]
    async fn test_actor_useful_authors_updates_to_peer() {
        let (handle, actor) = CordialKnowledgeHandle::new(4, test_metrics());
        let actor_task = tokio::spawn(actor.run());

        // Peer 1 tells us authorities 0 and 2 are useful at round 10
        let bitmask = AuthoritySet::singleton(0) | AuthoritySet::singleton(2);
        handle.send(CordialKnowledgeMessage::UsefulAuthors(Box::new(
            UsefulAuthorsMessage {
                peer: 1,
                headers: bitmask,
                shards: bitmask,
                round: 10,
            },
        )));

        tokio::task::yield_now().await;

        {
            let ck = handle.connection_knowledge(1).unwrap();
            let ck = ck.read();
            assert_eq!(ck.last_useful_headers_to_peer_round[0], Some(10));
            assert_eq!(ck.last_useful_shards_to_peer_round[2], Some(10));
        }

        drop(handle);
        actor_task.await.ok();
    }

    #[tokio::test]
    async fn test_actor_propagates_useful_shards_from_peers_to_all_connections() {
        let (handle, actor) = CordialKnowledgeHandle::new(4, test_metrics());
        let actor_task = tokio::spawn(actor.run());

        handle.send(CordialKnowledgeMessage::UsefulShardsFromPeers(vec![
            block_ref(0, 10),
            block_ref(2, 12),
            block_ref(0, 8),
        ]));

        tokio::task::yield_now().await;

        for peer in 0..4 {
            let ck = handle.connection_knowledge(peer).unwrap();
            let ck = ck.read();
            assert_eq!(ck.last_useful_shards_from_peer_round[0], Some(10));
            assert_eq!(ck.last_useful_shards_from_peer_round[2], Some(12));
        }

        handle.send(CordialKnowledgeMessage::UsefulShardsFromPeers(vec![
            block_ref(0, 7),
            block_ref(2, 11),
        ]));

        tokio::task::yield_now().await;

        for peer in 0..4 {
            let ck = handle.connection_knowledge(peer).unwrap();
            let ck = ck.read();
            assert_eq!(ck.last_useful_shards_from_peer_round[0], Some(10));
            assert_eq!(ck.last_useful_shards_from_peer_round[2], Some(12));
        }

        drop(handle);
        actor_task.await.ok();
    }

    #[tokio::test]
    async fn test_actor_propagates_new_header() {
        let (handle, actor) = CordialKnowledgeHandle::new(4, test_metrics());
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

    #[tokio::test]
    async fn test_actor_propagates_dag_parts_batch() {
        let (handle, actor) = CordialKnowledgeHandle::new(4, test_metrics());
        let actor_task = tokio::spawn(actor.run());

        let header = block_ref(2, 5);
        let shard = block_ref(3, 6);
        handle.send(CordialKnowledgeMessage::DagParts {
            headers: vec![header],
            shards: vec![shard],
        });

        tokio::task::yield_now().await;

        let ck = handle.connection_knowledge(0).unwrap();
        {
            let ck = ck.read();
            assert!(!ck.knows_header(&header));
            assert_eq!(ck.unknown_headers_count(), 1);
            assert_eq!(ck.unknown_shards_count(), 1);
        }

        let ck3 = handle.connection_knowledge(3).unwrap();
        assert_eq!(ck3.read().unknown_shards_count(), 0);

        drop(handle);
        actor_task.await.ok();
    }
}
