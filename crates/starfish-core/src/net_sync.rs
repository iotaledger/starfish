// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use ahash::{AHashMap, AHashSet};
use futures::future::join_all;
use rand::seq::SliceRandom;
use reed_solomon_simd::ReedSolomonEncoder;
use tokio::time::Instant;
use tokio::{
    select,
    sync::{Notify, mpsc},
};

use crate::{
    block_handler::BlockHandler,
    bls_certificate_aggregator::{BlsCertificateAggregator, CertificateEvent},
    bls_service::{BlsServiceHandle, BlsServiceMessage, start_bls_service},
    broadcaster::{BlockDisseminator, BlockFetcher, BroadcasterParameters, DataRequester},
    committee::Committee,
    config::{DisseminationMode, NodeParameters},
    consensus::universal_committer::UniversalCommitter,
    cordial_knowledge::{
        ConnectionKnowledge, CordialKnowledgeHandle, CordialKnowledgeMessage, UsefulAuthorsMessage,
    },
    core::Core,
    core_thread::CoreThreadDispatcher,
    crypto::{Blake3Hasher, BlsSigner, MacKey},
    dag_state::{ConsensusProtocol, DagState, DataSource},
    data::Data,
    metrics::{Metrics, UtilizationTimerVecExt},
    network::{BlockBatch, Connection, Network, NetworkMessage, ShardPayload},
    runtime::{Handle, JoinError, JoinHandle, sleep},
    sailfish_service::{
        SailfishCertEvent, SailfishServiceHandle, SailfishServiceMessage, start_sailfish_service,
    },
    shard_reconstructor::{DecodedBlocks, ShardMessage, start_shard_reconstructor},
    starfish_rbc::{PinnedRbcHeader, RbcCanonicalHeader, RbcCommitteeId, RbcProtocolInstanceId},
    starfish_rbc_dag::{
        RbcDagCommitteeContextV1, RbcDagContextV1, RbcDagProtocolInstanceId,
        storage::ShadowWalSyncPolicyV1,
    },
    starfish_rbc_dag_shadow::{
        ShadowAuthorizerV1, ShadowDeliveryComparisonV1, ShadowDeliveryIdentityV1,
    },
    starfish_rbc_dag_shadow_service::{
        ShadowServiceErrorV1, ShadowServiceEventV1, StarfishRbcDagShadowServiceHandleV1,
        start_starfish_rbc_dag_autonomous_clock_service_v1,
        start_starfish_rbc_dag_shadow_service_v1,
    },
    starfish_rbc_service::{
        RbcInitialAuthenticator, RbcPhaseAuthorityV1, RbcServiceEvent, RbcServiceHandle,
        start_starfish_rbc_service_with_phase_authority,
    },
    syncer::{CommitObserver, Syncer, SyncerSignals},
    types::{
        AuthorityIndex, AuthoritySet, BlockAuthentication, BlockAuthenticationScheme, BlockDigest,
        BlockReference, PartialSig, PartialSigKind, ProvableShard, ReconstructedTransactionData,
        RoundNumber, TransactionData, VerifiedBlock, format_authority_index,
    },
};

const MAX_FILTER_SIZE: usize = 100_000;
const SAILFISH_CERT_BATCH_FLUSH_INTERVAL: Duration = Duration::from_millis(5);
const SAILFISH_CERT_BATCH_MAX_LEN: usize = 256;
const STARFISH_RBC_HEADER_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const STARFISH_RBC_DAG_SHADOW_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const STARFISH_RBC_DAG_AUTONOMOUS_INSTANCE_CONTEXT: &str =
    "STARFISH_RBC_DAG_AUTONOMOUS_CLOCK_V1_PROTOCOL_INSTANCE";

/// Recover the exact locally selected Starfish-RBC chain so the persisted
/// non-authoritative shadow can reconcile a WAL that ended before the direct
/// DAG. The newest local block determines the branch when a Byzantine test
/// produced more than one value in a round.
fn recovered_local_rbc_headers<H: BlockHandler>(
    core: &Core<H>,
) -> Result<Vec<RbcCanonicalHeader>, String> {
    if !core.dag_state().consensus_protocol.is_starfish_rbc() || core.last_proposed() == 0 {
        return Ok(Vec::new());
    }

    let own_authority = core.authority();
    let store = core.store();
    let mut current = core.last_own_block().clone();
    let mut reversed = Vec::with_capacity(current.round() as usize);
    loop {
        if current.round() == 0 {
            break;
        }
        if current.authority() != own_authority {
            return Err(format!(
                "recovered local chain contains authority {} at round {} (expected {})",
                current.authority(),
                current.round(),
                own_authority
            ));
        }
        reversed.push(
            RbcCanonicalHeader::from_block_header(current.header()).map_err(|error| {
                format!(
                    "recovered local Starfish-RBC header {} is not canonical: {error}",
                    current.reference()
                )
            })?,
        );
        if current.round() == 1 {
            break;
        }

        let expected_round = current.round() - 1;
        let predecessor = current
            .block_references()
            .iter()
            .find(|reference| {
                reference.authority == own_authority && reference.round == expected_round
            })
            .copied()
            .ok_or_else(|| {
                format!(
                    "recovered local Starfish-RBC block {} has no own predecessor at round {}",
                    current.reference(),
                    expected_round
                )
            })?;
        current = core
            .dag_state()
            .get_blocks_at_authority_round(own_authority, expected_round)
            .into_iter()
            .find(|block| block.reference() == &predecessor)
            .or_else(|| store.get_block(&predecessor).ok().flatten())
            .ok_or_else(|| {
                format!("recovered local Starfish-RBC predecessor {predecessor} is unavailable")
            })?;
    }
    reversed.reverse();
    Ok(reversed)
}

fn shadow_transport_error_invalidates_run(error: &ShadowServiceErrorV1) -> bool {
    matches!(
        error,
        ShadowServiceErrorV1::Overloaded { .. } | ShadowServiceErrorV1::Stopped
    )
}

fn invalidate_shadow_run(metrics: &Metrics) {
    // Exactly one verdict is active for a configured shadow mode, but setting
    // both to zero makes every transport/startup failure fail closed without
    // duplicating mode knowledge throughout the network plumbing.
    metrics.starfish_rbc_dag_shadow_comparison_valid.set(0);
    metrics.starfish_rbc_dag_shadow_clock_valid.set(0);
}

fn rbc_dag_shadow_protocol_instance(
    direct_instance: [u8; 32],
    autonomous_clock: bool,
) -> RbcDagProtocolInstanceId {
    let bytes = if autonomous_clock {
        // Autonomous heartbeat carriers intentionally do not authenticate in
        // the same namespace as milestone-three's direct-header mirror. This
        // makes a heterogeneous deployment fail closed at the shadow boundary
        // instead of cross-admitting application and control carriers.
        let mut hasher = Blake3Hasher::new_derive_key(STARFISH_RBC_DAG_AUTONOMOUS_INSTANCE_CONTEXT);
        hasher.update(&direct_instance);
        *hasher.finalize().as_bytes()
    } else {
        direct_instance
    };
    RbcDagProtocolInstanceId::new(bytes)
        .expect("a configured direct RBC instance and its derived namespace are nonzero")
}

/// Enforce the MAC experiment's transport contract before cryptographic
/// verification:
///
/// - a full vector is accepted only on proactive block streaming directly from
///   the block's claimed author;
/// - every relay and synchronization path must carry one recipient tag;
/// - a direct author stream must carry the full vector, so recipients retain
///   the material needed for one-hop relay.
fn verify_mac_transport(
    block: &VerifiedBlock,
    authentication_scheme: BlockAuthenticationScheme,
    peer_id: AuthorityIndex,
    source: DataSource,
) -> eyre::Result<()> {
    if authentication_scheme != BlockAuthenticationScheme::MacVector {
        return Ok(());
    }

    let direct_author_stream = peer_id == block.authority()
        && matches!(
            source,
            DataSource::BlockBundleStreaming | DataSource::BlockBundleStreamingHeader
        );

    match block.authentication() {
        BlockAuthentication::MacVector(_) if direct_author_stream => Ok(()),
        BlockAuthentication::MacVector(_) => eyre::bail!(
            "Full MAC vector for block {} must arrive via direct author block streaming; \
             received from authority {} with source {}",
            block.reference(),
            peer_id,
            source,
        ),
        BlockAuthentication::MacTag(_) if !direct_author_stream => Ok(()),
        BlockAuthentication::MacTag(_) => eyre::bail!(
            "Direct author block stream for block {} must carry the full MAC vector",
            block.reference(),
        ),
        _ => Ok(()),
    }
}

fn verify_starfish_rbc_transaction_payload(
    canonical_header: &RbcCanonicalHeader,
    transaction_data: Arc<TransactionData>,
    committee: &Committee,
    own_id: AuthorityIndex,
    peer_id: AuthorityIndex,
    encoder: &mut ReedSolomonEncoder,
    authentication_scheme: BlockAuthenticationScheme,
    mac_keys: &[MacKey],
) -> eyre::Result<ReconstructedTransactionData> {
    let block_reference = canonical_header.reference();
    let transaction_data = Arc::try_unwrap(transaction_data).unwrap_or_else(|data| (*data).clone());
    let (block_header, _) = canonical_header.to_authentication_free_block().into_parts();
    let mut block = VerifiedBlock::from_parts(block_header, Some(transaction_data));
    let Some(mut shard_data) = block.verify_with_authentication(
        committee,
        own_id as usize,
        peer_id as usize,
        encoder,
        ConsensusProtocol::StarfishRbc,
        authentication_scheme,
        mac_keys,
    )?
    else {
        eyre::bail!("Starfish-RBC transaction payload for {block_reference} is empty");
    };
    block.preserialize();
    shard_data.preserialize();
    let transaction_data = block
        .transaction_data()
        .expect("verified RBC payload must contain transaction data")
        .clone();
    Ok(ReconstructedTransactionData {
        block_reference,
        transaction_data,
        shard_data,
    })
}

/// Prepare blocks forwarded through relay or synchronization paths for a
/// specific peer. Legacy MAC-experiment blocks retain their complete vector
/// only at direct recipients; forwarding selects the destination's tag. A
/// tag-only copy cannot be forwarded again and is therefore omitted.
/// Starfish-RBC carriers are authentication-free and remain forwardable: the
/// separate RBC service, rather than the carrier, controls clean admission.
pub(crate) fn prepare_forwarded_blocks_for_peer(
    authentication_scheme: BlockAuthenticationScheme,
    consensus_protocol: ConsensusProtocol,
    recipient: AuthorityIndex,
    blocks: Vec<Data<VerifiedBlock>>,
) -> Vec<Data<VerifiedBlock>> {
    if authentication_scheme != BlockAuthenticationScheme::MacVector
        || consensus_protocol.is_starfish_rbc()
    {
        return blocks;
    }

    blocks
        .into_iter()
        .filter_map(|block| {
            block
                .with_recipient_mac(recipient)
                .map(Data::new)
                .or_else(|| {
                    tracing::debug!(
                        "Cannot forward MAC-authenticated block {} to authority {}: \
                         complete MAC vector is unavailable",
                        block.reference(),
                        recipient,
                    );
                    None
                })
        })
        .collect()
}

async fn send_network_message_reliably(
    sender: &mpsc::Sender<NetworkMessage>,
    message: NetworkMessage,
) {
    match sender.try_send(message) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(message)) => {
            let _ = sender.send(message).await;
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
}

async fn broadcast_sailfish_cert_messages(
    senders: &[mpsc::Sender<NetworkMessage>],
    cert_messages: &[crate::types::CertMessage],
) {
    if cert_messages.is_empty() {
        return;
    }

    if cert_messages.len() == 1 {
        let cert_message = cert_messages[0].clone();
        for sender in senders {
            send_network_message_reliably(
                sender,
                NetworkMessage::CertMessage(cert_message.clone()),
            )
            .await;
        }
        return;
    }

    let cert_batch = cert_messages.to_vec();
    for sender in senders {
        send_network_message_reliably(sender, NetworkMessage::CertBatch(cert_batch.clone())).await;
    }
}

fn select_random_peers<R>(
    mut candidates: Vec<AuthorityIndex>,
    max_peers: usize,
    rng: &mut R,
) -> Vec<AuthorityIndex>
where
    R: rand::Rng + ?Sized,
{
    candidates.shuffle(rng);
    candidates.truncate(candidates.len().min(max_peers));
    candidates
}

fn select_random_peer_senders<H, C>(
    inner: &Arc<NetworkSyncerInner<H, C>>,
    max_peers: usize,
) -> Vec<(AuthorityIndex, mpsc::Sender<NetworkMessage>)>
where
    H: BlockHandler,
    C: CommitObserver,
{
    let peer_senders = inner.peer_senders.read();
    let candidates = select_random_peers(
        peer_senders.keys().copied().collect(),
        max_peers,
        &mut rand::thread_rng(),
    );
    candidates
        .into_iter()
        .filter_map(|authority| {
            peer_senders
                .get(&authority)
                .map(|sender| (authority, sender.clone()))
        })
        .collect()
}

fn eligible_missing_parent_refs(
    missing_refs: &[BlockReference],
    first_seen: &mut AHashMap<BlockReference, Instant>,
    last_requested: &mut AHashMap<BlockReference, Instant>,
    now: Instant,
    retry_interval: Duration,
) -> Vec<BlockReference> {
    let pending: AHashSet<_> = missing_refs.iter().copied().collect();
    first_seen.retain(|block_ref, _| pending.contains(block_ref));
    last_requested.retain(|block_ref, _| pending.contains(block_ref));

    missing_refs
        .iter()
        .filter_map(|block_ref| {
            let first = first_seen.entry(*block_ref).or_insert(now);
            if now.duration_since(*first) < retry_interval {
                return None;
            }
            if let Some(last) = last_requested.get(block_ref) {
                if now.duration_since(*last) < retry_interval {
                    return None;
                }
            }
            Some(*block_ref)
        })
        .collect()
}

struct FilterForBlocks {
    digests: parking_lot::RwLock<AHashSet<BlockDigest>>,
    full_mac_vectors: parking_lot::RwLock<AHashSet<BlockDigest>>,
    queue: parking_lot::RwLock<VecDeque<BlockDigest>>,
}

impl FilterForBlocks {
    fn new() -> Self {
        Self {
            digests: parking_lot::RwLock::new(AHashSet::new()),
            full_mac_vectors: parking_lot::RwLock::new(AHashSet::new()),
            queue: parking_lot::RwLock::new(VecDeque::new()),
        }
    }

    fn contains_batch(&self, digests: &[BlockDigest]) -> Vec<bool> {
        let set = self.digests.read();
        digests.iter().map(|d| set.contains(d)).collect()
    }

    fn contains_full_mac_batch(&self, digests: &[BlockDigest]) -> Vec<bool> {
        let set = self.full_mac_vectors.read();
        digests.iter().map(|d| set.contains(d)).collect()
    }

    fn insert_batch(&self, blocks: &[(BlockDigest, bool)]) {
        let mut digests = self.digests.write();
        let mut full_mac_vectors = self.full_mac_vectors.write();
        let mut queue = self.queue.write();

        for (digest, has_full_mac_vector) in blocks {
            if digests.insert(*digest) {
                queue.push_back(*digest);
            }
            if *has_full_mac_vector {
                full_mac_vectors.insert(*digest);
            }
        }

        while queue.len() > MAX_FILTER_SIZE {
            if let Some(removed) = queue.pop_front() {
                digests.remove(&removed);
                full_mac_vectors.remove(&removed);
            }
        }
    }

    /// Inserts all verified copies and returns `true` for each copy that adds
    /// either a new block reference or the first full MAC vector for a
    /// previously recipient-tag-only reference.
    fn insert_and_report_useful(&self, blocks: &[(BlockDigest, bool)]) -> Vec<bool> {
        let mut set = self.digests.write();
        let mut full_mac_vectors = self.full_mac_vectors.write();
        let mut queue = self.queue.write();

        let is_useful: Vec<bool> = blocks
            .iter()
            .map(|(digest, has_full_mac_vector)| {
                let is_new = set.insert(*digest);
                if is_new {
                    queue.push_back(*digest);
                }
                let is_mac_upgrade = *has_full_mac_vector && full_mac_vectors.insert(*digest);
                is_new || is_mac_upgrade
            })
            .collect();

        while queue.len() > MAX_FILTER_SIZE {
            if let Some(removed) = queue.pop_front() {
                set.remove(&removed);
                full_mac_vectors.remove(&removed);
            }
        }
        is_useful
    }

    /// For each header, returns `true` if it is either unseen or upgrades a
    /// previously seen recipient-only MAC to a full vector.
    fn needed_headers(&self, batch: &[(BlockDigest, bool)]) -> Vec<bool> {
        let digests = self.digests.read();
        let full_mac_vectors = self.full_mac_vectors.read();
        let mut seen_in_batch = AHashMap::with_capacity(batch.len());

        batch
            .iter()
            .map(|(digest, has_full_mac_vector)| {
                let was_seen = digests.contains(digest) || seen_in_batch.contains_key(digest);
                let had_full_mac_vector = seen_in_batch
                    .get(digest)
                    .copied()
                    .unwrap_or_else(|| full_mac_vectors.contains(digest));
                let is_needed = !was_seen || (*has_full_mac_vector && !had_full_mac_vector);
                seen_in_batch
                    .entry(*digest)
                    .and_modify(|full| *full |= *has_full_mac_vector)
                    .or_insert(*has_full_mac_vector);
                is_needed
            })
            .collect()
    }
}

#[derive(Clone, Copy)]
struct ShardStatus {
    count: usize,
    bitmap: AuthoritySet,
    full_block_received: bool,
}

struct FilterForShards {
    info_length: usize,
    digests: parking_lot::RwLock<AHashMap<BlockDigest, ShardStatus>>,
    queue: parking_lot::RwLock<VecDeque<BlockDigest>>,
}

impl FilterForShards {
    fn new(info_length: usize) -> Self {
        Self {
            info_length,
            digests: parking_lot::RwLock::new(AHashMap::new()),
            queue: parking_lot::RwLock::new(VecDeque::new()),
        }
    }

    /// Returns `true` if this shard is still needed for reconstruction.
    fn needed(&self, digest: &BlockDigest, shard_index: usize) -> bool {
        let digests = self.digests.read();
        match digests.get(digest) {
            Some(status) => {
                !status.full_block_received
                    && status.count < self.info_length
                    && !status.bitmap.contains(shard_index as AuthorityIndex)
            }
            None => true,
        }
    }

    fn add_batch(&self, entries: &[(BlockDigest, usize)]) {
        let mut digests = self.digests.write();
        let mut queue = self.queue.write();
        for &(digest, shard_index) in entries {
            let entry = digests.entry(digest).or_insert_with(|| {
                queue.push_back(digest);
                ShardStatus {
                    count: 0,
                    bitmap: AuthoritySet::default(),
                    full_block_received: false,
                }
            });
            let authority = shard_index as AuthorityIndex;
            if !entry.bitmap.contains(authority) {
                entry.bitmap.insert(authority);
                entry.count += 1;
            }
        }
        while queue.len() > MAX_FILTER_SIZE {
            if let Some(removed) = queue.pop_front() {
                digests.remove(&removed);
            }
        }
    }

    fn has_full_batch(&self, digests: &[BlockDigest]) -> Vec<bool> {
        let map = self.digests.read();
        digests
            .iter()
            .map(|d| map.get(d).is_some_and(|s| s.full_block_received))
            .collect()
    }

    fn mark_full_batch(&self, batch: &[BlockDigest]) {
        let mut digests = self.digests.write();
        let mut queue = self.queue.write();
        for &digest in batch {
            let entry = digests.entry(digest).or_insert_with(|| {
                queue.push_back(digest);
                ShardStatus {
                    count: 0,
                    bitmap: AuthoritySet::default(),
                    full_block_received: false,
                }
            });
            entry.count = self.info_length;
            entry.full_block_received = true;
        }
    }
}

fn infer_peer_knowledge_from_received_batch(
    ck: &mut ConnectionKnowledge,
    full_blocks: &[Data<VerifiedBlock>],
    headers: &[Data<VerifiedBlock>],
    shards: &[ShardPayload],
) {
    for block in full_blocks.iter().chain(headers.iter()) {
        // Peer knows this block's header because they sent it.
        ck.mark_header_known(*block.reference());
        // Peer knows the header of every parent in the causal history.
        for parent_ref in block.block_references() {
            ck.mark_header_known(*parent_ref);
        }
        // Acknowledging a block implies the peer already has that block's data.
        for ack_ref in block.acknowledgments() {
            ck.mark_header_known(ack_ref);
            ck.mark_shard_known(ack_ref);
        }
    }
    for shard in shards {
        ck.mark_header_known(shard.block_reference);
        ck.mark_shard_known(shard.block_reference);
    }
}

/// Spawn the per-connection worker task that drains raw shard payloads,
/// verifies their merkle proofs, applies the dedup filter, and forwards the
/// surviving shards to the global shard reconstructor. Running off the
/// connection's main loop keeps verification work off the path that handles
/// the next incoming network message.
fn spawn_standalone_shard_worker<H: BlockHandler + 'static, C: CommitObserver + 'static>(
    mut rx: mpsc::UnboundedReceiver<Vec<ShardPayload>>,
    inner: Arc<NetworkSyncerInner<H, C>>,
    filter_for_shards: Arc<FilterForShards>,
    metrics: Arc<Metrics>,
    committee_size: usize,
    peer: String,
) {
    tokio::spawn(async move {
        while let Some(shards) = rx.recv().await {
            let maybe_tx = inner.shard_tx.lock().clone();
            let Some(shard_tx) = maybe_tx else { continue };

            let mut verified: Vec<(BlockReference, ShardMessage, usize)> =
                Vec::with_capacity(shards.len());
            for payload in shards {
                let shard_index = payload.shard.shard_index();
                if !filter_for_shards.needed(&payload.block_reference.digest, shard_index) {
                    metrics.filtered_shards_total.inc();
                    continue;
                }
                if !payload.shard.verify(committee_size) {
                    tracing::warn!(
                        "Standalone shard for {:?} from {} failed Merkle proof — dropped",
                        payload.block_reference,
                        peer
                    );
                    continue;
                }
                verified.push((
                    payload.block_reference,
                    ShardMessage::Shard {
                        block_reference: payload.block_reference,
                        transactions_commitment: payload.shard.transactions_commitment(),
                        shard: payload.shard.shard().clone(),
                        shard_index,
                    },
                    shard_index,
                ));
            }

            let filter_entries: Vec<_> = verified
                .iter()
                .map(|(r, _, idx)| (r.digest, *idx))
                .collect();
            filter_for_shards.add_batch(&filter_entries);

            let batch: Vec<_> = verified.into_iter().map(|(_, msg, _)| msg).collect();
            if !batch.is_empty() {
                let _ = shard_tx.send(batch);
            }
        }
    });
}

/// Spawn the per-connection worker task that drains header-only block
/// batches, verifies them, and inserts them into the local DAG. Running off
/// the connection's main loop keeps verify + `add_headers` work off the path
/// that handles the next incoming network message.
fn spawn_header_worker<H: BlockHandler + 'static, C: CommitObserver + 'static>(
    mut rx: mpsc::UnboundedReceiver<(Vec<Data<VerifiedBlock>>, DataSource)>,
    inner: Arc<NetworkSyncerInner<H, C>>,
    filter_for_blocks: Arc<FilterForBlocks>,
    metrics: Arc<Metrics>,
    sender: mpsc::Sender<NetworkMessage>,
    bls_service: Option<BlsServiceHandle>,
    consensus_protocol: ConsensusProtocol,
    peer: String,
    peer_id: AuthorityIndex,
    own_id: AuthorityIndex,
) {
    tokio::spawn(async move {
        let mut encoder = ReedSolomonEncoder::new(2, 4, 2).expect("Encoder should be created");
        while let Some((blocks, source)) = rx.recv().await {
            let connection_knowledge = inner.cordial_knowledge.connection_knowledge(peer_id);
            let incoming_headers: Vec<_> = blocks
                .iter()
                .map(|block| (block.digest(), block.has_full_mac_vector()))
                .collect();
            let needed_before_verify = filter_for_blocks.needed_headers(&incoming_headers);
            let mut verified_blocks: Vec<VerifiedBlock> = Vec::new();

            for (data_block, is_needed) in blocks.into_iter().zip(needed_before_verify) {
                if !is_needed {
                    metrics.filtered_blocks_total.inc();
                    continue;
                }
                let mut block: VerifiedBlock = (*data_block).clone();
                tracing::debug!("Received {} from {}", block, peer);
                if let Err(e) = verify_mac_transport(
                    &block,
                    inner.dag_state.block_authentication_scheme,
                    peer_id,
                    source,
                ) {
                    tracing::warn!(
                        "Rejected incorrectly transported block {} from {}: {:?}",
                        block.reference(),
                        peer,
                        e
                    );
                    break;
                }
                match block.verify_with_authentication(
                    &inner.committee,
                    own_id as usize,
                    peer_id as usize,
                    &mut encoder,
                    consensus_protocol,
                    inner.dag_state.block_authentication_scheme,
                    &inner.mac_keys,
                ) {
                    Ok(shard) => {
                        debug_assert!(shard.is_none(), "shard must be None for header-only blocks")
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Rejected incorrect block {} from {}: {:?}",
                            block.reference(),
                            peer,
                            e
                        );
                        break;
                    }
                };
                verified_blocks.push(block);
            }

            if let Some(ck) = connection_knowledge.as_ref() {
                let refs: Vec<_> = verified_blocks.iter().map(|b| *b.reference()).collect();
                let mut ck = ck.write();
                ck.mark_headers_useful_from_peer(&refs);
            }

            let filter_entries: Vec<_> = verified_blocks
                .iter()
                .map(|block| (block.digest(), block.has_full_mac_vector()))
                .collect();
            let is_useful = filter_for_blocks.insert_and_report_useful(&filter_entries);
            let mut new_data_blocks = Vec::new();
            for (storage_block, is_useful) in verified_blocks.into_iter().zip(is_useful) {
                if is_useful {
                    let mut storage_block = storage_block;
                    storage_block.preserialize();
                    debug_assert!(
                        storage_block.serialized_header_bytes().is_some(),
                        "header must be preserialized before entering core"
                    );
                    new_data_blocks.push(Data::new(storage_block));
                }
            }

            tracing::debug!(
                "To be processed after verification from {:?}, source={}, {} new \
                 blocks without transactions {:?}",
                peer,
                source,
                new_data_blocks.len(),
                new_data_blocks
            );
            if new_data_blocks.is_empty() {
                continue;
            }

            if let Some(ref bls) = bls_service {
                bls.send(BlsServiceMessage::ProcessBlocks(new_data_blocks.clone()));
            }
            let header_refs = new_data_blocks
                .iter()
                .map(|block| *block.reference())
                .collect();
            inner
                .cordial_knowledge
                .send(CordialKnowledgeMessage::DagParts {
                    headers: header_refs,
                    shards: Vec::new(),
                });
            // Note: shard usefulness is no longer derived from header
            // arrival. Headers are too noisy a trigger — push-mode
            // disseminates the entire causal cone, lighting up every
            // authority in the bitmask. Instead, the
            // `UsefulShardsFromPeers` signal fires only when this
            // validator sends a `MissingTxDataRequest` (see
            // `BlockDisseminator::request_missing_data_blocks` in
            // broadcaster.rs), which reflects real outstanding demand.
            let (missing_parents, processed_additional_refs) =
                inner.syncer.add_headers(new_data_blocks, source).await;
            if !missing_parents.is_empty() {
                let missing_parents = missing_parents.iter().copied().collect::<Vec<_>>();
                tracing::debug!(
                    "Make request missing parents of header/shard blocks {:?} \
                     from peer {:?} after source={}",
                    missing_parents,
                    peer,
                    source
                );
                metrics
                    .block_sync_requests_sent
                    .with_label_values(&[&peer_id.to_string()])
                    .inc();
                sender
                    .send(NetworkMessage::MissingParentsRequest(missing_parents))
                    .await
                    .ok();
            }
            metrics
                .used_additional_blocks_total
                .inc_by(processed_additional_refs.len() as u64);
        }
    });
}

/// Per-connection state for `connection_task`. Groups the 15+ shared locals
/// into a struct so the 400-line match body can be split into focused handlers.
struct ConnectionHandler<H: BlockHandler + 'static, C: CommitObserver + 'static> {
    consensus_protocol: ConsensusProtocol,
    inner: Arc<NetworkSyncerInner<H, C>>,
    metrics: Arc<Metrics>,
    filter_for_blocks: Arc<FilterForBlocks>,
    filter_for_shards: Arc<FilterForShards>,
    disseminator: BlockDisseminator<H, C>,
    data_requester: DataRequester<H, C>,
    encoder: ReedSolomonEncoder,
    peer_id: AuthorityIndex,
    peer: String,
    own_id: AuthorityIndex,
    sender: mpsc::Sender<NetworkMessage>,
    /// Hand-off channel into the per-connection standalone-shard worker
    /// task. The main connection loop fires raw shard payloads here and
    /// returns immediately; the worker verifies merkle proofs and forwards
    /// to the global shard reconstructor.
    standalone_shard_tx: mpsc::UnboundedSender<Vec<ShardPayload>>,
    /// Hand-off channel into the per-connection header worker task. The
    /// main connection loop fires header-only block batches here and
    /// returns immediately; the worker verifies, filters, and inserts
    /// the headers into the DAG.
    header_tx: mpsc::UnboundedSender<(Vec<Data<VerifiedBlock>>, DataSource)>,
    bls_service: Option<BlsServiceHandle>,
    sailfish_service: Option<SailfishServiceHandle>,
    starfish_rbc_service: Option<RbcServiceHandle>,
    starfish_rbc_dag_shadow_service: Option<StarfishRbcDagShadowServiceHandleV1>,
}

impl<H: BlockHandler + 'static, C: CommitObserver + 'static> ConnectionHandler<H, C> {
    fn new(
        connection: &Connection,
        universal_committer: UniversalCommitter,
        inner: Arc<NetworkSyncerInner<H, C>>,
        metrics: Arc<Metrics>,
        filter_for_blocks: Arc<FilterForBlocks>,
        filter_for_shards: Arc<FilterForShards>,
        bls_service: Option<BlsServiceHandle>,
        sailfish_service: Option<SailfishServiceHandle>,
    ) -> Self {
        let consensus_protocol = inner.dag_state.consensus_protocol;
        let committee_size = inner.dag_state.committee_size;
        let broadcaster_parameters = BroadcasterParameters::new(
            committee_size,
            consensus_protocol,
            inner.dissemination_mode,
            inner.causal_push_shard_round_lag,
        );
        let peer_id = connection.peer_id as AuthorityIndex;

        let disseminator = BlockDisseminator::new(
            peer_id,
            connection.sender.clone(),
            universal_committer,
            inner.clone(),
            broadcaster_parameters.clone(),
            metrics.clone(),
        );
        let data_requester = DataRequester::new(
            peer_id,
            connection.sender.clone(),
            inner.clone(),
            metrics.clone(),
            broadcaster_parameters,
        );

        let encoder = ReedSolomonEncoder::new(2, 4, 2).expect("Encoder should be created");
        let own_id = inner.dag_state.get_own_authority_index();
        let starfish_rbc_service = inner.starfish_rbc_service.clone();
        let starfish_rbc_dag_shadow_service = inner.starfish_rbc_dag_shadow_service.clone();
        let peer = format_authority_index(peer_id);

        let (standalone_shard_tx, standalone_shard_rx) = mpsc::unbounded_channel();
        spawn_standalone_shard_worker(
            standalone_shard_rx,
            inner.clone(),
            filter_for_shards.clone(),
            metrics.clone(),
            committee_size,
            peer.clone(),
        );

        let (header_tx, header_rx) = mpsc::unbounded_channel();
        spawn_header_worker(
            header_rx,
            inner.clone(),
            filter_for_blocks.clone(),
            metrics.clone(),
            connection.sender.clone(),
            bls_service.clone(),
            consensus_protocol,
            peer.clone(),
            peer_id,
            own_id,
        );

        Self {
            consensus_protocol,
            inner,
            metrics,
            filter_for_blocks,
            filter_for_shards,
            disseminator,
            data_requester,
            encoder,
            peer_id,
            peer,
            own_id,
            sender: connection.sender.clone(),
            standalone_shard_tx,
            header_tx,
            bls_service,
            sailfish_service,
            starfish_rbc_service,
            starfish_rbc_dag_shadow_service,
        }
    }

    async fn start(&mut self) {
        // Pre-create received-request time series per peer so Grafana can show
        // zero-valued lines before the first request arrives.
        self.metrics
            .block_sync_requests_received
            .with_label_values(&[&self.peer_id.to_string()])
            .inc_by(0);

        // Data requester is needed for Starfish protocols because of the practical
        // way we update the DAG known by other validators
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishRbc
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
                | ConsensusProtocol::SparseStarfishSpeed
        ) {
            self.metrics
                .tx_data_requests_received
                .with_label_values(&[&self.peer_id.to_string()])
                .inc_by(0);
            self.data_requester.start().await;
        }
    }

    /// Dispatch a single message. Returns `true` to continue, `false` to break
    /// the loop.
    async fn handle_message(&mut self, message: NetworkMessage) -> bool {
        match message {
            NetworkMessage::SubscribeBroadcastRequest(round) => {
                self.handle_subscribe(round).await;
            }
            NetworkMessage::Batch(blocks) => {
                self.handle_batch(*blocks).await;
            }
            NetworkMessage::MissingParentsRequest(refs) => {
                return self.handle_missing_parents_request(refs).await;
            }
            NetworkMessage::MissingTxDataRequest(refs) => {
                return self.handle_missing_tx_data_request(refs).await;
            }
            NetworkMessage::PartialSig(sig) => {
                // DAC sigs are addressed: accept only if block author is us.
                // Round/Leader sigs are broadcast: always accept.
                let dominated = match sig.kind {
                    PartialSigKind::Dac(block_ref) => block_ref.authority != self.own_id,
                    _ => false,
                };
                if !dominated {
                    if let Some(ref bls) = self.bls_service {
                        bls.send(BlsServiceMessage::PartialSig(sig));
                    }
                }
            }
            NetworkMessage::CertMessage(message) => {
                if message.sender != self.peer_id {
                    tracing::debug!(
                        "Rejected CertMessage: sender {} != peer {}",
                        message.sender,
                        self.peer_id,
                    );
                    return true;
                }
                tracing::debug!(
                    "Received {:?} from peer {} for {:?}",
                    message.kind,
                    message.sender,
                    message.block_ref,
                );
                if let Some(ref sf) = self.sailfish_service {
                    sf.send(SailfishServiceMessage::CertMessage(message));
                }
            }
            NetworkMessage::CertBatch(messages) => {
                tracing::debug!(
                    "Received Sailfish cert batch from peer {} with {} messages",
                    self.peer_id,
                    messages.len(),
                );
                for message in messages {
                    if message.sender != self.peer_id {
                        tracing::debug!(
                            "Rejected CertBatch message: sender {} != peer {}",
                            message.sender,
                            self.peer_id,
                        );
                        continue;
                    }
                    if let Some(ref sf) = self.sailfish_service {
                        sf.send(SailfishServiceMessage::CertMessage(message));
                    }
                }
            }
            NetworkMessage::SailfishTimeout(msg) => {
                if msg.sender != self.peer_id {
                    return true;
                }
                if let Some(ref sf) = self.sailfish_service {
                    sf.send(SailfishServiceMessage::TimeoutMsg(msg));
                }
            }
            NetworkMessage::SailfishNoVote(msg) => {
                if msg.sender != self.peer_id {
                    return true;
                }
                if let Some(ref sf) = self.sailfish_service {
                    sf.send(SailfishServiceMessage::NoVoteMsg(msg));
                }
            }
            NetworkMessage::UnprovableCertificateRequest {
                leader_ref,
                known_voters,
            } => {
                return self
                    .handle_unprovable_cert_request(leader_ref, known_voters)
                    .await;
            }
            NetworkMessage::RoundGapRequest {
                round,
                known_authorities,
            } => {
                return self
                    .handle_round_gap_request(round, known_authorities)
                    .await;
            }
            NetworkMessage::RbcInitial(proposal) => {
                if let Some(ref rbc) = self.starfish_rbc_service {
                    if let Err(error) = rbc.direct_initial(self.peer_id, proposal) {
                        tracing::warn!("Failed to forward Starfish-RBC INIT: {error}");
                    }
                }
            }
            NetworkMessage::RbcPhase(message) => {
                if let Some(ref rbc) = self.starfish_rbc_service {
                    if let Err(error) = rbc.phase(self.peer_id, message) {
                        tracing::warn!("Failed to forward Starfish-RBC phase: {error}");
                    }
                }
            }
            NetworkMessage::RbcHeaderRequest(block_ref) => {
                if let Some(ref rbc) = self.starfish_rbc_service {
                    if let Err(error) = rbc.header_request(self.peer_id, block_ref) {
                        tracing::warn!("Failed to forward Starfish-RBC header request: {error}");
                    }
                }
            }
            NetworkMessage::RbcHeaderResponse(header) => {
                if let Some(ref rbc) = self.starfish_rbc_service {
                    if let Err(error) = rbc.header_response(self.peer_id, header) {
                        tracing::warn!("Failed to forward Starfish-RBC header response: {error}");
                    }
                }
            }
            NetworkMessage::RbcDagShadowCarrier(envelope) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow.carrier(self.peer_id, envelope) {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!("Failed to forward RBC-DAG shadow carrier: {error}");
                    }
                }
            }
            NetworkMessage::RbcDagShadowCarrierRequest(reference) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow.carrier_request(self.peer_id, reference) {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!("Failed to forward RBC-DAG shadow request: {error}");
                    }
                }
            }
            NetworkMessage::RbcDagShadowCarrierResponse(response) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow.carrier_response(self.peer_id, response) {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!("Failed to forward RBC-DAG shadow response: {error}");
                    }
                }
            }
            NetworkMessage::RbcDagShadowCarrierSyncRequest(request) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow.carrier_sync_request(self.peer_id, request) {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!(
                            "Failed to forward RBC-DAG shadow carrier sync request: {error}"
                        );
                    }
                }
            }
            NetworkMessage::RbcDagShadowCarrierSyncResponse(response) => {
                if let Some(ref shadow) = self.starfish_rbc_dag_shadow_service {
                    if let Err(error) = shadow.carrier_sync_response(self.peer_id, response) {
                        if shadow_transport_error_invalidates_run(&error) {
                            invalidate_shadow_run(&self.metrics);
                        }
                        tracing::warn!(
                            "Failed to forward RBC-DAG shadow carrier sync response: {error}"
                        );
                    }
                }
            }
        }
        true
    }

    async fn handle_subscribe(&mut self, round: RoundNumber) {
        self.inner.syncer.peer_subscribed(self.peer_id).await;
        self.inner
            .cordial_knowledge
            .send(CordialKnowledgeMessage::ResetPeerKnown {
                peer: self.peer_id,
                after_round: round,
            });
        if self.inner.dag_state.byzantine_strategy.is_some() {
            let round = 0;
            self.disseminator.disseminate_own_blocks(round).await;
        } else {
            match self.inner.dissemination_mode {
                DisseminationMode::Pull => {
                    self.disseminator.disseminate_own_blocks(round).await;
                }
                DisseminationMode::PushCausal | DisseminationMode::PushUseful => {
                    self.disseminator.start_push_batch_stream(round).await;
                }
                DisseminationMode::ProtocolDefault => {
                    unreachable!("protocol-default dissemination mode must be resolved")
                }
            }
        }
    }

    async fn handle_batch(&mut self, batch: BlockBatch) {
        let timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Network: verify blocks");

        let BlockBatch {
            source,
            full_blocks,
            headers,
            shards,
            useful_headers_authors,
            useful_shards_authors,
        } = batch;

        tracing::debug!(
            "Received batch from peer {:?}: source={}, full_blocks={}, headers={}, shards={}",
            self.peer,
            source,
            full_blocks.len(),
            headers.len(),
            shards.len()
        );

        // Mark received full blocks as "sent" so we don't re-send them.
        {
            let mut sent = self.disseminator.sent_to_peer.write();
            for block in &full_blocks {
                sent.insert(*block.reference());
            }
            for block in &headers {
                sent.insert(*block.reference());
            }
        }

        // Forward useful-authors feedback to CordialKnowledge
        if !useful_headers_authors.is_empty() || !useful_shards_authors.is_empty() {
            let max_round = full_blocks
                .iter()
                .chain(headers.iter())
                .map(|b| b.round())
                .chain(shards.iter().map(|payload| payload.block_reference.round))
                .max()
                .unwrap_or(0);
            self.inner
                .cordial_knowledge
                .send(CordialKnowledgeMessage::UsefulAuthors(Box::new(
                    UsefulAuthorsMessage {
                        peer: self.peer_id,
                        headers: useful_headers_authors,
                        shards: useful_shards_authors,
                        round: max_round,
                    },
                )));
        }

        // Update ConnectionKnowledge directly — infer what the peer knows
        // from the blocks they sent us and their causal references.
        if let Some(ck) = self
            .inner
            .cordial_knowledge
            .connection_knowledge(self.peer_id)
        {
            let mut ck = ck.write();
            infer_peer_knowledge_from_received_batch(&mut ck, &full_blocks, &headers, &shards);
        }

        let mut blocks_with_transactions = Vec::new();
        let mut blocks_without_transactions = Vec::new();
        for block in full_blocks {
            match self.consensus_protocol {
                // In full-block protocols, an empty payload is still a complete
                // block and must follow the normal add_blocks path.
                ConsensusProtocol::Mysticeti
                | ConsensusProtocol::CordialMiners
                | ConsensusProtocol::SailfishPlusPlus
                | ConsensusProtocol::Bluestreak
                | ConsensusProtocol::MysticetiBls => {
                    blocks_with_transactions.push(block);
                }
                ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishRbc
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
                | ConsensusProtocol::SparseStarfishSpeed => {
                    if block.transactions().is_some() {
                        blocks_with_transactions.push(block);
                    } else {
                        blocks_without_transactions.push(block);
                    }
                }
            }
        }

        // Process full blocks first.
        self.process_full_blocks(blocks_with_transactions, source)
            .await;

        // Header-only blocks are only valid for Starfish erasure-coding
        // variants. SailfishPlusPlus and Mysticeti require full blocks;
        // reject any headers a peer may have sent. Hand the header batch
        // off to the per-connection header worker so the main connection
        // loop does not block on verify / DAG insertion.
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishRbc
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
                | ConsensusProtocol::SparseStarfishSpeed
        ) {
            blocks_without_transactions.extend(headers);
            if !blocks_without_transactions.is_empty() {
                let header_source = match source {
                    DataSource::BlockBundleStreaming => DataSource::BlockBundleStreamingHeader,
                    other => other,
                };
                let _ = self
                    .header_tx
                    .send((blocks_without_transactions, header_source));
            }
        } else if !headers.is_empty() {
            tracing::warn!(
                "Rejecting {} header-only blocks from peer {} \
                 (not supported by {:?})",
                headers.len(),
                self.peer_id,
                self.consensus_protocol,
            );
        }

        // Process standalone shards last so that any full blocks that
        // landed above can cancel in-flight reconstruction work via
        // ShardMessage::FullBlock before we accumulate more shards. The
        // verification + forwarding happens on a per-connection worker
        // task so the main connection loop does not block on merkle
        // proof checks.
        if !shards.is_empty() {
            let _ = self.standalone_shard_tx.send(shards);
        }

        drop(timer);
    }

    async fn process_full_blocks(&mut self, blocks: Vec<Data<VerifiedBlock>>, source: DataSource) {
        let connection_knowledge = self
            .inner
            .cordial_knowledge
            .connection_knowledge(self.peer_id);
        let incoming_digests: Vec<_> = blocks.iter().map(|block| block.digest()).collect();
        let shard_tx = self.inner.shard_tx.lock().clone();

        // --- batch pre-filter (one read lock each) ---
        let block_known = self.filter_for_blocks.contains_batch(&incoming_digests);
        let full_mac_known = self
            .filter_for_blocks
            .contains_full_mac_batch(&incoming_digests);
        let shard_full = self.filter_for_shards.has_full_batch(&incoming_digests);

        // --- verify loop (no lock acquisitions) ---
        let mut verified: Vec<(VerifiedBlock, Option<ProvableShard>)> = Vec::new();
        for (index, data_block) in blocks.into_iter().enumerate() {
            let bk = block_known[index];
            let sf = shard_full[index];
            let incoming_has_full_mac = data_block.has_full_mac_vector();
            if bk && sf && (!incoming_has_full_mac || full_mac_known[index]) {
                self.metrics.filtered_blocks_total.inc();
                continue;
            }
            let mut block: VerifiedBlock = (*data_block).clone();
            tracing::debug!("Received {} from {}", block, self.peer);
            if let Err(e) = verify_mac_transport(
                &block,
                self.inner.dag_state.block_authentication_scheme,
                self.peer_id,
                source,
            ) {
                tracing::warn!(
                    "Rejected incorrectly transported block {} from {}: {:?}",
                    block.reference(),
                    self.peer,
                    e
                );
                break;
            }
            let shard = match block.verify_with_authentication(
                &self.inner.committee,
                self.own_id as usize,
                self.peer_id as usize,
                &mut self.encoder,
                self.consensus_protocol,
                self.inner.dag_state.block_authentication_scheme,
                &self.inner.mac_keys,
            ) {
                Ok(shard) => shard,
                Err(e) => {
                    tracing::warn!(
                        "Rejected incorrect block {} from {}: {:?}",
                        block.reference(),
                        self.peer,
                        e
                    );
                    // todo: Terminate connection upon receiving incorrect block.
                    break;
                }
            };
            verified.push((block, shard));
        }

        // --- batch CK update (one write lock) ---
        if let Some(ck) = connection_knowledge.as_ref() {
            let header_refs: Vec<_> = verified.iter().map(|(b, _)| *b.reference()).collect();
            let mut ck = ck.write();
            // Full blocks carry useful header/causal information, but the
            // derived shard sidecar is local bookkeeping rather than a shard
            // the peer pushed to us.
            ck.mark_headers_useful_from_peer(&header_refs);
        }

        // --- batch filter updates (one write lock each) ---
        let verified_filter_entries: Vec<_> = verified
            .iter()
            .map(|(block, _)| (block.digest(), block.has_full_mac_vector()))
            .collect();
        let verified_digests: Vec<_> = verified_filter_entries
            .iter()
            .map(|(digest, _)| *digest)
            .collect();
        self.filter_for_blocks
            .insert_batch(&verified_filter_entries);
        self.filter_for_shards.mark_full_batch(&verified_digests);

        // --- preserialize + collect ---
        let mut verified_data_blocks = Vec::new();
        let mut verified_has_shard = Vec::new();
        let mut verified_block_shards = Vec::new();
        for (mut block, shard) in verified {
            let has_shard = shard.is_some();
            block.preserialize();
            debug_assert!(
                block.serialized_header_bytes().is_some(),
                "header must be preserialized before entering core"
            );
            let block = Data::new(block);
            verified_data_blocks.push(block.clone());
            verified_has_shard.push(has_shard);
            verified_block_shards.push((block, shard));
        }

        // Notify reconstructor to stop collecting shards for these blocks (batched).
        if let Some(shard_tx) = shard_tx.as_ref() {
            let full_block_msgs: Vec<_> = verified_data_blocks
                .iter()
                .map(|b| ShardMessage::FullBlock(*b.reference()))
                .collect();
            if !full_block_msgs.is_empty() {
                let _ = shard_tx.send(full_block_msgs);
            }
        }

        tracing::debug!(
            "To be processed after verification from {:?}, source={}, {} \
             blocks with transactions {:?}",
            self.peer,
            source,
            verified_data_blocks.len(),
            verified_data_blocks
        );
        if verified_data_blocks.is_empty() {
            return;
        }
        // Send block copies to BLS service for signature verification.
        if let Some(ref bls) = self.bls_service {
            bls.send(BlsServiceMessage::ProcessBlocks(
                verified_data_blocks.clone(),
            ));
        }
        // Notify CordialKnowledge about all new headers and shards in one batch.
        let header_refs: Vec<_> = verified_data_blocks
            .iter()
            .map(|block| *block.reference())
            .collect();
        let shard_refs: Vec<_> = verified_data_blocks
            .iter()
            .zip(verified_has_shard.iter())
            .filter_map(|(block, &has_shard)| has_shard.then_some(*block.reference()))
            .collect();
        self.inner
            .cordial_knowledge
            .send(CordialKnowledgeMessage::DagParts {
                headers: header_refs,
                shards: shard_refs,
            });
        let (_pending_block_references, missing_parents, _processed_additional_blocks) = self
            .inner
            .syncer
            .add_blocks(verified_block_shards, source)
            .await;
        if !missing_parents.is_empty() {
            tracing::debug!(
                "Missing parents when processing block from peer {:?} after source={}: {:?}",
                self.peer,
                source,
                missing_parents
            );
            let missing_parents_vec = missing_parents.iter().copied().collect::<Vec<_>>();
            tracing::debug!(
                "Make request missing parents of blocks {:?} from peer \
                 {:?} after source={}",
                missing_parents_vec,
                self.peer,
                source
            );
            self.metrics
                .block_sync_requests_sent
                .with_label_values(&[&self.peer_id.to_string()])
                .inc();
            self.sender
                .send(NetworkMessage::MissingParentsRequest(missing_parents_vec))
                .await
                .ok();
        }
    }

    /// Returns `true` to continue, `false` to break the connection loop.
    async fn handle_missing_parents_request(
        &mut self,
        block_references: Vec<BlockReference>,
    ) -> bool {
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::Mysticeti
                | ConsensusProtocol::MysticetiBls
                | ConsensusProtocol::CordialMiners
                | ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
                | ConsensusProtocol::SailfishPlusPlus
                | ConsensusProtocol::Bluestreak
                | ConsensusProtocol::SparseStarfishSpeed
                | ConsensusProtocol::StarfishRbc
        ) {
            self.metrics
                .block_sync_requests_received
                .with_label_values(&[&self.peer_id.to_string()])
                .inc();
            tracing::debug!(
                "Received request missing data {:?} from peer {:?}",
                block_references,
                self.peer
            );
            let available = self
                .inner
                .dag_state
                .get_storage_blocks(&block_references)
                .into_iter()
                .flatten()
                .count();
            let unavailable = block_references.len().saturating_sub(available);
            tracing::debug!(
                "MissingParentsRequest stats for peer {:?}: requested={}, \
                 available={}, unavailable={}, serving_allowed={}",
                self.peer,
                block_references.len(),
                available,
                unavailable,
                self.inner.dag_state.byzantine_strategy.is_none()
            );
            if self.inner.dissemination_mode == DisseminationMode::PushUseful {
                if let Some(ck) = self
                    .inner
                    .cordial_knowledge
                    .connection_knowledge(self.peer_id)
                {
                    let mut ck = ck.write();
                    let mut useful_headers_mask = AuthoritySet::default();
                    for block_ref in &block_references {
                        useful_headers_mask.insert(block_ref.authority);
                    }
                    if !useful_headers_mask.is_empty() {
                        let current_round = self.inner.dag_state.highest_round();
                        ck.update_useful_authors_to_peer(
                            useful_headers_mask,
                            AuthoritySet::default(),
                            current_round,
                        );
                    }
                }
            }
            if self.inner.dag_state.byzantine_strategy.is_none()
                && self
                    .disseminator
                    .send_storage_blocks(self.peer_id, block_references)
                    .await
                    .is_none()
            {
                return false;
            }
        }
        true
    }

    /// Returns `true` to continue, `false` to break the connection loop.
    async fn handle_missing_tx_data_request(
        &mut self,
        block_references: Vec<BlockReference>,
    ) -> bool {
        if matches!(
            self.consensus_protocol,
            ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
                | ConsensusProtocol::SparseStarfishSpeed
                | ConsensusProtocol::StarfishRbc
        ) {
            self.metrics
                .tx_data_requests_received
                .with_label_values(&[&self.peer_id.to_string()])
                .inc();
            tracing::debug!(
                "Received request missing data {:?} from peer {:?}",
                block_references,
                self.peer
            );
            if self.inner.dissemination_mode == DisseminationMode::PushUseful {
                if let Some(ck) = self
                    .inner
                    .cordial_knowledge
                    .connection_knowledge(self.peer_id)
                {
                    let mut ck = ck.write();
                    for block_ref in &block_references {
                        ck.mark_shard_useful_to_peer(*block_ref);
                    }
                }
            }
            if self.inner.dag_state.byzantine_strategy.is_none()
                && self
                    .disseminator
                    .send_transmission_blocks(self.peer_id, block_references)
                    .await
                    .is_none()
            {
                return false;
            }
        }
        true
    }

    /// Respond with voting blocks for a Bluestreak unprovable certificate.
    /// Returns `true` to continue, `false` to break the connection loop.
    async fn handle_unprovable_cert_request(
        &mut self,
        leader_ref: BlockReference,
        known_voters: AuthoritySet,
    ) -> bool {
        if self.consensus_protocol != ConsensusProtocol::Bluestreak {
            return true;
        }
        // Voting blocks live at leader_ref.round + 1 and reference the leader.
        let voting_round = leader_ref.round + 1;
        let voting_blocks = self.inner.dag_state.get_blocks_by_round(voting_round);
        let missing: Vec<_> = voting_blocks
            .into_iter()
            .filter(|b| {
                !known_voters.contains(b.authority()) && b.block_references().contains(&leader_ref)
            })
            .collect();
        let missing = prepare_forwarded_blocks_for_peer(
            self.inner.dag_state.block_authentication_scheme,
            self.consensus_protocol,
            self.peer_id,
            missing,
        );
        tracing::debug!(
            "UnprovableCertificateRequest from peer {:?} for leader {}: \
             known_voters={}, serving_blocks={}",
            self.peer,
            leader_ref,
            known_voters.count_ones(),
            missing.len()
        );
        if missing.is_empty() {
            return true;
        }
        let batch = BlockBatch::full_only(DataSource::UnprovableCertificateResponse, missing);
        self.sender
            .send(NetworkMessage::Batch(Box::new(batch)))
            .await
            .ok()
            .is_some()
    }

    /// Respond with blocks at the requested round that the requester doesn't
    /// yet have. Returns `true` to continue, `false` to break the connection
    /// loop.
    async fn handle_round_gap_request(
        &mut self,
        round: RoundNumber,
        known_authorities: AuthoritySet,
    ) -> bool {
        if !self.consensus_protocol.uses_compressed_refs() {
            return true;
        }
        let blocks = self.inner.dag_state.get_blocks_by_round(round);
        let missing: Vec<_> = blocks
            .into_iter()
            .filter(|b| !known_authorities.contains(b.authority()))
            .collect();
        let missing = prepare_forwarded_blocks_for_peer(
            self.inner.dag_state.block_authentication_scheme,
            self.consensus_protocol,
            self.peer_id,
            missing,
        );
        if missing.is_empty() {
            return true;
        }
        tracing::debug!(
            "RoundGapRequest from peer {:?} for round {}: \
             known_authorities={}, serving_blocks={}",
            self.peer,
            round,
            known_authorities.count_ones(),
            missing.len()
        );
        let batch = BlockBatch::full_only(DataSource::RoundGapResponse, missing);
        self.sender
            .send(NetworkMessage::Batch(Box::new(batch)))
            .await
            .ok()
            .is_some()
    }

    async fn shutdown(self) {
        self.disseminator.shutdown().await;
        self.data_requester.shutdown().await;
    }
}

pub struct NetworkSyncer<H: BlockHandler, C: CommitObserver> {
    inner: Arc<NetworkSyncerInner<H, C>>,
    main_task: JoinHandle<()>,
    stop: mpsc::Receiver<()>,
    bridge_task: Option<JoinHandle<()>>,
    partial_sig_routing_task: Option<JoinHandle<()>>,
    bls_event_task: Option<JoinHandle<()>>,
    bls_broadcast_task: Option<JoinHandle<()>>,
    sf_event_task: Option<JoinHandle<()>>,
    rbc_event_task: Option<JoinHandle<()>>,
    rbc_service_task: Option<JoinHandle<()>>,
    rbc_dag_shadow_event_task: Option<JoinHandle<()>>,
    rbc_dag_shadow_service_task: Option<JoinHandle<()>>,
    cordial_knowledge_task: JoinHandle<()>,
}

pub(crate) struct NetworkSyncSignals {
    block_ready_notify: Arc<Notify>,
    proposal_round_notify: Arc<Notify>,
}

pub struct NetworkSyncerInner<H: BlockHandler, C: CommitObserver> {
    syncer: CoreThreadDispatcher<H, NetworkSyncSignals, C>,
    pub dag_state: DagState,
    pub block_ready_notify: Arc<Notify>,
    pub proposal_round_notify: Arc<Notify>,
    pub committee: Arc<Committee>,
    pub mac_keys: Arc<Vec<MacKey>>,
    pub dissemination_mode: DisseminationMode,
    pub causal_push_shard_round_lag: RoundNumber,
    stop: mpsc::Sender<()>,
    pub gc_round: Arc<AtomicU32>,
    pub shard_tx: parking_lot::Mutex<
        Option<mpsc::UnboundedSender<Vec<crate::shard_reconstructor::ShardMessage>>>,
    >,
    pub cordial_knowledge: CordialKnowledgeHandle,
    /// Per-peer message senders for direct unicast (e.g. DAC partial sigs).
    pub peer_senders: parking_lot::RwLock<AHashMap<AuthorityIndex, mpsc::Sender<NetworkMessage>>>,
    /// Nonblocking ingress to per-connection RBC outbound workers. Keeping
    /// these queues separate prevents one backpressured peer from delaying
    /// another peer or the actor's local HeaderStaged/Delivered effects.
    rbc_peer_senders:
        parking_lot::RwLock<AHashMap<AuthorityIndex, mpsc::UnboundedSender<NetworkMessage>>>,
    pub leader_timeout: Duration,
    pub soft_block_timeout: Duration,
    /// Sailfish++ service handle for sending control messages
    /// (timeout/no-vote). None for non-SailfishPlusPlus protocols.
    pub sailfish_handle: Option<SailfishServiceHandle>,
    /// Central Starfish-RBC service. Connection workers only forward their
    /// trusted peer identity and wire payload into this single owner.
    pub(crate) starfish_rbc_service: Option<RbcServiceHandle>,
    /// Non-authoritative persisted embedded-RBC shadow. It emits only network
    /// and metric events and can never call the core dispatcher.
    pub(crate) starfish_rbc_dag_shadow_service: Option<StarfishRbcDagShadowServiceHandleV1>,
    /// Wall-clock at NetworkSyncer start; consumed by time-dependent
    /// Byzantine strategies (e.g. RampUpWithholding) to ramp behavior
    /// over a fixed schedule.
    pub start_time: std::time::Instant,
}

impl<H: BlockHandler + 'static, C: CommitObserver + 'static> NetworkSyncer<H, C> {
    pub async fn start(
        network: Network,
        mut core: Core<H>,
        mut commit_observer: C,
        metrics: Arc<Metrics>,
        node_parameters: NodeParameters,
        starfish_rbc_dag_shadow_wal: PathBuf,
        partial_sig_outbox_rx: Option<mpsc::UnboundedReceiver<PartialSig>>,
        bls_cert_aggregator: Option<BlsCertificateAggregator>,
        bls_signer: Option<BlsSigner>,
    ) -> Self {
        let handle = Handle::current();
        let block_ready_notify = Arc::new(Notify::new());
        let proposal_round_notify = Arc::new(Notify::new());
        let (committed, committed_leaders_count) = core.take_recovered_committed();
        commit_observer.recover_committed(committed, committed_leaders_count);
        let committee = core.committee().clone();
        let mac_keys = core.mac_keys();
        let dag_state = core.dag_state().clone();
        let recovered_shadow_local_headers = if node_parameters.starfish_rbc_dag_shadow {
            match recovered_local_rbc_headers(&core) {
                Ok(headers) => Some(headers),
                Err(error) => {
                    // A partial local history would make delivery comparisons
                    // meaningless. Disable the whole observational run while
                    // allowing authoritative direct RBC to continue.
                    tracing::error!(
                        "Disabling non-authoritative RBC-DAG shadow because recovered direct headers cannot be reconciled: {error}"
                    );
                    None
                }
            }
        } else {
            None
        };
        let dissemination_mode = dag_state
            .consensus_protocol
            .resolve_dissemination_mode(node_parameters.dissemination_mode);
        let _store = core.store();
        let universal_committer = core.get_universal_committer();
        // Create BLS service channel — sender clones go to Syncer (Core thread)
        // and network connection handlers, receiver goes to the BLS service task.
        let (bls_msg_tx, bls_msg_rx) = if bls_cert_aggregator.is_some() {
            let (tx, rx) = mpsc::unbounded_channel::<BlsServiceMessage>();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        // Create Sailfish service channel for SailfishPlusPlus protocol.
        let is_sailfish_pp = dag_state.consensus_protocol.is_sailfish_pp();
        let sailfish_signer = if is_sailfish_pp {
            Some(core.get_signer().clone())
        } else {
            None
        };
        let (sf_msg_tx, sf_msg_rx) = if is_sailfish_pp {
            let (tx, rx) = mpsc::unbounded_channel::<SailfishServiceMessage>();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let sf_handle_for_inner = sf_msg_tx
            .as_ref()
            .map(|tx| SailfishServiceHandle::new(tx.clone()));
        let (starfish_rbc_service, rbc_event_rx, rbc_service_task) =
            if dag_state.consensus_protocol.is_starfish_rbc() {
                let protocol_instance = node_parameters
                .starfish_rbc_protocol_instance
                .and_then(|bytes| RbcProtocolInstanceId::new(bytes).ok())
                .expect(
                    "validated Starfish-RBC configuration must contain a nonzero protocol instance",
                );
                let initial_authenticator = match dag_state.block_authentication_scheme {
                    BlockAuthenticationScheme::Ed25519 => {
                        RbcInitialAuthenticator::Ed25519(core.get_signer().clone())
                    }
                    BlockAuthenticationScheme::MlDsa44 => {
                        RbcInitialAuthenticator::MlDsa44(core.get_ml_dsa_44_signer().clone())
                    }
                    BlockAuthenticationScheme::MlDsa65 => {
                        RbcInitialAuthenticator::MlDsa65(core.get_ml_dsa_65_signer().clone())
                    }
                    BlockAuthenticationScheme::MacVector => RbcInitialAuthenticator::Mac,
                };
                let phase_authority = if node_parameters.starfish_rbc_dag_embedded_rbc_authority {
                    RbcPhaseAuthorityV1::EmbeddedCarrierDag
                } else {
                    RbcPhaseAuthorityV1::Direct
                };
                let (service, events, task) = start_starfish_rbc_service_with_phase_authority(
                    committee.clone(),
                    dag_state.get_own_authority_index(),
                    protocol_instance,
                    dag_state.block_authentication_scheme,
                    mac_keys.clone(),
                    initial_authenticator,
                    dag_state.highest_round(),
                    STARFISH_RBC_HEADER_RETRY_INTERVAL,
                    phase_authority,
                )
                .expect("validated Starfish-RBC configuration must start its service");
                (Some(service), Some(events), Some(task))
            } else {
                (None, None, None)
            };
        let (starfish_rbc_dag_shadow_service, rbc_dag_shadow_event_rx, rbc_dag_shadow_service_task) =
            if let Some(recovered_local_headers) = recovered_shadow_local_headers {
                let protocol_instance_bytes = node_parameters
                    .starfish_rbc_protocol_instance
                    .expect("validated shadow configuration must share the direct RBC instance");
                let protocol_instance = rbc_dag_shadow_protocol_instance(
                    protocol_instance_bytes,
                    node_parameters.starfish_rbc_dag_autonomous_clock,
                );
                let committee_context = RbcDagCommitteeContextV1::new(committee.clone())
                    .expect("validated committee must initialize the RBC-DAG shadow");
                let context = RbcDagContextV1::new_with_committee(
                    protocol_instance,
                    &committee_context,
                    dag_state.block_authentication_scheme,
                );
                let authorizer = match dag_state.block_authentication_scheme {
                    BlockAuthenticationScheme::Ed25519 => {
                        ShadowAuthorizerV1::Ed25519(core.get_signer().clone())
                    }
                    BlockAuthenticationScheme::MlDsa44 => {
                        ShadowAuthorizerV1::MlDsa44(core.get_ml_dsa_44_signer().clone())
                    }
                    BlockAuthenticationScheme::MlDsa65 => {
                        ShadowAuthorizerV1::MlDsa65(core.get_ml_dsa_65_signer().clone())
                    }
                    BlockAuthenticationScheme::MacVector => {
                        ShadowAuthorizerV1::MacVector(mac_keys.as_ref().clone())
                    }
                };
                // -1 means the background WAL replay has not completed yet;
                // Ready moves the active observational mode to 1 unless work
                // was already shed (0). The inactive verdict remains zero.
                if node_parameters.starfish_rbc_dag_autonomous_clock {
                    metrics.starfish_rbc_dag_shadow_clock_valid.set(-1);
                    metrics.starfish_rbc_dag_shadow_comparison_valid.set(0);
                } else {
                    metrics.starfish_rbc_dag_shadow_comparison_valid.set(-1);
                    metrics.starfish_rbc_dag_shadow_clock_valid.set(0);
                }
                let started = if node_parameters.starfish_rbc_dag_autonomous_clock {
                    let wal_sync_policy = if node_parameters.starfish_rbc_dag_shadow_buffered_wal {
                        ShadowWalSyncPolicyV1::OnShutdown
                    } else {
                        ShadowWalSyncPolicyV1::EveryBatch
                    };
                    start_starfish_rbc_dag_autonomous_clock_service_v1(
                        starfish_rbc_dag_shadow_wal,
                        committee_context,
                        dag_state.get_own_authority_index(),
                        context,
                        authorizer,
                        recovered_local_headers,
                        // The idle carrier pacemaker deliberately shares the
                        // resolved Starfish leader timeout. Application and
                        // embedded RBC phase carriers remain event-driven.
                        node_parameters.leader_timeout,
                        wal_sync_policy,
                    )
                } else {
                    let wal_sync_policy = if node_parameters.starfish_rbc_dag_shadow_buffered_wal {
                        ShadowWalSyncPolicyV1::OnShutdown
                    } else {
                        ShadowWalSyncPolicyV1::EveryBatch
                    };
                    start_starfish_rbc_dag_shadow_service_v1(
                        starfish_rbc_dag_shadow_wal,
                        committee_context,
                        dag_state.get_own_authority_index(),
                        context,
                        authorizer,
                        recovered_local_headers,
                        wal_sync_policy,
                    )
                };
                match started {
                    Ok((service, events, task)) => (Some(service), Some(events), Some(task)),
                    Err(error) => {
                        invalidate_shadow_run(&metrics);
                        tracing::error!(
                            "Disabling non-authoritative Starfish-RBC-DAG shadow: {error}"
                        );
                        (None, None, None)
                    }
                }
            } else {
                (None, None, None)
            };
        let syncer = Syncer::new(
            core,
            NetworkSyncSignals {
                block_ready_notify: block_ready_notify.clone(),
                proposal_round_notify: proposal_round_notify.clone(),
            },
            commit_observer,
            metrics.clone(),
            bls_msg_tx.clone(),
            sf_msg_tx.clone(),
            starfish_rbc_service.clone(),
            starfish_rbc_dag_shadow_service.clone(),
        );
        let initial_round = syncer.core().next_block_round();
        let syncer = CoreThreadDispatcher::start(syncer);
        // Await the initial command while the async RBC actor remains
        // schedulable. The command itself runs on the dedicated core thread,
        // where synchronous local-INIT selection is safe.
        syncer.force_new_block(initial_round).await;
        let (stop_sender, stop_receiver) = mpsc::channel(1);
        // Occupy the only available permit, so that all other
        // calls to send() will block.
        stop_sender.try_send(()).unwrap();
        // Conditionally prepare shard reconstructor channels for Starfish protocols
        let is_starfish = matches!(
            dag_state.consensus_protocol,
            ConsensusProtocol::Starfish
                | ConsensusProtocol::StarfishSpeed
                | ConsensusProtocol::StarfishBls
                | ConsensusProtocol::SparseStarfishSpeed
                | ConsensusProtocol::StarfishRbc
        );
        let gc_round = Arc::new(AtomicU32::new(dag_state.gc_round()));
        let (shard_tx, decoded_rx) = if is_starfish {
            let (decoded_tx, decoded_rx) = mpsc::channel::<DecodedBlocks>(1000);
            let reconstructor_handle = start_shard_reconstructor(
                committee.clone(),
                dag_state.get_own_authority_index(),
                metrics.clone(),
                decoded_tx,
                gc_round.clone(),
            );
            (
                Some(reconstructor_handle.shard_message_sender()),
                Some(decoded_rx),
            )
        } else {
            (None, None)
        };

        // Create CordialKnowledge actor. The dag knowledge `Arc` is owned
        // by `DagState` (built during `open()` for push modes); we share
        // the same handle so the actor and the broadcaster's reads target
        // the same `RwLock`.
        let (cordial_knowledge_handle, cordial_knowledge_actor) = CordialKnowledgeHandle::new(
            committee.len(),
            dag_state.dag_knowledge(),
            metrics.clone(),
        );
        dag_state.attach_cordial_knowledge(cordial_knowledge_handle.clone());
        let cordial_knowledge_task = handle.spawn(cordial_knowledge_actor.run());

        let inner = Arc::new(NetworkSyncerInner {
            block_ready_notify,
            dag_state: dag_state.clone(),
            syncer,
            proposal_round_notify,
            committee,
            mac_keys,
            dissemination_mode,
            causal_push_shard_round_lag: node_parameters.causal_push_shard_round_lag,
            stop: stop_sender.clone(),
            gc_round,
            shard_tx: parking_lot::Mutex::new(shard_tx),
            cordial_knowledge: cordial_knowledge_handle,
            peer_senders: parking_lot::RwLock::new(AHashMap::new()),
            rbc_peer_senders: parking_lot::RwLock::new(AHashMap::new()),
            leader_timeout: node_parameters.leader_timeout,
            soft_block_timeout: node_parameters.soft_block_timeout,
            sailfish_handle: sf_handle_for_inner,
            starfish_rbc_service: starfish_rbc_service.clone(),
            starfish_rbc_dag_shadow_service: starfish_rbc_dag_shadow_service.clone(),
            start_time: std::time::Instant::now(),
        });

        // Bridge the single-owner RBC actor to direct network unicasts and to
        // the core thread's dirty/clean DAG boundaries. Header staging never
        // implies delivery; only a typed `Delivered` effect can mark a vertex
        // clean.
        let rbc_event_task = rbc_event_rx.map(|mut event_rx| {
            let event_inner = inner.clone();
            let rbc_metrics = metrics.clone();
            handle.spawn(async move {
                let mut payload_encoder = ReedSolomonEncoder::new(2, 4, 2)
                    .expect("Starfish-RBC payload encoder should be created");
                while let Some(event) = event_rx.recv().await {
                    match event {
                        RbcServiceEvent::Network { recipient, message } => {
                            let sender =
                                event_inner.rbc_peer_senders.read().get(&recipient).cloned();
                            if let Some(sender) = sender {
                                if sender.send(message).is_err() {
                                    tracing::debug!(
                                        "Starfish-RBC outbound worker for authority {} stopped",
                                        recipient
                                    );
                                }
                            } else {
                                // Local INITs and phase intents are retained by
                                // the actor and replayed when this peer connects.
                                tracing::debug!(
                                    "Deferring Starfish-RBC message for disconnected authority {}",
                                    recipient
                                );
                            }
                        }
                        RbcServiceEvent::HeaderStaged(header) => {
                            let mut block = header.header().to_authentication_free_block();
                            block.preserialize();
                            let block_ref = *block.reference();
                            event_inner
                                .cordial_knowledge
                                .send(CordialKnowledgeMessage::DagParts {
                                    headers: vec![block_ref],
                                    shards: Vec::new(),
                                });
                            let (missing_parents, _) = event_inner
                                .syncer
                                .add_headers(
                                    vec![Data::new(block)],
                                    DataSource::BlockBundleStreamingHeader,
                                )
                                .await;
                            if !missing_parents.is_empty() {
                                tracing::debug!(
                                    "Starfish-RBC staged header {} waits for dependencies {:?}",
                                    block_ref,
                                    missing_parents
                                );
                            }
                        }
                        RbcServiceEvent::TransactionPayloadStaged {
                            peer,
                            header,
                            transaction_data,
                        } => {
                            let block_ref = header.reference();
                            let item = match verify_starfish_rbc_transaction_payload(
                                header.header(),
                                transaction_data,
                                &event_inner.committee,
                                event_inner.dag_state.get_own_authority_index(),
                                peer,
                                &mut payload_encoder,
                                event_inner.dag_state.block_authentication_scheme,
                                &event_inner.mac_keys,
                            ) {
                                Ok(item) => item,
                                Err(error) => {
                                    tracing::warn!(
                                        ?block_ref,
                                        peer,
                                        ?error,
                                        "Rejected Starfish-RBC transaction payload"
                                    );
                                    continue;
                                }
                            };
                            event_inner
                                .cordial_knowledge
                                .send(CordialKnowledgeMessage::DagParts {
                                    headers: Vec::new(),
                                    shards: vec![block_ref],
                                });
                            if let Some(shard_tx) = event_inner.shard_tx.lock().as_ref() {
                                let _ = shard_tx.send(vec![ShardMessage::FullBlock(block_ref)]);
                            }
                            event_inner
                                .syncer
                                .add_transaction_data(vec![item], DataSource::StarfishRbcPayload)
                                .await;
                        }
                        RbcServiceEvent::Delivered(header) => {
                            if let Some(ref shadow) =
                                event_inner.starfish_rbc_dag_shadow_service
                            {
                                let canonical = header.header();
                                let identity = ShadowDeliveryIdentityV1::new(
                                    canonical.reference().authority,
                                    canonical.reference().round,
                                    canonical.transactions_commitment(),
                                );
                                if let Err(error) = shadow.direct_delivered(identity) {
                                    if shadow_transport_error_invalidates_run(&error) {
                                        invalidate_shadow_run(&rbc_metrics);
                                    }
                                    tracing::warn!(
                                        "Failed to notify RBC-DAG shadow of direct delivery: {error}"
                                    );
                                }
                            }
                            event_inner
                                .syncer
                                .apply_starfish_rbc_deliveries(vec![header])
                                .await;
                        }
                        RbcServiceEvent::Rejected { peer, error } => {
                            tracing::warn!(
                                "Rejected Starfish-RBC input from {:?}: {}",
                                peer,
                                error
                            );
                        }
                    }
                }
            })
        });

        let embedded_rbc_authority = node_parameters.starfish_rbc_dag_embedded_rbc_authority;
        let embedded_rbc_committee_id = embedded_rbc_authority.then(|| {
            RbcCommitteeId::derive(&inner.committee)
                .expect("validated direct RBC committee must retain a stable identifier")
        });
        let rbc_dag_shadow_event_task = rbc_dag_shadow_event_rx.map(|mut event_rx| {
            let event_inner = inner.clone();
            let shadow_metrics = metrics.clone();
            handle.spawn(async move {
                while let Some(event) = event_rx.recv().await {
                    match event {
                        ShadowServiceEventV1::Network { recipient, message } => {
                            let sender = event_inner.peer_senders.read().get(&recipient).cloned();
                            if let Some(sender) = sender {
                                match sender.try_send(message) {
                                    Ok(()) => shadow_metrics
                                        .starfish_rbc_dag_shadow_inputs_total
                                        .with_label_values(&["network", "sent"])
                                        .inc(),
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        // The shadow is observational. It must
                                        // shed work instead of backpressuring
                                        // the authoritative network path.
                                        shadow_metrics
                                            .starfish_rbc_dag_shadow_inputs_total
                                            .with_label_values(&["network", "dropped_backpressure"])
                                            .inc();
                                        shadow_metrics
                                            .starfish_rbc_dag_shadow_comparison_valid
                                            .set(0);
                                        shadow_metrics.starfish_rbc_dag_shadow_clock_valid.set(0);
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        shadow_metrics
                                            .starfish_rbc_dag_shadow_inputs_total
                                            .with_label_values(&["network", "disconnected"])
                                            .inc();
                                        shadow_metrics
                                            .starfish_rbc_dag_shadow_comparison_valid
                                            .set(0);
                                        shadow_metrics.starfish_rbc_dag_shadow_clock_valid.set(0);
                                    }
                                }
                            } else {
                                shadow_metrics
                                    .starfish_rbc_dag_shadow_inputs_total
                                    .with_label_values(&["network", "disconnected"])
                                    .inc();
                                // No observation was lost: the actor retains
                                // local carriers and replays them when this
                                // peer connects.
                            }
                        }
                        ShadowServiceEventV1::Delivered(identity) => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_inputs_total
                                .with_label_values(&["delivery", "shadow"])
                                .inc();
                            tracing::debug!(?identity, "RBC-DAG shadow delivered carrier");
                        }
                        ShadowServiceEventV1::EmbeddedApplicationDelivered { carrier, header } => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_inputs_total
                                .with_label_values(&["delivery", "embedded_application"])
                                .inc();
                            tracing::debug!(
                                ?carrier,
                                application = ?header.reference(),
                                "RBC-DAG shadow delivered embedded application header"
                            );
                            if embedded_rbc_authority {
                                match PinnedRbcHeader::validate_with_committee_id(
                                    header,
                                    &event_inner.committee,
                                    embedded_rbc_committee_id
                                        .expect("embedded authority must cache its committee ID"),
                                ) {
                                    Ok(header) => {
                                        event_inner
                                            .syncer
                                            .apply_starfish_rbc_deliveries(vec![header])
                                            .await;
                                    }
                                    Err(error) => {
                                        shadow_metrics.starfish_rbc_dag_shadow_clock_valid.set(0);
                                        tracing::error!(
                                            ?carrier,
                                            ?error,
                                            "Embedded RBC delivered an invalid application header"
                                        );
                                    }
                                }
                            }
                        }
                        ShadowServiceEventV1::ComparisonBacklog {
                            unpaired_direct,
                            unpaired_shadow,
                            max_round_lag,
                        } => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_unpaired_direct
                                .set(i64::try_from(unpaired_direct).unwrap_or(i64::MAX));
                            shadow_metrics
                                .starfish_rbc_dag_shadow_unpaired_shadow
                                .set(i64::try_from(unpaired_shadow).unwrap_or(i64::MAX));
                            shadow_metrics
                                .starfish_rbc_dag_shadow_unpaired_max_round_lag
                                .set(i64::from(max_round_lag));
                        }
                        ShadowServiceEventV1::Comparison(comparison) => {
                            let outcome = match &comparison {
                                ShadowDeliveryComparisonV1::Match => "match",
                                ShadowDeliveryComparisonV1::Mismatch {
                                    direct_only,
                                    shadow_only,
                                } if !direct_only.is_empty() && shadow_only.is_empty() => {
                                    "direct_only"
                                }
                                ShadowDeliveryComparisonV1::Mismatch {
                                    direct_only,
                                    shadow_only,
                                } if direct_only.is_empty() && !shadow_only.is_empty() => {
                                    "shadow_only"
                                }
                                ShadowDeliveryComparisonV1::Mismatch { .. } => "mismatch",
                                ShadowDeliveryComparisonV1::Ambiguous { .. } => "ambiguous",
                            };
                            shadow_metrics
                                .starfish_rbc_dag_shadow_delivery_comparisons_total
                                .with_label_values(&[outcome])
                                .inc();
                        }
                        ShadowServiceEventV1::Input { kind, outcome } => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_inputs_total
                                .with_label_values(&[kind, outcome])
                                .inc();
                        }
                        ShadowServiceEventV1::WalAppended {
                            batches,
                            records,
                            durable,
                        } => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_wal_appended_batches_total
                                .inc_by(batches);
                            shadow_metrics
                                .starfish_rbc_dag_shadow_wal_appended_records_total
                                .inc_by(records);
                            if durable {
                                shadow_metrics
                                    .starfish_rbc_dag_shadow_wal_durable_batches_total
                                    .inc_by(batches);
                                shadow_metrics
                                    .starfish_rbc_dag_shadow_wal_durable_records_total
                                    .inc_by(records);
                            }
                        }
                        ShadowServiceEventV1::Ready { autonomous_clock } => {
                            let verdict = if autonomous_clock {
                                &shadow_metrics.starfish_rbc_dag_shadow_clock_valid
                            } else {
                                &shadow_metrics.starfish_rbc_dag_shadow_comparison_valid
                            };
                            if verdict.get() != 0 {
                                verdict.set(1);
                            }
                        }
                        ShadowServiceEventV1::ClockState {
                            open_round,
                            phase_backlog,
                            admitted_authors,
                            admitted_stake,
                            buffered_authenticated,
                        } => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_carrier_round
                                .set(i64::from(open_round));
                            shadow_metrics
                                .starfish_rbc_dag_shadow_phase_backlog
                                .set(i64::try_from(phase_backlog).unwrap_or(i64::MAX));
                            shadow_metrics
                                .starfish_rbc_dag_shadow_admitted_authors
                                .set(i64::try_from(admitted_authors).unwrap_or(i64::MAX));
                            shadow_metrics
                                .starfish_rbc_dag_shadow_admitted_stake
                                .set(i64::try_from(admitted_stake).unwrap_or(i64::MAX));
                            shadow_metrics
                                .starfish_rbc_dag_shadow_buffered_authenticated
                                .set(i64::try_from(buffered_authenticated).unwrap_or(i64::MAX));
                        }
                        ShadowServiceEventV1::Recovered {
                            batches,
                            discarded_tail_bytes,
                        } => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_wal_replayed_batches
                                .set(batches as i64);
                            shadow_metrics
                                .starfish_rbc_dag_shadow_wal_discarded_tail_bytes_total
                                .inc_by(discarded_tail_bytes);
                        }
                        ShadowServiceEventV1::PendingRecovery(pending) => {
                            shadow_metrics
                                .starfish_rbc_dag_shadow_pending_recovery
                                .set(pending as i64);
                        }
                        ShadowServiceEventV1::Rejected { peer, error } => {
                            if peer.is_none() {
                                shadow_metrics
                                    .starfish_rbc_dag_shadow_comparison_valid
                                    .set(0);
                                shadow_metrics.starfish_rbc_dag_shadow_clock_valid.set(0);
                            }
                            tracing::warn!(
                                "Rejected non-authoritative RBC-DAG shadow input from {:?}: {}",
                                peer,
                                error
                            );
                        }
                    }
                }
            })
        });

        // Start bridge task that forwards reconstructed transaction data to core
        let bridge_task = decoded_rx.map(|mut decoded_rx| {
            let bridge_inner = inner.clone();
            handle.spawn(async move {
                while let Some(items) = decoded_rx.recv().await {
                    // Reconstruction proves we now have the shard data for the
                    // entire batch.
                    let shard_refs = items.iter().map(|item| item.block_reference).collect();
                    bridge_inner
                        .cordial_knowledge
                        .send(CordialKnowledgeMessage::DagParts {
                            headers: Vec::new(),
                            shards: shard_refs,
                        });
                    bridge_inner
                        .syncer
                        .add_transaction_data(items, DataSource::ShardReconstructor)
                        .await;
                }
            })
        });
        // Spawn partial-sig routing task: drains Core's outbox and routes
        // partial sigs by kind — DAC to block author, round/leader to all.
        let partial_sig_routing_task = partial_sig_outbox_rx.map(|mut rx| {
            let routing_inner = inner.clone();
            handle.spawn(async move {
                while let Some(partial_sig) = rx.recv().await {
                    match partial_sig.kind {
                        PartialSigKind::Dac(block_ref) => {
                            let target = block_ref.authority;
                            let sender = routing_inner.peer_senders.read().get(&target).cloned();
                            if let Some(sender) = sender {
                                send_network_message_reliably(
                                    &sender,
                                    NetworkMessage::PartialSig(partial_sig),
                                )
                                .await;
                            }
                        }
                        PartialSigKind::Round(_) | PartialSigKind::Leader(_) => {
                            let senders: Vec<_> = routing_inner
                                .peer_senders
                                .read()
                                .values()
                                .cloned()
                                .collect();
                            for sender in senders {
                                send_network_message_reliably(
                                    &sender,
                                    NetworkMessage::PartialSig(partial_sig.clone()),
                                )
                                .await;
                            }
                        }
                    }
                }
            })
        });
        // Start BLS verification service and event bridge task.
        // The BLS service gets a broadcast sender for pre-computed partial sigs.
        let (bls_broadcast_tx, bls_broadcast_task) = if bls_signer.is_some() {
            let (tx, mut rx) = mpsc::unbounded_channel::<PartialSig>();
            let routing_inner = inner.clone();
            let task = handle.spawn(async move {
                while let Some(partial_sig) = rx.recv().await {
                    // Pre-computed sigs are always round/leader, broadcast to all.
                    let senders: Vec<_> = routing_inner
                        .peer_senders
                        .read()
                        .values()
                        .cloned()
                        .collect();
                    for sender in senders {
                        send_network_message_reliably(
                            &sender,
                            NetworkMessage::PartialSig(partial_sig.clone()),
                        )
                        .await;
                    }
                }
            });
            (Some(tx), Some(task))
        } else {
            (None, None)
        };

        let own_authority = dag_state.get_own_authority_index();
        let bls_committee = inner.committee.clone();
        let (bls_service, bls_event_task) = if let (Some(aggregator), Some(bls_rx), Some(bls_tx)) =
            (bls_cert_aggregator, bls_msg_rx, bls_msg_tx)
        {
            let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Vec<CertificateEvent>>();
            start_bls_service(
                aggregator,
                bls_tx.clone(),
                bls_rx,
                event_tx,
                metrics.clone(),
                bls_signer,
                own_authority,
                bls_committee,
                bls_broadcast_tx,
                dag_state.clone(),
                inner.block_ready_notify.clone(),
                inner.proposal_round_notify.clone(),
            );
            let bls_handle = BlsServiceHandle::new(bls_tx);
            let event_inner = inner.clone();
            let task = handle.spawn(async move {
                while let Some(events) = event_rx.recv().await {
                    event_inner.syncer.apply_certificate_events(events).await;
                }
            });
            (Some(bls_handle), Some(task))
        } else {
            (None, None)
        };

        // Start Sailfish++ RBC certification service.
        let (sf_service, sf_event_task) = if let (Some(sf_tx), Some(sf_rx), Some(sf_signer)) =
            (sf_msg_tx, sf_msg_rx, sailfish_signer)
        {
            let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Vec<SailfishCertEvent>>();
            start_sailfish_service(
                inner.committee.clone(),
                own_authority,
                sf_signer,
                sf_rx,
                event_tx,
                metrics.clone(),
            );
            let sf_handle = SailfishServiceHandle::new(sf_tx);
            // Event bridge: certification events -> core thread + network broadcast
            let event_inner = inner.clone();
            let event_task = handle.spawn(async move {
                let mut cert_flush_interval =
                    tokio::time::interval(SAILFISH_CERT_BATCH_FLUSH_INTERVAL);
                cert_flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                cert_flush_interval.tick().await;
                let mut pending_cert_messages = Vec::new();

                loop {
                    select! {
                        maybe_events = event_rx.recv() => {
                            let Some(events) = maybe_events else {
                                break;
                            };

                            tracing::debug!("Sailfish event bridge: {} events", events.len(),);
                            let certified_refs: Vec<_> = events
                                .iter()
                                .filter_map(|event| match event {
                                    SailfishCertEvent::Certified(block_ref) => Some(*block_ref),
                                    _ => None,
                                })
                                .collect();
                            if !certified_refs.is_empty() {
                                tracing::info!(
                                    "Applying {} Sailfish certificates: {:?}",
                                    certified_refs.len(),
                                    certified_refs,
                                );
                                event_inner
                                    .syncer
                                    .apply_sailfish_certificates(certified_refs)
                                    .await;
                            }
                            // Apply timeout/novote certs to dag state
                            for event in &events {
                                match event {
                                    SailfishCertEvent::TimeoutReady(cert) => {
                                        event_inner.syncer.apply_timeout_cert(cert.clone()).await;
                                    }
                                    SailfishCertEvent::NoVoteReady(cert) => {
                                        event_inner.syncer.apply_novote_cert(cert.clone()).await;
                                    }
                                    _ => {}
                                }
                            }
                            // Broadcast Vote/Ready/Timeout/NoVote messages
                            {
                                let senders: Vec<_> =
                                    event_inner.peer_senders.read().values().cloned().collect();
                                tracing::debug!(
                                    "Sailfish broadcast: {} peers, {} events",
                                    senders.len(),
                                    events.len(),
                                );
                                for event in &events {
                                    match event {
                                        SailfishCertEvent::Broadcast(message) => {
                                            pending_cert_messages.push(message.clone());
                                        }
                                        SailfishCertEvent::BroadcastTimeout(msg) => {
                                            if !pending_cert_messages.is_empty() {
                                                broadcast_sailfish_cert_messages(
                                                    &senders,
                                                    &pending_cert_messages,
                                                )
                                                .await;
                                                pending_cert_messages.clear();
                                            }
                                            for sender in &senders {
                                                send_network_message_reliably(
                                                    sender,
                                                    NetworkMessage::SailfishTimeout(msg.clone()),
                                                )
                                                .await;
                                            }
                                        }
                                        SailfishCertEvent::SendNoVote(msg) => {
                                            // Route no-vote only to the next-round leader.
                                            let next_leader =
                                                event_inner.committee.elect_leader(msg.round + 1);
                                            let leader_tx = event_inner
                                                .peer_senders
                                                .read()
                                                .get(&next_leader)
                                                .cloned();
                                            if let Some(sender) = leader_tx {
                                                send_network_message_reliably(
                                                    &sender,
                                                    NetworkMessage::SailfishNoVote(msg.clone()),
                                                )
                                                .await;
                                            }
                                        }
                                        SailfishCertEvent::Certified(_)
                                        | SailfishCertEvent::TimeoutReady(_)
                                        | SailfishCertEvent::NoVoteReady(_) => {}
                                    }
                                }

                                if pending_cert_messages.len() >= SAILFISH_CERT_BATCH_MAX_LEN {
                                    broadcast_sailfish_cert_messages(
                                        &senders,
                                        &pending_cert_messages,
                                    )
                                    .await;
                                    pending_cert_messages.clear();
                                }
                            }
                        }
                        _ = cert_flush_interval.tick(), if !pending_cert_messages.is_empty() => {
                            let senders: Vec<_> =
                                event_inner.peer_senders.read().values().cloned().collect();
                            broadcast_sailfish_cert_messages(&senders, &pending_cert_messages)
                                .await;
                            pending_cert_messages.clear();
                        }
                    }
                }

                if !pending_cert_messages.is_empty() {
                    let senders: Vec<_> =
                        event_inner.peer_senders.read().values().cloned().collect();
                    broadcast_sailfish_cert_messages(&senders, &pending_cert_messages).await;
                }
            });
            (Some(sf_handle), Some(event_task))
        } else {
            (None, None)
        };

        let block_fetcher = Arc::new(BlockFetcher::start());
        let main_task = handle.spawn(Self::run(
            network,
            universal_committer,
            inner.clone(),
            block_fetcher,
            metrics.clone(),
            bls_service.clone(),
            sf_service.clone(),
        ));
        Self {
            inner,
            main_task,
            stop: stop_receiver,
            bridge_task,
            partial_sig_routing_task,
            bls_event_task,
            bls_broadcast_task,
            sf_event_task,
            rbc_event_task,
            rbc_service_task,
            rbc_dag_shadow_event_task,
            rbc_dag_shadow_service_task,
            cordial_knowledge_task,
        }
    }

    pub(crate) async fn shutdown(self) -> Syncer<H, NetworkSyncSignals, C> {
        drop(self.stop);
        // todo - wait for network shutdown as well
        self.main_task.await.ok();
        // Close the shard reconstructor channel so the bridge task can exit
        // and release its Arc reference.
        self.inner.shard_tx.lock().take();
        // Wait for the bridge task to observe channel closure and exit.
        if let Some(bridge_task) = self.bridge_task {
            bridge_task.await.ok();
        }
        // The partial-sig routing task holds an `Arc` to `inner` and waits on
        // a receiver whose sender lives inside the core thread. Abort it here
        // to break that shutdown cycle before unwrapping `inner`.
        if let Some(sig_task) = self.partial_sig_routing_task {
            sig_task.abort();
            sig_task.await.ok();
        }
        // The BLS event bridge task holds an `Arc` to `inner`. Abort it to
        // allow `Arc::try_unwrap` below.
        if let Some(bls_task) = self.bls_event_task {
            bls_task.abort();
            bls_task.await.ok();
        }
        if let Some(bls_broadcast) = self.bls_broadcast_task {
            bls_broadcast.abort();
            bls_broadcast.await.ok();
        }
        // Abort Sailfish event bridge task.
        if let Some(sf_task) = self.sf_event_task {
            sf_task.abort();
            sf_task.await.ok();
        }
        // Stop RBC event ingress first, but keep the service actor alive while
        // the core queue drains: an already queued core action may still
        // synchronously select another local INIT.
        if let Some(rbc_task) = self.rbc_event_task {
            rbc_task.abort();
            rbc_task.await.ok();
        }
        let rbc_service_task = self.rbc_service_task;
        if let Some(shadow_task) = self.rbc_dag_shadow_event_task {
            shadow_task.abort();
            shadow_task.await.ok();
        }
        let rbc_dag_shadow_service_task = self.rbc_dag_shadow_service_task;
        // Stop the cordial knowledge actor.
        self.cordial_knowledge_task.abort();
        self.cordial_knowledge_task.await.ok();
        // Some auxiliary tasks (e.g. per-round timeout timers) are spawned
        // detached and only notice shutdown once they get a chance to poll and
        // observe `stopped()`. Give them a short window to drop their `Arc`s
        // before insisting on `try_unwrap`.
        let mut inner_arc = self.inner;
        let mut attempts = 0usize;
        let inner = loop {
            match Arc::try_unwrap(inner_arc) {
                Ok(inner) => break inner,
                Err(arc) => {
                    attempts += 1;
                    if attempts >= 100 {
                        panic!(
                            "Shutdown failed - not all resources are freed \
                             after main task is completed"
                        );
                    }
                    inner_arc = arc;
                    tokio::task::yield_now().await;
                }
            }
        };
        // `inner` is now exclusive, so no auxiliary task can enqueue after
        // this FIFO barrier. Awaiting it keeps the runtime available to the
        // RBC actor while any earlier core action completes.
        let _ = inner.syncer.missing_parent_references().await;
        let mut shadow_shutdown_timed_out = false;
        if let Some(ref shadow) = inner.starfish_rbc_dag_shadow_service {
            match tokio::time::timeout(STARFISH_RBC_DAG_SHADOW_SHUTDOWN_TIMEOUT, shadow.shutdown())
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(
                    "Non-authoritative RBC-DAG shadow did not acknowledge shutdown: {error}"
                ),
                Err(_) => {
                    shadow_shutdown_timed_out = true;
                    tracing::warn!(
                        "Timed out stopping non-authoritative RBC-DAG shadow; detaching it from validator shutdown"
                    );
                    if let Some(task) = rbc_dag_shadow_service_task.as_ref() {
                        task.abort();
                    }
                }
            }
        }
        let syncer = inner.syncer.stop();
        if let Some(rbc_service_task) = rbc_service_task {
            rbc_service_task.abort();
            rbc_service_task.await.ok();
        }
        if let Some(shadow_service_task) = rbc_dag_shadow_service_task {
            match shadow_service_task.await {
                Err(error) if !shadow_shutdown_timed_out => tracing::warn!(
                    "Non-authoritative RBC-DAG shadow supervisor failed during shutdown: {error}"
                ),
                _ => {}
            }
        }
        syncer
    }

    async fn run(
        mut network: Network,
        universal_committer: UniversalCommitter,
        inner: Arc<NetworkSyncerInner<H, C>>,
        block_fetcher: Arc<BlockFetcher>,
        metrics: Arc<Metrics>,
        bls_service: Option<BlsServiceHandle>,
        sf_service: Option<SailfishServiceHandle>,
    ) {
        let mut connections: HashMap<usize, JoinHandle<Option<()>>> = HashMap::new();
        let handle = Handle::current();
        let leader_timeout_task = handle.spawn(Self::leader_timeout_task(inner.clone()));
        let soft_block_timeout_task = if inner.dag_state.consensus_protocol.uses_strong_vote() {
            Some(handle.spawn(Self::soft_block_timeout_task(inner.clone())))
        } else {
            None
        };

        let commit_timeout_task = handle.spawn(Self::commit_timeout_task(inner.clone()));
        let cleanup_task = handle.spawn(Self::cleanup_task(
            inner.clone(),
            bls_service.clone(),
            sf_service.clone(),
        ));
        let missing_parent_pull_task = handle.spawn(Self::missing_parent_pull_task(
            inner.clone(),
            metrics.clone(),
        ));
        let cert_pull_task = if inner
            .dag_state
            .consensus_protocol
            .carries_unprovable_certificate()
        {
            Some(handle.spawn(Self::unprovable_cert_pull_task(inner.clone())))
        } else {
            None
        };
        let round_gap_pull_task = if inner.dag_state.consensus_protocol.uses_compressed_refs() {
            Some(handle.spawn(Self::round_gap_pull_task(inner.clone())))
        } else {
            None
        };
        let filter_for_blocks = Arc::new(FilterForBlocks::new());
        let filter_for_shards = Arc::new(FilterForShards::new(inner.committee.info_length()));
        while let Some(connection) = inner.recv_or_stopped(network.connection_receiver()).await {
            let peer_id = connection.peer_id;
            if let Some(task) = connections.remove(&peer_id) {
                // wait until previous sync task completes
                task.await.ok();
            }

            let sender = connection.sender.clone();
            let authority = peer_id as AuthorityIndex;
            block_fetcher.register_authority(authority, sender).await;

            let task = handle.spawn(Self::connection_task(
                connection,
                universal_committer.clone(),
                inner.clone(),
                block_fetcher.clone(),
                metrics.clone(),
                filter_for_blocks.clone(),
                filter_for_shards.clone(),
                bls_service.clone(),
                sf_service.clone(),
            ));
            connections.insert(peer_id, task);
        }
        join_all(
            connections
                .into_values()
                .chain([
                    leader_timeout_task,
                    commit_timeout_task,
                    cleanup_task,
                    missing_parent_pull_task,
                ])
                .chain(soft_block_timeout_task)
                .chain(cert_pull_task)
                .chain(round_gap_pull_task),
        )
        .await;
        Arc::try_unwrap(block_fetcher)
            .unwrap_or_else(|_| panic!("Failed to drop all connections"))
            .shutdown()
            .await;
        // Abort the TCP server so the listening port is released.
        network.abort_server();
    }

    async fn connection_task(
        mut connection: Connection,
        universal_committer: UniversalCommitter,
        inner: Arc<NetworkSyncerInner<H, C>>,
        block_fetcher: Arc<BlockFetcher>,
        metrics: Arc<Metrics>,
        filter_for_blocks: Arc<FilterForBlocks>,
        filter_for_shards: Arc<FilterForShards>,
        bls_service: Option<BlsServiceHandle>,
        sf_service: Option<SailfishServiceHandle>,
    ) -> Option<()> {
        let gc_round = inner.dag_state.gc_round();
        connection
            .sender
            .send(NetworkMessage::SubscribeBroadcastRequest(gc_round))
            .await
            .ok()?;

        let shadow_metrics = metrics.clone();
        let mut handler = ConnectionHandler::new(
            &connection,
            universal_committer,
            inner.clone(),
            metrics,
            filter_for_blocks,
            filter_for_shards,
            bls_service,
            sf_service,
        );
        handler.start().await;

        let peer_id = handler.peer_id;
        let own_id = handler.own_id;

        // Register peer sender for direct unicast messages (DAC partial sigs).
        inner
            .peer_senders
            .write()
            .insert(peer_id, connection.sender.clone());
        let rbc_outbound_task = inner.starfish_rbc_service.as_ref().map(|_| {
            let (rbc_sender, mut rbc_receiver) = mpsc::unbounded_channel();
            inner.rbc_peer_senders.write().insert(peer_id, rbc_sender);
            let network_sender = connection.sender.clone();
            Handle::current().spawn(async move {
                while let Some(message) = rbc_receiver.recv().await {
                    send_network_message_reliably(&network_sender, message).await;
                }
            })
        });
        if let Some(ref rbc) = inner.starfish_rbc_service {
            if let Err(error) = rbc.peer_connected(peer_id) {
                tracing::warn!(
                    "Failed to notify Starfish-RBC service that authority {} connected: {}",
                    peer_id,
                    error
                );
            }
        }
        if let Some(ref shadow) = inner.starfish_rbc_dag_shadow_service {
            if let Err(error) = shadow.peer_connected(peer_id) {
                if shadow_transport_error_invalidates_run(&error) {
                    invalidate_shadow_run(&shadow_metrics);
                }
                tracing::warn!(
                    "Failed to notify RBC-DAG shadow that authority {} connected: {}",
                    peer_id,
                    error
                );
            }
        }

        if inner.dag_state.consensus_protocol.uses_bls() {
            for (round, signature) in inner.dag_state.precomputed_round_sigs() {
                let _ = connection
                    .sender
                    .send(NetworkMessage::PartialSig(PartialSig {
                        kind: PartialSigKind::Round(round),
                        signer: own_id,
                        signature,
                    }))
                    .await;
            }
            for (leader_ref, signature) in inner.dag_state.precomputed_leader_sigs() {
                let _ = connection
                    .sender
                    .send(NetworkMessage::PartialSig(PartialSig {
                        kind: PartialSigKind::Leader(leader_ref),
                        signer: own_id,
                        signature,
                    }))
                    .await;
            }
        }

        inner.syncer.authority_connection(peer_id, true).await;

        tracing::debug!(
            "Connection from {:?} to {:?} is established",
            own_id,
            peer_id
        );
        while let Some(message) = inner.recv_or_stopped(&mut connection.receiver).await {
            if !handler.handle_message(message).await {
                break;
            }
        }

        tracing::debug!("Connection between {own_id} and {peer_id} is dropped");
        if let Some(ref rbc) = inner.starfish_rbc_service {
            if let Err(error) = rbc.peer_disconnected(peer_id) {
                tracing::warn!(
                    "Failed to notify Starfish-RBC service that authority {} disconnected: {}",
                    peer_id,
                    error
                );
            }
        }
        if let Some(ref shadow) = inner.starfish_rbc_dag_shadow_service {
            if let Err(error) = shadow.peer_disconnected(peer_id) {
                if shadow_transport_error_invalidates_run(&error) {
                    invalidate_shadow_run(&shadow_metrics);
                }
                tracing::warn!(
                    "Failed to notify RBC-DAG shadow that authority {} disconnected: {}",
                    peer_id,
                    error
                );
            }
        }
        inner.peer_senders.write().remove(&peer_id);
        inner.rbc_peer_senders.write().remove(&peer_id);
        if let Some(rbc_outbound_task) = rbc_outbound_task {
            rbc_outbound_task.abort();
            rbc_outbound_task.await.ok();
        }
        inner.syncer.authority_connection(peer_id, false).await;
        handler.shutdown().await;
        block_fetcher.remove_authority(peer_id).await;
        None
    }

    async fn leader_timeout_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        let mut armed_round = inner.dag_state.proposal_round().saturating_sub(1);
        loop {
            while inner.dag_state.proposal_round() <= armed_round {
                let proposal_round_advanced = inner.proposal_round_notify.notified();
                select! {
                    _notified = proposal_round_advanced => {}
                    _stopped = inner.stopped() => {
                        return None;
                    }
                }
            }

            let current_round = inner.dag_state.proposal_round();
            for round in armed_round + 1..=current_round {
                let timer_inner = inner.clone();
                Handle::current().spawn(async move {
                    let leader_timeout = timer_inner.leader_timeout;
                    select! {
                        _sleep = sleep(leader_timeout) => {
                            tracing::debug!("Timeout for proposal round {round}");
                            if let Some(ref sf) = timer_inner.sailfish_handle {
                                let leader_round = round.saturating_sub(1);
                                if leader_round > 0 {
                                    sf.send(SailfishServiceMessage::LocalTimeout(leader_round));
                                }
                            }
                            timer_inner.syncer.force_new_block(round).await;
                        }
                        _stopped = timer_inner.stopped() => {}
                    }
                });
            }
            armed_round = current_round;
        }
    }

    /// Strong-vote soft timeout (StarfishSpeed / SparseStarfishSpeed): once a
    /// proposal round can be entered but the strong-vote quorum has not formed,
    /// fall back to the base Starfish readiness check and propose a blame
    /// block. Armed on the proposal round so dual-DAG protocols (where the
    /// proposal round can lag the threshold clock) fire for the round they
    /// can actually enter.
    async fn soft_block_timeout_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        let soft_timeout = inner.soft_block_timeout;
        let mut armed_round = inner.dag_state.proposal_round();
        loop {
            while inner.dag_state.proposal_round() <= armed_round {
                let notified = inner.proposal_round_notify.notified();
                select! {
                    _notified = notified => {}
                    _stopped = inner.stopped() => {
                        return None;
                    }
                }
            }

            armed_round = inner.dag_state.proposal_round();
            let notified = inner.proposal_round_notify.notified();
            select! {
                _sleep = sleep(soft_timeout) => {
                    tracing::debug!("Soft block timeout in proposal round {armed_round}");
                    inner.syncer.try_new_block_relaxed(armed_round).await;
                }
                _notified = notified => {
                    // Round advanced — restart timer
                }
                _stopped = inner.stopped() => {
                    return None;
                }
            }
        }
    }

    async fn commit_timeout_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        let commit_timeout = Duration::from_millis(10);
        loop {
            let notified = inner.block_ready_notify.notified();
            let round = inner
                .dag_state
                .last_own_block_ref()
                .map(|b| b.round())
                .unwrap_or_default();
            select! {
                _sleep = sleep(commit_timeout) => {
                    tracing::debug!("Commit timeout in round {round}");
                    // try commit
                    inner.syncer.force_commit().await;

                }
                _notified = notified => {
                    // todo - more then one round timeout can happen, need to fix this
                    inner.syncer.force_commit().await;
                }
                _stopped = inner.stopped() => {
                    return None;
                }
            }
        }
    }

    /// Periodically re-requests block-manager parents that are still missing,
    /// fanning requests out to a few random peers instead of only the original
    /// sender.
    async fn missing_parent_pull_task(
        inner: Arc<NetworkSyncerInner<H, C>>,
        metrics: Arc<Metrics>,
    ) -> Option<()> {
        const SCAN_INTERVAL: Duration = Duration::from_millis(500);
        const PEER_COUNT: usize = 2;

        let mut first_seen: AHashMap<BlockReference, Instant> = AHashMap::new();
        let mut last_requested: AHashMap<BlockReference, Instant> = AHashMap::new();

        loop {
            select! {
                _ = sleep(SCAN_INTERVAL) => {}
                _ = inner.stopped() => { return None; }
            }

            let missing_refs = inner.syncer.missing_parent_references().await;
            let now = Instant::now();
            let eligible_refs = eligible_missing_parent_refs(
                &missing_refs,
                &mut first_seen,
                &mut last_requested,
                now,
                SCAN_INTERVAL,
            );
            if eligible_refs.is_empty() {
                continue;
            }

            let senders = select_random_peer_senders(&inner, PEER_COUNT);
            if senders.is_empty() {
                continue;
            }

            tracing::debug!(
                "Retry missing parents {:?} from {} random peers",
                eligible_refs,
                senders.len()
            );
            for (peer, sender) in &senders {
                metrics
                    .block_sync_requests_sent
                    .with_label_values(&[&peer.to_string()])
                    .inc();
                send_network_message_reliably(
                    sender,
                    NetworkMessage::MissingParentsRequest(eligible_refs.clone()),
                )
                .await;
            }

            for block_ref in eligible_refs {
                last_requested.insert(block_ref, now);
            }
        }
    }

    /// Periodically scans for stalled Bluestreak unprovable certificates and
    /// requests missing voting blocks from random peers.
    async fn unprovable_cert_pull_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        const SCAN_INTERVAL: Duration = Duration::from_millis(100);
        const PEER_COUNT: usize = 2;

        // Tracking is keyed by (leader_ref, strong) so that standard and
        // strong cert flavors are rate-limited independently (SSFS).
        let mut first_seen: AHashMap<(BlockReference, bool), Instant> = AHashMap::new();
        let mut last_requested: AHashMap<(BlockReference, bool), Instant> = AHashMap::new();

        loop {
            select! {
                _ = sleep(SCAN_INTERVAL) => {}
                _ = inner.stopped() => { return None; }
            }

            let pending = inner.dag_state.pending_unprovable_certificates();
            let now = Instant::now();

            // Prune tracking maps for cert keys no longer pending.
            first_seen.retain(|k, _| pending.iter().any(|(lr, strong, _)| (*lr, *strong) == *k));
            last_requested
                .retain(|k, _| pending.iter().any(|(lr, strong, _)| (*lr, *strong) == *k));

            for (leader_ref, strong, known_voters) in &pending {
                let key = (*leader_ref, *strong);
                // Must have been waiting >= SCAN_INTERVAL before first request.
                let first = first_seen.entry(key).or_insert(now);
                if now.duration_since(*first) < SCAN_INTERVAL {
                    continue;
                }
                // Rate limit: one request per cert flavor per interval.
                if let Some(last) = last_requested.get(&key) {
                    if now.duration_since(*last) < SCAN_INTERVAL {
                        continue;
                    }
                }

                let senders = select_random_peer_senders(&inner, PEER_COUNT);
                if senders.is_empty() {
                    continue;
                }

                tracing::debug!(
                    "Request unprovable certificate support for leader {} \
                     (strong={}) from {} peers (known_voters={})",
                    leader_ref,
                    strong,
                    senders.len(),
                    known_voters.count_ones()
                );
                for (_peer, sender) in &senders {
                    let msg = NetworkMessage::UnprovableCertificateRequest {
                        leader_ref: *leader_ref,
                        known_voters: *known_voters,
                    };
                    let _ = sender.send(msg).await;
                }

                last_requested.insert(key, now);
            }
        }
    }

    /// Periodically checks whether the node's proposal round lags behind
    /// the highest observed DAG round. When the gap persists for two
    /// consecutive ticks, requests missing blocks at `highest_round - 1`
    /// from 2 random peers.
    async fn round_gap_pull_task(inner: Arc<NetworkSyncerInner<H, C>>) -> Option<()> {
        const SCAN_INTERVAL: Duration = Duration::from_millis(100);
        const PEER_COUNT: usize = 2;

        let mut gap_detected = false;

        loop {
            select! {
                _ = sleep(SCAN_INTERVAL) => {}
                _ = inner.stopped() => { return None; }
            }

            let highest_round = inner.dag_state.highest_round();
            let proposal_round = inner.dag_state.proposal_round();

            if proposal_round < highest_round {
                if !gap_detected {
                    gap_detected = true;
                    continue;
                }

                let senders = select_random_peer_senders(&inner, PEER_COUNT);
                if senders.is_empty() {
                    continue;
                }

                let target_round = highest_round - 1;
                let blocks = inner.dag_state.get_blocks_by_round_cached(target_round);
                let mut known_authorities = AuthoritySet::default();
                for b in blocks.iter() {
                    known_authorities.insert(b.authority());
                }

                tracing::debug!(
                    "Round gap detected: proposal_round={}, highest_round={}, \
                     requesting round {} from {} peers (known={})",
                    proposal_round,
                    highest_round,
                    target_round,
                    senders.len(),
                    known_authorities.count_ones()
                );

                for (_peer, sender) in &senders {
                    let msg = NetworkMessage::RoundGapRequest {
                        round: target_round,
                        known_authorities,
                    };
                    let _ = sender.send(msg).await;
                }

                // Reset so the two-tick gate must re-activate before the
                // next request.
                gap_detected = false;
            } else {
                gap_detected = false;
            }
        }
    }

    async fn cleanup_task(
        inner: Arc<NetworkSyncerInner<H, C>>,
        bls_service: Option<BlsServiceHandle>,
        sf_service: Option<SailfishServiceHandle>,
    ) -> Option<()> {
        let cleanup_interval = Duration::from_secs(10);
        loop {
            select! {
                _sleep = sleep(cleanup_interval) => {
                    inner.syncer.cleanup().await;
                    let gc_round = inner.dag_state.gc_round();
                    inner.gc_round.store(gc_round, Ordering::Relaxed);

                    // Notify BLS service to clean up old aggregator state.
                    if let Some(ref bls) = bls_service {
                        bls.send(BlsServiceMessage::Cleanup(gc_round));
                    }

                    // Notify Sailfish service to clean up old aggregator state.
                    if let Some(ref sf) = sf_service {
                        sf.send(SailfishServiceMessage::Cleanup(gc_round));
                    }

                    // Evict stale entries from CordialKnowledge
                    // using per-authority eviction rounds.
                    let eviction_rounds = inner.dag_state.evicted_rounds();
                    if eviction_rounds.iter().any(|&r| r > 0) {
                        inner.cordial_knowledge.send(
                            CordialKnowledgeMessage::EvictBelow(eviction_rounds),
                        );
                    }
                }
                _stopped = inner.stopped() => {
                    return None;
                }
            }
        }
    }

    pub async fn await_completion(self) -> Result<(), JoinError> {
        self.main_task.await
    }
}

impl<H: BlockHandler + 'static, C: CommitObserver + 'static> NetworkSyncerInner<H, C> {
    // Returns None either if channel is closed or NetworkSyncerInner receives stop
    // signal
    async fn recv_or_stopped<T>(&self, channel: &mut mpsc::Receiver<T>) -> Option<T> {
        select! {
            stopped = self.stop.send(()) => {
                assert!(stopped.is_err());
                None
            }
            data = channel.recv() => {
                data
            }
        }
    }

    async fn stopped(&self) {
        let _ = self.stop.send(()).await;
    }
}

impl SyncerSignals for NetworkSyncSignals {
    fn new_block_ready(&mut self) {
        self.block_ready_notify.notify_waiters();
    }

    fn proposal_round_advanced(&mut self, _round: RoundNumber) {
        self.proposal_round_notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        crypto::{self, SignatureBytes, TransactionsCommitment},
        encoder::ShardEncoder,
        types::{BaseTransaction, BlockReference, Transaction, TransactionData},
    };

    #[tokio::test]
    async fn proposal_round_signal_notifies_waiters() {
        let block_ready_notify = Arc::new(Notify::new());
        let proposal_round_notify = Arc::new(Notify::new());
        let mut signals = NetworkSyncSignals {
            block_ready_notify,
            proposal_round_notify: proposal_round_notify.clone(),
        };

        let wait = proposal_round_notify.notified();
        signals.proposal_round_advanced(5);
        wait.await;
    }

    #[test]
    fn starfish_rbc_initial_payload_is_commitment_checked() {
        let committee = Committee::new_test(vec![1; 4]);
        let transactions = vec![BaseTransaction::Share(Transaction::new(vec![7; 64]))];
        let mut commitment_encoder =
            ReedSolomonEncoder::new(2, 4, 2).expect("encoder should be created");
        let encoded = commitment_encoder.encode_transactions(
            &transactions,
            committee.info_length(),
            committee.len() - committee.info_length(),
        );
        let (commitment, _) = TransactionsCommitment::new_from_encoded_transactions(&encoded, 1);
        let canonical = RbcCanonicalHeader::try_new(
            0,
            1,
            vec![
                BlockReference::new_test(0, 0),
                BlockReference::new_test(1, 0),
                BlockReference::new_test(2, 0),
            ],
            Vec::new(),
            11,
            commitment,
        )
        .unwrap();
        let payload = Arc::new(TransactionData::new(transactions.clone()));
        let mut verifier = ReedSolomonEncoder::new(2, 4, 2).expect("encoder should be created");
        let verified = verify_starfish_rbc_transaction_payload(
            &canonical,
            payload,
            &committee,
            1,
            0,
            &mut verifier,
            BlockAuthenticationScheme::MacVector,
            &[],
        )
        .unwrap();
        assert_eq!(verified.block_reference, canonical.reference());
        assert_eq!(verified.transaction_data.transactions(), &transactions);
        assert_eq!(verified.shard_data.shard_index(), 1);

        let tampered = Arc::new(TransactionData::new(vec![BaseTransaction::Share(
            Transaction::new(vec![8; 64]),
        )]));
        assert!(
            verify_starfish_rbc_transaction_payload(
                &canonical,
                tampered,
                &committee,
                1,
                0,
                &mut verifier,
                BlockAuthenticationScheme::MacVector,
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn block_filter_allows_exactly_one_tag_to_full_mac_upgrade() {
        let filter = FilterForBlocks::new();
        let digest = BlockReference::new_test(1, 7).digest;

        assert_eq!(
            filter.needed_headers(&[(digest, false), (digest, true), (digest, true)]),
            vec![true, true, false]
        );
        assert_eq!(
            filter.insert_and_report_useful(&[(digest, false)]),
            vec![true]
        );
        assert_eq!(filter.needed_headers(&[(digest, false)]), vec![false]);
        assert_eq!(filter.needed_headers(&[(digest, true)]), vec![true]);
        assert_eq!(
            filter.insert_and_report_useful(&[(digest, true), (digest, true)]),
            vec![true, false]
        );
        assert_eq!(filter.needed_headers(&[(digest, true)]), vec![false]);
        assert_eq!(filter.contains_full_mac_batch(&[digest]), vec![true]);
    }

    #[test]
    fn full_mac_vectors_require_direct_author_block_streaming() {
        let committee = Committee::new_for_benchmarks(4);
        let keyrings = crypto::mac_keyrings_for_test(committee.len());
        let mut full = VerifiedBlock::new(
            1,
            1,
            Vec::new(),
            Vec::new(),
            0,
            SignatureBytes::default(),
            Vec::new(),
            None,
            None,
            None,
            None,
        );
        let tags = keyrings[1]
            .iter()
            .enumerate()
            .map(|(recipient, key)| key.compute_tag(1, recipient as AuthorityIndex, &full.digest()))
            .collect();
        full.header.authentication = BlockAuthentication::MacVector(tags);

        assert!(
            verify_mac_transport(
                &full,
                BlockAuthenticationScheme::MacVector,
                1,
                DataSource::BlockBundleStreaming,
            )
            .is_ok()
        );
        assert!(
            verify_mac_transport(
                &full,
                BlockAuthenticationScheme::MacVector,
                1,
                DataSource::BlockBundleStreamingHeader,
            )
            .is_ok()
        );
        assert!(
            verify_mac_transport(
                &full,
                BlockAuthenticationScheme::MacVector,
                2,
                DataSource::BlockBundleStreaming,
            )
            .is_err()
        );
        assert!(
            verify_mac_transport(
                &full,
                BlockAuthenticationScheme::MacVector,
                1,
                DataSource::BlockHeaderRequest,
            )
            .is_err()
        );

        let tagged = full.with_recipient_mac(0).unwrap();
        assert!(
            verify_mac_transport(
                &tagged,
                BlockAuthenticationScheme::MacVector,
                2,
                DataSource::BlockBundleStreaming,
            )
            .is_ok()
        );
        assert!(
            verify_mac_transport(
                &tagged,
                BlockAuthenticationScheme::MacVector,
                1,
                DataSource::BlockHeaderRequest,
            )
            .is_ok()
        );
        assert!(
            verify_mac_transport(
                &tagged,
                BlockAuthenticationScheme::MacVector,
                1,
                DataSource::BlockBundleStreaming,
            )
            .is_err()
        );

        let round_gap_blocks = prepare_forwarded_blocks_for_peer(
            BlockAuthenticationScheme::MacVector,
            ConsensusProtocol::Bluestreak,
            0,
            vec![Data::new(full)],
        );
        assert_eq!(round_gap_blocks.len(), 1);
        assert!(matches!(
            round_gap_blocks[0].authentication(),
            BlockAuthentication::MacTag(_)
        ));
        assert!(
            verify_mac_transport(
                &round_gap_blocks[0],
                BlockAuthenticationScheme::MacVector,
                2,
                DataSource::RoundGapResponse,
            )
            .is_ok()
        );
    }

    #[test]
    fn acknowledgments_imply_peer_knows_shard_data() {
        let ack_ref = BlockReference::new_test(2, 3);
        let block = Data::new(VerifiedBlock::new(
            0,
            4,
            vec![BlockReference::new_test(0, 3)],
            vec![ack_ref],
            0,
            SignatureBytes::default(),
            Vec::<BaseTransaction>::new(),
            None,
            None,
            None,
            None,
        ));

        let mut ck = ConnectionKnowledge::new(1, 4);
        infer_peer_knowledge_from_received_batch(&mut ck, &[block], &[], &[]);

        assert!(ck.knows_header(&ack_ref));
        assert!(ck.knows_shard(&ack_ref));
    }

    #[test]
    fn missing_parent_retry_waits_and_retries_after_interval() {
        const INTERVAL: Duration = Duration::from_millis(500);

        let missing = BlockReference::new_test(3, 7);
        let now = Instant::now();
        let mut first_seen = AHashMap::new();
        let mut last_requested = AHashMap::new();

        assert!(
            eligible_missing_parent_refs(
                &[missing],
                &mut first_seen,
                &mut last_requested,
                now,
                INTERVAL,
            )
            .is_empty()
        );
        assert_eq!(first_seen.get(&missing), Some(&now));

        let eligible = eligible_missing_parent_refs(
            &[missing],
            &mut first_seen,
            &mut last_requested,
            now + INTERVAL,
            INTERVAL,
        );
        assert_eq!(eligible, vec![missing]);

        last_requested.insert(missing, now + INTERVAL);
        assert!(
            eligible_missing_parent_refs(
                &[missing],
                &mut first_seen,
                &mut last_requested,
                now + INTERVAL + Duration::from_millis(100),
                INTERVAL,
            )
            .is_empty()
        );

        let eligible = eligible_missing_parent_refs(
            &[missing],
            &mut first_seen,
            &mut last_requested,
            now + INTERVAL * 2,
            INTERVAL,
        );
        assert_eq!(eligible, vec![missing]);
    }

    #[test]
    fn missing_parent_retry_prunes_resolved_refs() {
        const INTERVAL: Duration = Duration::from_millis(500);

        let missing = BlockReference::new_test(1, 9);
        let now = Instant::now();
        let mut first_seen = AHashMap::from_iter([(missing, now)]);
        let mut last_requested = AHashMap::from_iter([(missing, now)]);

        assert!(
            eligible_missing_parent_refs(
                &[],
                &mut first_seen,
                &mut last_requested,
                now + INTERVAL,
                INTERVAL,
            )
            .is_empty()
        );
        assert!(first_seen.is_empty());
        assert!(last_requested.is_empty());
    }

    #[test]
    fn random_peer_selection_is_capped() {
        let candidates: Vec<AuthorityIndex> = (0..10).collect();
        let mut rng = StdRng::seed_from_u64(7);
        let selected = select_random_peers(candidates.clone(), 5, &mut rng);
        let unique: AHashSet<_> = selected.iter().copied().collect();

        assert_eq!(selected.len(), 5);
        assert_eq!(unique.len(), selected.len());
        assert!(selected.iter().all(|peer| candidates.contains(peer)));
    }

    #[test]
    fn autonomous_carriers_use_a_distinct_authentication_namespace() {
        let direct = [0x5A; 32];
        let mirror = rbc_dag_shadow_protocol_instance(direct, false);
        let autonomous = rbc_dag_shadow_protocol_instance(direct, true);

        assert_eq!(mirror.as_bytes(), &direct);
        assert_ne!(autonomous, mirror);
        assert_eq!(
            autonomous,
            rbc_dag_shadow_protocol_instance(direct, true),
            "derived autonomous namespace must be deterministic across nodes"
        );
    }
}
