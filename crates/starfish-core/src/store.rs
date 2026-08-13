// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::io;

use crate::{
    dag_state::CommitData,
    data::Data,
    types::{BlockReference, ProvableShard, RoundNumber, VerifiedBlock},
};

/// Backend-agnostic storage interface for consensus blocks and commit data.
///
/// Implementations must be thread-safe (`Send + Sync`).
/// Two implementations exist:
/// - `RocksStore` (default) — RocksDB-backed
/// - `TideHunterStore` (feature `tidehunter`) — TideHunter WAL-backed
pub trait Store: Send + Sync + 'static {
    fn store_block(&self, block: Data<VerifiedBlock>) -> io::Result<()>;

    fn get_block(&self, reference: &BlockReference) -> io::Result<Option<Data<VerifiedBlock>>>;

    fn get_blocks(
        &self,
        references: &[BlockReference],
    ) -> io::Result<Vec<Option<Data<VerifiedBlock>>>> {
        references
            .iter()
            .map(|reference| self.get_block(reference))
            .collect()
    }

    fn get_blocks_by_round(&self, round: RoundNumber) -> io::Result<Vec<Data<VerifiedBlock>>>;

    fn store_commits(&self, committed_sub_dags: Vec<CommitData>) -> io::Result<()>;

    fn get_commit(&self, reference: &BlockReference) -> io::Result<Option<CommitData>>;

    // -- Component-level writes (pre-serialized) --
    // Accept raw bincode bytes produced off the core thread by
    // `VerifiedBlock::preserialize()` or shard reconstructor workers.

    fn store_header_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()>;

    fn store_tx_data_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()>;

    fn store_shard_data_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()>;

    fn get_shard_data(&self, reference: &BlockReference) -> io::Result<Option<ProvableShard>>;

    fn get_shard_data_batch(
        &self,
        references: &[BlockReference],
    ) -> io::Result<Vec<Option<ProvableShard>>> {
        references
            .iter()
            .map(|reference| self.get_shard_data(reference))
            .collect()
    }

    /// Return the most recently stored commit (highest leader round).
    fn read_last_commit(&self) -> io::Result<Option<CommitData>>;

    /// Return all blocks from `from_round` onward (inclusive), across all
    /// authorities.
    fn scan_blocks_from_round(
        &self,
        from_round: RoundNumber,
    ) -> io::Result<Vec<Data<VerifiedBlock>>>;

    /// Persist a batch of dual-DAG clean block references.
    fn store_dual_dag_clean_refs(&self, refs: &[BlockReference]) -> io::Result<()>;

    /// Return all persisted dual-DAG clean block references from
    /// `from_round` onward (inclusive).
    fn scan_dual_dag_clean_refs_from_round(
        &self,
        from_round: RoundNumber,
    ) -> io::Result<Vec<BlockReference>>;
}
