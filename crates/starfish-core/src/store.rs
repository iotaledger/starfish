// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::io;

use crate::{
    dag_state::CommitData,
    data::Data,
    types::{BlockReference, RoundNumber, VerifiedStatementBlock},
};

/// Backend-agnostic storage interface for consensus blocks and commit data.
///
/// Implementations must be thread-safe (`Send + Sync`).
/// Two implementations exist:
/// - `RocksStore` (default) — RocksDB-backed
/// - `TideHunterStore` (feature `tidehunter`) — TideHunter WAL-backed
pub trait Store: Send + Sync + 'static {
    fn store_block(&self, block: Data<VerifiedStatementBlock>) -> io::Result<()>;

    fn get_block(
        &self,
        reference: &BlockReference,
    ) -> io::Result<Option<Data<VerifiedStatementBlock>>>;

    fn get_blocks_by_round(
        &self,
        round: RoundNumber,
    ) -> io::Result<Vec<Data<VerifiedStatementBlock>>>;

    fn store_commits(&self, committed_sub_dags: Vec<CommitData>) -> io::Result<()>;

    fn get_commit(&self, reference: &BlockReference) -> io::Result<Option<CommitData>>;

    /// Flush buffered writes to the storage backend (non-blocking).
    fn flush(&self) -> io::Result<()>;

    /// Flush any pending batched operations.
    fn flush_pending_batches(&self) -> io::Result<()>;

    /// Sync data to disk (blocking, ensures durability).
    fn sync(&self) -> io::Result<()>;
}
