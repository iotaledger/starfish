// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{io, path::Path, sync::Arc};

use bytes::Bytes;

use tidehunter::{
    config::Config,
    db::Db,
    key_shape::{KeyShapeBuilder, KeySpace, KeyType},
    metrics::Metrics,
};

use crate::{
    dag_state::CommitData,
    data::Data,
    store::Store,
    types::{BlockReference, RoundNumber, VerifiedBlock},
};

/// Key = round(8B BE) ++ authority(8B BE) ++ digest(32B) = 48 bytes.
const KEY_SIZE: usize = 48;

/// Prefix length for `PrefixUniform` key type.
/// Top 3 bytes of big-endian round → one shard per ~256 rounds, covers rounds
/// 0..16M.
const PREFIX_LEN: usize = 3;

/// Number of mutexes per key space for concurrency control. Must be power of 2.
const MUTEXES: usize = 64;

pub struct TideHunterStore {
    db: Arc<Db>,
    ks_blocks: KeySpace,
    ks_commits: KeySpace,
}

impl TideHunterStore {
    /// Encode a [`BlockReference`] as a fixed 48-byte big-endian key.
    fn encode_key(reference: &BlockReference) -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        key[0..8].copy_from_slice(&reference.round.to_be_bytes());
        key[8..16].copy_from_slice(&reference.authority.to_be_bytes());
        key[16..48].copy_from_slice(reference.digest.as_ref());
        key
    }

    /// Lower bound key (inclusive) for iterating all blocks at `round`.
    fn round_lower_bound(round: RoundNumber) -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        key[0..8].copy_from_slice(&round.to_be_bytes());
        key
    }

    /// Upper bound key (exclusive) for iterating all blocks at `round`.
    fn round_upper_bound(round: RoundNumber) -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        key[0..8].copy_from_slice(&(round + 1).to_be_bytes());
        key
    }

    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut builder = KeyShapeBuilder::new();
        let ks_blocks = builder.add_key_space(
            "blocks",
            KEY_SIZE,
            MUTEXES,
            KeyType::prefix_uniform(PREFIX_LEN, 0),
        );
        let ks_commits = builder.add_key_space(
            "commits",
            KEY_SIZE,
            MUTEXES,
            KeyType::prefix_uniform(PREFIX_LEN, 0),
        );
        let key_shape = builder.build();

        let config = Arc::new(Config {
            direct_io: true,
            ..Config::default()
        });

        let metrics = Metrics::new();

        std::fs::create_dir_all(path.as_ref())?;

        let db = Db::open(path.as_ref(), key_shape, config, metrics)
            .map_err(|e| io::Error::other(format!("TideHunter open: {e:?}")))?;

        Ok(Self {
            db,
            ks_blocks,
            ks_commits,
        })
    }
}

impl Store for TideHunterStore {
    fn store_block(&self, block: Data<VerifiedBlock>) -> io::Result<()> {
        let key = Self::encode_key(block.reference());
        // bytes::Bytes → minibytes::Bytes is zero-copy via BytesOwner impl.
        let value = block.serialized_bytes().clone();
        self.db
            .insert(self.ks_blocks, key, value)
            .map_err(|e| io::Error::other(format!("TideHunter store block: {e:?}")))
    }

    fn get_block(&self, reference: &BlockReference) -> io::Result<Option<Data<VerifiedBlock>>> {
        let key = Self::encode_key(reference);
        match self
            .db
            .get(self.ks_blocks, &key)
            .map_err(|e| io::Error::other(format!("TideHunter get block: {e:?}")))?
        {
            Some(value) => Data::from_bytes(Bytes::from(value.to_vec()))
                .map(Some)
                .map_err(io::Error::other),
            None => Ok(None),
        }
    }

    fn get_blocks_by_round(&self, round: RoundNumber) -> io::Result<Vec<Data<VerifiedBlock>>> {
        let mut iter = self.db.iterator(self.ks_blocks);
        iter.set_lower_bound(Self::round_lower_bound(round).to_vec());
        iter.set_upper_bound(Self::round_upper_bound(round).to_vec());

        let mut blocks = Vec::new();
        for result in iter {
            let (_key, value) =
                result.map_err(|e| io::Error::other(format!("TideHunter iter: {e:?}")))?;
            let block = Data::from_bytes(Bytes::from(value.to_vec())).map_err(io::Error::other)?;
            blocks.push(block);
        }
        Ok(blocks)
    }

    fn store_commits(&self, committed_sub_dags: Vec<CommitData>) -> io::Result<()> {
        let mut batch = self.db.write_batch();
        for commit_data in committed_sub_dags {
            let key = Self::encode_key(&commit_data.leader);
            let value = bincode::serialize(&commit_data).map_err(io::Error::other)?;
            batch.write(self.ks_commits, key.to_vec(), value);
        }
        batch
            .commit()
            .map_err(|e| io::Error::other(format!("TideHunter commit batch: {e:?}")))
    }

    fn get_commit(&self, reference: &BlockReference) -> io::Result<Option<CommitData>> {
        let key = Self::encode_key(reference);
        match self
            .db
            .get(self.ks_commits, &key)
            .map_err(|e| io::Error::other(format!("TideHunter get commit: {e:?}")))?
        {
            Some(value) => {
                let commit_data: CommitData =
                    bincode::deserialize(&value).map_err(io::Error::other)?;
                Ok(Some(commit_data))
            }
            None => Ok(None),
        }
    }

    fn flush(&self) -> io::Result<()> {
        // TideHunter's WAL is the permanent storage — no separate flush needed.
        Ok(())
    }

    fn flush_pending_batches(&self) -> io::Result<()> {
        // No external batching layer — writes go directly to TideHunter's WAL.
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        // Writes are durable after insert()/commit() returns — WAL is the source of
        // truth.
        Ok(())
    }
}
