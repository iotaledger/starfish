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
    types::{
        BlockHeader, BlockReference, ProvableShard, RoundNumber, TransactionData, VerifiedBlock,
    },
};

/// Key = round(4B BE) ++ authority(2B BE) ++ digest(32B) = 38 bytes.
const KEY_SIZE: usize = 38;

/// Prefix length for `PrefixUniform` key type.
/// Top 3 bytes of big-endian round → one shard per ~256 rounds, covers rounds
/// 0..16M.
const PREFIX_LEN: usize = 3;

/// Number of mutexes per key space for concurrency control. Must be power of 2.
const MUTEXES: usize = 64;

pub struct TideHunterStore {
    db: Arc<Db>,
    ks_blocks: KeySpace, // legacy composite blob (read-only for migration)
    ks_headers: KeySpace,
    ks_tx_data: KeySpace,
    ks_shard_data: KeySpace,
    ks_commits: KeySpace,
    ks_dual_dag_clean: KeySpace,
}

impl TideHunterStore {
    /// Encode a [`BlockReference`] as a fixed 38-byte big-endian key.
    fn encode_key(reference: &BlockReference) -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        key[0..4].copy_from_slice(&reference.round.to_be_bytes());
        key[4..6].copy_from_slice(&reference.authority.to_be_bytes());
        key[6..38].copy_from_slice(reference.digest.as_ref());
        key
    }

    /// Lower bound key (inclusive) for iterating all blocks at `round`.
    fn round_lower_bound(round: RoundNumber) -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        key[0..4].copy_from_slice(&round.to_be_bytes());
        key
    }

    /// Upper bound key (exclusive) for iterating all blocks at `round`.
    fn round_upper_bound(round: RoundNumber) -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        key[0..4].copy_from_slice(&(round + 1).to_be_bytes());
        key
    }

    fn add_ks(builder: &mut KeyShapeBuilder, name: &str) -> KeySpace {
        builder.add_key_space(
            name,
            KEY_SIZE,
            MUTEXES,
            KeyType::prefix_uniform(PREFIX_LEN, 0),
        )
    }

    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut builder = KeyShapeBuilder::new();
        let ks_blocks = Self::add_ks(&mut builder, "blocks");
        let ks_headers = Self::add_ks(&mut builder, "headers");
        let ks_tx_data = Self::add_ks(&mut builder, "tx_data");
        let ks_shard_data = Self::add_ks(&mut builder, "shard_data");
        let ks_commits = Self::add_ks(&mut builder, "commits");
        let ks_dual_dag_clean = Self::add_ks(&mut builder, "sailfish_certified");
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
            ks_headers,
            ks_tx_data,
            ks_shard_data,
            ks_commits,
            ks_dual_dag_clean,
        })
    }

    /// Point-read and deserialize an optional value from a key space.
    fn point_read<T: serde::de::DeserializeOwned>(
        &self,
        ks: KeySpace,
        key: &[u8; KEY_SIZE],
    ) -> io::Result<Option<T>> {
        match self
            .db
            .get(ks, key)
            .map_err(|e| io::Error::other(format!("TideHunter get: {e:?}")))?
        {
            Some(value) => bincode::deserialize(&value)
                .map(Some)
                .map_err(io::Error::other),
            None => Ok(None),
        }
    }

    /// Assemble a VerifiedBlock from component key spaces. Returns None if
    /// header not found.
    fn assemble_from_components(
        &self,
        key: &[u8; KEY_SIZE],
    ) -> io::Result<Option<Data<VerifiedBlock>>> {
        let header: Option<BlockHeader> = self.point_read(self.ks_headers, key)?;
        let Some(header) = header else {
            return Ok(None);
        };
        let tx: Option<TransactionData> = self.point_read(self.ks_tx_data, key)?;
        Ok(Some(Data::new(VerifiedBlock::from_parts(header, tx))))
    }
}

impl Store for TideHunterStore {
    fn store_block(&self, block: Data<VerifiedBlock>) -> io::Result<()> {
        let key = Self::encode_key(block.reference());

        // All blocks must be pre-serialized before reaching the store.
        let header_bytes = block
            .serialized_header_bytes()
            .expect("header must be preserialized before store")
            .to_vec();

        let mut batch = self.db.write_batch();
        batch.write(self.ks_headers, key.to_vec(), header_bytes);

        if let Some(_tx) = block.transaction_data() {
            let tx_bytes = block
                .serialized_tx_data_bytes()
                .expect("tx_data must be preserialized before store")
                .to_vec();
            batch.write(self.ks_tx_data, key.to_vec(), tx_bytes);
        }
        batch
            .commit()
            .map_err(|e| io::Error::other(format!("TideHunter store block: {e:?}")))
    }

    fn get_block(&self, reference: &BlockReference) -> io::Result<Option<Data<VerifiedBlock>>> {
        let key = Self::encode_key(reference);

        // Try component key spaces first.
        if let Some(block) = self.assemble_from_components(&key)? {
            return Ok(Some(block));
        }

        // Legacy fallback: ks_blocks.
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
        let mut blocks = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // 1. Iterate component ks_headers.
        let lower = Self::round_lower_bound(round);
        let upper = Self::round_upper_bound(round);

        let mut iter = self.db.iterator(self.ks_headers);
        iter.set_lower_bound(lower.to_vec());
        iter.set_upper_bound(upper.to_vec());

        for result in iter {
            let (key_bytes, header_bytes) =
                result.map_err(|e| io::Error::other(format!("TideHunter iter: {e:?}")))?;
            let header: BlockHeader =
                bincode::deserialize(&header_bytes).map_err(io::Error::other)?;

            let key: [u8; KEY_SIZE] = key_bytes[..KEY_SIZE]
                .try_into()
                .map_err(|_| io::Error::other("invalid key length"))?;
            let tx: Option<TransactionData> = self.point_read(self.ks_tx_data, &key)?;

            blocks.push(Data::new(VerifiedBlock::from_parts(header, tx)));
            seen.insert(key);
        }

        // 2. Legacy fallback: ks_blocks for any not yet found.
        let mut iter = self.db.iterator(self.ks_blocks);
        iter.set_lower_bound(lower.to_vec());
        iter.set_upper_bound(upper.to_vec());

        for result in iter {
            let (key_bytes, value) =
                result.map_err(|e| io::Error::other(format!("TideHunter iter: {e:?}")))?;
            let key: [u8; KEY_SIZE] = key_bytes[..KEY_SIZE]
                .try_into()
                .map_err(|_| io::Error::other("invalid key length"))?;
            if !seen.contains(&key) {
                let block =
                    Data::from_bytes(Bytes::from(value.to_vec())).map_err(io::Error::other)?;
                blocks.push(block);
            }
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

    fn store_header_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()> {
        let key = Self::encode_key(reference);
        self.db
            .insert(self.ks_headers, key, bytes.to_vec())
            .map_err(|e| io::Error::other(format!("TideHunter store header: {e:?}")))
    }

    fn store_tx_data_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()> {
        let key = Self::encode_key(reference);
        self.db
            .insert(self.ks_tx_data, key, bytes.to_vec())
            .map_err(|e| io::Error::other(format!("TideHunter store tx_data: {e:?}")))
    }

    fn store_shard_data_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()> {
        let key = Self::encode_key(reference);
        self.db
            .insert(self.ks_shard_data, key, bytes.to_vec())
            .map_err(|e| io::Error::other(format!("TideHunter store shard_data: {e:?}")))
    }

    fn read_last_commit(&self) -> io::Result<Option<CommitData>> {
        // Forward-scan all commits, keep the one with the highest leader round.
        let mut best: Option<CommitData> = None;

        let iter = self.db.iterator(self.ks_commits);
        for result in iter {
            let (_key_bytes, value) =
                result.map_err(|e| io::Error::other(format!("TideHunter iter: {e:?}")))?;
            let commit: CommitData = bincode::deserialize(&value).map_err(io::Error::other)?;
            if best
                .as_ref()
                .map(|b| commit.leader.round > b.leader.round)
                .unwrap_or(true)
            {
                best = Some(commit);
            }
        }

        Ok(best)
    }

    fn scan_blocks_from_round(
        &self,
        from_round: RoundNumber,
    ) -> io::Result<Vec<Data<VerifiedBlock>>> {
        let mut blocks = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let lower = Self::round_lower_bound(from_round);

        // 1. Iterate component ks_headers from from_round onward.
        let mut iter = self.db.iterator(self.ks_headers);
        iter.set_lower_bound(lower.to_vec());

        for result in iter {
            let (key_bytes, header_bytes) =
                result.map_err(|e| io::Error::other(format!("TideHunter iter: {e:?}")))?;
            let header: BlockHeader =
                bincode::deserialize(&header_bytes).map_err(io::Error::other)?;

            let key: [u8; KEY_SIZE] = key_bytes[..KEY_SIZE]
                .try_into()
                .map_err(|_| io::Error::other("invalid key length"))?;
            let tx: Option<TransactionData> = self.point_read(self.ks_tx_data, &key)?;

            blocks.push(Data::new(VerifiedBlock::from_parts(header, tx)));
            seen.insert(key);
        }

        // 2. Legacy fallback: ks_blocks.
        let mut iter = self.db.iterator(self.ks_blocks);
        iter.set_lower_bound(lower.to_vec());

        for result in iter {
            let (key_bytes, value) =
                result.map_err(|e| io::Error::other(format!("TideHunter iter: {e:?}")))?;
            let key: [u8; KEY_SIZE] = key_bytes[..KEY_SIZE]
                .try_into()
                .map_err(|_| io::Error::other("invalid key length"))?;
            if !seen.contains(&key) {
                let block =
                    Data::from_bytes(Bytes::from(value.to_vec())).map_err(io::Error::other)?;
                blocks.push(block);
            }
        }

        Ok(blocks)
    }

    fn get_shard_data(&self, reference: &BlockReference) -> io::Result<Option<ProvableShard>> {
        let key = Self::encode_key(reference);
        self.point_read(self.ks_shard_data, &key)
    }

    fn store_dual_dag_clean_refs(&self, refs: &[BlockReference]) -> io::Result<()> {
        if refs.is_empty() {
            return Ok(());
        }
        let mut batch = self.db.write_batch();
        for reference in refs {
            let key = Self::encode_key(reference);
            batch.write(self.ks_dual_dag_clean, key.to_vec(), Vec::new());
        }
        batch
            .commit()
            .map_err(|e| io::Error::other(format!("TideHunter store clean refs: {e:?}")))
    }

    fn scan_dual_dag_clean_refs_from_round(
        &self,
        from_round: RoundNumber,
    ) -> io::Result<Vec<BlockReference>> {
        let mut refs = Vec::new();
        let lower = Self::round_lower_bound(from_round);

        let mut iter = self.db.iterator(self.ks_dual_dag_clean);
        iter.set_lower_bound(lower.to_vec());

        for result in iter {
            let (key_bytes, _value) =
                result.map_err(|e| io::Error::other(format!("TideHunter iter: {e:?}")))?;
            let key: [u8; KEY_SIZE] = key_bytes[..KEY_SIZE]
                .try_into()
                .map_err(|_| io::Error::other("invalid key length"))?;

            let mut digest = [0u8; 32];
            digest.copy_from_slice(&key[6..38]);
            refs.push(BlockReference {
                round: u32::from_be_bytes(key[0..4].try_into().expect("slice length checked")),
                authority: u16::from_be_bytes(key[4..6].try_into().expect("slice length checked")),
                digest: digest.into(),
            });
        }

        Ok(refs)
    }
}

#[cfg(test)]
mod tests {
    use super::TideHunterStore;
    use crate::types::BlockReference;

    #[test]
    fn encode_key_preserves_u16_authority() {
        let reference = BlockReference::new_test(513, 42);
        let key = TideHunterStore::encode_key(&reference);

        assert_eq!(key.len(), 38);
        assert_eq!(&key[0..4], &42u32.to_be_bytes());
        assert_eq!(&key[4..6], &513u16.to_be_bytes());
    }

    #[test]
    fn encode_key_distinguishes_255_from_256() {
        let low = BlockReference::new_test(255, 7);
        let high = BlockReference::new_test(256, 7);

        let low_key = TideHunterStore::encode_key(&low);
        let high_key = TideHunterStore::encode_key(&high);

        assert_ne!(low_key, high_key);
        assert_eq!(&low_key[4..6], &255u16.to_be_bytes());
        assert_eq!(&high_key[4..6], &256u16.to_be_bytes());
    }
}
