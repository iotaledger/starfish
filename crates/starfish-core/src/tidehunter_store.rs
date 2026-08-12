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
    store::{RbcDagFrontierReceipt, Store, validate_rbc_dag_frontier_commit_batch},
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
const LATEST_RBC_DAG_FRONTIER_RECEIPT_KEY: [u8; KEY_SIZE] = [0; KEY_SIZE];

pub struct TideHunterStore {
    db: Arc<Db>,
    ks_blocks: KeySpace, // legacy composite blob (read-only for migration)
    ks_headers: KeySpace,
    ks_tx_data: KeySpace,
    ks_shard_data: KeySpace,
    ks_commits: KeySpace,
    ks_dual_dag_clean: KeySpace,
    ks_rbc_dag_frontier_receipt: KeySpace,
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
        let ks_rbc_dag_frontier_receipt = Self::add_ks(&mut builder, "rbc_dag_frontier_receipt");
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
            ks_rbc_dag_frontier_receipt,
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

    fn store_commits_with_rbc_dag_receipt(
        &self,
        committed_sub_dags: Vec<CommitData>,
        receipt: RbcDagFrontierReceipt,
    ) -> io::Result<()> {
        validate_rbc_dag_frontier_commit_batch(&committed_sub_dags, &receipt)?;
        let receipt_bytes = receipt.to_bytes()?;

        let mut batch = self.db.write_batch();
        if committed_sub_dags.is_empty() {
            batch.delete(
                self.ks_commits,
                Self::encode_key(&receipt.carrier_anchor).to_vec(),
            );
        } else {
            let commit_data = &committed_sub_dags[0];
            let key = Self::encode_key(&commit_data.leader);
            let value = bincode::serialize(&commit_data).map_err(io::Error::other)?;
            batch.write(self.ks_commits, key.to_vec(), value);
        }
        batch.write(
            self.ks_rbc_dag_frontier_receipt,
            LATEST_RBC_DAG_FRONTIER_RECEIPT_KEY.to_vec(),
            receipt_bytes,
        );
        batch.commit().map_err(|e| {
            io::Error::other(format!("TideHunter RBC-DAG commit/receipt batch: {e:?}"))
        })
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

    fn read_latest_rbc_dag_frontier_receipt(&self) -> io::Result<Option<RbcDagFrontierReceipt>> {
        match self
            .db
            .get(
                self.ks_rbc_dag_frontier_receipt,
                &LATEST_RBC_DAG_FRONTIER_RECEIPT_KEY,
            )
            .map_err(|e| io::Error::other(format!("TideHunter get receipt: {e:?}")))?
        {
            Some(bytes) => RbcDagFrontierReceipt::from_bytes(&bytes).map(Some),
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
    use tempfile::TempDir;

    use super::TideHunterStore;
    use crate::{
        dag_state::CommitData,
        store::{RbcDagFrontierReceipt, Store},
        types::{BlockReference, MAX_COMMITTEE_SIZE},
    };

    fn commit(leader: BlockReference, committed_rounds: Vec<u32>) -> CommitData {
        CommitData {
            leader,
            sub_dag: vec![BlockReference::new_test(1, leader.round)],
            committed_rounds,
        }
    }

    fn assert_commit(store: &impl Store, expected: &CommitData) {
        let actual = store
            .get_commit(&expected.leader)
            .expect("commit read should succeed")
            .expect("commit should exist");
        assert_eq!(actual.leader, expected.leader);
        assert_eq!(actual.sub_dag, expected.sub_dag);
        assert_eq!(actual.committed_rounds, expected.committed_rounds);
    }

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

    #[test]
    fn rbc_dag_receipt_and_commits_are_atomic_and_latest_is_a_point_value() {
        let temp_dir = TempDir::new().unwrap();
        let store = TideHunterStore::open(temp_dir.path()).unwrap();

        let legacy_leader = BlockReference::new_test(2, 253);
        let legacy_commit = commit(legacy_leader, vec![253; 4]);
        store.store_commits(vec![legacy_commit.clone()]).unwrap();
        assert_commit(&store, &legacy_commit);
        assert!(
            store
                .read_latest_rbc_dag_frontier_receipt()
                .unwrap()
                .is_none()
        );

        // A control-only frontier has no new application commits, but its
        // durable cursor must still advance.
        let first_anchor = BlockReference::new_test(7, 255);
        let first_receipt = RbcDagFrontierReceipt {
            carrier_anchor: first_anchor,
            output_sequence: 255,
            committed_rounds: vec![250, 251, 252, 253],
        };
        let stale_first_commit = commit(first_anchor, first_receipt.committed_rounds.clone());
        store.store_commits(vec![stale_first_commit]).unwrap();
        assert!(store.get_commit(&first_anchor).unwrap().is_some());
        store
            .store_commits_with_rbc_dag_receipt(Vec::new(), first_receipt.clone())
            .unwrap();
        assert_eq!(
            store.read_latest_rbc_dag_frontier_receipt().unwrap(),
            Some(first_receipt)
        );
        assert!(store.get_commit(&first_anchor).unwrap().is_none());

        // The exact application commit is stored under the consensus carrier
        // anchor so Core can reconstruct the compact receipt's application
        // references after restart.
        let second_anchor = BlockReference::new_test(7, 256);
        let application_commit = commit(second_anchor, vec![255, 256, 255, 256]);
        let second_receipt = RbcDagFrontierReceipt {
            carrier_anchor: second_anchor,
            output_sequence: 256,
            committed_rounds: vec![255, 256, 255, 256],
        };
        store
            .store_commits_with_rbc_dag_receipt(
                vec![application_commit.clone()],
                second_receipt.clone(),
            )
            .unwrap();
        assert_commit(&store, &application_commit);
        assert_eq!(
            store.read_latest_rbc_dag_frontier_receipt().unwrap(),
            Some(second_receipt.clone())
        );

        // Mismatched/multiple application commits are rejected before either
        // commit data or the latest receipt can change.
        let mismatched = commit(BlockReference::new_test(2, 254), vec![255, 256, 255, 256]);
        let mismatched_watermarks = commit(second_anchor, vec![1; 4]);
        for invalid in [
            vec![mismatched],
            vec![mismatched_watermarks],
            vec![application_commit.clone(), application_commit.clone()],
        ] {
            let error = store
                .store_commits_with_rbc_dag_receipt(invalid, second_receipt.clone())
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert_eq!(
                store.read_latest_rbc_dag_frontier_receipt().unwrap(),
                Some(second_receipt.clone())
            );
        }

        // Reusing the exact anchor for a control-only marker atomically
        // removes stale application CommitData, preserving absence semantics.
        let control_receipt = RbcDagFrontierReceipt {
            carrier_anchor: second_anchor,
            output_sequence: 257,
            committed_rounds: second_receipt.committed_rounds.clone(),
        };
        store
            .store_commits_with_rbc_dag_receipt(Vec::new(), control_receipt.clone())
            .unwrap();
        assert!(store.get_commit(&second_anchor).unwrap().is_none());
        assert_eq!(
            store.read_latest_rbc_dag_frontier_receipt().unwrap(),
            Some(control_receipt.clone())
        );

        // Receipt validation happens before the batch is submitted, so an
        // invalid vector cannot partially write its application commit or
        // replace the last valid cursor.
        let rejected_leader = BlockReference::new_test(3, 257);
        let rejected = commit(rejected_leader, vec![257; 4]);
        for committed_rounds in [Vec::new(), vec![0; usize::from(MAX_COMMITTEE_SIZE) + 1]] {
            let invalid = RbcDagFrontierReceipt {
                carrier_anchor: BlockReference::new_test(7, 257),
                output_sequence: 258,
                committed_rounds,
            };
            let error = store
                .store_commits_with_rbc_dag_receipt(vec![rejected.clone()], invalid)
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
        assert!(store.get_commit(&rejected_leader).unwrap().is_none());
        assert_eq!(
            store.read_latest_rbc_dag_frontier_receipt().unwrap(),
            Some(control_receipt.clone())
        );

        drop(store);
        let reopened = TideHunterStore::open(temp_dir.path()).unwrap();
        assert_commit(&reopened, &legacy_commit);
        assert!(reopened.get_commit(&second_anchor).unwrap().is_none());
        assert_eq!(
            reopened.read_latest_rbc_dag_frontier_receipt().unwrap(),
            Some(control_receipt)
        );
    }
}
