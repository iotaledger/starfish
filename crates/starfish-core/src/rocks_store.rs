// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{io, path::Path, sync::Arc};

use ahash::AHashSet;

use bincode::{deserialize, serialize};
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, DBCompactionStyle, Options, ReadOptions,
    WriteOptions,
};

use crate::{
    crypto::BlockDigest,
    dag_state::CommitData,
    data::Data,
    store::{RbcDagFrontierReceipt, Store, validate_rbc_dag_frontier_commit_batch},
    types::{
        BlockHeader, BlockReference, ProvableShard, RoundNumber, TransactionData, VerifiedBlock,
    },
};

// Column families
const CF_BLOCKS: &str = "blocks"; // legacy composite blob (read-only for migration)
const CF_HEADERS: &str = "headers";
const CF_TX_DATA: &str = "tx_data";
const CF_SHARD_DATA: &str = "shard_data";
const CF_COMMITS: &str = "commits";
const CF_DUAL_DAG_CLEAN: &str = "sailfish_certified";
const CF_RBC_DAG_FRONTIER_RECEIPT: &str = "rbc_dag_frontier_receipt";
const LATEST_RBC_DAG_FRONTIER_RECEIPT_KEY: &[u8] = b"latest";

pub struct RocksStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
}

impl RocksStore {
    fn get_read_opts() -> ReadOptions {
        ReadOptions::default()
    }

    /// Creates block-based table options with bloom filter and LRU cache.
    fn block_options(block_cache_size_mb: usize, block_size_bytes: usize) -> BlockBasedOptions {
        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_size(block_size_bytes);
        block_opts.set_block_cache(&Cache::new_lru_cache(block_cache_size_mb << 20));
        // 10-bit bloom filter = ~1% false positive rate
        block_opts.set_bloom_filter(10.0, false);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        block_opts
    }

    /// Default per-CF options for metadata column families (commits, blocks).
    fn metadata_cf_options() -> Options {
        let mut opts = Options::default();
        opts.set_target_file_size_base(128 * 1024 * 1024);
        opts.set_write_buffer_size(256 * 1024 * 1024);
        opts.set_max_write_buffer_number(6);

        // Level compaction with aligned L0 triggers.
        let l0_trigger = 4;
        opts.set_level_zero_file_num_compaction_trigger(l0_trigger);
        opts.set_level_zero_slowdown_writes_trigger(l0_trigger * 12);
        opts.set_level_zero_stop_writes_trigger(l0_trigger * 16);

        opts.set_block_based_table_factory(&Self::block_options(128, 16 << 10));
        opts.set_memtable_prefix_bloom_ratio(0.02);
        opts
    }

    /// Per-CF options for data column families (headers, tx_data, shard_data).
    /// Uses universal compaction and larger block cache / block size.
    fn data_cf_options() -> Options {
        let mut opts = Options::default();
        opts.set_target_file_size_base(128 * 1024 * 1024);
        opts.set_write_buffer_size(256 * 1024 * 1024);
        opts.set_max_write_buffer_number(6);

        // Universal compaction for append-heavy data CFs.
        opts.set_compaction_style(DBCompactionStyle::Universal);
        opts.set_level_zero_file_num_compaction_trigger(80);
        opts.set_level_zero_slowdown_writes_trigger(96);
        opts.set_level_zero_stop_writes_trigger(128);

        // Larger block cache and block size for bulk data.
        opts.set_block_based_table_factory(&Self::block_options(512, 128 << 10));
        opts.set_memtable_prefix_bloom_ratio(0.02);
        opts
    }

    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Raise fd limit and cap open files to avoid "too many open files" errors
        if let Ok(fdlimit::Outcome::LimitRaised { to, .. }) = fdlimit::raise_fd_limit() {
            opts.set_max_open_files((to / 8) as i32);
        }

        // Table cache sharding to reduce lock contention
        opts.set_table_cache_num_shard_bits(10);

        // Compression: LZ4 for hot levels (fast), Zstd for bottommost (compact)
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
        opts.set_bottommost_zstd_max_train_bytes(1024 * 1024, true);

        // Write buffer settings
        opts.set_db_write_buffer_size(2 * 1024 * 1024 * 1024); // 2 GB global limit
        opts.set_write_buffer_size(256 * 1024 * 1024); // 256 MB per CF
        opts.set_max_write_buffer_number(6);

        // L0 compaction triggers with backpressure
        let l0_trigger = 4;
        opts.set_level_zero_file_num_compaction_trigger(l0_trigger);
        opts.set_level_zero_slowdown_writes_trigger(l0_trigger * 12);
        opts.set_level_zero_stop_writes_trigger(l0_trigger * 16);

        // WAL limit
        opts.set_max_total_wal_size(2 * 1024 * 1024 * 1024); // 2 GB

        // Parallelism
        opts.increase_parallelism(8);

        // Sync and I/O settings
        opts.set_use_fsync(false); // fdatasync is sufficient
        opts.set_writable_file_max_buffer_size(64 * 1048576);

        // Compaction tuning
        opts.set_target_file_size_base(128 * 1024 * 1024);

        // Write performance
        opts.set_enable_pipelined_write(true);

        // Default block options
        opts.set_block_based_table_factory(&Self::block_options(128, 16 << 10));
        opts.set_memtable_prefix_bloom_ratio(0.02);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, Self::metadata_cf_options()),
            ColumnFamilyDescriptor::new(CF_HEADERS, Self::data_cf_options()),
            ColumnFamilyDescriptor::new(CF_TX_DATA, Self::data_cf_options()),
            ColumnFamilyDescriptor::new(CF_SHARD_DATA, Self::data_cf_options()),
            ColumnFamilyDescriptor::new(CF_COMMITS, Self::metadata_cf_options()),
            ColumnFamilyDescriptor::new(CF_DUAL_DAG_CLEAN, Self::metadata_cf_options()),
            ColumnFamilyDescriptor::new(CF_RBC_DAG_FRONTIER_RECEIPT, Self::metadata_cf_options()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors).map_err(io::Error::other)?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false);

        Ok(Self {
            db: Arc::new(db),
            write_opts,
        })
    }

    fn cf(&self, name: &str) -> io::Result<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| io::Error::other(format!("Column family '{name}' not found")))
    }

    /// Point-read and deserialize an optional value from a column family.
    fn point_read_cf<T: serde::de::DeserializeOwned>(
        &self,
        cf: &impl rocksdb::AsColumnFamilyRef,
        key: &[u8],
    ) -> io::Result<Option<T>> {
        match self
            .db
            .get_cf_opt(cf, key, &Self::get_read_opts())
            .map_err(io::Error::other)?
        {
            Some(bytes) => deserialize(&bytes).map(Some).map_err(io::Error::other),
            None => Ok(None),
        }
    }

    /// Assemble a block from the component column families in the DB.
    fn assemble_from_db(&self, key: &[u8]) -> io::Result<Option<Data<VerifiedBlock>>> {
        let cf_headers = self.cf(CF_HEADERS)?;
        let read_opts = Self::get_read_opts();
        let header_bytes = self
            .db
            .get_cf_opt(&cf_headers, key, &read_opts)
            .map_err(io::Error::other)?;

        let Some(header_bytes) = header_bytes else {
            return Ok(None);
        };

        let header: BlockHeader = deserialize(&header_bytes).map_err(io::Error::other)?;
        let cf_tx_data = self.cf(CF_TX_DATA)?;
        let tx: Option<TransactionData> = self.point_read_cf(&cf_tx_data, key)?;

        Ok(Some(Data::new(VerifiedBlock::from_parts(header, tx))))
    }
}

impl Store for RocksStore {
    fn store_block(&self, block: Data<VerifiedBlock>) -> io::Result<()> {
        let reference = *block.reference();
        let key = serialize(&reference).map_err(io::Error::other)?;

        // All blocks must be pre-serialized before reaching the store.
        let header_bytes = block
            .serialized_header_bytes()
            .expect("header must be preserialized before store");

        let mut wb = rocksdb::WriteBatch::default();
        let cf_headers = self.cf(CF_HEADERS)?;
        wb.put_cf(&cf_headers, &key, header_bytes.as_ref());

        if let Some(_tx) = block.transaction_data() {
            let tx_bytes = block
                .serialized_tx_data_bytes()
                .expect("tx_data must be preserialized before store")
                .as_ref();
            let cf_tx_data = self.cf(CF_TX_DATA)?;
            wb.put_cf(&cf_tx_data, &key, tx_bytes);
        }

        self.db
            .write_opt(wb, &self.write_opts)
            .map_err(io::Error::other)
    }

    fn get_block(&self, reference: &BlockReference) -> io::Result<Option<Data<VerifiedBlock>>> {
        let key = serialize(reference).map_err(io::Error::other)?;

        // Try component CFs first.
        if let Some(block) = self.assemble_from_db(&key)? {
            return Ok(Some(block));
        }

        // Legacy fallback: CF_BLOCKS.
        let cf_blocks = self.cf(CF_BLOCKS)?;
        match self
            .db
            .get_cf_opt(&cf_blocks, key, &Self::get_read_opts())
            .map_err(io::Error::other)?
        {
            Some(value) => Data::from_bytes(value.into())
                .map(Some)
                .map_err(io::Error::other),
            None => Ok(None),
        }
    }

    fn get_blocks(
        &self,
        references: &[BlockReference],
    ) -> io::Result<Vec<Option<Data<VerifiedBlock>>>> {
        if references.is_empty() {
            return Ok(Vec::new());
        }

        let keys: Vec<Vec<u8>> = references
            .iter()
            .map(|reference| serialize(reference).map_err(io::Error::other))
            .collect::<io::Result<_>>()?;

        let cf_headers = self.cf(CF_HEADERS)?;
        let header_results = self
            .db
            .batched_multi_get_cf(&cf_headers, keys.iter(), false);
        let headers: Vec<Option<BlockHeader>> = header_results
            .into_iter()
            .map(|result| {
                result
                    .map_err(io::Error::other)?
                    .map(|bytes| deserialize(bytes.as_ref()).map_err(io::Error::other))
                    .transpose()
            })
            .collect::<io::Result<_>>()?;

        let cf_tx_data = self.cf(CF_TX_DATA)?;
        let tx_results = self
            .db
            .batched_multi_get_cf(&cf_tx_data, keys.iter(), false);
        let tx_data: Vec<Option<TransactionData>> = tx_results
            .into_iter()
            .map(|result| {
                result
                    .map_err(io::Error::other)?
                    .map(|bytes| deserialize(bytes.as_ref()).map_err(io::Error::other))
                    .transpose()
            })
            .collect::<io::Result<_>>()?;

        let mut blocks: Vec<Option<Data<VerifiedBlock>>> = headers
            .into_iter()
            .zip(tx_data)
            .map(|(header, tx)| {
                header.map(|header| Data::new(VerifiedBlock::from_parts(header, tx)))
            })
            .collect();

        let missing_indices: Vec<_> = blocks
            .iter()
            .enumerate()
            .filter_map(|(index, block)| block.is_none().then_some(index))
            .collect();
        if missing_indices.is_empty() {
            return Ok(blocks);
        }

        let cf_blocks = self.cf(CF_BLOCKS)?;
        let legacy_results = self.db.batched_multi_get_cf(
            &cf_blocks,
            missing_indices.iter().map(|&index| &keys[index]),
            false,
        );

        for (index, result) in missing_indices.into_iter().zip(legacy_results) {
            blocks[index] = match result.map_err(io::Error::other)? {
                Some(bytes) => Some(
                    Data::from_bytes(bytes.as_ref().to_vec().into()).map_err(io::Error::other)?,
                ),
                None => None,
            };
        }

        Ok(blocks)
    }

    fn get_blocks_by_round(&self, round: RoundNumber) -> io::Result<Vec<Data<VerifiedBlock>>> {
        let mut blocks = Vec::new();
        let mut seen = AHashSet::new();

        let seek_key = serialize(&BlockReference {
            round,
            authority: 0,
            digest: BlockDigest::default(),
        })
        .map_err(io::Error::other)?;

        // 1. Iterate CF_HEADERS by round, assemble with tx lookups.
        let cf_headers = self.cf(CF_HEADERS)?;
        let cf_tx_data = self.cf(CF_TX_DATA)?;

        let read_opts = Self::get_read_opts();
        let mut iter = self.db.raw_iterator_cf_opt(&cf_headers, read_opts);
        iter.seek(&seek_key);

        while iter.valid() {
            let key_bytes = iter.key().ok_or_else(|| io::Error::other("Invalid key"))?;
            let header_bytes = iter
                .value()
                .ok_or_else(|| io::Error::other("Invalid value"))?;

            let reference: BlockReference = deserialize(key_bytes).map_err(io::Error::other)?;
            if reference.round > round {
                break;
            }

            let header: BlockHeader = deserialize(header_bytes).map_err(io::Error::other)?;
            let tx = self.point_read_cf(&cf_tx_data, key_bytes)?;
            blocks.push(Data::new(VerifiedBlock::from_parts(header, tx)));
            seen.insert(reference);

            iter.next();
        }

        // 2. Legacy fallback: iterate CF_BLOCKS for any not yet found.
        let cf_blocks = self.cf(CF_BLOCKS)?;
        let mut iter = self
            .db
            .raw_iterator_cf_opt(&cf_blocks, Self::get_read_opts());
        iter.seek(&seek_key);

        while iter.valid() {
            let key_bytes = iter.key().ok_or_else(|| io::Error::other("Invalid key"))?;
            let value = iter
                .value()
                .ok_or_else(|| io::Error::other("Invalid value"))?;

            let reference: BlockReference = deserialize(key_bytes).map_err(io::Error::other)?;
            if reference.round > round {
                break;
            }

            if !seen.contains(&reference) {
                let block = Data::from_bytes(value.to_vec().into()).map_err(io::Error::other)?;
                blocks.push(block);
            }

            iter.next();
        }

        Ok(blocks)
    }

    fn store_commits(&self, committed_sub_dags: Vec<CommitData>) -> io::Result<()> {
        let mut wb = rocksdb::WriteBatch::default();
        let cf_commits = self.cf(CF_COMMITS)?;
        for commit_data in &committed_sub_dags {
            let key = serialize(&commit_data.leader).map_err(io::Error::other)?;
            let value = serialize(commit_data).map_err(io::Error::other)?;
            wb.put_cf(&cf_commits, key, value);
        }
        self.db
            .write_opt(wb, &self.write_opts)
            .map_err(io::Error::other)
    }

    fn store_commits_with_rbc_dag_receipt(
        &self,
        committed_sub_dags: Vec<CommitData>,
        receipt: RbcDagFrontierReceipt,
    ) -> io::Result<()> {
        validate_rbc_dag_frontier_commit_batch(&committed_sub_dags, &receipt)?;
        let receipt_bytes = receipt.to_bytes()?;

        let mut wb = rocksdb::WriteBatch::default();
        let cf_commits = self.cf(CF_COMMITS)?;
        if committed_sub_dags.is_empty() {
            let key = serialize(&receipt.carrier_anchor).map_err(io::Error::other)?;
            wb.delete_cf(&cf_commits, key);
        } else {
            let commit_data = &committed_sub_dags[0];
            let key = serialize(&commit_data.leader).map_err(io::Error::other)?;
            let value = serialize(commit_data).map_err(io::Error::other)?;
            wb.put_cf(&cf_commits, key, value);
        }

        let cf_receipt = self.cf(CF_RBC_DAG_FRONTIER_RECEIPT)?;
        wb.put_cf(
            &cf_receipt,
            LATEST_RBC_DAG_FRONTIER_RECEIPT_KEY,
            receipt_bytes,
        );

        self.db
            .write_opt(wb, &self.write_opts)
            .map_err(io::Error::other)
    }

    fn get_commit(&self, reference: &BlockReference) -> io::Result<Option<CommitData>> {
        let key = serialize(reference).map_err(io::Error::other)?;
        let cf_commits = self.cf(CF_COMMITS)?;
        match self
            .db
            .get_cf_opt(&cf_commits, key, &Self::get_read_opts())
            .map_err(io::Error::other)?
        {
            Some(value) => {
                let commit_data: CommitData = deserialize(&value).map_err(io::Error::other)?;
                Ok(Some(commit_data))
            }
            None => Ok(None),
        }
    }

    fn read_latest_rbc_dag_frontier_receipt(&self) -> io::Result<Option<RbcDagFrontierReceipt>> {
        let cf = self.cf(CF_RBC_DAG_FRONTIER_RECEIPT)?;
        match self
            .db
            .get_cf_opt(
                &cf,
                LATEST_RBC_DAG_FRONTIER_RECEIPT_KEY,
                &Self::get_read_opts(),
            )
            .map_err(io::Error::other)?
        {
            Some(bytes) => RbcDagFrontierReceipt::from_bytes(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn store_header_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()> {
        let key = serialize(reference).map_err(io::Error::other)?;
        let cf = self.cf(CF_HEADERS)?;
        self.db
            .put_cf_opt(&cf, key, bytes, &self.write_opts)
            .map_err(io::Error::other)
    }

    fn store_tx_data_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()> {
        let key = serialize(reference).map_err(io::Error::other)?;
        let cf = self.cf(CF_TX_DATA)?;
        self.db
            .put_cf_opt(&cf, key, bytes, &self.write_opts)
            .map_err(io::Error::other)
    }

    fn store_shard_data_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()> {
        let key = serialize(reference).map_err(io::Error::other)?;
        let cf = self.cf(CF_SHARD_DATA)?;
        self.db
            .put_cf_opt(&cf, key, bytes, &self.write_opts)
            .map_err(io::Error::other)
    }

    fn read_last_commit(&self) -> io::Result<Option<CommitData>> {
        let cf_commits = self.cf(CF_COMMITS)?;
        let mut iter = self
            .db
            .raw_iterator_cf_opt(&cf_commits, Self::get_read_opts());
        iter.seek_to_last();
        if iter.valid() {
            if let Some(value) = iter.value() {
                let commit: CommitData = deserialize(value).map_err(io::Error::other)?;
                return Ok(Some(commit));
            }
        }
        Ok(None)
    }

    fn scan_blocks_from_round(
        &self,
        from_round: RoundNumber,
    ) -> io::Result<Vec<Data<VerifiedBlock>>> {
        let mut blocks = Vec::new();
        let mut seen = AHashSet::new();

        let seek_key = serialize(&BlockReference {
            round: from_round,
            authority: 0,
            digest: BlockDigest::default(),
        })
        .map_err(io::Error::other)?;

        // 1. Iterate CF_HEADERS from from_round onward.
        let cf_headers = self.cf(CF_HEADERS)?;
        let cf_tx_data = self.cf(CF_TX_DATA)?;

        let read_opts = Self::get_read_opts();
        let mut iter = self.db.raw_iterator_cf_opt(&cf_headers, read_opts);
        iter.seek(&seek_key);

        while iter.valid() {
            let key_bytes = iter.key().ok_or_else(|| io::Error::other("Invalid key"))?;
            let header_bytes = iter
                .value()
                .ok_or_else(|| io::Error::other("Invalid value"))?;

            let reference: BlockReference = deserialize(key_bytes).map_err(io::Error::other)?;
            let header: BlockHeader = deserialize(header_bytes).map_err(io::Error::other)?;
            let tx = self.point_read_cf(&cf_tx_data, key_bytes)?;
            blocks.push(Data::new(VerifiedBlock::from_parts(header, tx)));
            seen.insert(reference);

            iter.next();
        }

        // 2. Legacy fallback: CF_BLOCKS.
        let cf_blocks = self.cf(CF_BLOCKS)?;
        let mut iter = self
            .db
            .raw_iterator_cf_opt(&cf_blocks, Self::get_read_opts());
        iter.seek(&seek_key);

        while iter.valid() {
            let key_bytes = iter.key().ok_or_else(|| io::Error::other("Invalid key"))?;
            let value = iter
                .value()
                .ok_or_else(|| io::Error::other("Invalid value"))?;

            let reference: BlockReference = deserialize(key_bytes).map_err(io::Error::other)?;
            if !seen.contains(&reference) {
                let block = Data::from_bytes(value.to_vec().into()).map_err(io::Error::other)?;
                blocks.push(block);
            }

            iter.next();
        }

        Ok(blocks)
    }

    fn get_shard_data(&self, reference: &BlockReference) -> io::Result<Option<ProvableShard>> {
        let key = serialize(reference).map_err(io::Error::other)?;
        let cf = self.cf(CF_SHARD_DATA)?;
        self.point_read_cf(&cf, &key)
    }

    fn get_shard_data_batch(
        &self,
        references: &[BlockReference],
    ) -> io::Result<Vec<Option<ProvableShard>>> {
        if references.is_empty() {
            return Ok(Vec::new());
        }

        let keys: Vec<Vec<u8>> = references
            .iter()
            .map(|reference| serialize(reference).map_err(io::Error::other))
            .collect::<io::Result<_>>()?;
        let cf = self.cf(CF_SHARD_DATA)?;
        self.db
            .batched_multi_get_cf(&cf, keys.iter(), false)
            .into_iter()
            .map(|result| {
                result
                    .map_err(io::Error::other)?
                    .map(|bytes| deserialize(bytes.as_ref()).map_err(io::Error::other))
                    .transpose()
            })
            .collect()
    }

    fn store_dual_dag_clean_refs(&self, refs: &[BlockReference]) -> io::Result<()> {
        if refs.is_empty() {
            return Ok(());
        }
        let cf = self.cf(CF_DUAL_DAG_CLEAN)?;
        let mut wb = rocksdb::WriteBatch::default();
        for reference in refs {
            let key = serialize(reference).map_err(io::Error::other)?;
            wb.put_cf(&cf, key, []);
        }
        self.db
            .write_opt(wb, &self.write_opts)
            .map_err(io::Error::other)
    }

    fn scan_dual_dag_clean_refs_from_round(
        &self,
        from_round: RoundNumber,
    ) -> io::Result<Vec<BlockReference>> {
        let mut refs = Vec::new();
        let seek_key = serialize(&BlockReference {
            round: from_round,
            authority: 0,
            digest: BlockDigest::default(),
        })
        .map_err(io::Error::other)?;

        let cf = self.cf(CF_DUAL_DAG_CLEAN)?;
        let mut iter = self.db.raw_iterator_cf_opt(&cf, Self::get_read_opts());
        iter.seek(&seek_key);

        while iter.valid() {
            let key_bytes = iter.key().ok_or_else(|| io::Error::other("Invalid key"))?;
            let reference: BlockReference = deserialize(key_bytes).map_err(io::Error::other)?;
            refs.push(reference);
            iter.next();
        }

        Ok(refs)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::RocksStore;
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
    fn rbc_dag_receipt_and_commits_are_atomic_and_latest_is_a_point_value() {
        let temp_dir = TempDir::new().unwrap();
        let store = RocksStore::open(temp_dir.path()).unwrap();

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
        let reopened = RocksStore::open(temp_dir.path()).unwrap();
        assert_commit(&reopened, &legacy_commit);
        assert!(reopened.get_commit(&second_anchor).unwrap().is_none());
        assert_eq!(
            reopened.read_latest_rbc_dag_frontier_receipt().unwrap(),
            Some(control_receipt)
        );
    }
}
