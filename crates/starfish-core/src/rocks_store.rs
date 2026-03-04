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
    store::Store,
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
            .expect("header must be preserialized before store")
            .to_vec();

        let mut wb = rocksdb::WriteBatch::default();
        let cf_headers = self.cf(CF_HEADERS)?;
        wb.put_cf(&cf_headers, &key, header_bytes);

        if let Some(_tx) = block.transaction_data() {
            let tx_bytes = block
                .serialized_tx_data_bytes()
                .expect("tx_data must be preserialized before store")
                .to_vec();
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
}
