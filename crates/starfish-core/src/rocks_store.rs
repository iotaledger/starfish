// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, VecDeque},
    io,
    path::Path,
    sync::Arc,
};

use ahash::AHashSet;

use bincode::{deserialize, serialize};
use parking_lot::RwLock;
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, Options, ReadOptions, WriteOptions,
};
use tokio::{sync::watch, time::Instant};

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
const BATCH_SIZE_THRESHOLD: usize = 2 * 1024 * 1024; // target batch size

// Keep the batched operations in memory
#[derive(Default)]
struct BatchedOperations {
    // Legacy composite blocks — no longer written to, but may exist in pending
    // batches from before a rolling upgrade.
    blocks: HashMap<BlockReference, Data<VerifiedBlock>>,
    // Component maps for the new separated storage.
    headers: HashMap<BlockReference, Vec<u8>>,
    tx_data: HashMap<BlockReference, Vec<u8>>,
    shard_data: HashMap<BlockReference, Vec<u8>>,
    commits: HashMap<BlockReference, CommitData>,
    total_size: usize,
}

impl BatchedOperations {
    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
            && self.headers.is_empty()
            && self.tx_data.is_empty()
            && self.shard_data.is_empty()
            && self.commits.is_empty()
    }
}

pub struct RocksStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
    batch: Arc<RwLock<BatchedOperations>>,
    pending_batches: Arc<parking_lot::Mutex<VecDeque<BatchedOperations>>>,
    last_flush: Arc<RwLock<Instant>>,
    last_sync: Arc<RwLock<Instant>>,
    shutdown: Arc<watch::Sender<bool>>,
}

impl Clone for RocksStore {
    fn clone(&self) -> Self {
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false);
        write_opts.disable_wal(true); // Might be problems when crashed

        Self {
            db: self.db.clone(),
            write_opts,
            batch: self.batch.clone(),
            last_flush: self.last_flush.clone(),
            pending_batches: self.pending_batches.clone(),
            last_sync: Arc::new(RwLock::new(Instant::now())),
            shutdown: self.shutdown.clone(),
        }
    }
}

impl Drop for RocksStore {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
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
        let l0_trigger = 8;
        opts.set_level_zero_file_num_compaction_trigger(l0_trigger);
        opts.set_level_zero_slowdown_writes_trigger(l0_trigger * 12);
        opts.set_level_zero_stop_writes_trigger(l0_trigger * 16);

        // WAL limit
        opts.set_max_total_wal_size(1024 * 1024 * 1024); // 1 GB

        // Parallelism
        opts.increase_parallelism(8);
        opts.set_max_subcompactions(4);

        // Sync and I/O settings
        opts.set_bytes_per_sync(32 * 1048576);
        opts.set_use_fsync(false); // fdatasync is sufficient
        opts.set_writable_file_max_buffer_size(64 * 1048576);
        opts.set_use_direct_io_for_flush_and_compaction(true);

        // Compaction tuning
        opts.set_level_compaction_dynamic_level_bytes(true);
        opts.set_target_file_size_base(128 * 1024 * 1024);

        // Write performance
        opts.set_enable_pipelined_write(true);
        opts.set_allow_concurrent_memtable_write(true);
        opts.set_enable_write_thread_adaptive_yield(true);

        // Explicit block options instead of optimize_for_point_lookup
        // (optimize_for_point_lookup silently overwrites block settings)
        opts.set_block_based_table_factory(&Self::block_options(128, 16 << 10));
        opts.set_memtable_prefix_bloom_ratio(0.02);

        // Per-CF options
        let mut cf_opts = Options::default();
        cf_opts.set_target_file_size_base(128 * 1024 * 1024);
        cf_opts.set_write_buffer_size(256 * 1024 * 1024);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_HEADERS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_TX_DATA, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_SHARD_DATA, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_COMMITS, cf_opts),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors).map_err(io::Error::other)?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false); // Async writes for better performance

        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let store = Self {
            db: Arc::new(db),
            write_opts,
            pending_batches: Arc::new(parking_lot::Mutex::new(VecDeque::new())),
            batch: Arc::new(RwLock::new(BatchedOperations::default())),
            last_flush: Arc::new(RwLock::new(Instant::now())),
            last_sync: Arc::new(RwLock::new(Instant::now())),
            shutdown: Arc::new(shutdown_tx),
        };

        Ok(store)
    }

    fn do_flush(&self) -> io::Result<()> {
        self.drain_pending_batches()?;

        // Quick check with read lock
        {
            let batch_read = self.batch.read();
            if batch_read.is_empty() {
                return Ok(());
            }
        }

        let ops = {
            let mut batch_ops = self.batch.write();
            std::mem::take(&mut *batch_ops)
        };

        self.write_batch_ops(ops, &self.write_opts)?;
        *self.last_flush.write() = Instant::now();
        Ok(())
    }

    fn do_store_block(&self, block: Data<VerifiedBlock>) -> io::Result<()> {
        let reference = *block.reference();

        // All blocks must be pre-serialized before reaching the store.
        let header_bytes = block
            .serialized_header_bytes()
            .expect("header must be preserialized before store")
            .to_vec();
        let mut size = header_bytes.len();

        let mut batch = self.batch.write();
        batch.headers.insert(reference, header_bytes);

        if let Some(_tx) = block.transaction_data() {
            let tx_bytes = block
                .serialized_tx_data_bytes()
                .expect("tx_data must be preserialized before store")
                .to_vec();
            size += tx_bytes.len();
            batch.tx_data.insert(reference, tx_bytes);
        }
        if let Some(_shard) = block.shard_data() {
            let shard_bytes = block
                .serialized_shard_data_bytes()
                .expect("shard_data must be preserialized before store")
                .to_vec();
            size += shard_bytes.len();
            batch.shard_data.insert(reference, shard_bytes);
        }

        batch.total_size += size;
        Self::maybe_flush_batch(&mut batch, &self.pending_batches);
        Ok(())
    }

    fn drain_pending_batches(&self) -> io::Result<()> {
        loop {
            let ops = self.pending_batches.lock().pop_front();
            let Some(ops) = ops else { break };
            self.write_batch_ops(ops, &self.write_opts)?;
        }
        Ok(())
    }

    /// Write all buffered operations in a single atomic RocksDB WriteBatch.
    fn write_batch_ops(&self, ops: BatchedOperations, write_opts: &WriteOptions) -> io::Result<()> {
        if ops.is_empty() {
            return Ok(());
        }

        let mut wb = rocksdb::WriteBatch::default();

        let cf_headers = self.cf(CF_HEADERS)?;
        let cf_tx_data = self.cf(CF_TX_DATA)?;
        let cf_shard_data = self.cf(CF_SHARD_DATA)?;
        let cf_commits = self.cf(CF_COMMITS)?;

        // Legacy composite blocks (from pending batches created before upgrade).
        if !ops.blocks.is_empty() {
            let cf_blocks = self.cf(CF_BLOCKS)?;
            for (reference, block) in &ops.blocks {
                let key = serialize(reference).map_err(io::Error::other)?;
                wb.put_cf(&cf_blocks, key, block.serialized_bytes().as_ref());
            }
        }

        for (reference, bytes) in &ops.headers {
            let key = serialize(reference).map_err(io::Error::other)?;
            wb.put_cf(&cf_headers, &key, bytes);
        }
        for (reference, bytes) in &ops.tx_data {
            let key = serialize(reference).map_err(io::Error::other)?;
            wb.put_cf(&cf_tx_data, &key, bytes);
        }
        for (reference, bytes) in &ops.shard_data {
            let key = serialize(reference).map_err(io::Error::other)?;
            wb.put_cf(&cf_shard_data, &key, bytes);
        }
        for (anchor, commit_data) in &ops.commits {
            let key = serialize(anchor).map_err(io::Error::other)?;
            let value = serialize(commit_data).map_err(io::Error::other)?;
            wb.put_cf(&cf_commits, key, value);
        }

        self.db.write_opt(wb, write_opts).map_err(io::Error::other)
    }

    fn cf(&self, name: &str) -> io::Result<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| io::Error::other(format!("Column family '{name}' not found")))
    }

    fn do_store_commits(&self, committed_sub_dags: Vec<CommitData>) -> io::Result<()> {
        let mut batch = self.batch.write();
        for committed_sub_dag in committed_sub_dags {
            batch
                .commits
                .insert(committed_sub_dag.leader, committed_sub_dag);
        }
        Ok(())
    }

    fn do_get_block(&self, reference: &BlockReference) -> io::Result<Option<Data<VerifiedBlock>>> {
        // 1. Check in-memory batches (current + pending) for component data.
        if let Some(block) = self.assemble_from_batches(reference) {
            return Ok(Some(block));
        }

        // 2. Try component CFs in DB.
        let key = serialize(reference).map_err(io::Error::other)?;
        if let Some(block) = self.assemble_from_db(&key)? {
            return Ok(Some(block));
        }

        // 3. Legacy fallback: CF_BLOCKS.
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

    fn do_get_blocks_by_round(&self, round: RoundNumber) -> io::Result<Vec<Data<VerifiedBlock>>> {
        let mut blocks = Vec::new();
        let mut seen = AHashSet::new();

        // 1. Check in-memory batch for components at this round.
        {
            let batch = self.batch.read();
            Self::collect_round_from_ops(&batch, round, &mut blocks, &mut seen)?;
        }
        {
            let pending = self.pending_batches.lock();
            for ops in pending.iter() {
                Self::collect_round_from_ops(ops, round, &mut blocks, &mut seen)?;
            }
        }

        // 2. Iterate CF_HEADERS by round, assemble with tx/shard lookups.
        let cf_headers = self.cf(CF_HEADERS)?;
        let cf_tx_data = self.cf(CF_TX_DATA)?;
        let cf_shard_data = self.cf(CF_SHARD_DATA)?;

        let seek_key = serialize(&BlockReference {
            round,
            authority: 0,
            digest: BlockDigest::default(),
        })
        .map_err(io::Error::other)?;

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

            if !seen.contains(&reference) {
                let header: BlockHeader = deserialize(header_bytes).map_err(io::Error::other)?;
                let tx = self.point_read_cf(&cf_tx_data, key_bytes)?;
                let shard = self.point_read_cf(&cf_shard_data, key_bytes)?;
                blocks.push(Data::new(VerifiedBlock::from_parts(header, tx, shard)));
                seen.insert(reference);
            }

            iter.next();
        }

        // 3. Legacy fallback: iterate CF_BLOCKS for any not yet found.
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

    /// Assemble a block from in-memory batch component maps.
    fn assemble_from_batches(&self, reference: &BlockReference) -> Option<Data<VerifiedBlock>> {
        // Check current batch.
        let batch = self.batch.read();
        if let Some(block) = Self::assemble_from_ops(&batch, reference) {
            return Some(block);
        }
        drop(batch);

        // Check pending batches.
        let pending = self.pending_batches.lock();
        for ops in pending.iter() {
            if let Some(block) = Self::assemble_from_ops(ops, reference) {
                return Some(block);
            }
        }
        None
    }

    /// Try to assemble a block from a single BatchedOperations.
    fn assemble_from_ops(
        ops: &BatchedOperations,
        reference: &BlockReference,
    ) -> Option<Data<VerifiedBlock>> {
        // Legacy composite entry takes priority.
        if let Some(block) = ops.blocks.get(reference) {
            return Some(block.clone());
        }
        // Try component maps.
        let header_bytes = ops.headers.get(reference)?;
        let header: BlockHeader = deserialize(header_bytes).ok()?;
        let tx = ops.tx_data.get(reference).and_then(|b| deserialize(b).ok());
        let shard = ops
            .shard_data
            .get(reference)
            .and_then(|b| deserialize(b).ok());
        Some(Data::new(VerifiedBlock::from_parts(header, tx, shard)))
    }

    /// Collect assembled blocks for a given round from batch ops.
    fn collect_round_from_ops(
        ops: &BatchedOperations,
        round: RoundNumber,
        out: &mut Vec<Data<VerifiedBlock>>,
        seen: &mut AHashSet<BlockReference>,
    ) -> io::Result<()> {
        // Legacy composite entries.
        for (reference, block) in &ops.blocks {
            if reference.round == round && seen.insert(*reference) {
                out.push(block.clone());
            }
        }
        // Component entries.
        for (reference, header_bytes) in &ops.headers {
            if reference.round == round && seen.insert(*reference) {
                let header: BlockHeader = deserialize(header_bytes).map_err(io::Error::other)?;
                let tx = ops.tx_data.get(reference).and_then(|b| deserialize(b).ok());
                let shard = ops
                    .shard_data
                    .get(reference)
                    .and_then(|b| deserialize(b).ok());
                out.push(Data::new(VerifiedBlock::from_parts(header, tx, shard)));
            }
        }
        Ok(())
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
        let cf_shard_data = self.cf(CF_SHARD_DATA)?;
        let tx: Option<TransactionData> = self.point_read_cf(&cf_tx_data, key)?;
        let shard: Option<ProvableShard> = self.point_read_cf(&cf_shard_data, key)?;

        Ok(Some(Data::new(VerifiedBlock::from_parts(
            header, tx, shard,
        ))))
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

    fn do_get_commit(&self, reference: &BlockReference) -> io::Result<Option<CommitData>> {
        // Check in-memory batch first
        let batch = self.batch.read();
        if let Some(commit) = batch.commits.get(reference) {
            return Ok(Some(commit.clone()));
        }
        drop(batch);

        // If not in batch, check DB
        let key = serialize(reference).map_err(io::Error::other)?;

        let cf_commits = self
            .db
            .cf_handle(CF_COMMITS)
            .ok_or_else(|| io::Error::other("Column family not found"))?;

        match self
            .db
            .get_cf_opt(&cf_commits, key, &Self::get_read_opts())
            .map_err(io::Error::other)?
        {
            Some(value) => {
                let commit_data: CommitData = deserialize(&value).map_err(io::Error::other)?;
                Ok(Some(commit_data.clone()))
            }
            None => Ok(None),
        }
    }

    fn do_sync(&self) -> io::Result<()> {
        {
            let batch_read = self.batch.read();
            if batch_read.is_empty() {
                return Ok(());
            }
        }

        self.drain_pending_batches()?;

        let mut sync_opts = WriteOptions::default();
        sync_opts.set_sync(true);

        let ops = {
            let mut batch_ops = self.batch.write();
            std::mem::take(&mut *batch_ops)
        };

        self.write_batch_ops(ops, &sync_opts)?;
        tracing::debug!("Data is synced with disk");
        *self.last_sync.write() = Instant::now();
        Ok(())
    }

    fn do_store_header_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()> {
        let size = bytes.len();
        let mut batch = self.batch.write();
        batch.headers.insert(*reference, bytes.to_vec());
        batch.total_size += size;
        Self::maybe_flush_batch(&mut batch, &self.pending_batches);
        Ok(())
    }

    fn do_store_tx_data_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()> {
        let size = bytes.len();
        let mut batch = self.batch.write();
        batch.tx_data.insert(*reference, bytes.to_vec());
        batch.total_size += size;
        Self::maybe_flush_batch(&mut batch, &self.pending_batches);
        Ok(())
    }

    fn do_store_shard_data_bytes(
        &self,
        reference: &BlockReference,
        bytes: &[u8],
    ) -> io::Result<()> {
        let size = bytes.len();
        let mut batch = self.batch.write();
        batch.shard_data.insert(*reference, bytes.to_vec());
        batch.total_size += size;
        Self::maybe_flush_batch(&mut batch, &self.pending_batches);
        Ok(())
    }

    fn maybe_flush_batch(
        batch: &mut BatchedOperations,
        pending: &parking_lot::Mutex<VecDeque<BatchedOperations>>,
    ) {
        if batch.total_size >= BATCH_SIZE_THRESHOLD {
            let ops = std::mem::take(batch);
            pending.lock().push_back(ops);
        }
    }
}

impl Store for RocksStore {
    fn store_block(&self, block: Data<VerifiedBlock>) -> io::Result<()> {
        self.do_store_block(block)
    }

    fn get_block(&self, reference: &BlockReference) -> io::Result<Option<Data<VerifiedBlock>>> {
        self.do_get_block(reference)
    }

    fn get_blocks_by_round(&self, round: RoundNumber) -> io::Result<Vec<Data<VerifiedBlock>>> {
        self.do_get_blocks_by_round(round)
    }

    fn store_commits(&self, committed_sub_dags: Vec<CommitData>) -> io::Result<()> {
        self.do_store_commits(committed_sub_dags)
    }

    fn get_commit(&self, reference: &BlockReference) -> io::Result<Option<CommitData>> {
        self.do_get_commit(reference)
    }

    fn flush(&self) -> io::Result<()> {
        self.do_flush()
    }

    fn flush_pending_batches(&self) -> io::Result<()> {
        self.drain_pending_batches()
    }

    fn sync(&self) -> io::Result<()> {
        self.do_sync()
    }

    fn store_header_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()> {
        self.do_store_header_bytes(reference, bytes)
    }

    fn store_tx_data_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()> {
        self.do_store_tx_data_bytes(reference, bytes)
    }

    fn store_shard_data_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()> {
        self.do_store_shard_data_bytes(reference, bytes)
    }
}
