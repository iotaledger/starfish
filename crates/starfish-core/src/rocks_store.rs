use crate::block_store::CommitData;
use crate::data::Data;
use crate::types::{BlockReference, RoundNumber, VerifiedStatementBlock};
use bincode::{deserialize, serialize};
use parking_lot::RwLock;
use rocksdb::{ColumnFamilyDescriptor, Options, ReadOptions, WriteOptions, DB};
use std::collections::VecDeque;
use std::{collections::HashMap, io, path::Path, sync::Arc};
use std::cmp::Ordering;
use tokio::sync::watch;
use tokio::time::Instant;
// Column families for different types of data
const CF_BLOCKS: &str = "blocks";
const CF_COMMITS: &str = "commits";
const BATCH_SIZE_THRESHOLD: usize = 2 * 1024 * 1024; // target batch size

// Keep the batched operations in memory
#[derive(Default)]
struct BatchedOperations {
    blocks: HashMap<BlockReference, Data<VerifiedStatementBlock>>,
    commits: HashMap<BlockReference, CommitData>,
    total_size: usize,
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

    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Optimize for frequent syncs
        opts.set_write_buffer_size(512 * 1024 * 1024);
        opts.set_max_write_buffer_number(8);
        opts.set_min_write_buffer_number_to_merge(4);
        opts.set_level_zero_file_num_compaction_trigger(8);
        opts.set_max_background_jobs(16);
        opts.set_bytes_per_sync(32 * 1048576);

        // Add these settings for sync optimization
        opts.set_use_fsync(false); // Use fdatasync instead of fsync
        opts.set_writable_file_max_buffer_size(64 * 1048576); // 64MB buffer
        opts.set_use_direct_io_for_flush_and_compaction(true); // Use direct I/O for background ops
        opts.set_level_compaction_dynamic_level_bytes(true); // Dynamically change the level of compaction
                                                             // Additional optimizations for high write throughput
        opts.set_min_level_to_compress(2);
        opts.set_compression_type(rocksdb::DBCompressionType::Zlib);
        opts.set_max_subcompactions(4); // Allow parallel compactions
        opts.set_enable_write_thread_adaptive_yield(true); // Better CPU utilization

        // Additional performance optimizations
        opts.set_allow_concurrent_memtable_write(true);
        opts.optimize_for_point_lookup(1024);
        opts.increase_parallelism(8); // Adjust based on CPU cores (NumCpu - 1)

        let mut cf_opts = Options::default();
        cf_opts.set_target_file_size_base(128 * 1024 * 1024);
        cf_opts.set_write_buffer_size(512 * 1024 * 1024); // 256MB per CF

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_COMMITS, cf_opts),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

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

    pub fn flush(&self) -> io::Result<()> {
        self.flush_pending_batches()?;

        // Then do regular flush of current batch
        // Quick check with read lock
        {
            let batch_read = self.batch.read();
            if batch_read.blocks.is_empty() && batch_read.commits.is_empty() {
                return Ok(());
            }
        }

        // Create batch outside of lock
        let mut batch = rocksdb::WriteBatch::default();

        // Take a snapshot of data under brief write lock
        let (blocks_to_write, commits_to_write) = {
            let mut batch_ops = self.batch.write();
            (
                std::mem::take(&mut batch_ops.blocks),
                std::mem::take(&mut batch_ops.commits),
            )
            // Lock is dropped here
        };

        let cf_blocks = self
            .db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;
        let cf_commits = self
            .db
            .cf_handle(CF_COMMITS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        // Process without holding locks
        for (reference, block) in blocks_to_write {
            let key = serialize(&reference).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            batch.put_cf(&cf_blocks, key, block.serialized_bytes().as_ref());
        }

        for (anchor, commit_data) in commits_to_write {
            let key = serialize(&anchor).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let value =
                serialize(&commit_data).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            batch.put_cf(&cf_commits, key, value);
        }

        // Single write operation
        self.db
            .write_opt(batch, &self.write_opts)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Update timestamp with minimal lock duration
        *self.last_flush.write() = Instant::now();

        Ok(())
    }

    pub fn store_block(&self, block: Data<VerifiedStatementBlock>) -> io::Result<()> {
        let reference = block.reference();
        let size = block.serialized_bytes().len();
        let mut batch = self.batch.write();
        batch.blocks.insert(*reference, block);
        batch.total_size += size;
        // If batch is large enough, move it to pending queue
        if batch.total_size >= BATCH_SIZE_THRESHOLD {
            let ops = std::mem::take(&mut *batch);
            drop(batch);
            let mut pending = self.pending_batches.lock();
            pending.push_back(ops);
        }
        Ok(())
    }

    pub fn flush_pending_batches(&self) -> io::Result<()> {
        loop {
            let ops = {
                let mut pending = self.pending_batches.lock();
                pending.pop_front()
            };

            let Some(ops) = ops else {
                break;
            };

            let mut batch = rocksdb::WriteBatch::default();

            let cf_blocks = self
                .db
                .cf_handle(CF_BLOCKS)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;
            let cf_commits = self
                .db
                .cf_handle(CF_COMMITS)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

            // Process without holding locks
            for (reference, block) in ops.blocks {
                let key =
                    serialize(&reference).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                batch.put_cf(&cf_blocks, key, block.serialized_bytes().as_ref());
            }

            for (anchor, commit_data) in ops.commits {
                let key =
                    serialize(&anchor).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let value =
                    serialize(&commit_data).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                batch.put_cf(&cf_commits, key, value);
            }

            // Single write operation
            self.db
                .write_opt(batch, &self.write_opts)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }
        Ok(())
    }

    pub fn store_commits(&self, committed_sub_dags: Vec<CommitData>) -> io::Result<()> {
        let mut batch = self.batch.write();
        for committed_sub_dag in committed_sub_dags {
            batch
                .commits
                .insert(committed_sub_dag.leader, committed_sub_dag);
        }
        Ok(())
    }

    pub fn get_block(
        &self,
        reference: &BlockReference,
    ) -> io::Result<Option<Data<VerifiedStatementBlock>>> {
        // Check in-memory batch first
        // Check current batch first
        let batch = self.batch.read();
        if let Some(block) = batch.blocks.get(reference) {
            return Ok(Some(block.clone()));
        }
        drop(batch);

        // Check pending batches
        let pending = self.pending_batches.lock();
        for ops in pending.iter() {
            if let Some(block) = ops.blocks.get(reference) {
                return Ok(Some(block.clone()));
            }
        }
        drop(pending);

        // If not in batch, check DB
        let key = serialize(reference).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let cf_blocks = self
            .db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        match self
            .db
            .get_cf_opt(&cf_blocks, key, &Self::get_read_opts())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        {
            Some(value) => Data::from_bytes(value.into())
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            None => Ok(None),
        }
    }

    pub fn get_blocks_by_round(
        &self,
        round: RoundNumber,
    ) -> io::Result<Vec<Data<VerifiedStatementBlock>>> {
        let mut blocks = Vec::new();

        // Check in-memory batch first
        {
            let batch = self.batch.read();
            for (reference, block) in batch.blocks.iter() {
                if reference.round == round {
                    blocks.push(block.clone());
                }
            }
        }

        // Then check DB
        let cf_blocks = self
            .db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        // Collect all matching blocks from DB
        {
            let mut iter = self
                .db
                .raw_iterator_cf_opt(&cf_blocks, Self::get_read_opts());
            iter.seek_to_first();

            while iter.valid() {
                let key_bytes = iter
                    .key()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid key"))?
                    .to_vec();
                let value = iter
                    .value()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid value"))?
                    .to_vec();

                let reference: BlockReference =
                    deserialize(&key_bytes).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                match reference.round.cmp(&round) {
                    Ordering::Equal => {
                        let block = Data::from_bytes(value.into())
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                        blocks.push(block);
                    },
                    Ordering::Greater => break,
                    Ordering::Less => {},
                }

                iter.next();
            }
        }

        Ok(blocks)
    }

    pub fn get_commit(&self, reference: &BlockReference) -> io::Result<Option<CommitData>> {
        // Check in-memory batch first
        let batch = self.batch.read();
        if let Some(commit) = batch.commits.get(reference) {
            return Ok(Some(commit.clone()));
        }
        drop(batch);

        // If not in batch, check DB
        let key = serialize(reference).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let cf_commits = self
            .db
            .cf_handle(CF_COMMITS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        match self
            .db
            .get_cf_opt(&cf_commits, key, &Self::get_read_opts())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        {
            Some(value) => {
                let commit_data: CommitData =
                    deserialize(&value).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                Ok(Some(commit_data.clone()))
            }
            None => Ok(None),
        }
    }

    pub fn sync(&self) -> io::Result<()> {
        // Quick check with read lock
        {
            let batch_read = self.batch.read();
            if batch_read.blocks.is_empty() && batch_read.commits.is_empty() {
                return Ok(());
            }
        }

        let mut sync_opts = WriteOptions::default();
        sync_opts.set_sync(true);

        // Create batch outside of lock
        let mut batch = rocksdb::WriteBatch::default();

        // Take a snapshot of data under brief write lock
        let (blocks_to_write, commits_to_write) = {
            let mut batch_ops = self.batch.write();
            (
                std::mem::take(&mut batch_ops.blocks),
                std::mem::take(&mut batch_ops.commits),
            )
        };

        // Only process if we have data
        if !blocks_to_write.is_empty() || !commits_to_write.is_empty() {
            let cf_blocks = self
                .db
                .cf_handle(CF_BLOCKS)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;
            let cf_commits = self
                .db
                .cf_handle(CF_COMMITS)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

            // Process blocks without holding any locks
            for (reference, block) in blocks_to_write {
                let key =
                    serialize(&reference).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                batch.put_cf(&cf_blocks, key, block.serialized_bytes().as_ref());
            }

            // Process commits without holding any locks
            for (anchor, commit_data) in commits_to_write {
                let key =
                    serialize(&anchor).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let value =
                    serialize(&commit_data).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                batch.put_cf(&cf_commits, key, value);
            }
        }

        // Single write operation with sync
        self.db
            .write_opt(batch, &sync_opts)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        tracing::debug!("Data is synced with disk");
        *self.last_sync.write() = Instant::now();
        Ok(())
    }
}
