use std::{
    path::Path,
    io,
    sync::Arc,
    collections::HashMap,
};
use rocksdb::{
    DB, Options, ColumnFamilyDescriptor, WriteOptions,
    ReadOptions, DBCompressionType,
};
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};
use parking_lot::RwLock;
use bytes::Bytes;

use crate::types::{
    AuthorityIndex, BlockReference,
    RoundNumber, VerifiedStatementBlock,
};
use crate::data::Data;
use crate::consensus::linearizer::CommittedSubDag;
use crate::committee::{QuorumThreshold, StakeAggregator};

// Column families for different types of data
const CF_BLOCKS: &str = "blocks";
const CF_COMMITS: &str = "commits";

#[derive(Serialize, Deserialize)]
struct CommitData {
    sub_dag: CommittedSubDag,
}

// Keep the batched operations in memory
#[derive(Default)]
struct BatchedOperations {
    blocks: HashMap<BlockReference, Data<VerifiedStatementBlock>>,
    commits: HashMap<BlockReference, CommittedSubDag>,
}

pub struct RocksStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
    batch: Arc<RwLock<BatchedOperations>>,
}

impl RocksStore {
    fn get_read_opts() -> ReadOptions {
        ReadOptions::default()
    }

    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_write_buffer_size(256 * 1024 * 1024); // 256MB write buffer
        opts.set_max_write_buffer_number(6);

        let mut cf_opts = Options::default();
        cf_opts.set_compression_type(DBCompressionType::Lz4);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_COMMITS, cf_opts),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false); // Async writes for better performance

        Ok(Self {
            db: Arc::new(db),
            write_opts,
            batch: Arc::new(RwLock::new(BatchedOperations::default())),
        })
    }

    pub fn store_block(
        &self,
        block: Data<VerifiedStatementBlock>,
    ) -> io::Result<()> {
        let reference = block.reference();
        let mut batch = self.batch.write();
        batch.blocks.insert(reference.clone(), block);
        Ok(())
    }

    pub fn store_commit(
        &self,
        sub_dag: CommittedSubDag,
    ) -> io::Result<()> {
        let mut batch = self.batch.write();
        batch.commits.insert(sub_dag.anchor.clone(), sub_dag);
        Ok(())
    }

    pub fn flush(&self) -> io::Result<()> {
        let mut batch_ops = self.batch.write();
        let mut batch = rocksdb::WriteBatch::default();

        // Write blocks
        let cf_blocks = self.db.cf_handle(CF_BLOCKS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        for (reference, block) in batch_ops.blocks.iter() {
            let key = serialize(reference)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            batch.put_cf(&cf_blocks, key, block.serialized_bytes().as_ref());
        }

        // Write commits
        let cf_commits = self.db.cf_handle(CF_COMMITS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        for (anchor, sub_dag) in batch_ops.commits.iter() {
            let commit_data = CommitData { sub_dag: sub_dag.clone() };
            let key = serialize(anchor)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let value = serialize(&commit_data)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            batch.put_cf(&cf_commits, key, value);
        }

        // Write batch to DB
        self.db.write_opt(batch, &self.write_opts)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Clear the batch after successful write
        batch_ops.blocks.clear();
        batch_ops.commits.clear();

        Ok(())
    }

    pub fn get_block(&self, reference: &BlockReference) -> io::Result<Option<Data<VerifiedStatementBlock>>> {
        // Check in-memory batch first
        let batch = self.batch.read();
        if let Some(block) = batch.blocks.get(reference) {
            return Ok(Some(block.clone()));
        }
        drop(batch);

        // If not in batch, check DB
        let key = serialize(reference)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let cf_blocks = self.db.cf_handle(CF_BLOCKS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        match self.db.get_cf_opt(&cf_blocks, key, &Self::get_read_opts())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))? {
            Some(value) => Data::from_bytes(value.into())
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            None => Ok(None),
        }
    }

    pub fn get_blocks_by_round(&self, round: RoundNumber) -> io::Result<Vec<Data<VerifiedStatementBlock>>> {
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
        let cf_blocks = self.db.cf_handle(CF_BLOCKS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        // Collect all matching blocks from DB
        {
            let mut iter = self.db.raw_iterator_cf_opt(&cf_blocks, Self::get_read_opts());
            iter.seek_to_first();

            while iter.valid() {
                let key_bytes = iter.key()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid key"))?.to_vec();
                let value = iter.value()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid value"))?.to_vec();

                let reference: BlockReference = deserialize(&key_bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                if reference.round == round {
                    let block = Data::from_bytes(value.into())
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                    blocks.push(block);
                } else if reference.round > round {
                    break;
                }

                iter.next();
            }
        }

        Ok(blocks)
    }



    pub fn get_commit(&self, reference: &BlockReference) -> io::Result<Option<CommittedSubDag>> {
        // Check in-memory batch first
        let batch = self.batch.read();
        if let Some(commit) = batch.commits.get(reference) {
            return Ok(Some(commit.clone()));
        }
        drop(batch);

        // If not in batch, check DB
        let key = serialize(reference)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let cf_commits = self.db.cf_handle(CF_COMMITS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        match self.db.get_cf_opt(&cf_commits, key, &Self::get_read_opts())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))? {
            Some(value) => {
                let commit_data: CommitData = deserialize(&value)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                Ok(Some(commit_data.sub_dag))
            },
            None => Ok(None),
        }
    }

    pub fn sync(&self) -> io::Result<()> {
        // First flush any pending batch operations
        self.flush()?;

        // Then sync the DB
        let mut sync_opts = WriteOptions::default();
        sync_opts.set_sync(true);
        self.db.write_opt(rocksdb::WriteBatch::default(), &sync_opts)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}