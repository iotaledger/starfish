use std::{
    path::Path,
    io,
    sync::Arc,
};
use rocksdb::{
    DB, Options, ColumnFamilyDescriptor, WriteOptions,
    ReadOptions, DBCompressionType,
};
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};

use crate::types::{
    AuthorityIndex, BlockReference,
    RoundNumber, VerifiedStatementBlock,
};
use crate::data::Data;
use crate::consensus::linearizer::CommittedSubDag;
use crate::committee::{QuorumThreshold, StakeAggregator};

// Column families for different types of data
const CF_BLOCKS: &str = "blocks";
const CF_OWN_BLOCKS: &str = "own_blocks";
const CF_COMMITS: &str = "commits";

#[derive(Serialize, Deserialize)]
struct CommitData {
    sub_dag: CommittedSubDag,
}

pub struct RocksStore {
    db: Arc<DB>,
    write_opts: WriteOptions,
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
        opts.set_max_write_buffer_number(4);

        let mut cf_opts = Options::default();
        cf_opts.set_compression_type(DBCompressionType::Lz4);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_OWN_BLOCKS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_COMMITS, cf_opts),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false); // Async writes for better performance

        Ok(Self {
            db: Arc::new(db),
            write_opts,
        })
    }

    pub fn store_commit(
        &self,
        sub_dag: CommittedSubDag,
    ) -> io::Result<()> {
        let commit_data = CommitData {
            sub_dag,
        };

        let key = serialize(&commit_data.sub_dag.anchor)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let value = serialize(&commit_data)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let cf_commits = self.db.cf_handle(CF_COMMITS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        self.db.put_cf_opt(&cf_commits, key, value, &self.write_opts)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    pub fn get_commit(&self, reference: &BlockReference) -> io::Result<Option<CommittedSubDag>> {
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

    pub fn get_commits_after_round(&self, from_round: RoundNumber) -> io::Result<Vec<CommittedSubDag>> {
        let cf_commits = self.db.cf_handle(CF_COMMITS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        let mut commits = Vec::new();
        let mut iter = self.db.raw_iterator_cf_opt(&cf_commits, Self::get_read_opts());
        iter.seek_to_first();

        while iter.valid() {
            let value = iter.value().unwrap();
            let commit_data: CommitData = deserialize(value)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            if commit_data.sub_dag.anchor.round > from_round {
                commits.push(commit_data.sub_dag);
            }

            iter.next();
        }

        Ok(commits)
    }

    // Store block methods...
    pub fn store_block(
        &self,
        block: &Data<VerifiedStatementBlock>,
        authority_index_start: AuthorityIndex,
        authority_index_end: AuthorityIndex,
    ) -> io::Result<()> {
        let reference = block.reference();
        let key = serialize(&reference)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let value = block.serialized_bytes();

        let cf_blocks = self.db.cf_handle(CF_BLOCKS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        self.db.put_cf_opt(&cf_blocks, key.clone(), value, &self.write_opts)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Store own block reference if needed
        if authority_index_start < authority_index_end {
            let cf_own = self.db.cf_handle(CF_OWN_BLOCKS)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

            let own_key = serialize(&(reference.round, authority_index_start, authority_index_end))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            self.db.put_cf_opt(&cf_own, own_key, key, &self.write_opts)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }

        Ok(())
    }

    pub fn get_block(&self, reference: &BlockReference) -> io::Result<Option<Data<VerifiedStatementBlock>>> {
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
        let cf_blocks = self.db.cf_handle(CF_BLOCKS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        let mut blocks = Vec::new();
        let mut iter = self.db.raw_iterator_cf_opt(&cf_blocks, Self::get_read_opts());
        iter.seek_to_first();

        while iter.valid() {
            let key_bytes = iter.key().unwrap().to_vec(); // Clone the key
            let value = iter.value().unwrap().to_vec();   // Clone the value

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

        Ok(blocks)
    }

    pub fn get_own_blocks_after_round(
        &self,
        from_round: RoundNumber,
        limit: usize,
    ) -> io::Result<Vec<Data<VerifiedStatementBlock>>> {
        let cf_own = self.db.cf_handle(CF_OWN_BLOCKS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        let mut blocks = Vec::with_capacity(limit);
        let mut iter = self.db.raw_iterator_cf_opt(&cf_own, Self::get_read_opts());
        iter.seek_to_first();

        while iter.valid() && blocks.len() < limit {
            let key_bytes = iter.key().unwrap();
            let (round, _, _): (RoundNumber, AuthorityIndex, AuthorityIndex) = deserialize(key_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            if round > from_round {
                let block_key = iter.value().unwrap();
                let block = self.get_block_by_key(block_key)?;
                if let Some(block) = block {
                    blocks.push(block);
                }
            }

            iter.next();
        }

        Ok(blocks)
    }

    fn get_block_by_key(&self, key_bytes: &[u8]) -> io::Result<Option<Data<VerifiedStatementBlock>>> {
        let cf_blocks = self.db.cf_handle(CF_BLOCKS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        match self.db.get_cf_opt(&cf_blocks, key_bytes, &Self::get_read_opts())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))? {
            Some(value) => Data::from_bytes(value.into())
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            None => Ok(None),
        }
    }

    pub fn cleanup_before_round(&self, threshold_round: RoundNumber) -> io::Result<()> {
        let cf_blocks = self.db.cf_handle(CF_BLOCKS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        let cf_own = self.db.cf_handle(CF_OWN_BLOCKS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        let cf_commits = self.db.cf_handle(CF_COMMITS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Column family not found"))?;

        let mut batch = rocksdb::WriteBatch::default();

        // Delete old blocks
        let mut iter = self.db.raw_iterator_cf_opt(&cf_blocks, Self::get_read_opts());
        iter.seek_to_first();

        while iter.valid() {
            let key_bytes = iter.key().unwrap();
            let reference: BlockReference = deserialize(key_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            if reference.round <= threshold_round {
                batch.delete_cf(&cf_blocks, key_bytes);
            } else {
                break;
            }

            iter.next();
        }

        // Delete old own block references
        let mut iter = self.db.raw_iterator_cf_opt(&cf_own, Self::get_read_opts());
        iter.seek_to_first();

        while iter.valid() {
            let key_bytes = iter.key().unwrap();
            let (round, _, _): (RoundNumber, AuthorityIndex, AuthorityIndex) = deserialize(key_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            if round <= threshold_round {
                batch.delete_cf(&cf_own, key_bytes);
            } else {
                break;
            }

            iter.next();
        }

        // Delete old commits
        let mut iter = self.db.raw_iterator_cf_opt(&cf_commits, Self::get_read_opts());
        iter.seek_to_first();

        while iter.valid() {
            let value = iter.value().unwrap();
            let commit_data: CommitData = deserialize(value)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            if commit_data.sub_dag.anchor.round <= threshold_round {
                batch.delete_cf(&cf_commits, iter.key().unwrap());
            } else {
                break;
            }

            iter.next();
        }

        self.db.write_opt(batch, &self.write_opts)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    pub fn sync(&self) -> io::Result<()> {
        let mut sync_opts = WriteOptions::default();
        sync_opts.set_sync(true);
        self.db.write_opt(rocksdb::WriteBatch::default(), &sync_opts)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}