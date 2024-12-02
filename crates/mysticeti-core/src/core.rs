// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashSet, VecDeque},
    mem,
    sync::{atomic::AtomicU64, Arc},
};
use reed_solomon_simd::ReedSolomonEncoder;
use minibytes::Bytes;

use crate::{
    block_handler::BlockHandler,
    block_manager::BlockManager,
    block_store::{
        BlockStore, BlockWriter, CommitData, OwnBlockData, WAL_ENTRY_COMMIT, WAL_ENTRY_PAYLOAD,
        WAL_ENTRY_STATE,
    },
    committee::Committee,
    config::{NodePrivateConfig, NodePublicConfig},
    consensus::{
        linearizer::CommittedSubDag,
        universal_committer::{UniversalCommitter, UniversalCommitterBuilder},
    },
    crypto::Signer,
    data::Data,
    epoch_close::EpochManager,
    metrics::{Metrics, UtilizationTimerVecExt},
    runtime::timestamp_utc,
    state::RecoveredState,
    threshold_clock::ThresholdClockAggregator,
    types::{AuthorityIndex, BaseStatement, BlockReference, RoundNumber, StatementBlock},
    wal::{WalPosition, WalSyncer, WalWriter},
};
use crate::types::{Encoder, Shard};

pub struct Core<H: BlockHandler> {
    block_manager: BlockManager,
    pending: VecDeque<(WalPosition, MetaStatement)>,
    // For Byzantine node, last_own_block contains a vector of blocks
    last_own_block: Vec<OwnBlockData>,
    block_handler: H,
    authority: AuthorityIndex,
    threshold_clock: ThresholdClockAggregator,
    pub(crate) committee: Arc<Committee>,
    last_commit_leader: BlockReference,
    wal_writer: WalWriter,
    block_store: BlockStore,
    pub(crate) metrics: Arc<Metrics>,
    options: CoreOptions,
    signer: Signer,
    // todo - ugly, probably need to merge syncer and core
    recovered_committed_blocks: Option<(HashSet<BlockReference>, Option<Bytes>)>,
    epoch_manager: EpochManager,
    rounds_in_epoch: RoundNumber,
    committer: UniversalCommitter,
    //coding_engine : reed_solomon_simd::engine::DefaultEngine,
    encoder : Encoder,
}

pub struct CoreOptions {
    fsync: bool,
}

#[derive(Debug, Clone)]
pub enum MetaStatement {
    Include(BlockReference),
    Payload(Vec<BaseStatement>),
}

impl<H: BlockHandler> Core<H> {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        mut block_handler: H,
        authority: AuthorityIndex,
        committee: Arc<Committee>,
        private_config: NodePrivateConfig,
        public_config: &NodePublicConfig,
        metrics: Arc<Metrics>,
        recovered: RecoveredState,
        mut wal_writer: WalWriter,
        options: CoreOptions,
    ) -> Self {
        let RecoveredState {
            block_store,
            last_own_block,
            mut pending,
            state,
            unprocessed_blocks,
            last_committed_leader,
            committed_blocks,
            committed_state,
        } = recovered;
        let mut threshold_clock = ThresholdClockAggregator::new(0);
        let last_own_block = if let Some(own_block) = last_own_block {
            for (_, pending_block) in pending.iter() {
                if let MetaStatement::Include(include) = pending_block {
                    threshold_clock.add_block(*include, &committee);
                }
            }
            own_block
        } else {
            // todo(fix) - this technically has a race condition if node crashes after genesis
            assert!(pending.is_empty());
            // Initialize empty block store
            // A lot of this code is shared with Self::add_blocks, this is not great and some code reuse would be great
            let (own_genesis_block, other_genesis_blocks) = committee.genesis_blocks(authority);
            assert_eq!(own_genesis_block.author(), authority);
            let mut block_writer = (&mut wal_writer, &block_store);
            for block in other_genesis_blocks {
                let reference = *block.reference();
                threshold_clock.add_block(reference, &committee);
                let position = block_writer.insert_block(block);
                pending.push_back((position, MetaStatement::Include(reference)));
            }
            threshold_clock.add_block(*own_genesis_block.reference(), &committee);
            let own_block_data = OwnBlockData {
                next_entry: WalPosition::MAX,
                block: own_genesis_block,
            };
            block_writer.insert_own_block(&own_block_data, 0, committee.len() as AuthorityIndex);
            own_block_data
        };
        let block_manager = BlockManager::new(block_store.clone(), &committee);

        if let Some(state) = state {
            block_handler.recover_state(&state);
        }

        let epoch_manager = EpochManager::new();

        let committer =
            UniversalCommitterBuilder::new(committee.clone(), block_store.clone(), metrics.clone())
                .with_number_of_leaders(public_config.parameters.number_of_leaders)
                .with_pipeline(public_config.parameters.enable_pipelining)
                .build();
        tracing::info!(
            "Pipeline enabled: {}",
            public_config.parameters.enable_pipelining
        );
        tracing::info!(
            "Number of leaders: {}",
            public_config.parameters.number_of_leaders
        );
        let encoder = ReedSolomonEncoder::new(2,
                                              4,
                                              64).unwrap();
        let mut this = Self {
            block_manager,
            pending,
            last_own_block: vec![last_own_block],
            block_handler,
            authority,
            threshold_clock,
            committee,
            last_commit_leader: last_committed_leader.unwrap_or_default(),
            wal_writer,
            block_store,
            metrics,
            options,
            signer: private_config.keypair,
            recovered_committed_blocks: Some((committed_blocks, committed_state)),
            epoch_manager,
            rounds_in_epoch: public_config.parameters.rounds_in_epoch,
            committer,
            encoder,
        };

        if !unprocessed_blocks.is_empty() {
            tracing::info!(
                "Replaying {} blocks for transaction aggregator",
                unprocessed_blocks.len()
            );
        }

        this
    }

    pub fn get_universal_committer(&self) -> UniversalCommitter {
        self.committer.clone()
    }

    pub fn with_options(mut self, options: CoreOptions) -> Self {
        self.options = options;
        self
    }

    // Note that generally when you update this function you also want to change genesis initialization above
    pub fn add_blocks(&mut self, blocks: Vec<Data<StatementBlock>>) -> Vec<Data<StatementBlock>> {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::add_blocks");
        let processed = self
            .block_manager
            .add_blocks(blocks, &mut (&mut self.wal_writer, &self.block_store));
        let mut result = Vec::with_capacity(processed.len());
        for (position, processed) in processed.into_iter() {
            self.threshold_clock
                .add_block(*processed.reference(), &self.committee);
            self.pending
                .push_back((position, MetaStatement::Include(*processed.reference())));
            result.push(processed);
        }
        result
    }


    pub fn try_new_block(&mut self) -> Option<Data<StatementBlock>> {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Core::try_new_block");
        let clock_round = self.threshold_clock.get_round();
        if clock_round <= self.last_proposed() {
            return None;
        }
        let first_include_index = self
            .pending
            .iter()
            .position(|(_, statement)| match statement {
                MetaStatement::Include(block_ref) => block_ref.round >= clock_round,
                _ => false,
            })
            .unwrap_or(self.pending.len());

        let mut taken = self.pending.split_off(first_include_index);
        // Split off returns the "tail", what we want is keep the tail in "pending" and get the head
        mem::swap(&mut taken, &mut self.pending);

        let mut blocks = vec![];
        if self.block_store.byzantine_strategy.is_some() && self.last_own_block.len() < self.committee.len() {
            for _j in self.last_own_block.len()..self.committee.len() {
                self.last_own_block.push(self.last_own_block[0].clone());
            }
        }
        let mut statements =  Vec::new();
        for (_, statement) in taken.clone().into_iter() {
            match statement {
                MetaStatement::Include(include) => {
                }
                MetaStatement::Payload(payload) => {
                    if self.block_store.byzantine_strategy.is_none() && !self.epoch_changing() {
                        statements.extend(payload);
                    }
                }
            }
        }
        let info_length = self.committee.len() / 3 + 1;
        let parity_length = self.committee.len() - 1 - self.committee.len() / 3;
        let encoded_statements = self.encode(statements, info_length, parity_length);
        for j in 0..self.last_own_block.len() {
            // Compress the references in the block
            // Iterate through all the include statements in the block, and make a set of all the references in their includes.
            let mut references_in_block: HashSet<BlockReference> = HashSet::new();
            references_in_block.extend(self.last_own_block[j].block.includes());
            for (_, statement) in &taken {
                if let MetaStatement::Include(block_ref) = statement {
                    // for all the includes in the block, add the references in the block to the set
                    if let Some(block) = self.block_store.get_block(*block_ref) {
                        references_in_block.extend(block.includes());
                    }
                }
            }
            let mut includes = vec![];
            includes.push(*self.last_own_block[j].block.reference());
            for (_, statement) in taken.clone().into_iter() {
                match statement {
                    MetaStatement::Include(include) => {
                        if !references_in_block.contains(&include)
                            && include.authority != self.authority
                        {
                            includes.push(include);
                        }
                    }
                    MetaStatement::Payload(payload) => {

                    }
                }
            }

            assert!(!includes.is_empty());
            let time_ns = timestamp_utc().as_nanos() + j as u128;
            // Todo change this once we track known transactions
            let acknowledgement_statements = includes.clone();
            let new_block = StatementBlock::new_with_signer(
                self.authority,
                clock_round,
                includes.clone(),
                acknowledgement_statements,
                time_ns,
                self.epoch_changing(),
                &self.signer,
                encoded_statements.clone(),
            );
            blocks.push(new_block);
        }

        let mut return_blocks = vec![];
        let mut authority_bounds = vec![0];
        for i in 1..=blocks.len() {
            authority_bounds.push(i * self.committee.len() / blocks.len());
        }
        self.last_own_block = vec![];
        let mut block_id = 0;
        for block in blocks {
            assert_eq!(
                block.includes().get(0).unwrap().authority,
                self.authority,
                "Invalid block {}",
                block.clone()
            );

            let block = Data::new(block);
            if block.serialized_bytes().len() > crate::wal::MAX_ENTRY_SIZE / 2 {
                // Sanity check for now
                panic!(
                    "Created an oversized block (check all limits set properly: {} > {}): {:?}",
                    block.serialized_bytes().len(),
                    crate::wal::MAX_ENTRY_SIZE / 2,
                    block.detailed()
                );
            }
            self.threshold_clock
                .add_block(*block.reference(), &self.committee);
            self.proposed_block_stats(&block);
            let next_entry = if let Some((pos, _)) = self.pending.get(0) {
                *pos
            } else {
                WalPosition::MAX
            };
            self.last_own_block.push(OwnBlockData {
                next_entry,
                block: block.clone(),
            });
            (&mut self.wal_writer, &self.block_store).insert_own_block(
                &self.last_own_block.last().unwrap(),
                authority_bounds[block_id] as AuthorityIndex,
                authority_bounds[block_id + 1] as AuthorityIndex,
            );

            if self.options.fsync {
                self.wal_writer.sync().expect("Wal sync failed");
            }

            tracing::debug!("Created block {block:?}");
            return_blocks.push(block);
            block_id += 1;
        }
        Some(return_blocks[0].clone())
    }


    pub fn encode(&mut self, block: Vec<BaseStatement>, info_length: usize, parity_length: usize) -> Vec<Option<Shard>> {
        let mut serialized = bincode::serialize(&block).expect("Serialization of statements before encoding failed");
        let bytes_length = serialized.len();
        let mut statements_with_len:Vec<u8> = (bytes_length as u32).to_le_bytes().to_vec();
        statements_with_len.append(&mut serialized);
        let mut shard_bytes = (bytes_length + info_length - 1) / info_length;
        //shard_bytes should be divisible by 64 in version 2.2.2
        //it only needs to be even in a new version 3.0.1, but it requires a newer version of rust 1.80
        if shard_bytes % 64 != 0 {
            shard_bytes += 64 - shard_bytes % 64;
        }
        let length_with_padding = shard_bytes * info_length;
        statements_with_len.resize(length_with_padding, 0);
        let mut data : Vec<Option<Shard>> = statements_with_len.chunks(shard_bytes).map(|chunk| Some(chunk.to_vec())).collect();
        self.encoder.reset(info_length, parity_length, shard_bytes).expect("reset failed");
        for shard in data.clone() {
            self.encoder.add_original_shard(shard.unwrap()).expect("Adding shard failed");
        }
        let result = self.encoder.encode().expect("Encoding failed");
        let recovery: Vec<Option<Shard>> = result.recovery_iter().map(|slice| Some(slice.to_vec())).collect();
        data.extend(recovery);
        data
    }

    pub fn wal_syncer(&self) -> WalSyncer {
        self.wal_writer
            .syncer()
            .expect("Failed to create wal syncer")
    }

    fn proposed_block_stats(&self, block: &Data<StatementBlock>) {
        self.metrics
            .proposed_block_size_bytes
            .observe(block.serialized_bytes().len());
    }

    pub fn try_commit(&mut self) -> Vec<Data<StatementBlock>> {
        let sequence: Vec<_> = self
            .committer
            .try_commit(self.last_commit_leader)
            .into_iter()
            .filter_map(|leader| leader.into_decided_block())
            .collect();

        if let Some(last) = sequence.last() {
            self.last_commit_leader = *last.reference();
        }

        // todo: should ideally come from execution result of epoch smart contract
        if self.last_commit_leader.round() > self.rounds_in_epoch {
            self.epoch_manager.epoch_change_begun();
        }

        sequence
    }

    pub fn cleanup(&self) {
        const RETAIN_BELOW_COMMIT_ROUNDS: RoundNumber = 100;

        self.block_store.cleanup(
            self.last_commit_leader
                .round()
                .saturating_sub(RETAIN_BELOW_COMMIT_ROUNDS),
        );

        self.block_handler.cleanup();
    }

    /// This only checks readiness in terms of helping liveness for commit rule,
    /// try_new_block might still return None if threshold clock is not ready
    ///
    /// The algorithm to calling is roughly: if timeout || commit_ready_new_block then try_new_block(..)
    pub fn ready_new_block(
        &self,
        period: u64,
        connected_authorities: &HashSet<AuthorityIndex>,
    ) -> bool {
        let quorum_round = self.threshold_clock.get_round();

        // Leader round we check if we have a leader block
        if quorum_round > self.last_commit_leader.round().max(period - 1) {
            let leader_round = quorum_round - 1;
            let mut leaders = self.committer.get_leaders(leader_round);
            leaders.retain(|leader| connected_authorities.contains(leader));
            self.block_store
                .all_blocks_exists_at_authority_round(&leaders, leader_round)
        } else {
            false
        }
    }

    pub fn handle_committed_subdag(
        &mut self,
        committed: Vec<CommittedSubDag>,
        state: &Bytes,
    ) -> Vec<CommitData> {
        let mut commit_data = vec![];
        for commit in &committed {
            for block in &commit.blocks {
                self.epoch_manager
                    .observe_committed_block(block, &self.committee);
            }
            commit_data.push(CommitData::from(commit));
        }
        self.write_state(); // todo - this can be done less frequently to reduce IO
        self.write_commits(&commit_data, state);
        // todo - We should also persist state of the epoch manager, otherwise if validator
        // restarts during epoch change it will fork on the epoch change state.
        commit_data
    }

    pub fn write_state(&mut self) {
        #[cfg(feature = "simulator")]
        if self.block_handler().state().len() >= crate::wal::MAX_ENTRY_SIZE {
            // todo - this is something needs a proper fix
            // Need to revisit this after we have a proper synchronizer
            // We need to put some limit/backpressure on the accumulator state
            return;
        }
        self.wal_writer
            .write(WAL_ENTRY_STATE, &self.block_handler().state())
            .expect("Write to wal has failed");
    }

    pub fn write_commits(&mut self, commits: &[CommitData], state: &Bytes) {
        let commits = bincode::serialize(&(commits, state)).expect("Commits serialization failed");
        self.wal_writer
            .write(WAL_ENTRY_COMMIT, &commits)
            .expect("Write to wal has failed");
    }

    pub fn take_recovered_committed_blocks(&mut self) -> (HashSet<BlockReference>, Option<Bytes>) {
        self.recovered_committed_blocks
            .take()
            .expect("take_recovered_committed_blocks called twice")
    }

    pub fn block_store(&self) -> &BlockStore {
        &self.block_store
    }

    // This function is needed only for signalling that we created a new block
    pub fn last_own_block(&self) -> &Data<StatementBlock> {
        &self.last_own_block[0].block
    }

    // This function is needed only for retrieving the last round of a block we proposed
    pub fn last_proposed(&self) -> RoundNumber {
        self.last_own_block[0].block.round()
    }

    pub fn authority(&self) -> AuthorityIndex {
        self.authority
    }

    pub fn block_handler(&self) -> &H {
        &self.block_handler
    }

    pub fn block_manager(&self) -> &BlockManager {
        &self.block_manager
    }

    pub fn block_handler_mut(&mut self) -> &mut H {
        &mut self.block_handler
    }

    pub fn committee(&self) -> &Arc<Committee> {
        &self.committee
    }

    pub fn epoch_closed(&self) -> bool {
        self.epoch_manager.closed()
    }

    pub fn epoch_changing(&self) -> bool {
        self.epoch_manager.changing()
    }

    pub fn epoch_closing_time(&self) -> Arc<AtomicU64> {
        self.epoch_manager.closing_time()
    }
}

impl Default for CoreOptions {
    fn default() -> Self {
        Self::test()
    }
}

impl CoreOptions {
    pub fn test() -> Self {
        Self { fsync: false }
    }

    pub fn production() -> Self {
        Self { fsync: true }
    }
}

#[cfg(test)]
mod test {
    use std::fmt::Write;

    use rand::{prelude::StdRng, Rng, SeedableRng};

    use super::*;
    use crate::{
        test_util::{honest_committee_and_cores, honest_committee_and_cores_persisted},
        threshold_clock,
    };

    #[test]
    fn test_core_simple_exchange() {
        let (_committee, mut cores, _) = honest_committee_and_cores(4);

        let mut proposed_transactions = vec![];
        let mut blocks = vec![];
        for core in &mut cores {
            let block = core
                .try_new_block()
                .expect("Must be able to create block after genesis");
            assert_eq!(block.reference().round, 1);
            proposed_transactions.extend(core.block_handler.proposed.drain(..));
            eprintln!("{}: {}", core.authority, block);
            blocks.push(block.clone());
        }
        assert_eq!(proposed_transactions.len(), 4);
        let more_blocks = blocks.split_off(1);

        eprintln!("===");

        let mut blocks_r2 = vec![];
        for core in &mut cores {
            core.add_blocks(blocks.clone());
            assert!(core.try_new_block().is_none());
            core.add_blocks(more_blocks.clone());
            let block = core
                .try_new_block()
                .expect("Must be able to create block after full round");
            eprintln!("{}: {}", core.authority, block);
            assert_eq!(block.reference().round, 2);
            blocks_r2.push(block.clone());
        }

        for core in &mut cores {
            core.add_blocks(blocks_r2.clone());
            let block = core
                .try_new_block()
                .expect("Must be able to create block after full round");
            eprintln!("{}: {}", core.authority, block);
            assert_eq!(block.reference().round, 3);
            for txid in &proposed_transactions {
                assert!(
                    core.block_handler.is_certified(txid),
                    "Transaction {} is not certified by {}",
                    txid,
                    core.authority
                );
            }
        }
    }

    #[test]
    fn test_randomized_simple_exchange() {
        'l: for seed in 0..100 {
            let mut rng = StdRng::from_seed([seed; 32]);
            let (committee, mut cores, _) = honest_committee_and_cores(4);

            let mut proposed_transactions = vec![];
            let mut pending: Vec<_> = committee.authorities().map(|_| vec![]).collect();
            for core in &mut cores {
                let block = core
                    .try_new_block()
                    .expect("Must be able to create block after genesis");
                assert_eq!(block.reference().round, 1);
                proposed_transactions.extend(core.block_handler.proposed.drain(..));
                eprintln!("{}: {}", core.authority, block);
                assert!(
                    threshold_clock::threshold_clock_valid_non_genesis(&block, &committee),
                    "Invalid clock {}",
                    block
                );
                push_all(&mut pending, core.authority, &block);
            }
            // Each iteration we pick one authority and deliver to it 1..3 random blocks
            // First 20 iterations we record all transactions created by authorities
            // After this we wait for those recorded transactions to be eventually certified
            'a: for i in 0..1000 {
                let authority = committee.random_authority(&mut rng);
                eprintln!("Iteration {i}, authority {authority}");
                let core = &mut cores[authority as usize];
                let this_pending = &mut pending[authority as usize];
                let c = rng.gen_range(1..4usize);
                let mut blocks = vec![];
                let mut deliver = String::new();
                for _ in 0..c {
                    if this_pending.is_empty() {
                        break;
                    }
                    let block = this_pending.remove(rng.gen_range(0..this_pending.len()));
                    write!(deliver, "{}, ", block).ok();
                    blocks.push(block);
                }
                if blocks.is_empty() {
                    eprintln!("No pending blocks for {authority}");
                    continue;
                }
                eprint!("Deliver {deliver} to {authority} => ");
                core.add_blocks(blocks);
                let Some(block) = core.try_new_block() else {
                    eprintln!("No new block");
                    continue;
                };
                assert!(
                    threshold_clock::threshold_clock_valid_non_genesis(&block, &committee),
                    "Invalid clock {}",
                    block
                );
                eprintln!("Created {block}");
                push_all(&mut pending, core.authority, &block);
                if i < 20 {
                    // First 20 iterations we record proposed transactions
                    proposed_transactions.extend(core.block_handler.proposed.drain(..));
                    // proposed_transactions.push(core.block_handler.last_transaction());
                } else {
                    assert!(!proposed_transactions.is_empty());
                    // After 20 iterations we just wait for all transactions to be committed everywhere
                    for proposed in &proposed_transactions {
                        for core in &cores {
                            if !core.block_handler.is_certified(proposed) {
                                continue 'a;
                            }
                        }
                    }
                    println!(
                        "Seed {seed} succeed, {} transactions certified in {i} exchanges",
                        proposed_transactions.len()
                    );
                    continue 'l;
                }
            }
            panic!("Seed {seed} failed - not all transactions are committed");
        }
    }

    #[test]
    fn test_core_recovery() {
        let tmp = tempdir::TempDir::new("test_core_recovery").unwrap();
        let (_committee, mut cores, _) = honest_committee_and_cores_persisted(4, Some(tmp.path()));

        let mut proposed_transactions = vec![];
        let mut blocks = vec![];
        for core in &mut cores {
            let block = core
                .try_new_block()
                .expect("Must be able to create block after genesis");
            assert_eq!(block.reference().round, 1);
            proposed_transactions.extend(core.block_handler.proposed.clone());
            eprintln!("{}: {}", core.authority, block);
            blocks.push(block.clone());
        }
        assert_eq!(proposed_transactions.len(), 4);
        cores.iter_mut().for_each(Core::write_state);
        drop(cores);

        let (_committee, mut cores, _) = honest_committee_and_cores_persisted(4, Some(tmp.path()));

        let more_blocks = blocks.split_off(2);

        eprintln!("===");

        let mut blocks_r2 = vec![];
        for core in &mut cores {
            core.add_blocks(blocks.clone());
            assert!(core.try_new_block().is_none());
            core.add_blocks(more_blocks.clone());
            let block = core
                .try_new_block()
                .expect("Must be able to create block after full round");
            eprintln!("{}: {}", core.authority, block);
            assert_eq!(block.reference().round, 2);
            blocks_r2.push(block.clone());
        }

        // Note that we do not call Core::write_state here unlike before.
        // This should also be handled correctly by re-processing unprocessed_blocks
        drop(cores);

        eprintln!("===");

        let (_committee, mut cores, _) = honest_committee_and_cores_persisted(4, Some(tmp.path()));

        for core in &mut cores {
            core.add_blocks(blocks_r2.clone());
            let block = core
                .try_new_block()
                .expect("Must be able to create block after full round");
            eprintln!("{}: {}", core.authority, block);
            assert_eq!(block.reference().round, 3);
            for txid in &proposed_transactions {
                assert!(
                    core.block_handler.is_certified(txid),
                    "Transaction {} is not certified by {}",
                    txid,
                    core.authority
                );
            }
        }
    }

    fn push_all(
        p: &mut Vec<Vec<Data<StatementBlock>>>,
        except: AuthorityIndex,
        block: &Data<StatementBlock>,
    ) {
        for (i, q) in p.iter_mut().enumerate() {
            if i as AuthorityIndex != except {
                q.push(block.clone());
            }
        }
    }
}
