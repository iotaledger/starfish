// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    block_store::BlockStore,
    committee::{Committee, QuorumThreshold, StakeAggregator},
    data::Data,
    types::{
        AuthorityIndex, BlockReference, StatementBlock, TransactionLocator,
    },
};

#[allow(dead_code)]
pub struct FinalizationInterpreter<'a> {
    transaction_aggregator:
        HashMap<BlockReference, HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>>,
    certificate_aggregator: HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>,
    transaction_certificates: HashMap<TransactionLocator, HashSet<BlockReference>>,
    committee: Arc<Committee>,
    block_store: &'a BlockStore,
    finalized_transactions: HashSet<TransactionLocator>,
}

#[allow(dead_code)]
impl<'a> FinalizationInterpreter<'a> {
    pub fn new(block_store: &'a BlockStore, committee: Arc<Committee>) -> Self {
        Self {
            transaction_aggregator: Default::default(),
            certificate_aggregator: Default::default(),
            transaction_certificates: Default::default(),
            committee,
            block_store,
            finalized_transactions: Default::default(),
        }
    }




    fn vote(
        &mut self,
        block: &Data<StatementBlock>,
        transaction: &TransactionLocator,
        tx_voter: AuthorityIndex,
    ) {
        let block_transaction_aggregator = self
            .transaction_aggregator
            .get_mut(block.reference())
            .unwrap();
        if !block_transaction_aggregator.contains_key(transaction) {
            block_transaction_aggregator
                .insert(*transaction, StakeAggregator::<QuorumThreshold>::new());
        }
        if block_transaction_aggregator
            .get_mut(transaction)
            .unwrap()
            .add(tx_voter, &self.committee)
            && !block.epoch_changed()
        {
            // this is a certifying block
            if !self.transaction_certificates.contains_key(transaction) {
                self.transaction_certificates
                    .insert(*transaction, Default::default());
            }
            self.transaction_certificates
                .get_mut(transaction)
                .unwrap()
                .insert(*block.reference());

            if !self.certificate_aggregator.contains_key(transaction) {
                self.certificate_aggregator
                    .insert(*transaction, StakeAggregator::new());
            }

            if self
                .certificate_aggregator
                .get_mut(transaction)
                .unwrap()
                .add(block.author(), &self.committee)
            {
                self.finalized_transactions.insert(*transaction);
            }
        }
    }

    fn transaction_aggregator_for(
        &mut self,
        block: &BlockReference,
    ) -> &mut HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>> {
        self.transaction_aggregator.get_mut(block).unwrap()
    }
}
