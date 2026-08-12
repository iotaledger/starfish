// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::io;

use serde::{Deserialize, Serialize};

use crate::{
    crypto::BLOCK_DIGEST_SIZE,
    dag_state::CommitData,
    data::Data,
    types::{BlockReference, MAX_COMMITTEE_SIZE, ProvableShard, RoundNumber, VerifiedBlock},
};

/// Durable acknowledgement that Core applied one RBC-DAG committed frontier.
///
/// This is a single, bounded latest-value cursor rather than an append-only
/// history. `carrier_anchor` is intentionally independent of application block
/// storage: an RBC-DAG consensus carrier is not necessarily a Core block. The
/// per-authority watermark lets Core restore commit progress without scanning
/// application references.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RbcDagFrontierReceipt {
    pub(crate) carrier_anchor: BlockReference,
    /// Monotone one-based position in the authoritative frontier output
    /// stream. This is intentionally independent of the anchor's logical
    /// consensus round, which may regress when a later certifier resolves an
    /// older leader.
    pub(crate) output_sequence: RoundNumber,
    pub(crate) committed_rounds: Vec<RoundNumber>,
}

impl RbcDagFrontierReceipt {
    const ENCODING_MAGIC: [u8; 4] = *b"RDF1";
    const FIXED_ENCODED_LEN: usize = Self::ENCODING_MAGIC.len()
        + std::mem::size_of::<RoundNumber>()
        + std::mem::size_of::<u16>()
        + BLOCK_DIGEST_SIZE
        + std::mem::size_of::<RoundNumber>()
        + std::mem::size_of::<u16>();
    const MAX_ENCODED_LEN: usize =
        Self::FIXED_ENCODED_LEN + MAX_COMMITTEE_SIZE as usize * std::mem::size_of::<RoundNumber>();

    fn validate(&self, error_kind: io::ErrorKind) -> io::Result<()> {
        if self.output_sequence == 0 {
            return Err(io::Error::new(
                error_kind,
                "RBC-DAG frontier receipt output sequence must be nonzero",
            ));
        }
        if self.committed_rounds.is_empty()
            || self.committed_rounds.len() > usize::from(MAX_COMMITTEE_SIZE)
        {
            return Err(io::Error::new(
                error_kind,
                format!(
                    "RBC-DAG frontier receipt must contain 1..={MAX_COMMITTEE_SIZE} committed-round watermarks, got {}",
                    self.committed_rounds.len()
                ),
            ));
        }
        if self.carrier_anchor.authority >= MAX_COMMITTEE_SIZE {
            return Err(io::Error::new(
                error_kind,
                format!(
                    "RBC-DAG frontier receipt carrier authority {} exceeds the maximum {}",
                    self.carrier_anchor.authority,
                    MAX_COMMITTEE_SIZE - 1
                ),
            ));
        }
        Ok(())
    }

    pub(crate) fn to_bytes(&self) -> io::Result<Vec<u8>> {
        self.validate(io::ErrorKind::InvalidInput)?;

        let mut bytes = Vec::with_capacity(
            Self::FIXED_ENCODED_LEN
                + self.committed_rounds.len() * std::mem::size_of::<RoundNumber>(),
        );
        bytes.extend_from_slice(&Self::ENCODING_MAGIC);
        bytes.extend_from_slice(&self.carrier_anchor.round.to_le_bytes());
        bytes.extend_from_slice(&self.carrier_anchor.authority.to_le_bytes());
        bytes.extend_from_slice(self.carrier_anchor.digest.as_array());
        bytes.extend_from_slice(&self.output_sequence.to_le_bytes());
        let watermark_count = u16::try_from(self.committed_rounds.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "RBC-DAG frontier receipt watermark count is not encodable",
            )
        })?;
        bytes.extend_from_slice(&watermark_count.to_le_bytes());
        for round in &self.committed_rounds {
            bytes.extend_from_slice(&round.to_le_bytes());
        }

        Ok(bytes)
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if !(Self::FIXED_ENCODED_LEN..=Self::MAX_ENCODED_LEN).contains(&bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored RBC-DAG frontier receipt has an invalid encoded length",
            ));
        }
        if bytes[..Self::ENCODING_MAGIC.len()] != Self::ENCODING_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored RBC-DAG frontier receipt has an unsupported encoding",
            ));
        }

        let mut cursor = Self::ENCODING_MAGIC.len();
        let take_u32 = |bytes: &[u8], cursor: &mut usize| {
            let mut encoded = [0; std::mem::size_of::<u32>()];
            let end = *cursor + std::mem::size_of::<u32>();
            encoded.copy_from_slice(&bytes[*cursor..end]);
            *cursor = end;
            u32::from_le_bytes(encoded)
        };
        let take_u16 = |bytes: &[u8], cursor: &mut usize| {
            let mut encoded = [0; std::mem::size_of::<u16>()];
            let end = *cursor + std::mem::size_of::<u16>();
            encoded.copy_from_slice(&bytes[*cursor..end]);
            *cursor = end;
            u16::from_le_bytes(encoded)
        };

        let carrier_round = take_u32(bytes, &mut cursor);
        let carrier_authority = take_u16(bytes, &mut cursor);
        let mut carrier_digest = [0; BLOCK_DIGEST_SIZE];
        carrier_digest.copy_from_slice(&bytes[cursor..cursor + BLOCK_DIGEST_SIZE]);
        cursor += BLOCK_DIGEST_SIZE;
        let output_sequence = take_u32(bytes, &mut cursor);
        let watermark_count = usize::from(take_u16(bytes, &mut cursor));
        if watermark_count == 0 || watermark_count > usize::from(MAX_COMMITTEE_SIZE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored RBC-DAG frontier receipt has an invalid watermark count",
            ));
        }
        let expected_len =
            Self::FIXED_ENCODED_LEN + watermark_count * std::mem::size_of::<RoundNumber>();
        if bytes.len() != expected_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored RBC-DAG frontier receipt length does not match its watermark count",
            ));
        }

        let mut committed_rounds = Vec::with_capacity(watermark_count);
        for _ in 0..watermark_count {
            committed_rounds.push(take_u32(bytes, &mut cursor));
        }
        let receipt = Self {
            carrier_anchor: BlockReference {
                round: carrier_round,
                authority: carrier_authority,
                digest: carrier_digest.into(),
            },
            output_sequence,
            committed_rounds,
        };
        receipt.validate(io::ErrorKind::InvalidData)?;
        Ok(receipt)
    }
}

/// Validate the exact atomic frontier write shape shared by every backend.
/// A nonempty batch contains precisely the current delta under its carrier
/// anchor; an empty batch is an explicit control-only marker.
pub(crate) fn validate_rbc_dag_frontier_commit_batch(
    committed_sub_dags: &[CommitData],
    receipt: &RbcDagFrontierReceipt,
) -> io::Result<()> {
    receipt.validate(io::ErrorKind::InvalidInput)?;
    if committed_sub_dags.len() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RBC-DAG frontier receipt batch must contain at most one application commit",
        ));
    }
    if let Some(commit) = committed_sub_dags.first() {
        if commit.sub_dag.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RBC-DAG frontier application commit must contain at least one application",
            ));
        }
        if commit.leader != receipt.carrier_anchor {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RBC-DAG frontier application commit leader must equal the receipt carrier anchor",
            ));
        }
        if commit.committed_rounds != receipt.committed_rounds {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RBC-DAG frontier application commit watermarks must equal the receipt watermarks",
            ));
        }
    }
    Ok(())
}

/// Backend-agnostic storage interface for consensus blocks and commit data.
///
/// Implementations must be thread-safe (`Send + Sync`).
/// Two implementations exist:
/// - `RocksStore` (default) — RocksDB-backed
/// - `TideHunterStore` (feature `tidehunter`) — TideHunter WAL-backed
pub trait Store: Send + Sync + 'static {
    fn store_block(&self, block: Data<VerifiedBlock>) -> io::Result<()>;

    fn get_block(&self, reference: &BlockReference) -> io::Result<Option<Data<VerifiedBlock>>>;

    fn get_blocks(
        &self,
        references: &[BlockReference],
    ) -> io::Result<Vec<Option<Data<VerifiedBlock>>>> {
        references
            .iter()
            .map(|reference| self.get_block(reference))
            .collect()
    }

    fn get_blocks_by_round(&self, round: RoundNumber) -> io::Result<Vec<Data<VerifiedBlock>>>;

    fn store_commits(&self, committed_sub_dags: Vec<CommitData>) -> io::Result<()>;

    /// Atomically persist zero or more application commits and advance the
    /// latest applied RBC-DAG frontier cursor. The carrier anchor is a
    /// consensus-layer identity and is intentionally independent of any
    /// application commit leader. A successful receipt read implies that all
    /// commit data passed to this call is durable in the same batch.
    fn store_commits_with_rbc_dag_receipt(
        &self,
        committed_sub_dags: Vec<CommitData>,
        receipt: RbcDagFrontierReceipt,
    ) -> io::Result<()>;

    fn get_commit(&self, reference: &BlockReference) -> io::Result<Option<CommitData>>;

    /// Point-read the latest applied RBC-DAG frontier cursor in O(1).
    fn read_latest_rbc_dag_frontier_receipt(&self) -> io::Result<Option<RbcDagFrontierReceipt>>;

    // -- Component-level writes (pre-serialized) --
    // Accept raw bincode bytes produced off the core thread by
    // `VerifiedBlock::preserialize()` or shard reconstructor workers.

    fn store_header_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()>;

    fn store_tx_data_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()>;

    fn store_shard_data_bytes(&self, reference: &BlockReference, bytes: &[u8]) -> io::Result<()>;

    fn get_shard_data(&self, reference: &BlockReference) -> io::Result<Option<ProvableShard>>;

    fn get_shard_data_batch(
        &self,
        references: &[BlockReference],
    ) -> io::Result<Vec<Option<ProvableShard>>> {
        references
            .iter()
            .map(|reference| self.get_shard_data(reference))
            .collect()
    }

    /// Return the most recently stored commit (highest leader round).
    fn read_last_commit(&self) -> io::Result<Option<CommitData>>;

    /// Return all blocks from `from_round` onward (inclusive), across all
    /// authorities.
    fn scan_blocks_from_round(
        &self,
        from_round: RoundNumber,
    ) -> io::Result<Vec<Data<VerifiedBlock>>>;

    /// Persist a batch of dual-DAG clean block references.
    fn store_dual_dag_clean_refs(&self, refs: &[BlockReference]) -> io::Result<()>;

    /// Return all persisted dual-DAG clean block references from
    /// `from_round` onward (inclusive).
    fn scan_dual_dag_clean_refs_from_round(
        &self,
        from_round: RoundNumber,
    ) -> io::Result<Vec<BlockReference>>;
}

#[cfg(test)]
mod tests {
    use super::{RbcDagFrontierReceipt, validate_rbc_dag_frontier_commit_batch};
    use crate::{dag_state::CommitData, types::BlockReference};

    #[test]
    fn rbc_dag_receipt_encoding_is_exact_and_bounded() {
        let receipt = RbcDagFrontierReceipt {
            carrier_anchor: BlockReference::new_test(3, 255),
            output_sequence: 256,
            committed_rounds: vec![250, 251, 252, 253],
        };
        let encoded = receipt.to_bytes().unwrap();
        assert_eq!(
            encoded.len(),
            RbcDagFrontierReceipt::FIXED_ENCODED_LEN
                + receipt.committed_rounds.len() * std::mem::size_of::<u32>()
        );
        assert_eq!(
            RbcDagFrontierReceipt::from_bytes(&encoded).unwrap(),
            receipt
        );

        let mut trailing_byte = encoded.clone();
        trailing_byte.push(0);
        assert_eq!(
            RbcDagFrontierReceipt::from_bytes(&trailing_byte)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );

        let mut mismatched_count = encoded;
        let count_offset = RbcDagFrontierReceipt::FIXED_ENCODED_LEN - std::mem::size_of::<u16>();
        mismatched_count[count_offset..count_offset + std::mem::size_of::<u16>()]
            .copy_from_slice(&5u16.to_le_bytes());
        assert_eq!(
            RbcDagFrontierReceipt::from_bytes(&mismatched_count)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );

        let zero_sequence = RbcDagFrontierReceipt {
            carrier_anchor: BlockReference::new_test(0, 1),
            output_sequence: 0,
            committed_rounds: vec![0; 4],
        };
        assert_eq!(
            zero_sequence.to_bytes().unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn rbc_dag_frontier_commit_rejects_present_empty_application_data() {
        let anchor = BlockReference::new_test(2, 7);
        let receipt = RbcDagFrontierReceipt {
            carrier_anchor: anchor,
            output_sequence: 1,
            committed_rounds: vec![0; 4],
        };
        let empty_commit = CommitData {
            leader: anchor,
            sub_dag: Vec::new(),
            committed_rounds: receipt.committed_rounds.clone(),
        };

        assert_eq!(
            validate_rbc_dag_frontier_commit_batch(&[empty_commit], &receipt)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert!(validate_rbc_dag_frontier_commit_batch(&[], &receipt).is_ok());
    }
}
