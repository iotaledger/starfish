// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Durable, opaque-record WAL for Starfish-RBC-DAG shadow state.
//!
//! The storage layer deliberately does not encode [`super::journal::JournalEventV1`].
//! A later integration layer owns that versioned codec and the recovery of
//! opaque authentication capabilities. This module supplies the durability
//! boundary underneath it: one batch is one checksummed frame, and a caller
//! may expose the corresponding effects only after [`ShadowWalV1::append_batch`]
//! returns successfully.
//!
//! Recovery discards only a physically short final frame. A fully present
//! frame with a bad header, commit marker, or checksum is reported as
//! corruption even at end-of-file, so acknowledged proof-critical state is
//! never silently erased.

use std::{
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::{ffi::CString, os::unix::ffi::OsStrExt};

use crate::types::AuthorityIndex;

use super::RbcDagContextV1;

const FILE_MAGIC: &[u8; 16] = b"STRFSH_RBCDAGWAL";
const FRAME_MAGIC: u32 = 0x5242_4446; // "RBDF"
const FRAME_COMMIT_MAGIC: u32 = 0x434F_4D54; // "COMT"

pub const SHADOW_WAL_FORMAT_VERSION_V1: u16 = 1;
pub const MAX_SHADOW_WAL_RECORD_SIZE_V1: usize = 16 * 1024 * 1024;
pub const MAX_SHADOW_WAL_BATCH_RECORDS_V1: usize = 4_096;
pub const MAX_SHADOW_WAL_FRAME_PAYLOAD_V1: usize = 64 * 1024 * 1024;

const FILE_HEADER_PREFIX_LEN: usize = 16 + 2 + 2 + 32 + 32 + 2 + 2;
const FILE_HEADER_LEN: usize = FILE_HEADER_PREFIX_LEN + 4;
const FRAME_HEADER_PREFIX_LEN: usize = 4 + 2 + 2 + 8 + 8 + 4 + 4;
const FRAME_HEADER_LEN: usize = FRAME_HEADER_PREFIX_LEN + 4;
const FRAME_TRAILER_LEN: usize = 4 + 4;
const MAX_INITIALIZATION_TEMP_ATTEMPTS: usize = 128;

static INITIALIZATION_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShadowWalNamespaceV1 {
    protocol_instance: [u8; 32],
    committee_id: [u8; 32],
    own_authority: AuthorityIndex,
}

impl ShadowWalNamespaceV1 {
    pub fn new(context: RbcDagContextV1, own_authority: AuthorityIndex) -> Self {
        Self {
            protocol_instance: *context.protocol_instance().as_bytes(),
            committee_id: *context.committee_id().as_bytes(),
            own_authority,
        }
    }

    pub fn protocol_instance(&self) -> &[u8; 32] {
        &self.protocol_instance
    }

    pub fn committee_id(&self) -> &[u8; 32] {
        &self.committee_id
    }

    pub fn own_authority(&self) -> AuthorityIndex {
        self.own_authority
    }

    pub fn format_version(&self) -> u16 {
        SHADOW_WAL_FORMAT_VERSION_V1
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredBatchV1 {
    sequence: u64,
    start_offset: u64,
    end_offset: u64,
    records: Vec<Vec<u8>>,
}

impl RecoveredBatchV1 {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }

    pub fn end_offset(&self) -> u64 {
        self.end_offset
    }

    pub fn records(&self) -> &[Vec<u8>] {
        &self.records
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowWalRecoveryV1 {
    batches: Vec<RecoveredBatchV1>,
    durable_file_len: u64,
    record_count: u64,
    discarded_tail_bytes: u64,
}

impl ShadowWalRecoveryV1 {
    pub fn batches(&self) -> &[RecoveredBatchV1] {
        &self.batches
    }

    pub fn batch_count(&self) -> u64 {
        u64::try_from(self.batches.len()).expect("batch count always fits u64")
    }

    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    pub fn durable_file_len(&self) -> u64 {
        self.durable_file_len
    }

    pub fn discarded_tail_bytes(&self) -> u64 {
        self.discarded_tail_bytes
    }

    pub fn records(&self) -> Vec<&[u8]> {
        self.batches
            .iter()
            .flat_map(|batch| batch.records.iter().map(Vec::as_slice))
            .collect()
    }

    pub fn into_records(self) -> Vec<Vec<u8>> {
        self.batches
            .into_iter()
            .flat_map(|batch| batch.records)
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableBatchPositionV1 {
    sequence: u64,
    start_offset: u64,
    end_offset: u64,
    record_count: u32,
}

impl DurableBatchPositionV1 {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }

    pub fn end_offset(&self) -> u64 {
        self.end_offset
    }

    pub fn record_count(&self) -> u32 {
        self.record_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShadowWalSummaryV1 {
    file_len: u64,
    batch_count: u64,
    record_count: u64,
}

impl ShadowWalSummaryV1 {
    pub fn file_len(&self) -> u64 {
        self.file_len
    }

    pub fn batch_count(&self) -> u64 {
        self.batch_count
    }

    pub fn record_count(&self) -> u64 {
        self.record_count
    }
}

#[derive(Debug)]
pub enum ShadowWalErrorV1 {
    Io(io::Error),
    TruncatedFileHeader {
        actual: u64,
        expected: usize,
    },
    InvalidFileMagic,
    UnsupportedFileVersion(u16),
    InvalidFileHeaderLength(u16),
    InvalidFileHeaderFlags(u16),
    InvalidFileHeaderChecksum,
    NamespaceMismatch,
    EmptyBatch,
    TooManyRecords(usize),
    RecordTooLarge(usize),
    FramePayloadTooLarge(usize),
    LengthOverflow,
    CorruptFrame {
        offset: u64,
        reason: &'static str,
    },
    UnexpectedFrameSequence {
        offset: u64,
        expected: u64,
        actual: u64,
    },
    ExternalFileMutation {
        expected: u64,
        actual: u64,
    },
    Poisoned,
}

impl fmt::Display for ShadowWalErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "Starfish-RBC-DAG shadow WAL I/O error: {error}"),
            other => write!(formatter, "Starfish-RBC-DAG shadow WAL error: {other:?}"),
        }
    }
}

impl Error for ShadowWalErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ShadowWalErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct ShadowWalV1 {
    path: PathBuf,
    file: File,
    namespace: ShadowWalNamespaceV1,
    durable_file_len: u64,
    batch_count: u64,
    record_count: u64,
    poisoned: bool,
}

impl ShadowWalV1 {
    /// Open the WAL for exclusive single-writer use and replay every complete
    /// durable batch in sequence order.
    ///
    /// The caller must ensure that no other writer mutates `path` while this
    /// handle is alive. A changed file length is detected before an append,
    /// but this adapter intentionally does not provide cross-process locking.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: ShadowWalNamespaceV1,
    ) -> Result<(Self, ShadowWalRecoveryV1), ShadowWalErrorV1> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = nonempty_parent(&path) {
            create_parent_directories_durable(parent)?;
        }

        let mut file = loop {
            match OpenOptions::new().read(true).write(true).open(&path) {
                Ok(file) => break file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    match fs::symlink_metadata(&path) {
                        Ok(_) => {
                            // A directory entry (for example a dangling
                            // symlink) already exists. Treat it as malformed;
                            // otherwise a no-replace publication retry would
                            // spin forever and might later mask the entry.
                            return Err(error.into());
                        }
                        Err(metadata_error) if metadata_error.kind() == io::ErrorKind::NotFound => {
                        }
                        Err(metadata_error) => return Err(metadata_error.into()),
                    }
                    if let Some(file) = initialize_new_wal(&path, namespace)? {
                        break file;
                    }
                    // Another initializer atomically published `path` first.
                    // Open and validate exactly what won the race; never
                    // replace or repair it here.
                }
                Err(error) => return Err(error.into()),
            }
        };

        let recovery = recover_file(&mut file, namespace)?;
        file.seek(SeekFrom::Start(recovery.durable_file_len))?;
        let wal = Self {
            path,
            file,
            namespace,
            durable_file_len: recovery.durable_file_len,
            batch_count: recovery.batch_count(),
            record_count: recovery.record_count,
            poisoned: false,
        };
        Ok((wal, recovery))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn namespace(&self) -> ShadowWalNamespaceV1 {
        self.namespace
    }

    pub fn file_len(&self) -> u64 {
        self.durable_file_len
    }

    pub fn batch_count(&self) -> u64 {
        self.batch_count
    }

    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Append and fsync one atomic record batch before returning.
    ///
    /// Any seek, write, or fsync failure poisons this handle because the commit
    /// result may be ambiguous. Drop it and reopen the WAL; recovery will
    /// either retain the complete frame or discard its physically short torn
    /// suffix.
    pub fn append_batch(
        &mut self,
        records: &[Vec<u8>],
    ) -> Result<DurableBatchPositionV1, ShadowWalErrorV1> {
        if self.poisoned {
            return Err(ShadowWalErrorV1::Poisoned);
        }
        let sequence = self.batch_count;
        let frame = encode_frame(sequence, records)?;
        let added_records =
            u64::try_from(records.len()).map_err(|_| ShadowWalErrorV1::LengthOverflow)?;
        let next_batch_count = self
            .batch_count
            .checked_add(1)
            .ok_or(ShadowWalErrorV1::LengthOverflow)?;
        let next_record_count = self
            .record_count
            .checked_add(added_records)
            .ok_or(ShadowWalErrorV1::LengthOverflow)?;
        let durable_record_count =
            u32::try_from(records.len()).map_err(|_| ShadowWalErrorV1::LengthOverflow)?;
        let actual_len = self.file.metadata()?.len();
        if actual_len != self.durable_file_len {
            self.poisoned = true;
            return Err(ShadowWalErrorV1::ExternalFileMutation {
                expected: self.durable_file_len,
                actual: actual_len,
            });
        }
        let start_offset = self.durable_file_len;
        let frame_len = u64::try_from(frame.len()).map_err(|_| ShadowWalErrorV1::LengthOverflow)?;
        let end_offset = start_offset
            .checked_add(frame_len)
            .ok_or(ShadowWalErrorV1::LengthOverflow)?;

        if let Err(error) = self
            .file
            .seek(SeekFrom::Start(start_offset))
            .and_then(|_| self.file.write_all(&frame))
            .and_then(|_| self.file.sync_all())
        {
            self.poisoned = true;
            return Err(ShadowWalErrorV1::Io(error));
        }

        self.durable_file_len = end_offset;
        self.batch_count = next_batch_count;
        self.record_count = next_record_count;
        Ok(DurableBatchPositionV1 {
            sequence,
            start_offset,
            end_offset,
            record_count: durable_record_count,
        })
    }

    pub fn summary(&self) -> ShadowWalSummaryV1 {
        ShadowWalSummaryV1 {
            file_len: self.durable_file_len,
            batch_count: self.batch_count,
            record_count: self.record_count,
        }
    }

    /// Flush file metadata and close this writer by consuming it.
    pub fn shutdown(self) -> Result<ShadowWalSummaryV1, ShadowWalErrorV1> {
        self.file.sync_all()?;
        if self.poisoned {
            return Err(ShadowWalErrorV1::Poisoned);
        }
        Ok(self.summary())
    }
}

/// Build a complete, durable header away from the canonical path, then
/// publish it without replacing any concurrently-created target.
///
/// `Ok(None)` means another initializer won the publication race. The caller
/// must open and validate that target rather than assuming it is compatible.
fn initialize_new_wal(
    path: &Path,
    namespace: ShadowWalNamespaceV1,
) -> Result<Option<File>, ShadowWalErrorV1> {
    let (temporary_path, mut file) = create_initialization_temp(path)?;
    let cleanup = InitializationTempCleanup::new(temporary_path.clone());
    file.write_all(&encode_file_header(namespace))?;
    file.sync_all()?;

    match atomic_rename_noreplace(&temporary_path, path) {
        Ok(()) => {
            // The rename makes the complete inode visible atomically; the
            // directory sync makes that name durable across a power loss.
            sync_parent_directory(path)?;
            cleanup.disarm();
            Ok(Some(file))
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn create_initialization_temp(path: &Path) -> io::Result<(PathBuf, File)> {
    let parent = nonempty_parent(path).unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "shadow WAL path has no file name",
        )
    })?;
    for _ in 0..MAX_INITIALIZATION_TEMP_ATTEMPTS {
        let counter = INITIALIZATION_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".init-{}-{counter}.tmp", std::process::id()));
        let temporary_path = parent.join(temporary_name);
        match OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&temporary_path)
        {
            Ok(file) => return Ok((temporary_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique shadow WAL initialization file",
    ))
}

struct InitializationTempCleanup {
    path: PathBuf,
    armed: bool,
}

impl InitializationTempCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for InitializationTempCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn atomic_rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let from = path_to_c_string(from)?;
    let to = path_to_c_string(to)?;
    // SAFETY: both paths are live NUL-terminated C strings for the duration
    // of the call. RENAME_NOREPLACE gives the required atomic no-clobber
    // publication semantics.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(code)
            if code == libc::ENOSYS
                || code == libc::EINVAL
                || code == libc::ENOTSUP
                || code == libc::EOPNOTSUPP)
        {
            atomic_link_noreplace(from.as_bytes(), to.as_bytes())
        } else {
            Err(error)
        }
    }
}

#[cfg(target_vendor = "apple")]
fn atomic_rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let from = path_to_c_string(from)?;
    let to = path_to_c_string(to)?;
    // SAFETY: both paths are live NUL-terminated C strings for the duration
    // of the call. RENAME_EXCL prevents replacement of an existing target.
    let result = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(code) if code == libc::ENOTSUP || code == libc::EINVAL)
        {
            atomic_link_noreplace(from.as_bytes(), to.as_bytes())
        } else {
            Err(error)
        }
    }
}

#[cfg(unix)]
fn path_to_c_string(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "shadow WAL path contains an interior NUL",
        )
    })
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn atomic_link_noreplace(from: &[u8], to: &[u8]) -> io::Result<()> {
    let from = Path::new(std::ffi::OsStr::from_bytes(from));
    let to = Path::new(std::ffi::OsStr::from_bytes(to));
    fs::hard_link(from, to)?;
    // The target now atomically names the fully-synced inode. Failure to
    // remove the private temporary name is harmless to WAL correctness.
    let _ = fs::remove_file(from);
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn atomic_rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    // Portable fallback for platforms without a no-replace rename primitive:
    // same-directory hard-link creation is still an atomic no-clobber publish.
    fs::hard_link(from, to)?;
    let _ = fs::remove_file(from);
    Ok(())
}

fn encode_file_header(namespace: ShadowWalNamespaceV1) -> [u8; FILE_HEADER_LEN] {
    let mut header = [0u8; FILE_HEADER_LEN];
    header[0..16].copy_from_slice(FILE_MAGIC);
    header[16..18].copy_from_slice(&SHADOW_WAL_FORMAT_VERSION_V1.to_be_bytes());
    header[18..20].copy_from_slice(&(FILE_HEADER_LEN as u16).to_be_bytes());
    header[20..52].copy_from_slice(&namespace.protocol_instance);
    header[52..84].copy_from_slice(&namespace.committee_id);
    header[84..86].copy_from_slice(&namespace.own_authority.to_be_bytes());
    header[86..88].copy_from_slice(&0u16.to_be_bytes());
    let checksum = crc32c(&header[..FILE_HEADER_PREFIX_LEN]);
    header[FILE_HEADER_PREFIX_LEN..FILE_HEADER_LEN].copy_from_slice(&checksum.to_be_bytes());
    header
}

fn validate_file_header(
    header: &[u8; FILE_HEADER_LEN],
    expected_namespace: ShadowWalNamespaceV1,
) -> Result<(), ShadowWalErrorV1> {
    if &header[0..16] != FILE_MAGIC {
        return Err(ShadowWalErrorV1::InvalidFileMagic);
    }
    let version = read_u16(&header[16..18]);
    if version != SHADOW_WAL_FORMAT_VERSION_V1 {
        return Err(ShadowWalErrorV1::UnsupportedFileVersion(version));
    }
    let header_len = read_u16(&header[18..20]);
    if usize::from(header_len) != FILE_HEADER_LEN {
        return Err(ShadowWalErrorV1::InvalidFileHeaderLength(header_len));
    }
    let flags = read_u16(&header[86..88]);
    if flags != 0 {
        return Err(ShadowWalErrorV1::InvalidFileHeaderFlags(flags));
    }
    let checksum = read_u32(&header[FILE_HEADER_PREFIX_LEN..FILE_HEADER_LEN]);
    if checksum != crc32c(&header[..FILE_HEADER_PREFIX_LEN]) {
        return Err(ShadowWalErrorV1::InvalidFileHeaderChecksum);
    }
    let actual_namespace = ShadowWalNamespaceV1 {
        protocol_instance: header[20..52]
            .try_into()
            .expect("fixed protocol-instance range"),
        committee_id: header[52..84].try_into().expect("fixed committee range"),
        own_authority: read_u16(&header[84..86]),
    };
    if actual_namespace != expected_namespace {
        return Err(ShadowWalErrorV1::NamespaceMismatch);
    }
    Ok(())
}

fn recover_file(
    file: &mut File,
    namespace: ShadowWalNamespaceV1,
) -> Result<ShadowWalRecoveryV1, ShadowWalErrorV1> {
    let original_len = file.metadata()?.len();
    if original_len < FILE_HEADER_LEN as u64 {
        return Err(ShadowWalErrorV1::TruncatedFileHeader {
            actual: original_len,
            expected: FILE_HEADER_LEN,
        });
    }
    file.seek(SeekFrom::Start(0))?;
    let mut file_header = [0u8; FILE_HEADER_LEN];
    file.read_exact(&mut file_header)?;
    validate_file_header(&file_header, namespace)?;

    let mut batches = Vec::new();
    let mut record_count = 0u64;
    let mut offset = FILE_HEADER_LEN as u64;
    let mut expected_sequence = 0u64;
    while offset < original_len {
        let remaining = original_len - offset;
        if remaining < FRAME_HEADER_LEN as u64 {
            break;
        }

        file.seek(SeekFrom::Start(offset))?;
        let mut frame_header = [0u8; FRAME_HEADER_LEN];
        file.read_exact(&mut frame_header)?;
        validate_frame_header(&frame_header, offset)?;
        let sequence = read_u64(&frame_header[8..16]);
        if sequence != expected_sequence {
            return Err(ShadowWalErrorV1::UnexpectedFrameSequence {
                offset,
                expected: expected_sequence,
                actual: sequence,
            });
        }
        let payload_len_u64 = read_u64(&frame_header[16..24]);
        let payload_len =
            usize::try_from(payload_len_u64).map_err(|_| ShadowWalErrorV1::CorruptFrame {
                offset,
                reason: "payload length does not fit usize",
            })?;
        if payload_len > MAX_SHADOW_WAL_FRAME_PAYLOAD_V1 {
            return Err(ShadowWalErrorV1::CorruptFrame {
                offset,
                reason: "payload exceeds configured maximum",
            });
        }
        let frame_len = (FRAME_HEADER_LEN as u64)
            .checked_add(payload_len_u64)
            .and_then(|length| length.checked_add(FRAME_TRAILER_LEN as u64))
            .ok_or(ShadowWalErrorV1::CorruptFrame {
                offset,
                reason: "frame length overflow",
            })?;
        if frame_len > remaining {
            break;
        }

        let mut payload = vec![0u8; payload_len];
        file.read_exact(&mut payload)?;
        let mut trailer = [0u8; FRAME_TRAILER_LEN];
        file.read_exact(&mut trailer)?;
        if read_u32(&trailer[4..8]) != FRAME_COMMIT_MAGIC {
            return Err(ShadowWalErrorV1::CorruptFrame {
                offset,
                reason: "invalid frame commit marker",
            });
        }
        let mut checksum_bytes = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        checksum_bytes.extend_from_slice(&frame_header);
        checksum_bytes.extend_from_slice(&payload);
        if read_u32(&trailer[0..4]) != crc32c(&checksum_bytes) {
            return Err(ShadowWalErrorV1::CorruptFrame {
                offset,
                reason: "frame checksum mismatch",
            });
        }

        let declared_records = read_u32(&frame_header[24..28]);
        let records = decode_records(&payload, declared_records, offset)?;
        record_count = record_count
            .checked_add(u64::from(declared_records))
            .ok_or(ShadowWalErrorV1::LengthOverflow)?;
        let end_offset = offset + frame_len;
        batches.push(RecoveredBatchV1 {
            sequence,
            start_offset: offset,
            end_offset,
            records,
        });
        offset = end_offset;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(ShadowWalErrorV1::LengthOverflow)?;
    }

    let discarded_tail_bytes = original_len - offset;
    if discarded_tail_bytes != 0 {
        file.set_len(offset)?;
        file.sync_all()?;
    }
    Ok(ShadowWalRecoveryV1 {
        batches,
        durable_file_len: offset,
        record_count,
        discarded_tail_bytes,
    })
}

fn encode_frame(sequence: u64, records: &[Vec<u8>]) -> Result<Vec<u8>, ShadowWalErrorV1> {
    if records.is_empty() {
        return Err(ShadowWalErrorV1::EmptyBatch);
    }
    if records.len() > MAX_SHADOW_WAL_BATCH_RECORDS_V1 {
        return Err(ShadowWalErrorV1::TooManyRecords(records.len()));
    }
    let mut payload_len = 0usize;
    for record in records {
        if record.len() > MAX_SHADOW_WAL_RECORD_SIZE_V1 {
            return Err(ShadowWalErrorV1::RecordTooLarge(record.len()));
        }
        payload_len = payload_len
            .checked_add(4)
            .and_then(|length| length.checked_add(record.len()))
            .ok_or(ShadowWalErrorV1::LengthOverflow)?;
    }
    if payload_len > MAX_SHADOW_WAL_FRAME_PAYLOAD_V1 {
        return Err(ShadowWalErrorV1::FramePayloadTooLarge(payload_len));
    }
    let payload_len_u64 =
        u64::try_from(payload_len).map_err(|_| ShadowWalErrorV1::LengthOverflow)?;
    let record_count =
        u32::try_from(records.len()).map_err(|_| ShadowWalErrorV1::LengthOverflow)?;

    let total_len = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(FRAME_TRAILER_LEN))
        .ok_or(ShadowWalErrorV1::LengthOverflow)?;
    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
    frame.extend_from_slice(&SHADOW_WAL_FORMAT_VERSION_V1.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&payload_len_u64.to_be_bytes());
    frame.extend_from_slice(&record_count.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    let header_checksum = crc32c(&frame);
    frame.extend_from_slice(&header_checksum.to_be_bytes());
    debug_assert_eq!(frame.len(), FRAME_HEADER_LEN);
    for record in records {
        let record_len =
            u32::try_from(record.len()).expect("record length was validated before encoding");
        frame.extend_from_slice(&record_len.to_be_bytes());
        frame.extend_from_slice(record);
    }
    let frame_checksum = crc32c(&frame);
    frame.extend_from_slice(&frame_checksum.to_be_bytes());
    frame.extend_from_slice(&FRAME_COMMIT_MAGIC.to_be_bytes());
    debug_assert_eq!(frame.len(), total_len);
    Ok(frame)
}

fn validate_frame_header(
    header: &[u8; FRAME_HEADER_LEN],
    offset: u64,
) -> Result<(), ShadowWalErrorV1> {
    if read_u32(&header[0..4]) != FRAME_MAGIC {
        return Err(ShadowWalErrorV1::CorruptFrame {
            offset,
            reason: "invalid frame magic",
        });
    }
    if read_u16(&header[4..6]) != SHADOW_WAL_FORMAT_VERSION_V1 {
        return Err(ShadowWalErrorV1::CorruptFrame {
            offset,
            reason: "unsupported frame version",
        });
    }
    if read_u16(&header[6..8]) != 0 || read_u32(&header[28..32]) != 0 {
        return Err(ShadowWalErrorV1::CorruptFrame {
            offset,
            reason: "nonzero frame flags",
        });
    }
    if read_u32(&header[32..36]) != crc32c(&header[..FRAME_HEADER_PREFIX_LEN]) {
        return Err(ShadowWalErrorV1::CorruptFrame {
            offset,
            reason: "frame header checksum mismatch",
        });
    }
    let record_count = read_u32(&header[24..28]);
    if record_count == 0
        || usize::try_from(record_count).expect("u32 always fits supported usize")
            > MAX_SHADOW_WAL_BATCH_RECORDS_V1
    {
        return Err(ShadowWalErrorV1::CorruptFrame {
            offset,
            reason: "invalid frame record count",
        });
    }
    Ok(())
}

fn decode_records(
    payload: &[u8],
    declared_records: u32,
    frame_offset: u64,
) -> Result<Vec<Vec<u8>>, ShadowWalErrorV1> {
    let declared_records =
        usize::try_from(declared_records).expect("u32 always fits supported usize");
    let mut records = Vec::with_capacity(declared_records);
    let mut cursor = 0usize;
    for _ in 0..declared_records {
        let length_end = cursor
            .checked_add(4)
            .ok_or(ShadowWalErrorV1::CorruptFrame {
                offset: frame_offset,
                reason: "record length offset overflow",
            })?;
        let Some(length_bytes) = payload.get(cursor..length_end) else {
            return Err(ShadowWalErrorV1::CorruptFrame {
                offset: frame_offset,
                reason: "truncated record length",
            });
        };
        let record_len =
            usize::try_from(read_u32(length_bytes)).expect("u32 always fits supported usize");
        if record_len > MAX_SHADOW_WAL_RECORD_SIZE_V1 {
            return Err(ShadowWalErrorV1::CorruptFrame {
                offset: frame_offset,
                reason: "record exceeds configured maximum",
            });
        }
        let record_end =
            length_end
                .checked_add(record_len)
                .ok_or(ShadowWalErrorV1::CorruptFrame {
                    offset: frame_offset,
                    reason: "record offset overflow",
                })?;
        let Some(record) = payload.get(length_end..record_end) else {
            return Err(ShadowWalErrorV1::CorruptFrame {
                offset: frame_offset,
                reason: "truncated record",
            });
        };
        records.push(record.to_vec());
        cursor = record_end;
    }
    if cursor != payload.len() {
        return Err(ShadowWalErrorV1::CorruptFrame {
            offset: frame_offset,
            reason: "trailing frame payload bytes",
        });
    }
    Ok(records)
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = nonempty_parent(path).unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

/// Create a potentially nested WAL parent and durably publish every new
/// directory name from the nearest existing ancestor downwards.
fn create_parent_directories_durable(parent: &Path) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut cursor = parent.to_path_buf();
    loop {
        if cursor.as_os_str().is_empty() {
            cursor = PathBuf::from(".");
        }
        match fs::symlink_metadata(&cursor) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(cursor.clone());
                cursor = nonempty_parent(&cursor)
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."));
            }
            Err(error) => return Err(error),
        }
    }

    fs::create_dir_all(parent)?;
    for directory in missing.iter().rev() {
        File::open(directory)?.sync_all()?;
        sync_parent_directory(directory)?;
    }
    Ok(())
}

fn nonempty_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().expect("fixed u16 range"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("fixed u32 range"))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("fixed u64 range"))
}

// Table-free CRC32C (Castagnoli). WAL writes are not on the protocol hot path,
// and avoiding another dependency keeps this isolated adapter self-contained.
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        committee::Committee, starfish_rbc_dag::RbcDagProtocolInstanceId,
        types::BlockAuthenticationScheme,
    };
    use std::io::{Seek, SeekFrom, Write};

    fn namespace_with_stakes(
        instance_marker: u8,
        own_authority: AuthorityIndex,
        stakes: Vec<u64>,
    ) -> ShadowWalNamespaceV1 {
        let committee = Committee::new_test(stakes);
        let context = RbcDagContextV1::new(
            RbcDagProtocolInstanceId::new([instance_marker; 32]).unwrap(),
            &committee,
            BlockAuthenticationScheme::MacVector,
        )
        .unwrap();
        ShadowWalNamespaceV1::new(context, own_authority)
    }

    fn namespace(instance_marker: u8, own_authority: AuthorityIndex) -> ShadowWalNamespaceV1 {
        namespace_with_stakes(instance_marker, own_authority, vec![1; 4])
    }

    fn wal_path(directory: &tempfile::TempDir) -> PathBuf {
        directory.path().join("shadow").join("rbc-dag.wal")
    }

    fn append_raw(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn overwrite_byte(path: &Path, offset: u64) {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn crc32c_matches_the_standard_check_vector() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn batches_reopen_with_exact_record_bytes_and_continue_sequence() {
        let directory = tempfile::tempdir().unwrap();
        let path = wal_path(&directory);
        let namespace = namespace(0xA1, 2);
        let (mut wal, recovery) = ShadowWalV1::open(&path, namespace).unwrap();
        assert_eq!(recovery.batch_count(), 0);
        assert_eq!(recovery.durable_file_len(), FILE_HEADER_LEN as u64);

        let first_records = vec![b"first".to_vec(), Vec::new(), vec![0, 0xFF, 7]];
        let first = wal.append_batch(&first_records).unwrap();
        assert_eq!(first.sequence(), 0);
        assert_eq!(first.start_offset(), FILE_HEADER_LEN as u64);
        assert_eq!(first.record_count(), 3);
        let second_records = vec![b"second".to_vec()];
        let second = wal.append_batch(&second_records).unwrap();
        assert_eq!(second.sequence(), 1);
        assert_eq!(second.start_offset(), first.end_offset());
        let summary = wal.shutdown().unwrap();
        assert_eq!(summary.batch_count(), 2);
        assert_eq!(summary.record_count(), 4);

        let (mut reopened, recovery) = ShadowWalV1::open(&path, namespace).unwrap();
        assert_eq!(recovery.batch_count(), 2);
        assert_eq!(recovery.record_count(), 4);
        assert_eq!(
            recovery.records(),
            vec![
                b"first".as_slice(),
                b"".as_slice(),
                [0, 0xFF, 7].as_slice(),
                b"second".as_slice(),
            ]
        );
        assert_eq!(recovery.durable_file_len(), summary.file_len());
        assert_eq!(
            reopened
                .append_batch(&[b"third".to_vec()])
                .unwrap()
                .sequence(),
            2
        );
        reopened.shutdown().unwrap();

        let (_, recovery) = ShadowWalV1::open(&path, namespace).unwrap();
        assert_eq!(recovery.batch_count(), 3);
        assert_eq!(
            recovery.records().last().copied(),
            Some(b"third".as_slice())
        );
    }

    #[test]
    fn every_incomplete_final_frame_byte_boundary_is_discarded_once() {
        let torn = encode_frame(1, &[b"not-durable".to_vec()]).unwrap();
        for cut in 1..torn.len() {
            let directory = tempfile::tempdir().unwrap();
            let path = wal_path(&directory);
            let namespace = namespace(0xA2, 1);
            let (mut wal, _) = ShadowWalV1::open(&path, namespace).unwrap();
            wal.append_batch(&[b"durable".to_vec()]).unwrap();
            let durable_len = wal.file_len();
            wal.shutdown().unwrap();

            append_raw(&path, &torn[..cut]);
            let (wal, recovery) = ShadowWalV1::open(&path, namespace).unwrap();
            assert_eq!(recovery.records(), vec![b"durable".as_slice()]);
            assert_eq!(recovery.discarded_tail_bytes(), cut as u64);
            assert_eq!(wal.file_len(), durable_len);
            wal.shutdown().unwrap();

            let (_, clean_recovery) = ShadowWalV1::open(&path, namespace).unwrap();
            assert_eq!(clean_recovery.discarded_tail_bytes(), 0);
        }
    }

    #[test]
    fn partial_payload_or_trailer_is_discarded_as_one_torn_final_batch() {
        let directory = tempfile::tempdir().unwrap();
        let path = wal_path(&directory);
        let namespace = namespace(0xA3, 0);
        let (wal, _) = ShadowWalV1::open(&path, namespace).unwrap();
        wal.shutdown().unwrap();
        let frame = encode_frame(0, &[vec![0xAB; 128], b"tail".to_vec()]).unwrap();

        for cut in [FRAME_HEADER_LEN + 10, frame.len() - 1] {
            let original = fs::read(&path).unwrap();
            append_raw(&path, &frame[..cut]);
            let (wal, recovery) = ShadowWalV1::open(&path, namespace).unwrap();
            assert_eq!(recovery.batch_count(), 0);
            assert_eq!(recovery.discarded_tail_bytes(), cut as u64);
            wal.shutdown().unwrap();
            fs::write(&path, &original).unwrap();
        }
    }

    #[test]
    fn checksum_corruption_in_complete_first_or_last_frame_is_rejected() {
        for corrupt_first in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let path = wal_path(&directory);
            let namespace = namespace(0xA4, 3);
            let (mut wal, _) = ShadowWalV1::open(&path, namespace).unwrap();
            let first = wal.append_batch(&[b"one".to_vec()]).unwrap();
            let second = wal.append_batch(&[b"two".to_vec()]).unwrap();
            wal.shutdown().unwrap();
            let position = if corrupt_first { first } else { second };
            overwrite_byte(&path, position.start_offset() + FRAME_HEADER_LEN as u64 + 4);
            assert!(matches!(
                ShadowWalV1::open(&path, namespace),
                Err(ShadowWalErrorV1::CorruptFrame {
                    reason: "frame checksum mismatch",
                    ..
                })
            ));
        }
    }

    #[test]
    fn corrupted_frame_header_is_not_misclassified_as_a_torn_tail() {
        let directory = tempfile::tempdir().unwrap();
        let path = wal_path(&directory);
        let namespace = namespace(0xA5, 1);
        let (mut wal, _) = ShadowWalV1::open(&path, namespace).unwrap();
        let frame = wal.append_batch(&[b"record".to_vec()]).unwrap();
        wal.shutdown().unwrap();
        overwrite_byte(&path, frame.start_offset() + 18);
        assert!(matches!(
            ShadowWalV1::open(&path, namespace),
            Err(ShadowWalErrorV1::CorruptFrame {
                reason: "frame header checksum mismatch",
                ..
            })
        ));
    }

    #[test]
    fn namespace_is_bound_to_instance_committee_authority_and_version() {
        let directory = tempfile::tempdir().unwrap();
        let path = wal_path(&directory);
        let expected_namespace = namespace(0xA6, 1);
        let (wal, _) = ShadowWalV1::open(&path, expected_namespace).unwrap();
        wal.shutdown().unwrap();

        assert!(matches!(
            ShadowWalV1::open(&path, namespace(0xA7, 1)),
            Err(ShadowWalErrorV1::NamespaceMismatch)
        ));
        assert!(matches!(
            ShadowWalV1::open(&path, namespace(0xA6, 2)),
            Err(ShadowWalErrorV1::NamespaceMismatch)
        ));
        assert!(matches!(
            ShadowWalV1::open(&path, namespace_with_stakes(0xA6, 1, vec![1, 1, 1, 2])),
            Err(ShadowWalErrorV1::NamespaceMismatch)
        ));

        let version_offset = 16u64;
        overwrite_byte(&path, version_offset + 1);
        assert!(matches!(
            ShadowWalV1::open(&path, expected_namespace),
            Err(ShadowWalErrorV1::UnsupportedFileVersion(_))
        ));
    }

    #[test]
    fn truncated_or_corrupt_file_header_is_rejected_without_reinitializing() {
        let directory = tempfile::tempdir().unwrap();
        let path = wal_path(&directory);
        let namespace = namespace(0xA8, 0);
        let (wal, _) = ShadowWalV1::open(&path, namespace).unwrap();
        wal.shutdown().unwrap();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len((FILE_HEADER_LEN - 1) as u64)
            .unwrap();
        assert!(matches!(
            ShadowWalV1::open(&path, namespace),
            Err(ShadowWalErrorV1::TruncatedFileHeader { .. })
        ));

        fs::write(&path, encode_file_header(namespace)).unwrap();
        overwrite_byte(&path, 30);
        assert!(matches!(
            ShadowWalV1::open(&path, namespace),
            Err(ShadowWalErrorV1::InvalidFileHeaderChecksum)
        ));
    }

    #[test]
    fn preexisting_empty_file_is_rejected_instead_of_erasing_durable_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = wal_path(&directory);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        File::create(&path).unwrap().sync_all().unwrap();

        assert!(matches!(
            ShadowWalV1::open(&path, namespace(0xAB, 0)),
            Err(ShadowWalErrorV1::TruncatedFileHeader {
                actual: 0,
                expected: FILE_HEADER_LEN,
            })
        ));
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_dangling_symlink_fails_closed_without_publication_retry() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let path = wal_path(&directory);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        symlink("missing-shadow-wal", &path).unwrap();

        assert!(matches!(
            ShadowWalV1::open(&path, namespace(0xAF, 0)),
            Err(ShadowWalErrorV1::Io(error))
                if error.kind() == io::ErrorKind::NotFound
        ));
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn crash_before_initialization_publish_never_exposes_a_partial_header() {
        for cut in [0, 1, FILE_HEADER_LEN - 1, FILE_HEADER_LEN] {
            let directory = tempfile::tempdir().unwrap();
            let path = wal_path(&directory);
            let namespace = namespace(0xAC, 0);
            fs::create_dir_all(path.parent().unwrap()).unwrap();

            // Model a process dying at any write boundary before the atomic
            // publish. Its private same-directory file may survive, but the
            // canonical name must remain absent and independently creatable.
            let (temporary_path, mut temporary) = create_initialization_temp(&path).unwrap();
            temporary
                .write_all(&encode_file_header(namespace)[..cut])
                .unwrap();
            temporary.sync_all().unwrap();
            drop(temporary);
            assert!(!path.exists());

            let (wal, recovery) = ShadowWalV1::open(&path, namespace).unwrap();
            assert_eq!(recovery.durable_file_len(), FILE_HEADER_LEN as u64);
            assert_eq!(recovery.batch_count(), 0);
            wal.shutdown().unwrap();
            assert_eq!(fs::metadata(&path).unwrap().len(), FILE_HEADER_LEN as u64);

            // Orphan cleanup is opportunistic and never part of identifying
            // the canonical WAL. Remove the simulated crashed process's file
            // so the test itself leaves no debris.
            assert!(temporary_path.exists());
            fs::remove_file(temporary_path).unwrap();
        }
    }

    #[test]
    fn initialization_race_never_replaces_an_existing_malformed_target() {
        let directory = tempfile::tempdir().unwrap();
        let path = wal_path(&directory);
        let namespace = namespace(0xAD, 0);
        fs::create_dir_all(path.parent().unwrap()).unwrap();

        let (temporary_path, mut temporary) = create_initialization_temp(&path).unwrap();
        temporary.write_all(&encode_file_header(namespace)).unwrap();
        temporary.sync_all().unwrap();
        File::create(&path).unwrap().sync_all().unwrap();

        let error = atomic_rename_noreplace(&temporary_path, &path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        assert!(temporary_path.exists());
        drop(temporary);
        fs::remove_file(temporary_path).unwrap();

        assert!(matches!(
            ShadowWalV1::open(&path, namespace),
            Err(ShadowWalErrorV1::TruncatedFileHeader {
                actual: 0,
                expected: FILE_HEADER_LEN,
            })
        ));
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn successful_initialization_publishes_only_the_canonical_name() {
        let directory = tempfile::tempdir().unwrap();
        let path = wal_path(&directory);
        let namespace = namespace(0xAE, 0);
        let (wal, recovery) = ShadowWalV1::open(&path, namespace).unwrap();
        assert_eq!(recovery.durable_file_len(), FILE_HEADER_LEN as u64);
        wal.shutdown().unwrap();

        let entries = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, vec![path.file_name().unwrap()]);

        let (wal, reopened) = ShadowWalV1::open(&path, namespace).unwrap();
        assert_eq!(reopened.discarded_tail_bytes(), 0);
        assert_eq!(reopened.durable_file_len(), FILE_HEADER_LEN as u64);
        wal.shutdown().unwrap();
    }

    #[test]
    fn invalid_batch_is_rejected_without_changing_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = wal_path(&directory);
        let namespace = namespace(0xA9, 0);
        let (mut wal, _) = ShadowWalV1::open(&path, namespace).unwrap();
        let initial_len = wal.file_len();
        assert!(matches!(
            wal.append_batch(&[]),
            Err(ShadowWalErrorV1::EmptyBatch)
        ));
        assert!(matches!(
            wal.append_batch(&[vec![0; MAX_SHADOW_WAL_RECORD_SIZE_V1 + 1]]),
            Err(ShadowWalErrorV1::RecordTooLarge(_))
        ));
        assert_eq!(wal.file_len(), initial_len);
        assert_eq!(wal.batch_count(), 0);
        assert!(!wal.is_poisoned());
        wal.shutdown().unwrap();
    }

    #[test]
    fn external_file_mutation_poisoning_requires_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = wal_path(&directory);
        let namespace = namespace(0xAA, 1);
        let (mut wal, _) = ShadowWalV1::open(&path, namespace).unwrap();
        append_raw(&path, &[0xDE, 0xAD]);
        assert!(matches!(
            wal.append_batch(&[b"event".to_vec()]),
            Err(ShadowWalErrorV1::ExternalFileMutation { .. })
        ));
        assert!(wal.is_poisoned());
        assert!(matches!(
            wal.append_batch(&[b"again".to_vec()]),
            Err(ShadowWalErrorV1::Poisoned)
        ));
        drop(wal);

        let (mut reopened, recovery) = ShadowWalV1::open(&path, namespace).unwrap();
        assert_eq!(recovery.discarded_tail_bytes(), 2);
        reopened.append_batch(&[b"after-reopen".to_vec()]).unwrap();
        reopened.shutdown().unwrap();
    }
}
