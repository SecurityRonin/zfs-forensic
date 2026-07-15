//! Error types for the ZFS reader.

use thiserror::Error;

/// Errors surfaced while parsing ZFS on-disk structures.
///
/// Every variant names the offending value so an "unknown/invalid" report hands
/// the investigator the evidence (raw bytes / offset), never a bare "invalid".
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZfsError {
    /// The buffer was too small to hold the structure being parsed.
    #[error("buffer too small for {structure}: need {need} bytes, have {have}")]
    Truncated {
        /// Name of the structure that could not be read.
        structure: &'static str,
        /// Minimum byte length required.
        need: usize,
        /// Byte length actually available.
        have: usize,
    },

    /// No uberblock with the ZFS magic (`0x0000_0000_00ba_b10c`) was found in the
    /// label's uberblock array, so the pool's byte order could not be detected
    /// and no active uberblock exists.
    ///
    /// Carries the byte order that *was* tried and the count of slots scanned so
    /// the caller sees what was searched (fail-loud rather than silent-empty).
    #[error("no valid uberblock found in {scanned} array slots (neither little- nor big-endian magic 0x00bab10c matched)")]
    NoUberblock {
        /// Number of uberblock slots scanned.
        scanned: usize,
    },

    /// The packed nvlist config declared an encoding this reader does not handle.
    ///
    /// ZFS on-disk config is always XDR (`encoding == 1`); any other value means
    /// the buffer is not a ZFS nvlist. Carries the offending encoding byte and
    /// the offset so the investigator can see what was really there.
    #[error(
        "unsupported nvlist encoding {encoding:#04x} at offset {offset} (expected 0x01 = XDR)"
    )]
    BadNvlistEncoding {
        /// The encoding byte actually read.
        encoding: u8,
        /// Offset of the nvlist header within the source buffer.
        offset: usize,
    },

    /// An nvlist length/count field exceeded a sane bound, so parsing rejected it
    /// rather than attempting an allocation-bomb-sized read.
    ///
    /// Carries the field name, the offending value, and the cap it breached.
    #[error("nvlist {field} value {value} exceeds cap {cap} (allocation-bomb guard)")]
    NvlistBomb {
        /// Which length/count field was out of range.
        field: &'static str,
        /// The offending value.
        value: u64,
        /// The maximum this reader accepts.
        cap: u64,
    },

    /// A block pointer declared a logical size beyond the sane cap, so the read
    /// was rejected rather than attempting the allocation.
    ///
    /// Carries the field name, the offending value, and the cap breached.
    #[error("block {field} value {value} exceeds cap {cap} (allocation-bomb guard)")]
    AllocationBomb {
        /// Which size field was out of range (`LSIZE`).
        field: &'static str,
        /// The offending value (bytes).
        value: u64,
        /// The maximum this reader accepts (bytes).
        cap: u64,
    },

    /// A block's on-disk data could not be decompressed — the codec failed or
    /// the framing was malformed. Carries the codec name and a reason so the
    /// investigator sees which decoder rejected what.
    #[error("{codec} decompression failed: {reason}")]
    Decompress {
        /// The compression codec that failed.
        codec: &'static str,
        /// Why decompression failed.
        reason: &'static str,
    },

    /// A block pointer selected a compression function this reader does not
    /// implement. Carries the raw enum value so the report names it.
    #[error("unsupported compression function {value} (no decoder implemented)")]
    UnsupportedCompression {
        /// The raw `zio_compress` enum value.
        value: u8,
    },

    /// A block pointer is **embedded** — its payload is inline in the blkptr
    /// words rather than on disk. Inline-payload extraction is a later phase;
    /// this surfaces the case explicitly (never a silent wrong read). Carries the
    /// declared logical size.
    #[error("embedded block pointer with inline {lsize}-byte payload (inline extraction not yet implemented)")]
    EmbeddedBlkptr {
        /// The declared logical size (bytes) of the inline payload.
        lsize: u64,
    },

    /// An index/id exceeded its valid range while walking objects or an indirect
    /// block tree. Carries what was indexed, the offending value, and the max.
    #[error("{what} value {value} out of range (max {max})")]
    OutOfRange {
        /// What was being indexed (`blkid`, `top blkptr index`, …).
        what: &'static str,
        /// The offending value.
        value: u64,
        /// The maximum valid value.
        max: u64,
    },
}
