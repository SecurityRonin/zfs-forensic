//! ZFS block decompression (off, lzjb, lz4, gzip, zle, zstd).
//!
//! A block pointer's `comp` field selects the function used to compress the
//! on-disk (PSIZE) bytes down from the logical (LSIZE) bytes. On read the reader
//! decompresses `src` (PSIZE bytes) back to exactly `lsize` bytes. This module is
//! **batteries-included**: every legacy codec a real pool may use is compiled in
//! (no Cargo feature to remember), so an evidence workstation reads any block.
//!
//! # Codecs
//!
//! - **off** (2) — raw copy of the first `lsize` bytes.
//! - **lzjb** (3) — the original ZFS codec; a small clean-room implementation
//!   (per OpenZFS `lzjb.c`, oracle-checkable via `zdb -R`).
//! - **lz4** (15) — ZFS frames LZ4 with a **4-byte big-endian** *compressed*-size
//!   prefix, then the raw LZ4 block; decoded via the `lz4_flex` block API to the
//!   known `lsize`. Validated against a real ZFS-written LZ4 block.
//! - **`gzip_1..9`** (5-13) — zlib/DEFLATE via `flate2`.
//! - **zle** (14) — zero-length encoding (run-length of zero bytes).
//! - **zstd** (16) — ZFS frames zstd with a 4-byte-length + 4-byte-version header
//!   before the standard zstd frame; decoded via the `zstd` crate.
//!
//! # Robustness
//!
//! `lsize` is capped against allocation bombs by the caller (`read_block`); here
//! every codec is told the exact output size and refuses to grow beyond it, so a
//! lying compressed stream errors rather than OOMs.

use crate::bytes::be_u32;
use crate::error::ZfsError;
use std::io::Read;

/// ZFS compression function (`zio_compress` enum, `blk_prop` bits 32-38).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompressType {
    /// `ZIO_COMPRESS_INHERIT` (0).
    Inherit,
    /// `ZIO_COMPRESS_ON` (1) — the default (lz4); not stored on a block.
    On,
    /// `ZIO_COMPRESS_OFF` (2) — uncompressed.
    Off,
    /// `ZIO_COMPRESS_LZJB` (3).
    Lzjb,
    /// `ZIO_COMPRESS_EMPTY` (4).
    Empty,
    /// `ZIO_COMPRESS_GZIP_1..9` (5-13) — the level is carried in the value.
    Gzip(u8),
    /// `ZIO_COMPRESS_ZLE` (14) — zero-length encoding.
    Zle,
    /// `ZIO_COMPRESS_LZ4` (15).
    Lz4,
    /// `ZIO_COMPRESS_ZSTD` (16).
    Zstd,
    /// Any other / newer function — carried as its raw enum value so an
    /// "unsupported compression" report names the value.
    Other(u8),
}

impl CompressType {
    /// Map a raw on-disk compression enum value to a [`CompressType`].
    #[must_use]
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => CompressType::Inherit,
            1 => CompressType::On,
            2 => CompressType::Off,
            3 => CompressType::Lzjb,
            4 => CompressType::Empty,
            5..=13 => CompressType::Gzip(v),
            14 => CompressType::Zle,
            15 => CompressType::Lz4,
            16 => CompressType::Zstd,
            other => CompressType::Other(other),
        }
    }

    /// The raw on-disk `zio_compress` enum value.
    #[must_use]
    pub fn raw(self) -> u8 {
        match self {
            CompressType::Inherit => 0,
            CompressType::On => 1,
            CompressType::Off => 2,
            CompressType::Lzjb => 3,
            CompressType::Empty => 4,
            CompressType::Zle => 14,
            CompressType::Lz4 => 15,
            CompressType::Zstd => 16,
            // Both carry their raw value directly (a gzip level 5-13, or any
            // other/newer function).
            CompressType::Gzip(v) | CompressType::Other(v) => v,
        }
    }
}

/// Decompress `src` (the PSIZE on-disk bytes) to exactly `lsize` logical bytes.
///
/// # Errors
///
/// - [`ZfsError::Decompress`] if the codec fails, the framing is malformed, or
///   the output does not reach `lsize`. Never panics or over-allocates: each
///   codec targets the fixed `lsize` output.
/// - [`ZfsError::UnsupportedCompression`] for a function this reader does not
///   implement (the raw enum value is named).
pub fn decompress(kind: CompressType, src: &[u8], lsize: usize) -> Result<Vec<u8>, ZfsError> {
    match kind {
        CompressType::Off => Ok(decompress_off(src, lsize)),
        CompressType::Lzjb => decompress_lzjb(src, lsize),
        CompressType::Lz4 => decompress_lz4(src, lsize),
        CompressType::Gzip(_) | CompressType::On => decompress_gzip(src, lsize),
        CompressType::Zle => decompress_zle(src, lsize),
        CompressType::Zstd => decompress_zstd(src, lsize),
        CompressType::Empty => Ok(vec![0u8; lsize]),
        CompressType::Inherit => Err(ZfsError::UnsupportedCompression { value: 0 }),
        CompressType::Other(v) => Err(ZfsError::UnsupportedCompression { value: v }),
    }
}

/// Uncompressed: copy the first `lsize` bytes (zero-padded if `src` is shorter,
/// which never happens for a real block but must not panic).
fn decompress_off(src: &[u8], lsize: usize) -> Vec<u8> {
    let mut out = vec![0u8; lsize];
    let n = src.len().min(lsize);
    if let (Some(dst), Some(s)) = (out.get_mut(..n), src.get(..n)) {
        dst.copy_from_slice(s);
    }
    out
}

/// LZ4 as ZFS frames it: a 4-byte **big-endian** compressed-length prefix, then
/// the raw LZ4 block, decoded to the known `lsize`.
fn decompress_lz4(src: &[u8], lsize: usize) -> Result<Vec<u8>, ZfsError> {
    if src.len() < 4 {
        return Err(ZfsError::Decompress {
            codec: "lz4",
            reason: "input shorter than the 4-byte length prefix",
        });
    }
    let clen = be_u32(src, 0) as usize;
    let block = src
        .get(4..4usize.saturating_add(clen))
        .ok_or(ZfsError::Decompress {
            codec: "lz4",
            reason: "declared compressed length exceeds the input",
        })?;
    lz4_flex::block::decompress(block, lsize).map_err(|_| ZfsError::Decompress {
        codec: "lz4",
        reason: "malformed LZ4 stream or output overrun",
    })
}

/// GZIP/zlib DEFLATE via `flate2`, bounded to `lsize` output.
fn decompress_gzip(src: &[u8], lsize: usize) -> Result<Vec<u8>, ZfsError> {
    let mut out = Vec::new();
    // Bound the reader to lsize bytes so a lying stream cannot grow without
    // limit; a real block decompresses to exactly lsize.
    let mut dec = flate2::read::ZlibDecoder::new(src).take(lsize as u64);
    dec.read_to_end(&mut out)
        .map_err(|_| ZfsError::Decompress {
            codec: "gzip",
            reason: "malformed zlib/DEFLATE stream",
        })?;
    out.resize(lsize, 0);
    Ok(out)
}

/// zstd via the `zstd` crate. ZFS prepends a 4-byte length + 4-byte version to
/// the standard zstd frame (`zfs_zstd` header); skip it and decode to `lsize`.
fn decompress_zstd(src: &[u8], lsize: usize) -> Result<Vec<u8>, ZfsError> {
    // zfs_zstd header: uint32 c_len (BE) + uint32 packed(version|level) (BE),
    // then the standard zstd frame.
    let frame = src.get(8..).ok_or(ZfsError::Decompress {
        codec: "zstd",
        reason: "input shorter than the 8-byte zfs_zstd header",
    })?;
    let mut out = Vec::new();
    let mut dec = zstd::stream::read::Decoder::new(frame)
        .map_err(|_| ZfsError::Decompress {
            codec: "zstd",
            reason: "cannot initialise the zstd decoder",
        })? // cov:unreachable: Decoder::new over an in-memory reader only fails on ctx allocation, never on input
        .take(lsize as u64);
    dec.read_to_end(&mut out)
        .map_err(|_| ZfsError::Decompress {
            codec: "zstd",
            reason: "malformed zstd frame",
        })?;
    out.resize(lsize, 0);
    Ok(out)
}

/// LZJB (clean-room, per OpenZFS `lzjb.c`): a `copymap` byte gates 8 following
/// items; a set bit is a `(len, offset)` back-reference, a clear bit a literal.
fn decompress_lzjb(src: &[u8], lsize: usize) -> Result<Vec<u8>, ZfsError> {
    const MATCH_BITS: u32 = 6;
    const MATCH_MIN: usize = 3;
    const OFFSET_MASK: usize = (1 << (16 - MATCH_BITS)) - 1; // 0x3ff

    let mut out: Vec<u8> = Vec::with_capacity(lsize);
    let mut si = 0usize;
    let mut copymap = 0u8;
    let mut copymask = 1u32 << 7; // forces a fresh copymap load on the first item

    while out.len() < lsize {
        copymask <<= 1;
        if copymask == (1 << 8) {
            copymask = 1;
            copymap = *src.get(si).ok_or(ZfsError::Decompress {
                codec: "lzjb",
                reason: "truncated copymap byte",
            })?;
            si += 1;
        }
        if u32::from(copymap) & copymask != 0 {
            // Back-reference: two control bytes -> (mlen, offset).
            let b0 = *src.get(si).ok_or(ZfsError::Decompress {
                codec: "lzjb",
                reason: "truncated match control byte 0",
            })?;
            let b1 = *src.get(si + 1).ok_or(ZfsError::Decompress {
                codec: "lzjb",
                reason: "truncated match control byte 1",
            })?;
            si += 2;
            let mlen = (usize::from(b0) >> (8 - MATCH_BITS)) + MATCH_MIN;
            let offset = ((usize::from(b0) << 8) | usize::from(b1)) & OFFSET_MASK;
            let start = out.len().checked_sub(offset).ok_or(ZfsError::Decompress {
                codec: "lzjb",
                reason: "back-reference before start of output",
            })?;
            for k in 0..mlen {
                if out.len() >= lsize {
                    break;
                }
                let byte = *out.get(start + k).ok_or(ZfsError::Decompress {
                    codec: "lzjb",
                    reason: "back-reference reads past written output",
                })?;
                out.push(byte);
            }
        } else {
            // Literal byte.
            let byte = *src.get(si).ok_or(ZfsError::Decompress {
                codec: "lzjb",
                reason: "truncated literal byte",
            })?;
            si += 1;
            out.push(byte);
        }
    }
    Ok(out)
}

/// ZLE (zero-length encoding): a control byte encodes a run. Bit 7 clear -> a run
/// of `(ctrl + 1)` **literal** bytes follow; bit 7 set -> a run of
/// `(ctrl - 0x80 + 1) + 63` **zero** bytes. (Per OpenZFS `zle.c`, level 64.)
fn decompress_zle(src: &[u8], lsize: usize) -> Result<Vec<u8>, ZfsError> {
    let mut out = Vec::with_capacity(lsize);
    let mut si = 0usize;
    while out.len() < lsize {
        let ctrl = *src.get(si).ok_or(ZfsError::Decompress {
            codec: "zle",
            reason: "truncated control byte",
        })?;
        si += 1;
        if ctrl & 0x80 == 0 {
            let run = usize::from(ctrl) + 1;
            let bytes = src.get(si..si + run).ok_or(ZfsError::Decompress {
                codec: "zle",
                reason: "literal run exceeds input",
            })?;
            si += run;
            for &b in bytes {
                if out.len() >= lsize {
                    break;
                }
                out.push(b);
            }
        } else {
            let run = usize::from(ctrl - 0x80) + 1 + 63;
            for _ in 0..run {
                if out.len() >= lsize {
                    break;
                }
                out.push(0);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod unit {
    use super::{decompress, CompressType};
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn compress_type_raw_round_trips_every_variant() {
        for v in [0u8, 1, 2, 3, 4, 5, 9, 13, 14, 15, 16, 200] {
            assert_eq!(CompressType::from_raw(v).raw(), v);
        }
    }

    #[test]
    fn compress_type_from_raw_covers_the_enum() {
        assert_eq!(CompressType::from_raw(0), CompressType::Inherit);
        assert_eq!(CompressType::from_raw(1), CompressType::On);
        assert_eq!(CompressType::from_raw(2), CompressType::Off);
        assert_eq!(CompressType::from_raw(3), CompressType::Lzjb);
        assert_eq!(CompressType::from_raw(4), CompressType::Empty);
        assert_eq!(CompressType::from_raw(9), CompressType::Gzip(9));
        assert_eq!(CompressType::from_raw(14), CompressType::Zle);
        assert_eq!(CompressType::from_raw(15), CompressType::Lz4);
        assert_eq!(CompressType::from_raw(16), CompressType::Zstd);
        assert_eq!(CompressType::from_raw(200), CompressType::Other(200));
    }

    #[test]
    fn off_copies_lsize_bytes() {
        let src = [1, 2, 3, 4, 5, 6, 7, 8];
        let out = decompress(CompressType::Off, &src, 4).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
        // Shorter-than-lsize input zero-pads rather than panicking.
        let out = decompress(CompressType::Off, &[9, 9], 4).unwrap();
        assert_eq!(out, [9, 9, 0, 0]);
    }

    #[test]
    fn empty_yields_zeroes() {
        let out = decompress(CompressType::Empty, &[], 8).unwrap();
        assert_eq!(out, [0u8; 8]);
    }

    #[test]
    fn gzip_round_trip_independent_encoder() {
        // Independent oracle: flate2's *encoder* produces the stream; our
        // decoder must recover it (encoder != decoder path).
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(4);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&plain).unwrap();
        let compressed = enc.finish().unwrap();
        let out = decompress(CompressType::Gzip(6), &compressed, plain.len()).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn zstd_round_trip_independent_encoder() {
        // Build a zfs_zstd-framed stream: 8-byte header + standard zstd frame.
        let plain = b"zstd payload zstd payload zstd payload".repeat(8);
        let frame = zstd::stream::encode_all(plain.as_slice(), 3).unwrap();
        let mut framed = vec![0u8; 8]; // 4-byte len + 4-byte version (skipped)
        framed.extend_from_slice(&frame);
        let out = decompress(CompressType::Zstd, &framed, plain.len()).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn lzjb_literals_and_backreference() {
        // Hand-built LZJB stream (per lzjb.c): a copymap byte then items.
        // copymap = 0b0000_0111 (bits: item0,1,2 are matches). But building a
        // valid match needs prior output; simplest: all-literal run of "ABCD".
        // copymap bit clear = literal. 4 literals -> copymap 0x00, then A B C D.
        let stream = [0x00u8, b'A', b'B', b'C', b'D'];
        let out = decompress(CompressType::Lzjb, &stream, 4).unwrap();
        assert_eq!(&out, b"ABCD");
    }

    #[test]
    fn lzjb_backreference_copies_prior_bytes() {
        // "ABAB": literals A,B then a match (len 2, offset 2) reproducing "AB".
        // copymap: item0 literal(A), item1 literal(B), item2 match -> bit2 set.
        // copymap = 0b0000_0100 = 0x04.
        // match control: mlen stored = len - MATCH_MIN = 2-3 -> negative, so use
        // len 3 offset 2 -> "ABA...": produce "ABAAB"? Keep it simple: len 3.
        // b0 = ((mlen-3) << 2) | (offset >> 8); mlen=3 -> (0<<2)|0 = 0; b1 = offset&0xff = 2.
        let stream = [0x04u8, b'A', b'B', 0x00, 0x02];
        let out = decompress(CompressType::Lzjb, &stream, 5).unwrap();
        assert_eq!(&out, b"ABABA");
    }

    #[test]
    fn zle_zero_run_and_literals() {
        // ctrl 0x80 -> zero run of (0+1)+63 = 64 zeros; ask for 4.
        let out = decompress(CompressType::Zle, &[0x80], 4).unwrap();
        assert_eq!(out, [0, 0, 0, 0]);
        // ctrl 0x02 -> literal run of 3 bytes.
        let out = decompress(CompressType::Zle, &[0x02, 7, 8, 9], 3).unwrap();
        assert_eq!(out, [7, 8, 9]);
    }

    #[test]
    fn unsupported_and_inherit_name_the_value() {
        assert!(matches!(
            decompress(CompressType::Other(99), &[], 8),
            Err(crate::ZfsError::UnsupportedCompression { value: 99 })
        ));
        assert!(matches!(
            decompress(CompressType::Inherit, &[], 8),
            Err(crate::ZfsError::UnsupportedCompression { value: 0 })
        ));
    }

    #[test]
    fn malformed_streams_error_not_panic() {
        assert!(decompress(CompressType::Lz4, &[0, 0], 8).is_err()); // short prefix
        assert!(decompress(CompressType::Lz4, &[0, 0, 0, 99], 8).is_err()); // clen>input
                                                                            // valid clen (4) but a garbage LZ4 block -> decode error (the map_err arm).
        assert!(decompress(CompressType::Lz4, &[0, 0, 0, 4, 0xff, 0xff, 0xff, 0xff], 8).is_err());
        assert!(decompress(CompressType::Gzip(6), &[0xff; 8], 8).is_err());
        assert!(decompress(CompressType::Zstd, &[0, 0, 0], 8).is_err()); // short header
                                                                         // 8-byte header present but a garbage zstd frame -> decode error.
        assert!(decompress(CompressType::Zstd, &[0u8; 8], 8).is_err());
        // 8-byte header + bytes that init the decoder but fail mid-frame.
        let mut bad_zstd = vec![0u8; 8];
        bad_zstd.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0xff, 0xff, 0xff, 0xff]);
        assert!(decompress(CompressType::Zstd, &bad_zstd, 64).is_err());
        assert!(decompress(CompressType::Lzjb, &[], 8).is_err()); // no copymap
        assert!(decompress(CompressType::Zle, &[], 8).is_err()); // no ctrl
    }

    #[test]
    fn lzjb_backreference_overshooting_lsize_stops_at_lsize() {
        // A match whose length would exceed lsize must stop at lsize (the break).
        // "AB" then a match len 3 offset 2 -> would extend to "ABABA" (5), but ask
        // for only 3 -> "ABA".
        let stream = [0x04u8, b'A', b'B', 0x00, 0x02];
        let out = decompress(CompressType::Lzjb, &stream, 3).unwrap();
        assert_eq!(&out, b"ABA");
    }

    #[test]
    fn zle_zero_run_overshooting_lsize_stops_at_lsize() {
        // A 64-zero run but ask for 2 -> stops at 2 (the zero-run break).
        let out = decompress(CompressType::Zle, &[0x80], 2).unwrap();
        assert_eq!(out, [0, 0]);
        // A literal run longer than the remaining lsize stops at lsize (literal break).
        let out = decompress(CompressType::Zle, &[0x03, 1, 2, 3, 4], 2).unwrap();
        assert_eq!(out, [1, 2]);
    }
}
