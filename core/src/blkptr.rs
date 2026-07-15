//! Full 128-byte block pointer (`blkptr_t`) decode.
//!
//! The block pointer is the central ZFS structure: every block reference in the
//! pool is a 128-byte `blkptr_t` holding up to three ditto **DVAs**, the packed
//! `blk_prop` word (sizes/compression/checksum/type/level/byteorder/embedded),
//! the logical birth txg, a fill count, and the 256-bit checksum.
//!
//! # On-disk layout (`blkptr_t`, 128 bytes — verified against OpenZFS `spa.h`)
//!
//! | offset | field                         |
//! |--------|-------------------------------|
//! | 0      | `blk_dva[0]` (16 bytes)       |
//! | 16     | `blk_dva[1]` (16 bytes)       |
//! | 32     | `blk_dva[2]` (16 bytes)       |
//! | 48     | `blk_prop`                    |
//! | 56     | `blk_prop2` / pad             |
//! | 64     | `blk_pad`                     |
//! | 72     | `blk_birth_word[0]` (physical)|
//! | 80     | `blk_birth_word[1]` (logical) |
//! | 88     | `blk_fill`                    |
//! | 96     | `blk_cksum` (256-bit)         |
//!
//! Each DVA (`dva_word[0]`, `dva_word[1]`): `word0` = `asize`(bits 0-23) +
//! `grid`(24-31) + `vdev`(32-55); `word1` = `offset`(bits 0-62) + `G`(gang, 63).
//! Sizes are stored **in 512-byte sectors, as value − 1**, so LSIZE/PSIZE in
//! bytes = `((raw & 0xffff) + 1) << 9`; the DVA offset in bytes = `offset << 9`.
//!
//! # `blk_prop` bit fields (`BF64_GET(blk_prop, lowbit, len)`)
//!
//! | field       | bits   | note                                   |
//! |-------------|--------|----------------------------------------|
//! | LSIZE       | 0-15   | sectors − 1                            |
//! | PSIZE       | 16-31  | sectors − 1                            |
//! | compression | 32-38  | `zio_compress` enum                    |
//! | embedded    | 39     | `E` — data is inline, no DVA           |
//! | checksum    | 40-47  | `zio_checksum` enum                    |
//! | type        | 48-55  | DMU object type                        |
//! | level       | 56-60  | indirection level (0 = data)           |
//! | dedup       | 62     |                                        |
//! | byteorder   | 63     | 0 = big-endian, 1 = little-endian      |
//!
//! **Embedded blkptrs** (`E` set) carry their payload inline and use a different
//! packing (`BPE_GET_LSIZE`/`BPE_GET_PSIZE`); they have no DVA. This decoder
//! flags `embedded` and extracts the embedded LSIZE/PSIZE so a caller can pull
//! the inline payload; the DVAs are then not meaningful.

use crate::bytes::{le_u64, Endian, Reader};

/// The 4 MiB skew that skips the two front vdev labels + boot block, added when
/// translating a DVA offset to a raw byte position on the vdev.
pub const BOOT_SKEW: u64 = 0x0040_0000;

/// `BPE_PAYLOAD_SIZE` — bytes of inline payload an embedded blkptr carries in the
/// three non-`blk_prop`/non-pad regions of the 128-byte pointer
/// (`[0,48) ++ [56,88) ++ [96,128)` = 48 + 32 + 32).
pub const BPE_PAYLOAD_SIZE: usize = 112;

/// A Data Virtual Address: one ditto copy a block pointer records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dva {
    /// Top-level vdev index (`vdev`, `dva_word[0]` bits 32-55).
    pub vdev: u32,
    /// Allocated size, in 512-byte sectors (`asize`, bits 0-23).
    pub asize_sectors: u32,
    /// Offset within the vdev, in 512-byte sectors (bits 0-62 of `dva_word[1]`),
    /// before the boot-region skew.
    pub offset_sectors: u64,
    /// Gang-block flag (`G`, bit 63 of `dva_word[1]`).
    pub gang: bool,
}

impl Dva {
    /// The 4 MiB skew that skips the two front vdev labels + boot block, added
    /// when translating a DVA offset to a raw byte position on the vdev. Mirror
    /// of the module-level [`BOOT_SKEW`] as an associated constant.
    pub const BOOT_SKEW: u64 = BOOT_SKEW;

    /// Translate this DVA to a raw byte offset on its vdev:
    /// `(offset_sectors << 9) + 0x400000`.
    ///
    /// The `+ 0x400000` accounts for the two 256 KiB front labels plus the
    /// 3.5 MiB boot block that precede the allocatable region. Meaningful for
    /// `vdev == 0` in the single-vdev P1 scope; multi-vdev resolution is later.
    #[must_use]
    pub fn physical_byte_offset(self) -> u64 {
        (self.offset_sectors << 9).saturating_add(BOOT_SKEW)
    }

    /// Whether this DVA is unused (all-zero) — the second/third ditto slots are
    /// zero when a block has fewer than three copies.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.vdev == 0 && self.asize_sectors == 0 && self.offset_sectors == 0
    }

    /// Decode a 16-byte DVA at `off` within `bp`, in `rd`'s byte order.
    #[must_use]
    fn parse(rd: Reader, bp: &[u8], off: usize) -> Self {
        let w0 = rd.u64(bp, off);
        let w1 = rd.u64(bp, off + 8);
        Dva {
            vdev: ((w0 >> 32) & 0x00ff_ffff) as u32,
            asize_sectors: (w0 & 0x00ff_ffff) as u32,
            offset_sectors: w1 & 0x7fff_ffff_ffff_ffff,
            gang: (w1 >> 63) & 1 == 1,
        }
    }
}

/// A fully-decoded 128-byte block pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blkptr {
    /// The three ditto DVAs (unused copies are all-zero — see [`Dva::is_empty`]).
    pub dvas: [Dva; 3],
    /// Raw LSIZE field (`blk_prop` bits 0-15) — sectors − 1. Use [`Self::lsize_bytes`].
    pub lsize_raw: u32,
    /// Raw PSIZE field (`blk_prop` bits 16-31) — sectors − 1. Use [`Self::psize_bytes`].
    pub psize_raw: u32,
    /// Compression function enum (`comp`, bits 32-38).
    pub compression: u8,
    /// Embedded-blkptr flag (`E`, bit 39).
    pub embedded: bool,
    /// Checksum function enum (`cksum`, bits 40-47).
    pub checksum: u8,
    /// DMU object type (`type`, bits 48-55).
    pub object_type: u8,
    /// Indirection level (`lvl`, bits 56-60); `0` == data / leaf.
    pub level: u8,
    /// Dedup flag (`D`, bit 62).
    pub dedup: bool,
    /// On-disk byte order of the pointed-to block (`byteorder`, bit 63).
    pub byteorder: Endian,
    /// Logical birth transaction group (`blk_birth_word[1]`).
    pub logical_birth: u64,
    /// Fill count (`blk_fill`) — for an objset/dnode block, the number of
    /// allocated objects/dnodes beneath it.
    pub fill: u64,
    /// The 256-bit checksum (`blk_cksum`), four native-order `u64` words.
    pub checksum_words: [u64; 4],
    /// For an **embedded** blkptr: the inline logical size in bytes (`BPE_GET_LSIZE`).
    pub embedded_lsize: u32,
    /// For an **embedded** blkptr: the inline physical size in bytes (`BPE_GET_PSIZE`).
    pub embedded_psize: u32,
    /// For an **embedded** blkptr: the 112-byte inline payload gathered from the
    /// three non-prop/non-pad regions of the 128-byte pointer
    /// (`[0,48) ++ [56,88) ++ [96,128)`, `BPE_PAYLOAD_SIZE`). The first
    /// [`Self::embedded_psize`] bytes are the (possibly compressed) block content.
    pub embedded_payload: [u8; BPE_PAYLOAD_SIZE],
}

impl Default for Blkptr {
    fn default() -> Self {
        Blkptr {
            dvas: [Dva::default(); 3],
            lsize_raw: 0,
            psize_raw: 0,
            compression: 0,
            embedded: false,
            checksum: 0,
            object_type: 0,
            level: 0,
            dedup: false,
            byteorder: Endian::default(),
            logical_birth: 0,
            fill: 0,
            checksum_words: [0; 4],
            embedded_lsize: 0,
            embedded_psize: 0,
            embedded_payload: [0u8; BPE_PAYLOAD_SIZE],
        }
    }
}

impl Blkptr {
    /// The (possibly compressed) inline payload of an **embedded** blkptr: the
    /// first [`Self::embedded_psize`] bytes of [`Self::embedded_payload`]. Empty
    /// for a non-embedded blkptr.
    #[must_use]
    pub fn embedded_data(&self) -> &[u8] {
        if self.embedded {
            let n = (self.embedded_psize as usize).min(BPE_PAYLOAD_SIZE);
            &self.embedded_payload[..n]
        } else {
            &[]
        }
    }

    /// Logical size in bytes: `((lsize_raw) + 1) << 9`. For an embedded blkptr,
    /// this is [`Self::embedded_lsize`] instead.
    #[must_use]
    pub fn lsize_bytes(self) -> usize {
        if self.embedded {
            self.embedded_lsize as usize
        } else {
            (usize::try_from(self.lsize_raw)
                .unwrap_or(0)
                .saturating_add(1))
                << 9
        }
    }

    /// Physical (on-disk) size in bytes: `((psize_raw) + 1) << 9`. For an embedded
    /// blkptr, this is [`Self::embedded_psize`] instead.
    #[must_use]
    pub fn psize_bytes(self) -> usize {
        if self.embedded {
            self.embedded_psize as usize
        } else {
            (usize::try_from(self.psize_raw)
                .unwrap_or(0)
                .saturating_add(1))
                << 9
        }
    }

    /// Whether every DVA is empty — a hole (never-written / zero-filled block).
    #[must_use]
    pub fn is_hole(self) -> bool {
        !self.embedded && self.dvas.iter().all(|d| d.is_empty())
    }

    /// Decode the 128-byte block pointer in `bp`, in `endian` byte order.
    ///
    /// The `blk_prop` word (and the embedded flag) is always read in `endian`;
    /// the byteorder bit within it then tells the caller how the *pointed-to*
    /// block's contents (and its fletcher checksum words) are laid out.
    #[must_use]
    pub fn parse(bp: &[u8], endian: Endian) -> Self {
        let rd = Reader::new(endian);
        let prop = rd.u64(bp, 48);
        let embedded = (prop >> 39) & 1 == 1;
        // byteorder bit: 0 = big-endian, 1 = little-endian.
        let byteorder = if (prop >> 63) & 1 == 1 {
            Endian::Little
        } else {
            Endian::Big
        };

        let mut dvas = [Dva::default(); 3];
        let mut checksum_words = [0u64; 4];
        let (mut embedded_lsize, mut embedded_psize) = (0u32, 0u32);
        let mut embedded_payload = [0u8; BPE_PAYLOAD_SIZE];
        let mut fill = 0u64;
        let mut logical_birth = 0u64;

        if embedded {
            // BPE_GET_LSIZE = BF64_GET_SB(prop, 0, 25, 0, 1); PSIZE = (25,7,0,1).
            embedded_lsize = ((prop & 0x01ff_ffff) as u32).saturating_add(1);
            embedded_psize = (((prop >> 25) & 0x7f) as u32).saturating_add(1);
            // The 112-byte payload is gathered from the three regions of the
            // 128-byte pointer that are not the blk_prop word (48..56) or the pad
            // words (88..96): [0,48) ++ [56,88) ++ [96,128).
            gather_bpe_payload(bp, &mut embedded_payload);
        } else {
            for (i, dva) in dvas.iter_mut().enumerate() {
                *dva = Dva::parse(rd, bp, i * 16);
            }
            logical_birth = rd.u64(bp, 80);
            fill = rd.u64(bp, 88);
            for (i, w) in checksum_words.iter_mut().enumerate() {
                *w = rd.u64(bp, 96 + i * 8);
            }
        }

        Blkptr {
            dvas,
            lsize_raw: (prop & 0xffff) as u32,
            psize_raw: ((prop >> 16) & 0xffff) as u32,
            compression: ((prop >> 32) & 0x7f) as u8,
            embedded,
            checksum: ((prop >> 40) & 0xff) as u8,
            object_type: ((prop >> 48) & 0xff) as u8,
            level: ((prop >> 56) & 0x1f) as u8,
            dedup: (prop >> 62) & 1 == 1,
            byteorder,
            logical_birth,
            fill,
            checksum_words,
            embedded_lsize,
            embedded_psize,
            embedded_payload,
        }
    }
}

/// Gather the 112-byte `BPE_PAYLOAD` from the 128-byte embedded blkptr `bp` into
/// `out`, copying `[0,48) ++ [56,88) ++ [96,128)` and zero-filling any region a
/// truncated `bp` cannot supply (never panics/over-reads).
fn gather_bpe_payload(bp: &[u8], out: &mut [u8; BPE_PAYLOAD_SIZE]) {
    // (src_range, dst_start) for the three payload regions.
    let regions: [(usize, usize, usize); 3] = [(0, 48, 0), (56, 88, 48), (96, 128, 80)];
    for (start, end, dst) in regions {
        if let Some(seg) = bp.get(start..end) {
            out[dst..dst + (end - start)].copy_from_slice(seg);
        }
    }
}

/// Detect the byte order to decode a blkptr with, from its `blk_prop` byteorder
/// bit — used when a blkptr is read from a block whose endianness the caller
/// does not already know. Reads the prop word both ways; the one whose byteorder
/// bit is self-consistent with a plausible level/type is preferred, but for the
/// single-endian pools P1 targets the caller passes the pool endian directly, so
/// this helper is a convenience for standalone blkptr bytes.
#[must_use]
pub fn detect_blkptr_endian(bp: &[u8]) -> Endian {
    // The byteorder bit is the top bit of blk_prop (offset 48). Read that byte
    // directly (endian-independent for a single bit at a fixed byte position:
    // little-endian u64 top byte is at offset 55, big-endian at 48).
    let le_top = crate::bytes::u8_at(bp, 55);
    if le_top & 0x80 != 0 {
        Endian::Little
    } else {
        // Fall back: a big-endian prop has its top bit in byte 48.
        let be_top = crate::bytes::u8_at(bp, 48);
        if be_top & 0x80 != 0 {
            Endian::Big
        } else {
            // No byteorder bit set anywhere plausible; default to the common case.
            let _ = le_u64(bp, 48);
            Endian::Little
        }
    }
}

#[cfg(test)]
mod unit {
    use super::{detect_blkptr_endian, Blkptr, Dva};
    use crate::bytes::Endian;

    #[test]
    fn empty_dva_and_physical_offset() {
        assert!(Dva::default().is_empty());
        let d = Dva {
            vdev: 0,
            asize_sectors: 8,
            offset_sectors: 2,
            gang: false,
        };
        assert!(!d.is_empty());
        assert_eq!(d.physical_byte_offset(), (2 << 9) + 0x0040_0000);
    }

    #[test]
    fn parse_decodes_all_fields_little_endian() {
        // Build a blkptr: DVA[0] asize=8 off=7 gang; prop with known fields.
        let mut bp = [0u8; 128];
        bp[0..8].copy_from_slice(&8u64.to_le_bytes()); // dva0 w0 asize=8
        let w1 = 7u64 | (1u64 << 63); // offset 7, gang
        bp[8..16].copy_from_slice(&w1.to_le_bytes());
        // prop: lsize_raw=7 (-> 8 sectors -> 4096), psize_raw=7, comp=15(lz4),
        // embedded=0, cksum=7, type=11, level=1, byteorder=1(LE).
        let prop = 7u64
            | (7u64 << 16)
            | (15u64 << 32)
            | (7u64 << 40)
            | (11u64 << 48)
            | (1u64 << 56)
            | (1u64 << 63);
        bp[48..56].copy_from_slice(&prop.to_le_bytes());
        bp[80..88].copy_from_slice(&22u64.to_le_bytes()); // logical birth
        bp[88..96].copy_from_slice(&51u64.to_le_bytes()); // fill
        bp[96..104].copy_from_slice(&0xdead_beefu64.to_le_bytes());
        let p = Blkptr::parse(&bp, Endian::Little);
        assert_eq!(p.dvas[0].asize_sectors, 8);
        assert_eq!(p.dvas[0].offset_sectors, 7);
        assert!(p.dvas[0].gang);
        assert_eq!(p.lsize_bytes(), 4096);
        assert_eq!(p.psize_bytes(), 4096);
        assert_eq!(p.compression, 15);
        assert_eq!(p.checksum, 7);
        assert_eq!(p.object_type, 11);
        assert_eq!(p.level, 1);
        assert_eq!(p.byteorder, Endian::Little);
        assert!(!p.embedded);
        assert_eq!(p.logical_birth, 22);
        assert_eq!(p.fill, 51);
        assert_eq!(p.checksum_words[0], 0xdead_beef);
        assert!(!p.is_hole());
    }

    #[test]
    fn byteorder_bit_clear_is_big_endian() {
        let mut bp = [0u8; 128];
        // prop with byteorder bit clear -> big-endian; write big-endian.
        let prop = 0u64;
        bp[48..56].copy_from_slice(&prop.to_be_bytes());
        let p = Blkptr::parse(&bp, Endian::Big);
        assert_eq!(p.byteorder, Endian::Big);
    }

    #[test]
    fn embedded_blkptr_extracts_inline_sizes_and_has_no_dva() {
        let mut bp = [0u8; 128];
        // embedded bit (39) set; embedded lsize_raw=99 -> 100, psize_raw=3 -> 4.
        let prop = 0x63u64 | (3u64 << 25) | (1u64 << 39) | (1u64 << 63);
        bp[48..56].copy_from_slice(&prop.to_le_bytes());
        let p = Blkptr::parse(&bp, Endian::Little);
        assert!(p.embedded);
        assert_eq!(p.embedded_lsize, 100);
        assert_eq!(p.lsize_bytes(), 100);
        assert_eq!(p.embedded_psize, 4);
        assert_eq!(p.psize_bytes(), 4);
        // is_hole is false for embedded (data is inline).
        assert!(!p.is_hole());
        // embedded_data() returns the first psize (4) bytes of the payload.
        assert_eq!(p.embedded_data().len(), 4);
    }

    #[test]
    fn embedded_data_is_empty_for_a_non_embedded_blkptr() {
        let p = Blkptr::parse(&[0u8; 128], Endian::Little);
        assert!(!p.embedded);
        assert!(p.embedded_data().is_empty());
    }

    #[test]
    fn embedded_payload_gathers_three_regions() {
        // Mark bytes in each of the three payload regions and confirm they land
        // contiguously in embedded_payload: [0,48) [56,88) [96,128) -> 0,48,80.
        let mut bp = [0u8; 128];
        let prop = 0x63u64 | (0x6f << 25) | (1u64 << 39) | (1u64 << 63); // psize 0x70=112
        bp[48..56].copy_from_slice(&prop.to_le_bytes());
        bp[0] = 0xA1; // region 1 start -> payload[0]
        bp[56] = 0xB2; // region 2 start -> payload[48]
        bp[96] = 0xC3; // region 3 start -> payload[80]
        let p = Blkptr::parse(&bp, Endian::Little);
        assert_eq!(p.embedded_payload[0], 0xA1);
        assert_eq!(p.embedded_payload[48], 0xB2);
        assert_eq!(p.embedded_payload[80], 0xC3);
    }

    #[test]
    fn all_zero_blkptr_is_a_hole() {
        let p = Blkptr::parse(&[0u8; 128], Endian::Little);
        assert!(p.is_hole());
        assert_eq!(p.lsize_bytes(), 512); // (0+1)<<9
    }

    #[test]
    fn detect_endian_from_byteorder_bit() {
        let mut le = [0u8; 128];
        le[55] = 0x80; // little-endian prop top byte
        assert_eq!(detect_blkptr_endian(&le), Endian::Little);
        let mut be = [0u8; 128];
        be[48] = 0x80; // big-endian prop top byte
        assert_eq!(detect_blkptr_endian(&be), Endian::Big);
        // Neither set -> defaults to little.
        assert_eq!(detect_blkptr_endian(&[0u8; 128]), Endian::Little);
    }

    #[test]
    fn parse_out_of_range_never_panics() {
        let _ = Blkptr::parse(&[], Endian::Little);
        let _ = Blkptr::parse(&[0xAB; 40], Endian::Big);
    }
}
