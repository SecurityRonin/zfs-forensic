//! `dnode_phys_t` — the on-disk DMU object metadata (512-byte base).
//!
//! A dnode describes one DMU object: its type, the shape of its block tree
//! (`dn_nlevels` levels of indirection, `dn_nblkptr` top-level pointers, a data
//! block size), and a bonus buffer carrying object-specific metadata (a
//! `dsl_dataset_phys_t`, a znode/SA registry, …).
//!
//! # On-disk layout (`dnode_phys_t`, 512-byte base — verified against `dnode.h`)
//!
//! | offset | field              | size |
//! |--------|--------------------|------|
//! | 0      | `dn_type`          | 1    |
//! | 1      | `dn_indblkshift`   | 1    |
//! | 2      | `dn_nlevels`       | 1    |
//! | 3      | `dn_nblkptr`       | 1    |
//! | 4      | `dn_bonustype`     | 1    |
//! | 5      | `dn_checksum`      | 1    |
//! | 6      | `dn_compress`      | 1    |
//! | 7      | `dn_flags`         | 1    |
//! | 8      | `dn_datablkszsec`  | 2    |
//! | 10     | `dn_bonuslen`      | 2    |
//! | 12     | `dn_extra_slots`   | 1    |
//! | 13     | `dn_pad2[3]`       | 3    |
//! | 16     | `dn_maxblkid`      | 8    |
//! | 24     | `dn_used`          | 8    |
//! | 32     | `dn_pad3[4]`       | 32   |
//! | 64     | `dn_blkptr[]`      | 128× `dn_nblkptr` |
//! | …      | `dn_bonus[]` / `dn_spill` | tail |
//!
//! `DNODE_CORE_SIZE` = 64, so the first block pointer begins at offset 64. A
//! dnode may span multiple 512-byte slots (`dn_extra_slots`); the bonus buffer
//! begins after the `dn_nblkptr` block pointers.

use crate::blkptr::Blkptr;
use crate::bytes::{u8_at, Endian, Reader};

/// The base size of a dnode (`DNODE_MIN_SIZE`), one slot.
pub const DNODE_SIZE: usize = 512;
/// The size of a dnode's fixed core, before the block-pointer array
/// (`DNODE_CORE_SIZE`).
pub const DNODE_CORE_SIZE: usize = 64;
/// The size of one block pointer.
pub const BLKPTR_SIZE: usize = 128;

/// A parsed `dnode_phys_t`.
#[derive(Debug, Clone)]
pub struct Dnode {
    /// `dn_type` — DMU object type (raw; map via `DmuType::from_raw`).
    pub dn_type: u8,
    /// `dn_indblkshift` — log2 of the indirect block size in bytes.
    pub dn_indblkshift: u8,
    /// `dn_nlevels` — indirection depth (1 = `dn_blkptr` point at data blocks).
    pub dn_nlevels: u8,
    /// `dn_nblkptr` — number of block pointers in `dn_blkptr[]`.
    pub dn_nblkptr: u8,
    /// `dn_bonustype` — type of data in the bonus buffer.
    pub dn_bonustype: u8,
    /// `dn_checksum` — ZIO checksum type for this object's blocks.
    pub dn_checksum: u8,
    /// `dn_compress` — ZIO compression type for this object's blocks.
    pub dn_compress: u8,
    /// `dn_flags` — `DNODE_FLAG_*`.
    pub dn_flags: u8,
    /// `dn_datablkszsec` — data block size in 512-byte sectors.
    pub dn_datablkszsec: u16,
    /// `dn_bonuslen` — length of the bonus buffer in bytes.
    pub dn_bonuslen: u16,
    /// `dn_extra_slots` — subsequent 512-byte slots this dnode consumes.
    pub dn_extra_slots: u8,
    /// `dn_maxblkid` — largest allocated block id (object spans blocks `0..=max`).
    pub dn_maxblkid: u64,
    /// `dn_used` — disk space used, in bytes or sectors (see `DNODE_FLAG_USED_BYTES`).
    pub dn_used: u64,
    /// The on-disk byte order this dnode (and its block tree) is written in.
    pub endian: Endian,
    /// The decoded top-level block pointers (`dn_blkptr[0..dn_nblkptr]`, capped
    /// at the physical maximum that fits the dnode's slots).
    pub blkptrs: Vec<Blkptr>,
    /// The bonus buffer bytes (`dn_bonus[0..dn_bonuslen]`), if present.
    pub bonus: Vec<u8>,
}

impl Dnode {
    /// Data block size in bytes (`dn_datablkszsec << 9`).
    #[must_use]
    pub fn data_block_size(&self) -> usize {
        (self.dn_datablkszsec as usize) << 9
    }

    /// Indirect block size in bytes (`1 << dn_indblkshift`), the number of L(n)
    /// block pointers per indirect block being `indirect_block_size / 128`.
    #[must_use]
    pub fn indirect_block_size(&self) -> usize {
        1usize << (self.dn_indblkshift.min(24))
    }

    /// A top-level block pointer by index, if present.
    #[must_use]
    pub fn blkptr(&self, i: usize) -> Option<&Blkptr> {
        self.blkptrs.get(i)
    }

    /// Parse a `dnode_phys_t` from `raw` (at least 512 bytes), in `endian` order.
    ///
    /// Returns `None` only if `raw` is shorter than the 64-byte core; a dnode
    /// with `dn_type == DMU_OT_NONE` still parses (it is a valid empty slot).
    #[must_use]
    pub fn parse(raw: &[u8], endian: Endian) -> Option<Self> {
        if raw.len() < DNODE_CORE_SIZE {
            return None;
        }
        let rd = Reader::new(endian);
        let dn_type = u8_at(raw, 0);
        let dn_indblkshift = u8_at(raw, 1);
        let dn_nlevels = u8_at(raw, 2);
        let dn_nblkptr = u8_at(raw, 3);
        let dn_bonustype = u8_at(raw, 4);
        let dn_checksum = u8_at(raw, 5);
        let dn_compress = u8_at(raw, 6);
        let dn_flags = u8_at(raw, 7);
        let dn_datablkszsec = rd.u16(raw, 8);
        let dn_bonuslen = rd.u16(raw, 10);
        let dn_extra_slots = u8_at(raw, 12);
        let dn_maxblkid = rd.u64(raw, 16);
        let dn_used = rd.u64(raw, 24);

        // How many blkptrs physically fit: the dnode occupies (1 + extra) slots;
        // its tail (after the 64-byte core) holds blkptrs then bonus. Cap
        // dn_nblkptr against a lying value so we never read past the dnode.
        let total_bytes = (usize::from(dn_extra_slots).saturating_add(1)) * DNODE_SIZE;
        let tail_bytes = total_bytes.saturating_sub(DNODE_CORE_SIZE);
        let max_blkptrs = tail_bytes / BLKPTR_SIZE;
        let nblkptr = usize::from(dn_nblkptr).min(max_blkptrs);

        let mut blkptrs = Vec::with_capacity(nblkptr);
        for i in 0..nblkptr {
            let off = DNODE_CORE_SIZE + i * BLKPTR_SIZE;
            match raw.get(off..off + BLKPTR_SIZE) {
                Some(bp) => blkptrs.push(Blkptr::parse(bp, endian)),
                None => break, // cov:unreachable: nblkptr capped to fit total_bytes
            }
        }

        // The bonus buffer begins after the block pointers, bounded by dn_bonuslen
        // and the space actually available in the dnode tail.
        let bonus_off = DNODE_CORE_SIZE + nblkptr * BLKPTR_SIZE;
        let bonus_avail = total_bytes.saturating_sub(bonus_off);
        let bonus_len = usize::from(dn_bonuslen).min(bonus_avail);
        let bonus = raw
            .get(bonus_off..bonus_off + bonus_len)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();

        Some(Dnode {
            dn_type,
            dn_indblkshift,
            dn_nlevels,
            dn_nblkptr,
            dn_bonustype,
            dn_checksum,
            dn_compress,
            dn_flags,
            dn_datablkszsec,
            dn_bonuslen,
            dn_extra_slots,
            dn_maxblkid,
            dn_used,
            endian,
            blkptrs,
            bonus,
        })
    }
}

#[cfg(test)]
mod unit {
    use super::Dnode;
    use crate::bytes::Endian;

    #[test]
    fn parse_none_when_shorter_than_core() {
        assert!(Dnode::parse(&[0u8; 63], Endian::Little).is_none());
    }

    #[test]
    fn parse_reads_core_fields_and_blkptrs() {
        let mut raw = [0u8; 512];
        raw[0] = 10; // dn_type = DNODE
        raw[1] = 17; // indblkshift
        raw[2] = 2; // nlevels
        raw[3] = 3; // nblkptr
        raw[8..10].copy_from_slice(&32u16.to_le_bytes()); // datablkszsec = 16 KiB
        raw[10..12].copy_from_slice(&0u16.to_le_bytes()); // bonuslen
        raw[16..24].copy_from_slice(&1u64.to_le_bytes()); // maxblkid
                                                          // blkptr[0] at offset 64: give it a recognisable prop level=1.
        let prop = 1u64 << 56 | (1u64 << 63);
        raw[64 + 48..64 + 56].copy_from_slice(&prop.to_le_bytes());
        let d = Dnode::parse(&raw, Endian::Little).unwrap();
        assert_eq!(d.dn_type, 10);
        assert_eq!(d.dn_nlevels, 2);
        assert_eq!(d.dn_nblkptr, 3);
        assert_eq!(d.dn_datablkszsec, 32);
        assert_eq!(d.data_block_size(), 16 * 1024);
        assert_eq!(d.dn_maxblkid, 1);
        assert_eq!(d.blkptrs.len(), 3);
        assert_eq!(d.blkptr(0).unwrap().level, 1);
        assert!(d.blkptr(3).is_none());
        assert_eq!(d.indirect_block_size(), 1 << 17);
    }

    #[test]
    fn nblkptr_is_capped_to_what_fits_the_slots() {
        // A single-slot dnode has room for (512-64)/128 = 3 blkptrs; a lying
        // dn_nblkptr of 200 is capped, not over-read.
        let mut raw = [0u8; 512];
        raw[3] = 200; // dn_nblkptr (lie)
        let d = Dnode::parse(&raw, Endian::Little).unwrap();
        assert_eq!(d.blkptrs.len(), 3);
    }

    #[test]
    fn bonus_buffer_is_bounded() {
        // 1 blkptr, then a 64-byte bonus buffer with a marker.
        let mut raw = [0u8; 512];
        raw[3] = 1; // nblkptr
        raw[10..12].copy_from_slice(&64u16.to_le_bytes()); // bonuslen
        let bonus_off = 64 + 128;
        raw[bonus_off] = 0xAB;
        let d = Dnode::parse(&raw, Endian::Little).unwrap();
        assert_eq!(d.bonus.len(), 64);
        assert_eq!(d.bonus[0], 0xAB);
    }

    #[test]
    fn lying_bonuslen_is_clamped_to_available_space() {
        let mut raw = [0u8; 512];
        raw[3] = 0; // no blkptrs
        raw[10..12].copy_from_slice(&60000u16.to_le_bytes()); // absurd bonuslen
        let d = Dnode::parse(&raw, Endian::Little).unwrap();
        // Available tail = 512 - 64 = 448 bytes.
        assert_eq!(d.bonus.len(), 448);
    }
}
