//! Uberblock parsing and active-uberblock selection.
//!
//! An uberblock is ZFS's superblock-equivalent: the root of the current pool
//! state. It lives in a **ring array** at the end of every vdev label; the pool
//! rotates through slots as transaction groups (`txg`) commit, so the array
//! holds a history of recent pool roots. The **active** uberblock is the one
//! with the highest valid `txg`.
//!
//! # Endian-adaptive detection (verified against `zdb -u`)
//!
//! `ub_magic` is `0x0000_0000_00ba_b10c` (`OuroBoros`). ZFS writes it in the
//! host byte order of the pool's creator, so on read: if the little-endian
//! interpretation equals the magic the pool is little-endian; if the big-endian
//! interpretation matches, it is big-endian. The detected [`Endian`] drives every
//! subsequent field read of that uberblock.
//!
//! # On-disk layout (`uberblock_phys_t`, verified against `zdb -uuuuu`)
//!
//! | offset | field          |
//! |--------|----------------|
//! | 0      | `ub_magic`     |
//! | 8      | `ub_version`   |
//! | 16     | `ub_txg`       |
//! | 24     | `ub_guid_sum`  |
//! | 32     | `ub_timestamp` |
//! | 40     | `ub_rootbp` (a 128-byte `blkptr_t`) |
//!
//! The `ub_rootbp` points at the MOS objset. P0 exposes a [`BlkptrSummary`] of
//! it (the three DVAs plus type/level/compression); the full block-pointer tree
//! walk, checksum verify, and decompression belong to a later phase.

use crate::bytes::{be_u64, le_u64, Endian, Reader};

/// `UBERBLOCK_MAGIC` (`OuroBoros`).
pub const UBERBLOCK_MAGIC: u64 = 0x0000_0000_00ba_b10c;

/// `MMP_MAGIC` — multi-modifier protection magic in the uberblock tail.
pub const UB_MMP_MAGIC: u64 = 0x0000_0000_a11c_ea11;

/// `UBERBLOCK_SHIFT` — log2 of the minimum uberblock slot size (1 KiB). The
/// actual slot size is `max(1 KiB, 2^ashift)`, so a `ashift == 12` pool uses
/// 4 KiB slots and therefore 32 slots per 128 KiB ring (not 128).
pub const UBERBLOCK_MIN_SHIFT: u32 = 10;

// Field offsets within an uberblock slot.
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 8;
const OFF_TXG: usize = 16;
const OFF_GUID_SUM: usize = 24;
const OFF_TIMESTAMP: usize = 32;
const OFF_ROOTBP: usize = 40;

/// A Data Virtual Address: one of the (up to three, ditto) copies a block
/// pointer records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dva {
    /// Top-level vdev index.
    pub vdev: u32,
    /// Allocated size, in 512-byte sectors (`asize`).
    pub asize_sectors: u32,
    /// Offset within the vdev, in 512-byte sectors (before the boot-region skew).
    pub offset_sectors: u64,
    /// Gang-block flag (`G`).
    pub gang: bool,
}

impl Dva {
    /// The 4 MiB skew that skips the two front vdev labels + boot block, added
    /// when translating a DVA offset to a raw byte position on the vdev.
    pub const BOOT_SKEW: u64 = 0x0040_0000;

    /// Translate this DVA to a raw byte offset on its vdev:
    /// `(offset_sectors << 9) + 0x400000`.
    ///
    /// Only meaningful when [`Self::gang`] is false and `vdev == 0` in the
    /// single-vdev P0 scope; multi-vdev / gang resolution is a later phase.
    #[must_use]
    pub fn physical_byte_offset(self) -> u64 {
        (self.offset_sectors << 9).saturating_add(Self::BOOT_SKEW)
    }

    /// Whether this DVA is unused (all-zero) — the second/third ditto slots are
    /// zero when a block has fewer than three copies.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.vdev == 0 && self.asize_sectors == 0 && self.offset_sectors == 0
    }
}

/// The P0 subset of a `blkptr_t`: enough to expose the MOS root without walking
/// the tree. Full DVA translation across vdevs, gang blocks, embedded blkptrs,
/// checksum verify, and decompression are later phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlkptrSummary {
    /// The three ditto DVAs (unused copies are all-zero — see [`Dva::is_empty`]).
    pub dvas: [Dva; 3],
    /// Logical size, in 512-byte sectors (`LSIZE`, stored as value − 1).
    pub lsize_sectors: u32,
    /// Physical (on-disk) size, in 512-byte sectors (`PSIZE`, stored as − 1).
    pub psize_sectors: u32,
    /// Compression function enum (`comp`); `2` == `ZIO_COMPRESS_OFF`.
    pub compression: u8,
    /// DMU object type (`type`); `11` == `DMU_OT_OBJSET`.
    pub object_type: u8,
    /// Indirection level (`lvl`); `0` == data / leaf.
    pub level: u8,
    /// Embedded-blkptr flag (`E`).
    pub embedded: bool,
}

impl BlkptrSummary {
    /// Parse the 128-byte block pointer at `bp` (a sub-slice of the uberblock),
    /// in the pool's detected byte order.
    #[must_use]
    fn parse(rd: Reader, bp: &[u8]) -> Self {
        let mut dvas = [Dva::default(); 3];
        for (i, dva) in dvas.iter_mut().enumerate() {
            let base = i * 16;
            let w0 = rd.u64(bp, base);
            let w1 = rd.u64(bp, base + 8);
            *dva = Dva {
                vdev: (w0 >> 32) as u32,
                asize_sectors: (w0 & 0x00ff_ffff) as u32,
                offset_sectors: w1 & 0x7fff_ffff_ffff_ffff,
                gang: (w1 >> 63) & 1 == 1,
            };
        }
        // The packed props word sits after the three DVAs (offset 48).
        let props = rd.u64(bp, 48);
        let embedded = (props >> 39) & 1 == 1;
        BlkptrSummary {
            dvas,
            lsize_sectors: ((props & 0xffff) as u32).saturating_add(1),
            psize_sectors: (((props >> 16) & 0xffff) as u32).saturating_add(1),
            compression: ((props >> 32) & 0x7f) as u8,
            object_type: ((props >> 48) & 0xff) as u8,
            level: ((props >> 56) & 0x1f) as u8,
            embedded,
        }
    }
}

/// A parsed uberblock: the pool root at one transaction group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uberblock {
    /// Byte order this uberblock (and the pool) was written in.
    pub endian: Endian,
    /// `ub_magic` — always [`UBERBLOCK_MAGIC`] once detected.
    pub magic: u64,
    /// `ub_version` (SPA version; feature-flag pools report `5000`).
    pub version: u64,
    /// `ub_txg` — the transaction group this uberblock roots. Highest valid
    /// `txg` across the array = the active uberblock.
    pub txg: u64,
    /// `ub_guid_sum` — sum of all vdev GUIDs, a consistency check.
    pub guid_sum: u64,
    /// `ub_timestamp` — Unix seconds when this txg was written.
    pub timestamp: u64,
    /// `ub_rootbp` summary — the block pointer to the MOS objset.
    pub rootbp: BlkptrSummary,
}

impl Uberblock {
    /// Attempt to parse an uberblock slot, detecting byte order from the magic.
    ///
    /// Returns `None` when neither endian interpretation of the first 8 bytes is
    /// [`UBERBLOCK_MAGIC`] (an empty or non-uberblock slot).
    #[must_use]
    pub fn parse(slot: &[u8]) -> Option<Self> {
        // P0 STUB (RED): field decode + endian detection not yet implemented, so
        // every slot reports "not an uberblock" and the oracle assertions fail.
        // GREEN detects the magic, sets the byte order, and reads the fields.
        let _ = (slot, detect_endian, BlkptrSummary::parse);
        let _ = (
            OFF_VERSION,
            OFF_TXG,
            OFF_GUID_SUM,
            OFF_TIMESTAMP,
            OFF_ROOTBP,
        );
        None
    }
}

/// Detect the pool's byte order from an uberblock slot's magic field.
///
/// Returns `None` if the slot does not begin with [`UBERBLOCK_MAGIC`] in either
/// order (i.e. it is not a live uberblock).
#[must_use]
pub fn detect_endian(slot: &[u8]) -> Option<Endian> {
    if le_u64(slot, OFF_MAGIC) == UBERBLOCK_MAGIC {
        Some(Endian::Little)
    } else if be_u64(slot, OFF_MAGIC) == UBERBLOCK_MAGIC {
        Some(Endian::Big)
    } else {
        None
    }
}
