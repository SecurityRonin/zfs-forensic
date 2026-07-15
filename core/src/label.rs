//! Vdev label geometry and parsing.
//!
//! Every ZFS vdev carries **four** 256 KiB labels — two at the front (L0, L1) and
//! two at the back (L2, L3) — so the config survives partial overwrites. Each
//! label is:
//!
//! | region              | size    | offset within label |
//! |---------------------|---------|---------------------|
//! | blank pad           | 8 KiB   | 0                   |
//! | boot-block header   | 8 KiB   | 8 KiB               |
//! | packed nvlist config| 112 KiB | 16 KiB              |
//! | uberblock ring array| 128 KiB | 128 KiB             |
//!
//! Label positions on a vdev of `vdev_size` bytes (verified against `zdb -l`,
//! which reports `labels = 0 1 2 3`):
//!
//! - L0 @ `0`
//! - L1 @ `256 KiB`
//! - L2 @ `vdev_size − 512 KiB`
//! - L3 @ `vdev_size − 256 KiB`
//!
//! The uberblock ring holds `128 KiB / slot_size` slots, where
//! `slot_size = max(1 KiB, 2^ashift)`. So an `ashift == 12` (4 KiB) pool has 32
//! slots, not 128 — the count is derived from `ashift`, never hard-coded.

use crate::error::ZfsError;
use crate::nvlist::{self, NvList};
use crate::uberblock::{Uberblock, UBERBLOCK_MIN_SHIFT};

/// Size of a single vdev label (256 KiB).
pub const LABEL_SIZE: usize = 256 * 1024;
/// Size of the leading blank pad region (8 KiB).
pub const VDEV_PAD_SIZE: usize = 8 * 1024;
/// Size of the boot-block header region (8 KiB).
pub const VDEV_BOOT_HEADER_SIZE: usize = 8 * 1024;
/// Offset of the packed nvlist config within a label (16 KiB).
pub const NVLIST_OFFSET: usize = VDEV_PAD_SIZE + VDEV_BOOT_HEADER_SIZE;
/// Size of the packed nvlist config region (112 KiB).
pub const NVLIST_SIZE: usize = 112 * 1024;
/// Offset of the uberblock ring array within a label (128 KiB).
pub const UBERBLOCK_RING_OFFSET: usize = 128 * 1024;
/// Size of the uberblock ring array (128 KiB).
pub const UBERBLOCK_RING_SIZE: usize = 128 * 1024;

/// The byte offsets of the four vdev labels on a vdev of `vdev_size` bytes.
///
/// Returns the front pair `[L0, L1]` unconditionally; the back pair `[L2, L3]`
/// is `None` when `vdev_size` is too small to hold them without overlapping the
/// front labels (a degenerate/truncated image).
#[must_use]
pub fn label_offsets(vdev_size: u64) -> ([u64; 2], Option<[u64; 2]>) {
    let front = [0u64, LABEL_SIZE as u64];
    let back_start = vdev_size.checked_sub(2 * LABEL_SIZE as u64);
    let back = match back_start {
        Some(_) if vdev_size >= 4 * LABEL_SIZE as u64 => Some([
            vdev_size - 2 * LABEL_SIZE as u64,
            vdev_size - LABEL_SIZE as u64,
        ]),
        _ => None,
    };
    (front, back)
}

/// A parsed vdev label: its config nvlist and its active uberblock.
#[derive(Debug, Clone)]
pub struct VdevLabel {
    /// The decoded pool config nvlist (`version`/`name`/`pool_guid`/`vdev_tree`…).
    pub config: NvList,
    /// The active uberblock — highest valid `txg` in this label's ring.
    pub active_uberblock: Uberblock,
    /// The ring slot index the active uberblock was found in.
    pub active_slot: usize,
}

impl VdevLabel {
    /// Parse a single 256 KiB label buffer.
    ///
    /// The nvlist `vdev_tree.ashift` determines the uberblock slot size and hence
    /// the number of slots scanned. Falls back to the 1 KiB minimum slot size
    /// (128 slots) when `ashift` is absent or absurd.
    ///
    /// # Errors
    ///
    /// - [`ZfsError::Truncated`] if the buffer is smaller than one label.
    /// - Propagates [`nvlist::parse`] errors (bad encoding / allocation bomb).
    /// - [`ZfsError::NoUberblock`] if no ring slot holds a valid uberblock.
    pub fn parse(label: &[u8]) -> Result<Self, ZfsError> {
        if label.len() < LABEL_SIZE {
            return Err(ZfsError::Truncated {
                structure: "vdev label",
                need: LABEL_SIZE,
                have: label.len(),
            });
        }
        let nv_region = label
            .get(NVLIST_OFFSET..NVLIST_OFFSET + NVLIST_SIZE)
            .ok_or(ZfsError::Truncated {
                structure: "label nvlist region",
                need: NVLIST_OFFSET + NVLIST_SIZE,
                have: label.len(),
            })?;
        let config = nvlist::parse(nv_region)?;

        let ashift = config
            .vdev_tree()
            .map(|v| v.ashift)
            .filter(|&a| (UBERBLOCK_MIN_SHIFT as u64..=16).contains(&a))
            .unwrap_or(UBERBLOCK_MIN_SHIFT as u64);
        let slot_size = 1usize << ashift.max(u64::from(UBERBLOCK_MIN_SHIFT));
        let slot_count = UBERBLOCK_RING_SIZE / slot_size;

        let ring = label
            .get(UBERBLOCK_RING_OFFSET..UBERBLOCK_RING_OFFSET + UBERBLOCK_RING_SIZE)
            .ok_or(ZfsError::Truncated {
                structure: "uberblock ring",
                need: UBERBLOCK_RING_OFFSET + UBERBLOCK_RING_SIZE,
                have: label.len(),
            })?;

        let (active_uberblock, active_slot) =
            active_uberblock(ring, slot_size, slot_count).ok_or(ZfsError::NoUberblock {
                scanned: slot_count,
            })?;

        Ok(VdevLabel {
            config,
            active_uberblock,
            active_slot,
        })
    }
}

/// Scan an uberblock ring, returning the valid uberblock with the highest `txg`
/// and its slot index, or `None` if no slot holds a valid uberblock.
#[must_use]
pub fn active_uberblock(
    ring: &[u8],
    slot_size: usize,
    slot_count: usize,
) -> Option<(Uberblock, usize)> {
    let mut best: Option<(Uberblock, usize)> = None;
    for slot in 0..slot_count {
        let start = slot.checked_mul(slot_size)?;
        let Some(bytes) = ring.get(start..start.saturating_add(slot_size)) else {
            break;
        };
        let Some(ub) = Uberblock::parse(bytes) else {
            continue;
        };
        match best {
            Some((cur, _)) if ub.txg <= cur.txg => {}
            _ => best = Some((ub, slot)),
        }
    }
    best
}
