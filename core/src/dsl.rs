//! DSL — the Dataset and Snapshot Layer: the objects in the MOS that name
//! datasets and point at each one's objset.
//!
//! The MOS object directory's `root_dataset` entry is the object id of the pool's
//! top **DSL directory** (`dsl_dir_phys_t`, in a dnode's bonus). Its
//! `dd_head_dataset_obj` is the object id of the active **DSL dataset**
//! (`dsl_dataset_phys_t`, also a bonus), whose `ds_bp` is a full `blkptr_t`
//! pointing at that dataset's ZPL objset.
//!
//! # `dsl_dir_phys_t` (bonus of a `DMU_OT_DSL_DIR` dnode — verified against `zdb`)
//!
//! | offset | field                  |
//! |--------|------------------------|
//! | 0      | `dd_creation_time`     |
//! | 8      | `dd_head_dataset_obj`  |
//! | 16     | `dd_parent_obj`        |
//! | 24     | `dd_origin_obj`        |
//! | 32     | `dd_child_dir_zapobj`  |
//! | …      | used/quota/props …     |
//!
//! # `dsl_dataset_phys_t` (bonus of the head-dataset dnode — verified against `zdb`)
//!
//! | offset | field                  |
//! |--------|------------------------|
//! | 0      | `ds_dir_obj`           |
//! | 8      | `ds_prev_snap_obj`     |
//! | 16     | `ds_prev_snap_txg`     |
//! | 24     | `ds_next_snap_obj`     |
//! | 32     | `ds_snapnames_zapobj`  |
//! | …      | creation/used/… (through 128) |
//! | 128    | `ds_bp` (a 128-byte `blkptr_t`) |
//!
//! `ds_bp` at bonus offset 128 is the block pointer to the dataset's objset —
//! resolve it with [`crate::read_block`] to obtain the ZPL `objset_phys_t`.

use crate::blkptr::Blkptr;
use crate::bytes::le_u64;
use crate::dnode::Dnode;

/// `dsl_dir_phys_t.dd_head_dataset_obj` bonus offset.
const DD_HEAD_DATASET_OBJ: usize = 8;
/// `dsl_dataset_phys_t.ds_prev_snap_obj` bonus offset — the object id of the
/// previous (older) snapshot dataset in this dataset's snapshot chain.
const DS_PREV_SNAP_OBJ: usize = 8;
/// `dsl_dataset_phys_t.ds_bp` bonus offset (a full 128-byte `blkptr_t`).
const DS_BP_OFFSET: usize = 128;

/// The head dataset object id from a DSL directory dnode's bonus
/// (`dsl_dir_phys_t.dd_head_dataset_obj`).
///
/// Returns `0` when the bonus is too short to hold the field (a corrupt or
/// non-DSL-dir dnode); `0` is not a valid dataset object, so callers treat it as
/// "absent".
#[must_use]
pub fn dsl_dir_head_dataset(dnode: &Dnode) -> u64 {
    le_u64(&dnode.bonus, DD_HEAD_DATASET_OBJ)
}

/// The previous-snapshot object id from a DSL dataset dnode's bonus
/// (`dsl_dataset_phys_t.ds_prev_snap_obj`) — the older snapshot dataset in this
/// dataset's snapshot chain, or `0` when there is none (the origin).
///
/// Following this field from the head dataset walks the linked list of snapshots
/// newest → oldest; each snapshot's [`dsl_dataset_bp`] points at a ZPL objset
/// that pins the filesystem state at the snapshot's creation. Returns `0` when
/// the bonus is too short to hold the field (a corrupt or non-DSL-dataset dnode).
#[must_use]
pub fn dsl_dataset_prev_snap(dnode: &Dnode) -> u64 {
    le_u64(&dnode.bonus, DS_PREV_SNAP_OBJ)
}

/// The `ds_bp` block pointer from a DSL dataset dnode's bonus
/// (`dsl_dataset_phys_t.ds_bp`) — the pointer to that dataset's objset.
///
/// Decoded in the dnode's byte order. A bonus shorter than `ds_bp` yields an
/// all-zero (hole) blkptr, which [`crate::read_block`] reads as zeros rather than
/// panicking.
#[must_use]
pub fn dsl_dataset_bp(dnode: &Dnode) -> Blkptr {
    let bp = dnode
        .bonus
        .get(DS_BP_OFFSET..DS_BP_OFFSET + 128)
        .unwrap_or(&[]);
    Blkptr::parse(bp, dnode.endian)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::{dsl_dataset_bp, dsl_dataset_prev_snap, dsl_dir_head_dataset};
    use crate::bytes::Endian;
    use crate::dnode::Dnode;

    /// Build a dnode with `dn_nblkptr = 0` and the given bonus bytes so the bonus
    /// starts right after the 64-byte core.
    fn dnode_with_bonus(bonus: &[u8]) -> Dnode {
        let mut raw = vec![0u8; 512];
        raw[0] = 12; // DMU_OT_DSL_DIR
        raw[3] = 0; // nblkptr = 0 -> bonus at offset 64
        let blen = bonus.len().min(512 - 64);
        raw[10..12].copy_from_slice(&(blen as u16).to_le_bytes());
        raw[64..64 + blen].copy_from_slice(&bonus[..blen]);
        Dnode::parse(&raw, Endian::Little).unwrap()
    }

    #[test]
    fn head_dataset_obj_reads_bonus_field() {
        let mut bonus = vec![0u8; 256];
        bonus[8..16].copy_from_slice(&54u64.to_le_bytes());
        let dnode = dnode_with_bonus(&bonus);
        assert_eq!(dsl_dir_head_dataset(&dnode), 54);
    }

    #[test]
    fn head_dataset_obj_zero_when_bonus_short() {
        let dnode = dnode_with_bonus(&[0u8; 4]);
        assert_eq!(dsl_dir_head_dataset(&dnode), 0);
    }

    #[test]
    fn prev_snap_obj_reads_bonus_field() {
        let mut bonus = vec![0u8; 320];
        bonus[8..16].copy_from_slice(&86u64.to_le_bytes());
        let dnode = dnode_with_bonus(&bonus);
        assert_eq!(dsl_dataset_prev_snap(&dnode), 86);
    }

    #[test]
    fn prev_snap_obj_zero_when_bonus_short() {
        let dnode = dnode_with_bonus(&[0u8; 4]);
        assert_eq!(dsl_dataset_prev_snap(&dnode), 0);
    }

    #[test]
    fn dataset_bp_reads_blkptr_at_offset_128() {
        let mut bonus = vec![0u8; 320];
        // ds_bp DVA[0] at bonus 128: offset_sectors in w1 (bonus 128+8).
        bonus[128..136].copy_from_slice(&8u64.to_le_bytes()); // w0 asize=8
        bonus[136..144].copy_from_slice(&7u64.to_le_bytes()); // w1 offset=7
        let dnode = dnode_with_bonus(&bonus);
        let bp = dsl_dataset_bp(&dnode);
        assert_eq!(bp.dvas[0].asize_sectors, 8);
        assert_eq!(bp.dvas[0].offset_sectors, 7);
    }

    #[test]
    fn dataset_bp_is_hole_when_bonus_short() {
        let dnode = dnode_with_bonus(&[0u8; 64]);
        let bp = dsl_dataset_bp(&dnode);
        assert!(bp.is_hole());
    }
}
