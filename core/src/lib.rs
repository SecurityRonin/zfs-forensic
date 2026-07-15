//! `zfs-core` — a pure-Rust, from-scratch ZFS on-disk reader.
//!
//! P0 parses the ZFS bootstrap: the four **vdev labels**, the XDR-encoded
//! **nvlist config** (pool `version`/`name`/`pool_guid`/`txg` and the nested
//! `vdev_tree` `ashift`/`asize`), and the **endian-adaptive uberblock array**
//! (active = highest valid `txg`), exposing the active uberblock's `ub_rootbp`
//! block pointer to the MOS. Later phases resolve the block-pointer tree,
//! dnodes, objsets, ZAP, and datasets.
//!
//! Import path is `zfs_core` (the bare `zfs` and `zfs-core` crate names are both
//! taken on crates.io — see the repo README), e.g. `use zfs_core::VdevLabel;`.
//!
//! # Safety and robustness
//!
//! This crate parses untrusted, attacker-controllable disk images. It is
//! `#![forbid(unsafe_code)]` and every integer is read through bounds-checked,
//! endian-adaptive helpers ([`bytes`]) that yield `0`/`None` out of range rather
//! than panic (the Paranoid Gatekeeper standard). nvlist length/count fields are
//! capped against allocation bombs.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod blkptr;
pub mod bytes;
pub mod checksum;
pub mod compress;
mod dmu;
mod dnode;
mod dsl;
mod error;
mod label;
mod nvlist;
mod objset;
mod read;
mod sa;
mod uberblock;
mod zap;
mod zpl;

pub use blkptr::{detect_blkptr_endian, Blkptr, Dva, BOOT_SKEW, BPE_PAYLOAD_SIZE};
pub use bytes::{Endian, Reader};
pub use checksum::ChecksumType;
pub use compress::CompressType;
pub use dmu::DmuType;
pub use dnode::{Dnode, BLKPTR_SIZE, DNODE_CORE_SIZE, DNODE_SIZE};
pub use dsl::{dsl_dataset_bp, dsl_dataset_prev_snap, dsl_dir_head_dataset};
pub use error::ZfsError;
pub use label::{
    active_uberblock, label_offsets, VdevLabel, LABEL_SIZE, NVLIST_OFFSET, NVLIST_SIZE,
    UBERBLOCK_RING_OFFSET, UBERBLOCK_RING_SIZE, VDEV_BOOT_HEADER_SIZE, VDEV_PAD_SIZE,
};
pub use nvlist::{NvList, NvValue, VdevTree};
pub use objset::{ObjsetPhys, DMU_OST_META, DMU_OST_ZFS};
pub use read::{
    mos_dnode, read_block, read_dnode_data, Block, MAX_BLOCK_SIZE, MAX_INDIRECT_LEVELS,
};
pub use sa::{
    decode_sa_bonus, decode_znode_phys, parse_sa_layouts, parse_sa_registry, SaAttrDesc, SaLayouts,
    SaRegistry, ZplAttrs, SA_MAGIC, SA_TIME_SIZE, ZNODE_PHYS_SIZE,
};
pub use uberblock::{BlkptrSummary, Uberblock, UBERBLOCK_MAGIC, UBERBLOCK_MIN_SHIFT, UB_MMP_MAGIC};
pub use zap::{
    read_zap_object, zap_list, zap_list_arrays, zap_lookup, ZAP_LEAF_MAGIC, ZAP_MAGIC, ZBT_HEADER,
    ZBT_LEAF, ZBT_MICRO,
};
pub use zpl::{
    zpl_attrs, zpl_list_dir, zpl_lookup, zpl_master_root, zpl_objset, zpl_read_file,
    zpl_read_file_with, zpl_read_path, zpl_root_dir, zpl_sa_context, DMU_OT_SA, DMU_OT_ZNODE,
    SA_LAYOUTS_NAME, SA_REGISTRY_NAME, ZPL_DIRENT_OBJ_MASK, ZPL_MASTER_NODE_OBJ, ZPL_ROOT_NAME,
    ZPL_SA_ATTRS_NAME,
};

/// Parse a packed XDR nvlist config from a buffer beginning with the 4-byte
/// packed header. Convenience re-export of [`nvlist::parse`].
///
/// # Errors
///
/// See [`nvlist::parse`].
pub fn nvlist_parse(data: &[u8]) -> Result<NvList, ZfsError> {
    nvlist::parse(data)
}

/// Parse a single uberblock slot, detecting byte order from the magic. Returns
/// `None` for a slot that is not a live uberblock. Convenience re-export of
/// [`uberblock::Uberblock::parse`].
#[must_use]
pub fn uberblock_parse(slot: &[u8]) -> Option<Uberblock> {
    Uberblock::parse(slot)
}
