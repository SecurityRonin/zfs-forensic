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

pub mod bytes;
mod error;
mod label;
mod nvlist;
mod uberblock;

pub use bytes::{Endian, Reader};
pub use error::ZfsError;
pub use label::{
    active_uberblock, label_offsets, VdevLabel, LABEL_SIZE, NVLIST_OFFSET, NVLIST_SIZE,
    UBERBLOCK_RING_OFFSET, UBERBLOCK_RING_SIZE, VDEV_BOOT_HEADER_SIZE, VDEV_PAD_SIZE,
};
pub use nvlist::{NvList, NvValue, VdevTree};
pub use uberblock::{
    BlkptrSummary, Dva, Uberblock, UBERBLOCK_MAGIC, UBERBLOCK_MIN_SHIFT, UB_MMP_MAGIC,
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
