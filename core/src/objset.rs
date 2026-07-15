//! `objset_phys_t` — the header of a DMU object set (the MOS or a dataset).
//!
//! An objset is what a blkptr of type `DMU_OT_OBJSET` points at (the uberblock's
//! `rootbp` → the MOS; a dataset's `ds_bp` → that dataset's objset). It opens
//! with a **meta-dnode** whose block tree *is* the array of every object's
//! `dnode_phys_t`, followed by the ZIL header and the objset type/flags.
//!
//! # On-disk layout (`objset_phys_t` — verified against `dmu_objset.h`)
//!
//! | offset | field              | size |
//! |--------|--------------------|------|
//! | 0      | `os_meta_dnode`    | 512  (a `dnode_phys_t`) |
//! | 512    | `os_zil_header`    | 192  (`zil_header_t`)   |
//! | 704    | `os_type`          | 8    |
//! | 712    | `os_flags`         | 8    |
//! | …      | MACs / pad / user-accounting dnodes (V2/V3) |
//!
//! `os_type` is the `dmu_objset_type` (`DMU_OST_META` = 1 for the MOS,
//! `DMU_OST_ZFS` = 2 for a filesystem dataset). The meta-dnode's block tree is
//! walked (via [`crate::read_dnode_data`]) to fetch any object's dnode.

use crate::bytes::{Endian, Reader};
use crate::dnode::Dnode;
use crate::error::ZfsError;

/// Offset of `os_type` within an objset (after the 512-byte meta-dnode and the
/// 192-byte `os_zil_header`).
pub const OS_TYPE_OFFSET: usize = 704;
/// Offset of `os_flags` within an objset.
pub const OS_FLAGS_OFFSET: usize = 712;
/// The minimum objset size (`OBJSET_PHYS_SIZE_V1`): meta-dnode + ZIL + type/flags.
pub const OBJSET_MIN_SIZE: usize = 1024;

/// `DMU_OST_META` — the objset type of the MOS.
pub const DMU_OST_META: u64 = 1;
/// `DMU_OST_ZFS` — the objset type of a ZPL filesystem dataset.
pub const DMU_OST_ZFS: u64 = 2;

/// A parsed `objset_phys_t`.
#[derive(Debug, Clone)]
pub struct ObjsetPhys {
    /// The meta-dnode (`os_meta_dnode`) — its block tree is the array of every
    /// object's `dnode_phys_t`.
    pub meta_dnode: Dnode,
    /// `os_type` — the objset type (`DMU_OST_META` / `DMU_OST_ZFS` / …).
    pub os_type: u64,
    /// `os_flags` — objset flags (`OBJSET_FLAG_*`).
    pub os_flags: u64,
    /// The byte order this objset is written in.
    pub endian: Endian,
}

impl ObjsetPhys {
    /// Parse an `objset_phys_t` from a decompressed objset block, in `endian`.
    ///
    /// # Errors
    ///
    /// [`ZfsError::Truncated`] if `data` is smaller than the meta-dnode + ZIL +
    /// type/flags core, or the meta-dnode fails to parse.
    pub fn parse(data: &[u8], endian: Endian) -> Result<Self, ZfsError> {
        if data.len() < OBJSET_MIN_SIZE {
            return Err(ZfsError::Truncated {
                structure: "objset_phys",
                need: OBJSET_MIN_SIZE,
                have: data.len(),
            });
        }
        let meta_dnode = Dnode::parse(data, endian).ok_or(ZfsError::Truncated {
            structure: "objset meta-dnode",
            need: 512,
            have: data.len(),
        })?;
        let rd = Reader::new(endian);
        Ok(ObjsetPhys {
            meta_dnode,
            os_type: rd.u64(data, OS_TYPE_OFFSET),
            os_flags: rd.u64(data, OS_FLAGS_OFFSET),
            endian,
        })
    }
}

#[cfg(test)]
mod unit {
    use super::{ObjsetPhys, OS_TYPE_OFFSET};
    use crate::bytes::Endian;

    #[test]
    fn parse_truncated_errors() {
        assert!(ObjsetPhys::parse(&[0u8; 512], Endian::Little).is_err());
    }

    #[test]
    fn parse_reads_meta_dnode_and_type() {
        let mut data = [0u8; 1024];
        data[0] = 10; // meta-dnode dn_type = DNODE
        data[3] = 3; // nblkptr
        data[OS_TYPE_OFFSET..OS_TYPE_OFFSET + 8].copy_from_slice(&1u64.to_le_bytes());
        let os = ObjsetPhys::parse(&data, Endian::Little).unwrap();
        assert_eq!(os.os_type, 1);
        assert_eq!(os.meta_dnode.dn_type, 10);
    }
}
