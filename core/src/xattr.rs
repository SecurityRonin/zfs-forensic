//! ZFS extended attributes — both storage modes.
//!
//! ZFS keeps extended attributes two structurally unrelated ways, chosen per
//! dataset by the `xattr` property. They share no on-disk structure, so a reader
//! must handle both or it silently reports "no attributes" on half the pools it
//! meets — a failure that looks exactly like a file that genuinely has none.
//!
//! | `xattr=` | where the attributes live |
//! |---|---|
//! | `sa` | a packed **nvlist** in the `ZPL_DXATTR` System Attribute |
//! | `dir` | a hidden **ZAP directory**, each attribute a separate file object |
//!
//! [`list_xattrs`] tries both and returns whatever it finds, rather than asking
//! the caller which mode a pool uses: the property lives on the dataset, and an
//! image under examination may hold datasets set either way.
//!
//! ## `sa` — the `ZPL_DXATTR` nvlist
//!
//! `ZPL_DXATTR` is a **variable-length** System Attribute, which is why
//! [`crate::sa::decode_sa_bonus`] cannot reach it: that walk stops at the first
//! variable-length attribute instead of mis-skipping it.
//! [`crate::sa::sa_attr_bytes`] does the longer walk, consuming the header's
//! `sa_lengths[]` array, and hands over the packed nvlist.
//!
//! Attribute values inside that nvlist are `DATA_TYPE_BYTE_ARRAY`, whose XDR
//! encoding gives each byte its own 4-byte big-endian word — see
//! [`crate::nvlist`].
//!
//! ## `dir` — the hidden attribute directory
//!
//! The znode's `ZPL_XATTR` attribute holds the object id of a ZAP directory
//! whose entries map each attribute name to a file object holding its value.
//! Reading one is then an ordinary directory listing plus an ordinary file read.
//!
//! ## What is NOT covered
//!
//! A `ZPL_DXATTR` too large for the dnode's bonus buffer moves to a **spill
//! block**, flagged by `DNODE_FLAG_SPILL_BLKPTR`. The committed fixtures carry a
//! 108-byte DXATTR that fits the bonus, so the spill path has no validated
//! sample here. It is therefore not implemented rather than written blind: an
//! object whose attributes live in a spill block reports none, and
//! [`has_unread_spill_xattrs`] exists so a caller can tell that apart from a
//! file with no attributes at all.

use crate::dnode::Dnode;
use crate::nvlist::{self, NvValue};
use crate::objset::ObjsetPhys;
use crate::read::mos_dnode;
use crate::sa::sa_attr_bytes;
use crate::zpl::{zpl_list_dir, zpl_read_file, zpl_sa_context};

/// `DNODE_FLAG_SPILL_BLKPTR` — the dnode carries a spill block pointer.
const DNODE_FLAG_SPILL_BLKPTR: u8 = 1 << 2;

/// Registry name of the packed-xattr System Attribute (`xattr=sa`).
const ZPL_DXATTR: &str = "ZPL_DXATTR";
/// Registry name of the attribute-directory pointer (`xattr=dir`).
const ZPL_XATTR: &str = "ZPL_XATTR";

/// One extended attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xattr {
    /// The attribute's full name as the system presents it, e.g. `user.small`
    /// on Linux or `small` on `FreeBSD` — ZFS stores whatever the caller set, so
    /// nothing is reconstructed or stripped here.
    pub name: String,
    /// The attribute's value.
    pub value: Vec<u8>,
}

/// List every extended attribute on `object_id`, whichever way it is stored.
///
/// An object with no attributes yields an empty vector; that is not an error.
/// Both storage modes are attempted because a pool may hold datasets configured
/// either way, and the mode is a property of the dataset rather than of the
/// image.
#[must_use]
pub fn list_xattrs(image: &[u8], zpl: &ObjsetPhys, object_id: u64) -> Vec<Xattr> {
    let Some(dnode) = mos_dnode(image, zpl, object_id) else {
        return Vec::new();
    };
    let mut out = sa_xattrs(image, zpl, &dnode);
    if out.is_empty() {
        out = dir_xattrs(image, zpl, &dnode);
    }
    out
}

/// True when this object's attributes are in a spill block this reader does not
/// follow, so an empty result from [`list_xattrs`] must NOT be read as "no
/// extended attributes".
///
/// The distinction matters more than the missing capability: an examiner can act
/// on "not recovered", but "none present" is a claim about the evidence.
#[must_use]
pub fn has_unread_spill_xattrs(image: &[u8], zpl: &ObjsetPhys, object_id: u64) -> bool {
    let Some(dnode) = mos_dnode(image, zpl, object_id) else {
        return false;
    };
    dnode.dn_flags & DNODE_FLAG_SPILL_BLKPTR != 0 && sa_xattrs(image, zpl, &dnode).is_empty()
}

/// `xattr=sa`: decode the `ZPL_DXATTR` nvlist out of the dnode's bonus buffer.
fn sa_xattrs(image: &[u8], zpl: &ObjsetPhys, dnode: &Dnode) -> Vec<Xattr> {
    let Some((registry, layouts)) = zpl_sa_context(image, zpl) else {
        return Vec::new();
    };
    let Some(packed) = sa_attr_bytes(&dnode.bonus, &registry, &layouts, ZPL_DXATTR) else {
        return Vec::new();
    };
    let Ok(nv) = nvlist::parse(packed) else {
        return Vec::new();
    };
    nv.pairs()
        .iter()
        .filter_map(|(name, value)| match value {
            NvValue::Bytes(b) => Some(Xattr {
                name: name.clone(),
                value: b.clone(),
            }),
            // A non-byte-array pair is not an attribute value; skipping it is
            // right, but the name is kept out of the list rather than reported
            // with empty contents, which would read as a zero-length attribute.
            _ => None,
        })
        .collect()
}

/// `xattr=dir`: read the hidden attribute directory named by `ZPL_XATTR`.
fn dir_xattrs(image: &[u8], zpl: &ObjsetPhys, dnode: &Dnode) -> Vec<Xattr> {
    let Some((registry, layouts)) = zpl_sa_context(image, zpl) else {
        return Vec::new();
    };
    let Some(raw) = sa_attr_bytes(&dnode.bonus, &registry, &layouts, ZPL_XATTR) else {
        return Vec::new();
    };
    if raw.len() < 8 {
        return Vec::new();
    }
    let dir_obj = u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]);
    // 0 is the "no attribute directory" sentinel, not object 0.
    if dir_obj == 0 {
        return Vec::new();
    }
    zpl_list_dir(image, zpl, dir_obj)
        .into_iter()
        .filter_map(|(name, obj)| {
            // Each entry names a file object holding that attribute's bytes. An
            // unreadable one is dropped rather than reported with an empty
            // value, which would understate the attribute as zero-length.
            let value = zpl_read_file(image, zpl, obj).ok()?;
            Some(Xattr { name, value })
        })
        .collect()
}
