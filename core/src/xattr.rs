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
//! encoding gives each byte its own 4-byte big-endian word; they decode to
//! [`crate::NvValue::Bytes`].
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
    dxattr_pairs(packed)
}

/// Decode a packed `ZPL_DXATTR` nvlist into attributes. Pure, so the
/// corrupt-input branches are testable without a pool.
fn dxattr_pairs(packed: &[u8]) -> Vec<Xattr> {
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
    // No ZPL_XATTR attribute, a value too short to name an object, and the 0
    // sentinel all mean the same thing: no attribute directory.
    let Some(dir_obj) =
        sa_attr_bytes(&dnode.bonus, &registry, &layouts, ZPL_XATTR).and_then(xattr_dir_object)
    else {
        return Vec::new();
    };
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

/// The attribute-directory object named by a `ZPL_XATTR` value, or `None` when
/// the value is too short to hold one or is the 0 "no directory" sentinel.
fn xattr_dir_object(raw: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = raw.get(..8)?.try_into().ok()?;
    // 0 is the "no attribute directory" sentinel, not object 0.
    match u64::from_le_bytes(bytes) {
        0 => None,
        obj => Some(obj),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::{dir_xattrs, dxattr_pairs, sa_xattrs, xattr_dir_object};
    use crate::bytes::Endian;
    use crate::dnode::{Dnode, DNODE_SIZE};
    use crate::objset::{ObjsetPhys, OBJSET_MIN_SIZE};

    #[test]
    fn no_sa_context_yields_no_attributes_in_either_mode() {
        // An image with no ZPL master node has no SA registry to decode with.
        let zpl = ObjsetPhys::parse(&[0u8; OBJSET_MIN_SIZE], Endian::Little).unwrap();
        let dnode = Dnode::parse(&[0u8; DNODE_SIZE], Endian::Little).unwrap();
        assert!(sa_xattrs(&[], &zpl, &dnode).is_empty());
        assert!(dir_xattrs(&[], &zpl, &dnode).is_empty());
    }

    #[test]
    fn a_corrupt_dxattr_nvlist_yields_no_attributes() {
        assert!(dxattr_pairs(&[0xFF, 0x00, 0x00, 0x00]).is_empty());
    }

    #[test]
    fn a_non_byte_array_pair_is_not_reported_as_an_attribute() {
        // header, version, nvflag, one uint64 pair "n" = 7, terminator.
        let mut b = vec![0x01, 0x01, 0x00, 0x00];
        b.extend_from_slice(&0i32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        let mut pair = Vec::new();
        pair.extend_from_slice(&1i32.to_be_bytes());
        pair.extend_from_slice(b"n\0\0\0");
        pair.extend_from_slice(&8i32.to_be_bytes()); // DATA_TYPE_UINT64
        pair.extend_from_slice(&1i32.to_be_bytes());
        pair.extend_from_slice(&7u64.to_be_bytes());
        let encoded = i32::try_from(8 + pair.len()).unwrap();
        b.extend_from_slice(&encoded.to_be_bytes());
        b.extend_from_slice(&encoded.to_be_bytes());
        b.extend_from_slice(&pair);
        b.extend_from_slice(&[0u8; 8]);
        assert!(
            crate::nvlist::parse(&b).unwrap().get("n").is_some(),
            "control: the pair parses"
        );
        assert!(dxattr_pairs(&b).is_empty());
    }

    #[test]
    fn xattr_dir_object_rejects_short_and_sentinel_values() {
        assert_eq!(xattr_dir_object(&[1, 0, 0]), None, "shorter than a u64");
        assert_eq!(xattr_dir_object(&[0u8; 8]), None, "0 means no directory");
        assert_eq!(xattr_dir_object(&384u64.to_le_bytes()), Some(384));
    }
}
