//! ZPL — the ZFS POSIX Layer: the filesystem objects inside a dataset's objset.
//!
//! A dataset's objset (reached via MOS → DSL → `ds_bp`) has a meta-dnode whose
//! block tree is the array of that filesystem's objects. Two objects bootstrap
//! the directory tree:
//!
//! - **Master node** — object **1**, a ZAP naming `VERSION`, `ROOT`, `SA_ATTRS`,
//!   `DELETE_QUEUE`. `ROOT` is the object id of the root directory (commonly
//!   object 3, but the master node is authoritative — a real pool may use any id,
//!   e.g. object 34).
//! - **Root directory** — the object named `ROOT`, a directory ZAP mapping each
//!   child name → a 64-bit value whose **low 48 bits are the child object id** and
//!   whose **top 4 bits are the `ZFS_DIRENT_TYPE`** (file/dir/…). Small
//!   directories are stored as an embedded-blkptr micro-ZAP.
//!
//! This module wires the DSL walk into a ZPL objset and lists directories by name
//! → object id, masking the dirent-type bits off the value.

use crate::blkptr::Blkptr;
use crate::dnode::Dnode;
use crate::dsl::{dsl_dataset_bp, dsl_dir_head_dataset};
use crate::error::ZfsError;
use crate::objset::ObjsetPhys;
use crate::read::{mos_dnode, read_block, read_dnode_data};
use crate::sa::{
    decode_sa_bonus, decode_znode_phys, parse_sa_layouts, parse_sa_registry, SaLayouts, SaRegistry,
    ZplAttrs,
};
use crate::zap::{read_zap_object, zap_list, zap_lookup};

/// The ZPL master node object id (fixed by the on-disk format).
pub const ZPL_MASTER_NODE_OBJ: u64 = 1;
/// The name under which the master node records the root directory's object id.
pub const ZPL_ROOT_NAME: &str = "ROOT";
/// The name under which the master node records the SA master object id.
pub const ZPL_SA_ATTRS_NAME: &str = "SA_ATTRS";
/// The SA master object's `REGISTRY` entry name (→ the attribute-registration ZAP).
pub const SA_REGISTRY_NAME: &str = "REGISTRY";
/// The SA master object's `LAYOUTS` entry name (→ the attribute-layouts ZAP).
pub const SA_LAYOUTS_NAME: &str = "LAYOUTS";
/// `DMU_OT_SA` (44) — a dnode bonus holding System Attributes.
pub const DMU_OT_SA: u8 = 44;
/// `DMU_OT_ZNODE` (17) — a legacy `znode_phys_t` bonus.
pub const DMU_OT_ZNODE: u8 = 17;
/// Mask for the object id within a ZPL directory-entry value (low 48 bits); the
/// top 4 bits carry the `ZFS_DIRENT_TYPE`.
pub const ZPL_DIRENT_OBJ_MASK: u64 = 0x0000_ffff_ffff_ffff;

/// Resolve a dataset's ZPL `objset_phys_t` from the MOS, walking
/// MOS object directory → `root_dataset` (DSL dir) → `dd_head_dataset_obj`
/// (DSL dataset) → `ds_bp` → the ZPL objset block.
///
/// Returns `None` if any hop is missing (object not found, ZAP entry absent, or
/// the objset block cannot be read/parsed) — never panics.
#[must_use]
pub fn zpl_objset(image: &[u8], mos: &ObjsetPhys) -> Option<ObjsetPhys> {
    // Object 1 of the MOS is the object directory (a ZAP). root_dataset -> DSL dir.
    let objdir = mos_dnode(image, mos, 1)?;
    let objdir_data = read_zap_object(image, &objdir).ok()?;
    let root_dataset = zap_lookup(&objdir_data, "root_dataset")?;

    let dsl_dir = mos_dnode(image, mos, root_dataset)?;
    let head = dsl_dir_head_dataset(&dsl_dir);
    if head == 0 {
        return None;
    }
    let dataset = mos_dnode(image, mos, head)?;
    let ds_bp: Blkptr = dsl_dataset_bp(&dataset);
    let block = read_block(image, &ds_bp).ok()?;
    ObjsetPhys::parse(&block.data, mos.endian).ok()
}

/// The root directory's object id, read from a ZPL objset's master node
/// (object 1) `ROOT` entry. Returns `None` if the master node or the `ROOT`
/// entry is absent.
#[must_use]
pub fn zpl_master_root(image: &[u8], zpl: &ObjsetPhys) -> Option<u64> {
    let master = mos_dnode(image, zpl, ZPL_MASTER_NODE_OBJ)?;
    let data = read_zap_object(image, &master).ok()?;
    zap_lookup(&data, ZPL_ROOT_NAME)
}

/// The root directory's dnode within a ZPL objset (the object named `ROOT` by the
/// master node). Returns `None` if the master node, the `ROOT` entry, or the root
/// object cannot be resolved.
#[must_use]
pub fn zpl_root_dir(image: &[u8], zpl: &ObjsetPhys) -> Option<Dnode> {
    let root_id = zpl_master_root(image, zpl)?;
    mos_dnode(image, zpl, root_id)
}

/// List a ZPL directory object `dir_obj_id` within objset `zpl` as
/// `(name, object_id)` pairs, masking the `ZFS_DIRENT_TYPE` bits off each value.
///
/// A directory is a ZAP; this reads its object data and decodes every entry.
/// Returns an empty list (never panics) if the object is absent or unreadable.
#[must_use]
pub fn zpl_list_dir(image: &[u8], zpl: &ObjsetPhys, dir_obj_id: u64) -> Vec<(String, u64)> {
    let Some(dir) = mos_dnode(image, zpl, dir_obj_id) else {
        return Vec::new();
    };
    let Ok(data) = read_zap_object(image, &dir) else {
        return Vec::new();
    };
    zap_list(&data)
        .into_iter()
        .map(|(name, value)| (name, value & ZPL_DIRENT_OBJ_MASK))
        .collect()
}

/// Build the SA decoding context for a ZPL objset: parse the `REGISTRY` and
/// `LAYOUTS` ZAPs reachable from the master node's `SA_ATTRS` entry.
///
/// Walk: master node (object 1) `SA_ATTRS` → the SA master object (a micro-ZAP
/// naming `REGISTRY` and `LAYOUTS`) → those two objects' ZAP data. Returns `None`
/// if any hop is missing (a pool with no SA — pure legacy znode — has no
/// `SA_ATTRS`).
#[must_use]
pub fn zpl_sa_context(image: &[u8], zpl: &ObjsetPhys) -> Option<(SaRegistry, SaLayouts)> {
    let master = mos_dnode(image, zpl, ZPL_MASTER_NODE_OBJ)?;
    let master_data = read_zap_object(image, &master).ok()?;
    let sa_master_obj = zap_lookup(&master_data, ZPL_SA_ATTRS_NAME)?;

    let sa_master = mos_dnode(image, zpl, sa_master_obj)?;
    let sa_master_data = read_zap_object(image, &sa_master).ok()?;
    let registry_obj = zap_lookup(&sa_master_data, SA_REGISTRY_NAME)?;
    let layouts_obj = zap_lookup(&sa_master_data, SA_LAYOUTS_NAME)?;

    let registry_dnode = mos_dnode(image, zpl, registry_obj)?;
    let registry_data = read_zap_object(image, &registry_dnode).ok()?;
    let layouts_dnode = mos_dnode(image, zpl, layouts_obj)?;
    let layouts_data = read_zap_object(image, &layouts_dnode).ok()?;

    Some((
        parse_sa_registry(&registry_data),
        parse_sa_layouts(&layouts_data),
    ))
}

/// Decode object `object_id`'s ZPL metadata into [`ZplAttrs`], dispatching on the
/// dnode's bonus type: `DMU_OT_SA` (44) → SA decode via `registry`/`layouts`;
/// `DMU_OT_ZNODE` (17) → legacy `znode_phys_t`. Returns `None` if the object is
/// absent, its bonus type is neither, or the bonus does not decode.
#[must_use]
pub fn zpl_attrs(
    image: &[u8],
    zpl: &ObjsetPhys,
    registry: &SaRegistry,
    layouts: &SaLayouts,
    object_id: u64,
) -> Option<ZplAttrs> {
    let dnode = mos_dnode(image, zpl, object_id)?;
    match dnode.dn_bonustype {
        DMU_OT_SA => decode_sa_bonus(&dnode.bonus, registry, layouts, dnode.endian),
        DMU_OT_ZNODE => decode_znode_phys(&dnode.bonus, dnode.endian),
        _ => None,
    }
}

/// Read object `object_id`'s file content: concatenate its data blocks
/// `0..=dn_maxblkid` and truncate to the object's logical size.
///
/// The logical size is taken from the object's SA/znode metadata when
/// `registry`/`layouts` decode it; when that is unavailable (`None`), the content
/// is returned untruncated (whole blocks) so no bytes are silently dropped.
///
/// # Errors
///
/// - [`ZfsError::Truncated`] if the object is absent or has a zero block size.
/// - Propagates [`read_dnode_data`] errors along the block tree.
pub fn zpl_read_file_with(
    image: &[u8],
    zpl: &ObjsetPhys,
    object_id: u64,
    size: Option<u64>,
) -> Result<Vec<u8>, ZfsError> {
    let dnode = mos_dnode(image, zpl, object_id).ok_or(ZfsError::Truncated {
        structure: "zpl file object (absent or empty slot)",
        need: 1,
        have: 0,
    })?;
    let block_size = dnode.data_block_size();
    if block_size == 0 {
        return Err(ZfsError::Truncated {
            structure: "zpl file object (zero block size)",
            need: 1,
            have: 0,
        });
    }
    // Cap the block count against a lying dn_maxblkid; MAX_BLOCK is the file cap.
    const MAX_FILE_BYTES: usize = 512 * 1024 * 1024;
    let max_blocks = (MAX_FILE_BYTES / block_size).max(1);
    let nblocks = (dnode.dn_maxblkid as usize)
        .saturating_add(1)
        .min(max_blocks);
    let mut out = Vec::with_capacity(nblocks.saturating_mul(block_size).min(MAX_FILE_BYTES));
    for blkid in 0..nblocks {
        let block = read_dnode_data(image, &dnode, blkid as u64)?;
        out.extend_from_slice(&block.data);
    }
    if let Some(sz) = size {
        // Truncate to the logical size, capped so a lying size can't grow `out`.
        let sz = usize::try_from(sz).unwrap_or(usize::MAX).min(out.len());
        out.truncate(sz);
    }
    Ok(out)
}

/// Read object `object_id`'s file content, truncated to its SA/znode logical size.
///
/// Convenience over [`zpl_read_file_with`] that first builds the SA context
/// ([`zpl_sa_context`]) to learn the logical size. If the object's size cannot be
/// determined, the whole-block content is returned untruncated.
///
/// # Errors
///
/// See [`zpl_read_file_with`].
pub fn zpl_read_file(image: &[u8], zpl: &ObjsetPhys, object_id: u64) -> Result<Vec<u8>, ZfsError> {
    let size = zpl_sa_context(image, zpl)
        .and_then(|(reg, layouts)| zpl_attrs(image, zpl, &reg, &layouts, object_id))
        .map(|a| a.size);
    zpl_read_file_with(image, zpl, object_id, size)
}

/// Resolve an absolute path (`/dir/sub/file`) within a ZPL objset to its target
/// object id and [`ZplAttrs`], descending the directory tree from the root.
///
/// Each path component is looked up in the current directory's ZAP (the value's
/// low 48 bits are the child object id). Returns `None` if any component is
/// missing. The root path (`/` or empty) resolves to the root directory itself.
#[must_use]
pub fn zpl_lookup(image: &[u8], zpl: &ObjsetPhys, path: &str) -> Option<(u64, ZplAttrs)> {
    let root_id = zpl_master_root(image, zpl)?;
    let (registry, layouts) = zpl_sa_context(image, zpl)?;

    let mut current = root_id;
    for component in path.split('/').filter(|c| !c.is_empty()) {
        let children = zpl_list_dir(image, zpl, current);
        current = children
            .into_iter()
            .find(|(name, _)| name == component)
            .map(|(_, obj)| obj)?;
    }
    let attrs = zpl_attrs(image, zpl, &registry, &layouts, current)?;
    Some((current, attrs))
}

/// Resolve `path` (see [`zpl_lookup`]) and read the target file's content.
///
/// # Errors
///
/// - [`ZfsError::Truncated`] with `structure = "zpl path (not found)"` if the path
///   does not resolve to an object.
/// - Propagates [`zpl_read_file_with`] read errors.
pub fn zpl_read_path(image: &[u8], zpl: &ObjsetPhys, path: &str) -> Result<Vec<u8>, ZfsError> {
    let (object_id, attrs) = zpl_lookup(image, zpl, path).ok_or(ZfsError::Truncated {
        structure: "zpl path (not found)",
        need: 1,
        have: 0,
    })?;
    zpl_read_file_with(image, zpl, object_id, Some(attrs.size))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::{zpl_list_dir, zpl_objset, ZPL_DIRENT_OBJ_MASK};
    use crate::bytes::Endian;
    use crate::objset::ObjsetPhys;

    /// A minimal objset whose meta-dnode's single 512-byte data block (at physical
    /// 0x400000, DVA offset 0) is `block` — an array of up to one 512-byte dnode.
    /// Returns `(image, objset)`.
    fn synthetic_objset(block: &[u8; 512]) -> (Vec<u8>, ObjsetPhys) {
        let mut img = vec![0u8; 0x0040_0000 + 4096];
        img[0x0040_0000..0x0040_0000 + 512].copy_from_slice(block);
        // meta-dnode: nlevels=1, nblkptr=1, datablkszsec=1 (512-byte blocks),
        // blkptr[0] -> DVA offset 0, uncompressed, LE.
        let mut data = [0u8; 1024];
        data[0] = 10; // DMU_OT_DNODE
        data[2] = 1; // nlevels
        data[3] = 1; // nblkptr
        data[8..10].copy_from_slice(&1u16.to_le_bytes()); // datablkszsec = 512
        data[64..72].copy_from_slice(&1u64.to_le_bytes()); // blkptr[0] asize=1
        let prop = (2u64 << 32) | (1u64 << 63); // comp off, LE
        data[64 + 48..64 + 56].copy_from_slice(&prop.to_le_bytes());
        let os = ObjsetPhys::parse(&data, Endian::Little).unwrap();
        (img, os)
    }

    #[test]
    fn dirent_mask_strips_type_bits() {
        // foo.txt = obj 2 with DT_REG (8) in the top nibble.
        assert_eq!(0x8000_0000_0000_0002u64 & ZPL_DIRENT_OBJ_MASK, 2);
        assert_eq!(0x4000_0000_0000_0003u64 & ZPL_DIRENT_OBJ_MASK, 3);
    }

    #[test]
    fn zpl_list_dir_none_when_object_absent() {
        // The object 0 slot is empty (DMU_OT_NONE) -> mos_dnode None -> empty.
        let (img, os) = synthetic_objset(&[0u8; 512]);
        assert!(zpl_list_dir(&img, &os, 0).is_empty());
    }

    #[test]
    fn zpl_list_dir_none_when_zap_object_unreadable() {
        // Object 0 is a directory dnode (dn_type=20) but datablkszsec=0, so
        // read_zap_object errors -> zpl_list_dir returns empty (never panics).
        let mut block = [0u8; 512];
        block[0] = 20; // DMU_OT_DIRECTORY_CONTENTS (non-empty slot)
        block[2] = 1; // nlevels
        block[3] = 1; // nblkptr
                      // datablkszsec left 0 -> data_block_size 0 -> read_zap_object Err.
        let (img, os) = synthetic_objset(&block);
        assert!(zpl_list_dir(&img, &os, 0).is_empty());
    }

    #[test]
    fn zpl_objset_none_when_object_directory_missing() {
        // A MOS whose object-1 slot is empty: no object directory -> None.
        let (img, os) = synthetic_objset(&[0u8; 512]);
        assert!(zpl_objset(&img, &os).is_none());
    }

    /// A MOS with a meta-dnode over a 16 KiB data block (32 dnode slots), letting
    /// several objects coexist. `dnodes[i]` is written at object slot `i`.
    fn synthetic_mos(dnodes: &[(usize, [u8; 512])]) -> (Vec<u8>, ObjsetPhys) {
        let mut img = vec![0u8; 0x0040_0000 + 0x8000];
        let mut block = vec![0u8; 0x4000]; // 16 KiB = 32 dnode slots
        for (idx, dn) in dnodes {
            block[idx * 512..idx * 512 + 512].copy_from_slice(dn);
        }
        img[0x0040_0000..0x0040_0000 + 0x4000].copy_from_slice(&block);
        // meta-dnode: nlevels=1, nblkptr=1, datablkszsec=32 (16 KiB), DVA offset 0.
        let mut data = [0u8; 1024];
        data[0] = 10;
        data[2] = 1;
        data[3] = 1;
        data[8..10].copy_from_slice(&32u16.to_le_bytes());
        data[64..72].copy_from_slice(&32u64.to_le_bytes()); // asize = 32 sectors (16 KiB)
                                                            // LSIZE/PSIZE raw = 31 -> (31+1)<<9 = 16 KiB.
        let prop = 31u64 | (31u64 << 16) | (2u64 << 32) | (1u64 << 63);
        data[64 + 48..64 + 56].copy_from_slice(&prop.to_le_bytes());
        let os = ObjsetPhys::parse(&data, Endian::Little).unwrap();
        (img, os)
    }

    /// Build a directory dnode (object 1, the MOS object directory is a micro-ZAP)
    /// whose single 512-byte data block is a micro-ZAP with the given entries.
    fn microzap_dir_dnode(entries: &[(&str, u64)]) -> [u8; 512] {
        // The object's own dnode: dn_type=1 (object directory), nlevels=1,
        // nblkptr=1, datablkszsec=1, blkptr[0] -> a DVA we point into the image.
        // Simpler: give the dnode an EMBEDDED-free path is hard; instead store the
        // ZAP inline via a second block. But to keep it self-contained we point the
        // dnode's blkptr[0] at a fixed image offset the caller fills. Here we build
        // only the dnode; the ZAP block is placed by the test.
        let mut dn = [0u8; 512];
        dn[0] = 1; // DMU_OT_OBJECT_DIRECTORY
        dn[2] = 1; // nlevels
        dn[3] = 1; // nblkptr
        dn[8..10].copy_from_slice(&1u16.to_le_bytes()); // datablkszsec = 512
                                                        // blkptr[0]: DVA offset (sectors) 0x40 (phys 0x400000 + 0x8000) so it does not
                                                        // collide with the dnode block at offset 0.
        dn[64..72].copy_from_slice(&1u64.to_le_bytes()); // asize=1
        dn[72..80].copy_from_slice(&0x40u64.to_le_bytes()); // offset_sectors=0x40
        let prop = (2u64 << 32) | (1u64 << 63); // off, LE
        dn[64 + 48..64 + 56].copy_from_slice(&prop.to_le_bytes());
        let _ = entries; // entries are written into the ZAP block by the test
        dn
    }

    #[test]
    fn zpl_objset_none_when_dsl_dir_head_is_zero() {
        // object 1 = object directory micro-ZAP with root_dataset -> 5;
        // object 5 = a DSL dir dnode whose bonus head_dataset_obj == 0 -> None.
        let objdir_dn = microzap_dir_dnode(&[]);
        // DSL dir dnode (object 5): dn_type=12, nblkptr=0, bonus with head==0.
        let mut dsl = [0u8; 512];
        dsl[0] = 12; // DMU_OT_DSL_DIR
        dsl[3] = 0; // nblkptr -> bonus at offset 64
        dsl[10..12].copy_from_slice(&256u16.to_le_bytes()); // bonuslen (head field is 0)
        let (mut img, os) = synthetic_mos(&[(1, objdir_dn), (5, dsl)]);
        // Place the object-directory micro-ZAP block at phys 0x400000 + 0x8000
        // (DVA offset_sectors 0x40 -> byte 0x8000 -> phys 0x408000).
        let zap_phys = 0x0040_0000 + 0x8000;
        img.resize(zap_phys + 512, 0);
        let mut zap = vec![0u8; 512];
        zap[0..8].copy_from_slice(&crate::zap::ZBT_MICRO.to_le_bytes());
        // entry root_dataset -> 5
        let name = b"root_dataset";
        zap[64..72].copy_from_slice(&5u64.to_le_bytes());
        zap[64 + 14..64 + 14 + name.len()].copy_from_slice(name);
        img[zap_phys..zap_phys + 512].copy_from_slice(&zap);
        assert!(zpl_objset(&img, &os).is_none());
    }

    /// A plain-file dnode whose single 512-byte data block is at DVA
    /// `offset_sectors` = `off_sec`, uncompressed, LE.
    fn file_dnode(off_sec: u64) -> [u8; 512] {
        let mut dn = [0u8; 512];
        dn[0] = 19; // DMU_OT_PLAIN_FILE_CONTENTS
        dn[2] = 1; // nlevels
        dn[3] = 1; // nblkptr
        dn[8..10].copy_from_slice(&1u16.to_le_bytes()); // datablkszsec = 512
        dn[64..72].copy_from_slice(&1u64.to_le_bytes()); // asize=1
        dn[72..80].copy_from_slice(&off_sec.to_le_bytes()); // offset_sectors
        let prop = (2u64 << 32) | (1u64 << 63); // comp off, LE
        dn[64 + 48..64 + 56].copy_from_slice(&prop.to_le_bytes());
        dn
    }

    #[test]
    fn zpl_attrs_dispatches_legacy_znode_bonus() {
        use super::zpl_attrs;
        use crate::sa::{SaLayouts, SaRegistry};
        // Object 4: a legacy znode object (bonustype 17) with a 264-byte bonus.
        let mut dn = [0u8; 512];
        dn[0] = 19; // plain file
        dn[3] = 0; // nblkptr = 0 -> bonus at offset 64
        dn[4] = super::DMU_OT_ZNODE; // bonustype = 17
        dn[10..12].copy_from_slice(&264u16.to_le_bytes());
        // Cannot fit 264 bonus in a single 512 slot after core? 64+264=328 <= 512 ok.
        dn[64 + 72..64 + 80].copy_from_slice(&0o100_600u64.to_le_bytes()); // mode @72
        dn[64 + 80..64 + 88].copy_from_slice(&99u64.to_le_bytes()); // size @80
        let (img, os) = synthetic_mos(&[(4, dn)]);
        let attrs = zpl_attrs(&img, &os, &SaRegistry::default(), &SaLayouts::default(), 4).unwrap();
        assert_eq!(attrs.mode, 0o100_600);
        assert_eq!(attrs.size, 99);
    }

    #[test]
    fn zpl_attrs_none_for_non_sa_non_znode_bonus() {
        use super::zpl_attrs;
        use crate::sa::{SaLayouts, SaRegistry};
        // Object 4: bonustype 0 (neither SA nor znode) -> None.
        let mut dn = [0u8; 512];
        dn[0] = 19;
        dn[3] = 0;
        dn[4] = 0; // bonustype none
        let (img, os) = synthetic_mos(&[(4, dn)]);
        assert!(zpl_attrs(&img, &os, &SaRegistry::default(), &SaLayouts::default(), 4).is_none());
    }

    #[test]
    fn zpl_read_file_with_truncates_to_size_and_reads_content() {
        use super::zpl_read_file_with;
        // Object 4: a plain file whose 512-byte data block holds a marker payload.
        // Point its data block at DVA offset_sectors 0x40 (phys 0x408000) so it does
        // not collide with the meta-dnode block at phys 0x400000.
        let dn = file_dnode(0x40);
        let (mut img, os) = synthetic_mos(&[(4, dn)]);
        let data_phys = 0x0040_0000 + 0x8000;
        img.resize(data_phys + 512, 0);
        let mut payload = vec![0u8; 512];
        payload[..5].copy_from_slice(b"hello");
        img[data_phys..data_phys + 512].copy_from_slice(&payload);
        // Truncate to logical size 5 -> "hello".
        let out = zpl_read_file_with(&img, &os, 4, Some(5)).unwrap();
        assert_eq!(out, b"hello");
        // No size -> the whole 512-byte block.
        let full = zpl_read_file_with(&img, &os, 4, None).unwrap();
        assert_eq!(full.len(), 512);
    }

    #[test]
    fn zpl_read_file_with_errors_on_absent_and_zero_block_object() {
        use super::zpl_read_file_with;
        // Absent object slot -> Truncated error.
        let (img, os) = synthetic_mos(&[]);
        assert!(zpl_read_file_with(&img, &os, 4, None).is_err());
        // Object 4: a non-empty dnode with datablkszsec == 0 -> zero block size error.
        let mut dn = [0u8; 512];
        dn[0] = 19; // non-empty
        dn[2] = 1;
        dn[3] = 1;
        // datablkszsec left 0.
        let (img, os) = synthetic_mos(&[(4, dn)]);
        assert!(zpl_read_file_with(&img, &os, 4, None).is_err());
    }
}
