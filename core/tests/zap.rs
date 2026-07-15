//! P2 ZAP + DSL → ZPL root-directory integration tests.
//!
//! Oracle: `zdb` on the self-minted `tpool` (Tier-2 REAL-self; `zdb` is an
//! independent implementation). Every offset/value asserted here was verified
//! byte-exact against `zdb -dddddd` on the minted pool. Ground truth in
//! `tests/data/README.md`.
//!
//! Committed always-on fixtures (no env gate) — all extracted + decompressed
//! from the minted pool with `zdb -R`:
//! - `zfs_zap_fat_objdir.bin` — the MOS **object directory** (object 1), a
//!   **fat-ZAP**: block 0 (`zap_phys_t` header + embedded pointer table) ++
//!   block 1 (`zap_leaf_phys_t`), each 16 KiB, concatenated to 32 KiB (the object's
//!   logical data). `zdb` reports 15 entries incl. `root_dataset = 32`.
//! - `zfs_zap_micro_master.bin` — the ZPL **master node** (object 1) 512-byte
//!   **micro-ZAP** block. `zdb`: `ROOT = 34`, `VERSION = 5`, `SA_ATTRS = 32`.
//! - `zfs_zap_micro_root.bin` — the ZPL **root directory** (object 34) 512-byte
//!   micro-ZAP (decompressed from its embedded blkptr). `zdb`: `foo.txt = 2`
//!   (regular file), `sub = 3` (directory).
//!
//! The env-gated `ZFS_ORACLE_IMG` tests read the full 512 MiB image and do the
//! real MOS → DSL → ZPL walk end-to-end.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zfs_core::{
    dsl_dataset_bp, dsl_dir_head_dataset, mos_dnode, read_block, zap_list, zap_lookup,
    zpl_list_dir, zpl_master_root, zpl_objset, zpl_root_dir, Dnode, Endian, ObjsetPhys, VdevLabel,
};

const FAT_OBJDIR: &[u8] = include_bytes!("../../tests/data/zfs_zap_fat_objdir.bin");
const MICRO_MASTER: &[u8] = include_bytes!("../../tests/data/zfs_zap_micro_master.bin");
const MICRO_ROOT: &[u8] = include_bytes!("../../tests/data/zfs_zap_micro_root.bin");

// --------------------------------------------------------------------------
// 1. micro-ZAP — the ZPL master node (VERSION / ROOT / SA_ATTRS / DELETE_QUEUE).
// --------------------------------------------------------------------------

#[test]
fn micro_zap_list_master_node_matches_zdb() {
    let entries = zap_list(MICRO_MASTER);
    // zdb: 7 entries. The three normalization props are 0; the four real ones:
    let map: std::collections::BTreeMap<_, _> = entries.iter().cloned().collect();
    assert_eq!(map.get("VERSION").copied(), Some(5));
    assert_eq!(map.get("ROOT").copied(), Some(34));
    assert_eq!(map.get("SA_ATTRS").copied(), Some(32));
    assert_eq!(map.get("DELETE_QUEUE").copied(), Some(33));
    assert_eq!(map.get("normalization").copied(), Some(0));
    assert_eq!(map.get("utf8only").copied(), Some(0));
    assert_eq!(map.get("casesensitivity").copied(), Some(0));
    assert_eq!(entries.len(), 7);
}

#[test]
fn micro_zap_lookup_finds_and_misses() {
    assert_eq!(zap_lookup(MICRO_MASTER, "ROOT"), Some(34));
    assert_eq!(zap_lookup(MICRO_MASTER, "VERSION"), Some(5));
    assert_eq!(zap_lookup(MICRO_MASTER, "NOPE"), None);
}

// --------------------------------------------------------------------------
// 2. fat-ZAP — the MOS object directory (root_dataset et al.).
// --------------------------------------------------------------------------

#[test]
fn fat_zap_list_object_directory_matches_zdb() {
    let entries = zap_list(FAT_OBJDIR);
    let map: std::collections::BTreeMap<_, _> = entries.iter().cloned().collect();
    // zdb "ZAP entries: 15", incl. these exact name→value pairs.
    assert_eq!(map.get("root_dataset").copied(), Some(32));
    assert_eq!(map.get("free_bpobj").copied(), Some(41));
    assert_eq!(map.get("features_for_read").copied(), Some(51));
    assert_eq!(map.get("features_for_write").copied(), Some(52));
    assert_eq!(map.get("feature_descriptions").copied(), Some(53));
    assert_eq!(map.get("history").copied(), Some(60));
    assert_eq!(map.get("config").copied(), Some(61));
    assert_eq!(map.get("creation_version").copied(), Some(5000));
    assert_eq!(map.get("deflate").copied(), Some(1));
    assert_eq!(map.get("com.delphix:vdev_zap_map").copied(), Some(128));
    // 15 entries total (one has an int_size=1 32-byte value: checksum_salt).
    assert_eq!(entries.len(), 15);
}

#[test]
fn fat_zap_lookup_root_dataset() {
    assert_eq!(zap_lookup(FAT_OBJDIR, "root_dataset"), Some(32));
    assert_eq!(zap_lookup(FAT_OBJDIR, "config"), Some(61));
    assert_eq!(zap_lookup(FAT_OBJDIR, "not_present"), None);
}

// --------------------------------------------------------------------------
// 3. micro-ZAP — the ZPL root directory (name → object id + dirent type bits).
// --------------------------------------------------------------------------

#[test]
fn micro_zap_root_directory_lists_minted_files() {
    let entries = zap_list(MICRO_ROOT);
    let map: std::collections::BTreeMap<_, _> = entries.iter().cloned().collect();
    // The raw ZAP value carries ZFS_DIRENT_TYPE in the top 4 bits; the object id
    // is the low bits. zap_list returns the RAW value (callers mask).
    // foo.txt = obj 2, type 8 (DT_REG) -> 0x8000000000000002
    // sub     = obj 3, type 4 (DT_DIR) -> 0x4000000000000003
    assert_eq!(map.get("foo.txt").copied(), Some(0x8000_0000_0000_0002));
    assert_eq!(map.get("sub").copied(), Some(0x4000_0000_0000_0003));
    assert_eq!(entries.len(), 2);
    // Masked object ids:
    assert_eq!(
        zap_lookup(MICRO_ROOT, "foo.txt").unwrap() & 0x0000_ffff_ffff_ffff,
        2
    );
    assert_eq!(
        zap_lookup(MICRO_ROOT, "sub").unwrap() & 0x0000_ffff_ffff_ffff,
        3
    );
}

// --------------------------------------------------------------------------
// 4. Panic-free: lying ZAP chunk count / name length / block type never OOM.
// --------------------------------------------------------------------------

#[test]
fn zap_list_on_garbage_never_panics() {
    let _ = zap_list(&[]);
    let _ = zap_list(&[0xffu8; 3]);
    let _ = zap_list(&[0xffu8; 4096]);
    // A block claiming ZBT_MICRO but truncated: no entries, no panic.
    let mut micro = vec![0u8; 128];
    micro[7] = 0x80; // mz_block_type high byte -> ZBT_MICRO-ish
    micro[0] = 3;
    let _ = zap_list(&micro);
    let _ = zap_lookup(&micro, "anything");
}

#[test]
fn fat_zap_lying_chunk_and_name_lengths_never_over_read() {
    // Take the real fat-ZAP but corrupt the leaf's chunk fields with absurd
    // values: name_numints huge, name_chunk out of range, value_chunk out of
    // range. zap_list must terminate and not panic/over-read.
    let mut bad = FAT_OBJDIR.to_vec();
    // The leaf block starts at 16384; smash a stretch of it with 0xff.
    for b in bad.iter_mut().skip(16384 + 1072).take(2048) {
        *b = 0xff;
    }
    let _ = zap_list(&bad);
    let _ = zap_lookup(&bad, "root_dataset");
}

// --------------------------------------------------------------------------
// 5. End-to-end MOS → DSL → ZPL → root directory (env-gated full image).
// --------------------------------------------------------------------------

fn load_mos(img: &[u8]) -> ObjsetPhys {
    let label = VdevLabel::parse(&img[..zfs_core::LABEL_SIZE]).unwrap();
    let bp = label.active_uberblock.rootbp_full();
    let block = read_block(img, &bp).unwrap();
    ObjsetPhys::parse(&block.data, Endian::Little).unwrap()
}

#[test]
fn mos_object_directory_lookup_root_dataset_end_to_end() {
    let Ok(path) = std::env::var("ZFS_ORACLE_IMG") else {
        eprintln!("skipping: set ZFS_ORACLE_IMG to the minted zfs.img to run");
        return;
    };
    let img = std::fs::read(&path).expect("read ZFS_ORACLE_IMG");
    let mos = load_mos(&img);

    // Object 1 = the MOS object directory (a fat-ZAP). Read its object data and
    // look up root_dataset — must equal zdb's 32.
    let objdir = mos_dnode(&img, &mos, 1).expect("object directory dnode");
    let data = zfs_core::read_zap_object(&img, &objdir).expect("read object dir data");
    assert_eq!(zap_lookup(&data, "root_dataset"), Some(32));
}

#[test]
fn dsl_walk_reaches_zpl_objset_end_to_end() {
    let Ok(path) = std::env::var("ZFS_ORACLE_IMG") else {
        eprintln!("skipping: set ZFS_ORACLE_IMG to the minted zfs.img to run");
        return;
    };
    let img = std::fs::read(&path).expect("read ZFS_ORACLE_IMG");
    let mos = load_mos(&img);

    // root_dataset (32) is a DSL dir; its head_dataset_obj (54) is the DSL
    // dataset; its ds_bp points at the ZPL objset.
    let dsl_dir = mos_dnode(&img, &mos, 32).expect("DSL dir dnode");
    assert_eq!(dsl_dir_head_dataset(&dsl_dir), 54);
    let dataset = mos_dnode(&img, &mos, 54).expect("DSL dataset dnode");
    let ds_bp = dsl_dataset_bp(&dataset);
    // ds_bp DVA[0] = 0:f000 (verified against zdb).
    assert_eq!(ds_bp.dvas[0].offset_sectors, 0xf000 / 512);
    let zpl_block = read_block(&img, &ds_bp).expect("read ds_bp");
    let zpl = ObjsetPhys::parse(&zpl_block.data, Endian::Little).unwrap();
    assert_eq!(zpl.os_type, zfs_core::DMU_OST_ZFS);
}

#[test]
fn zpl_objset_convenience_and_master_node_root_end_to_end() {
    let Ok(path) = std::env::var("ZFS_ORACLE_IMG") else {
        eprintln!("skipping: set ZFS_ORACLE_IMG to the minted zfs.img to run");
        return;
    };
    let img = std::fs::read(&path).expect("read ZFS_ORACLE_IMG");
    let mos = load_mos(&img);

    // The convenience walk MOS -> DSL -> ZPL objset in one call.
    let zpl = zpl_objset(&img, &mos).expect("zpl_objset");
    assert_eq!(zpl.os_type, zfs_core::DMU_OST_ZFS);

    // Master node (object 1) -> ROOT = 34.
    let root_id = zpl_master_root(&img, &zpl).expect("master root");
    assert_eq!(root_id, 34);
}

#[test]
fn zpl_root_dir_lists_minted_files_end_to_end() {
    let Ok(path) = std::env::var("ZFS_ORACLE_IMG") else {
        eprintln!("skipping: set ZFS_ORACLE_IMG to the minted zfs.img to run");
        return;
    };
    let img = std::fs::read(&path).expect("read ZFS_ORACLE_IMG");
    let mos = load_mos(&img);
    let zpl = zpl_objset(&img, &mos).expect("zpl_objset");

    // The root directory dnode (object 34, an embedded-blkptr micro-ZAP).
    let root: Dnode = zpl_root_dir(&img, &zpl).expect("root dir dnode");
    assert_eq!(root.dn_type, zfs_core::DmuType::DirectoryContents.raw());

    // List it: name -> object id (top 4 bits = dirent type, masked off here).
    let root_id = zpl_master_root(&img, &zpl).unwrap();
    let listing = zpl_list_dir(&img, &zpl, root_id);
    let map: std::collections::BTreeMap<_, _> = listing.into_iter().collect();
    // Minted files: foo.txt (obj 2), sub (obj 3).
    assert_eq!(map.get("foo.txt").copied(), Some(2));
    assert_eq!(map.get("sub").copied(), Some(3));
    assert_eq!(map.len(), 2);
}
