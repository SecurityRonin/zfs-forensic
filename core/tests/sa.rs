//! P3 — SA / znode metadata, file content, and path resolution integration tests.
//!
//! Oracle: `zdb` on the self-minted `tpool` (Tier-2 REAL-self; `zdb` is an
//! independent implementation). Every value asserted here was verified byte-exact
//! against `zdb -dddddd` on the minted pool. Ground truth in `tests/data/README.md`.
//!
//! Committed always-on fixtures (no env gate), all extracted + decompressed from
//! the minted pool with `zdb -R`:
//! - `zfs_sa_file_dnode.bin` — object 2 (`/foo.txt`): a 512-byte `dnode_phys_t`
//!   with `dn_bonustype = DMU_OT_SA` (44) and a 176-byte SA bonus. `zdb`:
//!   mode 100644, size 20, gen 11, links 1, uid/gid 0, parent 34.
//! - `zfs_sa_dir_dnode.bin` — object 3 (`/sub`): a directory dnode, SA bonus.
//!   `zdb`: mode 40755, size 3, links 2, gen 11.
//! - `zfs_sa_registry.bin` — the SA attribute registration (object 35), a
//!   micro-ZAP of 22 entries; each value packs `[length:bswap:id]`
//!   (`ATTR_LENGTH/ATTR_BSWAP/ATTR_NUM`). `zdb`: `ZPL_MODE = id 5, len 8`, …
//! - `zfs_sa_layouts.bin` — the SA attribute layouts (object 36), a fat-ZAP
//!   (header ++ leaf, 32 KiB) whose values are u16 **big-endian** attr-id arrays.
//!   `zdb`: layout `3 = [5 6 4 12 13 7 11 0 1 2 3 8 21 16 19]`.
//!
//! The env-gated `ZFS_ORACLE_IMG` tests read the full 512 MiB image and do the
//! real SA-registry → `ZplAttrs`, file-content, and path-resolution walk end-to-end.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zfs_core::{
    decode_sa_bonus, decode_znode_phys, parse_sa_layouts, parse_sa_registry, zpl_attrs, zpl_lookup,
    zpl_objset, zpl_read_file, zpl_read_path, zpl_sa_context, Dnode, Endian, ObjsetPhys, SaLayouts,
    SaRegistry, VdevLabel, ZplAttrs,
};

const FILE_DNODE: &[u8] = include_bytes!("../../tests/data/zfs_sa_file_dnode.bin");
const DIR_DNODE: &[u8] = include_bytes!("../../tests/data/zfs_sa_dir_dnode.bin");
const SA_REGISTRY: &[u8] = include_bytes!("../../tests/data/zfs_sa_registry.bin");
const SA_LAYOUTS: &[u8] = include_bytes!("../../tests/data/zfs_sa_layouts.bin");

// foo.txt (object 2) content ground truth (README §content).
const FOO_SHA256: &str = "e597509763371d8a0bad983118b63911217040632e9c9d4d9cbcf6b7da3fb00d";
const FOO_CONTENT: &[u8] = b"hello zfs forensics\n";
// sub/bar.txt (object 128) content ground truth.
const BAR_SHA256: &str = "e68db4521d8c341f11de6231fabd41ac8e35655934b7dced82db76465047c04b";

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(data);
    digest.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

// ---- SA registry ----------------------------------------------------------

#[test]
fn sa_registry_parses_attr_name_to_id_and_size() {
    let reg: SaRegistry = parse_sa_registry(SA_REGISTRY);
    // zdb: ZPL_MODE = [8:0:5], ZPL_SIZE = [8:0:6], ZPL_ATIME = [16:0:0], …
    let mode = reg.by_name("ZPL_MODE").expect("ZPL_MODE registered");
    assert_eq!(mode.id, 5);
    assert_eq!(mode.size, 8);
    let atime = reg.by_name("ZPL_ATIME").expect("ZPL_ATIME registered");
    assert_eq!(atime.id, 0);
    assert_eq!(atime.size, 16);
    assert_eq!(reg.by_name("ZPL_SIZE").unwrap().id, 6);
    assert_eq!(reg.by_name("ZPL_GEN").unwrap().id, 4);
    assert_eq!(reg.by_name("ZPL_LINKS").unwrap().id, 8);
    assert_eq!(reg.by_name("ZPL_UID").unwrap().id, 12);
    assert_eq!(reg.by_name("ZPL_GID").unwrap().id, 13);
    // 22 registered attributes in this pool.
    assert_eq!(reg.len(), 22);
    // A name that is not registered resolves to None (surfaced, not fatal).
    assert!(reg.by_name("ZPL_NOT_A_REAL_ATTR").is_none());
}

#[test]
fn sa_layouts_parses_ordered_attr_id_arrays() {
    let layouts: SaLayouts = parse_sa_layouts(SA_LAYOUTS);
    // zdb: layout 3 = [5 6 4 12 13 7 11 0 1 2 3 8 21 16 19].
    assert_eq!(
        layouts.attr_ids(3),
        Some(&[5u16, 6, 4, 12, 13, 7, 11, 0, 1, 2, 3, 8, 21, 16, 19][..])
    );
    // layout 2 = [5 6 4 12 13 7 11 0 1 2 3 8 16 19].
    assert_eq!(
        layouts.attr_ids(2),
        Some(&[5u16, 6, 4, 12, 13, 7, 11, 0, 1, 2, 3, 8, 16, 19][..])
    );
    // An unknown layout number resolves to None.
    assert!(layouts.attr_ids(999).is_none());
}

// ---- SA bonus decode ------------------------------------------------------

#[test]
fn sa_bonus_decodes_file_attrs_matching_zdb() {
    let reg = parse_sa_registry(SA_REGISTRY);
    let layouts = parse_sa_layouts(SA_LAYOUTS);
    let dnode = Dnode::parse(FILE_DNODE, Endian::Little).unwrap();
    // dn_bonustype == DMU_OT_SA (44).
    assert_eq!(dnode.dn_bonustype, 44);
    let attrs: ZplAttrs =
        decode_sa_bonus(&dnode.bonus, &reg, &layouts, Endian::Little).expect("decode SA bonus");

    // Ground truth from `zdb -dddddd tpool/ 2`.
    assert_eq!(attrs.mode, 0o100_644, "mode");
    assert_eq!(attrs.size, 20, "size");
    assert_eq!(attrs.gen, 11, "gen");
    assert_eq!(attrs.links, 1, "links");
    assert_eq!(attrs.uid, 0, "uid");
    assert_eq!(attrs.gid, 0, "gid");
    // timestamps: atime/crtime nsec 403052711, mtime/ctime nsec 405052711;
    // all sec = 1783939238 (Mon Jul 13 18:40:38 2026).
    assert_eq!(attrs.mtime, (1_783_939_238, 405_052_711));
    assert_eq!(attrs.atime, (1_783_939_238, 403_052_711));
    assert_eq!(attrs.ctime, (1_783_939_238, 405_052_711));
    assert_eq!(attrs.crtime, (1_783_939_238, 403_052_711));
    // No unknown attribute ids in a fully-registered layout.
    assert!(attrs.unknown_attr_ids.is_empty());
}

#[test]
fn sa_bonus_decodes_directory_attrs_matching_zdb() {
    let reg = parse_sa_registry(SA_REGISTRY);
    let layouts = parse_sa_layouts(SA_LAYOUTS);
    let dnode = Dnode::parse(DIR_DNODE, Endian::Little).unwrap();
    let attrs = decode_sa_bonus(&dnode.bonus, &reg, &layouts, Endian::Little).expect("decode dir");
    // `zdb -dddddd tpool/ 3`: mode 40755, size 3, links 2, gen 11.
    assert_eq!(attrs.mode, 0o40_755);
    assert_eq!(attrs.size, 3);
    assert_eq!(attrs.links, 2);
    assert_eq!(attrs.gen, 11);
}

#[test]
fn sa_bonus_with_missing_layout_returns_none_never_panics() {
    // A valid SA header magic but a layout number the layouts object does not
    // define: decode cannot proceed, returns None (never a panic).
    let reg = parse_sa_registry(SA_REGISTRY);
    let layouts = parse_sa_layouts(SA_LAYOUTS);
    let mut bonus = vec![0u8; 176];
    bonus[0..4].copy_from_slice(&0x2F_505Au32.to_le_bytes()); // SA_MAGIC
                                                              // layout number 1000 (not defined), hdrsz 1*8.
    let info: u16 = (1u16 << 10) | 0x03e8; // layout number 1000
    bonus[4..6].copy_from_slice(&info.to_le_bytes());
    assert!(decode_sa_bonus(&bonus, &reg, &layouts, Endian::Little).is_none());
}

#[test]
fn sa_bonus_wrong_magic_returns_none() {
    let reg = parse_sa_registry(SA_REGISTRY);
    let layouts = parse_sa_layouts(SA_LAYOUTS);
    let bonus = vec![0u8; 176]; // magic 0
    assert!(decode_sa_bonus(&bonus, &reg, &layouts, Endian::Little).is_none());
}

#[test]
fn sa_bonus_lying_layout_never_over_reads() {
    // A layout that claims more attributes than the bonus can hold: the decode
    // stops at the buffer end, never panics or over-reads, and surfaces nothing
    // beyond what fits.
    let reg = parse_sa_registry(SA_REGISTRY);
    let layouts = parse_sa_layouts(SA_LAYOUTS);
    let dnode = Dnode::parse(FILE_DNODE, Endian::Little).unwrap();
    // Truncate the bonus to 24 bytes: header (8) + mode (8) + size (8) only.
    let short = &dnode.bonus[..24];
    let attrs = decode_sa_bonus(short, &reg, &layouts, Endian::Little);
    // Either None or a partial decode — but never a panic.
    if let Some(a) = attrs {
        assert_eq!(a.mode, 0o100_644);
    }
}

// ---- legacy znode_phys_t --------------------------------------------------

#[test]
fn znode_phys_decodes_crafted_legacy_bonus() {
    // The minted pool is modern (SA), so craft a 264-byte znode_phys_t to prove
    // the legacy path. Layout (verified vs zfs_znode.h):
    //   atime  @0   [sec,nsec]
    //   mtime  @16
    //   ctime  @32
    //   crtime @48
    //   gen    @64  u64
    //   mode   @72  u64
    //   size   @80  u64
    //   parent @88  u64
    //   links  @96  u64
    let mut bonus = vec![0u8; 264];
    let put = |b: &mut [u8], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    put(&mut bonus, 0, 111); // atime sec
    put(&mut bonus, 8, 222); // atime nsec
    put(&mut bonus, 16, 333); // mtime sec
    put(&mut bonus, 24, 444); // mtime nsec
    put(&mut bonus, 32, 555); // ctime sec
    put(&mut bonus, 48, 777); // crtime sec
    put(&mut bonus, 64, 7); // gen
    put(&mut bonus, 72, 0o100_600); // mode
    put(&mut bonus, 80, 4096); // size
    put(&mut bonus, 88, 34); // parent
    put(&mut bonus, 96, 1); // links
    let attrs = decode_znode_phys(&bonus, Endian::Little).expect("decode znode");
    assert_eq!(attrs.mode, 0o100_600);
    assert_eq!(attrs.size, 4096);
    assert_eq!(attrs.gen, 7);
    assert_eq!(attrs.links, 1);
    assert_eq!(attrs.atime, (111, 222));
    assert_eq!(attrs.mtime, (333, 444));
    assert_eq!(attrs.ctime, (555, 0));
    assert_eq!(attrs.crtime, (777, 0));
}

#[test]
fn znode_phys_too_short_returns_none() {
    assert!(decode_znode_phys(&[0u8; 100], Endian::Little).is_none());
}

// ---- full-image: SA context, attrs, content, path -------------------------

fn load_zpl(img: &[u8]) -> ObjsetPhys {
    let label = VdevLabel::parse(&img[..zfs_core::LABEL_SIZE]).unwrap();
    let bp = label.active_uberblock.rootbp_full();
    let block = zfs_core::read_block(img, &bp).unwrap();
    let mos = ObjsetPhys::parse(&block.data, Endian::Little).unwrap();
    zpl_objset(img, &mos).expect("zpl_objset")
}

#[test]
fn zpl_sa_context_builds_registry_and_layouts_end_to_end() {
    let Ok(path) = std::env::var("ZFS_ORACLE_IMG") else {
        eprintln!("skipping: set ZFS_ORACLE_IMG to the minted zfs.img to run");
        return;
    };
    let img = std::fs::read(&path).expect("read ZFS_ORACLE_IMG");
    let zpl = load_zpl(&img);
    let (reg, layouts) = zpl_sa_context(&img, &zpl).expect("SA context");
    assert_eq!(reg.by_name("ZPL_MODE").unwrap().id, 5);
    assert_eq!(reg.len(), 22);
    assert_eq!(
        layouts.attr_ids(3),
        Some(&[5u16, 6, 4, 12, 13, 7, 11, 0, 1, 2, 3, 8, 21, 16, 19][..])
    );
}

#[test]
fn zpl_attrs_of_foo_txt_matches_zdb_end_to_end() {
    let Ok(path) = std::env::var("ZFS_ORACLE_IMG") else {
        eprintln!("skipping: set ZFS_ORACLE_IMG to the minted zfs.img to run");
        return;
    };
    let img = std::fs::read(&path).expect("read ZFS_ORACLE_IMG");
    let zpl = load_zpl(&img);
    let (reg, layouts) = zpl_sa_context(&img, &zpl).unwrap();
    // Object 2 = /foo.txt.
    let attrs = zpl_attrs(&img, &zpl, &reg, &layouts, 2).expect("attrs of obj 2");
    assert_eq!(attrs.mode, 0o100_644);
    assert_eq!(attrs.size, 20);
    assert_eq!(attrs.gen, 11);
    assert_eq!(attrs.links, 1);
    assert_eq!(attrs.mtime.0, 1_783_939_238);
}

#[test]
fn zpl_read_file_foo_txt_content_sha256_matches_end_to_end() {
    let Ok(path) = std::env::var("ZFS_ORACLE_IMG") else {
        eprintln!("skipping: set ZFS_ORACLE_IMG to the minted zfs.img to run");
        return;
    };
    let img = std::fs::read(&path).expect("read ZFS_ORACLE_IMG");
    let zpl = load_zpl(&img);
    // Object 2 = /foo.txt: read its content, truncated to the SA logical size (20).
    let content = zpl_read_file(&img, &zpl, 2).expect("read foo.txt");
    assert_eq!(content, FOO_CONTENT);
    assert_eq!(sha256_hex(&content), FOO_SHA256);
}

#[test]
fn zpl_lookup_and_read_path_resolve_nested_file_end_to_end() {
    let Ok(path) = std::env::var("ZFS_ORACLE_IMG") else {
        eprintln!("skipping: set ZFS_ORACLE_IMG to the minted zfs.img to run");
        return;
    };
    let img = std::fs::read(&path).expect("read ZFS_ORACLE_IMG");
    let zpl = load_zpl(&img);

    // /foo.txt -> object 2, attrs match zdb.
    let (obj, attrs) = zpl_lookup(&img, &zpl, "/foo.txt").expect("lookup /foo.txt");
    assert_eq!(obj, 2);
    assert_eq!(attrs.size, 20);

    // /sub -> object 3 (directory), mode 40755.
    let (sub_obj, sub_attrs) = zpl_lookup(&img, &zpl, "/sub").expect("lookup /sub");
    assert_eq!(sub_obj, 3);
    assert_eq!(sub_attrs.mode, 0o40_755);

    // /sub/bar.txt -> object 128, content sha256 matches ground truth.
    let (bar_obj, bar_attrs) = zpl_lookup(&img, &zpl, "/sub/bar.txt").expect("lookup nested");
    assert_eq!(bar_obj, 128);
    assert_eq!(bar_attrs.size, 20);
    let content = zpl_read_path(&img, &zpl, "/sub/bar.txt").expect("read nested");
    assert_eq!(sha256_hex(&content), BAR_SHA256);

    // A missing path resolves to None.
    assert!(zpl_lookup(&img, &zpl, "/does/not/exist").is_none());
}
