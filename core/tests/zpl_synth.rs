//! P3 ZPL end-to-end walk over a **fully synthetic, self-consistent mini-image**.
//!
//! The env-gated `ZFS_ORACLE_IMG` tests (in `sa.rs` / `zap.rs`) do the real MOS →
//! DSL → ZPL → SA walk against the 512 MiB minted pool; those lines are therefore
//! uncovered on CI, which does not carry the oracle image. This test drives the
//! *same* higher-level `zpl_*` walk functions over a small crafted vdev image so
//! the coverage path is always on (no env gate), exactly like the committed block
//! fixtures.
//!
//! ## Construction (Tier-3 crafted fixture — SYNTHETIC)
//!
//! The image is assembled byte-by-byte from the ZFS on-disk structures the reader
//! parses (dnode / objset / blkptr / DVA / micro-ZAP / `dsl_dir_phys_t` /
//! `dsl_dataset_phys_t` / `znode_phys_t`), so the reader walks it end to end:
//!
//!   real `zfs_label0.bin`  → active uberblock `rootbp` (DVA[0])
//!     └─ MOS objset block (crafted, placed at the rootbp DVA offset)
//!          meta-dnode → MOS dnode array (objects 1..=N, one 512-byte dnode each)
//!            obj 1  object directory  (micro-ZAP: `root_dataset` = 2)
//!            obj 2  DSL directory     (bonus `dd_head_dataset_obj` = 3)
//!            obj 3  DSL dataset       (bonus `ds_bp` → the ZPL objset block)
//!     └─ ZPL objset block (crafted)
//!          meta-dnode → ZPL dnode array (objects 1..=N)
//!            obj 1  ZPL master node   (micro-ZAP: `ROOT` = 2, `VERSION` = 5)
//!            obj 2  root directory    (micro-ZAP: `hello.txt` = 3, dirent-typed)
//!            obj 3  hello.txt         (legacy `znode_phys_t` bonus, 12-byte file)
//!
//! Every DVA offset is chosen by this builder (the label's real rootbp DVA is read
//! back from the parsed uberblock, never hard-coded), so the image is coherent and
//! the reader resolves each hop. Checksums are verified non-fatally, so the crafted
//! blocks need no valid fletcher4 — a mismatch does not stop the read.
//!
//! Ground truth here is the *construction*: what the builder writes is what the
//! walk must return. The independent correctness oracle stays the env-gated real
//! pool; this is the CI coverage path (see `tests/data/README.md`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zfs_core::{
    read_dnode_data, zpl_attrs, zpl_list_dir, zpl_lookup, zpl_master_root, zpl_objset,
    zpl_read_file, zpl_read_file_with, zpl_read_path, zpl_root_dir, zpl_sa_context, Dnode, Endian,
    ObjsetPhys, VdevLabel, BLKPTR_SIZE, DNODE_SIZE,
};

/// The real L0 vdev label: a valid XDR nvlist config + a real uberblock ring whose
/// active uberblock carries a `rootbp`. We reuse it only to anchor the walk at a
/// genuine rootbp; everything the rootbp points at is crafted below.
const LABEL0: &[u8] = include_bytes!("../../tests/data/zfs_label0.bin");

// ZPL dirent type bits live in the top 4 bits of a directory-entry value.
const DT_REG: u64 = 8 << 60;
const DT_DIR: u64 = 4 << 60;

// ZPL legacy znode bonus type, and the System Attributes bonus type.
const DMU_OT_ZNODE: u8 = 17;
const DMU_OT_SA: u8 = 44;
// DSL directory / dataset bonus types (any non-SA/non-znode type works; the DSL
// helpers read the bonus by fixed offset regardless of dn_bonustype).
const DMU_OT_DSL_DIR: u8 = 12;
const DMU_OT_DSL_DATASET: u8 = 16;

const BLOCK: usize = 4096;
// `znode_phys_t` on-disk size (matches `zfs_core`'s exported `ZNODE_PHYS_SIZE`).
const ZNODE_PHYS_SIZE: usize = 264;

/// A 512-byte micro-ZAP block: header `ZBT_MICRO` then 64-byte entries
/// (value @0 little-endian, NUL-terminated name @14).
fn micro_zap(entries: &[(&str, u64)]) -> Vec<u8> {
    const ZBT_MICRO: u64 = (1 << 63) | 3;
    let mut b = vec![0u8; 512];
    b[0..8].copy_from_slice(&ZBT_MICRO.to_le_bytes());
    for (i, (name, val)) in entries.iter().enumerate() {
        let off = 64 + i * 64;
        b[off..off + 8].copy_from_slice(&val.to_le_bytes());
        let nb = name.as_bytes();
        b[off + 14..off + 14 + nb.len()].copy_from_slice(nb);
    }
    b
}

/// Write a little-endian `blkptr_t` into `buf` at `off` that points a single L0
/// data block (level 0, `dn_nlevels == 1`) at vdev-relative byte `phys`, of
/// logical/physical size `size` bytes, uncompressed (comp == off == 2).
fn write_blkptr(buf: &mut [u8], off: usize, phys: u64, size: usize) {
    // A `phys` of 0 means "no data block" (the object's payload lives in its
    // bonus, e.g. a DSL dir/dataset): leave an all-zero (hole) blkptr.
    if phys == 0 {
        return;
    }
    // DVA[0]: word0 = asize(bits0-23) + vdev(bits32-55); word1 = offset_sectors.
    let boot_skew: u64 = 0x0040_0000;
    let offset_sectors = (phys - boot_skew) >> 9;
    let asize_sectors = (size as u64).div_ceil(512);
    let w0 = asize_sectors & 0x00ff_ffff; // vdev 0
    let w1 = offset_sectors & 0x7fff_ffff_ffff_ffff;
    buf[off..off + 8].copy_from_slice(&w0.to_le_bytes());
    buf[off + 8..off + 16].copy_from_slice(&w1.to_le_bytes());
    // blk_prop @48: LSIZE(0-15) + PSIZE(16-31) + comp(32-38) + cksum(40-47)
    // + type(48-55) + level(56-60) + byteorder(63). Sizes stored as sectors-1.
    let sectors = (size as u64).div_ceil(512);
    let lsize_raw = sectors - 1;
    let comp: u64 = 2; // ZIO_COMPRESS_OFF
    let byteorder: u64 = 1; // little-endian
    let prop =
        (lsize_raw & 0xffff) | ((lsize_raw & 0xffff) << 16) | (comp << 32) | (byteorder << 63);
    buf[off + 48..off + 56].copy_from_slice(&prop.to_le_bytes());
}

/// A 512-byte `dnode_phys_t` for an object whose single L0 data block is `phys`
/// (a `BLOCK`-byte block); `bonustype`/`bonus` populate the bonus buffer.
fn dnode(phys: u64, bonustype: u8, bonus: &[u8]) -> [u8; DNODE_SIZE] {
    let mut d = [0u8; DNODE_SIZE];
    d[0] = 10; // dn_type = DMU_OT_DNODE (non-zero: a live slot)
    d[1] = 12; // dn_indblkshift (4 KiB indirect)
    d[2] = 1; // dn_nlevels = 1 (blkptr[0] points straight at the L0 data block)
    d[3] = 1; // dn_nblkptr = 1
    d[4] = bonustype; // dn_bonustype
    d[8..10].copy_from_slice(&((BLOCK as u16) >> 9).to_le_bytes()); // dn_datablkszsec
    d[10..12].copy_from_slice(&(bonus.len() as u16).to_le_bytes()); // dn_bonuslen
    d[16..24].copy_from_slice(&0u64.to_le_bytes()); // dn_maxblkid = 0 (single block)
    write_blkptr(&mut d, 64, phys, BLOCK);
    // Bonus follows the single block pointer: 64 (core) + 128 (blkptr) = 192.
    let bonus_off = 64 + BLKPTR_SIZE;
    d[bonus_off..bonus_off + bonus.len()].copy_from_slice(bonus);
    d
}

/// A dnode for an object whose data block is a micro-ZAP (bonus empty).
fn zap_dnode(phys: u64) -> [u8; DNODE_SIZE] {
    dnode(phys, 0, &[])
}

/// A `BLOCK`-byte objset block: the meta-dnode (offset 0) points at the object
/// array data block at `dnode_array_phys`; `os_type` @704 = `DMU_OST_ZFS` (2).
fn objset_block(dnode_array_phys: u64, dnodes: usize) -> Vec<u8> {
    let mut b = vec![0u8; BLOCK];
    // meta-dnode: nlevels=1, nblkptr=1, its data block is the object dnode array.
    b[0] = 10;
    b[1] = 12;
    b[2] = 1;
    b[3] = 1;
    // The meta-dnode's data block spans the whole dnode array, so its data block
    // size must cover `dnodes * 512` bytes; use the smallest 512-multiple >= that,
    // rounded up to a whole block. maxblkid = 0 (one block holds the array).
    let arr_bytes = dnodes * DNODE_SIZE;
    let dblk_sectors = arr_bytes.div_ceil(512) as u16;
    b[8..10].copy_from_slice(&dblk_sectors.to_le_bytes());
    b[16..24].copy_from_slice(&0u64.to_le_bytes()); // maxblkid = 0
    write_blkptr(&mut b, 64, dnode_array_phys, arr_bytes.max(512));
    // os_type = DMU_OST_ZFS.
    b[704..712].copy_from_slice(&2u64.to_le_bytes());
    b
}

/// A `dsl_dir_phys_t` bonus: `dd_head_dataset_obj` @8.
fn dsl_dir_bonus(head_dataset_obj: u64) -> Vec<u8> {
    let mut v = vec![0u8; 256];
    v[8..16].copy_from_slice(&head_dataset_obj.to_le_bytes());
    v
}

/// A `dsl_dataset_phys_t` bonus: `ds_prev_snap_obj` @8 (= 0, no snapshots) and the
/// 128-byte `ds_bp` @128 pointing at the dataset's ZPL objset block.
fn dsl_dataset_bonus(zpl_objset_phys: u64) -> Vec<u8> {
    let mut v = vec![0u8; 256];
    // ds_bp @128 → the ZPL objset block (a BLOCK-byte objset).
    write_blkptr(&mut v, 128, zpl_objset_phys, BLOCK);
    v
}

/// A legacy `znode_phys_t` bonus (little-endian): mode @72, size @80.
fn znode_bonus(mode: u64, size: u64) -> Vec<u8> {
    let mut v = vec![0u8; ZNODE_PHYS_SIZE];
    v[64..72].copy_from_slice(&11u64.to_le_bytes()); // gen
    v[72..80].copy_from_slice(&mode.to_le_bytes());
    v[80..88].copy_from_slice(&size.to_le_bytes());
    v
}

// SA attribute ids used by the crafted registry/layout below.
const SA_MAGIC: u32 = 0x2F_505A;
const ID_ZPL_MODE: u16 = 5;
const ID_ZPL_SIZE: u16 = 6;

/// A `DMU_OT_SA` bonus for layout 1 (= `[ZPL_MODE(8), ZPL_SIZE(8)]`): `sa_magic`
/// @0, the `sa_layout_info` word @4 (`layout_num=1`, `hdrsz=8`), then the packed
/// mode/size scalars right after the 8-byte header.
fn sa_bonus(mode: u64, size: u64) -> Vec<u8> {
    let mut v = vec![0u8; 8 + 16];
    v[0..4].copy_from_slice(&SA_MAGIC.to_le_bytes());
    // info: layout_num in bits[0..10) = 1; hdrsz-in-8-byte-words in bits[10..16) = 1
    // (so hdrsz = 1 << 3 = 8 bytes).
    let info: u16 = 1 | (1 << 10);
    v[4..6].copy_from_slice(&info.to_le_bytes());
    // Attributes follow the 8-byte header, in layout order: ZPL_MODE then ZPL_SIZE.
    v[8..16].copy_from_slice(&mode.to_le_bytes());
    v[16..24].copy_from_slice(&size.to_le_bytes());
    v
}

/// Pack a micro-ZAP LAYOUTS value so `parse_sa_layouts` reads `ids` as big-endian
/// u16s: value's little-endian bytes are `[00, id0, 00, id1, …]`.
fn layout_value(ids: &[u16]) -> u64 {
    let mut bytes = [0u8; 8];
    for (i, &id) in ids.iter().enumerate().take(4) {
        bytes[i * 2..i * 2 + 2].copy_from_slice(&id.to_be_bytes());
    }
    u64::from_le_bytes(bytes)
}

/// Pack an SA `REGISTRY` value: length in bits[24..40), bswap [16..24), id [0..16).
fn registry_value(id: u16, size: u16) -> u64 {
    (u64::from(size) << 24) | u64::from(id)
}

/// The synthetic file's contents (object 3 in the ZPL).
const HELLO_CONTENT: &[u8] = b"hello, zfs!\n";

/// Assemble the complete mini-image. Layout is contiguous 4 KiB regions starting
/// at the MOS objset (placed at the real rootbp DVA), then a run of crafted blocks.
struct Image {
    bytes: Vec<u8>,
}

fn build_image() -> Image {
    let label = VdevLabel::parse(LABEL0).unwrap();
    let rootbp = label.active_uberblock.rootbp_full();
    // The MOS objset block must sit exactly where the rootbp DVA[0] resolves.
    let mos_phys = rootbp.dvas[0].physical_byte_offset() as usize;
    let mos_lsize = rootbp.lsize_bytes(); // 4 KiB on this pool

    // Place every subsequent crafted block right after the MOS block, each
    // BLOCK-aligned. We choose these offsets, so they are internally consistent.
    let base = mos_phys + mos_lsize;
    let mos_dnode_arr_phys = (base) as u64; // MOS object dnode array
    let obj_dir_phys = (base + BLOCK) as u64; // obj 1 data (object directory micro-ZAP)
    let zpl_objset_phys = (base + 2 * BLOCK) as u64; // the dataset's ZPL objset
    let zpl_dnode_arr_phys = (base + 3 * BLOCK) as u64; // ZPL object dnode array
    let zpl_master_phys = (base + 4 * BLOCK) as u64; // ZPL obj 1 (master node ZAP)
    let zpl_root_phys = (base + 5 * BLOCK) as u64; // ZPL obj 2 (root dir ZAP)
    let zpl_file_phys = (base + 6 * BLOCK) as u64; // ZPL obj 3 (hello.txt data)
    let sa_master_phys = (base + 7 * BLOCK) as u64; // ZPL obj 4 (SA master ZAP)
    let sa_registry_phys = (base + 8 * BLOCK) as u64; // ZPL obj 5 (SA REGISTRY ZAP)
    let sa_layouts_phys = (base + 9 * BLOCK) as u64; // ZPL obj 6 (SA LAYOUTS ZAP)
    let znode_file_phys = (base + 10 * BLOCK) as u64; // ZPL obj 7 (legacy-znode file)

    let image_end = (base + 11 * BLOCK).max(mos_phys + mos_lsize);
    let mut img = vec![0u8; image_end];

    // --- the real label at offset 0 ---
    img[..LABEL0.len()].copy_from_slice(LABEL0);

    // --- MOS objset block (at the rootbp DVA) ---
    // 3 objects: 0 (unused), 1 (obj dir), 2 (DSL dir), 3 (DSL dataset) → 4 slots.
    let mos_objset = objset_block(mos_dnode_arr_phys, 4);
    img[mos_phys..mos_phys + mos_objset.len().min(mos_lsize)]
        .copy_from_slice(&mos_objset[..mos_objset.len().min(mos_lsize)]);

    // --- MOS dnode array: objects 0..=3 ---
    let mut mos_arr = vec![0u8; 4 * DNODE_SIZE];
    // obj 1: object directory (micro-ZAP naming root_dataset = 2).
    mos_arr[DNODE_SIZE..2 * DNODE_SIZE].copy_from_slice(&zap_dnode(obj_dir_phys));
    // obj 2: DSL directory (bonus dd_head_dataset_obj = 3). Data block unused.
    mos_arr[2 * DNODE_SIZE..3 * DNODE_SIZE].copy_from_slice(&dnode(
        0,
        DMU_OT_DSL_DIR,
        &dsl_dir_bonus(3),
    ));
    // obj 3: DSL dataset (bonus ds_bp → ZPL objset).
    mos_arr[3 * DNODE_SIZE..4 * DNODE_SIZE].copy_from_slice(&dnode(
        0,
        DMU_OT_DSL_DATASET,
        &dsl_dataset_bonus(zpl_objset_phys),
    ));
    let mos_arr_off = mos_dnode_arr_phys as usize;
    img[mos_arr_off..mos_arr_off + mos_arr.len()].copy_from_slice(&mos_arr);

    // --- object directory micro-ZAP (obj 1's data block) ---
    let obj_dir = micro_zap(&[("root_dataset", 2)]);
    let obj_dir_off = obj_dir_phys as usize;
    img[obj_dir_off..obj_dir_off + obj_dir.len()].copy_from_slice(&obj_dir);

    // --- ZPL objset block (the dataset's objset) ---
    // 8 slots: 0 (unused), 1 master, 2 root dir, 3 hello.txt (SA), 4 SA master,
    // 5 REGISTRY, 6 LAYOUTS, 7 legacy-znode file.
    let zpl_objset = objset_block(zpl_dnode_arr_phys, 8);
    let zpl_objset_off = zpl_objset_phys as usize;
    img[zpl_objset_off..zpl_objset_off + zpl_objset.len()].copy_from_slice(&zpl_objset);

    // --- ZPL dnode array: objects 0..=7 ---
    let mut zpl_arr = vec![0u8; 8 * DNODE_SIZE];
    zpl_arr[DNODE_SIZE..2 * DNODE_SIZE].copy_from_slice(&zap_dnode(zpl_master_phys));
    zpl_arr[2 * DNODE_SIZE..3 * DNODE_SIZE].copy_from_slice(&zap_dnode(zpl_root_phys));
    // obj 3: hello.txt, an SA-bonus regular file resolved via the SA context.
    zpl_arr[3 * DNODE_SIZE..4 * DNODE_SIZE].copy_from_slice(&dnode(
        zpl_file_phys,
        DMU_OT_SA,
        &sa_bonus(0o100_644, HELLO_CONTENT.len() as u64),
    ));
    zpl_arr[4 * DNODE_SIZE..5 * DNODE_SIZE].copy_from_slice(&zap_dnode(sa_master_phys));
    zpl_arr[5 * DNODE_SIZE..6 * DNODE_SIZE].copy_from_slice(&zap_dnode(sa_registry_phys));
    zpl_arr[6 * DNODE_SIZE..7 * DNODE_SIZE].copy_from_slice(&zap_dnode(sa_layouts_phys));
    // obj 7: a legacy-znode-bonus file, so the `DMU_OT_ZNODE` dispatch arm runs.
    zpl_arr[7 * DNODE_SIZE..8 * DNODE_SIZE].copy_from_slice(&dnode(
        znode_file_phys,
        DMU_OT_ZNODE,
        &znode_bonus(0o100_600, HELLO_CONTENT.len() as u64),
    ));
    let zpl_arr_off = zpl_dnode_arr_phys as usize;
    img[zpl_arr_off..zpl_arr_off + zpl_arr.len()].copy_from_slice(&zpl_arr);

    // --- ZPL master node micro-ZAP: ROOT, VERSION, SA_ATTRS = obj 4 ---
    let master = micro_zap(&[("ROOT", 2), ("VERSION", 5), ("SA_ATTRS", 4)]);
    let master_off = zpl_master_phys as usize;
    img[master_off..master_off + master.len()].copy_from_slice(&master);

    // --- ZPL root directory micro-ZAP: hello.txt = obj 3, znode.txt = obj 7 ---
    let root = micro_zap(&[
        ("hello.txt", 0x3 | DT_REG),
        ("znode.txt", 0x7 | DT_REG),
        ("adir", 0x63 | DT_DIR),
    ]);
    let root_off = zpl_root_phys as usize;
    img[root_off..root_off + root.len()].copy_from_slice(&root);

    // --- SA master micro-ZAP: REGISTRY = obj 5, LAYOUTS = obj 6 ---
    let sa_master = micro_zap(&[("REGISTRY", 5), ("LAYOUTS", 6)]);
    let sa_master_off = sa_master_phys as usize;
    img[sa_master_off..sa_master_off + sa_master.len()].copy_from_slice(&sa_master);

    // --- SA REGISTRY micro-ZAP: ZPL_MODE (id 5, 8 bytes), ZPL_SIZE (id 6, 8) ---
    let sa_registry = micro_zap(&[
        ("ZPL_MODE", registry_value(ID_ZPL_MODE, 8)),
        ("ZPL_SIZE", registry_value(ID_ZPL_SIZE, 8)),
    ]);
    let sa_registry_off = sa_registry_phys as usize;
    img[sa_registry_off..sa_registry_off + sa_registry.len()].copy_from_slice(&sa_registry);

    // --- SA LAYOUTS micro-ZAP: layout "1" = [ZPL_MODE, ZPL_SIZE] ---
    let sa_layouts = micro_zap(&[("1", layout_value(&[ID_ZPL_MODE, ID_ZPL_SIZE]))]);
    let sa_layouts_off = sa_layouts_phys as usize;
    img[sa_layouts_off..sa_layouts_off + sa_layouts.len()].copy_from_slice(&sa_layouts);

    // --- hello.txt (obj 3) and znode.txt (obj 7) file data blocks ---
    let file_off = zpl_file_phys as usize;
    img[file_off..file_off + HELLO_CONTENT.len()].copy_from_slice(HELLO_CONTENT);
    let znode_file_off = znode_file_phys as usize;
    img[znode_file_off..znode_file_off + HELLO_CONTENT.len()].copy_from_slice(HELLO_CONTENT);

    Image { bytes: img }
}

fn mos_and_zpl(img: &[u8]) -> (ObjsetPhys, ObjsetPhys) {
    let label = VdevLabel::parse(img).unwrap();
    let rootbp = label.active_uberblock.rootbp_full();
    let mos_block = zfs_core::read_block(img, &rootbp).unwrap();
    let mos = ObjsetPhys::parse(&mos_block.data, Endian::Little).unwrap();
    let zpl = zpl_objset(img, &mos).expect("the DSL walk must reach the ZPL objset");
    (mos, zpl)
}

#[test]
fn zpl_objset_walk_reaches_the_dataset_objset() {
    let img = build_image().bytes;
    let (_mos, zpl) = mos_and_zpl(&img);
    assert_eq!(zpl.os_type, 2, "the dataset objset is DMU_OST_ZFS");
}

#[test]
fn zpl_master_root_and_root_dir_resolve() {
    let img = build_image().bytes;
    let (_mos, zpl) = mos_and_zpl(&img);
    assert_eq!(
        zpl_master_root(&img, &zpl),
        Some(2),
        "master node ROOT = obj 2"
    );
    let root = zpl_root_dir(&img, &zpl).expect("root directory dnode resolves");
    // The root dir dnode is a live ZAP object (non-empty).
    assert_eq!(root.dn_nlevels, 1);
}

#[test]
fn zpl_list_dir_masks_dirent_type_bits() {
    let img = build_image().bytes;
    let (_mos, zpl) = mos_and_zpl(&img);
    let root_id = zpl_master_root(&img, &zpl).unwrap();
    let entries: std::collections::BTreeMap<_, _> =
        zpl_list_dir(&img, &zpl, root_id).into_iter().collect();
    // The dirent-type bits are masked off, leaving the bare object ids.
    assert_eq!(entries.get("hello.txt").copied(), Some(3));
    assert_eq!(entries.get("adir").copied(), Some(99));
}

#[test]
fn zpl_sa_context_resolves_registry_and_layouts() {
    let img = build_image().bytes;
    let (_mos, zpl) = mos_and_zpl(&img);
    // The master node names SA_ATTRS → SA master → REGISTRY + LAYOUTS, so the SA
    // context resolves; the registry knows the ZPL_MODE/ZPL_SIZE ids.
    let (registry, layouts) = zpl_sa_context(&img, &zpl).expect("SA context resolves");
    assert_eq!(
        registry.by_name("ZPL_MODE").map(|d| d.id),
        Some(ID_ZPL_MODE)
    );
    // A micro-ZAP value is a fixed 8 bytes → four u16 ids; the two real ids
    // (mode, size) lead, and the trailing zero-pad is inert (decode stops at the
    // bonus end). A real pool uses a fat-ZAP with the exact length; here the pad
    // is a harmless artifact of the micro-ZAP encoding.
    assert_eq!(
        layouts.attr_ids(1),
        Some(&[ID_ZPL_MODE, ID_ZPL_SIZE, 0, 0][..]),
        "layout 1 leads with mode then size"
    );
}

#[test]
fn zpl_attrs_decodes_sa_and_legacy_znode_metadata() {
    let img = build_image().bytes;
    let (_mos, zpl) = mos_and_zpl(&img);
    let (registry, layouts) = zpl_sa_context(&img, &zpl).unwrap();
    // obj 3 carries an SA bonus decoded via the registry/layout.
    let sa = zpl_attrs(&img, &zpl, &registry, &layouts, 3).expect("SA attrs decode");
    assert_eq!(sa.mode, 0o100_644);
    assert_eq!(sa.size, HELLO_CONTENT.len() as u64);
    // obj 7 carries a legacy znode bonus, exercising the DMU_OT_ZNODE dispatch arm.
    let znode = zpl_attrs(&img, &zpl, &registry, &layouts, 7).expect("znode attrs decode");
    assert_eq!(znode.mode, 0o100_600);
    assert_eq!(znode.gen, 11);
}

#[test]
fn zpl_read_file_and_with_return_content() {
    let img = build_image().bytes;
    let (_mos, zpl) = mos_and_zpl(&img);
    // zpl_read_file builds the (absent) SA context, falls back to whole-block, and
    // returns the file bytes; zpl_read_file_with truncates to the given size.
    let whole = zpl_read_file(&img, &zpl, 3).expect("read hello.txt");
    assert!(whole.starts_with(HELLO_CONTENT));
    let sized = zpl_read_file_with(&img, &zpl, 3, Some(HELLO_CONTENT.len() as u64))
        .expect("sized read hello.txt");
    assert_eq!(sized, HELLO_CONTENT);
}

#[test]
fn zpl_lookup_and_read_path_resolve_a_file_by_name() {
    let img = build_image().bytes;
    let (_mos, zpl) = mos_and_zpl(&img);
    let (obj, attrs) = zpl_lookup(&img, &zpl, "hello.txt").expect("lookup hello.txt");
    assert_eq!(obj, 3);
    assert_eq!(attrs.size, HELLO_CONTENT.len() as u64);
    let content = zpl_read_path(&img, &zpl, "hello.txt").expect("read hello.txt by path");
    assert_eq!(content, HELLO_CONTENT);
    // A missing path is surfaced as an error, not a panic.
    assert!(zpl_read_path(&img, &zpl, "nope.txt").is_err());
    assert!(zpl_lookup(&img, &zpl, "nope.txt").is_none());
}

#[test]
fn read_dnode_data_descends_a_two_level_indirect_tree() {
    // A `dn_nlevels == 2` object: dn_blkptr[0] → an L1 indirect block whose
    // child[0] → the L0 data block. This exercises the indirect-descent loop in
    // `read_dnode_data` (the single-level objects above never enter it).
    let boot_skew: u64 = 0x0040_0000;
    let l1_phys = boot_skew + 0x1_0000; // an arbitrary allocatable offset
    let l0_phys = boot_skew + 0x2_0000;
    let image_end = (l0_phys as usize) + BLOCK;
    let mut img = vec![0u8; image_end];

    // L0 data block: recognizable content.
    let payload = b"multi-level payload";
    img[l0_phys as usize..l0_phys as usize + payload.len()].copy_from_slice(payload);

    // L1 indirect block: child[0] (a 128-byte blkptr) → the L0 data block.
    let mut l1 = vec![0u8; BLOCK];
    write_blkptr(&mut l1, 0, l0_phys, BLOCK);
    img[l1_phys as usize..l1_phys as usize + l1.len()].copy_from_slice(&l1);

    // The object dnode: nlevels=2, one top blkptr → the L1 indirect block.
    let mut raw = [0u8; DNODE_SIZE];
    raw[0] = 10; // dn_type
    raw[1] = 12; // dn_indblkshift = 4 KiB indirect (32 blkptrs, shift 5)
    raw[2] = 2; // dn_nlevels = 2
    raw[3] = 1; // dn_nblkptr = 1
    raw[8..10].copy_from_slice(&((BLOCK as u16) >> 9).to_le_bytes()); // datablkszsec
    raw[16..24].copy_from_slice(&0u64.to_le_bytes()); // dn_maxblkid = 0
    write_blkptr(&mut raw, 64, l1_phys, BLOCK); // dn_blkptr[0] → L1
    let dnode = Dnode::parse(&raw, Endian::Little).unwrap();
    assert_eq!(dnode.dn_nlevels, 2);

    let block = read_dnode_data(&img, &dnode, 0).expect("descend L1 → L0");
    assert!(block.data.starts_with(payload));
}
