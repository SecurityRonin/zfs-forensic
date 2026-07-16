//! F-CARVE coverage over a **fully synthetic, self-consistent snapshot image**.
//!
//! The env-gated `ZFS_SNAP_ORACLE_IMG` test (`carve.rs`) proves [`recover_deleted`]
//! against the real self-minted `dtpool` snapshot pool; CI does not carry that
//! image, so the whole snapshot-carve path (`recover_deleted` / `open_mos` /
//! `dataset_root_names` / `dataset_zpl_objset` / `recover_from_snapshot`) is
//! uncovered there. This test drives the *same* functions over a small crafted
//! image, exactly like the committed block fixtures — the always-on CI coverage
//! path, with the real pool staying the independent correctness oracle.
//!
//! ## Construction (Tier-3 crafted fixture — SYNTHETIC)
//!
//!   real `zfs_label0.bin` → active uberblock `rootbp`
//!     └─ MOS objset (crafted, at the rootbp DVA)
//!          obj 1 object directory  (micro-ZAP: `root_dataset` = 2)
//!          obj 2 DSL directory     (bonus `dd_head_dataset_obj` = 3)
//!          obj 3 head DSL dataset   (bonus `ds_bp` → LIVE ZPL objset,
//!                                    `ds_prev_snap_obj` = 4)
//!          obj 4 snapshot DSL dataset (bonus `ds_bp` → SNAPSHOT ZPL objset)
//!     └─ LIVE ZPL objset      (root dir lists only `keep.txt`)
//!     └─ SNAPSHOT ZPL objset  (root dir lists `keep.txt` + `secret.txt`)
//!
//! `secret.txt` is present in the snapshot but absent live, so `recover_deleted`
//! carves it; `keep.txt` is present in both, so it is not reported. What the
//! builder writes is the ground truth (see `tests/data/README.md`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zfs_forensic::recover_deleted;

use zfs_core::{VdevLabel, BLKPTR_SIZE, DNODE_SIZE};

const LABEL0: &[u8] = include_bytes!("../../tests/data/zfs_label0.bin");

const DT_REG: u64 = 8 << 60;
const DMU_OT_ZNODE: u8 = 17;
const DMU_OT_DSL_DIR: u8 = 12;
const DMU_OT_DSL_DATASET: u8 = 16;
const BLOCK: usize = 4096;
const ZNODE_PHYS_SIZE: usize = 264;

const SECRET_CONTENT: &[u8] = b"the password is hunter2\n";
const KEEP_CONTENT: &[u8] = b"nothing to see here\n";

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

fn write_blkptr(buf: &mut [u8], off: usize, phys: u64, size: usize) {
    if phys == 0 {
        return;
    }
    let boot_skew: u64 = 0x0040_0000;
    let offset_sectors = (phys - boot_skew) >> 9;
    let asize_sectors = (size as u64).div_ceil(512);
    let w0 = asize_sectors & 0x00ff_ffff;
    let w1 = offset_sectors & 0x7fff_ffff_ffff_ffff;
    buf[off..off + 8].copy_from_slice(&w0.to_le_bytes());
    buf[off + 8..off + 16].copy_from_slice(&w1.to_le_bytes());
    let sectors = (size as u64).div_ceil(512);
    let lsize_raw = sectors - 1;
    let comp: u64 = 2; // off
    let byteorder: u64 = 1; // little-endian
    let prop =
        (lsize_raw & 0xffff) | ((lsize_raw & 0xffff) << 16) | (comp << 32) | (byteorder << 63);
    buf[off + 48..off + 56].copy_from_slice(&prop.to_le_bytes());
}

fn dnode(phys: u64, bonustype: u8, bonus: &[u8]) -> [u8; DNODE_SIZE] {
    let mut d = [0u8; DNODE_SIZE];
    d[0] = 10;
    d[1] = 12;
    d[2] = 1;
    d[3] = 1;
    d[4] = bonustype;
    d[8..10].copy_from_slice(&((BLOCK as u16) >> 9).to_le_bytes());
    d[10..12].copy_from_slice(&(bonus.len() as u16).to_le_bytes());
    write_blkptr(&mut d, 64, phys, BLOCK);
    let bonus_off = 64 + BLKPTR_SIZE;
    d[bonus_off..bonus_off + bonus.len()].copy_from_slice(bonus);
    d
}

fn zap_dnode(phys: u64) -> [u8; DNODE_SIZE] {
    dnode(phys, 0, &[])
}

fn objset_block(dnode_array_phys: u64, dnodes: usize) -> Vec<u8> {
    let mut b = vec![0u8; BLOCK];
    b[0] = 10;
    b[1] = 12;
    b[2] = 1;
    b[3] = 1;
    let arr_bytes = dnodes * DNODE_SIZE;
    let dblk_sectors = (arr_bytes as u64).div_ceil(512) as u16;
    b[8..10].copy_from_slice(&dblk_sectors.to_le_bytes());
    write_blkptr(&mut b, 64, dnode_array_phys, arr_bytes.max(512));
    b[704..712].copy_from_slice(&2u64.to_le_bytes()); // DMU_OST_ZFS
    b
}

fn dsl_dir_bonus(head_dataset_obj: u64) -> Vec<u8> {
    let mut v = vec![0u8; 256];
    v[8..16].copy_from_slice(&head_dataset_obj.to_le_bytes());
    v
}

/// A `dsl_dataset_phys_t` bonus: `ds_prev_snap_obj` @8, `ds_bp` @128.
fn dsl_dataset_bonus(prev_snap_obj: u64, zpl_objset_phys: u64) -> Vec<u8> {
    let mut v = vec![0u8; 256];
    v[8..16].copy_from_slice(&prev_snap_obj.to_le_bytes());
    write_blkptr(&mut v, 128, zpl_objset_phys, BLOCK);
    v
}

fn znode_bonus(mode: u64, size: u64) -> Vec<u8> {
    let mut v = vec![0u8; ZNODE_PHYS_SIZE];
    v[64..72].copy_from_slice(&11u64.to_le_bytes());
    v[72..80].copy_from_slice(&mode.to_le_bytes());
    v[80..88].copy_from_slice(&size.to_le_bytes());
    v
}

/// Build a ZPL objset region: objset block + dnode array + master ZAP + root ZAP +
/// per-file dnodes/data. `files` are `(name, obj_id, content)`; object ids start at
/// 3 (1 = master, 2 = root dir). Returns the objset's physical offset.
#[allow(clippy::too_many_arguments)]
fn write_zpl(img: &mut [u8], base: usize, objset_phys: usize, files: &[(&str, u64, &[u8])]) {
    let nobjs = 3 + files.len(); // 0 unused, 1 master, 2 root, then files
    let arr_phys = base;
    let master_phys = base + BLOCK;
    let root_phys = base + 2 * BLOCK;

    let objset = objset_block(arr_phys as u64, nobjs);
    img[objset_phys..objset_phys + objset.len()].copy_from_slice(&objset);

    let mut arr = vec![0u8; nobjs * DNODE_SIZE];
    arr[DNODE_SIZE..2 * DNODE_SIZE].copy_from_slice(&zap_dnode(master_phys as u64));
    arr[2 * DNODE_SIZE..3 * DNODE_SIZE].copy_from_slice(&zap_dnode(root_phys as u64));

    let mut dirents: Vec<(String, u64)> = Vec::new();
    for (i, (name, obj, content)) in files.iter().enumerate() {
        let file_phys = base + (3 + i) * BLOCK;
        let slot = *obj as usize;
        arr[slot * DNODE_SIZE..(slot + 1) * DNODE_SIZE].copy_from_slice(&dnode(
            file_phys as u64,
            DMU_OT_ZNODE,
            &znode_bonus(0o100_644, content.len() as u64),
        ));
        img[file_phys..file_phys + content.len()].copy_from_slice(content);
        dirents.push(((*name).to_string(), *obj | DT_REG));
    }
    img[arr_phys..arr_phys + arr.len()].copy_from_slice(&arr);

    let master = micro_zap(&[("ROOT", 2), ("VERSION", 5)]);
    img[master_phys..master_phys + master.len()].copy_from_slice(&master);

    let dirent_refs: Vec<(&str, u64)> = dirents.iter().map(|(n, v)| (n.as_str(), *v)).collect();
    let root = micro_zap(&dirent_refs);
    img[root_phys..root_phys + root.len()].copy_from_slice(&root);
}

fn build_snapshot_image() -> Vec<u8> {
    let label = VdevLabel::parse(LABEL0).unwrap();
    let rootbp = label.active_uberblock.rootbp_full();
    let mos_phys = rootbp.dvas[0].physical_byte_offset() as usize;
    let mos_lsize = rootbp.lsize_bytes();

    let base = mos_phys + mos_lsize;
    let mos_arr_phys = base;
    let obj_dir_phys = base + BLOCK;
    let live_objset_phys = base + 2 * BLOCK;
    let snap_objset_phys = base + 3 * BLOCK;
    // Give each ZPL its own well-separated 16-block region for blocks.
    let live_zpl_base = base + 4 * BLOCK;
    let snap_zpl_base = base + 20 * BLOCK;
    let image_end = base + 40 * BLOCK;

    let mut img = vec![0u8; image_end];
    img[..LABEL0.len()].copy_from_slice(LABEL0);

    // MOS objset: 5 slots (0,1 objdir,2 dsldir,3 head-ds,4 snap-ds).
    let mos_objset = objset_block(mos_arr_phys as u64, 5);
    img[mos_phys..mos_phys + mos_objset.len().min(mos_lsize)]
        .copy_from_slice(&mos_objset[..mos_objset.len().min(mos_lsize)]);

    let mut mos_arr = vec![0u8; 5 * DNODE_SIZE];
    mos_arr[DNODE_SIZE..2 * DNODE_SIZE].copy_from_slice(&zap_dnode(obj_dir_phys as u64));
    mos_arr[2 * DNODE_SIZE..3 * DNODE_SIZE].copy_from_slice(&dnode(
        0,
        DMU_OT_DSL_DIR,
        &dsl_dir_bonus(3),
    ));
    // obj 3: head dataset — prev_snap = obj 4, ds_bp → live objset.
    mos_arr[3 * DNODE_SIZE..4 * DNODE_SIZE].copy_from_slice(&dnode(
        0,
        DMU_OT_DSL_DATASET,
        &dsl_dataset_bonus(4, live_objset_phys as u64),
    ));
    // obj 4: snapshot dataset — no older snap, ds_bp → snapshot objset.
    mos_arr[4 * DNODE_SIZE..5 * DNODE_SIZE].copy_from_slice(&dnode(
        0,
        DMU_OT_DSL_DATASET,
        &dsl_dataset_bonus(0, snap_objset_phys as u64),
    ));
    img[mos_arr_phys..mos_arr_phys + mos_arr.len()].copy_from_slice(&mos_arr);

    let obj_dir = micro_zap(&[("root_dataset", 2)]);
    img[obj_dir_phys..obj_dir_phys + obj_dir.len()].copy_from_slice(&obj_dir);

    // LIVE root: only keep.txt (obj 3).
    write_zpl(
        &mut img,
        live_zpl_base,
        live_objset_phys,
        &[("keep.txt", 3, KEEP_CONTENT)],
    );
    // SNAPSHOT root: keep.txt (obj 3) + secret.txt (obj 4, deleted live).
    write_zpl(
        &mut img,
        snap_zpl_base,
        snap_objset_phys,
        &[
            ("keep.txt", 3, KEEP_CONTENT),
            ("secret.txt", 4, SECRET_CONTENT),
        ],
    );

    img
}

#[test]
fn recover_deleted_carves_the_snapshot_only_file() {
    let img = build_snapshot_image();
    let recovered = recover_deleted(&img);

    let secret = recovered
        .iter()
        .find(|r| r.path == "secret.txt")
        .expect("secret.txt is in the snapshot but absent live → carved");
    // This crafted snapshot dataset is a legacy-znode pool (no SA context), so
    // `zpl_read_file` cannot learn the logical size and returns whole blocks
    // untruncated — the reader's documented "never silently drop bytes" fallback.
    // The carved content therefore *begins with* the deleted file's bytes.
    assert!(secret.content.starts_with(SECRET_CONTENT));
    assert_eq!(secret.size, secret.content.len() as u64);
    // The recovered sha256 is populated (the recovery gate); it is a 64-hex digest.
    assert_eq!(secret.content_sha256.len(), 64);
    assert!(secret.content_sha256.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(secret.inode, 4);
    assert!(
        secret.source.contains("snapshot"),
        "source names the snapshot: {}",
        secret.source
    );
}

#[test]
fn live_present_file_is_not_reported_as_deleted() {
    let img = build_snapshot_image();
    let recovered = recover_deleted(&img);
    // keep.txt is present in BOTH the live root and the snapshot, so it is not a
    // deletion and must not appear.
    assert!(recovered.iter().all(|r| r.path != "keep.txt"));
}

#[test]
fn non_zfs_image_recovers_nothing_without_panicking() {
    // A garbage buffer has no valid label → open_mos returns None → empty result.
    assert!(recover_deleted(&[0u8; 4096]).is_empty());
    assert!(recover_deleted(&[]).is_empty());
}
