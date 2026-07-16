//! **Tier-1** full-read-path validation against a third-party `FreeBSD` ZFS-root
//! image.
//!
//! Oracle: an official **`FreeBSD` 14.3-RELEASE amd64 ZFS-on-root** VM image
//! (`FreeBSD-14.3-RELEASE-amd64-zfs.qcow2.xz`, vendor-published SHA256), whose
//! ground truth is confirmed by two wholly independent OpenZFS implementations —
//! `zdb` (the ZFS debugger) and a live read-only kernel `zfs mount`. This is a
//! genuine **third-party artifact + third-party answer key** (Evidence-Based
//! Rigor *tier 1*): neither the pool nor the ground truth is ours.
//!
//! Why this upgrades the file layer to Tier-1. The existing `zol-0.6.1`
//! third-party pool (`tier1_zol061.rs`) is **raidz1**, so reading its data blocks
//! needs RAIDZ parity reconstruction across four vdevs — which `zfs-core` defers.
//! Only its per-vdev *bootstrap* (label + nvlist + uberblock) validated at
//! Tier-1 there; the DMU/ZAP/ZPL/SA/file layers stayed Tier-2 on a single-vdev
//! self-mint. This `FreeBSD` pool is a real **single `type: 'disk'` vdev**
//! (`zdb -l`: `vdev_tree type 'disk'`, not `raidz`), so **no reconstruction** is
//! needed and `zfs-core`'s *entire* read path — label → uberblock → MOS → DSL →
//! ZPL → SA → **file content** — validates against genuine third-party bytes.
//!
//! What the test walks (all through `zfs-core`, on the real partition):
//!   1. `VdevLabel::parse` → pool `zroot`, single `disk` vdev, ashift 12, and the
//!      active uberblock (`txg 8`, little-endian) — vs `zdb -l` / `zdb -u`.
//!   2. active uberblock `rootbp` → `read_block` → the MOS `objset_phys_t`.
//!   3. MOS object directory (obj 1) → `root_dataset` → the DSL directory tree.
//!   4. `FreeBSD` nests its root filesystem in a **child** dataset
//!      (`zroot/ROOT/default`, the boot environment), not the pool's head
//!      dataset. `zfs-core`'s `zpl_objset` reaches only the head dataset, so the
//!      child-dataset hop (`dd_child_dir_zapobj` → `ROOT` → `default` →
//!      `dd_head_dataset_obj` 30) is assembled here from `zfs-core`'s **exported
//!      primitives** (`mos_dnode` / `read_zap_object` / `zap_lookup` /
//!      `dsl_dataset_bp`). Every block read, checksum, DSL/ZAP/ZPL/SA decode
//!      still runs inside `zfs-core`; only the child-directory ZAP hop is wired
//!      in the test. (This is the one navigation primitive `zfs-core` does not
//!      yet expose as a high-level call — see `tests/data/README.md`.)
//!   5. the resulting ZPL objset → `zpl_root_dir` / `zpl_list_dir` list the real
//!      `FreeBSD` `/` (`bin boot COPYRIGHT dev etc … usr var`), and
//!      `zpl_read_path("/.cshrc")` / `zpl_read_path("/COPYRIGHT")` read real file
//!      bytes whose sha256 matches the independent kernel-mount + `zdb` oracle.
//!
//! Compression note: both validated files are stored **uncompressed** on this
//! pool (`zdb`: `1000L/1000P`, `2000L/2000P`), so the read exercises the
//! `CompressType::Off` path; `zfs-core` also decodes lz4/zstd (validated
//! elsewhere), but no compressed real file is needed to prove the end-to-end
//! read here.
//!
//! Provenance (source URL, vendor SHA256, partition md5, the `zdb`/mount answer
//! key): `tests/data/README.md`. Env-gated on `ZFS_TIER1_FREEBSD` → the absolute
//! path of the extracted `freebsd-zfs` partition; skips cleanly when unset.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zfs_core::{
    dsl_dataset_bp, mos_dnode, read_block, read_zap_object, zap_lookup, zpl_list_dir,
    zpl_master_root, zpl_read_path, zpl_root_dir, Endian, ObjsetPhys, VdevLabel,
};

// ── independent-oracle ground truth (zdb -l/-u + read-only kernel `zfs mount`) ──

/// The vendor pool name (`zdb -l`: `name 'zroot'`).
const POOL_NAME: &str = "zroot";
/// `zdb -u`: the active uberblock's transaction group.
const ACTIVE_TXG: u64 = 8;

/// The real `FreeBSD` `/` directory listing, as reported by a read-only kernel
/// `ls /mnt` of `zroot/ROOT/default` (sorted). `zfs-core`'s `zpl_list_dir` must
/// reproduce exactly this set.
const ROOT_LISTING: &[&str] = &[
    ".cshrc",
    ".profile",
    "COPYRIGHT",
    "bin",
    "boot",
    "dev",
    "etc",
    "firstboot",
    "lib",
    "libexec",
    "media",
    "mnt",
    "net",
    "proc",
    "rescue",
    "root",
    "sbin",
    "tmp",
    "usr",
    "var",
];

/// `/.cshrc` — size and sha256 from the independent oracle (both `zdb -R` block
/// extraction and a live read-only kernel `zfs mount` agree on this hash).
const CSHRC_SIZE: usize = 1011;
const CSHRC_SHA256: &str = "d1ba75d6e942aa2f17eb84061fe4edda1d17b9a9ab8e4e2ce3a19e650403b5d7";

/// `/COPYRIGHT` — the `FreeBSD` copyright notice; size + sha256 from the kernel
/// mount oracle.
const COPYRIGHT_SIZE: usize = 6109;
const COPYRIGHT_SHA256: &str = "4ce916521645614401dd3f625bd534a2281c5e494fe50a631718de1a7c3fb064";

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    Sha256::digest(data).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Read a DSL directory dnode's bonus fields directly (`dsl_dir_phys_t`):
/// `dd_head_dataset_obj` at bonus offset 8, `dd_child_dir_zapobj` at offset 32.
/// The layout is documented in `zfs-core`'s `dsl` module; `zfs-core` exposes an
/// accessor for the head-dataset field but not (yet) for the child-dir ZAP, so
/// the child hop reads offset 32 here.
fn dsl_dir_fields(image: &[u8], mos: &ObjsetPhys, dsl_dir_obj: u64) -> (u64, u64) {
    let d = mos_dnode(image, mos, dsl_dir_obj).expect("DSL directory dnode");
    let head = u64::from_le_bytes(d.bonus[8..16].try_into().unwrap());
    let child_zapobj = u64::from_le_bytes(d.bonus[32..40].try_into().unwrap());
    (head, child_zapobj)
}

/// Resolve a named child DSL directory: read the parent's `dd_child_dir_zapobj`
/// ZAP and look the name up → the child DSL directory object id.
fn child_dsl_dir(image: &[u8], mos: &ObjsetPhys, parent_dsl_dir: u64, name: &str) -> u64 {
    let (_head, child_zapobj) = dsl_dir_fields(image, mos, parent_dsl_dir);
    let zap_node = mos_dnode(image, mos, child_zapobj).expect("child_dir ZAP dnode");
    let zap_data = read_zap_object(image, &zap_node).expect("child_dir ZAP data");
    zap_lookup(&zap_data, name).unwrap_or_else(|| panic!("child DSL dir {name} present"))
}

/// The full third-party `FreeBSD` ZFS-root read-path validation. `zfs-core` reads a
/// real vendor-authored single-vdev pool end-to-end: label → uberblock → MOS →
/// DSL (incl. the child-dataset hop) → ZPL → SA → file content, and every value
/// matches the independent `zdb` / kernel-mount oracle. Skips cleanly when
/// `ZFS_TIER1_FREEBSD` is unset.
#[test]
fn freebsd_zfs_root_full_read_path_matches_zdb_and_mount() {
    let Ok(path) = std::env::var("ZFS_TIER1_FREEBSD") else {
        eprintln!("ZFS_TIER1_FREEBSD unset — skipping FreeBSD full-read-path Tier-1 check");
        return;
    };
    let img = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));

    // 1. Bootstrap: label + nvlist + uberblock (single `disk` vdev, not raidz).
    let label = VdevLabel::parse(&img[..zfs_core::LABEL_SIZE]).expect("parse FreeBSD vdev label");
    assert_eq!(
        label.config.get_str("name"),
        Some(POOL_NAME),
        "pool name (zdb -l)"
    );
    assert_eq!(
        label.config.get_u64("vdev_children"),
        Some(1),
        "single top-level vdev (zdb -l)"
    );
    let vt = label.config.vdev_tree().expect("vdev_tree present");
    assert_eq!(
        vt.vdev_type, "disk",
        "single `disk` vdev — no RAIDZ reconstruction needed (zdb -l)"
    );
    let ub = &label.active_uberblock;
    assert_eq!(ub.endian, Endian::Little, "little-endian pool (zdb -u)");
    assert_eq!(ub.txg, ACTIVE_TXG, "active uberblock txg (zdb -u)");

    // 2. rootbp → MOS objset.
    let mos_block = read_block(&img, &ub.rootbp_full()).expect("read_block(rootbp)");
    let mos = ObjsetPhys::parse(&mos_block.data, Endian::Little).expect("MOS objset_phys");

    // 3. MOS object directory (obj 1) → root_dataset (the pool's top DSL dir).
    let objdir = mos_dnode(&img, &mos, 1).expect("MOS object directory");
    let objdir_data = read_zap_object(&img, &objdir).expect("object directory ZAP");
    let root_dsl_dir = zap_lookup(&objdir_data, "root_dataset").expect("root_dataset entry");

    // 4. Child-dataset walk: root DSL dir → `ROOT` → `default` → head dataset.
    //    (FreeBSD's `/` lives in the `zroot/ROOT/default` boot environment.)
    let root_be_dir = child_dsl_dir(&img, &mos, root_dsl_dir, "ROOT");
    let default_be_dir = child_dsl_dir(&img, &mos, root_be_dir, "default");
    let (head_dataset, _cz) = dsl_dir_fields(&img, &mos, default_be_dir);
    assert_ne!(head_dataset, 0, "default boot-env head dataset resolved");

    // 5. head dataset → ds_bp → the real ZPL objset.
    let dataset = mos_dnode(&img, &mos, head_dataset).expect("head dataset dnode");
    let zpl_block = read_block(&img, &dsl_dataset_bp(&dataset)).expect("read_block(ds_bp)");
    let zpl = ObjsetPhys::parse(&zpl_block.data, Endian::Little).expect("ZPL objset_phys");
    assert_eq!(
        zpl.os_type,
        zfs_core::DMU_OST_ZFS,
        "ZPL objset (DMU_OST_ZFS)"
    );

    // 6. List the real FreeBSD `/` — must equal the kernel-mount `ls`.
    let root_id = zpl_master_root(&img, &zpl).expect("ZPL master node → ROOT id");
    zpl_root_dir(&img, &zpl).expect("root directory dnode");
    let mut names: Vec<String> = zpl_list_dir(&img, &zpl, root_id)
        .into_iter()
        .map(|(name, _obj)| name)
        .collect();
    names.sort();
    let mut expected: Vec<String> = ROOT_LISTING.iter().map(|s| (*s).to_string()).collect();
    expected.sort();
    assert_eq!(
        names, expected,
        "real FreeBSD / listing (kernel-mount oracle)"
    );

    // 7. THE full-Tier-1 gate: read real third-party file bytes; the whole reader
    //    path's output sha256 must equal the independent zdb / kernel-mount hash.
    let cshrc = zpl_read_path(&img, &zpl, "/.cshrc").expect("read /.cshrc");
    assert_eq!(cshrc.len(), CSHRC_SIZE, "/.cshrc logical size (zdb)");
    assert_eq!(
        sha256_hex(&cshrc),
        CSHRC_SHA256,
        "/.cshrc content sha256 == kernel-mount + zdb oracle"
    );

    let copyright = zpl_read_path(&img, &zpl, "/COPYRIGHT").expect("read /COPYRIGHT");
    assert_eq!(
        copyright.len(),
        COPYRIGHT_SIZE,
        "/COPYRIGHT logical size (zdb)"
    );
    assert_eq!(
        sha256_hex(&copyright),
        COPYRIGHT_SHA256,
        "/COPYRIGHT content sha256 == kernel-mount oracle"
    );

    // A path that does not exist resolves cleanly (never panics).
    assert!(zpl_read_path(&img, &zpl, "/does/not/exist").is_err());
}
