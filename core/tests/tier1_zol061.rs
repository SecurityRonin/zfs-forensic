//! **Tier-1** bootstrap-layer validation against a third-party OpenZFS reference
//! pool.
//!
//! Oracle: `openzfs/zfs-images` `zol-0.6.1.tar.bz2` — a reference `raidz1` pool
//! of four 256 MiB file-vdevs published by the OpenZFS project, with `zdb -l` as
//! the independent oracle. This is a genuine **third-party** artifact + answer
//! key (Evidence-Based Rigor *tier 1*), not a fixture we authored: neither the
//! pool nor the ground truth is ours.
//!
//! What is validated at Tier-1 here is the **bootstrap layer** that reads per
//! vdev **without** RAIDZ reconstruction — each vdev carries its own vdev labels,
//! XDR nvlist config, and uberblock ring. Our `VdevLabel::parse` / nvlist /
//! `Uberblock` decode of a real `zol-0.6.1` vdev must reproduce exactly what
//! `zdb -l` / `zdb -u` report:
//!
//! ```text
//! version 5000, name 'zol-0.6.1', txg 72, pool state 1,
//! vdev_tree type 'raidz', nparity 1, ashift 9, vdev_children 1
//! active uberblock: magic 0x00bab10c (little-endian), version 5000, txg 72
//! ```
//!
//! Reading the MOS / DMU / ZAP / ZPL / file layers of this pool needs RAIDZ
//! parity reconstruction across the four vdevs, which `zfs-core` defers — so
//! those layers stay **Tier-2** (validated against the single-vdev self-mint
//! `tpool` in the other test files). This file is deliberately scoped to the
//! bootstrap layer that is reachable on a single raidz member.
//!
//! Provenance (source URL, md5s, the `zdb -l` answer key): `tests/data/README.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zfs_core::{Endian, VdevLabel, LABEL_SIZE};

/// The L0 (256 KiB) vdev label lifted verbatim from `zol-0.6.1/vdev0` — the
/// always-on Tier-1 fixture. Small enough to commit; the full four-vdev corpus
/// is env-gated (`ZFS_TIER1_ZOL`) below.
const ZOL_VDEV0_LABEL0: &[u8] = include_bytes!("../../tests/data/zfs_zol061_vdev0_label0.bin");

/// The full documented `zdb -l` / `zdb -u` answer key for `zol-0.6.1/vdev0`.
/// Asserting our decode of a real vdev label against these third-party values is
/// the Tier-1 bootstrap check.
fn assert_zol061_bootstrap(label: &VdevLabel) {
    let c = &label.config;

    // ── top-level XDR nvlist config vs `zdb -l` ──────────────────────────────
    assert_eq!(c.get_u64("version"), Some(5000), "pool version (zdb -l)");
    assert_eq!(c.get_str("name"), Some("zol-0.6.1"), "pool name (zdb -l)");
    assert_eq!(c.get_u64("state"), Some(1), "pool state (zdb -l)");
    assert_eq!(c.get_u64("txg"), Some(72), "config txg (zdb -l)");
    assert_eq!(
        c.get_u64("vdev_children"),
        Some(1),
        "vdev_children (zdb -l)"
    );

    // ── nested vdev_tree vs `zdb -l` ─────────────────────────────────────────
    let vt = c.vdev_tree().expect("vdev_tree present");
    assert_eq!(vt.vdev_type, "raidz", "top-level vdev type (zdb -l)");
    assert_eq!(vt.ashift, 9, "ashift (zdb -l)");
    // `nparity` lives on the nested vdev_tree nvlist; raidz1 -> 1.
    let vt_nv = c.get_nvlist("vdev_tree").expect("vdev_tree nvlist");
    assert_eq!(vt_nv.get_u64("nparity"), Some(1), "raidz nparity (zdb -l)");

    // ── active uberblock vs `zdb -u` ─────────────────────────────────────────
    let ub = &label.active_uberblock;
    assert_eq!(
        ub.magic,
        zfs_core::UBERBLOCK_MAGIC,
        "uberblock magic (zdb -u)"
    );
    assert_eq!(ub.endian, Endian::Little, "little-endian pool (zdb -u)");
    assert_eq!(ub.version, 5000, "uberblock version (zdb -u)");
    assert_eq!(ub.txg, 72, "active uberblock txg (zdb -u)");
    // ashift 9 -> slot_size 1 KiB -> 128 ring slots -> active slot = txg % 128.
    assert_eq!(label.active_slot, 72 % 128, "active ring slot = txg % 128");
}

/// Tier-1 (always-on): the committed L0-label fixture from the real `zol-0.6.1`
/// vdev0 decodes to exactly the `zdb -l` / `zdb -u` ground truth.
#[test]
fn zol061_vdev0_label_matches_zdb() {
    assert_eq!(
        ZOL_VDEV0_LABEL0.len(),
        LABEL_SIZE,
        "fixture is one 256 KiB label"
    );
    let label = VdevLabel::parse(ZOL_VDEV0_LABEL0).expect("parse zol-0.6.1 vdev0 L0 label");
    assert_zol061_bootstrap(&label);
}

/// Tier-1 (env-gated): when the full four-vdev corpus is present
/// (`ZFS_TIER1_ZOL` → the extracted `zol-0.6.1` directory), each of the four
/// raidz members independently decodes its own L0 bootstrap to the same answer
/// key — every vdev label / nvlist / uberblock reads without RAIDZ
/// reconstruction. Skips cleanly when the env var is unset.
#[test]
fn zol061_all_four_vdevs_bootstrap_independently() {
    let Ok(dir) = std::env::var("ZFS_TIER1_ZOL") else {
        eprintln!("ZFS_TIER1_ZOL unset — skipping full-corpus Tier-1 check");
        return;
    };
    for v in 0..4 {
        let path = format!("{dir}/vdev{v}");
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let l0 = bytes.get(0..LABEL_SIZE).expect("vdev holds an L0 label");
        let label = VdevLabel::parse(l0).unwrap_or_else(|e| panic!("parse {path} L0: {e:?}"));
        // Pool-invariant identity: every member agrees on the pool config.
        assert_zol061_bootstrap(&label);
    }
}
