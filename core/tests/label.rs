//! P0 vdev-label + XDR-nvlist integration tests.
//!
//! Oracle: a self-minted single-file-vdev pool (`tpool`, OpenZFS 2.2.2, ashift
//! 12) decoded independently by `zdb -l` — Tier-2 REAL-self (the pool is real
//! OpenZFS output; `zdb` is a separate implementation that vouches for the
//! ground-truth values). The always-on fixture `tests/data/zfs_label0.bin` is
//! the 256 KiB L0 label lifted verbatim from that image. See
//! `tests/data/README.md` for provenance, mint commands, md5s, and the full
//! `zdb -l` ground truth.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zfs_core::{label_offsets, NvValue, VdevLabel, LABEL_SIZE, NVLIST_OFFSET};

const LABEL0: &[u8] = include_bytes!("../../tests/data/zfs_label0.bin");

// ---- label geometry --------------------------------------------------------

#[test]
fn four_label_offsets_are_computed_from_vdev_size() {
    // The minted image is 512 MiB.
    let vdev_size: u64 = 512 * 1024 * 1024;
    let (front, back) = label_offsets(vdev_size);
    assert_eq!(front, [0, 256 * 1024], "L0 @ 0, L1 @ 256 KiB");
    let back = back.expect("512 MiB vdev holds the back label pair");
    assert_eq!(
        back,
        [vdev_size - 512 * 1024, vdev_size - 256 * 1024],
        "L2 @ size-512KiB, L3 @ size-256KiB"
    );
}

#[test]
fn tiny_vdev_has_no_back_labels() {
    let (front, back) = label_offsets(300 * 1024); // < 4 labels
    assert_eq!(front, [0, 256 * 1024]);
    assert!(back.is_none(), "no room for the back label pair");
}

#[test]
fn label_region_constants_match_spec() {
    assert_eq!(LABEL_SIZE, 256 * 1024);
    assert_eq!(NVLIST_OFFSET, 16 * 1024);
}

// ---- XDR nvlist config vs `zdb -l` -----------------------------------------

#[test]
fn nvlist_decodes_top_level_config_matching_zdb() {
    let label = VdevLabel::parse(LABEL0).unwrap();
    let c = &label.config;
    // Ground truth from `zdb -l /tmp/zfs/zfs.img`:
    assert_eq!(c.get_u64("version"), Some(5000), "version");
    assert_eq!(c.get_str("name"), Some("tpool"), "pool name");
    assert_eq!(
        c.get_u64("pool_guid"),
        Some(11_379_600_771_744_596_893),
        "pool_guid"
    );
    assert_eq!(c.get_u64("txg"), Some(22), "config txg");
    assert_eq!(c.get_u64("state"), Some(1), "state");
}

#[test]
fn nvlist_decodes_nested_vdev_tree_matching_zdb() {
    let label = VdevLabel::parse(LABEL0).unwrap();
    let vt = label.config.vdev_tree().expect("vdev_tree present");
    // Ground truth from `zdb -l` vdev_tree:
    assert_eq!(vt.vdev_type, "file", "vdev type");
    assert_eq!(vt.ashift, 12, "ashift");
    assert_eq!(vt.asize, 532_152_320, "asize");
    assert_eq!(vt.guid, 7_150_170_430_718_702_530, "vdev guid");
}

#[test]
fn nvlist_value_typing_is_preserved() {
    let label = VdevLabel::parse(LABEL0).unwrap();
    assert!(matches!(label.config.get("name"), Some(NvValue::Str(_))));
    assert!(matches!(label.config.get("version"), Some(NvValue::U64(_))));
    assert!(matches!(
        label.config.get("vdev_tree"),
        Some(NvValue::NvList(_))
    ));
}

// ---- robustness ------------------------------------------------------------

#[test]
fn truncated_label_is_rejected_not_panicked() {
    let short = &LABEL0[..1024];
    assert!(VdevLabel::parse(short).is_err());
}

#[test]
fn nvlist_of_arbitrary_junk_never_panics() {
    // Every 1 KiB window of the label parsed as an nvlist must not panic (it may
    // error or return an empty/partial list) — malformed input is routine.
    for start in (0..LABEL0.len().saturating_sub(4096)).step_by(4096) {
        let window = &LABEL0[start..start + 4096];
        let _ = zfs_core::nvlist_parse(window);
    }
}

#[test]
fn empty_and_short_buffers_do_not_panic() {
    assert!(VdevLabel::parse(&[]).is_err());
    assert!(VdevLabel::parse(&[0u8; 16]).is_err());
    let _ = zfs_core::nvlist_parse(&[]);
    let _ = zfs_core::nvlist_parse(&[1, 1, 0, 0]); // XDR header, no body
}
