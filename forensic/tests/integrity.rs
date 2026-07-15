//! F-INTEGRITY structural-anomaly integration tests.
//!
//! Oracle: the self-minted `tpool` (Tier-2 REAL-self; `zdb` is an independent
//! implementation that vouches for the ground truth). The committed always-on
//! fixtures are real bytes lifted from that pool:
//!
//! - `zfs_label0.bin` — the 256 KiB L0 vdev label (real uberblock ring, real
//!   XDR nvlist config). Its active uberblock (slot 22, txg 22) `rootbp` stores
//!   the fletcher4 checksum of the MOS objset block.
//! - `zfs_mos_objset.bin` — the 4 KiB MOS `objset_phys_t` block the `rootbp`
//!   points at; the block whose real fletcher4 equals that stored checksum.
//!
//! The committed always-on tests assert *detection deltas* on a two-piece
//! synthetic image (L0 label + the MOS block at its rootbp DVA): a byte-flip of
//! the MOS block breaks the rootbp checksum → `ZFS-UBERBLOCK-CHECKSUM-MISMATCH`;
//! a crafted 4-label image with a corrupted L2 config → `ZFS-LABEL-DIVERGENCE`.
//! "Clean pool emits nothing" over a *complete* pool (all labels + all reachable
//! blocks present) runs env-gated on the full `ZFS_ORACLE_IMG` image, since a
//! deliberately-minimal committed image lacks the tail labels and child blocks a
//! whole-pool audit legitimately checks.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zfs_forensic::{audit_findings, audit_image, AnomalyKind, Severity};

/// The real L0 vdev label (uberblock ring + nvlist config).
const LABEL0: &[u8] = include_bytes!("../../tests/data/zfs_label0.bin");
/// The real MOS objset block the active uberblock's rootbp points at.
const MOS_OBJSET: &[u8] = include_bytes!("../../tests/data/zfs_mos_objset.bin");

/// The MOS block's DVA[0] physical byte offset (`rootbp DVA[0] <0:c015000:1000>`,
/// `+0x400000` boot skew).
const MOS_PHYS_OFFSET: usize = 0x0c01_5000 + 0x0040_0000;

/// Assemble a two-piece structurally-real image: the L0 label at offset 0, and
/// the MOS objset block at its rootbp DVA[0] physical offset, so the active
/// uberblock's rootbp checksum verifies against a genuine block. The image ends
/// right after the MOS block — it deliberately carries no tail labels and no
/// reachable child blocks (those are checked env-gated on the full image).
fn rootbp_image() -> Vec<u8> {
    let end = MOS_PHYS_OFFSET + MOS_OBJSET.len();
    let mut img = vec![0u8; end];
    img[..LABEL0.len()].copy_from_slice(LABEL0);
    img[MOS_PHYS_OFFSET..MOS_PHYS_OFFSET + MOS_OBJSET.len()].copy_from_slice(MOS_OBJSET);
    img
}

#[test]
fn intact_rootbp_and_matching_labels_emit_no_uberblock_or_label_anomaly() {
    // The two-piece image has an intact rootbp→MOS checksum and only the L0
    // label present (no tail labels to diverge), so neither an uberblock nor a
    // label anomaly should fire. (The reachable-block sweep is naturally quiet:
    // the MOS meta-dnode's child blkptr targets lie past this minimal image, so
    // they read as Unreadable, never a mismatch.)
    let img = rootbp_image();
    let anomalies = audit_image(&img);
    assert!(
        anomalies.is_empty(),
        "intact rootbp + single present label must emit nothing, got: {anomalies:?}"
    );
}

#[test]
fn byte_flipped_mos_block_flags_uberblock_checksum_mismatch() {
    // Flip a byte of the MOS block the active uberblock's rootbp points at: its
    // real fletcher4 no longer matches the rootbp's stored checksum.
    let mut img = rootbp_image();
    img[MOS_PHYS_OFFSET + 100] ^= 0xff;
    let anomalies = audit_image(&img);
    let hit = anomalies
        .iter()
        .find(|a| a.code == "ZFS-UBERBLOCK-CHECKSUM-MISMATCH")
        .expect("a broken rootbp->MOS checksum must be flagged");
    assert_eq!(hit.severity, Severity::High);
    assert!(matches!(
        hit.kind,
        AnomalyKind::UberblockChecksumMismatch { txg: 22, .. }
    ));
}

#[test]
fn crafted_label_config_divergence_is_flagged() {
    // Build a 4-label image (no data region, so the rootbp DVA lies past the
    // image → the rootbp check is Unreadable and the block sweep is quiet). L0,
    // L1, L3 carry the real config; L2's config region is corrupted so it cannot
    // be reconciled with the others.
    let vdev_size = 4 * 256 * 1024; // exactly 4 labels
    let mut img = vec![0u8; vdev_size];
    for &off in &[0usize, 256 * 1024, 3 * 256 * 1024] {
        img[off..off + LABEL0.len()].copy_from_slice(LABEL0);
    }
    // L2 @ vdev_size - 512KiB: real label, then zero its 4 KiB nvlist config so
    // it fails to parse while the others succeed.
    let l2 = vdev_size - 2 * 256 * 1024;
    img[l2..l2 + LABEL0.len()].copy_from_slice(LABEL0);
    for b in img.iter_mut().skip(l2 + 16 * 1024).take(4096) {
        *b = 0;
    }
    let anomalies = audit_image(&img);
    let hit = anomalies
        .iter()
        .find(|a| {
            a.code == "ZFS-LABEL-DIVERGENCE"
                && matches!(a.kind, AnomalyKind::LabelDivergence { label: 2, .. })
        })
        .expect("a label whose config cannot be reconciled must be flagged");
    assert_eq!(hit.severity, Severity::High);
    // No uberblock/blkptr anomaly on this label-only image (rootbp DVA is off the
    // end → Unreadable, not a mismatch).
    assert!(
        !anomalies
            .iter()
            .any(|a| a.code == "ZFS-UBERBLOCK-CHECKSUM-MISMATCH"
                || a.code == "ZFS-BLKPTR-CHECKSUM-MISMATCH"),
        "an out-of-image rootbp must not be reported as a checksum mismatch"
    );
}

/// The `pool_guid` value (big-endian XDR u64) lives at absolute offset 16568
/// within a label (verified: `pool_guid = 11379600771744596893`). Flipping a
/// byte there yields a label that still parses but with a different `pool_guid`.
const LABEL_POOL_GUID_OFF: usize = 16568;

#[test]
fn label_pool_guid_value_divergence_is_flagged() {
    // A well-formed 4-label vdev where L2 parses to a *different* pool_guid than
    // L0/L1/L3 — the unambiguous spliced-label signal.
    let vdev_size = 4 * 256 * 1024;
    let mut img = vec![0u8; vdev_size];
    let offs = [
        0usize,
        256 * 1024,
        vdev_size - 2 * 256 * 1024,
        vdev_size - 256 * 1024,
    ];
    for &off in &offs {
        img[off..off + LABEL0.len()].copy_from_slice(LABEL0);
    }
    // Flip a byte of L2's pool_guid value so it parses to a different guid.
    let l2 = vdev_size - 2 * 256 * 1024;
    img[l2 + LABEL_POOL_GUID_OFF] ^= 0xff;
    let anomalies = audit_image(&img);
    let hit = anomalies
        .iter()
        .find(|a| {
            matches!(
                &a.kind,
                AnomalyKind::LabelDivergence {
                    field: "pool_guid",
                    label: 2,
                    ..
                }
            )
        })
        .expect("a label with a divergent pool_guid must be flagged");
    assert_eq!(hit.severity, Severity::High);
}

/// The ashift value (big-endian XDR u64 = 12) low byte sits at absolute offset
/// 17115 within a label (verified). Setting it to a different value yields a
/// parseable label whose `vdev_tree.ashift` diverges.
const LABEL_ASHIFT_LOWBYTE_OFF: usize = 17115;

#[test]
fn label_ashift_value_divergence_is_flagged() {
    let vdev_size = 4 * 256 * 1024;
    let mut img = vec![0u8; vdev_size];
    for &off in &[
        0usize,
        256 * 1024,
        vdev_size - 2 * 256 * 1024,
        vdev_size - 256 * 1024,
    ] {
        img[off..off + LABEL0.len()].copy_from_slice(LABEL0);
    }
    // L2 keeps a valid config but a different ashift (12 → 13).
    let l2 = vdev_size - 2 * 256 * 1024;
    img[l2 + LABEL_ASHIFT_LOWBYTE_OFF] = 13;
    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::LabelDivergence {
                field: "ashift",
                label: 2,
                ..
            }
        )),
        "a label with a divergent ashift must be flagged, got: {anomalies:?}"
    );
}

#[test]
fn well_formed_four_label_pool_with_matching_labels_emits_no_divergence() {
    // All four labels identical (real config): no divergence, and the rootbp
    // check is Unreadable (no data region), so a whole clean 4-label device with
    // no reachable blocks emits nothing.
    let vdev_size = 4 * 256 * 1024;
    let mut img = vec![0u8; vdev_size];
    for &off in &[
        0usize,
        256 * 1024,
        vdev_size - 2 * 256 * 1024,
        vdev_size - 256 * 1024,
    ] {
        img[off..off + LABEL0.len()].copy_from_slice(LABEL0);
    }
    let anomalies = audit_image(&img);
    assert!(
        anomalies.is_empty(),
        "four matching labels + no data region must emit nothing, got: {anomalies:?}"
    );
}

#[test]
fn findings_mirror_forensicnomicon_report_model() {
    // audit_findings returns forensicnomicon report::Finding tagged with the
    // analyzer name and scope, mirroring btrfs/xfs-forensic.
    let mut img = rootbp_image();
    img[MOS_PHYS_OFFSET + 100] ^= 0xff;
    let findings = audit_findings(&img, "vdev0");
    assert!(!findings.is_empty());
    let f = &findings[0];
    assert_eq!(f.source.analyzer, "zfs-forensic");
    assert_eq!(f.source.scope, "vdev0");
    // The finding is an observation ("consistent with"), never a verdict.
    assert!(f.note.to_lowercase().contains("consistent with"));
}

#[test]
fn malformed_input_never_panics() {
    assert!(audit_image(&[]).is_empty());
    assert!(audit_image(&[0u8; 16]).is_empty());
    assert!(audit_image(&[0xffu8; 4096]).is_empty());
    // A full label-sized buffer of garbage: passes the length guard but fails
    // VdevLabel::parse (no uberblock magic) — the L0-parse-fail return.
    assert!(audit_image(&vec![0xffu8; 256 * 1024]).is_empty());
    for start in (0..LABEL0.len().saturating_sub(8192)).step_by(8192) {
        let _ = audit_image(&LABEL0[start..start + 8192]);
    }
}

#[test]
fn small_but_labelled_image_skips_the_whole_vdev_divergence_check() {
    // A real L0 label followed by too little space for a four-label vdev: the
    // divergence check is a whole-vdev signal, so it is skipped (the
    // image_len < 4 labels guard), yielding no label anomaly.
    let mut img = vec![0u8; 2 * 256 * 1024]; // only room for the front pair
    img[..LABEL0.len()].copy_from_slice(LABEL0);
    let anomalies = audit_image(&img);
    assert!(
        !anomalies.iter().any(|a| a.code == "ZFS-LABEL-DIVERGENCE"),
        "a sub-four-label image must not emit a label-divergence anomaly, got: {anomalies:?}"
    );
}

// ── env-gated whole-pool checks (complete image: all labels + child blocks) ──

fn full_image() -> Option<Vec<u8>> {
    let path = std::env::var("ZFS_ORACLE_IMG").ok()?;
    std::fs::read(path).ok()
}

#[test]
fn complete_clean_pool_emits_no_anomalies() {
    let Some(img) = full_image() else {
        eprintln!("ZFS_ORACLE_IMG unset — skipping whole-pool clean audit");
        return;
    };
    let anomalies = audit_image(&img);
    assert!(
        anomalies.is_empty(),
        "a complete, clean pool must emit nothing, got: {anomalies:?}"
    );
}

#[test]
fn complete_pool_with_corrupted_reachable_block_flags_blkptr_mismatch() {
    let Some(mut img) = full_image() else {
        return;
    };
    // The MOS meta-dnode's blkptr[0] is a level-1 indirect at DVA 0x4025000
    // (verified against zdb / tests/data/README.md); its physical byte offset is
    // 0x4025000 + 0x400000. Flip a byte inside that reachable child block: the
    // sweep must report ZFS-BLKPTR-CHECKSUM-MISMATCH (distinct from the rootbp
    // check, which stays intact because the MOS block itself is untouched).
    let child_phys = 0x0402_5000 + 0x0040_0000;
    img[child_phys + 200] ^= 0xff;
    let anomalies = audit_image(&img);
    assert!(
        anomalies
            .iter()
            .any(|a| a.code == "ZFS-BLKPTR-CHECKSUM-MISMATCH"),
        "a corrupted reachable metadata block must be flagged, got: {anomalies:?}"
    );
    assert!(
        !anomalies
            .iter()
            .any(|a| a.code == "ZFS-UBERBLOCK-CHECKSUM-MISMATCH"),
        "the untouched rootbp->MOS checksum must stay intact"
    );
}
