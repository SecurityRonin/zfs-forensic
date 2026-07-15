//! P0 endian-adaptive uberblock integration tests.
//!
//! Oracle: `zdb -uuu` / `zdb -uuuuu -e -p /tmp/zfs tpool` on the self-minted
//! `tpool` (Tier-2 REAL-self; `zdb` is an independent implementation). Ground
//! truth in `tests/data/README.md`. The active uberblock is slot 22 (`txg 22`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zfs_core::{Endian, VdevLabel};

const LABEL0: &[u8] = include_bytes!("../../tests/data/zfs_label0.bin");

#[test]
fn active_uberblock_is_highest_txg_matching_zdb() {
    let label = VdevLabel::parse(LABEL0).unwrap();
    let ub = &label.active_uberblock;
    // `zdb -uuu tpool`: the active uberblock is txg 22.
    assert_eq!(ub.txg, 22, "active uberblock txg");
    assert_eq!(label.active_slot, 22, "ring slot = txg % 32 for ashift 12");
    assert_eq!(ub.version, 5000, "ub_version");
    assert_eq!(ub.guid_sum, 83_027_128_753_747_807, "ub_guid_sum");
    assert_eq!(ub.timestamp, 1_783_939_238, "ub_timestamp");
}

#[test]
fn endianness_is_detected_from_the_magic() {
    let label = VdevLabel::parse(LABEL0).unwrap();
    // The pool was minted on a little-endian (aarch64) host.
    assert_eq!(label.active_uberblock.endian, Endian::Little);
    assert_eq!(label.active_uberblock.magic, 0x0000_0000_00ba_b10c);
}

#[test]
fn rootbp_exposes_the_mos_objset_pointer_matching_zdb() {
    let label = VdevLabel::parse(LABEL0).unwrap();
    let bp = &label.active_uberblock.rootbp;
    // `zdb -uuuuu`: rootbp = DVA[0]=<0:c015000:1000> ... [L0 DMU objset]
    //              fletcher4 uncompressed ... LE ... size=1000L/1000P
    let dva0 = bp.dvas[0];
    assert_eq!(dva0.vdev, 0, "DVA[0] vdev");
    assert_eq!(dva0.asize_sectors, 8, "DVA[0] asize = 0x1000 = 8 sectors");
    // zdb DVA offset 0xc015000 bytes = 393384 sectors.
    assert_eq!(
        dva0.offset_sectors,
        0x0c01_5000 / 512,
        "DVA[0] offset (sectors)"
    );
    // physical = (offset << 9) + 0x400000 boot skew.
    assert_eq!(dva0.physical_byte_offset(), 0x0c01_5000 + 0x0040_0000);
    // Second and third ditto copies are present (triple copies for MOS).
    assert!(!bp.dvas[1].is_empty(), "DVA[1] present (ditto)");
    assert!(!bp.dvas[2].is_empty(), "DVA[2] present (ditto)");
    // L0 DMU objset, uncompressed.
    assert_eq!(bp.level, 0, "rootbp level (L0)");
    assert_eq!(bp.object_type, 11, "DMU_OT_OBJSET");
    assert_eq!(bp.compression, 2, "ZIO_COMPRESS_OFF");
    assert_eq!(bp.lsize_sectors, 8, "LSIZE 0x1000 = 8 sectors");
    assert_eq!(bp.psize_sectors, 8, "PSIZE 0x1000 = 8 sectors");
}

#[test]
fn uberblock_parse_rejects_a_slot_without_the_magic() {
    // An all-zero slot is not a valid uberblock.
    assert!(zfs_core::uberblock_parse(&[0u8; 4096]).is_none());
}

#[test]
fn big_endian_magic_is_recognised() {
    // Craft a slot whose magic reads back only in big-endian order.
    let mut slot = [0u8; 1024];
    slot[..8].copy_from_slice(&0x0000_0000_00ba_b10c_u64.to_be_bytes());
    let ub = zfs_core::uberblock_parse(&slot).expect("BE magic recognised");
    assert_eq!(ub.endian, Endian::Big);
}

#[test]
fn oversized_and_garbage_slots_never_panic() {
    let _ = zfs_core::uberblock_parse(&[]);
    let _ = zfs_core::uberblock_parse(&[0xAB; 3]);
    let _ = zfs_core::uberblock_parse(&[0xFF; 4096]);
}

/// Full-image oracle test — env-gated on `ZFS_ORACLE_IMG` pointing at the minted
/// 512 MiB `zfs.img`. Confirms the L0 label parsed from the full image matches
/// the committed slice, and that all four labels decode consistently.
#[test]
fn full_image_all_four_labels_agree() {
    let Ok(path) = std::env::var("ZFS_ORACLE_IMG") else {
        eprintln!("skipping: set ZFS_ORACLE_IMG to the minted zfs.img to run");
        return;
    };
    let img = std::fs::read(&path).expect("read ZFS_ORACLE_IMG");
    let (front, back) = zfs_core::label_offsets(img.len() as u64);
    let back = back.expect("512 MiB image has back labels");
    let mut txgs = Vec::new();
    for off in front.into_iter().chain(back) {
        let off = off as usize;
        let label = VdevLabel::parse(&img[off..off + zfs_core::LABEL_SIZE]).unwrap();
        assert_eq!(label.config.get_str("name"), Some("tpool"));
        assert_eq!(
            label.config.get_u64("pool_guid"),
            Some(11_379_600_771_744_596_893)
        );
        txgs.push(label.active_uberblock.txg);
    }
    // All four labels root the same active txg.
    assert!(
        txgs.iter().all(|&t| t == 22),
        "labels agree on active txg 22: {txgs:?}"
    );
}
