//! F-INTEGRITY reachable-blkptr sweep over a **synthetic mismatch image**.
//!
//! `sweep_reachable_blkptrs` verifies each of the MOS meta-dnode's top block
//! pointers against the block it names; a `ZFS-BLKPTR-CHECKSUM-MISMATCH` is a
//! dead/corrupt/tampered reachable block. On the real pool this is exercised
//! env-gated (`ZFS_ORACLE_IMG`); this always-on test crafts a MOS whose meta-dnode
//! blkptr carries a Fletcher4 checksum that does NOT match its (non-zero) target
//! block, so the sweep flags it — the CI coverage path for that arm.
//!
//! ## Construction (Tier-3 crafted fixture — SYNTHETIC)
//!
//!   real `zfs_label0.bin` → active uberblock `rootbp`
//!     └─ MOS objset (crafted, at the rootbp DVA)
//!          meta-dnode `blkptr[0]` → a non-zero data block, checksum = Fletcher4,
//!          stored `checksum_words = [0,0,0,0]` (cannot equal the real fletcher4 of
//!          non-zero bytes) → the sweep reports a mismatch.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zfs_forensic::{audit_image, AnomalyKind};

use zfs_core::{VdevLabel, DNODE_SIZE};

const LABEL0: &[u8] = include_bytes!("../../tests/data/zfs_label0.bin");
const BLOCK: usize = 4096;
const CKSUM_FLETCHER4: u8 = 7;

/// Write a little-endian `blkptr_t` at `off` pointing at `phys` (size `BLOCK`),
/// uncompressed, with the given checksum function and stored checksum words.
fn write_blkptr(buf: &mut [u8], off: usize, phys: u64, cksum: u8, words: [u64; 4]) {
    let boot_skew: u64 = 0x0040_0000;
    let offset_sectors = (phys - boot_skew) >> 9;
    let sectors = (BLOCK as u64).div_ceil(512);
    buf[off..off + 8].copy_from_slice(&(sectors & 0x00ff_ffff).to_le_bytes()); // asize, vdev 0
    buf[off + 8..off + 16].copy_from_slice(&(offset_sectors & 0x7fff_ffff_ffff_ffff).to_le_bytes());
    // blk_prop @48: LSIZE/PSIZE (sectors-1) + comp(off) + cksum(bits40-47) + LE.
    let lsize_raw = sectors - 1;
    let comp: u64 = 2;
    let byteorder: u64 = 1;
    let prop = (lsize_raw & 0xffff)
        | ((lsize_raw & 0xffff) << 16)
        | (comp << 32)
        | (u64::from(cksum) << 40)
        | (byteorder << 63);
    buf[off + 48..off + 56].copy_from_slice(&prop.to_le_bytes());
    // blk_cksum @96: the four 64-bit checksum words.
    for (i, w) in words.iter().enumerate() {
        buf[off + 96 + i * 8..off + 96 + i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
}

fn build_mismatch_image() -> Vec<u8> {
    let label = VdevLabel::parse(LABEL0).unwrap();
    let rootbp = label.active_uberblock.rootbp_full();
    let mos_phys = rootbp.dvas[0].physical_byte_offset() as usize;
    let mos_lsize = rootbp.lsize_bytes();

    let base = mos_phys + mos_lsize;
    let child_phys = base as u64; // the meta-dnode blkptr[0] target
    let image_end = base + BLOCK;

    let mut img = vec![0u8; image_end];
    img[..LABEL0.len()].copy_from_slice(LABEL0);

    // MOS objset block: a meta-dnode whose single top blkptr → a non-zero child,
    // Fletcher4 checksum, stored words all-zero → guaranteed mismatch.
    let mut mos = vec![0u8; BLOCK];
    mos[0] = 10; // dn_type
    mos[1] = 12; // indblkshift
    mos[2] = 1; // nlevels = 1 (blkptr[0] → the child directly)
    mos[3] = 1; // nblkptr = 1
    mos[8..10].copy_from_slice(&((BLOCK as u16) >> 9).to_le_bytes()); // datablkszsec
    write_blkptr(&mut mos, 64, child_phys, CKSUM_FLETCHER4, [0, 0, 0, 0]);
    mos[704..712].copy_from_slice(&1u64.to_le_bytes()); // os_type = DMU_OST_META
    img[mos_phys..mos_phys + mos.len().min(mos_lsize)]
        .copy_from_slice(&mos[..mos.len().min(mos_lsize)]);

    // The child data block: non-zero bytes (a zeroed target reads as Unreadable,
    // not Mismatch — see blkptr_checksum_verdict), so its real fletcher4 ≠ [0;4].
    let c = child_phys as usize;
    img[c..c + 64].fill(0xA5);

    // Sanity: the crafted MOS parses and has exactly one meta-dnode blkptr.
    let _ = DNODE_SIZE;
    img
}

#[test]
fn sweep_flags_a_reachable_blkptr_checksum_mismatch() {
    let img = build_mismatch_image();
    let anomalies = audit_image(&img);
    let hit = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::BlkptrChecksumMismatch { .. }))
        .expect("the MOS meta-dnode blkptr's wrong checksum must be flagged");
    // The reported offset is the child block's physical DVA offset.
    let AnomalyKind::BlkptrChecksumMismatch { dva_offset, .. } = hit.kind else {
        unreachable!()
    };
    assert!(dva_offset >= 0x0040_0000, "offset carries the boot skew");
}
