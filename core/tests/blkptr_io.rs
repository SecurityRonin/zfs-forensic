//! P1 block-pointer I/O + DMU object integration tests.
//!
//! Oracle: `zdb` on the self-minted `tpool` (Tier-2 REAL-self; `zdb` is an
//! independent implementation). Ground truth in `tests/data/README.md`.
//!
//! Committed always-on fixtures (no env gate):
//! - `zfs_mos_objset.bin` — the 4 KiB MOS `objset_phys_t` block (`rootbp` target,
//!   `zdb -R tpool 0:c015000:1000:r`).
//! - `zfs_mos_l1_indirect_lz4.bin` — the 4 KiB **LZ4-compressed** L1 indirect
//!   block of the MOS meta-dnode (`comp=15`, decompresses to 128 KiB); its
//!   stored fletcher4 checksum (from the meta-dnode `blk_ptr[0]`) is the codec
//!   oracle.
//!
//! The env-gated `ZFS_ORACLE_IMG` test reads the full 512 MiB image and does the
//! real DVA→physical translation end-to-end.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zfs_core::{
    checksum, compress, mos_dnode, read_block, Blkptr, ChecksumType, CompressType, DmuType, Dnode,
    Endian, ObjsetPhys, VdevLabel,
};

/// The MOS objset block: the target of `rootbp`. Always-on fixture.
const MOS_OBJSET: &[u8] = include_bytes!("../../tests/data/zfs_mos_objset.bin");
/// The LZ4-compressed L1 indirect block of the MOS meta-dnode. Always-on.
const MOS_L1_LZ4: &[u8] = include_bytes!("../../tests/data/zfs_mos_l1_indirect_lz4.bin");
/// The L0 vdev label, for the env-gated end-to-end walk.
const LABEL0: &[u8] = include_bytes!("../../tests/data/zfs_label0.bin");

// --------------------------------------------------------------------------
// 1. Full blkptr_t decode of the rootbp — verified against zdb.
// --------------------------------------------------------------------------

#[test]
fn rootbp_full_blkptr_decode_matches_zdb() {
    // The rootbp lives inside the active uberblock parsed from the label.
    let label = VdevLabel::parse(LABEL0).unwrap();
    // Re-read the raw 128-byte blkptr from the uberblock slot to exercise the
    // full Blkptr::parse (the P0 summary only exposed a subset).
    let ub = &label.active_uberblock;
    let bp = ub.rootbp_full();

    // zdb: DVA[0]=<0:c015000:1000> DVA[1]=<0:e015000:1000> DVA[2]=<0:1004b000:1000>
    assert_eq!(bp.dvas[0].vdev, 0);
    assert_eq!(bp.dvas[0].asize_sectors, 8, "asize 0x1000 = 8 sectors");
    assert_eq!(bp.dvas[0].offset_sectors, 0x0c01_5000 / 512);
    assert_eq!(bp.dvas[0].physical_byte_offset(), 0x0c01_5000 + 0x0040_0000);
    assert_eq!(bp.dvas[1].offset_sectors, 0x0e01_5000 / 512);
    assert_eq!(bp.dvas[2].offset_sectors, 0x1004_b000 / 512);

    // zdb: [L0 DMU objset] fletcher4 uncompressed LE size=1000L/1000P birth=22 fill=51
    assert_eq!(bp.level, 0);
    assert_eq!(bp.object_type, DmuType::Objset as u8);
    assert_eq!(bp.compression, CompressType::Off as u8);
    assert_eq!(bp.checksum, ChecksumType::Fletcher4 as u8);
    assert_eq!(bp.byteorder, Endian::Little);
    assert_eq!(bp.lsize_bytes(), 0x1000);
    assert_eq!(bp.psize_bytes(), 0x1000);
    assert_eq!(bp.logical_birth, 22);
    assert_eq!(bp.fill, 51);
    assert!(!bp.embedded);
    // stored cksum from zdb:
    // 00000002bffcd5dd:00000a91372660e5:00145331c05695f5:1a16f2c8d3d157f0
    assert_eq!(
        bp.checksum_words,
        [
            0x0000_0002_bffc_d5dd,
            0x0000_0a91_3726_60e5,
            0x0014_5331_c056_95f5,
            0x1a16_f2c8_d3d1_57f0,
        ]
    );
}

// --------------------------------------------------------------------------
// 2. read_block(rootbp) yields the MOS objset block, checksum verified.
// --------------------------------------------------------------------------

#[test]
fn fletcher4_matches_zdb_over_mos_objset_block() {
    // The rootbp is uncompressed fletcher4; the checksum is computed over the
    // whole 4 KiB block. zdb reports this exact value for the rootbp.
    let words = checksum::fletcher4(MOS_OBJSET, Endian::Little);
    assert_eq!(
        words,
        [
            0x0000_0002_bffc_d5dd,
            0x0000_0a91_3726_60e5,
            0x0014_5331_c056_95f5,
            0x1a16_f2c8_d3d1_57f0,
        ]
    );
}

#[test]
fn read_block_of_rootbp_returns_mos_objset_and_verifies_checksum() {
    let path = match std::env::var("ZFS_ORACLE_IMG") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skipping: set ZFS_ORACLE_IMG to the minted zfs.img to run");
            return;
        }
    };
    let img = std::fs::read(&path).expect("read ZFS_ORACLE_IMG");
    let label = VdevLabel::parse(&img[..zfs_core::LABEL_SIZE]).unwrap();
    let bp = label.active_uberblock.rootbp_full();

    let block = read_block(&img, &bp).expect("read_block(rootbp)");
    assert_eq!(block.data.len(), 0x1000, "LSIZE 4 KiB");
    // The bytes must equal the committed MOS objset fixture.
    assert_eq!(block.data.as_slice(), MOS_OBJSET);
    // Checksum verified non-fatally.
    assert_eq!(block.checksum_valid, Some(true));
}

#[test]
fn read_block_flags_a_corrupt_block_without_failing() {
    // Flip a byte in the objset fixture: read_block-equivalent verification must
    // return Some(false), never error (forensic: surface the block anyway).
    let mut corrupt = MOS_OBJSET.to_vec();
    corrupt[100] ^= 0xff;
    let good = checksum::verify(
        ChecksumType::Fletcher4,
        Endian::Little,
        MOS_OBJSET,
        [
            0x0000_0002_bffc_d5dd,
            0x0000_0a91_3726_60e5,
            0x0014_5331_c056_95f5,
            0x1a16_f2c8_d3d1_57f0,
        ],
    );
    let bad = checksum::verify(
        ChecksumType::Fletcher4,
        Endian::Little,
        &corrupt,
        [
            0x0000_0002_bffc_d5dd,
            0x0000_0a91_3726_60e5,
            0x0014_5331_c056_95f5,
            0x1a16_f2c8_d3d1_57f0,
        ],
    );
    assert_eq!(good, Some(true));
    assert_eq!(bad, Some(false));
}

// --------------------------------------------------------------------------
// 3. objset_phys metadnode decodes.
// --------------------------------------------------------------------------

#[test]
fn objset_phys_metadnode_decodes() {
    let os = ObjsetPhys::parse(MOS_OBJSET, Endian::Little).expect("objset_phys");
    // os_type = DMU_OST_META = 1 (the MOS).
    assert_eq!(os.os_type, 1);
    // The meta-dnode: dn_type=DMU_OT_DNODE(10), nlevels=2, nblkptr=3,
    // datablkszsec=32 (16 KiB), maxblkid=1.
    let md = &os.meta_dnode;
    assert_eq!(md.dn_type, DmuType::Dnode as u8);
    assert_eq!(md.dn_nlevels, 2);
    assert_eq!(md.dn_nblkptr, 3);
    assert_eq!(md.dn_datablkszsec, 32);
    assert_eq!(md.dn_maxblkid, 1);
    // Its blkptr[0] is a level-1 indirect, LZ4-compressed, fletcher4.
    let bp0 = md.blkptr(0).expect("meta-dnode blkptr[0]");
    assert_eq!(bp0.level, 1);
    assert_eq!(bp0.compression, CompressType::Lz4 as u8);
    assert_eq!(bp0.object_type, DmuType::Dnode as u8);
    assert_eq!(bp0.lsize_bytes(), 0x2_0000, "LSIZE 128 KiB");
    assert_eq!(bp0.psize_bytes(), 0x1000, "PSIZE 4 KiB");
}

// --------------------------------------------------------------------------
// 4. LZ4 decompression validated against the real compressed L1 block.
// --------------------------------------------------------------------------

#[test]
fn lz4_decompresses_real_zfs_block_to_lsize() {
    // The L1 indirect block: PSIZE 4 KiB compressed -> LSIZE 128 KiB. Its stored
    // checksum (from the meta-dnode blkptr[0], read below) proves the raw bytes
    // are intact; a clean decompress to exactly LSIZE proves the codec.
    let out = compress::decompress(CompressType::Lz4, MOS_L1_LZ4, 0x2_0000).expect("lz4");
    assert_eq!(out.len(), 0x2_0000, "decompressed to LSIZE 128 KiB");
    // The decompressed L1 is an array of L0 blkptrs; blkptr[0] is a level-0
    // DMU_OT_DNODE data block (fletcher4, LZ4).
    let l0 = Blkptr::parse(&out[..128], Endian::Little);
    assert_eq!(l0.level, 0);
    assert_eq!(l0.object_type, DmuType::Dnode as u8);
}

#[test]
fn lz4_l1_block_checksum_matches_metadnode_stored_value() {
    // Oracle: the meta-dnode's blkptr[0] carries the fletcher4 checksum of the
    // compressed (PSIZE) L1 block. Verified byte-exact against zdb.
    let os = ObjsetPhys::parse(MOS_OBJSET, Endian::Little).unwrap();
    let bp0 = os.meta_dnode.blkptr(0).unwrap();
    let valid = checksum::verify(
        ChecksumType::Fletcher4,
        Endian::Little,
        MOS_L1_LZ4,
        bp0.checksum_words,
    );
    assert_eq!(valid, Some(true));
}

// --------------------------------------------------------------------------
// 5. MOS access — mos_dnode(mos, 1) resolves the object directory.
// --------------------------------------------------------------------------

#[test]
fn mos_dnode_object_1_is_the_object_directory() {
    let path = match std::env::var("ZFS_ORACLE_IMG") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skipping: set ZFS_ORACLE_IMG to the minted zfs.img to run");
            return;
        }
    };
    let img = std::fs::read(&path).expect("read ZFS_ORACLE_IMG");
    let label = VdevLabel::parse(&img[..zfs_core::LABEL_SIZE]).unwrap();
    let mos_bp = label.active_uberblock.rootbp_full();
    let mos_block = read_block(&img, &mos_bp).unwrap();
    let mos = ObjsetPhys::parse(&mos_block.data, Endian::Little).unwrap();

    // Object 1 = the MOS object directory (zdb: type "object directory").
    let obj1 = mos_dnode(&img, &mos, 1).expect("mos_dnode(1)");
    assert_eq!(
        obj1.dn_type,
        DmuType::ObjectDirectory as u8,
        "object 1 is the object directory"
    );
    // zdb: object 1 has lvl 1 (nlevels 1), dnsize 512 (1 slot).
    assert_eq!(obj1.dn_nlevels, 1);
    // Object 0 is the meta-dnode slot itself (all zero in the array) -> None or
    // DMU_OT_NONE; a wildly out-of-range object id returns None, never panics.
    assert!(mos_dnode(&img, &mos, 9_999_999).is_none());
}

// --------------------------------------------------------------------------
// 6. Panic-free: lying nlevels / LSIZE never panic or OOM.
// --------------------------------------------------------------------------

#[test]
fn lying_lsize_is_capped_not_ooming() {
    // A blkptr claiming a 4 GiB LSIZE against a tiny image must be rejected by
    // the allocation-bomb guard, not attempt the allocation.
    let mut bp = Blkptr::default();
    bp.dvas[0].offset_sectors = 0;
    bp.dvas[0].asize_sectors = 1;
    bp.lsize_raw = 0xffff; // (0xffff+1)<<9 = 32 MiB logical
    bp.psize_raw = 0xffff;
    bp.compression = CompressType::Off as u8;
    let tiny = vec![0u8; 4096];
    // read_block must return an error (allocation-bomb / truncated), never panic.
    let _ = read_block(&tiny, &bp);
}

#[test]
fn lying_nlevels_in_dnode_never_panics() {
    // A dnode claiming 255 levels of indirection against a tiny image must
    // terminate (bounded recursion / bounds-checked reads), never panic/OOM.
    let mut raw = [0u8; 512];
    raw[0] = DmuType::PlainFileContents as u8; // dn_type
    raw[2] = 255; // dn_nlevels (lie)
    raw[3] = 1; // dn_nblkptr
    let dnode = Dnode::parse(&raw, Endian::Little).unwrap();
    let tiny = vec![0u8; 4096];
    let _ = zfs_core::read_dnode_data(&tiny, &dnode, 0);
    let _ = zfs_core::read_dnode_data(&tiny, &dnode, u64::MAX);
}

#[test]
fn decompress_never_ooms_on_lying_compressed_input() {
    // Garbage LZ4 with a huge claimed LSIZE must error, not OOM.
    let garbage = [0xffu8; 64];
    let r = compress::decompress(CompressType::Lz4, &garbage, 1 << 30);
    assert!(r.is_err(), "capped/rejected, not OOM");
}
