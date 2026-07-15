//! F-CARVE — `CoW` deleted-file recovery integration tests.
//!
//! ZFS is copy-on-write: a **snapshot** pins the pre-delete state of a dataset,
//! so a file deleted from the live filesystem survives, byte-for-byte, in the
//! snapshot's ZPL objset. [`recover_deleted`] enumerates the datasets (walking
//! the DSL snapshot chain), reads each snapshot's ZPL root, diffs it against the
//! live root, and carves any file present in the snapshot but absent live.
//!
//! Oracle (Tier-2 REAL-self; `zdb` is the independent implementation): the
//! self-minted `dtpool` snapshot-deletion pool. `/secret.txt` (object 2, 36
//! bytes, sha256 `312799a1…`) was written, `dtpool@snap1` taken, then the file
//! `rm`'d and synced. `zdb -dddddd dtpool@snap1` confirms the snapshot's root
//! dir still lists `secret.txt = 2` while live `dtpool` lists only `keep.txt`.
//! The full 256 MiB image is gitignored and env-gated via `ZFS_SNAP_ORACLE_IMG`;
//! the test skips cleanly when it is unset. See `tests/data/README.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zfs_forensic::recover_deleted;

/// The pre-delete sha256 of `/secret.txt` recorded at mint time (the recovery
/// gate). Ground truth: `sha256sum /dtpool/secret.txt` before `rm`.
const SECRET_SHA256: &str = "312799a19921d2f13936c837d165496afa8775be3dd1967e9128e4e41f5c7bcd";

fn load_snap_image() -> Option<Vec<u8>> {
    let path = std::env::var("ZFS_SNAP_ORACLE_IMG").ok()?;
    std::fs::read(path).ok()
}

#[test]
fn snapshot_recovers_deleted_file_with_matching_sha256() {
    let Some(img) = load_snap_image() else {
        eprintln!("ZFS_SNAP_ORACLE_IMG unset — skipping snapshot deleted-file recovery");
        return;
    };
    let recovered = recover_deleted(&img);

    let secret = recovered
        .iter()
        .find(|r| r.path == "secret.txt")
        .expect("the deleted /secret.txt must be recovered from dtpool@snap1");

    // The recovery gate: the carved content's sha256 equals the pre-delete hash.
    assert_eq!(
        secret.content_sha256, SECRET_SHA256,
        "carved content sha256 must equal the pre-delete ground-truth hash"
    );
    assert_eq!(
        secret.size, 36,
        "logical size from the snapshot's SA metadata"
    );
    assert_eq!(secret.content.len(), 36);
    // The recovery source names the snapshot the file came from.
    assert!(
        secret.source.contains("snap"),
        "source should name the snapshot: {}",
        secret.source
    );
}

#[test]
fn live_present_file_is_not_reported_as_deleted() {
    let Some(img) = load_snap_image() else {
        return;
    };
    let recovered = recover_deleted(&img);
    // keep.txt is present in BOTH the snapshot and the live filesystem, so it was
    // not deleted and must not appear.
    assert!(
        !recovered.iter().any(|r| r.path == "keep.txt"),
        "a file still present live must not be reported as deleted"
    );
}

#[test]
fn pool_without_snapshots_recovers_nothing() {
    // The P0-P3 `tpool` image (ZFS_ORACLE_IMG) has no snapshots, so the DSL
    // snapshot chain (ds_prev_snap_obj) is empty and recovery finds nothing —
    // exercising the full happy path through an empty snapshot chain rather than
    // fabricating a recovery.
    let Ok(path) = std::env::var("ZFS_ORACLE_IMG") else {
        return;
    };
    let Ok(img) = std::fs::read(path) else {
        return;
    };
    assert!(
        recover_deleted(&img).is_empty(),
        "a pool with no snapshots must recover nothing"
    );
}

#[test]
fn malformed_image_recovers_nothing_without_panicking() {
    // A non-ZFS / truncated image yields nothing rather than fabricating or
    // panicking.
    assert!(recover_deleted(&[]).is_empty());
    assert!(recover_deleted(&[0u8; 4096]).is_empty());
    assert!(recover_deleted(&vec![0xffu8; 512 * 1024]).is_empty());
}
