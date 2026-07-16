# zfs-forensic

**A from-scratch ZFS on-disk reader and a graded anomaly auditor — walk the vdev labels, uberblock ring, MOS, DMU dnodes, ZAP, and ZPL of a ZFS pool over any byte source, then turn its copy-on-write, self-checksumming Merkle structure into evidence: torn vdev labels, uberblock-rootbp checksum mismatches, dead metadata blocks, and files still carvable from a snapshot after they were deleted live.**

Two crates, one workspace:

- **[`zfs-forensic-core`](https://crates.io/crates/zfs-forensic-core)** (imported as `zfs_core`) — the reader: four-label + XDR nvlist config bootstrap, endian-adaptive uberblock ring, block-pointer tree navigation with fletcher4 / SHA-256 checksums and LZ4 / gzip / zstd decompression, dnodes / objsets, ZAP (micro + fat), DSL datasets, and ZPL / SA file resolution — over any byte slice. `#![forbid(unsafe_code)]`.
- **[`zfs-forensic`](https://crates.io/crates/zfs-forensic)** — the auditor: turns parsed ZFS structures into severity-graded [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s, and carves CoW-deleted files from snapshots, so a ZFS pool's anomalies aggregate uniformly with the partition and container layers.

## Audit a ZFS image in 30 seconds

```toml
[dependencies]
zfs-forensic = "0.1"   # pulls in zfs-forensic-core
```

```rust
use zfs_forensic::audit_findings;

// Feed it the raw pool bytes; get back graded findings.
for finding in audit_findings(&image_bytes, "zfs") {
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // e.g. [Some(High)] ZFS-UBERBLOCK-CHECKSUM-MISMATCH — active uberblock (txg 22 …
}
```

`audit_findings` parses the L0 vdev label, verifies the active uberblock's `ub_rootbp` checksum against the MOS block, reconciles the four vdev labels, and sweeps the reachable metadata tree — all in place. A structurally invalid image yields no findings, never a panic.

## The anomaly codes

Each finding is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | What it observes |
|---|---|---|
| `ZFS-UBERBLOCK-CHECKSUM-MISMATCH` | High | The active uberblock's `ub_rootbp` checksum does not verify against the MOS block it points at — the top-of-tree Merkle check failing |
| `ZFS-LABEL-DIVERGENCE` | High | The four vdev labels disagree on `pool_guid` / `ashift` (or one fails to parse in an otherwise well-formed vdev) — a torn or spliced label |
| `ZFS-BLKPTR-CHECKSUM-MISMATCH` | High | A reachable metadata block whose blkptr checksum does not verify — a dead, corrupt, or tampered block |
| `ZFS-IMPOSSIBLE-GEOMETRY` | High | A size / count / offset field beyond what the image can hold — an allocation-bomb / corruption guard |

Deleted-file recovery is separate: `recover_deleted(&image)` walks the DSL snapshot chain, reads each snapshot's ZPL root directory, diffs it against the live root, and carves each file present in a snapshot but absent live from the snapshot's pinned blocks (`ZFS-DELETED-FILE-CARVED`: path, source snapshot, inode, size, content, and the content's sha256 recovery gate).

## The reader: navigate a pool

`zfs-forensic-core` (imported as `zfs_core`) reads a ZFS pool over any byte slice:

```rust
use zfs_core::{VdevLabel, read_block};

let label = VdevLabel::parse(&image[..zfs_core::LABEL_SIZE])?;
let rootbp = label.active_uberblock.rootbp_full();
let mos = read_block(&image, &rootbp)?; // fletcher4-checked, decompressed
# Ok::<(), zfs_core::ZfsError>(())
```

The bare crate names `zfs` and `zfs-core` are both taken on crates.io, so this on-disk reader publishes as `zfs-forensic-core` with `[lib] name = "zfs_core"` — consumers still write `use zfs_core::…`.

## Trust but verify

- **`#![forbid(unsafe_code)]`** in both crates — no `unsafe` in our source. (The batteries-included `zstd` extent decoder links libzstd's C; every ZFS-parsing line is our own safe Rust.)
- **Panic-free** — bounds-checked reads throughout; nvlist length / count fields capped against allocation bombs; malformed input degrades to an empty / typed result, never a panic.
- **Fuzzed** — one `cargo-fuzz` target per parsed structure (`label`, `uberblock`, `blkptr`, `dnode`, `zap`, `dsl`, `sa`, `read_block`) plus a `fuzz_forensic` target driving the full `audit_image` / `recover_deleted` pipeline. See [Validation](validation.md).
- **Tier-1 validated (bootstrap)** — the vdev label / nvlist / uberblock reader is checked against the OpenZFS project's own `zol-0.6.1` reference pool, with `zdb` as the independent oracle; the DMU / file / carve layers are Tier-2 against a single-vdev self-mint (RAIDZ reconstruction deferred). See [Validation](validation.md).

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd.
