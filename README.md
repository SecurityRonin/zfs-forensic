# zfs-forensic

[![zfs-forensic-core](https://img.shields.io/crates/v/zfs-forensic-core.svg?label=zfs-forensic-core)](https://crates.io/crates/zfs-forensic-core)
[![zfs-forensic](https://img.shields.io/crates/v/zfs-forensic.svg?label=zfs-forensic)](https://crates.io/crates/zfs-forensic)
[![Docs.rs](https://img.shields.io/docsrs/zfs-forensic?label=docs.rs)](https://docs.rs/zfs-forensic)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/zfs-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/zfs-forensic/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20lines-brightgreen.svg)](https://securityronin.github.io/zfs-forensic/validation/)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Security audit](https://img.shields.io/badge/security-cargo--deny-brightgreen.svg)](deny.toml)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://securityronin.github.io/zfs-forensic/)

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

`audit_findings` parses the L0 vdev label, verifies the active uberblock's `ub_rootbp` checksum against the MOS block, reconciles the four vdev labels, and sweeps the reachable metadata tree — all in place. A structurally invalid image yields no findings, never a panic. For the typed form, `audit_image(&image)` returns `Vec<Anomaly>`; each `anomaly.to_finding(source)` converts to a `report::Finding`.

## The anomaly codes

Each finding is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | What it observes |
|---|---|---|
| `ZFS-UBERBLOCK-CHECKSUM-MISMATCH` | High | The active uberblock's `ub_rootbp` checksum does not verify against the MOS block it points at — the top-of-tree Merkle check failing, consistent with corruption or post-write tampering of the pool root |
| `ZFS-LABEL-DIVERGENCE` | High | The four vdev labels disagree on `pool_guid` / `ashift` (or one fails to parse in an otherwise well-formed vdev) — consistent with a torn or spliced label |
| `ZFS-BLKPTR-CHECKSUM-MISMATCH` | High | A reachable metadata block whose blkptr checksum does not verify — a dead, corrupt, or tampered block, distinct from the rootbp check |
| `ZFS-IMPOSSIBLE-GEOMETRY` | High | A size / count / offset field beyond what the image can hold — an allocation-bomb / corruption guard |

Deleted-file recovery is separate: `recover_deleted(&image)` walks the DSL snapshot chain, reads each snapshot's ZPL root directory, diffs it against the live filesystem's root, and carves each file present in a snapshot but absent live from the snapshot's pinned blocks — returning each `RecoveredFile` (`ZFS-DELETED-FILE-CARVED`: path, source snapshot, inode, size, content, and the content's sha256 recovery gate).

## The reader: navigate a pool

`zfs-forensic-core` (imported as `zfs_core`) reads a ZFS pool over any byte slice:

```rust
use zfs_core::{VdevLabel, read_block};

// The L0 vdev label lives at physical offset 0; its active uberblock's rootbp
// points at the MOS objset block.
let label = VdevLabel::parse(&image[..zfs_core::LABEL_SIZE])?;
let rootbp = label.active_uberblock.rootbp_full();
let mos = read_block(&image, &rootbp)?; // fletcher4-checked, decompressed
# Ok::<(), zfs_core::ZfsError>(())
```

The bare crate name `zfs` (an abandoned 2016 stub) and `zfs-core` (a libzfs_core FFI wrapper) are both taken on crates.io, so this on-disk reader publishes as `zfs-forensic-core` with `[lib] name = "zfs_core"` — consumers still write `use zfs_core::…`.

## What makes this different from a general-purpose ZFS crate

Most ZFS tooling answers "what files are on this pool?" This workspace answers the questions a digital forensics examiner needs:

| Capability | General-purpose ZFS reader | this workspace |
|---|---|---|
| Vdev label + XDR nvlist config bootstrap | ✅ | ✅ |
| Endian-adaptive uberblock ring (active = highest txg) | ✅ | ✅ |
| Block-pointer tree navigation + fletcher4 / SHA-256 checksums | ✅ | ✅ |
| LZ4 / gzip / zstd extent decompression | partial | ✅ |
| Dnodes / objsets / ZAP (micro + fat) / DSL / ZPL / SA | ✅ | ✅ |
| Uberblock-rootbp checksum verification (top-of-tree Merkle) | — | ✅ |
| Four-label divergence detection (torn / spliced label tell) | — | ✅ |
| Reachable-tree blkptr checksum sweep | — | ✅ |
| CoW deleted-file recovery from a snapshot's pinned blocks | — | ✅ |
| Impossible-geometry / allocation-bomb guards | — | ✅ |
| Severity-graded `report::Finding` output | — | ✅ |
| `#![forbid(unsafe_code)]` (our own code) | — | ✅ |

## Trust but verify

- **`#![forbid(unsafe_code)]`** in both crates — no `unsafe` in our source. (The batteries-included `zstd` extent decoder links libzstd's C, so the reader is not a `#![no_std]` / pure-Rust build; every ZFS-parsing line is our own safe Rust.)
- **Panic-free** — every integer / length / offset field is read through bounds-checked helpers; nvlist length / count fields are capped against allocation bombs; a malformed image degrades to an empty or typed result, never a panic.
- **Fuzzed** — one `cargo-fuzz` target per parsed structure (`label`, `uberblock`, `blkptr`, `dnode`, `zap`, `dsl`, `sa`, `read_block`) plus a `fuzz_forensic` target driving the full `audit_image` / `recover_deleted` pipeline. `fuzz.yml` builds every target on each push and deep-fuzzes each for 10 minutes weekly.
- **Tier-1 validated (bootstrap layer)** — the vdev label + nvlist config + uberblock reader is checked against the OpenZFS project's own `zol-0.6.1` reference pool (`openzfs/zfs-images`), a third-party artifact whose ground truth comes from `zdb -l` / `zdb -u`, a wholly separate implementation.
- **Tier-2 validated (DMU / ZAP / ZPL / SA / file + carve layers)** — reading those layers on the raidz `zol-0.6.1` pool needs RAIDZ parity reconstruction, which this reader defers; they are validated against a single-vdev self-mint pool with `zdb` as the independent oracle. See [`docs/validation.md`](https://securityronin.github.io/zfs-forensic/validation/).

## Reader API (`zfs-forensic-core`)

| Item | Purpose |
|---|---|
| `VdevLabel::parse` | Four-label geometry, XDR nvlist config, active uberblock |
| `nvlist_parse` / `NvList` | Standalone packed-XDR nvlist decode (`get_u64` / `get_str` / `vdev_tree`) |
| `Uberblock::parse` / `uberblock_parse` | Endian-adaptive uberblock slot decode + `rootbp_full` |
| `Blkptr::parse` / `read_block` | Block-pointer decode; DVA read + checksum-verify + decompress |
| `Dnode::parse` / `ObjsetPhys::parse` / `mos_dnode` | Dnode / objset decode; MOS object lookup |
| `zap_list` / `zap_lookup` / `read_zap_object` | Micro- and fat-ZAP entry enumeration / lookup |
| `dsl_dir_head_dataset` / `dsl_dataset_prev_snap` / `dsl_dataset_bp` | DSL directory / dataset / snapshot-chain accessors |
| `zpl_list_dir` / `zpl_read_file` / `decode_sa_bonus` | ZPL directory / file-content read; SA / znode metadata |
| `checksum::{fletcher4, sha256, verify}` / `compress::decompress` | Block checksum + LZ4 / gzip / zstd decompression |

---

[Privacy Policy](https://securityronin.github.io/zfs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/zfs-forensic/terms/) · © 2026 Security Ronin Ltd
