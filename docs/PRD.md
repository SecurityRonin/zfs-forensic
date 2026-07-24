# zfs-forensic — Design & Scope

This is a **library** repo (two crates a developer links, not a binary an
examiner runs), so this is a design/scope document, not a PRD. It records what
the crates are for, where their boundaries sit, and how correctness is
established. The load-bearing decisions behind them live in
[`docs/decisions/`](decisions/).

## Purpose

Read a ZFS pool from a dead-box evidence image, over any byte source, in pure
Rust — and turn its copy-on-write, self-checksumming Merkle structure into
graded forensic findings. Nothing production-grade existed to reuse: the Sleuth
Kit does not support ZFS (pooled storage breaks its one-filesystem-per-volume
model), and every Rust "zfs" crate on crates.io is either a yanked stub or a
live-system `libzfs` FFI wrapper useless on a dead box
([RESEARCH.md](RESEARCH.md); ADR 0001).

Two crates, one workspace ([`Cargo.toml`](../Cargo.toml)):

- **`zfs-forensic-core`** (import path `zfs_core`) — the reader. Bootstraps a
  pool from its four vdev labels + XDR nvlist config, selects the active
  uberblock from the endian-adaptive ring, and navigates the block-pointer tree
  (fletcher4/SHA-256 checksums, LZ4/gzip/zstd decompression) down through dnodes,
  objsets, ZAP, DSL datasets, and ZPL/SA file resolution. No findings.
- **`zfs-forensic`** — the auditor. Converts parsed ZFS structures into
  severity-graded [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s
  and carves CoW-deleted files from snapshots (ADR 0002, ADR 0008).

## Who links these

- **Fleet orchestration** (Issen / `disk-forensic` / the VFS abstraction) — to
  add ZFS to the set of filesystems whose anomalies aggregate into one `Report`.
- **Rust developers** needing a read-only, pure-Rust ZFS on-disk reader with no C
  toolchain — `zfs-forensic-core` links standalone for navigation without the
  analyzer or `forensicnomicon`.

## What it does

- **Bootstrap** — four-label geometry, XDR-packed nvlist config
  (`pool_guid`/`ashift`/`vdev_tree`), endian-adaptive uberblock ring (active =
  highest valid `txg`), exposing `ub_rootbp` → MOS.
- **Block I/O** — block-pointer decode, DVA → physical translation
  (`(offset << 9) + 0x400000`), checksum verify (fletcher4 / SHA-256),
  decompression (LZ4 / gzip / zstd) — all in place, bounds-checked (ADR 0006).
- **Object layer** — dnodes, objsets, micro- and fat-ZAP, DSL directories /
  datasets / snapshot chains, ZPL directory + file-content read, SA/znode
  metadata.
- **F-INTEGRITY** — graded findings: `ZFS-UBERBLOCK-CHECKSUM-MISMATCH`,
  `ZFS-LABEL-DIVERGENCE`, `ZFS-BLKPTR-CHECKSUM-MISMATCH`,
  `ZFS-IMPOSSIBLE-GEOMETRY`.
- **F-CARVE** — `recover_deleted` diffs each snapshot's ZPL root against the live
  filesystem and carves files deleted live but pinned in a snapshot
  (`ZFS-DELETED-FILE-CARVED`), each gated by a sha256 of the recovered content.

## Scope boundaries (non-goals)

- **Single `disk` vdev only in v1.** RAIDZ parity reconstruction, mirror /
  multi-vdev, dedup (DDT), and native encryption are each a multi-month project
  and are deferred (ADR 0001, ADR 0008). The reader targets single-vdev pools;
  reading a RAIDZ pool's *data* layers is out of scope until parity
  reconstruction lands.
- **Read-only.** No pool import, no write, no `zfs`-command semantics. The carver
  is a reconstructor that emits derived bytes, never touches the source image.
- **No findings in the reader.** `zfs-forensic-core` stays a valid-path reader;
  all grading lives in `zfs-forensic` (ADR 0002).
- **No legal conclusions.** Every finding is an observation ("consistent with
  …"); the examiner draws the conclusions.
- **No C toolchain / no `unsafe`.** Pure-Rust clean-room; `#![forbid(unsafe_code)]`
  in both crates (ADR 0001, 0004).

## Artifact family

ZFS on-disk structures: vdev labels, XDR nvlist configs, the uberblock ring, the
`blkptr_t` Merkle tree, dnodes/objsets, ZAP (micro + fat), DSL datasets and
snapshots, and ZPL/SA files — over any byte slice, endian-adaptive (little-endian
x86_64/aarch64 pools and big-endian SPARC pools alike; ADR 0005).

## Validation approach

Correctness is tiered by *who vouches for the ground truth* (Evidence-Based
Rigor); full detail in [`docs/validation.md`](validation.md):

- **Tier-1, full read path** — a vendor-authored FreeBSD 14.3 ZFS-root image
  (single `disk` vdev) carries the entire path (label → uberblock → MOS → DSL →
  ZPL → SA → file content). Recovered file bytes' sha256 matches two independent
  OpenZFS oracles: `zdb` and a live read-only kernel `zfs mount`.
- **Tier-1, bootstrap layer** — additionally checked against OpenZFS's own
  `zol-0.6.1` reference pool (`zdb -l` / `-u` as the third-party oracle).
- **Tier-2 regression corpus** — always-on byte-exact self-mint fixtures with
  `zdb` as the independent oracle, an under-the-Tier-1-gate CI backstop.
- **Fuzzed** — one `cargo-fuzz` target per parsed structure (`label`,
  `uberblock`, `blkptr`, `dnode`, `zap`, `dsl`, `sa`, `read_block`) plus a
  `fuzz_forensic` target over the full `audit_image` / `recover_deleted`
  pipeline.
- **Panic-free by lint** — `unwrap_used`/`expect_used = deny`, bounds-checked
  endian-adaptive readers that yield `0` out of range, nvlist length/count fields
  capped against allocation bombs.
