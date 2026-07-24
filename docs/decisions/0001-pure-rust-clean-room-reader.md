# 1. Pure-Rust clean-room ZFS reader — reject libzpool FFI and CDDL source

Date: 2026-07-24
Status: Accepted

## Context

ZFS is the hardest mainstream filesystem to parse read-only. Reading one file by
path traverses ~9 chained object layers (label → nvlist → uberblock → MOS →
object directory → DSL → dataset objset → ZPL → dnode → blkptr → DVA → data),
each with its own encoding, checksum verification, and compression
(`docs/RESEARCH.md` §1, §4).

The Research-First survey (`docs/RESEARCH.md` §2) found nothing reusable as a
pure on-disk reader in Rust: `rzfs_lib` is a yanked `0.0.0` placeholder, the
2016 `zfs` crate is abandoned, and `zfs-rs`/`libzetta`/`zfs-core-sys` are all
live FFI wrappers around a running system's `libzfs` (admin tooling, useless on a
dead-box image). The Sleuth Kit does not support ZFS at all — pooled storage
breaks its one-filesystem-per-volume model.

Two build strategies were available for the core reader:

1. **Bind OpenZFS `libzpool`** (what `zdb`/`ztest` link) via FFI, reusing the
   reference codecs and traversal.
2. **Clean-room reimplement** in pure Rust from the OpenZFS headers
   (`include/sys/spa.h`, `uberblock_impl.h`, `dnode.h`, …) and the 2006 Sun
   "ZFS On-Disk Specification," with `zdb` as the correctness oracle.

`libzpool` is CDDL-1.0 (GPL-incompatible, file-level copyleft), a large C tree,
and would break three standing fleet properties: `forbid(unsafe)`, a single
static binary with no C toolchain, and Apache-2.0 licensing.

## Decision

Build `zfs-core` as a **pure-Rust, clean-room** on-disk reader from the OpenZFS
headers and the Sun spec (never copying CDDL source), with `zdb` and a live
read-only kernel `zfs mount` as independent oracles (`docs/RESEARCH.md` §2–3;
`docs/validation.md`). No `libzpool` FFI in the core, now or as a default path.

The risky codecs are the one place we reuse the ecosystem rather than reinvent:
fletcher4 (~30 lines, trivial) and SHA-256 (`sha2`) for checksums; `lz4_flex`,
`flate2`, and `ruzstd` for decompression — all pure Rust, all oracle-checkable
against `zdb -R :d` (the LZNT1-trap discipline: never validate a codec by
self-round-trip).

## Consequences

- The reader ships as a single static binary with no C bindings and stays
  `#![forbid(unsafe_code)]` (see ADR 0004), matching the fleet field-deployability
  promise (an examiner cannot `cargo build --features` on an evidence
  workstation).
- No `libzpool`/CDDL code enters the tree, so the workspace is cleanly
  Apache-2.0.
- We own the full parser surface — the cost the survey estimated at 3–5× an ext4
  reader for the single-vdev MVP, 5–8× with RAIDZ. That scope is bounded
  deliberately (ADR 0008): RAIDZ, dedup, and native encryption are deferred.
- Any future RAIDZ/encryption work that genuinely needs `libzpool` would be an
  explicitly-marked, `publish = false` module — never the core.
