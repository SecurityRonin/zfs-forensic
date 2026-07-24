# 2. Two-crate reader/analyzer split (`core/` + `forensic/`)

Date: 2026-07-24
Status: Accepted

## Context

The fleet Crate-structure standard (`ronin-issen/CLAUDE.md`) mandates that every
single-format repo be **Pattern A**: exactly two crates in one workspace — a
`<x>-core` reader that exposes valid-path navigation and no findings, and a
`<x>-forensic` analyzer that emits graded `forensicnomicon::report::Finding`s.

ZFS fits Pattern A: one on-disk format, one reader, one auditor. The workspace
declares `members = ["core", "forensic"]` (`Cargo.toml`).

A tension the standard anticipates: a forensic auditor often needs to see raw
structure a happy-path reader deliberately hides. ZFS makes this concrete — the
audit must verify each reachable block-pointer's checksum against the block it
points at (structure a reader trusts and discards) and walk the DSL bonus /
snapshot chain to recover pre-delete state from earlier snapshots.

## Decision

Split into two crates:

- **`core/` → `zfs-forensic-core`** (import path `zfs_core`) — the reader: vdev
  labels, XDR nvlist config, endian-adaptive uberblock ring, block-pointer tree,
  dnodes/objsets, ZAP, DSL, ZPL/SA file resolution. No findings.
  (`core/src/lib.rs`.)
- **`forensic/` → `zfs-forensic`** — the auditor: `AnomalyKind`/`Anomaly` +
  `audit_image`/`audit_findings` producing graded `report::Finding`s, plus
  `recover_deleted` CoW carving (`forensic/src/lib.rs`).

`zfs-forensic` depends on `zfs-core` **by default** but is not confined to its
happy-path API: where the audit must see what the reader normalizes away it drops
to the low-level accessors — `active_uberblock`, `dsl_dataset_prev_snap`,
`dsl_dataset_bp` — directly (`forensic/src/lib.rs` module docs, lines 22–25).
This is the standard's binding principle: *build `-forensic` on `-core` when the
API exposes what the audit needs; go lower when it doesn't.*

## Consequences

- Third-party developers can link the lean `zfs-forensic-core` reader for
  navigation alone, without pulling the analyzer or `forensicnomicon`.
- The auditor sees raw structure (per-block-pointer checksums, the snapshot
  chain) the reader hides, so anomaly detection is not contorted through a
  valid-only API.
- The repo is named `zfs-forensic` (analyzer is the headline) even though it also
  holds the core crate — per the naming grammar.
- Versioning is independent: `core` and `forensic` each carry their own
  `version` inline (not hoisted), so a reader-only change does not force an
  analyzer bump (`Cargo.toml` comment).
