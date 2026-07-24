# 8. Forensic layer — graded `report::Finding` producer pattern, CoW snapshot carving, single-vdev validation scope

Date: 2026-07-24
Status: Accepted

## Context

The analyzer must fit the fleet reporting model so a ZFS pool's anomalies
aggregate uniformly with the partition and container layers instead of a bespoke
`ZfsAnalysis` type. The fleet producer pattern is: keep a typed domain
`AnomalyKind`, `impl forensicnomicon::report::Observation`, and expose
`audit_*` → `Vec<Anomaly>` plus `audit_findings` → `Vec<Finding>`. Codes are a
published contract (scheme-prefixed SCREAMING-KEBAB), and every finding is an
*observation* ("consistent with …"), never a legal conclusion.

ZFS's copy-on-write, self-checksumming Merkle structure with a ring of recent
pool roots is the forensic lever (`docs/RESEARCH.md`; `forensic/src/lib.rs`):

- **F-INTEGRITY** — the top-of-tree Merkle check (`ub_rootbp` vs the MOS block),
  four-label divergence (torn/spliced label tell), a reachable-tree blkptr
  checksum sweep, and impossible-geometry/allocation-bomb guards.
- **F-CARVE** — a file deleted from the live filesystem is often still intact in
  a snapshot's pinned, un-overwritten blocks (the Hilgert 2017 "reconstruct old
  trees" technique). This is CoW recovery, distinct from filesystem-journal
  carving.

Scope must be bounded: the Research-First survey ranked RAIDZ parity, dedup, and
native encryption each as its own multi-month project and recommended deferring
them all in v1. Correctness must be proven against an *independent* oracle, not
records we deleted ourselves.

## Decision

1. **Producer pattern.** `AnomalyKind` carries the evidence per variant;
   `severity()`/`code()`/`note()` are the single sources of truth
   (`forensic/src/lib.rs` lines 50–130). Four F-INTEGRITY codes are published and
   stable: `ZFS-UBERBLOCK-CHECKSUM-MISMATCH`, `ZFS-LABEL-DIVERGENCE`,
   `ZFS-BLKPTR-CHECKSUM-MISMATCH`, `ZFS-IMPOSSIBLE-GEOMETRY` (all `High`).
   `audit_findings(&bytes, source)` converts to `report::Finding`s; a structurally
   invalid image yields no findings, never a panic.
2. **F-CARVE.** `recover_deleted` walks the DSL snapshot chain, reads each
   snapshot's ZPL root, diffs it against the live root, and carves each file
   present in a snapshot but absent live from the snapshot's pinned blocks —
   returning each `RecoveredFile` under `ZFS-DELETED-FILE-CARVED` with a **sha256
   recovery gate** on the carved content (Doer-Checker: the recovered bytes are
   hashed to reconcile against ground truth).
3. **Single-vdev MVP scope.** RAIDZ parity reconstruction, dedup, and native
   encryption are deferred; the reader targets single-`disk`-vdev pools. This is
   validated honestly: the **full read path is Tier-1** against a vendor-authored
   FreeBSD 14.3 ZFS-root image (single vdev), with `zdb` *and* a live read-only
   kernel `zfs mount` as two independent OpenZFS oracles; the **bootstrap layer**
   is additionally Tier-1 against OpenZFS's own `zol-0.6.1` reference pool; and a
   Tier-2 self-mint corpus (`zdb` oracle) is the always-on CI regression backstop
   (`docs/validation.md`; git commits `71e6d8c`, `f512bfb`).

## Consequences

- ZFS findings render through the same `forensicnomicon::report` model as every
  other fleet analyzer — one aggregation, one UI.
- Reading the RAIDZ `zol-0.6.1` pool's *data* layers still needs parity
  reconstruction (deferred), so the FreeBSD single-vdev pool is what carries those
  layers to Tier-1 — a gap stated plainly in `docs/validation.md`, not hidden.
- `recover_deleted` is a read-only reconstructor: it emits carved bytes, never
  touching the source image.
- New anomaly variants get new codes; shipped codes never change
  (`#[non_exhaustive]` + builders keep the model additively evolvable).
