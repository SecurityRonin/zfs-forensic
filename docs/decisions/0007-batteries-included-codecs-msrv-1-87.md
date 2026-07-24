# 7. Batteries-included pure-Rust codec stack; take the ruzstd-driven MSRV 1.87

Date: 2026-07-24
Status: Accepted

## Context

ZFS compresses metadata and data extents with several codecs (lzjb, lz4, gzip,
zstd). A forensic reader in the field must decompress *any* pool it is handed
from one static binary — the analyst cannot rebuild with `--features zstd` on an
evidence workstation. The fleet Batteries-Included policy bans
`default-features = false` slimming of capability and says "when full features
trip a gate, fix the gate, not the feature set," and "MSRV yields to capability."

Two sub-decisions:

1. **zstd backend.** The obvious `zstd` crate is a C-binding (`zstd-sys`), which
   would introduce a C toolchain dependency and `-sys` unsafe, breaking the
   pure-Rust / `forbid(unsafe)` / single-static-binary posture (ADR 0001, 0004).
   The pure-Rust alternative is `ruzstd`.
2. **MSRV floor.** The usual fleet library floor is 1.75/1.80. But `ruzstd 0.8`
   declares `rust-version = 1.87` and `lz4_flex 0.11` claims 1.81, so the
   always-compiled zstd path *dictates* a 1.87 toolchain floor — higher than our
   own code needs.

## Decision

Compile the full codec stack in unconditionally — `sha2`, `lz4_flex` (`std`,
`default-features = false` only to drop its unrelated defaults, not to slim
capability), `flate2`, and `ruzstd` — declared once in `[workspace.dependencies]`
and inherited by members (`Cargo.toml` lines 33–40). No codec is behind a Cargo
feature the analyst must know to enable.

Swap the C-binding zstd for pure-Rust `ruzstd` (git commit `2162936`,
"refactor(zfs-core): swap C-binding zstd for pure-Rust ruzstd"), matching
`btrfs-core` for fleet consistency, so the tree stays unsafe-free and the binary
a single static artifact.

Accept the resulting **MSRV 1.87** as the CI-verified floor rather than
feature-gate the decoder to preserve a lower number (`Cargo.toml`
`rust-version = "1.87"`, lines 8–18; verified by the `msrv` CI job). This is
"MSRV yields to capability" applied literally: the floor is dictated by `ruzstd`,
not by us.

## Consequences

- One static binary decompresses every ZFS codec with no rebuild, no C toolchain,
  no runtime dependency.
- The published crate's MSRV is 1.87 — higher than the fleet's low-library floor,
  a deliberate trade recorded in the `Cargo.toml` comment so a future reader does
  not "fix" it by slimming the decoder.
- The zstd choice keeps the `unsafe forbidden` badge honest (ADR 0004): no
  transitive C-FFI unsafe from the compression path.
