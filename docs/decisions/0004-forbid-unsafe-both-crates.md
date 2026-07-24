# 4. `#![forbid(unsafe_code)]` in both crates — no mmap deny+allow exception

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse untrusted, attacker-controllable disk images — the Paranoid
Gatekeeper zone, where a crafted input must never corrupt memory. The fleet
`unsafe` policy makes `unsafe_code = "forbid"` the default *and the goal*: a
provable "zero places a crafted input can corrupt memory." The only sanctioned
downgrade is `deny` + a bounded per-site `#[allow(unsafe_code)]` when a real
benefit justifies it — the canonical case being `memmap2::Mmap::map` in readers
that mmap the image (ewf's 4 sites; `memory-forensic`).

`zfs-core` reads over `&[u8]` byte slices, not an mmap'd file handle — the whole
reader is expressed as bounds-checked reads against an in-memory buffer
(`core/src/bytes.rs`; ADR 0005). So it has no mmap site, hence no reason to
downgrade `forbid` to `deny`.

## Decision

Both crates set `#![forbid(unsafe_code)]` — enforced at the workspace level
(`Cargo.toml`: `[workspace.lints.rust] unsafe_code = "forbid"`) and restated at
each crate root (`core/src/lib.rs` line 21, `forensic/src/lib.rs` line 32). No
`unsafe` appears in our source, and `forbid` cannot be locally overridden, so
`rg 'allow(unsafe_code)'` returning nothing is the complete audit.

The pure-Rust codec choice (ADR 0001, ADR 0007) is what makes this reachable:
every dependency in the block-decode stack (`sha2`, `lz4_flex`, `flate2`,
`ruzstd`) is pure Rust with no C FFI, so no C toolchain and no `-sys` unsafe
enters transitively.

## Consequences

- The repo qualifies for the `unsafe forbidden` README badge — unlike the mmap
  readers (`ewf`, `memory-forensic`), which are `deny` + bounded-allow and must
  skip that badge. `README.md` carries the badge honestly.
- Panic-freedom is enforced separately by the `unwrap_used`/`expect_used = deny`
  lints plus bounds-checked readers (ADR 0005) and fuzzing — memory-safety by
  `forbid`, panic-freedom by lint and fuzz are complementary.
