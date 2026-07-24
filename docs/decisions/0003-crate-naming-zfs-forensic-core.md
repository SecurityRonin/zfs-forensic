# 3. Publish the reader as `zfs-forensic-core`, not `zfs-core`

Date: 2026-07-24
Status: Accepted

## Context

Pattern A would name the reader `zfs-core`. But two names on crates.io are
already taken by unrelated third parties (`docs/RESEARCH.md` §4;
`core/Cargo.toml` comment):

- **`zfs`** — `ticki/zfs`, a 2016 abandoned stub, never functional.
- **`zfs-core`** — a `libzfs_core` FFI wrapper (2019), a live-system admin
  binding unrelated to a dead-box on-disk reader.

The fleet naming grammar has an explicit rule for exactly this collision: when
`<x>-core` is taken by an unrelated third party, the reader publishes under the
`<repo>-core` form `<x>-forensic-core`, mirroring the `browser-forensic-core`
and `zfs-forensic-core` precedent already recorded in the constitution. The
import path is kept stable via `[lib] name` so consumers are unaffected.

## Decision

Publish the reader crate as **`zfs-forensic-core`** with `[lib] name = "zfs_core"`
(`core/Cargo.toml` lines 1–2, 34–35), so consumers still write `use zfs_core::…`.
The analyzer stays `zfs-forensic`. The collision-driven rename is recorded in the
git history at commit `8f416b7` ("refactor(naming): publish reader as
zfs-forensic-core (zfs-core name taken)").

## Consequences

- The crate self-describes on crates.io as "the core of the `zfs-forensic`
  suite" — read bare in search / `cargo add` / dependency lists, the name claims
  the right namespace without hijacking the popular unrelated crates.
- The import path `zfs_core` is unchanged from what the pre-rename code used, so
  no downstream source churn.
- `zfs-forensic-core` is the version referenced from
  `[workspace.dependencies]` (`Cargo.toml` line 30) and by the analyzer's
  `zfs-forensic-core = { workspace = true }` (`forensic/Cargo.toml`).
