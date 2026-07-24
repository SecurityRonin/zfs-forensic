# 5. Endian-adaptive bounds-checked `Reader` instead of the fleet `safe-read` crate

Date: 2026-07-24
Status: Accepted

## Context

The fleet Paranoid Gatekeeper standard says: route every fixed-width integer
field read through the published `safe-read` crate; never hand-roll a per-crate
`bytes.rs`. `safe-read` gives fixed-endianness helpers (`le_u16`/`be_u32`/…) that
return `0` out of range, and is itself `forbid(unsafe)`, fuzzed, and audited once
for the whole fleet.

ZFS breaks the assumption `safe-read` is built on. A ZFS pool is written in the
**host byte order of the machine that created it**, and the reader must discover
that order at runtime from the uberblock magic (`0x0000_0000_00ba_b10c` reads
back native when same-endian, byte-swapped when opposite) — then decode every
subsequent integer in whichever order the on-disk data declared
(`core/src/bytes.rs` lines 1–19). The byte order is a *runtime value carried
through the parse*, not a compile-time constant per call site. `safe-read`'s
fixed `le_*`/`be_*` split cannot express "read this `u64` in the order this pool
declared" without the caller re-branching on endianness at every field.

There is a further wrinkle: the packed nvlist config is XDR-encoded (always
big-endian) *regardless* of the pool's native order, so the XDR readers must stay
separate from the endian-adaptive path or a config field silently decodes in the
wrong order.

## Decision

Provide a crate-local `core/src/bytes.rs` exposing:

- both fixed-endianness bounds-checked readers (`le_*` / `be_*`, each `0` out of
  range — the same panic-free contract as `safe-read`),
- an `Endian` selector (defaulting to `Little`, the x86_64/aarch64 common case)
  and a `Reader` that drives them, so the rest of the crate reads integers in the
  pool's declared order, and
- separate always-big-endian XDR readers (`xdr_i32`, `xdr_u64`) for the nvlist
  config, kept apart so the adaptive path never mis-orders a config field.

This is a **justified deviation** from the "never hand-roll `bytes.rs`" rule: the
rule exists to stop drift of fixed-endianness helpers and `off + n` overflow
bugs, and both are addressed here — the readers use `data.get(off..off + n)`
(the checked slice form) and yield `0` out of range. The deviation is warranted
because `safe-read` has no endian-adaptive `Reader` abstraction, which ZFS
structurally requires.

## Consequences

- Big-endian pools (created on SPARC and other big-endian hosts) read correctly,
  not just the little-endian common case — the same reader path serves both.
- The XDR/native separation is enforced by having distinct functions, so a
  config field cannot accidentally be read in the pool's native order.
- The crate carries a small amount of code `safe-read` would otherwise own; if
  `safe-read` ever grows an endian-adaptive `Reader`, this module is the
  migration target.
- Rationale reconstructed from `core/src/bytes.rs` module documentation and the
  crate's endianness handling; the module docs state the design intent directly.
