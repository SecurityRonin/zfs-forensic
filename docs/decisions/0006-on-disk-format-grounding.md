# 6. On-disk format grounding — OpenZFS headers + the 2006 Sun spec, `zdb` as oracle

Date: 2026-07-24
Status: Accepted

## Context

Clean-room reimplementation (ADR 0001) means every offset, bitfield, magic
number, and address translation is our own code and must be grounded in an
authoritative source, not recalled from memory. One wrong bit in the packed
blkptr word (`BDX|lvl|type|etype|E|comp|PSIZE|LSIZE`) yields garbage that a
self-authored test can pass while the code is wrong — the LZNT1 trap
(`docs/RESEARCH.md` §4).

The 2006 Sun "ZFS On-Disk Specification" is the structural skeleton but predates
lz4/zstd, the SA layer, large dnodes, and feature flags. The living reference is
the OpenZFS headers, which *are* the de-facto spec: `spa.h` (blkptr bit layout,
128 bytes, 3 DVAs), `uberblock_impl.h` (`UBERBLOCK_MAGIC 0x00bab10c`, 1 KiB
slots), `dnode.h`, `dmu.h`, `vdev_impl.h` (4 labels), `zap_impl.h`,
`zfs_znode.h`/`sa_impl.h`.

Three format facts are load-bearing and easy to get subtly wrong:

1. **DVA → physical address.** `physical_byte = (offset_sectors << 9) + 0x400000`
   — the `+0x400000` skips the two 256 KiB front vdev labels plus the boot block.
2. **Uberblock selection and endianness.** The active uberblock is the ring slot
   with the highest valid `txg` whose magic matches; the magic
   (`0x0000_0000_00ba_b10c`) also reveals the pool's byte order (ADR 0005).
3. **Sizes are `((raw)+1) << 9`** (LSIZE/PSIZE), and gang/embedded blkptr
   variants change the interpretation.

## Decision

Encode the format constants and address math directly from the OpenZFS
headers/Sun spec, and validate each value path against `zdb` (`zdb -l`, `-u`,
`-dddd`, and `zdb -R :d` for byte-exact decompression) — never a self-round-trip.
The load-bearing constants are named and documented at their definition sites:

- `Dva::physical_byte_offset` = `(offset_sectors << 9).saturating_add(BOOT_SKEW)`,
  with `BOOT_SKEW = 0x0040_0000` (`core/src/blkptr.rs` lines 51, 79–86); the unit
  test asserts `(2 << 9) + 0x0040_0000` (line 341).
- `UBERBLOCK_MAGIC = 0x0000_0000_00ba_b10c`, detected in either byte order
  (`core/src/uberblock.rs` lines 36, 176–182).
- LSIZE/PSIZE `((raw)+1) << 9` (`core/src/blkptr.rs` lines 188–212); embedded and
  gang variants handled explicitly.

The 128-byte blkptr layout is documented as an ASCII field table at the top of
`core/src/blkptr.rs`.

## Consequences

- The `saturating_add` on the DVA translation is itself a corruption guard: an
  offset field that would overflow physical address space saturates rather than
  wrapping to a valid-looking small offset.
- Because the constants trace to a citable header/spec line, a reviewer can check
  each against OpenZFS rather than trusting the implementation.
- Every value-producing path (checksum, decompression, DVA read) is oracle-gated
  by `zdb`, satisfying the Evidence-Based Rigor rule that a codec/decoder needs a
  Tier-1/Tier-2 independent oracle, never tier-3 alone.
