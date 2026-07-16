# Validation

`zfs-core` / `zfs-forensic` are validated against independent oracles on real
OpenZFS data. Correctness is tiered by **who vouches for the ground truth**
(Evidence-Based Rigor): Tier-1 is a third-party artifact with a third-party
answer key; Tier-2 is real OpenZFS output whose ground truth an *independent
tool* (`zdb`) confirms, but where we authored the scenario.

## Tier-1 — the bootstrap layer (third-party pool + `zdb`)

**Artifact:** `zol-0.6.1` from the OpenZFS project's own
[`openzfs/zfs-images`](https://github.com/openzfs/zfs-images) — a `raidz1` pool
of four 256 MiB file-vdevs. Neither the pool nor its ground truth is ours.

- **Source:** <https://raw.githubusercontent.com/openzfs/zfs-images/master/zol-0.6.1.tar.bz2>
  (md5 `53f3ad954d062e04ab7cd4744da77f9a`).
- **Independent oracle:** `zdb -l` / `zdb -u`, the ZFS debugger — a wholly
  separate implementation.

**What Tier-1 covers.** Every ZFS vdev carries its own **vdev labels**, its own
XDR **nvlist config**, and its own **uberblock ring** — and these read *per
vdev*, **without** RAIDZ parity reconstruction across the stripe. So the
bootstrap layer of a real raidz member is validatable against the third-party
answer key. `VdevLabel::parse` on `zol-0.6.1/vdev0` reproduces exactly what
`zdb -l` / `zdb -u` report:

| field | `zdb` ground truth | source |
|---|---|---|
| pool `version` | 5000 | `zdb -l` |
| pool `name` | `zol-0.6.1` | `zdb -l` |
| pool `state` | 1 | `zdb -l` |
| config `txg` | 72 | `zdb -l` |
| `vdev_children` | 1 | `zdb -l` |
| `vdev_tree` type | `raidz` | `zdb -l` |
| `nparity` | 1 (raidz1) | `zdb -l` |
| `ashift` | 9 | `zdb -l` |
| uberblock `magic` | `0x00bab10c` (little-endian) | `zdb -u` |
| uberblock `version` | 5000 | `zdb -u` |
| uberblock `txg` | 72 | `zdb -u` |
| active ring slot | `72 % 128 = 72` (ashift 9 → 1 KiB slots) | derived |

- **Always-on:** the committed 256 KiB L0-label fixture
  `tests/data/zfs_zol061_vdev0_label0.bin`.
- **Env-gated (`ZFS_TIER1_ZOL`):** all four vdevs, each decoding its own
  bootstrap independently to the shared answer key.
- **Test:** `core/tests/tier1_zol061.rs`.

## Tier-2 — the DMU / ZAP / ZPL / SA / file + F-CARVE layers (self-mint + `zdb`)

Reading the MOS, DMU, ZAP, ZPL, SA, and file-content layers of the `zol-0.6.1`
raidz pool requires **RAIDZ parity reconstruction** across its four vdevs, which
`zfs-core` deliberately defers (single-vdev / mirror in v1). Those layers are
therefore validated at Tier-2 against a **single-vdev self-mint** pool
(`tpool` — real OpenZFS 2.2.2 output, ashift 12), with `zdb` as the independent
structural oracle for every asserted value:

- **P0 label/nvlist/uberblock** — `core/tests/label.rs`, `core/tests/uberblock.rs`
  vs `zdb -l` / `zdb -uuuuu`.
- **P1 block I/O + checksum/decompress** — `core/tests/blkptr_io.rs`: `fletcher4`
  over each extracted block equals the `rootbp` checksum `zdb -uuuuu` reports
  (byte-exact); LZ4 inflate to the exact `lsize`.
- **P2 ZAP navigation (MOS → DSL → ZPL)** — `core/tests/zap.rs` vs
  `zdb -dddddd` entry lists.
- **P3 SA / znode metadata + directory content** — `core/tests/sa.rs` vs
  `zdb -dddddd` (mode/size/gen/links/timestamps, SA registry + layouts).
- **F-CARVE CoW deleted-file recovery** — `forensic/tests/carve.rs` over an
  env-gated snapshot-deletion pool (`dtpool@snap1`): the carved content's sha256
  equals the pre-delete `sha256sum` recorded at mint time.
- **F-INTEGRITY structural audit** — `forensic/tests/integrity.rs`: uberblock /
  label / blkptr checksum-mismatch and impossible-geometry findings.

The verbatim mint commands, per-fixture md5s, and the full `zdb` answer keys are
in [`tests/data/README.md`](https://github.com/SecurityRonin/zfs-forensic/blob/main/tests/data/README.md).

## Robustness

Both crates are `#![forbid(unsafe_code)]` and panic-free: every integer / length
/ offset field is read through bounds-checked helpers that yield `0` / `None`
out of range, and nvlist length / count fields are capped against allocation
bombs. Malformed input degrades to an empty or typed result, never a panic —
exercised by a `cargo-fuzz` target per parsed structure plus a `fuzz_forensic`
target driving the full `audit_image` / `recover_deleted` pipeline.
