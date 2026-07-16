# Validation

`zfs-core` / `zfs-forensic` are validated against independent oracles on real
OpenZFS data. Correctness is tiered by **who vouches for the ground truth**
(Evidence-Based Rigor): Tier-1 is a third-party artifact with a third-party
answer key; Tier-2 is real OpenZFS output whose ground truth an *independent
tool* (`zdb`) confirms, but where we authored the scenario.

**The full read path is Tier-1.** A real, vendor-authored **FreeBSD ZFS-root**
image (single `disk` vdev) carries `zfs-core`'s *entire* path — label →
uberblock → MOS → DSL → ZPL → SA → **file content** — to Tier-1: `zpl_read_path`
reads genuine third-party file bytes whose sha256 matches two independent OpenZFS
oracles. The self-mint fixtures below remain the always-on Tier-2 regression
backstop *under* that gate.

## Tier-1 — the full read path (real FreeBSD ZFS-root + `zdb` + kernel mount)

**Artifact:** an official **FreeBSD 14.3-RELEASE amd64 ZFS-on-root** VM image
(`FreeBSD-14.3-RELEASE-amd64-zfs.qcow2.xz`) — vendor-authored, so it is a genuine
third-party pool with a third-party layout. Its pool `zroot` is a real **single
`disk` vdev** (`zdb -l`: `vdev_tree type 'disk'`, not raidz), so `zfs-core` reads
its data blocks with **no RAIDZ reconstruction**.

- **Source:** <https://download.freebsd.org/releases/VM-IMAGES/14.3-RELEASE/amd64/Latest/FreeBSD-14.3-RELEASE-amd64-zfs.qcow2.xz>
  (vendor SHA256 `8bfcc2c6f3b3f259b0288b41db808328d98fe015f59432ffd8d69276829a9a8d`).
  The `-zfs.raw` variant shipped corrupt via a 14.3 `makefs` bug; the qcow2 is
  intact.
- **Independent oracles:** `zdb` (the ZFS debugger) **and** a live read-only
  kernel `zfs mount` — two wholly separate OpenZFS implementations, which agree
  on every file hash below.

**What Tier-1 now covers — the whole reader path.** `zfs-core` walks the real
partition end-to-end and reproduces exactly what the oracles report:

| step | value | oracle |
|---|---|---|
| pool `name` | `zroot` | `zdb -l` |
| `vdev_tree` type | `disk` (single vdev, **no raidz**) | `zdb -l` |
| `ashift` / `vdev_children` | 12 / 1 | `zdb -l` |
| active uberblock `magic` / `txg` | `0x00bab10c` (LE) / `8` | `zdb -u` |
| root filesystem dataset | `zroot/ROOT/default` (child, via DSL child-dir tree) | `zdb -d` |
| real `/` listing | `.cshrc .profile COPYRIGHT bin boot dev etc … usr var` (20 entries) | kernel `ls` |
| `zpl_read_path("/.cshrc")` sha256 | `d1ba75d6…403b5d7` (1011 B, uncompressed) | `zdb -R` + mount |
| `zpl_read_path("/COPYRIGHT")` sha256 | `4ce91652…c3fb064` (6109 B, uncompressed) | mount |

`FreeBSD` nests `/` in the **`zroot/ROOT/default`** boot-environment dataset, a
DSL *child* of the pool root. `zfs-core`'s `zpl_objset` resolves the pool's head
dataset directly; the one child-dataset hop (root DSL dir →
`dd_child_dir_zapobj` → `ROOT` → `default` → head dataset 30) is assembled in the
test from `zfs-core`'s exported primitives (`mos_dnode` / `read_zap_object` /
`zap_lookup` / `dsl_dataset_bp`) — every block read, checksum, and DSL/ZAP/ZPL/SA
decode still runs inside `zfs-core`. (A high-level *named-child-dataset* navigator
is the remaining API gap; the primitives to build it are already public.)

- **Env-gated (`ZFS_TIER1_FREEBSD`):** the extracted `freebsd-zfs` partition
  (md5 `22a711abfb33ca90e54676272034e216`, offset 1108026880, 5 GiB).
- **Test:** `core/tests/tier1_freebsd.rs` (skips cleanly when unset).

## Tier-1 — the bootstrap layer (third-party raidz pool + `zdb`)

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

## Tier-2 — the always-on self-mint regression corpus (`zdb`)

The full read path is proven at **Tier-1** on the FreeBSD single-vdev pool above.
The committed byte-exact self-mint fixtures below (`tpool` / `dtpool` — real
OpenZFS 2.2.2 output, ashift 12, `zdb` as the independent structural oracle)
remain the fast, deterministic, always-on **regression backstop** *under* that
gate — they run in CI with no large download and pin each layer's decode
byte-for-byte:

> **RAIDZ note (still current):** the *other* third-party pool, `zol-0.6.1`, is
> **raidz1**, so reading *its* MOS/ZAP/ZPL/SA/file layers needs parity
> reconstruction across four vdevs, which `zfs-core` defers (single-vdev / mirror
> in v1). That is why `zol-0.6.1` validates only the bootstrap layer at Tier-1;
> the FreeBSD *single-`disk`-vdev* pool is what carries the data layers to Tier-1
> without reconstruction. RAIDZ reconstruction remains future work.

Per-layer regression fixtures, each vs `zdb`:

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
