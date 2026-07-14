# ZFS Forensic Reader — Research-First Report (`zfs-core` + `zfs-forensic`)

Read-only Research-First deliverable.

**BLUF:** ZFS is the hardest mainstream filesystem to parse read-only, by a wide
margin. A minimum-viable pure-Rust reader that lists a directory and reads one file
by path must traverse ~9 chained object layers (label → nvlist → uberblock → MOS →
object directory → DSL → dataset objset → ZPL → dnode → blkptr → DVA → data), each
with its own encoding, checksum verification, and compression. **There is no
production-grade Rust on-disk ZFS parser to reuse or use as an oracle** — the one
crate (`rzfs_lib`) is a yanked 0.0.0 placeholder, and TSK does not support ZFS at all.
**Multi-month build, realistically 3–5× an ext4 reader for the single-vdev MVP, 5–8×
with RAIDZ/encryption.** Recommendation: **pure-Rust clean-room** (fits `forbid(unsafe)`,
single static binary, no C toolchain/CDDL), scoped brutally, `zdb` as the oracle — do
NOT try to match `zfs import` semantics in v1.

## 1. Authoritative spec

**Primary (foundational, dated):** "ZFS On-Disk Specification — Draft," Sun
Microsystems, 2006 (v1). The canonical structural skeleton every ZFS reader is built
from; predates lz4/zstd, encryption, large dnodes, the SA layer, feature flags,
RAIDZ3, device removal.
- Canonical mirror (maintained by **Matt Ahrens, ZFS co-creator**):
  **https://github.com/ahrens/zfsondisk** ("...the OpenZFS on-disk format is an
  extension of this"). Carries `docs/zfs_internals.md`.
- PDF copy: **https://www.giis.co.in/Zfs_ondiskformat.pdf** (gives DVA offset math +
  uberblock-selection rule verbatim; Flate-compressed — extract locally before citing
  page numbers).

**Living reference (authoritative post-2006) — OpenZFS headers are the de-facto spec:**
- `include/sys/spa.h` — **the `blkptr_t` bit-by-bit layout** (128 bytes; 3 DVAs; the
  compressed word `BDX|lvl|type|etype|E|comp|PSIZE|LSIZE`; embedded-blkptr variant;
  UBERBLOCK constants). This header *is* the blkptr spec.
- `include/sys/uberblock_impl.h` — `UBERBLOCK_MAGIC 0x00bab10c`, `UBERBLOCK_SHIFT 10`
  (1 KiB slots), `ub_txg`, `ub_rootbp`, `ub_checkpoint_txg`, MMP (`0xa11cea11`).
- `include/sys/dnode.h` — `dnode_phys_t` (512-byte base; `dn_blkptr[]`/`dn_bonus[]`/
  `dn_spill`; variable-length large dnodes in multiples of 512).
- `include/sys/dmu.h` — DMU object types, `objset_t`, meta-dnode (object 0), bonus.
- `include/sys/vdev_impl.h` — `VDEV_LABELS 4`, `VDEV_LABEL_START_SIZE`, `VDEV_LABEL_END_SIZE`.
- `include/sys/zap_impl.h` — micro-ZAP vs fat-ZAP (`zap_phys_t`, pointer table, `zap_leaf_t`).
- `include/sys/zfs_znode.h` — znode / SA-based (`z_is_sa`) layout.
- Also needed: `sys/dsl_dir.h`, `sys/dsl_dataset.h`, `sys/sa_impl.h`, `sys/spa_impl.h`,
  `sys/zio_checksum.h`/`zio_compress.h`, `sys/zil.h`.

**License:** OpenZFS headers are **CDDL-1.0** (GPL-incompatible, file-level copyleft).
Reference for a clean-room Rust reimplementation, **not code to vendor**. Apache-2.0
clean-room reader is fine; do not copy CDDL source.

**Traversal chain to read `/tank/ds1/foo.txt`:** vdev label → parse nvlist → select
active uberblock (max valid `ub_txg`) → `ub_rootbp` → MOS meta-dnode → MOS object
directory (ZAP) → DSL root dir → DSL dataset `ds1` → dataset objset blkptr → ZPL
master node (object 1) → ROOT dir dnode → root dir ZAP lookup `foo.txt` → file dnode →
resolve blkptr tree (DVA + decompress + checksum) → file bytes. **Every arrow crossing
a blkptr also does DVA translation + checksum verify + decompression.**

**Structures (dependency order):**
1. **vdev label** (`vdev_label_t`, 256 KiB, **4 copies**: L0/L1 front, L2/L3 back).
   Layout: 8 KiB blank + 8 KiB boot header + **112 KiB packed nvlist config** + **128-slot
   uberblock array** (1 KiB each). Front labels precede a 3.5 MiB boot block.
2. **nvlist** — self-describing config (pool GUID, vdev tree, ashift). On-disk = **XDR**
   (big-endian). Its own mini-parser (typed name/value, nested, arrays).
3. **uberblock array** (128 slots) — active = **highest `ub_txg`** with valid checksum
   + `ub_magic == 0x00bab10c`; carries `ub_rootbp` → MOS. (Older valid uberblocks = the
   forensic point-in-time lever.)
4. **blkptr_t** — THE central 128-byte structure: up to **3 DVAs** (`vdev`+`offset`),
   `LSIZE`/`PSIZE`/`ASIZE`, compression enum, checksum enum + 256-bit checksum, birth
   txg, `lvl`, DMU type, flags G(ang)/D(edup)/X(encryption)/E(mbedded). **DVA→physical:
   `physical_byte = (offset << 9) + 0x400000`** (skips the 2 front labels + boot).
   `lvl>0` = blkptr-tree arrays → recurse to `lvl==0` data.
5. **MOS** — root objset via `ub_rootbp`; holds the object directory, DSL, space maps.
6. **dnode** (`dnode_phys_t`, 512-byte base or multiple) — `dn_type`, `dn_nlevels`/
   `dn_nblkptr`, `dn_blkptr[]`, bonus buffer (holds znode SA metadata).
7. **DSL** — object directory → root_dataset → DSL dir → head/child_dir ZAP; each
   dataset (`dsl_dataset_phys_t` in a dnode bonus) points at its objset blkptr + snapshots.
8. **ZAP** — **micro-ZAP** (fixed 64-byte `mzap_ent_phys_t`, name ≤50) vs **fat-ZAP**
   (`zap_phys_t` + pointer table + hash-chained `zap_leaf_t`). Object directory + every
   ZPL directory are ZAPs.
9. **ZPL** — dataset objset: **object 1 = master node** (ZAP naming `ROOT`,
   `DELETE_QUEUE`, `VERSION`, `SA_ATTRS`). Dirs = ZAPs (name→object#); files = dnodes →
   blkptr tree → data. znode metadata (mode/size/times) in the **SA (System Attributes)**
   registry inside the dnode bonus (modern) or legacy `znode_phys_t`.

**csum:** fletcher2/4 (fletcher default), sha256, skein/edonr/blake3 (only if used).
**compression:** lzjb, lz4, gzip, zstd.

## 2. Existing implementations (build-vs-reuse)

**Rust pure on-disk readers: effectively none usable.** `rzfs_lib` (crates.io) = 0.0.0
YANKED placeholder; `zfs` (2016) abandoned/never functional; `zfs-rs` (clinta) = live
ioctls to /dev/zfs; `libzetta`/`libzfs`/`razor-rs`/`zfs-core-sys` = FFI to a running
system's libzfs (admin wrappers, irrelevant to dead-box); `illumos-nvpair` (Oxide) —
the `-sys` is FFI to libnvpair; evaluate the pure-Rust one for **nvlist XDR decode
only**, but **prefer writing a small bounded XDR-nvlist parser ourselves**.

**Non-Rust references + oracles:**
- **`zdb`** — the canonical ZFS debugger, **THE structural oracle**:
  - `zdb -l <device|image>` — 4 vdev labels + uberblock array + config nvlist.
  - `zdb -u <pool>` — active uberblock (txg, rootbp).
  - `zdb -dddd <pool>[/dataset] [objnum]` — objsets/dnodes/ZAP/blkptrs (each extra `d`
    = more detail; 4×d dumps indirect blkptrs + bonus/SA).
  - `zdb -mmm <pool>` — metaslabs/space maps.
  - `zdb -R <pool> <vdev>:<offset>:<size>[:flags]` — **raw block read at a DVA** (`d`
    = decompress) → byte-for-byte diff of our DVA math + decompressor.
  - `zdb -bbbb`/`-vvv` — traverse-all-blocks (validate full traversal).
- **OpenZFS `libzpool`** — reference impl (what zdb/ztest link); could be FFI-bound as
  an alternative to pure-Rust for the hard codecs — **but CDDL + C + large tree +
  clashes with forbid(unsafe)/single-static-binary → rejected for the core.**
- **`ZfsSharp`** (C#, github.com/AustinWise/ZfsSharp, CDDL) — the best-documented
  educational read-only reimplementation; its build-order write-up ("read the
  uberblock, then decompression + checksumming, then dnode + blkptr and everything
  falls out") is **the single most useful build-order map — read before writing a line.**
- **Hilgert et al. 2017, "Extending The Sleuth Kit … for pooled storage"** (DFRWS,
  ScienceDirect S1742287617301901) — the ZFS-on-TSK extension: `pls` command, recovers
  deleted data by **reconstructing old ZFS trees from older uberblocks**, handles
  **missing-disk (incomplete) pools** `zfs import` refuses. The `zfs-forensic` design target.
- **TSK does NOT support ZFS** — architectural (pooled storage breaks TSK's
  one-filesystem-per-volume model). Only the Hilgert research fork adds it.

**Recommendation: build pure-Rust, clean-room** from OpenZFS headers + Sun spec +
ZfsSharp as a map; `zdb` = the oracle. Nothing to reuse (yanked stub / live-FFI /
abandoned). Binding libzpool breaks the fleet's field-deployability promises. The
risky codecs (fletcher4, sha256, lz4/lzjb/gzip/zstd) have mature pure-Rust crates —
reuse those (`sha2`, `lz4_flex`, `flate2`, `zstd`; fletcher is trivial; lzjb is small +
oracle-checkable via `zdb -R`). **Defer RAIDZ, dedup, encryption entirely in v1.**

## 3. Real sample data + oracle (Tier-1 plan)

```bash
# Parallels Ubuntu VM: sudo apt install zfsutils-linux ; zdb -V (record OpenZFS version)
truncate -s 512M /tmp/zfs-vdev.img
sudo zpool create -o ashift=12 -O compression=off -O encryption=off -O atime=off \
     -O checksum=on tank /tmp/zfs-vdev.img          # SINGLE vdev, no raidz/mirror
sudo zfs create tank/ds1
echo "hello zfs forensics" | sudo tee /tank/ds1/foo.txt
sudo mkdir -p /tank/ds1/sub && echo "nested" | sudo tee /tank/ds1/sub/bar.txt
sudo zfs snapshot tank/ds1@snap1
echo "post-snapshot change" | sudo tee -a /tank/ds1/foo.txt
sha256sum /tank/ds1/foo.txt /tank/ds1/sub/bar.txt > /tmp/zfs-ground-truth.sha256
zpool get all tank ; zfs get all tank/ds1          # record actual defaults
sudo zpool export tank
# oracles
zdb -l /tmp/zfs-vdev.img                    > /tmp/oracle-labels.txt
sudo zpool import -o readonly=on -N -d /tmp tank
zdb -u tank                                 > /tmp/oracle-uberblock.txt
zdb -dddd tank                              > /tmp/oracle-mos.txt
zdb -dddd tank/ds1                          > /tmp/oracle-ds1.txt
zdb -mmm tank                               > /tmp/oracle-metaslabs.txt
# zdb -R tank <dva> :d                       # byte-exact decompression oracle
sudo zpool export tank
```

**Tiering:** **content Tier-1** (read-only import + sha256 vs OpenZFS-materialized
bytes — genuine independent third party). **structure Tier-2** (zdb output, real
reference-tool, independently produced; `zdb -R :d` = byte-exact decompression oracle).
Synthetic hand-built label bytes = **Tier-3** (fast panic/robustness only, never the
sole proof of a value path — blkptr/decompress/checksum). Env-gate the oracle tests.
**Corpora:** rare; a TrueNAS/Proxmox VM disk (both default to ZFS root) = good
real-world second sample; no NIST-CFReDS ZFS image.

## 4. Scope/difficulty — brutally honest + phased order

**MVP scope (single-vdev, uncompressed OR lz4, unencrypted, non-RAIDZ):** label →
XDR nvlist → active uberblock → MOS → object directory → one head dataset → ZPL objset
→ master node → root ZAP → name lookup → file dnode blkptr tree → DVA + checksum +
decompress → file bytes.

**Difficulty ranking:**
1. **blkptr indirection + DVA math + per-block checksum + compression** — the heart;
   every block access does all four. Indirect trees, `(offset<<9)+0x400000`,
   ditto-copy fallback across 3 DVAs, embedded-blkptrs, gang blocks, 256-bit checksum,
   decompress. One wrong bit in the packed `lvl|type|comp|PSIZE|LSIZE` word → garbage.
   **LZNT1-trap zone — validate with `zdb -R :d`, never self-round-trip.**
2. MOS → DSL → ZPL multi-objset traversal (three objset contexts + DSL indirection;
   off-by-one object# silently reads the wrong dnode).
3. fat-ZAP (hashed pointer-table + leaf-block sub-parser; directories of any size).
4. SA variable znode layout (mode/size/times as a *registered variable* attribute in
   the bonus; the SA registry is itself objects — the 2006 spec's fixed `znode_phys_t`
   is obsolete here).
5. nvlist XDR decode (bounded).
6. uberblock selection (simple, but "valid" = checksum verify → depends on 1).
7. Compression — reuse `lz4_flex`/`flate2`/`zstd`; lzjb = small clean-room, oracle via
   `zdb -R`. Checksums: fletcher2/4 ~30 lines each; `sha2` for sha256.
8. **Deferred in v1 (each a project):** RAIDZ1/2/3, mirror/multi-vdev, dedup (DDT),
   **native encryption** (AES-CCM/GCM + key hierarchy), device removal/indirect vdevs,
   ZIL replay, feature-flag matrix.

**Effort multiple:** 9+ chained layers vs ext4's ~3, every block checksummed +
compressed + CoW + indirection-tree'd, metadata stored as objects-in-objsets. **3–5×
ext4 for the MVP file-read path, 5–8× with RAIDZ + snapshots + SA robustness. Plan for
a multi-month build (≈2–4 months for a solid single-vdev MVP; RAIDZ/encryption → 6+).
The single largest FS reader in the fleet plan.**

**Pure-Rust vs bind-libzpool:** **pure-Rust for `zfs-core`** — the only single-static-
binary, forbid-unsafe, no-C-toolchain, no-CDDL option; complexity bounded for the
single-vdev/uncompressed-or-lz4 MVP; `zdb` gives byte-exact oracles. Reserve any
libzpool FFI for a far-future RAIDZ/encryption module (explicitly marked, `publish=false`
if ever) — not the core.

**`zfs-core` phases:** P0 codec primitives + oracle harness (fletcher2/4, sha256, lzjb,
lz4, gzip, zstd; DVA translation — build FIRST, validate each vs `zdb -R`, per
ZfsSharp) → P1 vdev label + XDR nvlist (oracle `zdb -l`) → P2 uberblock array + active
selection (oracle `zdb -u`) → P3 blkptr + dnode + objset (all bitfields, indirect-tree,
large dnodes; oracle `zdb -dddd` on MOS) → P4 MOS object directory + DSL → P5 ZPL + ZAP
+ SA → **read file by path, match Tier-1 sha256** (closes MVP).

**`zfs-forensic` (over `zfs-core`):** uberblock-history/txg point-in-time (enumerate
ALL valid uberblocks → reconstruct earlier txgs — the Hilgert technique, highest
value); snapshot/clone analysis (DSL snapshot list; diff live vs `@snap`); deleted-
dataset/file recovery (unreferenced-but-intact dnodes from old uberblocks; DSL delete
queue); integrity findings (checksum mismatch, blkptr anomaly, txg-ordering, MMP/
checkpoint) → `forensicnomicon::report::Finding` (`ZFS-UBERBLOCK-TXG-GAP`,
`ZFS-BLKPTR-CKSUM-MISMATCH`, `ZFS-DATASET-ORPHAN`); incomplete-pool handling (parse
what's present when a vdev is missing — pools `zfs import` refuses).

**Naming:** Pattern A `zfs-core` + `zfs-forensic`. `zfs` on crates.io = dead 2016 stub
(low-download, not popular) → publishing `zfs-core` with `[lib] name = "zfs"` for a
clean import is *likely* available — verify the stub's deletable/transferable status
before the 72h window.

**Gaps:** the Sun 2006 PDF is Flate-compressed (content confirmed via search, extract
locally before citing pages); evaluate `illumos-nvpair`'s pure-Rust XDR-label-nvlist
decode hands-on before build-vs-reuse (recommendation still: write our own small XDR-
nvlist parser); crates.io HTML search 404'd (use the JSON API with a UA).
