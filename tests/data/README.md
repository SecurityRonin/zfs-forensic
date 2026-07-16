# zfs-forensic test data — provenance

Single machine-index of the fleet corpus lives in
`~/src/issen/docs/corpus-catalog.md`; this file is the co-located human-facing
detail. Cross-reference, do not duplicate.

<!-- TODO(corpus-catalog): add these zfs-forensic entries (zfs_zol061_vdev0_label0.bin,
     zfs_label0.bin, zfs_mos_objset.bin, zfs_mos_l1_indirect_lz4.bin,
     zfs_zap_fat_objdir.bin, zfs_zap_micro_master.bin, zfs_zap_micro_root.bin,
     the P3 SA fixtures zfs_sa_file_dnode.bin, zfs_sa_dir_dnode.bin,
     zfs_sa_registry.bin, zfs_sa_layouts.bin + the env-gated zfs.img) to
     issen/docs/corpus-catalog.md when the P0–P3 work is folded into the fleet
     catalog. -->

## Validation tiers at a glance

- **Tier-1 (full read path — real `FreeBSD` ZFS-root):** an official, vendor-authored
  **`FreeBSD` 14.3-RELEASE amd64 ZFS-on-root** VM image whose pool is a real
  **single `disk` vdev** (`zdb -l`: `vdev_tree type 'disk'`, not raidz), so
  `zfs-core`'s **entire** read path — label → uberblock → MOS → DSL → ZPL → SA →
  **file content** — reads it **without** RAIDZ reconstruction and validates
  against two independent OpenZFS oracles (`zdb` + a live read-only kernel
  `zfs mount`). This upgrades the **file layer to Tier-1**: `zpl_read_path` reads
  real third-party file bytes whose sha256 matches the oracle. Env-gated via
  `ZFS_TIER1_FREEBSD`; test: `core/tests/tier1_freebsd.rs`.
- **Tier-1 (bootstrap layer — raidz reference pool):** a **third-party** OpenZFS
  reference pool (`openzfs/zfs-images` `zol-0.6.1`) with `zdb -l` as the
  independent answer key. Neither the pool nor the ground truth is ours. This
  validates the per-vdev bootstrap — vdev label + XDR nvlist config + uberblock
  ring — which reads on a single raidz member **without** RAIDZ reconstruction.
  Fixture: `zfs_zol061_vdev0_label0.bin`; test: `core/tests/tier1_zol061.rs`.
  (Its MOS/ZAP/ZPL/SA/file layers still need parity reconstruction across the
  four vdevs, deferred by `zfs-core` — so *this raidz pool's* data layers remain
  out of reach; the `FreeBSD` single-vdev pool above is what carries those layers
  to Tier-1.)
- **Tier-2 (self-mint fixtures — the always-on regression corpus):** a single-vdev
  self-mint pool (`tpool` / `dtpool`), real OpenZFS output whose ground truth is
  vouched for by `zdb` (a separate implementation), but authored by us. These
  committed byte-exact fixtures remain the fast, deterministic, CI-friendly
  regression backstop *under* the Tier-1 gates above. All the `zfs_*` fixtures
  below and the env-gated `zfs.img` / `zfs_snap.img` are Tier-2.

## Committed fixtures

### `zfs_zol061_vdev0_label0.bin` (Tier-1 — bootstrap layer)

- **Class:** `REAL-ext` (**Tier-1**). The L0 (256 KiB) vdev label lifted verbatim
  from **`vdev0`** of the **OpenZFS project's own reference pool**
  `zol-0.6.1` — a `raidz1` pool of four 256 MiB file-vdevs published in
  [`openzfs/zfs-images`](https://github.com/openzfs/zfs-images). This is a genuine
  third-party artifact with a documented `zdb -l` answer key: neither the pool nor
  the ground truth is ours.
- **Source:** <https://raw.githubusercontent.com/openzfs/zfs-images/master/zol-0.6.1.tar.bz2>
  (md5 `53f3ad954d062e04ab7cd4744da77f9a`, 384 KiB). Extract → `zol-0.6.1/vdev{0..3}`
  (per-vdev md5: `vdev0 d79575be780c064b12ffe926e69449af`,
  `vdev1 ced54d22d5db48f49d5cba31216cda5b`,
  `vdev2 66777ec94404ecb0170b1497b4c3d88b`,
  `vdev3 b734fd74dacfbc2678773838e6b2b7af`). Fixture cut with
  `dd if=zol-0.6.1/vdev0 of=zfs_zol061_vdev0_label0.bin bs=1024 count=256`.
- **`zdb -l` / `zdb -u` ground truth (the independent oracle, the answer key):**
  `version 5000`, `name 'zol-0.6.1'`, `state 1`, `txg 72`, `vdev_children 1`;
  `vdev_tree type 'raidz'`, `nparity 1`, `ashift 9`; active uberblock
  `magic 0x00bab10c` (little-endian), `version 5000`, `txg 72`, ring slot
  `72 % 128 = 72` (ashift 9 → 1 KiB slots → 128 slots).
- **Independent-oracle checks it satisfies:** `VdevLabel::parse` on this real vdev
  label reproduces every value above — the Tier-1 validation of the bootstrap
  layer (label + nvlist + uberblock) that reads per-vdev without RAIDZ
  reconstruction. The MOS/DMU/ZAP/ZPL/file layers of this raidz pool need parity
  reconstruction across the four vdevs (deferred by `zfs-core`), so those layers
  stay Tier-2 on the self-mint below.
- **md5:** `5351411f80df20ddea67629b1fca14d5`
- **Consumed by:** `core/tests/tier1_zol061.rs` (always-on). The full four-vdev
  corpus is env-gated via `ZFS_TIER1_ZOL` (see below) and NOT committed.

### `zfs_label0.bin`

- **Class:** `REAL-self` (Tier-2). Self-minted real OpenZFS pool; the ground
  truth is vouched for by `zdb` — a **separate, independent implementation** (the
  ZFS debugger), not by us. (The Tier-1 third-party artifact above validates the
  bootstrap layer; this self-mint carries the MOS→file layers `zol-0.6.1` cannot
  reach without RAIDZ reconstruction.) `zdb` is the independent structural oracle.
- **What it is:** the **L0 vdev label** — the first 256 KiB of the minted image
  (`dd if=zfs.img of=zfs_label0.bin bs=1 count=262144`). Contains the 8 KiB blank
  pad, 8 KiB boot header, 112 KiB XDR nvlist config, and the 128 KiB uberblock
  ring array — everything P0 (label + nvlist + uberblock) parses.
- **md5:** `9fd4f776e8a28134e2641ed60b3d78cf`
- **Consumed by:** `core/tests/label.rs`, `core/tests/uberblock.rs`.

### `zfs_mos_objset.bin`

- **Class:** `REAL-self` (Tier-2). The 4 KiB **MOS `objset_phys_t` block** — the
  block the active uberblock's `rootbp` points at. Extracted byte-for-byte from
  the minted pool with the independent oracle `zdb`:
  `zdb -R -e -p /media/psf/tmp/zfs tpool 0:c015000:1000:r > zfs_mos_objset.bin`
  (the `:r` flag dumps the raw 4096-byte block). Ground truth vouched for by
  `zdb`, a separate implementation — not by us.
- **What it holds:** the objset meta-dnode (a `dnode_phys_t`: `dn_type` = 10
  `DMU_OT_DNODE`, `dn_nlevels` = 2, `dn_nblkptr` = 3, 16 KiB data blocks,
  `dn_maxblkid` = 4, its `blkptr[0]` a level-1 LZ4 indirect), the ZIL header, and
  `os_type` = 1 (`DMU_OST_META`) at offset 704.
- **Independent-oracle checks it satisfies (P1):** `fletcher4` over the whole
  block equals the rootbp checksum `zdb -uuuuu` reports
  (`00000002bffcd5dd:00000a91372660e5:00145331c05695f5:1a16f2c8d3d157f0`) —
  verified byte-exact; `ObjsetPhys::parse` decodes the meta-dnode.
- **md5:** `d8d0b4e4a81c500f2533163a974decc7`
- **Consumed by:** `core/tests/blkptr_io.rs` (always-on, no env gate).

### `zfs_mos_l1_indirect_lz4.bin`

- **Class:** `REAL-self` (Tier-2). The 4 KiB **LZ4-compressed L1 indirect block**
  of the MOS meta-dnode (`comp` = 15, `psize` = 4 KiB, decompresses to
  `lsize` = 128 KiB). Extracted from the minted pool via the `zdb` oracle:
  `zdb -R -e -p /media/psf/tmp/zfs tpool 0:4025000:1000:r > zfs_mos_l1_indirect_lz4.bin`.
  The block opens with ZFS's LZ4 framing — a 4-byte **big-endian** compressed
  length prefix (`0x00000315` = 789 bytes) then the raw LZ4 stream.
- **Codec oracle (byte-exact, independent):** the meta-dnode's `blkptr[0]` stores
  the `fletcher4` checksum of *this* compressed block
  (`0000008ed7fd6861:0001f75c33157372:037a2a265b04cac2:1d601bdab3e7e328`);
  `checksum::verify` over the fixture matches it — proving the raw bytes are
  intact — and `compress::decompress` inflates it to exactly 128 KiB, whose first
  128 bytes decode as a level-0 `DMU_OT_DNODE` L0 blkptr.
- **md5:** `2c6019af6aabb8d7c4d8c74064d2a4d1`
- **Consumed by:** `core/tests/blkptr_io.rs` (always-on, no env gate).

### `zfs_zap_fat_objdir.bin` (P2)

- **Class:** `REAL-self` (Tier-2). The MOS **object directory** (object 1) — a
  **fat-ZAP** — as the object's whole logical data: block 0 (the `zap_phys_t`
  header + embedded pointer table) followed by block 1 (the `zap_leaf_phys_t`),
  each 16 KiB, **decompressed** from LZ4 and concatenated to 32 KiB. Extracted via
  the `zdb` oracle then inflated by the same LZ4 codec the reader uses:
  `zdb -R -e -p /media/psf/tmp/zfs tpool 0:4008000:1000:r` (block 0) and
  `0:4009000:1000:r` (block 1), each LZ4-decompressed to 16 KiB, concatenated.
- **Independent-oracle checks it satisfies:** `zap_list` yields exactly the 15
  entries `zdb -dddddd tpool 1` reports (`zap_magic` `0x2f52ab2ab`, `ZAP entries:
  15`), including `root_dataset = 32`, `config = 61`, `creation_version = 5000`.
- **md5:** `99fa6c8e0df7a4c8fef35f50324a9481`
- **Consumed by:** `core/tests/zap.rs` (always-on, no env gate).

### `zfs_zap_micro_master.bin` (P2)

- **Class:** `REAL-self` (Tier-2). The ZPL **master node** (object 1 of the
  `tpool` filesystem dataset) — a 512-byte **micro-ZAP** block (uncompressed).
  Extracted with the `zdb` oracle:
  `zdb -R -e -p /media/psf/tmp/zfs tpool 0:4002000:1000:r` (first 512 bytes).
- **Independent-oracle checks it satisfies:** `zap_list` yields the 7 entries
  `zdb -dddddd tpool/ 1` reports — `VERSION = 5`, `ROOT = 34`, `SA_ATTRS = 32`,
  `DELETE_QUEUE = 33`, and the three normalization props (all 0).
- **md5:** `9ba705d629a71acfb340c36f995258a5`
- **Consumed by:** `core/tests/zap.rs` (always-on, no env gate).

### `zfs_zap_micro_root.bin` (P2)

- **Class:** `REAL-self` (Tier-2). The ZPL **root directory** (object 34 of the
  `tpool` dataset) — a 512-byte **micro-ZAP**. In the pool this directory is
  stored in an **embedded blkptr** (`EMBEDDED 200L/43P`, LZ4); this fixture is its
  **decompressed** payload. Extracted by reading the ZPL meta-dnode L0 block
  holding objects 32–63 (`zdb -R … 0:401b000:1000:r`, LZ4-inflate to 16 KiB),
  taking object 34's dnode `blk_ptr[0]`, gathering the 112-byte BPE payload, and
  LZ4-decompressing (4-byte BE prefix) to 512 bytes.
- **Independent-oracle checks it satisfies:** `zap_list` yields the 2 entries
  `zdb -dddddd tpool/ 34` reports — `foo.txt = 2` (raw value `0x8…0002`, dirent
  type 8 = regular file) and `sub = 3` (raw `0x4…0003`, dirent type 4 = directory)
  — the two minted files.
- **md5:** `44d153bde208d45cd408b121918ba71f`
- **Consumed by:** `core/tests/zap.rs` (always-on, no env gate).

### `zfs_sa_file_dnode.bin` (P3)

- **Class:** `REAL-self` (Tier-2). Object **2** (`/foo.txt`) of the `tpool`
  dataset — a 512-byte `dnode_phys_t` with `dn_type = 19` (plain file),
  `dn_bonustype = 44` (`DMU_OT_SA`), and a **176-byte SA bonus**. Extracted by
  reading the ZPL meta-dnode L0 block holding objects 0–31
  (`zdb -R … 0:401a000:1000:r`, LZ4-inflate to 16 KiB) and slicing slot 2
  (offset 1024, 512 bytes).
- **Independent-oracle checks it satisfies:** `decode_sa_bonus` against the SA
  registry + layouts yields exactly what `zdb -dddddd tpool/ 2` reports —
  mode `100644`, size `20`, gen `11`, links `1`, uid/gid `0`, parent `34`,
  atime/crtime sec `1783939238` nsec `403052711`, mtime/ctime sec `1783939238`
  nsec `405052711`. SA header magic `0x2F505A`, `sa_layout_info` → layout `3`,
  header size `8`.
- **md5:** `e8eb4549bbe7a167a3a3c546a5d89153`
- **Consumed by:** `core/tests/sa.rs` (always-on, no env gate).

### `zfs_sa_dir_dnode.bin` (P3)

- **Class:** `REAL-self` (Tier-2). Object **3** (`/sub`) — a 512-byte directory
  dnode (`dn_type = 20`), SA bonus. Same block/extract as above, slot 3
  (offset 1536).
- **Independent-oracle checks it satisfies:** `decode_sa_bonus` matches
  `zdb -dddddd tpool/ 3` — mode `40755`, size `3`, links `2`, gen `11`.
- **md5:** `a4b481a3389ec821f89b568fee581d8a`
- **Consumed by:** `core/tests/sa.rs` (always-on, no env gate).

### `zfs_sa_registry.bin` (P3)

- **Class:** `REAL-self` (Tier-2). The **SA attribute registration** (object 35,
  named `REGISTRY` by the SA master node object 32) — a 1536-byte **micro-ZAP**
  of 22 entries, **uncompressed** on disk. Extracted with the `zdb` oracle:
  `zdb -R -e -p /media/psf/tmp/zfs tpool 0:0:600:r` (its L0 block, 1.5 KiB).
- **Encoding:** each entry's u64 value packs `[length:bswap:id]` per
  `ATTR_LENGTH(x)=BF32_GET(x,24,16)`, `ATTR_BSWAP(x)=BF32_GET(x,16,8)`,
  `ATTR_NUM(x)=BF32_GET(x,0,16)` (`sa_impl.h`). E.g. `ZPL_MODE = id 5, len 8`;
  `ZPL_ATIME = id 0, len 16`.
- **Independent-oracle checks it satisfies:** `parse_sa_registry` yields the 22
  attr names + ids/sizes `zdb -dddddd tpool/ 35` reports.
- **md5:** `4927c8159b5d150646d9788f12c7e920`
- **Consumed by:** `core/tests/sa.rs` (always-on, no env gate).

### `zfs_sa_layouts.bin` (P3)

- **Class:** `REAL-self` (Tier-2). The **SA attribute layouts** (object 36, named
  `LAYOUTS` by the SA master node) — a **fat-ZAP** (header block 0 ++ leaf
  block 1, each 16 KiB, **decompressed** from LZ4 and concatenated to 32 KiB).
  Extracted via the `zdb` oracle then inflated by the same LZ4 codec the reader
  uses: `zdb -R … 0:4018000:1000:r` (block 0) and `0:4017000:1000:r` (block 1).
- **Encoding:** each entry's name is the layout number (`"2"`, `"3"`) and its
  value is an array of `le_int_size = 2` (u16) attribute ids stored **big-endian**
  (the fat-ZAP value byte order). `zdb -dddddd tpool/ 36`:
  `2 = [5 6 4 12 13 7 11 0 1 2 3 8 16 19]`,
  `3 = [5 6 4 12 13 7 11 0 1 2 3 8 21 16 19]`.
- **Independent-oracle checks it satisfies:** `parse_sa_layouts` yields those two
  ordered attr-id arrays.
- **md5:** `3678d96bedd8fae56c0f93fddb15ee73`
- **Consumed by:** `core/tests/sa.rs` (always-on, no env gate).

### `zstd_frame.zst` + `zstd_frame.plain.txt` (zstd decode oracle)

- **Class:** `SYNTHETIC` (Tier-2). A raw zstd frame and its plaintext, used to
  validate the pure-Rust `ruzstd` zstd path (`compress::decompress` for
  `CompressType::Zstd`) with an **independent encoder** (the standard zstd CLI),
  never a self-encoded round-trip. `ruzstd` is decode-only, so the compressed
  input is committed rather than produced at test time.
- **Source / generator (verbatim):** the plaintext is the test string
  `"zstd payload zstd payload zstd payload"` repeated 8× (304 bytes), compressed
  once by the host **Zstandard CLI v1.5.6** (`zstd -3`):
  ```sh
  python3 -c "import sys; sys.stdout.buffer.write(b'zstd payload zstd payload zstd payload'*8)" > zstd_frame.plain.txt
  zstd -3 -c zstd_frame.plain.txt > zstd_frame.zst
  ```
  The reader wraps this raw frame in the 8-byte `zfs_zstd` header (which it
  skips) before decoding, so the fixture is the inner standard zstd frame.
- **Independent-oracle check it satisfies:** `decompress(Zstd, header ++ frame,
  304)` yields the plaintext byte-for-byte (encoder = zstd CLI, decoder = ruzstd
  — different implementations).
- **md5:** `zstd_frame.zst` `2ea131b849d4382ead6b695f42edf208`;
  `zstd_frame.plain.txt` `ab32f920c166630e3fd0a28066e610ac`.
- **sha256:** `zstd_frame.zst`
  `1cf620d47fd9cfdddbf2f631afdd7b56b2dd1784db84e1725759f6cd1edec1e7`;
  `zstd_frame.plain.txt`
  `d46d4f055f36e2f50376cc95ed754237abf8da2033d5d0a47e7744790f1b3f8c`.
- **Consumed by:** `core/src/compress.rs` unit test
  `zstd_decodes_committed_fixture` (always-on, no env gate).

### `zdb` ground truth (the independent oracle values the tests assert against)

From `sudo zdb -l zfs.img` (top-level nvlist config):

| field       | value                        |
|-------------|------------------------------|
| version     | 5000                         |
| name        | `tpool`                      |
| state       | 1                            |
| txg         | 22                           |
| pool_guid   | 11379600771744596893         |

`vdev_tree` (nested nvlist):

| field   | value                      |
|---------|----------------------------|
| type    | `file`                     |
| ashift  | 12                         |
| asize   | 532152320                  |
| guid    | 7150170430718702530        |

From `sudo zdb -uuuuu -e -p /media/psf/tmp/zfs tpool` (active uberblock):

| field       | value                        |
|-------------|------------------------------|
| magic       | `0x00bab10c` (little-endian) |
| version     | 5000                         |
| txg         | 22 (highest; ring slot 22)   |
| guid_sum    | 83027128753747807            |
| timestamp   | 1783939238 (2026-07-13 UTC)  |
| rootbp DVA[0] | `<0:c015000:1000>` (vdev 0, offset 0xc015000 bytes = 393384 sectors, asize 0x1000) |
| rootbp type | `L0 DMU objset`, fletcher4, uncompressed, LE, triple-ditto, size 0x1000L/0x1000P |

The uberblock ring has 32 slots of 4096 bytes (`slot_size = 2^ashift = 2^12`),
so the active slot index is `txg % 32 = 22`.

### P2 — MOS → DSL → ZPL navigation (from `zdb -dddddd`, byte-verified)

| step | object | zdb finding |
|------|--------|-------------|
| MOS object directory | 1 (fat-ZAP) | `root_dataset = 32` |
| DSL directory | 32 (`dsl_dir_phys_t` bonus) | `dd_head_dataset_obj = 54`, `dd_child_dir_zapobj = 34` |
| DSL dataset | 54 (`dsl_dataset_phys_t` bonus) | `ds_bp = <0:f000:1000>` → the ZPL objset |
| ZPL master node | 1 (micro-ZAP) | `ROOT = 34`, `VERSION = 5`, `SA_ATTRS = 32` |
| ZPL root directory | 34 (embedded micro-ZAP) | `foo.txt = 2` (reg file), `sub = 3` (directory) |

Verified byte-offsets (all against `zdb`): `dsl_dir_phys_t.dd_head_dataset_obj`
at bonus \@8; `dsl_dataset_phys_t.ds_bp` (a 128-byte `blkptr_t`) at bonus \@128;
micro-ZAP `mzap_ent_phys_t` = `mze_value`\@0 / `mze_cd`\@8 / `mze_name[50]`\@14,
64 bytes each; fat-ZAP leaf `ZAP_LEAF_ENTRY` chunk type 252, `ZAP_LEAF_ARRAY` 251,
values stored big-endian; embedded-blkptr `BPE_PAYLOAD` = bytes `[0,48) ++ [56,88)
++ [96,128)` of the 128-byte pointer, LZ4-framed with a 4-byte BE length prefix.

## Env-gated full images (NOT committed)

### `FreeBSD` ZFS-root partition — pointed to by `ZFS_TIER1_FREEBSD` (Tier-1, full read path)

- **Class:** `REAL-ext` (**Tier-1**). The `freebsd-zfs` GPT partition (5 GiB)
  carved from an official, vendor-authored **`FreeBSD` 14.3-RELEASE amd64
  ZFS-on-root** VM image. A genuine third-party artifact whose ground truth two
  independent OpenZFS implementations confirm — `zdb` and a live read-only kernel
  `zfs mount`. Its pool is a **single `disk` vdev** (not raidz), so `zfs-core`
  reads its data blocks with no parity reconstruction: the whole path
  label → uberblock → MOS → DSL → ZPL → SA → **file content** validates at Tier-1.
- **Source:** <https://download.freebsd.org/releases/VM-IMAGES/14.3-RELEASE/amd64/Latest/FreeBSD-14.3-RELEASE-amd64-zfs.qcow2.xz>
  (vendor-published **SHA256** `8bfcc2c6f3b3f259b0288b41db808328d98fe015f59432ffd8d69276829a9a8d`,
  ~811 MiB). The `-zfs.qcow2` is used deliberately: the 14.3 `-zfs.raw` shipped
  corrupt via a `makefs` bug (kernel panic on boot); the qcow2 is intact.
- **Preparation (verbatim — Parallels Ubuntu 24.04 VM, `qemu-utils` +
  `zfsutils-linux`; host `/tmp` shared at `/media/psf/tmp`):**
  ```bash
  # verify the vendor checksum, then decompress + convert to raw
  sha256sum FreeBSD-14.3-RELEASE-amd64-zfs.qcow2.xz   # == 8bfcc2c6…9a8d
  xz -dk FreeBSD-14.3-RELEASE-amd64-zfs.qcow2.xz
  qemu-img convert -O raw FreeBSD-14.3-RELEASE-amd64-zfs.qcow2 freebsd.raw
  parted -s freebsd.raw unit B print          # part 4 = freebsd-zfs (rootfs)
  # byte-exact extract of the freebsd-zfs partition (start/size NOT MiB-aligned)
  dd if=freebsd.raw of=freebsd-zfs.part bs=4M iflag=skip_bytes,count_bytes \
     skip=1108026880 count=5368709120 status=none
  ```
  Partition offset **1108026880** bytes, size **5368709120** bytes.
- **md5 of the extracted partition:** `22a711abfb33ca90e54676272034e216`.
- **Independent oracles (`zdb` + kernel mount):** `zdb -l freebsd-zfs.part` →
  pool `zroot`, `vdev_tree type 'disk'`, `ashift 12`, `vdev_children 1`,
  `pool_guid 4016146626377348012`; `zdb -e -p <dir> -u zroot` → active uberblock
  `magic 0x00bab10c` (LE), `version 5000`, **`txg 8`**. `FreeBSD` nests `/` in the
  child dataset **`zroot/ROOT/default`** (ID 30, the boot environment), reached
  via the DSL child-dir tree: root DSL dir (obj 3) `dd_child_dir_zapobj = 5` →
  `ROOT` (DSL dir 22) `dd_child_dir_zapobj = 24` → `default` (DSL dir 27)
  `dd_head_dataset_obj = 30`. A read-only kernel mount
  (`zpool import -o readonly=on -R /mnt -d /dev zroot; zfs mount zroot/ROOT/default`)
  and `zdb -R` block extraction both confirm the file hashes below.
- **Ground truth (the full-Tier-1 gate):**
  - real `/` listing (kernel `ls`, sorted): `.cshrc .profile COPYRIGHT bin boot dev
    etc firstboot lib libexec media mnt net proc rescue root sbin tmp usr var`.
  - `sha256(/.cshrc) = d1ba75d6e942aa2f17eb84061fe4edda1d17b9a9ab8e4e2ce3a19e650403b5d7`
    (size 1011, stored **uncompressed** — `zdb`: `1000L/1000P`).
  - `sha256(/COPYRIGHT) = 4ce916521645614401dd3f625bd534a2281c5e494fe50a631718de1a7c3fb064`
    (size 6109, uncompressed — `2000L/2000P`).
- **Consumed by:** `core/tests/tier1_freebsd.rs` →
  `freebsd_zfs_root_full_read_path_matches_zdb_and_mount`, which walks the full
  reader path (assembling only the child-dataset ZAP hop, which `zpl_objset` does
  not yet expose, from exported primitives) and asserts every value above. Extract
  the partition to `/tmp` (never under `~/src`) and set
  `ZFS_TIER1_FREEBSD=/tmp/zfs-freebsd/freebsd-zfs.part`. Skips cleanly when unset.

### `zol-0.6.1/` four vdevs — pointed to by `ZFS_TIER1_ZOL` (Tier-1)

- **Class:** `REAL-ext` (**Tier-1**), the same third-party `openzfs/zfs-images`
  `zol-0.6.1` raidz1 pool the committed L0 fixture comes from. Four 256 MiB
  (sparse) file-vdevs; not committed — freely re-downloadable from the source URL
  above (md5s above). Extract to `/tmp` (never under `~/src`) and set
  `ZFS_TIER1_ZOL=/tmp/zol061/zol-0.6.1`.
- **Consumed by:** `core/tests/tier1_zol061.rs` →
  `zol061_all_four_vdevs_bootstrap_independently`, which asserts each of the four
  raidz members independently decodes its own L0 bootstrap to the shared answer
  key. Skips cleanly when the env var is unset.

### `zfs.img` (512 MiB) — pointed to by `ZFS_ORACLE_IMG`

- **Class:** `REAL-self` (Tier-2), same pool. Gitignored (512 MiB). Tests that
  read it (`full_image_all_four_labels_agree`) skip cleanly when the env var is
  unset.
- **md5:** `c21d7810e706342321e5ee2a3121c676`
- Extract a working copy to `/tmp` (never under `~/src`); set
  `ZFS_ORACLE_IMG=/tmp/zfs/zfs.img`.

### `zfs_snap.img` (256 MiB) — pointed to by `ZFS_SNAP_ORACLE_IMG` (F-CARVE oracle)

- **Class:** `REAL-self` (Tier-2). A **snapshot-deletion** pool minted to prove
  `zfs-forensic`'s CoW deleted-file recovery (F-CARVE). Gitignored (256 MiB);
  the `forensic/tests/carve.rs` tests skip cleanly when the env var is unset.
- **md5:** `38af336fbb188700b8720819946fc527`
- **What it is:** an OpenZFS pool `dtpool` (ashift 12, compression off) in which
  `/secret.txt` (36 bytes) was written, the snapshot `dtpool@snap1` taken, and
  then `/secret.txt` `rm`'d + synced. `/keep.txt` was written and never deleted.
- **Ground truth (the recovery gate), recorded pre-delete:**
  - `sha256(/secret.txt) = 312799a19921d2f13936c837d165496afa8775be3dd1967e9128e4e41f5c7bcd`
  - `sha256(/keep.txt)   = 15fee6664fa150228e3d3d4f8516655c9f748995f8bfecda430f2c2ad23a7411`
- **Independent-oracle (`zdb`) structural checks:** `zdb -d` reports three
  datasets — `mos [META] ID 0`, `dtpool [ZPL] ID 54` (7 objects, live), and
  `dtpool@snap1 [ZPL] ID 86` (8 objects, the snapshot). `zdb -dddddd
  dtpool@snap1` shows the snapshot's root dir (object 34) still lists
  `secret.txt = 2` and `keep.txt = 3`, while live `dtpool`'s root lists only
  `keep.txt`. The deleted file is object **2** (`/secret.txt`, SA bonus, size
  36, mode 100600, parent 34; content at DVA `0:400d000:1000`).
- **DSL traversal the recovery follows** (all `zdb -dddd`-verified):
  MOS object directory (obj 1) `root_dataset = 32` → DSL dir 32
  `dd_head_dataset_obj = 54` → head DSL dataset 54 bonus `ds_prev_snap_obj = 86`
  → snapshot DSL dataset 86 bonus `ds_bp = <0:2012000:1000>` → the snapshot's
  ZPL objset (retaining the deleted file). `ds_prev_snap_obj` is
  `dsl_dataset_phys_t` bonus offset 8; `ds_bp` is bonus offset 128.
- Extract a working copy to `/tmp` (never under `~/src`); set
  `ZFS_SNAP_ORACLE_IMG=/tmp/zfs/zfs_snap.img`.

**Uberblock-history (best-effort) note:** the alternate F-CARVE path — walking
an OLDER uberblock in the 128-slot ring to reach a previous txg's MOS/ZPL state —
is inherently *state-dependent*: it recovers a deleted file only while the old
tree blocks remain un-overwritten by CoW, so it returns nothing (never a
fabricated result) once they are reused. The **snapshot** path is the reliable
one (a snapshot pins the pre-delete blocks against reuse), which is why the
recovery gate above validates the snapshot path.

### Mint command (snapshot-deletion oracle — verbatim)

```bash
IMG=/media/psf/tmp/zfs/zfs_snap.img
zpool destroy dtpool 2>/dev/null || true; rm -f "$IMG"
truncate -s 256M "$IMG"
zpool create -o ashift=12 -O compression=off -O atime=off dtpool "$IMG"
printf 'deleted zfs forensic secret payload\n' > /dtpool/secret.txt
printf 'this file stays alive\n'                > /dtpool/keep.txt
sync
sha256sum /dtpool/secret.txt /dtpool/keep.txt   # pre-delete ground truth
zfs snapshot dtpool@snap1                        # PIN the pre-delete state
rm -f /dtpool/secret.txt ; sync                  # delete from live
zpool export dtpool
# independent oracle (zdb): datasets incl. the snapshot, and the retained file
zdb -d     -e -p /media/psf/tmp/zfs dtpool
zdb -dddddd -e -p /media/psf/tmp/zfs dtpool@snap1   # root dir still lists secret.txt = 2
```

## Mint commands (verbatim — reproduce the corpus)

Run on a Linux host with OpenZFS installed (here: Parallels **Ubuntu 24.04 (with
Rosetta)**, `zfs-2.2.2-0ubuntu9.4`, aarch64 → little-endian pool). The host
`/tmp/zfs` is shared into the VM at `/media/psf/tmp/zfs`.

```bash
sudo apt-get install -y zfsutils-linux
sudo modprobe zfs

IMG=/media/psf/tmp/zfs/zfs.img
truncate -s 512M "$IMG"
sudo zpool create -o ashift=12 -O compression=off -O atime=off tpool "$IMG"

printf 'hello zfs forensics\n'  | sudo tee /tpool/foo.txt >/dev/null
sudo mkdir -p /tpool/sub
printf 'nested file content\n'  | sudo tee /tpool/sub/bar.txt >/dev/null
sync
sha256sum /tpool/foo.txt /tpool/sub/bar.txt   # content ground truth (later phases)
sudo zpool export tpool

# --- independent oracle (zdb, a separate implementation) ---
sudo zdb -l  "$IMG"                             # 4 vdev labels + XDR nvlist config
sudo zdb -lu "$IMG"                             # + uberblock array
sudo zdb -uuuuu -e -p /media/psf/tmp/zfs tpool  # active uberblock + rootbp

# --- extract committed fixtures ---
dd if="$IMG" of=zfs_label0.bin bs=1 count=262144   # L0 label (256 KiB)

# P1: raw block reads by DVA (pool exported; zdb -R needs -e -p). The :r flag
# dumps the raw block (post-compression, PSIZE bytes) to stdout.
zdb -R -e -p /media/psf/tmp/zfs tpool 0:c015000:1000:r > zfs_mos_objset.bin
zdb -R -e -p /media/psf/tmp/zfs tpool 0:4025000:1000:r > zfs_mos_l1_indirect_lz4.bin
# 0:c015000  = rootbp DVA[0] (the MOS objset block, uncompressed).
# 0:4025000  = the meta-dnode blkptr[0] DVA[0] (the LZ4 L1 indirect block);
#              its byte offset = (meta-dnode blkptr[0].offset_sectors << 9).

# P2: ZAP fixtures. zdb -R :r dumps the raw (compressed) block; the LZ4 inflate +
# BPE-payload gather + concatenation are done in-code (the same codec the reader
# uses). DVAs from `zdb -dddddd`:
zdb -R -e -p /media/psf/tmp/zfs tpool 0:4008000:1000:r  # MOS objdir fat-ZAP block 0 (header)
zdb -R -e -p /media/psf/tmp/zfs tpool 0:4009000:1000:r  # MOS objdir fat-ZAP block 1 (leaf)
#   -> LZ4-inflate each to 16 KiB, concatenate -> zfs_zap_fat_objdir.bin (32 KiB).
zdb -R -e -p /media/psf/tmp/zfs tpool 0:4002000:1000:r  # ZPL master micro-ZAP (first 512 B) -> zfs_zap_micro_master.bin
zdb -R -e -p /media/psf/tmp/zfs tpool 0:401b000:1000:r  # ZPL dnode block objs 32-63 (LZ4)
#   -> inflate, take obj 34 dnode blkptr[0], gather 112-B BPE payload, LZ4-inflate
#      (4-byte BE prefix) to 512 B -> zfs_zap_micro_root.bin.

# P3: SA metadata + file content fixtures. DVAs from `zdb -dddddd`.
zdb -R -e -p /media/psf/tmp/zfs tpool 0:401a000:1000:r  # ZPL dnode block objs 0-31 (LZ4)
#   -> inflate to 16 KiB, slot 2 (off 1024) -> zfs_sa_file_dnode.bin (foo.txt, obj 2)
#   ->                    slot 3 (off 1536) -> zfs_sa_dir_dnode.bin  (sub, obj 3)
zdb -R -e -p /media/psf/tmp/zfs tpool 0:0:600:r         # SA REGISTRY (obj 35) micro-ZAP, uncompressed -> zfs_sa_registry.bin
zdb -R -e -p /media/psf/tmp/zfs tpool 0:4018000:1000:r  # SA LAYOUTS (obj 36) fat-ZAP block 0 (header, LZ4)
zdb -R -e -p /media/psf/tmp/zfs tpool 0:4017000:1000:r  # SA LAYOUTS (obj 36) fat-ZAP block 1 (leaf, LZ4)
#   -> LZ4-inflate each to 16 KiB, concatenate -> zfs_sa_layouts.bin (32 KiB).
```

### P3 — SA / znode metadata + content ground truth (from `zdb -dddddd`, byte-verified)

| object | zdb finding |
|--------|-------------|
| 2 `/foo.txt` | SA bonus (layout 3): mode 100644, size 20, gen 11, links 1, uid/gid 0, parent 34; content `hello zfs forensics\n` (sha256 below) |
| 3 `/sub` | SA bonus: mode 40755, size 3, links 2, gen 11; directory ZAP `bar.txt = 128` |
| 128 `/sub/bar.txt` | SA bonus: mode 100644, size 20, parent 3; content sha256 below |
| 32 `SA_ATTRS` | SA master micro-ZAP: `REGISTRY = 35`, `LAYOUTS = 36` |
| 35 `REGISTRY` | 22 attrs, each `[len:bswap:id]`; `ZPL_MODE = [8:0:5]`, `ZPL_ATIME = [16:0:0]`, … |
| 36 `LAYOUTS` | `2 = [5 6 4 12 13 7 11 0 1 2 3 8 16 19]`, `3 = [5 6 4 12 13 7 11 0 1 2 3 8 21 16 19]` |

Verified layout (against OpenZFS `sa_impl.h` + `zfs_znode.h`, cross-checked vs `zdb`):
`sa_hdr_phys_t` = `sa_magic` u32 \@0 (`SA_MAGIC = 0x2F505A`), `sa_layout_info` u16
\@4 where `SA_HDR_LAYOUT_NUM = BF32_GET(info,0,10)` and
`SA_HDR_SIZE = BF32_GET_SB(info,10,6,3,0) = ((info>>10)&0x3f)<<3` bytes; packed
attributes follow at `hdrsz`, each in registry order for the layout, sizes from
the registry (u64 scalars; timestamps are `[u64 sec, u64 nsec]`). Legacy
`znode_phys_t` (bonustype 17, 264 bytes): atime/mtime/ctime/crtime `[sec,nsec]`
\@0/16/32/48, gen \@64, mode \@72, size \@80, parent \@88, links \@96.

### Content ground truth (for later file-read phases, not P0)

```
e597509763371d8a0bad983118b63911217040632e9c9d4d9cbcf6b7da3fb00d  /tpool/foo.txt
e68db4521d8c341f11de6231fabd41ac8e35655934b7dced82db76465047c04b  /tpool/sub/bar.txt
```
