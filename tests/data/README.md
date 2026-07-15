# zfs-forensic test data — provenance

Single machine-index of the fleet corpus lives in
`~/src/issen/docs/corpus-catalog.md`; this file is the co-located human-facing
detail. Cross-reference, do not duplicate.

<!-- TODO(corpus-catalog): add these zfs-forensic entries (zfs_label0.bin,
     zfs_mos_objset.bin, zfs_mos_l1_indirect_lz4.bin, zfs_zap_fat_objdir.bin,
     zfs_zap_micro_master.bin, zfs_zap_micro_root.bin + the env-gated zfs.img) to
     issen/docs/corpus-catalog.md when the P0/P1/P2 work is folded into the fleet
     catalog. -->

## Committed fixtures

### `zfs_label0.bin`

- **Class:** `REAL-self` (Tier-2). Self-minted real OpenZFS pool; the ground
  truth is vouched for by `zdb` — a **separate, independent implementation** (the
  ZFS debugger), not by us. A genuine Tier-1 artifact would be a third-party ZFS
  image with an external answer key; none is published for ZFS, so this is the
  best available oracle tier. `zdb` is the independent structural oracle.
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

## Env-gated full image (NOT committed)

### `zfs.img` (512 MiB) — pointed to by `ZFS_ORACLE_IMG`

- **Class:** `REAL-self` (Tier-2), same pool. Gitignored (512 MiB). Tests that
  read it (`full_image_all_four_labels_agree`) skip cleanly when the env var is
  unset.
- **md5:** `c21d7810e706342321e5ee2a3121c676`
- Extract a working copy to `/tmp` (never under `~/src`); set
  `ZFS_ORACLE_IMG=/tmp/zfs/zfs.img`.

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
```

### Content ground truth (for later file-read phases, not P0)

```
e597509763371d8a0bad983118b63911217040632e9c9d4d9cbcf6b7da3fb00d  /tpool/foo.txt
e68db4521d8c341f11de6231fabd41ac8e35655934b7dced82db76465047c04b  /tpool/sub/bar.txt
```
