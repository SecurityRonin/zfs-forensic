# zfs-forensic test data — provenance

Single machine-index of the fleet corpus lives in
`~/src/issen/docs/corpus-catalog.md`; this file is the co-located human-facing
detail. Cross-reference, do not duplicate.

<!-- TODO(corpus-catalog): add these zfs-forensic entries (zfs_label0.bin +
     the env-gated zfs.img) to issen/docs/corpus-catalog.md when the P0 work is
     folded into the fleet catalog. -->

## Committed fixture

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

# --- extract committed fixture ---
dd if="$IMG" of=zfs_label0.bin bs=1 count=262144   # L0 label (256 KiB)
```

### Content ground truth (for later file-read phases, not P0)

```
e597509763371d8a0bad983118b63911217040632e9c9d4d9cbcf6b7da3fb00d  /tpool/foo.txt
e68db4521d8c341f11de6231fabd41ac8e35655934b7dced82db76465047c04b  /tpool/sub/bar.txt
```
