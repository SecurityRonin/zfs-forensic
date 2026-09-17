

#### zfs_sa.img.gz / zfs_dir.img.gz — extended attributes, both storage modes

- **Class:** `REAL-self` (Tier-2). Two self-minted OpenZFS pools, one per
  `xattr` storage mode, with `zdb` and `lsextattr` as independent oracles.
- **Why two images.** ZFS stores extended attributes two structurally unrelated
  ways and the choice is a dataset property, so a reader handling only one
  silently reports "no attributes" on half the pools it meets:

  | `xattr=` | storage |
  |---|---|
  | `sa` | packed **nvlist** in the `ZPL_DXATTR` System Attribute |
  | `dir` | hidden **ZAP directory**, each attribute a separate file object |

- **Source:** minted inside a **FreeBSD 15.0-RELEASE arm64 guest** under
  qemu/HVF. FreeBSD is where `setextattr`/`lsextattr` live; no Linux host in
  this fleet has OpenZFS installed.
- **Generator (verbatim), per mode:**

  ```sh
  truncate -s 192M zfs_$mode.img
  zpool create -o ashift=12 -O compression=off -O atime=off -O xattr=$mode \
      xp$mode /root/zfs_$mode.img
  printf 'hello zfs xattrs\n' > /xp$mode/file.txt
  setextattr user small   'tiny-value'         /xp$mode/file.txt
  setextattr user comment 'a second attribute' /xp$mode/file.txt
  mkdir /xp$mode/adir
  setextattr user ondir 'on-a-directory' /xp$mode/adir
  sync; zpool export xp$mode
  ```

  The attributes are set on the **root dataset** so the pool's own ZPL objset
  carries them, which is what `zpl_objset` reaches.

- **The mode is confirmed by the filesystem, not by the command.**
  `zfs get -H -o value xattr` returns `sa` and `dir` respectively.
- **Ground truth:** `lsextattr -q user` read both attributes back through the
  FreeBSD kernel, and `zdb -e -p /root -dddd xpsa 2` reports the SA side
  structurally:

  ```text
       2    1   128K    512     4K     512    512  100.00  ZFS plain file
                                            292   bonus  System attributes
      SA xattrs: 108 bytes, 2 entries
          small = tiny-value
          comment = a second attribute
  ```

- **Scope limit — the spill path is NOT covered.** At 108 bytes the `DXATTR`
  nvlist fits the 292-byte bonus and the dnode carries no `SPILL_BLKPTR` flag.
  A larger attribute set moves `DXATTR` to a spill block; an earlier 256 MiB
  pool did produce a 3132-byte `DXATTR` that way. That shape has no committed
  sample, so the reader does not implement it and exposes
  `has_unread_spill_xattrs` instead, letting a caller tell "not recovered" from
  "none present".
- **`file.txt` is object 2 in both pools**; `adir` is 128 (`sa`) and 384 (`dir`).
- **Redistribution:** none — self-minted.
- **Committed gzipped** (192 MiB → 325 KiB and 334 KiB).
- **MD5 (gz):** `26dfb96abebc7b10f4597e1618ee032a` / `a364763c043beae6c42e53c1dd0f202e`
- **MD5 (raw):** `64a13ab50e4a145228a61040b8fd5773` / `2c32c041a3a9d48d65ebe9fed79baca5`
- **Used by:** `core/tests/xattr.rs`
