//! `impl forensic_vfs::FileSystem for ZfsFs` — the forensic-vfs adapter
//! (behind the `vfs` feature).
//!
//! [`ZfsFs`] mounts a ZFS pool's root dataset onto the
//! [`forensic_vfs::FileSystem`] contract, so a ZFS filesystem composes as
//! `Arc<dyn FileSystem>` in the forensic-vfs engine and is auto-detected through
//! the same probe registry as NTFS/ext4/APFS/XFS/… — a consumer never names
//! `zfs_core` (ADR-0011).
//!
//! ## Detection: the label nvlist config, not a byte magic
//!
//! ZFS writes **no fixed-offset filesystem magic**. Its one structural marker is
//! the uberblock ring, which begins 128 KiB into every vdev label — and the
//! resolver's head sniff window is capped at 128 KiB, so the window
//! `[0, 131072)` can never carry an uberblock. The label's **XDR nvlist config**
//! does sit inside it: `[NVLIST_OFFSET, NVLIST_OFFSET + NVLIST_SIZE)` =
//! `[16384, 131072)`. [`zfs_probe`] therefore parses that config and requires the
//! pool-identity keys every ZFS label carries — `version`, `pool_guid`, and the
//! nested `vdev_tree` — which is a structural check on a parsed structure rather
//! than a byte-magic guess, and it declines cleanly on anything else.
//!
//! ## The `&[u8]`-vs-positioned-read bridge
//!
//! `zfs-core` is a **slice reader**: [`crate::read_block`], [`crate::mos_dnode`],
//! and the `zpl_*` walk all take the whole vdev as `&[u8]` (vdev byte 0), because
//! a DVA is a vdev-relative offset that can point anywhere. A forensic-vfs
//! [`DynSource`] is a positioned-read byte source. The adapter bridges the two by
//! reading the **entire source into an owned `Vec<u8>` once at [`ZfsFs::open`]**
//! and serving every subsequent call from that buffer — the same choice the
//! UFS/XFS/btrfs adapters make for their slice readers.
//!
//! ## Bootstrap is validated and fails LOUD
//!
//! Mounting walks a prerequisite chain — uberblock ring → `rootbp` → MOS objset →
//! MOS object directory → DSL dir → DSL dataset → ZPL objset → master node →
//! root directory. A failure anywhere in it is a [`VfsError::Bootstrap`] naming
//! the stage and the offending value, never an empty-but-successful mount: an
//! "empty pool" and "we could not resolve the pool" must not look alike. The
//! bootstrap is then *validated* — the resolved dataset objset must report
//! `os_type == DMU_OST_ZFS` — before any listing is trusted.
//!
//! ## Honest scope of this adapter
//!
//! - **Namespace + content.** `read_dir` / `lookup` / `meta` / `read_at` /
//!   `extents` serve the pool's **root dataset** (the `root_dataset` the MOS
//!   object directory names). Other datasets and snapshots are reached through
//!   `zfs-forensic`'s analyzer surface, not this single-filesystem mount.
//! - **`deleted` / `unallocated` are empty by design, not by omission.** ZFS is
//!   copy-on-write: a deleted file leaves no tombstone in the live namespace, and
//!   recovery is a *snapshot* walk (`zfs_forensic::recover_deleted`), not a
//!   scan of this dataset. Free space lives in per-metaslab space maps, which
//!   `zfs-core` does not decode. Returning empty streams reports exactly what the
//!   reader knows; it never fabricates a run.
//! - **`extents` yields the L0 data runs it can address.** A hole contributes no
//!   run (it has no physical location — emitting offset 0 would name the vdev
//!   label as a file's data). An *embedded* blkptr carries its payload inline in
//!   the pointer, so it likewise has no byte run. Gang blocks and ditto copies
//!   past DVA[0] are not expanded.
//! - **`read_link` reconstructs a "slow" symlink** whose target lives in the
//!   object's data block. A ZFS "fast" symlink stores its target in the SA bonus
//!   under `ZPL_SYMLINK`, which [`crate::ZplAttrs`] does not decode, so such a
//!   link reads as an empty target rather than a guess.

use std::sync::Arc;

use forensic_vfs::{
    Allocation, ByteRun, Confidence, DirEntry as VfsDirEntry, DirStream, DynSource, ExtentStream,
    FileId, FileSystem, FsKind, FsMeta, MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc,
    RunFlags, RunInfo, SectorSizes, SniffWindow, StreamId, StreamInfo, StreamKind, TimeResolution,
    TimeSource, TimeStamp, TimeZonePolicy, VfsError, VfsResult,
};

use crate::blkptr::Blkptr;
use crate::dnode::{Dnode, BLKPTR_SIZE};
use crate::label::{
    active_uberblock, label_offsets, NVLIST_OFFSET, NVLIST_SIZE, UBERBLOCK_RING_OFFSET,
    UBERBLOCK_RING_SIZE,
};
use crate::nvlist::NvList;
use crate::objset::{ObjsetPhys, DMU_OST_ZFS};
use crate::read::{mos_dnode, read_block, MAX_INDIRECT_LEVELS};
use crate::sa::{SaLayouts, SaRegistry, ZplAttrs};
use crate::uberblock::{Uberblock, UBERBLOCK_MIN_SHIFT};
use crate::zap::{read_zap_object, zap_list};
use crate::zpl::{
    zpl_attrs, zpl_master_root, zpl_objset, zpl_read_file_with, zpl_sa_context, ZPL_DIRENT_OBJ_MASK,
};

/// `ZIO_COMPRESS_OFF` — the compression enum value meaning "stored raw". `0` is
/// `ZIO_COMPRESS_INHERIT`, which on a written block also means no compression was
/// applied at this pointer.
const ZIO_COMPRESS_OFF: u8 = 2;

/// ZFS's default dataset `recordsize` (128 KiB), used for
/// [`SectorSizes::cluster_or_block`] when the root directory object reports no
/// data block size. ZFS record size is per-object and variable, so this field is
/// indicative only.
const DEFAULT_RECORD_SIZE: u32 = 128 * 1024;

/// Upper bound on the number of L0 block pointers [`ZfsFs::extents`] will gather
/// for one object — an allocation-bomb guard, since a hostile `dn_nlevels` plus
/// wide indirect blocks could otherwise fan out without limit.
const MAX_RUNS: usize = 65_536;

/// POSIX `S_IFMT` — the file-type bits of a mode word.
const S_IFMT: u64 = 0o170_000;

/// ZPL dirent type shift: the `ZFS_DIRENT_TYPE` bits occupy the top 4 bits of a
/// directory ZAP entry's value.
const DIRENT_TYPE_SHIFT: u32 = 60;

/// Whether a parsed nvlist looks like a ZFS **pool config**: every vdev label
/// carries `version`, `pool_guid`, and the nested `vdev_tree`. Requiring all
/// three keeps an unrelated XDR nvlist from being claimed as a pool.
fn is_pool_config(list: &NvList) -> bool {
    list.get_u64("version").is_some()
        && list.get_u64("pool_guid").is_some()
        && list.get_nvlist("vdev_tree").is_some()
}

/// The packed nvlist config region of the label that starts at `base` in `image`.
fn config_region(image: &[u8], base: usize) -> Option<&[u8]> {
    let start = base.checked_add(NVLIST_OFFSET)?;
    let end = start.saturating_add(NVLIST_SIZE).min(image.len());
    image.get(start..end)
}

/// Parse the pool config from the L0 vdev label, if it is present and well
/// formed. Used for [`FileSystem::volume_label`] (the pool name) — never for
/// bootstrap, so a wiped config cannot block a mount.
fn pool_config(image: &[u8]) -> Option<NvList> {
    let region = config_region(image, 0)?;
    crate::nvlist_parse(region).ok().filter(is_pool_config)
}

/// Probe a sniff window for a ZFS pool by parsing the L0 vdev label's XDR nvlist
/// config at [`NVLIST_OFFSET`] and requiring the pool-identity keys
/// ([`is_pool_config`]).
///
/// A definite [`Confidence::Yes`] on a hit, [`Confidence::No`] otherwise —
/// panic-free (a short window, a non-XDR buffer, or a config missing any
/// identity key all decline). Only a window based at absolute 0 can carry the L0
/// label, so a mid-image window declines rather than misreading an interior
/// block as a label.
///
/// Exposed so the engine registers it without re-deriving the layout, and so
/// tests drive the probe directly.
#[must_use]
pub fn zfs_probe(w: &SniffWindow) -> Confidence {
    if w.base() != 0 {
        return Confidence::No;
    }
    let Some(region) = config_region(w.bytes(), 0) else {
        return Confidence::No;
    };
    match crate::nvlist_parse(region) {
        Ok(list) if is_pool_config(&list) => Confidence::Yes {
            how: "ZFS vdev label nvlist config (version + pool_guid + vdev_tree) at label offset 16384",
        },
        _ => Confidence::No,
    }
}

/// The active uberblock across every vdev label present in `image`: the valid
/// slot with the highest `txg`.
///
/// The ring is scanned at the **minimum** 1 KiB slot granularity
/// ([`UBERBLOCK_MIN_SHIFT`]) rather than the pool's `ashift`-derived slot size.
/// A larger slot size is always a multiple of 1 KiB, so its uberblocks still land
/// on scanned boundaries — a 1 KiB scan therefore finds the active uberblock at
/// any `ashift`, without trusting the (possibly wiped) nvlist config to tell us
/// what `ashift` is.
fn active_uberblock_across_labels(image: &[u8]) -> Option<Uberblock> {
    let (front, back) = label_offsets(image.len() as u64);
    let mut best: Option<Uberblock> = None;
    for off in front.into_iter().chain(back.into_iter().flatten()) {
        let Ok(base) = usize::try_from(off) else {
            continue; // cov:unreachable: label_offsets returns offsets bounded by image.len(), which came from a usize, so usize::try_from always succeeds on a 64-bit target; kept so a 32-bit build degrades instead of panicking.
        };
        let Some(ring_start) = base.checked_add(UBERBLOCK_RING_OFFSET) else {
            continue; // cov:unreachable: base <= image.len() and the ring offset is 128 KiB, so the sum cannot overflow usize; kept as a guard against a future caller passing an unbounded base.
        };
        let ring_end = ring_start
            .saturating_add(UBERBLOCK_RING_SIZE)
            .min(image.len());
        let Some(ring) = image.get(ring_start..ring_end) else {
            continue;
        };
        let slot_size = 1usize << UBERBLOCK_MIN_SHIFT;
        let slots = ring.len() / slot_size;
        if let Some((ub, _slot)) = active_uberblock(ring, slot_size, slots) {
            match &best {
                Some(cur) if ub.txg <= cur.txg => {}
                _ => best = Some(ub),
            }
        }
    }
    best
}

/// Map a POSIX mode's `S_IFMT` bits to the unified node kind.
fn node_kind_from_mode(mode: u64) -> NodeKind {
    match mode & S_IFMT {
        0o100_000 => NodeKind::File,
        0o040_000 => NodeKind::Dir,
        0o120_000 => NodeKind::Symlink,
        0o020_000 | 0o060_000 => NodeKind::Device,
        _ => NodeKind::Other,
    }
}

/// Map a ZPL directory-entry type code (`ZFS_DIRENT_TYPE`, the top 4 bits of a
/// directory ZAP value — the POSIX `DT_*` codes) to the unified node kind.
fn node_kind_from_dirent(dt: u64) -> NodeKind {
    match dt {
        8 => NodeKind::File,
        4 => NodeKind::Dir,
        10 => NodeKind::Symlink,
        2 | 6 => NodeKind::Device,
        _ => NodeKind::Other,
    }
}

/// Convert a ZFS `(seconds, nanoseconds)` timestamp to a VFS [`TimeStamp`] with
/// SA/znode provenance and nanosecond resolution.
fn to_ts(ts: (u64, u64)) -> TimeStamp {
    TimeStamp {
        unix_nanos: i128::from(ts.0) * 1_000_000_000 + i128::from(ts.1),
        source: TimeSource::InodeTable,
        resolution: TimeResolution::Nanos,
    }
}

/// Translate a `zfs-core` reader error into a VFS decode error, preserving the
/// underlying diagnostic.
fn decode_err(e: &crate::ZfsError) -> VfsError {
    VfsError::Decode {
        layer: "zfs",
        offset: 0,
        detail: e.to_string(),
        bytes: forensic_vfs::SmallHex::new(&[]),
    }
}

/// A ZFS object id could not be addressed as a VFS [`FileId`].
fn bad_file_id(id: FileId) -> VfsError {
    VfsError::Unsupported {
        layer: "zfs file-id",
        scheme: format!("{id:?} (ZFS addresses objects by object id: FileId::Opaque)"),
    }
}

/// The ZFS object id behind a [`FileId`].
fn object_of(id: FileId) -> VfsResult<u64> {
    match id {
        FileId::Opaque(n) => Ok(n),
        other => Err(bad_file_id(other)),
    }
}

/// A mounted ZFS pool's root dataset, presented as a `forensic-vfs`
/// [`FileSystem`].
pub struct ZfsFs {
    /// The whole vdev, owned — a DVA is a vdev-relative offset, so every read
    /// resolves against this buffer (see the module note on the bridge).
    image: Vec<u8>,
    /// The root dataset's ZPL objset (validated `os_type == DMU_OST_ZFS`).
    zpl: ObjsetPhys,
    /// The SA attribute registry/layouts for this dataset. Default (empty) when
    /// the dataset has no SA context; legacy `znode_phys_t` bonuses still decode,
    /// so an empty registry degrades rather than failing.
    registry: SaRegistry,
    layouts: SaLayouts,
    /// The root directory's object id (the master node's `ROOT`).
    root_id: u64,
    /// Indicative record size for [`SectorSizes::cluster_or_block`].
    record_size: u32,
    /// The pool name from the label config, when the config is readable.
    pool_name: Option<String>,
}

impl ZfsFs {
    /// Read `source` in full and bootstrap the pool: active uberblock → MOS →
    /// DSL → the root dataset's ZPL objset → master node → root directory.
    ///
    /// # Errors
    ///
    /// [`VfsError::Bootstrap`] naming the stage that failed (and the offending
    /// value) for any hop in the prerequisite chain, and if the resolved dataset
    /// objset is not a ZPL filesystem (`os_type != DMU_OST_ZFS`). [`VfsError::Io`]
    /// propagates a source read failure.
    pub fn open(source: &DynSource) -> VfsResult<Self> {
        let image = read_all(source)?;

        let ub = active_uberblock_across_labels(&image).ok_or_else(|| VfsError::Bootstrap {
            stage: "zfs uberblock ring",
            detail: format!(
                "no slot carrying UBERBLOCK_MAGIC 0x00bab10c in any vdev label of a {} byte source \
                 (scanned label offsets {:?} at 1 KiB granularity)",
                image.len(),
                label_offsets(image.len() as u64),
            ),
        })?;

        let rootbp = ub.rootbp_full();
        let mos_block = read_block(&image, &rootbp).map_err(|e| VfsError::Bootstrap {
            stage: "zfs MOS objset block (uberblock rootbp)",
            detail: format!(
                "txg {}, rootbp DVA[0] vdev {} offset_sectors {} -> byte {}: {e}",
                ub.txg,
                rootbp.dvas[0].vdev,
                rootbp.dvas[0].offset_sectors,
                rootbp.dvas[0].physical_byte_offset(),
            ),
        })?;
        let mos =
            ObjsetPhys::parse(&mos_block.data, ub.endian).map_err(|e| VfsError::Bootstrap {
                stage: "zfs MOS objset",
                detail: format!("txg {}: {e}", ub.txg),
            })?;

        let zpl = zpl_objset(&image, &mos).ok_or_else(|| VfsError::Bootstrap {
            stage: "zfs MOS object directory -> DSL dir -> DSL dataset -> ZPL objset",
            detail: format!(
                "the root_dataset chain did not resolve to a readable objset (MOS os_type {}, \
                 endian {:?})",
                mos.os_type, mos.endian,
            ),
        })?;

        // Validate the bootstrap before trusting any listing: the resolved
        // dataset must actually be a ZPL filesystem objset.
        if zpl.os_type != DMU_OST_ZFS {
            return Err(VfsError::Bootstrap {
                stage: "zfs dataset objset type",
                detail: format!(
                    "resolved objset os_type {} is not DMU_OST_ZFS ({DMU_OST_ZFS})",
                    zpl.os_type,
                ),
            });
        }

        let root_id = zpl_master_root(&image, &zpl).ok_or_else(|| VfsError::Bootstrap {
            stage: "zfs ZPL master node ROOT entry",
            detail: "the master node (object 1) named no ROOT directory".to_owned(),
        })?;

        let (registry, layouts) = zpl_sa_context(&image, &zpl).unwrap_or_default();
        let record_size = mos_dnode(&image, &zpl, root_id)
            .map(|d| d.data_block_size())
            .and_then(|n| u32::try_from(n).ok())
            .filter(|&n| n != 0)
            .unwrap_or(DEFAULT_RECORD_SIZE);
        let pool_name = pool_config(&image)
            .as_ref()
            .and_then(|c| c.get_str("name").map(ToOwned::to_owned));

        Ok(Self {
            image,
            zpl,
            registry,
            layouts,
            root_id,
            record_size,
            pool_name,
        })
    }

    /// The dnode of ZFS object `id` within the mounted dataset.
    fn dnode(&self, id: FileId) -> VfsResult<Dnode> {
        let obj = object_of(id)?;
        mos_dnode(&self.image, &self.zpl, obj).ok_or(VfsError::OutOfRange {
            what: "zfs object id (absent or an empty dnode slot)",
            offset: obj,
            len: 1,
            bound: 0,
        })
    }

    /// The decoded ZPL attributes of object `obj`, when its bonus decodes.
    fn attrs(&self, obj: u64) -> Option<ZplAttrs> {
        zpl_attrs(&self.image, &self.zpl, &self.registry, &self.layouts, obj)
    }

    /// The `(name, object_id, kind)` triples of directory object `obj`, read from
    /// its ZAP with the `ZFS_DIRENT_TYPE` bits preserved (so the entry kind comes
    /// from the directory itself, not from a second lookup per child).
    fn dir_entries(&self, obj: u64) -> VfsResult<Vec<(Vec<u8>, u64, NodeKind)>> {
        let dnode = mos_dnode(&self.image, &self.zpl, obj).ok_or(VfsError::OutOfRange {
            what: "zfs directory object id (absent or an empty dnode slot)",
            offset: obj,
            len: 1,
            bound: 0,
        })?;
        let data = read_zap_object(&self.image, &dnode).map_err(|e| decode_err(&e))?;
        Ok(zap_list(&data)
            .into_iter()
            .map(|(name, raw)| {
                let child = raw & ZPL_DIRENT_OBJ_MASK;
                let kind = node_kind_from_dirent((raw >> DIRENT_TYPE_SHIFT) & 0xF);
                (name.into_bytes(), child, kind)
            })
            .collect())
    }

    /// Every addressable L0 block pointer of `dnode`, descending the indirect
    /// tree. Holes and embedded pointers are dropped (they name no byte run) and
    /// the total is capped at [`MAX_RUNS`].
    fn l0_blkptrs(&self, dnode: &Dnode) -> Vec<Blkptr> {
        let mut level: Vec<Blkptr> = dnode
            .blkptrs
            .iter()
            .copied()
            .filter(|b| !b.is_hole())
            .take(MAX_RUNS)
            .collect();
        let mut remaining_levels = dnode.dn_nlevels.min(MAX_INDIRECT_LEVELS);
        while remaining_levels > 1 && !level.is_empty() {
            remaining_levels -= 1;
            let mut next = Vec::new();
            for bp in &level {
                if next.len() >= MAX_RUNS {
                    break;
                }
                let Ok(block) = read_block(&self.image, bp) else {
                    continue;
                };
                for chunk in block.data.chunks_exact(BLKPTR_SIZE) {
                    if next.len() >= MAX_RUNS {
                        break;
                    }
                    let child = Blkptr::parse(chunk, bp.byteorder);
                    if !child.is_hole() {
                        next.push(child);
                    }
                }
            }
            level = next;
        }
        level.retain(|bp| !bp.embedded && !bp.dvas[0].is_empty());
        level
    }

    /// The full logical content of object `obj`, truncated to its recorded size.
    fn content(&self, obj: u64) -> VfsResult<Vec<u8>> {
        let size = self.attrs(obj).map(|a| a.size);
        zpl_read_file_with(&self.image, &self.zpl, obj, size).map_err(|e| decode_err(&e))
    }
}

/// Read a whole [`DynSource`] into an owned buffer, tolerating a short read
/// (the buffer is truncated to what the source actually yielded).
fn read_all(source: &DynSource) -> VfsResult<Vec<u8>> {
    let len = source.len();
    // usize::try_from can only fail on a <64-bit target (usize == u64 on the
    // supported ones); clamp rather than panic.
    let cap = usize::try_from(len).unwrap_or(usize::MAX);
    let mut image = vec![0u8; cap];
    let mut filled = 0usize;
    while filled < cap {
        let n = source.read_at(filled as u64, &mut image[filled..])?;
        if n == 0 {
            break;
        }
        filled = filled.saturating_add(n);
    }
    image.truncate(filled);
    Ok(image)
}

impl std::fmt::Debug for ZfsFs {
    /// Names the mount without dumping the owned vdev buffer (which is the whole
    /// image and would swamp any diagnostic).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZfsFs")
            // The owned vdev buffer is the whole image; render its size rather
            // than dumping megabytes into a diagnostic.
            .field("image", &format_args!("<{} bytes>", self.image.len()))
            .field("zpl", &self.zpl)
            .field("registry", &self.registry)
            .field("layouts", &self.layouts)
            .field("root_id", &self.root_id)
            .field("record_size", &self.record_size)
            .field("pool_name", &self.pool_name)
            .finish()
    }
}

impl FileSystem for ZfsFs {
    fn kind(&self) -> FsKind {
        FsKind::ZFS
    }

    fn root(&self) -> FileId {
        FileId::Opaque(self.root_id)
    }

    fn sector_sizes(&self) -> SectorSizes {
        // A DVA addresses the vdev in 512-byte sectors, so 512 is the real
        // addressing unit regardless of the pool's ashift.
        SectorSizes {
            logical: 512,
            physical: 512,
            cluster_or_block: self.record_size,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        // ZFS stores SA/znode times as UTC seconds + nanoseconds.
        TimeZonePolicy::Utc
    }

    fn volume_label(&self) -> Option<String> {
        self.pool_name.clone()
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let obj = object_of(ino)?;
        let entries = self.dir_entries(obj)?;
        Ok(DirStream::new(entries.into_iter().map(
            |(name, child, kind)| {
                Ok(VfsDirEntry {
                    name,
                    id: FileId::Opaque(child),
                    kind,
                })
            },
        )))
    }

    fn extents(&self, ino: FileId, stream: StreamId) -> VfsResult<ExtentStream> {
        if stream != StreamId::Default {
            return Err(VfsError::Unsupported {
                layer: "zfs stream",
                scheme: format!("{stream:?} (ZFS objects carry a single data stream)"),
            });
        }
        let dnode = self.dnode(ino)?;
        let runs: Vec<RunInfo> = self
            .l0_blkptrs(&dnode)
            .into_iter()
            .map(|bp| RunInfo {
                run: ByteRun {
                    image_offset: bp.dvas[0].physical_byte_offset(),
                    len: bp.psize_bytes() as u64,
                    flags: RunFlags {
                        sparse: false,
                        encrypted: false,
                        compressed: !matches!(bp.compression, 0 | ZIO_COMPRESS_OFF),
                        filler: false,
                    },
                },
                // A live object's blocks are allocated by construction: ZFS never
                // rewrites a block in place, so a reachable blkptr is current.
                alloc: RunAlloc::Allocated,
            })
            .collect();
        Ok(ExtentStream::new(runs.into_iter().map(Ok)))
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let obj = object_of(parent)?;
        Ok(self
            .dir_entries(obj)?
            .into_iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, child, _)| FileId::Opaque(child)))
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let obj = object_of(ino)?;
        // Establishes the object exists (a missing id is OutOfRange, never a
        // silently-empty record) before any of its metadata is reported.
        self.dnode(ino)?;
        let attrs = self.attrs(obj);

        let kind = attrs.as_ref().map_or_else(
            // Without a decoded bonus the object's kind is not established; say
            // so rather than guessing a file.
            || NodeKind::Other,
            |a| node_kind_from_mode(a.mode),
        );
        let size = attrs.as_ref().map_or(0, |a| a.size);
        let times = attrs
            .as_ref()
            .map_or_else(MacbTimes::default, |a| MacbTimes {
                modified: Some(to_ts(a.mtime)),
                accessed: Some(to_ts(a.atime)),
                changed: Some(to_ts(a.ctime)),
                born: Some(to_ts(a.crtime)),
            });

        Ok(FsMeta {
            ino: obj,
            kind,
            // The live namespace only reaches allocated objects; deleted-object
            // recovery is a snapshot walk in the analyzer, not this mount.
            allocated: Allocation::Allocated,
            size,
            nlink: attrs
                .as_ref()
                .and_then(|a| u32::try_from(a.links).ok())
                .unwrap_or(0),
            uid: attrs.as_ref().and_then(|a| u32::try_from(a.uid).ok()),
            gid: attrs.as_ref().and_then(|a| u32::try_from(a.gid).ok()),
            mode: attrs.as_ref().and_then(|a| u32::try_from(a.mode).ok()),
            times,
            streams: vec![StreamInfo {
                id: StreamId::Default,
                name: None,
                size,
                residency: ResidencyKind::NonResident,
                kind: StreamKind::NtfsData,
            }],
            // ZFS stores object data in blocks addressed by the dnode's block
            // pointers; there is no resident/inline-in-the-record form. (An
            // embedded blkptr inlines data in the *pointer*, not the dnode.)
            residency: ResidencyKind::NonResident,
            link_target: None,
        })
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        if stream != StreamId::Default {
            return Err(VfsError::Unsupported {
                layer: "zfs stream",
                scheme: format!("{stream:?} (ZFS objects carry a single data stream)"),
            });
        }
        let obj = object_of(ino)?;
        let content = self.content(obj)?;
        let Ok(start) = usize::try_from(off) else {
            return Ok(0); // cov:unreachable: u64 -> usize always succeeds on a 64-bit target; kept so a 32-bit build reads short instead of panicking.
        };
        let Some(tail) = content.get(start..) else {
            return Ok(0);
        };
        let n = tail.len().min(buf.len());
        buf[..n].copy_from_slice(&tail[..n]);
        Ok(n)
    }

    fn read_link(&self, ino: FileId, cap: usize) -> VfsResult<Vec<u8>> {
        let obj = object_of(ino)?;
        let is_symlink = self
            .attrs(obj)
            .is_some_and(|a| node_kind_from_mode(a.mode) == NodeKind::Symlink);
        if !is_symlink {
            // A non-symlink reads as an empty target (matches ext4/NTFS/XFS/UFS).
            return Ok(Vec::new());
        }
        // A "slow" symlink's target is the object's data. A "fast" symlink keeps
        // it in the SA bonus under ZPL_SYMLINK, which ZplAttrs does not decode —
        // that reads as empty rather than a fabricated target.
        let mut target = self.content(obj)?;
        target.truncate(cap);
        Ok(target)
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        // Empty by design, not omission — see the module note. ZFS leaves no
        // tombstone in the live namespace; recovery is a snapshot walk in
        // zfs-forensic.
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        // Empty by design — ZFS free space lives in per-metaslab space maps,
        // which zfs-core does not decode. Reporting nothing is honest; a
        // fabricated run would not be.
        Ok(ExtentStream::empty())
    }
}

/// Mount a ZFS pool from a byte source as a `dyn FileSystem`.
///
/// # Errors
///
/// See [`ZfsFs::open`].
pub fn open(source: &DynSource) -> VfsResult<Arc<dyn FileSystem>> {
    Ok(Arc::new(ZfsFs::open(source)?))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The real L0 vdev label of a minted OpenZFS pool (`REAL-self`, Tier-2 —
    /// provenance in `tests/data/README.md`). Used to assert the prober accepts a
    /// **real** pool config, not only the crafted one below.
    const REAL_LABEL0: &[u8] = include_bytes!("../../tests/data/zfs_label0.bin");
    /// The real L0 vdev label of the external OpenZFS `zol-0.6.1` corpus
    /// (`REAL-ext`, Tier-1 — a third party authored the pool).
    const REAL_ZOL_LABEL0: &[u8] = include_bytes!("../../tests/data/zfs_zol061_vdev0_label0.bin");

    // ── the crafted mini-image (see the engine's tests/open_zfs.rs twin) ──────

    const BLOCK: usize = 4096;
    const DNODE_SZ: usize = 512;
    const BOOT_SKEW: u64 = 0x0040_0000;
    const IMAGE_LEN: usize = 8 * 1024 * 1024;
    const DT_REG: u64 = 8 << 60;
    const DT_DIR: u64 = 4 << 60;
    const DT_LNK: u64 = 10 << 60;
    const DMU_OT_SA: u8 = 44;
    const DMU_OT_ZNODE: u8 = 17;
    const DMU_OT_DSL_DIR: u8 = 12;
    const DMU_OT_DSL_DATASET: u8 = 16;
    const SA_MAGIC: u32 = 0x2F_505A;
    const ID_ZPL_MODE: u16 = 5;
    const ID_ZPL_SIZE: u16 = 6;
    const HELLO: &[u8] = b"hello, zfs!\n";
    const LINK_TARGET: &[u8] = b"hello.txt";

    fn xdr_pad(len: usize) -> usize {
        len.div_ceil(4) * 4
    }

    fn xdr_string(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut v = Vec::new();
        v.extend_from_slice(&(b.len() as u32).to_be_bytes());
        v.extend_from_slice(b);
        v.resize(4 + xdr_pad(b.len()), 0);
        v
    }

    enum Nv {
        U64(u64),
        Str(&'static str),
        List(Vec<(&'static str, Nv)>),
    }

    fn nv_type(v: &Nv) -> u32 {
        match v {
            Nv::U64(_) => 8,
            Nv::Str(_) => 9,
            Nv::List(_) => 19,
        }
    }

    fn nv_value_bytes(v: &Nv) -> Vec<u8> {
        match v {
            Nv::U64(n) => n.to_be_bytes().to_vec(),
            Nv::Str(s) => xdr_string(s),
            Nv::List(p) => nv_body(p),
        }
    }

    fn nv_body(pairs: &[(&'static str, Nv)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        for (name, value) in pairs {
            let name_b = xdr_string(name);
            let val_b = nv_value_bytes(value);
            let encoded = 8 + name_b.len() + 8 + val_b.len();
            out.extend_from_slice(&(encoded as u32).to_be_bytes());
            out.extend_from_slice(&(encoded as u32).to_be_bytes());
            out.extend_from_slice(&name_b);
            out.extend_from_slice(&nv_type(value).to_be_bytes());
            out.extend_from_slice(&1u32.to_be_bytes());
            out.extend_from_slice(&val_b);
        }
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out
    }

    /// A packed pool config carrying the identity keys, plus the pool `name`.
    fn label_config(name: &'static str) -> Vec<u8> {
        let mut v = vec![1u8, 1, 0, 0];
        v.extend_from_slice(&nv_body(&[
            ("version", Nv::U64(5000)),
            ("name", Nv::Str(name)),
            ("txg", Nv::U64(42)),
            ("pool_guid", Nv::U64(0x1234_5678_9abc_def0)),
            (
                "vdev_tree",
                Nv::List(vec![("type", Nv::Str("disk")), ("ashift", Nv::U64(9))]),
            ),
        ]));
        v
    }

    fn micro_zap(entries: &[(&str, u64)]) -> Vec<u8> {
        const ZBT_MICRO: u64 = (1 << 63) | 3;
        let mut b = vec![0u8; 512];
        b[0..8].copy_from_slice(&ZBT_MICRO.to_le_bytes());
        for (i, (name, val)) in entries.iter().enumerate() {
            let off = 64 + i * 64;
            b[off..off + 8].copy_from_slice(&val.to_le_bytes());
            let nb = name.as_bytes();
            b[off + 14..off + 14 + nb.len()].copy_from_slice(nb);
        }
        b
    }

    fn write_blkptr(buf: &mut [u8], off: usize, phys: u64, size: usize) {
        if phys == 0 {
            return;
        }
        let offset_sectors = (phys - BOOT_SKEW) >> 9;
        let asize_sectors = (size as u64).div_ceil(512);
        buf[off..off + 8].copy_from_slice(&(asize_sectors & 0x00ff_ffff).to_le_bytes());
        buf[off + 8..off + 16]
            .copy_from_slice(&(offset_sectors & 0x7fff_ffff_ffff_ffff).to_le_bytes());
        let sectors = (size as u64).div_ceil(512);
        let lsize_raw = sectors - 1;
        let prop =
            (lsize_raw & 0xffff) | ((lsize_raw & 0xffff) << 16) | (2u64 << 32) | (1u64 << 63);
        buf[off + 48..off + 56].copy_from_slice(&prop.to_le_bytes());
    }

    fn dnode_bytes(phys: u64, bonustype: u8, bonus: &[u8], nlevels: u8) -> [u8; DNODE_SZ] {
        let mut d = [0u8; DNODE_SZ];
        d[0] = 10;
        d[1] = 12;
        d[2] = nlevels;
        d[3] = 1;
        d[4] = bonustype;
        d[8..10].copy_from_slice(&((BLOCK as u16) >> 9).to_le_bytes());
        d[10..12].copy_from_slice(&(bonus.len() as u16).to_le_bytes());
        d[16..24].copy_from_slice(&0u64.to_le_bytes());
        write_blkptr(&mut d, 64, phys, BLOCK);
        let bonus_off = 64 + BLKPTR_SIZE;
        d[bonus_off..bonus_off + bonus.len()].copy_from_slice(bonus);
        d
    }

    fn dnode(phys: u64, bonustype: u8, bonus: &[u8]) -> [u8; DNODE_SZ] {
        dnode_bytes(phys, bonustype, bonus, 1)
    }

    fn zap_dnode(phys: u64) -> [u8; DNODE_SZ] {
        dnode(phys, 0, &[])
    }

    fn objset_block(dnode_array_phys: u64, dnodes: usize, os_type: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLOCK];
        b[0] = 10;
        b[1] = 12;
        b[2] = 1;
        b[3] = 1;
        let arr_bytes = dnodes * DNODE_SZ;
        b[8..10].copy_from_slice(&(arr_bytes.div_ceil(512) as u16).to_le_bytes());
        b[16..24].copy_from_slice(&0u64.to_le_bytes());
        write_blkptr(&mut b, 64, dnode_array_phys, arr_bytes.max(512));
        b[704..712].copy_from_slice(&os_type.to_le_bytes());
        b
    }

    fn dsl_dir_bonus(head: u64) -> Vec<u8> {
        let mut v = vec![0u8; 256];
        v[8..16].copy_from_slice(&head.to_le_bytes());
        v
    }

    fn dsl_dataset_bonus(zpl_phys: u64) -> Vec<u8> {
        let mut v = vec![0u8; 256];
        write_blkptr(&mut v, 128, zpl_phys, BLOCK);
        v
    }

    fn sa_bonus(mode: u64, size: u64) -> Vec<u8> {
        let mut v = vec![0u8; 24];
        v[0..4].copy_from_slice(&SA_MAGIC.to_le_bytes());
        let info: u16 = 1 | (1 << 10);
        v[4..6].copy_from_slice(&info.to_le_bytes());
        v[8..16].copy_from_slice(&mode.to_le_bytes());
        v[16..24].copy_from_slice(&size.to_le_bytes());
        v
    }

    /// A legacy `znode_phys_t` bonus: atime@0, mtime@16, ctime@32, crtime@48,
    /// gen@64, mode@72, size@80, parent@88, links@96.
    fn znode_bonus(mode: u64, size: u64) -> Vec<u8> {
        let mut v = vec![0u8; 264];
        v[0..8].copy_from_slice(&11u64.to_le_bytes()); // atime sec
        v[16..24].copy_from_slice(&22u64.to_le_bytes()); // mtime sec
        v[32..40].copy_from_slice(&33u64.to_le_bytes()); // ctime sec
        v[48..56].copy_from_slice(&44u64.to_le_bytes()); // crtime sec
        v[64..72].copy_from_slice(&11u64.to_le_bytes()); // gen
        v[72..80].copy_from_slice(&mode.to_le_bytes());
        v[80..88].copy_from_slice(&size.to_le_bytes());
        v[88..96].copy_from_slice(&2u64.to_le_bytes()); // parent (the root dir)
        v[96..104].copy_from_slice(&1u64.to_le_bytes()); // links
        v
    }

    fn layout_value(ids: &[u16]) -> u64 {
        let mut bytes = [0u8; 8];
        for (i, &id) in ids.iter().enumerate().take(4) {
            bytes[i * 2..i * 2 + 2].copy_from_slice(&id.to_be_bytes());
        }
        u64::from_le_bytes(bytes)
    }

    fn registry_value(id: u16, size: u16) -> u64 {
        (u64::from(size) << 24) | u64::from(id)
    }

    fn uberblock_slot(mos_phys: u64, txg: u64) -> Vec<u8> {
        let mut ub = vec![0u8; 1024];
        ub[0..8].copy_from_slice(&crate::uberblock::UBERBLOCK_MAGIC.to_le_bytes());
        ub[8..16].copy_from_slice(&5000u64.to_le_bytes());
        ub[16..24].copy_from_slice(&txg.to_le_bytes());
        ub[32..40].copy_from_slice(&1_700_000_000u64.to_le_bytes());
        write_blkptr(&mut ub, 40, mos_phys, BLOCK);
        ub
    }

    /// Assemble the walkable mini-image. `zpl_os_type` is a parameter so a test
    /// can drive the bootstrap-validation arm with a non-ZPL objset.
    fn build_image(zpl_os_type: u64) -> Vec<u8> {
        let base = BOOT_SKEW as usize;
        let mos_phys = base as u64;
        let mos_arr = (base + BLOCK) as u64;
        let obj_dir = (base + 2 * BLOCK) as u64;
        let zpl_phys = (base + 3 * BLOCK) as u64;
        // The ZPL dnode array holds 10 x 512-byte slots = 5120 bytes, so it spans
        // TWO 4 KiB regions; everything after it starts at index 6.
        let zpl_arr = (base + 4 * BLOCK) as u64;
        let master = (base + 6 * BLOCK) as u64;
        let root = (base + 7 * BLOCK) as u64;
        let file = (base + 8 * BLOCK) as u64;
        let sa_master = (base + 9 * BLOCK) as u64;
        let sa_registry = (base + 10 * BLOCK) as u64;
        let sa_layouts = (base + 11 * BLOCK) as u64;
        let subdir = (base + 12 * BLOCK) as u64;
        let link = (base + 13 * BLOCK) as u64;
        let znode_file = (base + 14 * BLOCK) as u64;

        let mut img = vec![0u8; IMAGE_LEN];

        let cfg = label_config("tank");
        img[NVLIST_OFFSET..NVLIST_OFFSET + cfg.len()].copy_from_slice(&cfg);
        let ub = uberblock_slot(mos_phys, 42);
        img[UBERBLOCK_RING_OFFSET..UBERBLOCK_RING_OFFSET + ub.len()].copy_from_slice(&ub);
        // A second, older slot so the highest-txg selection is exercised.
        let older = uberblock_slot(mos_phys, 7);
        let s2 = UBERBLOCK_RING_OFFSET + 1024;
        img[s2..s2 + older.len()].copy_from_slice(&older);

        let mos = objset_block(mos_arr, 4, crate::objset::DMU_OST_META);
        img[mos_phys as usize..mos_phys as usize + mos.len()].copy_from_slice(&mos);

        let mut arr = vec![0u8; 4 * DNODE_SZ];
        arr[DNODE_SZ..2 * DNODE_SZ].copy_from_slice(&zap_dnode(obj_dir));
        arr[2 * DNODE_SZ..3 * DNODE_SZ].copy_from_slice(&dnode(
            0,
            DMU_OT_DSL_DIR,
            &dsl_dir_bonus(3),
        ));
        arr[3 * DNODE_SZ..4 * DNODE_SZ].copy_from_slice(&dnode(
            0,
            DMU_OT_DSL_DATASET,
            &dsl_dataset_bonus(zpl_phys),
        ));
        img[mos_arr as usize..mos_arr as usize + arr.len()].copy_from_slice(&arr);

        let od = micro_zap(&[("root_dataset", 2)]);
        img[obj_dir as usize..obj_dir as usize + od.len()].copy_from_slice(&od);

        let zpl = objset_block(zpl_arr, 10, zpl_os_type);
        img[zpl_phys as usize..zpl_phys as usize + zpl.len()].copy_from_slice(&zpl);

        let mut za = vec![0u8; 10 * DNODE_SZ];
        za[DNODE_SZ..2 * DNODE_SZ].copy_from_slice(&zap_dnode(master));
        za[2 * DNODE_SZ..3 * DNODE_SZ].copy_from_slice(&zap_dnode(root));
        za[3 * DNODE_SZ..4 * DNODE_SZ].copy_from_slice(&dnode(
            file,
            DMU_OT_SA,
            &sa_bonus(0o100_644, HELLO.len() as u64),
        ));
        za[4 * DNODE_SZ..5 * DNODE_SZ].copy_from_slice(&zap_dnode(sa_master));
        za[5 * DNODE_SZ..6 * DNODE_SZ].copy_from_slice(&zap_dnode(sa_registry));
        za[6 * DNODE_SZ..7 * DNODE_SZ].copy_from_slice(&zap_dnode(sa_layouts));
        // obj 7: a subdirectory (its own micro-ZAP, one child file).
        za[7 * DNODE_SZ..8 * DNODE_SZ].copy_from_slice(&dnode(
            subdir,
            DMU_OT_SA,
            &sa_bonus(0o040_755, 0),
        ));
        // obj 8: a slow symlink whose data block holds the target.
        za[8 * DNODE_SZ..9 * DNODE_SZ].copy_from_slice(&dnode(
            link,
            DMU_OT_SA,
            &sa_bonus(0o120_777, LINK_TARGET.len() as u64),
        ));
        // obj 9: a legacy-znode file, so the DMU_OT_ZNODE bonus arm runs.
        za[9 * DNODE_SZ..10 * DNODE_SZ].copy_from_slice(&dnode(
            znode_file,
            DMU_OT_ZNODE,
            &znode_bonus(0o100_600, HELLO.len() as u64),
        ));
        img[zpl_arr as usize..zpl_arr as usize + za.len()].copy_from_slice(&za);

        let m = micro_zap(&[("ROOT", 2), ("VERSION", 5), ("SA_ATTRS", 4)]);
        img[master as usize..master as usize + m.len()].copy_from_slice(&m);

        let r = micro_zap(&[
            ("hello.txt", 0x3 | DT_REG),
            ("sub", 0x7 | DT_DIR),
            ("link", 0x8 | DT_LNK),
            ("znode.txt", 0x9 | DT_REG),
        ]);
        img[root as usize..root as usize + r.len()].copy_from_slice(&r);

        let sd = micro_zap(&[("nested.txt", 0x3 | DT_REG)]);
        img[subdir as usize..subdir as usize + sd.len()].copy_from_slice(&sd);

        let sam = micro_zap(&[("REGISTRY", 5), ("LAYOUTS", 6)]);
        img[sa_master as usize..sa_master as usize + sam.len()].copy_from_slice(&sam);

        let reg = micro_zap(&[
            ("ZPL_MODE", registry_value(ID_ZPL_MODE, 8)),
            ("ZPL_SIZE", registry_value(ID_ZPL_SIZE, 8)),
        ]);
        img[sa_registry as usize..sa_registry as usize + reg.len()].copy_from_slice(&reg);

        let lay = micro_zap(&[("1", layout_value(&[ID_ZPL_MODE, ID_ZPL_SIZE]))]);
        img[sa_layouts as usize..sa_layouts as usize + lay.len()].copy_from_slice(&lay);

        img[file as usize..file as usize + HELLO.len()].copy_from_slice(HELLO);
        img[link as usize..link as usize + LINK_TARGET.len()].copy_from_slice(LINK_TARGET);
        img[znode_file as usize..znode_file as usize + HELLO.len()].copy_from_slice(HELLO);

        img
    }

    /// An in-memory `ImageSource` over an owned buffer.
    struct Mem(Vec<u8>);
    impl forensic_vfs::ImageSource for Mem {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
            let start = (offset as usize).min(self.0.len());
            let avail = &self.0[start..];
            let n = avail.len().min(buf.len());
            buf[..n].copy_from_slice(&avail[..n]);
            Ok(n)
        }
    }

    fn src(bytes: Vec<u8>) -> DynSource {
        Arc::new(Mem(bytes))
    }

    fn mounted() -> ZfsFs {
        ZfsFs::open(&src(build_image(DMU_OST_ZFS))).expect("the crafted pool mounts")
    }

    fn win(b: &[u8]) -> SniffWindow<'_> {
        SniffWindow::new(0, b)
    }

    // ── the prober ───────────────────────────────────────────────────────────

    #[test]
    fn zfs_probe_accepts_a_real_pool_config() {
        // Real-bytes validation: both committed real labels must probe Yes, so
        // the detector is not merely agreeing with our own encoder.
        assert!(matches!(
            zfs_probe(&win(REAL_LABEL0)),
            Confidence::Yes { .. }
        ));
        assert!(matches!(
            zfs_probe(&win(REAL_ZOL_LABEL0)),
            Confidence::Yes { .. }
        ));
    }

    #[test]
    fn zfs_probe_accepts_the_crafted_config() {
        assert!(matches!(
            zfs_probe(&win(&build_image(DMU_OST_ZFS))),
            Confidence::Yes { .. }
        ));
    }

    #[test]
    fn zfs_probe_declines_non_zfs_short_and_offset_windows() {
        // Too short to reach the config region.
        assert_eq!(zfs_probe(&win(b"not zfs")), Confidence::No);
        assert_eq!(zfs_probe(&win(&[])), Confidence::No);
        // Long enough, but the config region is not an XDR nvlist.
        assert_eq!(
            zfs_probe(&win(&vec![0u8; NVLIST_OFFSET + 64])),
            Confidence::No
        );
        // A window that does not start at absolute 0 cannot carry the L0 label.
        let img = build_image(DMU_OST_ZFS);
        assert_eq!(zfs_probe(&SniffWindow::new(512, &img)), Confidence::No);
    }

    #[test]
    fn zfs_probe_declines_an_nvlist_without_the_pool_identity_keys() {
        // A valid XDR nvlist that is not a pool config (no pool_guid/vdev_tree).
        let mut img = vec![0u8; NVLIST_OFFSET + 4096];
        let mut cfg = vec![1u8, 1, 0, 0];
        cfg.extend_from_slice(&nv_body(&[("version", Nv::U64(5000))]));
        img[NVLIST_OFFSET..NVLIST_OFFSET + cfg.len()].copy_from_slice(&cfg);
        assert_eq!(zfs_probe(&win(&img)), Confidence::No);
        // is_pool_config is the gate: the same buffer parses fine.
        let list = crate::nvlist_parse(&img[NVLIST_OFFSET..]).expect("parses");
        assert!(!is_pool_config(&list));
    }

    // ── bootstrap ────────────────────────────────────────────────────────────

    #[test]
    fn open_bootstraps_the_crafted_pool() {
        let fs = mounted();
        assert_eq!(fs.kind(), FsKind::ZFS);
        assert_eq!(fs.root(), FileId::Opaque(2));
        assert_eq!(fs.volume_label().as_deref(), Some("tank"));
        assert_eq!(fs.timestamp_zone(), TimeZonePolicy::Utc);
        let s = fs.sector_sizes();
        assert_eq!((s.logical, s.physical), (512, 512));
        assert_eq!(s.cluster_or_block, BLOCK as u32);
    }

    #[test]
    fn open_fails_loud_when_no_uberblock_is_present() {
        let err = ZfsFs::open(&src(vec![0u8; IMAGE_LEN])).expect_err("no uberblock ⇒ Bootstrap");
        match err {
            VfsError::Bootstrap { stage, detail } => {
                assert_eq!(stage, "zfs uberblock ring");
                // The diagnostic names the magic and the scanned offsets.
                assert!(detail.contains("0x00bab10c"), "{detail}");
                assert!(detail.contains("8388608"), "{detail}");
            }
            other => panic!("expected Bootstrap, got {other:?}"), // cov:unreachable: an all-zero image has no uberblock magic, so open always fails at the ring stage; the arm is the match's required exhaustive branch
        }
    }

    #[test]
    fn open_fails_loud_when_the_rootbp_is_unreadable() {
        // An uberblock whose rootbp points past the end of the image.
        let mut img = vec![0u8; IMAGE_LEN];
        let mut ub = vec![0u8; 1024];
        ub[0..8].copy_from_slice(&crate::uberblock::UBERBLOCK_MAGIC.to_le_bytes());
        ub[16..24].copy_from_slice(&99u64.to_le_bytes());
        write_blkptr(&mut ub, 40, BOOT_SKEW + (IMAGE_LEN as u64) * 4, BLOCK);
        img[UBERBLOCK_RING_OFFSET..UBERBLOCK_RING_OFFSET + ub.len()].copy_from_slice(&ub);
        let err = ZfsFs::open(&src(img)).expect_err("unreadable rootbp ⇒ Bootstrap");
        match err {
            VfsError::Bootstrap { stage, detail } => {
                assert_eq!(stage, "zfs MOS objset block (uberblock rootbp)");
                assert!(detail.contains("txg 99"), "{detail}");
            }
            other => panic!("expected Bootstrap, got {other:?}"), // cov:unreachable: the rootbp names bytes past the image end, so open always fails at the MOS-objset-block stage; the arm is the match's required exhaustive branch
        }
    }

    #[test]
    fn open_fails_loud_when_the_mos_objset_is_too_small() {
        // A rootbp that reads a 512-byte block: too small for an objset_phys_t.
        let mut img = vec![0u8; IMAGE_LEN];
        let mut ub = vec![0u8; 1024];
        ub[0..8].copy_from_slice(&crate::uberblock::UBERBLOCK_MAGIC.to_le_bytes());
        ub[16..24].copy_from_slice(&5u64.to_le_bytes());
        write_blkptr(&mut ub, 40, BOOT_SKEW, 512);
        img[UBERBLOCK_RING_OFFSET..UBERBLOCK_RING_OFFSET + ub.len()].copy_from_slice(&ub);
        let err = ZfsFs::open(&src(img)).expect_err("short objset ⇒ Bootstrap");
        assert!(
            matches!(&err, VfsError::Bootstrap { stage, .. } if *stage == "zfs MOS objset"),
            "expected the MOS objset stage, got {err:?}"
        );
    }

    #[test]
    fn open_fails_loud_when_the_dsl_chain_does_not_resolve() {
        // A valid MOS objset whose object directory is missing → no ZPL objset.
        let base = BOOT_SKEW as usize;
        let mut img = vec![0u8; IMAGE_LEN];
        let cfg = label_config("tank");
        img[NVLIST_OFFSET..NVLIST_OFFSET + cfg.len()].copy_from_slice(&cfg);
        let ub = uberblock_slot(base as u64, 42);
        img[UBERBLOCK_RING_OFFSET..UBERBLOCK_RING_OFFSET + ub.len()].copy_from_slice(&ub);
        // The MOS objset's dnode array is all zeros: object 1 is an empty slot.
        let mos = objset_block((base + BLOCK) as u64, 4, crate::objset::DMU_OST_META);
        img[base..base + mos.len()].copy_from_slice(&mos);
        let err = ZfsFs::open(&src(img)).expect_err("no object directory ⇒ Bootstrap");
        match err {
            VfsError::Bootstrap { stage, detail } => {
                assert!(stage.contains("ZPL objset"), "{stage}");
                assert!(detail.contains("root_dataset"), "{detail}");
            }
            other => panic!("expected Bootstrap, got {other:?}"), // cov:unreachable: the all-zero MOS dnode array leaves object 1 absent, so open always fails at the ZPL-objset stage; the arm is the match's required exhaustive branch
        }
    }

    #[test]
    fn open_validates_the_dataset_objset_type() {
        // The bootstrap is validated: a resolved objset that is not DMU_OST_ZFS
        // is rejected loudly rather than mounted as an empty filesystem.
        let err = ZfsFs::open(&src(build_image(crate::objset::DMU_OST_META)))
            .expect_err("a non-ZPL objset ⇒ Bootstrap");
        match err {
            VfsError::Bootstrap { stage, detail } => {
                assert_eq!(stage, "zfs dataset objset type");
                assert!(detail.contains("is not DMU_OST_ZFS"), "{detail}");
            }
            other => panic!("expected Bootstrap, got {other:?}"), // cov:unreachable: build_image(DMU_OST_META) always resolves a non-ZPL objset, so open always fails at the dataset-objset-type stage; the arm is the match's required exhaustive branch
        }
    }

    #[test]
    fn open_fails_loud_when_the_master_node_names_no_root() {
        // A ZPL objset whose master node ZAP has no ROOT entry.
        let base = BOOT_SKEW as usize;
        let mut img = build_image(DMU_OST_ZFS);
        let master_off = base + 6 * BLOCK;
        let m = micro_zap(&[("VERSION", 5)]);
        img[master_off..master_off + BLOCK].fill(0);
        img[master_off..master_off + m.len()].copy_from_slice(&m);
        let err = ZfsFs::open(&src(img)).expect_err("no ROOT ⇒ Bootstrap");
        assert!(
            matches!(&err, VfsError::Bootstrap { stage, .. } if stage.contains("master node")),
            "expected the master-node stage, got {err:?}"
        );
    }

    #[test]
    fn open_tolerates_a_wiped_label_config() {
        // The config drives detection and the volume label, never the bootstrap:
        // a pool whose nvlist is zeroed still mounts, with no volume label.
        let mut img = build_image(DMU_OST_ZFS);
        img[NVLIST_OFFSET..NVLIST_OFFSET + NVLIST_SIZE].fill(0);
        let fs = ZfsFs::open(&src(img)).expect("a wiped config does not block the mount");
        assert_eq!(fs.volume_label(), None);
        assert_eq!(fs.root(), FileId::Opaque(2));
    }

    #[test]
    fn open_selects_the_highest_txg_uberblock() {
        // The image carries txg 42 in slot 0 and txg 7 in slot 1; the active
        // uberblock is the higher one, and it is the one that mounts.
        let img = build_image(DMU_OST_ZFS);
        let ub = active_uberblock_across_labels(&img).expect("an active uberblock");
        assert_eq!(ub.txg, 42);
    }

    #[test]
    fn active_uberblock_across_labels_keeps_the_highest_txg_label() {
        // Labels are scanned in offset order, so a later label carrying an OLDER
        // uberblock must not displace the running best — and a later label
        // carrying a newer one must.
        let hi = uberblock_slot(BOOT_SKEW, 42);
        let lo = uberblock_slot(BOOT_SKEW, 7);
        let l1_ring = crate::label::LABEL_SIZE + UBERBLOCK_RING_OFFSET;

        let mut older_last = vec![0u8; IMAGE_LEN];
        older_last[UBERBLOCK_RING_OFFSET..UBERBLOCK_RING_OFFSET + hi.len()].copy_from_slice(&hi);
        older_last[l1_ring..l1_ring + lo.len()].copy_from_slice(&lo);
        assert_eq!(
            active_uberblock_across_labels(&older_last)
                .expect("an active uberblock")
                .txg,
            42,
            "label 1's older txg must not displace label 0's"
        );

        let mut newer_last = vec![0u8; IMAGE_LEN];
        newer_last[UBERBLOCK_RING_OFFSET..UBERBLOCK_RING_OFFSET + lo.len()].copy_from_slice(&lo);
        newer_last[l1_ring..l1_ring + hi.len()].copy_from_slice(&hi);
        assert_eq!(
            active_uberblock_across_labels(&newer_last)
                .expect("an active uberblock")
                .txg,
            42,
            "label 1's newer txg must win"
        );
    }

    #[test]
    fn active_uberblock_across_labels_declines_a_tiny_image() {
        // Smaller than one label: no ring to scan, and no panic.
        assert!(active_uberblock_across_labels(&[0u8; 16]).is_none());
    }

    // ── namespace + content ──────────────────────────────────────────────────

    #[test]
    fn read_dir_yields_entries_with_kinds_from_the_dirent_type_bits() {
        let fs = mounted();
        let mut got: Vec<(String, u64, NodeKind)> = fs
            .read_dir(fs.root())
            .expect("read_dir root")
            .map(|e| {
                let e = e.expect("entry");
                let FileId::Opaque(n) = e.id else {
                    panic!("expected an opaque id") // cov:unreachable: read_dir builds every entry id as FileId::Opaque; the else arm is the let-else's required diverging branch
                };
                (String::from_utf8_lossy(&e.name).into_owned(), n, e.kind)
            })
            .collect();
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            got,
            vec![
                ("hello.txt".to_owned(), 3, NodeKind::File),
                ("link".to_owned(), 8, NodeKind::Symlink),
                ("sub".to_owned(), 7, NodeKind::Dir),
                ("znode.txt".to_owned(), 9, NodeKind::File),
            ]
        );
    }

    #[test]
    fn read_dir_descends_a_subdirectory() {
        let fs = mounted();
        let sub = fs
            .lookup(fs.root(), b"sub")
            .expect("lookup sub")
            .expect("sub present");
        let names: Vec<String> = fs
            .read_dir(sub)
            .expect("read_dir sub")
            .map(|e| String::from_utf8_lossy(&e.expect("entry").name).into_owned())
            .collect();
        assert_eq!(names, vec!["nested.txt".to_owned()]);
    }

    #[test]
    fn lookup_finds_a_name_and_misses_cleanly() {
        let fs = mounted();
        assert_eq!(
            fs.lookup(fs.root(), b"hello.txt").expect("lookup"),
            Some(FileId::Opaque(3))
        );
        assert_eq!(fs.lookup(fs.root(), b"nope.txt").expect("lookup"), None);
    }

    #[test]
    fn read_dir_on_a_missing_object_errors_rather_than_returning_empty() {
        let fs = mounted();
        // An absent object id must not read as an empty directory.
        match fs.read_dir(FileId::Opaque(4096)) {
            Ok(_) => panic!("an absent object must not read as an empty directory"), // cov:unreachable: object 4096 lies past the crafted ZPL dnode array, so dir_entries always returns OutOfRange; the arm is the match's required exhaustive branch
            Err(e) => assert!(matches!(e, VfsError::OutOfRange { .. }), "{e:?}"),
        }
    }

    #[test]
    fn read_dir_on_a_non_zap_object_surfaces_a_decode_error() {
        let fs = mounted();
        // Object 3 is a plain file; its data block is not a ZAP.
        let entries = fs.read_dir(FileId::Opaque(3)).map(Iterator::count);
        // Either a decode error or an empty listing is acceptable here; what
        // matters is that it does not panic.
        match entries {
            Ok(n) => assert_eq!(n, 0, "a file's data block holds no ZAP entries"),
            Err(e) => assert!(matches!(e, VfsError::Decode { .. }), "{e:?}"), // cov:unreachable: object 3's data block is a readable non-ZAP, so zap_list returns no entries rather than erroring; the arm keeps the weaker no-panic contract honest if that ever changes
        }
    }

    #[test]
    fn meta_decodes_sa_attributes_and_times() {
        let fs = mounted();
        let m = fs.meta(FileId::Opaque(3)).expect("meta hello.txt");
        assert_eq!(m.ino, 3);
        assert_eq!(m.kind, NodeKind::File);
        assert_eq!(m.size, HELLO.len() as u64);
        assert_eq!(m.mode, Some(0o100_644));
        assert_eq!(m.allocated, Allocation::Allocated);
        assert_eq!(m.residency, ResidencyKind::NonResident);
        assert_eq!(m.streams.len(), 1);
        assert_eq!(m.streams[0].id, StreamId::Default);
        // The crafted SA layout registers mode + size only, so the times decode
        // to the zero epoch — present (the attribute exists) but unset.
        assert!(m.times.modified.is_some());
        assert!(m.times.born.is_some());
    }

    #[test]
    fn meta_decodes_a_legacy_znode_bonus() {
        let fs = mounted();
        let m = fs.meta(FileId::Opaque(9)).expect("meta znode.txt");
        assert_eq!(m.kind, NodeKind::File);
        assert_eq!(m.mode, Some(0o100_600));
        assert_eq!(m.nlink, 1);
        // znode times are real seconds in this fixture.
        assert_eq!(
            m.times.modified.expect("mtime").unix_nanos,
            22 * 1_000_000_000
        );
        assert_eq!(
            m.times.accessed.expect("atime").unix_nanos,
            11 * 1_000_000_000
        );
        assert_eq!(
            m.times.changed.expect("ctime").unix_nanos,
            33 * 1_000_000_000
        );
        assert_eq!(m.times.born.expect("crtime").unix_nanos, 44 * 1_000_000_000);
    }

    #[test]
    fn meta_of_an_object_with_no_decodable_bonus_is_reported_as_unknown_kind() {
        let fs = mounted();
        // Object 1 (the master node) has an empty bonus: no mode to classify by.
        let m = fs.meta(FileId::Opaque(1)).expect("meta master node");
        assert_eq!(m.kind, NodeKind::Other);
        assert_eq!(m.mode, None);
        assert_eq!(m.times, MacbTimes::default());
    }

    #[test]
    fn meta_of_a_missing_object_is_out_of_range() {
        let fs = mounted();
        let err = fs.meta(FileId::Opaque(9999)).expect_err("absent object");
        assert!(matches!(err, VfsError::OutOfRange { .. }), "{err:?}");
    }

    #[test]
    fn read_at_returns_content_and_honours_the_offset() {
        let fs = mounted();
        let id = FileId::Opaque(3);
        let mut buf = vec![0u8; HELLO.len()];
        let n = fs
            .read_at(id, StreamId::Default, 0, &mut buf)
            .expect("read");
        assert_eq!(&buf[..n], HELLO);
        // A mid-file offset.
        let mut tail = vec![0u8; 4];
        let n = fs
            .read_at(id, StreamId::Default, 7, &mut tail)
            .expect("read");
        assert_eq!(&tail[..n], &HELLO[7..7 + n]);
        // Past the end reads zero bytes, never an error or a panic.
        let mut none = vec![0u8; 8];
        assert_eq!(
            fs.read_at(id, StreamId::Default, 1_000_000, &mut none)
                .expect("read past end"),
            0
        );
    }

    #[test]
    fn read_at_and_extents_reject_a_non_default_stream() {
        let fs = mounted();
        let id = FileId::Opaque(3);
        let mut buf = [0u8; 4];
        assert!(matches!(
            fs.read_at(id, StreamId::ResourceFork, 0, &mut buf),
            Err(VfsError::Unsupported {
                layer: "zfs stream",
                ..
            })
        ));
        assert!(matches!(
            fs.extents(id, StreamId::Xattr(0)),
            Err(VfsError::Unsupported {
                layer: "zfs stream",
                ..
            })
        ));
    }

    #[test]
    fn a_non_opaque_file_id_is_rejected() {
        let fs = mounted();
        let bad = FileId::NtfsRef { entry: 1, seq: 1 };
        assert!(matches!(
            fs.meta(bad),
            Err(VfsError::Unsupported {
                layer: "zfs file-id",
                ..
            })
        ));
        assert!(matches!(
            fs.read_dir(bad),
            Err(VfsError::Unsupported {
                layer: "zfs file-id",
                ..
            })
        ));
        assert!(matches!(
            fs.lookup(bad, b"x"),
            Err(VfsError::Unsupported {
                layer: "zfs file-id",
                ..
            })
        ));
        let mut buf = [0u8; 1];
        assert!(matches!(
            fs.read_at(bad, StreamId::Default, 0, &mut buf),
            Err(VfsError::Unsupported {
                layer: "zfs file-id",
                ..
            })
        ));
        assert!(matches!(
            fs.read_link(bad, 16),
            Err(VfsError::Unsupported {
                layer: "zfs file-id",
                ..
            })
        ));
        assert!(matches!(
            fs.extents(bad, StreamId::Default),
            Err(VfsError::Unsupported {
                layer: "zfs file-id",
                ..
            })
        ));
    }

    #[test]
    fn extents_yields_the_l0_data_run() {
        let fs = mounted();
        let runs: Vec<RunInfo> = fs
            .extents(FileId::Opaque(3), StreamId::Default)
            .expect("extents")
            .map(|r| r.expect("run"))
            .collect();
        assert_eq!(runs.len(), 1, "a single-block file has one run");
        let base = BOOT_SKEW + 8 * BLOCK as u64;
        assert_eq!(runs[0].run.image_offset, base);
        assert_eq!(runs[0].run.len, BLOCK as u64);
        assert_eq!(runs[0].alloc, RunAlloc::Allocated);
        assert!(!runs[0].run.flags.compressed);
    }

    #[test]
    fn extents_skips_holes_rather_than_naming_offset_zero() {
        let fs = mounted();
        // Object 2 (the DSL directory) has an all-zero (hole) blkptr in the MOS,
        // but within the ZPL objset object 2 is the root dir, which has a run.
        // Object 1's counterpart with a hole is the MOS DSL dir; use the ZPL
        // master node, whose data block is real, and assert no run has offset 0.
        for obj in [1u64, 2, 3, 7, 8, 9] {
            let runs: Vec<RunInfo> = fs
                .extents(FileId::Opaque(obj), StreamId::Default)
                .expect("extents")
                .map(|r| r.expect("run"))
                .collect();
            assert!(
                runs.iter().all(|r| r.run.image_offset >= BOOT_SKEW),
                "object {obj} produced a run below the boot skew: {runs:?}"
            );
        }
    }

    #[test]
    fn extents_descends_a_two_level_indirect_tree() {
        // A dnode with dn_nlevels == 2: the top blkptr points at an L1 indirect
        // block whose child[0] points at the L0 data block. `extents` must
        // report the L0 run, not the indirect block.
        let l1 = BOOT_SKEW + 20 * BLOCK as u64;
        let l0 = BOOT_SKEW + 21 * BLOCK as u64;
        let mut img = build_image(DMU_OST_ZFS);
        let mut ind = vec![0u8; BLOCK];
        write_blkptr(&mut ind, 0, l0, BLOCK);
        img[l1 as usize..l1 as usize + BLOCK].copy_from_slice(&ind);
        // Rewrite ZPL object 3's dnode as a 2-level object rooted at the L1 block.
        let zpl_arr = BOOT_SKEW as usize + 4 * BLOCK;
        let slot = zpl_arr + 3 * DNODE_SZ;
        img[slot..slot + DNODE_SZ].copy_from_slice(&dnode_bytes(
            l1,
            DMU_OT_SA,
            &sa_bonus(0o100_644, HELLO.len() as u64),
            2,
        ));
        let fs = ZfsFs::open(&src(img)).expect("mounts");
        let runs: Vec<RunInfo> = fs
            .extents(FileId::Opaque(3), StreamId::Default)
            .expect("extents")
            .map(|r| r.expect("run"))
            .collect();
        assert_eq!(runs.len(), 1, "one L0 run beneath the indirect block");
        assert_eq!(runs[0].run.image_offset, l0);
    }

    #[test]
    fn read_link_returns_a_slow_symlink_target_and_empty_for_a_non_symlink() {
        let fs = mounted();
        let target = fs.read_link(FileId::Opaque(8), 256).expect("read_link");
        assert_eq!(&target[..LINK_TARGET.len()], LINK_TARGET);
        // The cap truncates.
        let short = fs
            .read_link(FileId::Opaque(8), 5)
            .expect("read_link capped");
        assert_eq!(short.len(), 5);
        // A regular file reads as an empty target.
        assert!(fs
            .read_link(FileId::Opaque(3), 256)
            .expect("read_link")
            .is_empty());
        // So does an object with no decodable bonus.
        assert!(fs
            .read_link(FileId::Opaque(1), 256)
            .expect("read_link")
            .is_empty());
    }

    #[test]
    fn deleted_and_unallocated_are_empty_by_design() {
        let fs = mounted();
        assert_eq!(fs.deleted().expect("deleted").count(), 0);
        assert_eq!(fs.unallocated().expect("unallocated").count(), 0);
        assert_eq!(fs.deleted_nodes().expect("deleted_nodes").count(), 0);
        assert!(fs
            .data_streams(FileId::Opaque(3))
            .expect("streams")
            .is_empty());
        assert!(fs
            .hardlinks(FileId::Opaque(3))
            .expect("hardlinks")
            .is_empty());
        assert_eq!(
            fs.slack(FileId::Opaque(3), StreamId::Default)
                .expect("slack"),
            None
        );
    }

    // ── the free-function mount + pure helpers ───────────────────────────────

    #[test]
    fn open_free_function_returns_a_dyn_filesystem() {
        let fs = super::open(&src(build_image(DMU_OST_ZFS))).expect("mounts");
        assert_eq!(fs.kind(), FsKind::ZFS);
    }

    #[test]
    fn node_kind_from_mode_maps_every_ifmt_type() {
        assert_eq!(node_kind_from_mode(0o100_644), NodeKind::File);
        assert_eq!(node_kind_from_mode(0o040_755), NodeKind::Dir);
        assert_eq!(node_kind_from_mode(0o120_777), NodeKind::Symlink);
        assert_eq!(node_kind_from_mode(0o020_666), NodeKind::Device);
        assert_eq!(node_kind_from_mode(0o060_660), NodeKind::Device);
        assert_eq!(node_kind_from_mode(0o010_600), NodeKind::Other); // FIFO
        assert_eq!(node_kind_from_mode(0), NodeKind::Other);
    }

    #[test]
    fn node_kind_from_dirent_maps_every_dt_code() {
        assert_eq!(node_kind_from_dirent(8), NodeKind::File);
        assert_eq!(node_kind_from_dirent(4), NodeKind::Dir);
        assert_eq!(node_kind_from_dirent(10), NodeKind::Symlink);
        assert_eq!(node_kind_from_dirent(2), NodeKind::Device);
        assert_eq!(node_kind_from_dirent(6), NodeKind::Device);
        assert_eq!(node_kind_from_dirent(0), NodeKind::Other);
    }

    #[test]
    fn to_ts_carries_ns_and_inode_table_provenance() {
        let ts = to_ts((5, 123));
        assert_eq!(ts.unix_nanos, 5 * 1_000_000_000 + 123);
        assert_eq!(ts.source, TimeSource::InodeTable);
        assert_eq!(ts.resolution, TimeResolution::Nanos);
    }

    #[test]
    fn decode_err_preserves_the_reader_diagnostic() {
        let e = crate::ZfsError::Truncated {
            structure: "test",
            need: 4,
            have: 1,
        };
        match decode_err(&e) {
            VfsError::Decode { layer, detail, .. } => {
                assert_eq!(layer, "zfs");
                assert!(detail.contains("test"), "{detail}");
            }
            other => panic!("expected Decode, got {other:?}"), // cov:unreachable: decode_err maps every ZfsError to VfsError::Decode; the arm is the match's required exhaustive branch
        }
    }

    #[test]
    fn config_region_declines_when_the_buffer_is_short() {
        assert!(config_region(&[0u8; 16], 0).is_none());
        assert!(config_region(&[0u8; 16], usize::MAX).is_none());
    }

    #[test]
    fn debug_names_the_mount_without_dumping_the_image() {
        let fs = mounted();
        let shown = format!("{fs:?}");
        assert!(shown.contains("ZfsFs"), "{shown}");
        assert!(shown.contains("pool_name"), "{shown}");
        // The whole vdev is 8 MiB; the diagnostic must summarise, not dump it.
        assert!(shown.contains("<8388608 bytes>"), "{shown}");
        assert!(
            shown.len() < 4096,
            "debug output should stay diagnostic-sized"
        );
    }

    #[test]
    fn extents_flags_a_compressed_block() {
        // A blkptr whose `comp` is neither INHERIT (0) nor OFF (2) is reported
        // compressed, so a consumer knows the run's bytes are not the logical
        // content. lzjb (3) is the classic ZFS value.
        let mut img = build_image(DMU_OST_ZFS);
        let zpl_arr = BOOT_SKEW as usize + 4 * BLOCK;
        let slot = zpl_arr + 3 * DNODE_SZ;
        let mut d = dnode(
            BOOT_SKEW + 8 * BLOCK as u64,
            DMU_OT_SA,
            &sa_bonus(0o100_644, 12),
        );
        // Rewrite blk_prop's comp field (bits 32-38 of the word at blkptr+48).
        let prop_off = 64 + 48;
        let mut prop = u64::from_le_bytes(d[prop_off..prop_off + 8].try_into().unwrap());
        prop = (prop & !(0x7fu64 << 32)) | (3u64 << 32); // ZIO_COMPRESS_LZJB
        d[prop_off..prop_off + 8].copy_from_slice(&prop.to_le_bytes());
        img[slot..slot + DNODE_SZ].copy_from_slice(&d);

        let fs = ZfsFs::open(&src(img)).expect("mounts");
        let runs: Vec<RunInfo> = fs
            .extents(FileId::Opaque(3), StreamId::Default)
            .expect("extents")
            .map(|r| r.expect("run"))
            .collect();
        assert_eq!(runs.len(), 1);
        assert!(runs[0].run.flags.compressed, "lzjb blocks are compressed");
    }

    #[test]
    fn l0_blkptrs_skips_an_unreadable_indirect_block() {
        // A two-level object whose only top pointer names bytes past the end of
        // the image: the descent drops that subtree rather than fabricating a run
        // (and rather than propagating — extents of a partly-unreadable object
        // still report the runs it can prove).
        let fs = mounted();
        let mut raw = [0u8; DNODE_SZ];
        raw[2] = 2; // dn_nlevels: one indirect level above the data blocks
        raw[3] = 1; // dn_nblkptr
        raw[8..10].copy_from_slice(&((BLOCK as u16) >> 9).to_le_bytes());
        write_blkptr(&mut raw, 64, BOOT_SKEW + (IMAGE_LEN as u64) * 4, BLOCK);
        let dnode = Dnode::parse(&raw, crate::bytes::Endian::Little).expect("a 512-byte dnode");
        assert!(!dnode.blkptrs[0].is_hole(), "the top pointer is not a hole");
        assert!(fs.l0_blkptrs(&dnode).is_empty());
    }

    #[test]
    fn l0_blkptrs_stops_at_the_max_runs_cap() {
        // A hostile two-level object: 15 top pointers, each naming the SAME wide
        // indirect block of 5000 non-hole children (15 x 5000 = 75_000 > the
        // MAX_RUNS allocation-bomb cap). The descent must stop at the cap both
        // mid-block and before descending a further top pointer.
        const CHILDREN: usize = 5000;
        const IND_BYTES: usize = CHILDREN * BLKPTR_SIZE; // 640_000 B == 1250 sectors
        const TOP: usize = 15; // 15 * 128 + 64 == 1984 <= a 4-slot dnode's tail
        let base = BOOT_SKEW as usize;
        let ind_phys = (base + 64 * BLOCK) as u64; // past everything build_image writes

        let mut img = build_image(DMU_OST_ZFS);
        let mut ind = vec![0u8; IND_BYTES];
        for i in 0..CHILDREN {
            // Every child names a real, readable 4 KiB block, so none is a hole.
            write_blkptr(&mut ind, i * BLKPTR_SIZE, BOOT_SKEW, BLOCK);
        }
        img[ind_phys as usize..ind_phys as usize + IND_BYTES].copy_from_slice(&ind);
        let fs = ZfsFs::open(&src(img)).expect("the crafted pool still mounts");

        // dn_extra_slots = 3 → a 4-slot (2048-byte) dnode, whose tail holds 15
        // block pointers.
        let mut raw = vec![0u8; 4 * DNODE_SZ];
        raw[2] = 2; // dn_nlevels
        raw[3] = TOP as u8; // dn_nblkptr
        raw[8..10].copy_from_slice(&((BLOCK as u16) >> 9).to_le_bytes());
        raw[12] = 3; // dn_extra_slots
        for i in 0..TOP {
            write_blkptr(&mut raw, 64 + i * BLKPTR_SIZE, ind_phys, IND_BYTES);
        }
        let dnode = Dnode::parse(&raw, crate::bytes::Endian::Little).expect("a 4-slot dnode");
        assert_eq!(
            dnode.blkptrs.len(),
            TOP,
            "all 15 top pointers fit the dnode"
        );
        assert_eq!(fs.l0_blkptrs(&dnode).len(), MAX_RUNS);
    }

    #[test]
    fn read_all_propagates_a_source_read_error() {
        /// A source whose reads always fail.
        struct Failing;
        impl forensic_vfs::ImageSource for Failing {
            fn len(&self) -> u64 {
                4096
            }
            fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> VfsResult<usize> {
                Err(VfsError::Io {
                    op: "test read",
                    source: std::io::Error::other("always fails"),
                })
            }
        }
        let err = read_all(&(Arc::new(Failing) as DynSource)).expect_err("read error propagates");
        assert!(matches!(err, VfsError::Io { .. }), "{err:?}");
        // And it surfaces through the mount rather than becoming an empty pool.
        let err = ZfsFs::open(&(Arc::new(Failing) as DynSource)).expect_err("mount fails");
        assert!(matches!(err, VfsError::Io { .. }), "{err:?}");
    }

    #[test]
    fn read_all_truncates_to_what_the_source_yields() {
        /// A source that claims more length than it will serve.
        struct Short;
        impl forensic_vfs::ImageSource for Short {
            fn len(&self) -> u64 {
                4096
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
                if offset >= 16 {
                    return Ok(0);
                }
                let n = buf.len().min(16);
                buf[..n].fill(0xAB);
                Ok(n)
            }
        }
        let got = read_all(&(Arc::new(Short) as DynSource)).expect("read");
        assert_eq!(got.len(), 16);
        assert!(got.iter().all(|&b| b == 0xAB));
    }
}
