//! `zfs-forensic` — anomaly auditor + `CoW` deleted-file recovery for ZFS.
//!
//! ZFS is a copy-on-write pool with a self-checksumming Merkle block tree and a
//! ring of recent pool roots (uberblocks). That structure is the forensic lever
//! this crate pulls:
//!
//! - **F-INTEGRITY** ([`audit_image`] / [`audit_findings`]) emits graded
//!   [`forensicnomicon::report::Finding`]s for structural anomalies: the active
//!   uberblock's `ub_rootbp` checksum failing against the MOS block it points at
//!   (`ZFS-UBERBLOCK-CHECKSUM-MISMATCH`), the four vdev labels' nvlist configs
//!   disagreeing on `pool_guid`/`txg`/`ashift` (`ZFS-LABEL-DIVERGENCE`), a
//!   reachable metadata block whose blkptr checksum does not verify
//!   (`ZFS-BLKPTR-CHECKSUM-MISMATCH`), and geometry beyond the image
//!   (`ZFS-IMPOSSIBLE-GEOMETRY`).
//! - **F-CARVE** ([`recover_deleted`]) recovers deleted files from snapshots: it
//!   enumerates the datasets by walking the DSL snapshot chain, reads each
//!   snapshot's ZPL root directory, and diffs it against the live filesystem's
//!   root — a file present in the snapshot but absent live was deleted, and its
//!   content is carved from the snapshot's (pinned, un-overwritten) blocks
//!   (`ZFS-DELETED-FILE-CARVED`).
//!
//! Built on `zfs-core` for valid-path reading; where the audit must see the raw
//! uberblock ring / DSL bonus the reader does not surface, it uses the low-level
//! accessors (`active_uberblock`, `dsl_dataset_prev_snap`) directly (the
//! reader/analyzer-split principle).
//!
//! Each finding is an **observation** ("consistent with …"); the examiner draws
//! the conclusions. Mirrors the fleet producer pattern (typed `AnomalyKind` +
//! `impl Observation` + `audit_*` → `Vec<Anomaly>` + `audit_findings` →
//! `Vec<Finding>`), as in `xfs-forensic` / `btrfs-forensic`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub use forensicnomicon::report::Severity;
use forensicnomicon::report::{Evidence, Finding, Location, Observation, Source};

use zfs_core::{
    checksum, dsl_dataset_bp, dsl_dataset_prev_snap, dsl_dir_head_dataset, mos_dnode, read_block,
    read_zap_object, zap_lookup, zpl_list_dir, zpl_master_root, zpl_read_file, Blkptr,
    ChecksumType, Dnode, Endian, ObjsetPhys, VdevLabel, LABEL_SIZE, NVLIST_OFFSET, NVLIST_SIZE,
};

// ── F-INTEGRITY: structural-integrity anomaly kinds ───────────────────────────

/// Classification of a ZFS structural-integrity anomaly (F-INTEGRITY). Each
/// variant carries the evidence needed to reproduce the observation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// The active uberblock's `ub_rootbp` checksum does not verify against the
    /// MOS objset block it points at — the top-of-tree Merkle check failing,
    /// consistent with corruption or post-write tampering of the pool root.
    UberblockChecksumMismatch {
        /// The transaction group of the active uberblock whose rootbp failed.
        txg: u64,
        /// The uberblock ring slot the active uberblock was found in.
        slot: usize,
    },
    /// The vdev labels disagree on a pool-identity/geometry field
    /// (`pool_guid`/`txg`/`ashift`) — consistent with a torn or tampered label.
    /// A label whose config region cannot be parsed at all is reported here too.
    LabelDivergence {
        /// The config field that diverged (`pool_guid`, `txg`, `ashift`), or
        /// `config` when a label's nvlist could not be parsed.
        field: &'static str,
        /// The label index (`0..4`) that diverged from the others.
        label: usize,
        /// Human-readable description of the divergence.
        reason: String,
    },
    /// A reachable metadata block (from the active uberblock's MOS/objset tree)
    /// whose blkptr checksum does not verify — a dead / corrupt / tampered block.
    BlkptrChecksumMismatch {
        /// The block's DVA[0] physical byte offset in the image.
        dva_offset: u64,
        /// The DMU object type carried by the block pointer.
        object_type: u8,
    },
    /// A size/count/offset field beyond what the image can hold — an
    /// allocation-bomb / corruption guard.
    ImpossibleGeometry {
        /// The offending field name.
        field: &'static str,
        /// The value read from the structure.
        value: u64,
        /// The sane upper bound derived from the image size / spec.
        limit: u64,
    },
}

impl AnomalyKind {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::UberblockChecksumMismatch { .. }
            | AnomalyKind::LabelDivergence { .. }
            | AnomalyKind::BlkptrChecksumMismatch { .. }
            | AnomalyKind::ImpossibleGeometry { .. } => Severity::High,
        }
    }

    /// Stable machine-readable, scheme-prefixed code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::UberblockChecksumMismatch { .. } => "ZFS-UBERBLOCK-CHECKSUM-MISMATCH",
            AnomalyKind::LabelDivergence { .. } => "ZFS-LABEL-DIVERGENCE",
            AnomalyKind::BlkptrChecksumMismatch { .. } => "ZFS-BLKPTR-CHECKSUM-MISMATCH",
            AnomalyKind::ImpossibleGeometry { .. } => "ZFS-IMPOSSIBLE-GEOMETRY",
        }
    }

    /// Human-readable, "consistent with" note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::UberblockChecksumMismatch { txg, slot } => format!(
                "active uberblock (txg {txg}, ring slot {slot}): ub_rootbp checksum does not verify against the MOS block it points at — consistent with corruption or post-write tampering of the pool root"
            ),
            AnomalyKind::LabelDivergence {
                field,
                label,
                reason,
            } => format!(
                "vdev label L{label} {field}: {reason} — consistent with a torn or tampered vdev label"
            ),
            AnomalyKind::BlkptrChecksumMismatch {
                dva_offset,
                object_type,
            } => format!(
                "metadata block (DMU type {object_type}) at byte {dva_offset}: blkptr checksum does not verify — consistent with a dead, corrupt, or tampered block"
            ),
            AnomalyKind::ImpossibleGeometry {
                field,
                value,
                limit,
            } => format!(
                "geometry field {field} = {value} exceeds the sane bound {limit} for this image — consistent with corruption or an allocation-bomb"
            ),
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::UberblockChecksumMismatch { txg, slot } => vec![Evidence {
                field: "ub_rootbp".to_string(),
                value: format!("txg {txg} slot {slot}: checksum mismatch"),
                location: Some(Location::Other {
                    space: "zfs:uberblock_slot".to_string(),
                    value: *slot as u64,
                }),
            }],
            AnomalyKind::LabelDivergence {
                field,
                label,
                reason,
            } => vec![Evidence {
                field: (*field).to_string(),
                value: format!("L{label}: {reason}"),
                location: Some(Location::Other {
                    space: "zfs:vdev_label".to_string(),
                    value: *label as u64,
                }),
            }],
            AnomalyKind::BlkptrChecksumMismatch {
                dva_offset,
                object_type,
            } => vec![Evidence {
                field: "blkptr".to_string(),
                value: format!("DMU type {object_type}"),
                location: Some(Location::ByteOffset(*dva_offset)),
            }],
            AnomalyKind::ImpossibleGeometry {
                field,
                value,
                limit,
            } => vec![Evidence {
                field: (*field).to_string(),
                value: format!("{value} (limit {limit})"),
                location: None,
            }],
        }
    }
}

/// A ZFS structural-integrity anomaly: an observation graded by severity, with a
/// stable code and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly with its evidence.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn evidence(&self) -> Vec<Evidence> {
        self.kind.evidence()
    }
}

// ── F-INTEGRITY: the image auditor ────────────────────────────────────────────

/// Audit a whole ZFS image for structural-integrity anomalies (F-INTEGRITY):
/// parse the L0 vdev label, verify the active uberblock's rootbp checksum against
/// the MOS block, check the four vdev labels' configs for divergence, sweep the
/// reachable MOS/objset tree for blkptr checksum mismatches, and guard against
/// impossible geometry.
///
/// A clean image yields an empty vector. Malformed input never panics.
#[must_use]
pub fn audit_image(image: &[u8]) -> Vec<Anomaly> {
    let mut out = Vec::new();

    // Too small to hold even the front L0 label: nothing to audit (never panic).
    let Some(l0_bytes) = image.get(0..LABEL_SIZE) else {
        return out;
    };
    let Ok(l0) = VdevLabel::parse(l0_bytes) else {
        return out;
    };

    // Active uberblock: verify its rootbp checksum against the MOS block on disk.
    check_uberblock_rootbp(&mut out, image, &l0);

    // Vdev-label divergence across the four labels.
    check_label_divergence(&mut out, image, &l0);

    // Reachable-tree blkptr checksum sweep (from the active uberblock's rootbp).
    sweep_reachable_blkptrs(&mut out, image, &l0);

    out
}

/// Verify the active uberblock's `ub_rootbp` checksum against the MOS objset
/// block it points at. A mismatch is `ZFS-UBERBLOCK-CHECKSUM-MISMATCH`; an
/// impossible rootbp size is `ZFS-IMPOSSIBLE-GEOMETRY`.
fn check_uberblock_rootbp(out: &mut Vec<Anomaly>, image: &[u8], l0: &VdevLabel) {
    let ub = &l0.active_uberblock;
    let bp = ub.rootbp_full();
    match blkptr_checksum_verdict(image, &bp) {
        ChecksumVerdict::Mismatch => {
            out.push(Anomaly::new(AnomalyKind::UberblockChecksumMismatch {
                txg: ub.txg,
                slot: l0.active_slot,
            }));
        }
        ChecksumVerdict::AllocationBomb { value, cap } => {
            out.push(Anomaly::new(AnomalyKind::ImpossibleGeometry {
                field: "ub_rootbp LSIZE",
                value,
                limit: cap,
            }));
        }
        ChecksumVerdict::Ok | ChecksumVerdict::Unverified | ChecksumVerdict::Unreadable => {}
    }
}

/// The verdict of verifying a block pointer's checksum against the image.
enum ChecksumVerdict {
    /// Checksum recomputed and matched.
    Ok,
    /// Checksum recomputed and did NOT match — a forensic finding.
    Mismatch,
    /// The checksum function is off/unsupported — not verified.
    Unverified,
    /// No DVA could be read (the block lies outside the image) — not a checksum
    /// finding (a truncated image, not a tamper).
    Unreadable,
    /// The declared logical size is an allocation bomb — geometry error.
    AllocationBomb {
        /// The declared logical size (bytes).
        value: u64,
        /// The cap breached (bytes).
        cap: u64,
    },
}

/// Hard cap on a block's logical size, mirroring `zfs_core::MAX_BLOCK_SIZE`.
const MAX_BLOCK_SIZE: u64 = 32 * 1024 * 1024;

/// Verify a blkptr's on-disk checksum by re-reading the PSIZE bytes at its DVA(s)
/// and recomputing. Returns the verdict without allocating a decompressed copy
/// (checksums are over the on-disk PSIZE bytes, so no decompress is needed).
fn blkptr_checksum_verdict(image: &[u8], bp: &Blkptr) -> ChecksumVerdict {
    if bp.embedded || bp.is_hole() {
        // Embedded/hole blocks carry no independent checksum.
        return ChecksumVerdict::Unverified;
    }
    let lsize = bp.lsize_bytes() as u64;
    if lsize == 0 || lsize > MAX_BLOCK_SIZE {
        return ChecksumVerdict::AllocationBomb {
            value: lsize,
            cap: MAX_BLOCK_SIZE,
        };
    }
    let kind = ChecksumType::from_raw(bp.checksum);
    if matches!(
        kind,
        ChecksumType::Off | ChecksumType::Inherit | ChecksumType::On
    ) {
        return ChecksumVerdict::Unverified;
    }
    let psize = bp.psize_bytes();
    for dva in &bp.dvas {
        if dva.is_empty() {
            continue;
        }
        let phys = dva.physical_byte_offset() as usize;
        let Some(raw) = image.get(phys..phys.saturating_add(psize)) else {
            continue;
        };
        // An all-zero target region is unallocated / absent space (an incomplete
        // or carved image), not a corrupt block — a zeroed block can never match
        // a real checksum, so treating it as a mismatch would false-positive on a
        // truncated image. Skip it as Unreadable; a genuinely corrupt block still
        // carries non-zero bytes that fail the checksum.
        if raw.iter().all(|&b| b == 0) {
            return ChecksumVerdict::Unreadable;
        }
        return match checksum::verify(kind, bp.byteorder, raw, bp.checksum_words) {
            Some(true) => ChecksumVerdict::Ok,
            Some(false) => ChecksumVerdict::Mismatch,
            None => ChecksumVerdict::Unverified,
        };
    }
    ChecksumVerdict::Unreadable
}

/// Read a vdev label's decoded `pool_guid`/`txg`/`ashift`, or `None` if the label
/// (or its nvlist config) cannot be parsed at that offset.
fn label_identity(image: &[u8], off: u64) -> Option<(u64, u64, u64)> {
    let start = usize::try_from(off).ok()?;
    let bytes = image.get(start..start.saturating_add(LABEL_SIZE))?;
    // A label whose nvlist config region is absent cannot be reconciled.
    let _ = bytes.get(NVLIST_OFFSET..NVLIST_OFFSET.saturating_add(NVLIST_SIZE))?;
    let label = VdevLabel::parse(bytes).ok()?;
    let guid = label.config.get_u64("pool_guid")?;
    let txg = label.config.get_u64("txg").unwrap_or(0);
    let ashift = label.config.vdev_tree().map_or(0, |v| v.ashift);
    Some((guid, txg, ashift))
}

/// Compare the four vdev labels' configs; flag any label that diverges in
/// `pool_guid` / `ashift`, or that fails to parse while the vdev is otherwise a
/// well-formed four-label device.
///
/// Divergence is a **whole-vdev** signal, so it is checked only when the image is
/// a complete labelled vdev: the reference back label **L3 must parse**. That
/// gate keeps a partition slice or a truncated/carved image (whose tail label
/// slots are legitimately absent or zeroed) from mis-reporting its missing labels
/// as tamper. Inside a well-formed vdev, an L2 that cannot parse while L0/L1/L3
/// do — or a label whose `pool_guid`/`ashift` differs from the L0 baseline — is
/// consistent with a torn or spliced label. `txg` legitimately varies across
/// labels mid-transaction, so it is not a divergence signal; `pool_guid` and
/// `ashift` are pool-invariant.
fn check_label_divergence(out: &mut Vec<Anomaly>, image: &[u8], l0: &VdevLabel) {
    let Some(base_guid) = l0.config.get_u64("pool_guid") else {
        return; // no baseline identity to compare against
    };
    let base_ashift = l0.config.vdev_tree().map_or(0, |v| v.ashift);

    let image_len = image.len() as u64;
    // Not a complete four-label vdev: no back-label pair fits. Divergence is a
    // whole-vdev check, so skip it (a truncated/partition image is not tamper).
    if image_len < 4 * LABEL_SIZE as u64 {
        return;
    }
    let l3_off = image_len - LABEL_SIZE as u64;
    // The reference back label must parse for this to be a well-formed vdev;
    // otherwise the tail is not a labelled region and "missing labels" is not a
    // divergence signal.
    if label_identity(image, l3_off).is_none() {
        return;
    }

    // Compare L1 and L2 against the L0 baseline (L3 is the reference that just
    // parsed; still compare its identity for a spliced-back-label case).
    let candidates: [(usize, u64); 3] = [
        (1, LABEL_SIZE as u64),
        (2, image_len - 2 * LABEL_SIZE as u64),
        (3, l3_off),
    ];
    for (idx, off) in candidates {
        match label_identity(image, off) {
            None => out.push(Anomaly::new(AnomalyKind::LabelDivergence {
                field: "config",
                label: idx,
                reason: "vdev label config could not be parsed while the other labels did — \
                         consistent with a torn label in an otherwise well-formed vdev"
                    .to_string(),
            })),
            Some((guid, _txg, ashift)) => {
                if guid != base_guid {
                    out.push(Anomaly::new(AnomalyKind::LabelDivergence {
                        field: "pool_guid",
                        label: idx,
                        reason: format!("pool_guid {guid} differs from L0 baseline {base_guid}"),
                    }));
                }
                if ashift != base_ashift {
                    out.push(Anomaly::new(AnomalyKind::LabelDivergence {
                        field: "ashift",
                        label: idx,
                        reason: format!("ashift {ashift} differs from L0 baseline {base_ashift}"),
                    }));
                }
            }
        }
    }
}

/// Sweep the reachable MOS tree for blkptr checksum mismatches: read the MOS
/// objset via the active uberblock's rootbp, then verify each of the MOS
/// meta-dnode's top-level block pointers against the block it names. A mismatch
/// is `ZFS-BLKPTR-CHECKSUM-MISMATCH` — a dead / corrupt / tampered reachable
/// block, distinct from the top-of-tree rootbp check.
fn sweep_reachable_blkptrs(out: &mut Vec<Anomaly>, image: &[u8], l0: &VdevLabel) {
    let ub = &l0.active_uberblock;
    // Read the MOS objset via the rootbp (best-effort — a broken rootbp is
    // already reported by check_uberblock_rootbp).
    let rootbp = ub.rootbp_full();
    let Ok(mos_block) = read_block(image, &rootbp) else {
        return;
    };
    let Ok(mos) = ObjsetPhys::parse(&mos_block.data, ub.endian) else {
        return; // cov:unreachable: a readable rootbp block parses as an objset on a real pool
    };

    // Sweep the MOS meta-dnode's top-level block pointers: each names a reachable
    // metadata block whose checksum we can verify independently. A mismatch is a
    // corrupt/tampered block distinct from the rootbp-level check.
    let mut budget: usize = 4096;
    for bp in &mos.meta_dnode.blkptrs {
        if budget == 0 {
            break; // cov:unreachable: a real MOS meta-dnode has a handful of top blkptrs
        }
        budget -= 1;
        if bp.embedded || bp.is_hole() {
            continue;
        }
        if let ChecksumVerdict::Mismatch = blkptr_checksum_verdict(image, bp) {
            let dva_offset = bp
                .dvas
                .iter()
                .find(|d| !d.is_empty())
                .map_or(0, |d| d.physical_byte_offset());
            out.push(Anomaly::new(AnomalyKind::BlkptrChecksumMismatch {
                dva_offset,
                object_type: bp.object_type,
            }));
        }
    }
}

/// Audit an image and convert each F-INTEGRITY anomaly to a canonical [`Finding`]
/// tagged with `scope`.
#[must_use]
pub fn audit_findings(image: &[u8], scope: &str) -> Vec<Finding> {
    let source = Source {
        analyzer: "zfs-forensic".to_string(),
        scope: scope.to_string(),
        version: None,
    };
    audit_image(image)
        .iter()
        .map(|a| a.to_finding(source.clone()))
        .collect()
}

// ── F-CARVE: CoW deleted-file recovery ────────────────────────────────────────

/// A file recovered from a ZFS snapshot: present in a snapshot's ZPL root
/// directory but absent from the live filesystem, so it was deleted. Its content
/// was carved from the snapshot's (pinned, un-overwritten) blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredFile {
    /// The recovered file's name (its directory-entry name in the snapshot).
    pub path: String,
    /// The recovery source — the snapshot name (or `snapshot obj N` when the
    /// name is unavailable), for the F-CARVE `source` field.
    pub source: String,
    /// The object id (inode) within the snapshot's objset.
    pub inode: u64,
    /// The file's logical size in bytes (from the snapshot's SA metadata).
    pub size: u64,
    /// The carved file content.
    pub content: Vec<u8>,
    /// The carved content's sha256, lower-hex (the recovery gate).
    pub content_sha256: String,
}

/// Recover deleted files from ZFS snapshots over a whole `image` (F-CARVE).
///
/// ZFS is copy-on-write and a **snapshot** pins the pre-delete state of a
/// dataset. This:
///
/// 1. parses the L0 label → active uberblock → MOS objset,
/// 2. walks MOS object directory → `root_dataset` (DSL dir) →
///    `dd_head_dataset_obj` (the live head dataset),
/// 3. reads the live dataset's ZPL root directory (the current file set),
/// 4. follows the head dataset's `ds_prev_snap_obj` chain — each snapshot DSL
///    dataset's `ds_bp` points at that snapshot's ZPL objset — reads each
///    snapshot's root directory, and
/// 5. diffs: a name present in a snapshot's root but absent from the live root
///    was deleted; its content is carved from the snapshot's blocks via
///    `zpl_read_file`.
///
/// Recovery succeeds while the snapshot's blocks survive (a snapshot pins them
/// against `CoW` reuse, so this is the reliable path). The alternate
/// uberblock-history path (an older ring slot's MOS) is *best-effort* and
/// state-dependent — it returns nothing rather than fabricating once the old
/// tree blocks are overwritten — and is not walked here (snapshots are the
/// reliable source of pre-delete state).
///
/// Malformed input never panics; a non-ZFS or truncated image yields nothing.
#[must_use]
pub fn recover_deleted(image: &[u8]) -> Vec<RecoveredFile> {
    let mut out = Vec::new();

    let Some((mos, endian)) = open_mos(image) else {
        return out;
    };

    // MOS object directory (object 1) → root_dataset → DSL dir → head dataset.
    let Some(objdir) = mos_dnode(image, &mos, 1) else {
        return out;
    };
    let Ok(objdir_data) = read_zap_object(image, &objdir) else {
        return out; // cov:unreachable: the MOS object directory is always a readable ZAP on a real pool
    };
    let Some(root_dataset) = zap_lookup(&objdir_data, "root_dataset") else {
        return out;
    };
    let Some(dsl_dir) = mos_dnode(image, &mos, root_dataset) else {
        return out; // cov:unreachable: root_dataset names a live MOS object on a real pool
    };
    let head = dsl_dir_head_dataset(&dsl_dir);
    if head == 0 {
        return out;
    }
    let Some(head_ds) = mos_dnode(image, &mos, head) else {
        return out; // cov:unreachable: dd_head_dataset_obj names a live MOS object on a real pool
    };

    // The live filesystem's root directory (the current file set).
    let live_names = dataset_root_names(image, &head_ds, endian);

    // Walk the snapshot chain (newest → oldest) via ds_prev_snap_obj.
    let mut snap_obj = dsl_dataset_prev_snap(&head_ds);
    let mut budget: usize = 4096; // bound a lying/cyclic chain
    let mut seen: Vec<u64> = Vec::new();
    while snap_obj != 0 && budget > 0 {
        budget -= 1;
        if seen.contains(&snap_obj) {
            break; // a cyclic prev_snap pointer — stop
        }
        seen.push(snap_obj);

        let Some(snap_ds) = mos_dnode(image, &mos, snap_obj) else {
            break;
        };
        recover_from_snapshot(
            image,
            &mos,
            &snap_ds,
            snap_obj,
            endian,
            &live_names,
            &mut out,
        );
        snap_obj = dsl_dataset_prev_snap(&snap_ds);
    }

    out
}

/// Parse the L0 label → active uberblock → MOS objset, returning the MOS and its
/// byte order. `None` for a non-ZFS / truncated image.
fn open_mos(image: &[u8]) -> Option<(ObjsetPhys, Endian)> {
    let l0_bytes = image.get(0..LABEL_SIZE)?;
    let l0 = VdevLabel::parse(l0_bytes).ok()?;
    let endian = l0.active_uberblock.endian;
    let rootbp = l0.active_uberblock.rootbp_full();
    let block = read_block(image, &rootbp).ok()?;
    let mos = ObjsetPhys::parse(&block.data, endian).ok()?;
    Some((mos, endian))
}

/// The set of `(name, object_id)` entries in a DSL dataset's ZPL root directory.
/// Empty when the dataset's objset or root cannot be read.
fn dataset_root_names(image: &[u8], dataset: &Dnode, endian: Endian) -> Vec<(String, u64)> {
    let Some(zpl) = dataset_zpl_objset(image, dataset, endian) else {
        return Vec::new();
    };
    let Some(root) = zpl_master_root(image, &zpl) else {
        return Vec::new();
    };
    zpl_list_dir(image, &zpl, root)
}

/// Read a DSL dataset dnode's ZPL `objset_phys_t` via its `ds_bp`.
fn dataset_zpl_objset(image: &[u8], dataset: &Dnode, endian: Endian) -> Option<ObjsetPhys> {
    let ds_bp: Blkptr = dsl_dataset_bp(dataset);
    let block = read_block(image, &ds_bp).ok()?;
    ObjsetPhys::parse(&block.data, endian).ok()
}

/// Diff one snapshot's ZPL root against the live root and carve any file present
/// in the snapshot but absent live.
fn recover_from_snapshot(
    image: &[u8],
    _mos: &ObjsetPhys,
    snap_ds: &Dnode,
    snap_obj: u64,
    endian: Endian,
    live_names: &[(String, u64)],
    out: &mut Vec<RecoveredFile>,
) {
    let Some(zpl) = dataset_zpl_objset(image, snap_ds, endian) else {
        return;
    };
    let Some(root) = zpl_master_root(image, &zpl) else {
        return; // cov:unreachable: a snapshot ZPL objset always has a master node ROOT
    };
    let source = format!("snapshot obj {snap_obj}");
    for (name, obj) in zpl_list_dir(image, &zpl, root) {
        // Present live → not deleted.
        if live_names.iter().any(|(n, _)| *n == name) {
            continue;
        }
        // Already recovered from a newer snapshot → keep the first.
        if out.iter().any(|r| r.path == name) {
            continue;
        }
        // Carve the content from the snapshot's (pinned) blocks.
        let Ok(content) = zpl_read_file(image, &zpl, obj) else {
            continue;
        };
        let content_sha256 = sha256_hex(&content);
        out.push(RecoveredFile {
            path: name,
            source: source.clone(),
            inode: obj,
            size: content.len() as u64,
            content,
            content_sha256,
        });
    }
}

// ── shared private helpers ────────────────────────────────────────────────────

/// SHA-256 of `data`, lower-hex — the recovery gate compared to the mint-recorded
/// ground truth. Uses the audited `sha2` crate (never hand-rolled), re-exported
/// through `zfs-core`'s dependency graph.
fn sha256_hex(data: &[u8]) -> String {
    // zfs_core::checksum::sha256 packs the digest as four big-endian u64 words;
    // reassemble the 32-byte digest and hex-encode it.
    let words = checksum::sha256(data);
    let mut hex = String::with_capacity(64);
    use std::fmt::Write as _;
    for w in words {
        let _ = write!(hex, "{w:016x}");
    }
    hex
}

#[cfg(test)]
mod unit {
    use super::sha256_hex;

    #[test]
    fn sha256_of_empty_and_known_input() {
        assert_eq!(
            sha256_hex(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
