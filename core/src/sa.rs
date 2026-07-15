//! SA — System Attributes: the modern ZPL file/directory metadata format, plus
//! the legacy `znode_phys_t` it replaced.
//!
//! A file/dir dnode's bonus (bonustype `DMU_OT_SA` = 44) holds an
//! `sa_hdr_phys_t` — magic `SA_MAGIC = 0x2F505A`, then a `sa_layout_info` word
//! encoding the header size and a **layout number** — followed by the packed
//! attribute values. The attributes present, their order, and their sizes are NOT
//! self-describing in the bonus; they are looked up in the **SA registry** stored
//! in the MOS-reachable ZPL objset:
//!
//! - The ZPL master node's `SA_ATTRS` entry names the **SA master object**, a
//!   micro-ZAP with `REGISTRY` and `LAYOUTS` entries.
//! - `REGISTRY` (a micro-ZAP) maps each attribute **name** → a packed u64 encoding
//!   `[length : byteswap : id]` (`ATTR_LENGTH/ATTR_BSWAP/ATTR_NUM`, `sa_impl.h`).
//! - `LAYOUTS` (a fat-ZAP) maps each **layout number** → an ordered array of
//!   attribute ids (u16 each, stored big-endian like every fat-ZAP value).
//!
//! To decode a bonus: read its layout number, fetch that layout's id list, and
//! walk the packed values in order, taking each id's size from the registry. The
//! well-known ZPL attribute ids (`ZPL_MODE`, `ZPL_SIZE`, …) are resolved **by
//! name via the registry** — never hard-coded — so a pool that registered them at
//! different ids still decodes correctly.
//!
//! # `sa_hdr_phys_t` (verified against `sa_impl.h` + `zdb`)
//!
//! | offset | field            | size |
//! |--------|------------------|------|
//! | 0      | `sa_magic`       | 4    | `SA_MAGIC = 0x2F505A` |
//! | 4      | `sa_layout_info` | 2    | `LAYOUT_NUM = bits[0..10)`, `HDRSZ = (bits[10..16))*8` |
//! | 6      | `sa_lengths[]`   | 2×N  | optional variable-attr sizes (skipped by the fixed hdrsz) |
//!
//! Packed attribute data begins at `HDRSZ`. Timestamps are `[u64 sec, u64 nsec]`.
//!
//! # Legacy `znode_phys_t` (bonustype `DMU_OT_ZNODE` = 17, 264-byte fixed struct)
//!
//! atime/mtime/ctime/crtime `[sec,nsec]` at 0/16/32/48, `zp_gen` @64, `zp_mode`
//! @72, `zp_size` @80, `zp_parent` @88, `zp_links` @96 (verified vs `zfs_znode.h`).
//!
//! # Robustness (the Paranoid Gatekeeper standard)
//!
//! The bonus and the registry/layout ZAPs are untrusted. A wrong magic, an
//! unknown layout number, a layout that claims more bytes than the bonus holds, or
//! an unknown attribute id never panics/over-reads: decoding stops at the buffer
//! end and unknown ids are surfaced in [`ZplAttrs::unknown_attr_ids`], not treated
//! as fatal.

use crate::bytes::{le_u16, le_u32, Endian, Reader};
use crate::zap::{zap_list, zap_list_arrays};

/// `SA_MAGIC` — the `sa_hdr_phys_t.sa_magic` value.
pub const SA_MAGIC: u32 = 0x2F_505A;
/// The size of one packed timestamp attribute (`[u64 sec, u64 nsec]`).
pub const SA_TIME_SIZE: usize = 16;
/// The size of the legacy `znode_phys_t` bonus.
pub const ZNODE_PHYS_SIZE: usize = 264;

/// One SA attribute's registration: its numeric id, its byte length, and its
/// byteswap class — decoded from a `REGISTRY` ZAP value (`[length:bswap:id]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaAttrDesc {
    /// The attribute id (`ATTR_NUM`), the value referenced by a layout array.
    pub id: u16,
    /// The attribute's on-disk byte length (`ATTR_LENGTH`); `0` marks a
    /// variable-length attribute whose size comes from the header's length array.
    pub size: u16,
    /// The byteswap class (`ATTR_BSWAP`) — informational; the reader keeps values
    /// in their on-disk order.
    pub bswap: u8,
}

/// The SA attribute registry: attribute **name** → [`SaAttrDesc`].
///
/// Built from the `REGISTRY` micro-ZAP. Also indexes id → size so a layout's
/// id list can be walked without a name.
#[derive(Debug, Clone, Default)]
pub struct SaRegistry {
    by_name: Vec<(String, SaAttrDesc)>,
}

impl SaRegistry {
    /// Look up an attribute by its registered name (e.g. `"ZPL_MODE"`).
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<SaAttrDesc> {
        self.by_name
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| *d)
    }

    /// The registered byte size for attribute id `id`, if known.
    #[must_use]
    pub fn size_of(&self, id: u16) -> Option<u16> {
        self.by_name
            .iter()
            .find(|(_, d)| d.id == id)
            .map(|(_, d)| d.size)
    }

    /// The number of registered attributes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the registry holds no attributes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// The SA layouts: layout number → ordered array of attribute ids.
///
/// Built from the `LAYOUTS` fat-ZAP, whose values are big-endian u16 attr-id
/// arrays.
#[derive(Debug, Clone, Default)]
pub struct SaLayouts {
    by_num: Vec<(u64, Vec<u16>)>,
}

impl SaLayouts {
    /// The ordered attribute-id list for layout number `num`, if defined.
    #[must_use]
    pub fn attr_ids(&self, num: u64) -> Option<&[u16]> {
        self.by_num
            .iter()
            .find(|(n, _)| *n == num)
            .map(|(_, ids)| ids.as_slice())
    }

    /// The number of defined layouts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_num.len()
    }

    /// Whether no layouts are defined.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_num.is_empty()
    }
}

/// Decoded ZPL file/directory metadata — the superset the SA layout carries (and
/// the legacy `znode_phys_t` provides). Timestamps are `(seconds, nanoseconds)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZplAttrs {
    /// `ZPL_MODE` — POSIX mode bits (file type + permissions).
    pub mode: u64,
    /// `ZPL_SIZE` — logical file size in bytes (directory entry count for dirs).
    pub size: u64,
    /// `ZPL_LINKS` — hard-link count.
    pub links: u64,
    /// `ZPL_UID` — owner user id.
    pub uid: u64,
    /// `ZPL_GID` — owner group id.
    pub gid: u64,
    /// `ZPL_GEN` — the txg generation the object was created in.
    pub gen: u64,
    /// `ZPL_PARENT` — the parent directory's object id.
    pub parent: u64,
    /// `ZPL_FLAGS` — ZPL flag bits (`pflags`).
    pub flags: u64,
    /// `ZPL_ATIME` — last access time `(sec, nsec)`.
    pub atime: (u64, u64),
    /// `ZPL_MTIME` — last modification time `(sec, nsec)`.
    pub mtime: (u64, u64),
    /// `ZPL_CTIME` — last inode-change time `(sec, nsec)`.
    pub ctime: (u64, u64),
    /// `ZPL_CRTIME` — creation (birth) time `(sec, nsec)`.
    pub crtime: (u64, u64),
    /// Attribute ids present in the layout that the registry did not name — the
    /// evidence is surfaced (never dropped), so an unusual pool is visible.
    pub unknown_attr_ids: Vec<u16>,
}

/// Parse the SA attribute registration (`REGISTRY`) micro-ZAP into an
/// [`SaRegistry`]. Each entry's u64 value packs `[length:bswap:id]`
/// (`ATTR_LENGTH = bits[24..40)`, `ATTR_BSWAP = bits[16..24)`,
/// `ATTR_NUM = bits[0..16)`).
#[must_use]
pub fn parse_sa_registry(block: &[u8]) -> SaRegistry {
    let by_name = zap_list(block)
        .into_iter()
        .map(|(name, v)| {
            let desc = SaAttrDesc {
                id: (v & 0xFFFF) as u16,
                size: ((v >> 24) & 0xFFFF) as u16,
                bswap: ((v >> 16) & 0xFF) as u8,
            };
            (name, desc)
        })
        .collect();
    SaRegistry { by_name }
}

/// Parse the SA attribute layouts (`LAYOUTS`) fat-ZAP into an [`SaLayouts`]. Each
/// entry's name is the layout number (decimal string) and its value is an array of
/// big-endian u16 attribute ids.
#[must_use]
pub fn parse_sa_layouts(block: &[u8]) -> SaLayouts {
    let by_num = zap_list_arrays_to_layouts(block);
    SaLayouts { by_num }
}

fn zap_list_arrays_to_layouts(block: &[u8]) -> Vec<(u64, Vec<u16>)> {
    let mut out = Vec::new();
    for (name, bytes) in zap_list_arrays(block) {
        let Ok(num) = name.parse::<u64>() else {
            continue;
        };
        // Values are big-endian u16 ints packed contiguously.
        let ids = bytes
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        out.push((num, ids));
    }
    out
}

/// Decode a `DMU_OT_SA` bonus into [`ZplAttrs`], resolving attribute sizes/ids via
/// the registry and the packed order via the layout.
///
/// Returns `None` when the bonus is not a valid SA header (wrong magic / too
/// short) or its layout number is not defined by `layouts`. A layout that claims
/// more bytes than the bonus holds decodes as far as the buffer allows (the tail
/// attributes are left at their [`ZplAttrs::default`] value) and never panics.
#[must_use]
pub fn decode_sa_bonus(
    bonus: &[u8],
    registry: &SaRegistry,
    layouts: &SaLayouts,
    endian: Endian,
) -> Option<ZplAttrs> {
    if le_u32(bonus, 0) != SA_MAGIC {
        return None;
    }
    let info = le_u16(bonus, 4);
    let layout_num = u64::from(info & 0x3FF); // BF32_GET(info, 0, 10)
    let hdrsz = usize::from((info >> 10) & 0x3F) << 3; // BF32_GET_SB(info, 10, 6, 3, 0)
    let ids = layouts.attr_ids(layout_num)?;

    let rd = Reader::new(endian);
    let mut attrs = ZplAttrs::default();
    let mut off = hdrsz;

    // Resolve the well-known ZPL attribute ids BY NAME from the registry (not
    // hard-coded), so a pool that numbered them differently still decodes.
    let id_of = |name: &str| registry.by_name(name).map(|d| d.id);
    let known = KnownAttrs {
        mode: id_of("ZPL_MODE"),
        size: id_of("ZPL_SIZE"),
        links: id_of("ZPL_LINKS"),
        uid: id_of("ZPL_UID"),
        gid: id_of("ZPL_GID"),
        gen: id_of("ZPL_GEN"),
        parent: id_of("ZPL_PARENT"),
        flags: id_of("ZPL_FLAGS"),
        atime: id_of("ZPL_ATIME"),
        mtime: id_of("ZPL_MTIME"),
        ctime: id_of("ZPL_CTIME"),
        crtime: id_of("ZPL_CRTIME"),
    };

    for &id in ids {
        // The size of this attribute comes from the registry; a variable-length
        // attribute (size 0) or an unregistered id has no fixed footprint we can
        // skip past, so decoding stops (the remaining values are inaccessible
        // without the header length array — surfaced, not guessed).
        let Some(size) = registry.size_of(id) else {
            attrs.unknown_attr_ids.push(id);
            break;
        };
        let size = usize::from(size);
        if size == 0 {
            // A variable-length attribute; its footprint lives in the header's
            // sa_lengths[] array, which fixed-layout metadata (mode/size/times)
            // never needs, so stop here rather than mis-skip.
            break;
        }
        if off.saturating_add(size) > bonus.len() {
            break; // lying/oversized layout — decode as far as fits
        }
        assign_known(&mut attrs, &known, id, rd, bonus, off, size);
        off += size;
    }

    Some(attrs)
}

/// Resolved numeric ids of the well-known ZPL attributes for one registry.
struct KnownAttrs {
    mode: Option<u16>,
    size: Option<u16>,
    links: Option<u16>,
    uid: Option<u16>,
    gid: Option<u16>,
    gen: Option<u16>,
    parent: Option<u16>,
    flags: Option<u16>,
    atime: Option<u16>,
    mtime: Option<u16>,
    ctime: Option<u16>,
    crtime: Option<u16>,
}

fn assign_known(
    attrs: &mut ZplAttrs,
    known: &KnownAttrs,
    id: u16,
    rd: Reader,
    bonus: &[u8],
    off: usize,
    size: usize,
) {
    let scalar = || rd.u64(bonus, off);
    let time = || (rd.u64(bonus, off), rd.u64(bonus, off + 8));
    let some = Some(id);
    if some == known.mode && size >= 8 {
        attrs.mode = scalar();
    } else if some == known.size && size >= 8 {
        attrs.size = scalar();
    } else if some == known.links && size >= 8 {
        attrs.links = scalar();
    } else if some == known.uid && size >= 8 {
        attrs.uid = scalar();
    } else if some == known.gid && size >= 8 {
        attrs.gid = scalar();
    } else if some == known.gen && size >= 8 {
        attrs.gen = scalar();
    } else if some == known.parent && size >= 8 {
        attrs.parent = scalar();
    } else if some == known.flags && size >= 8 {
        attrs.flags = scalar();
    } else if some == known.atime && size >= SA_TIME_SIZE {
        attrs.atime = time();
    } else if some == known.mtime && size >= SA_TIME_SIZE {
        attrs.mtime = time();
    } else if some == known.ctime && size >= SA_TIME_SIZE {
        attrs.ctime = time();
    } else if some == known.crtime && size >= SA_TIME_SIZE {
        attrs.crtime = time();
    }
    // Any other (registered but not ZPL-core) attribute is simply skipped by
    // its size — not an error, just metadata this reader does not surface.
}

/// Decode a legacy `znode_phys_t` bonus (bonustype `DMU_OT_ZNODE` = 17) into
/// [`ZplAttrs`]. Returns `None` if the bonus is shorter than the 264-byte struct.
#[must_use]
pub fn decode_znode_phys(bonus: &[u8], endian: Endian) -> Option<ZplAttrs> {
    if bonus.len() < ZNODE_PHYS_SIZE {
        return None;
    }
    let rd = Reader::new(endian);
    let time = |off: usize| (rd.u64(bonus, off), rd.u64(bonus, off + 8));
    Some(ZplAttrs {
        atime: time(0),
        mtime: time(16),
        ctime: time(32),
        crtime: time(48),
        gen: rd.u64(bonus, 64),
        mode: rd.u64(bonus, 72),
        size: rd.u64(bonus, 80),
        parent: rd.u64(bonus, 88),
        links: rd.u64(bonus, 96),
        uid: 0,
        gid: 0,
        flags: 0,
        unknown_attr_ids: Vec::new(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::{
        decode_sa_bonus, decode_znode_phys, parse_sa_layouts, parse_sa_registry, SaAttrDesc,
        SaLayouts, SaRegistry, SA_MAGIC,
    };
    use crate::bytes::Endian;
    use crate::zap::ZBT_MICRO;

    /// Build a micro-ZAP registry block with the given `(name, packed_value)`
    /// entries.
    fn registry_block(entries: &[(&str, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; 64 + entries.len().max(1) * 64];
        b[0..8].copy_from_slice(&ZBT_MICRO.to_le_bytes());
        for (i, (name, val)) in entries.iter().enumerate() {
            let off = 64 + i * 64;
            b[off..off + 8].copy_from_slice(&val.to_le_bytes());
            let nb = name.as_bytes();
            b[off + 14..off + 14 + nb.len()].copy_from_slice(nb);
        }
        b
    }

    /// Pack a registry value: length in bits[24..40), bswap [16..24), id [0..16).
    fn pack(id: u16, size: u16, bswap: u8) -> u64 {
        (u64::from(size) << 24) | (u64::from(bswap) << 16) | u64::from(id)
    }

    #[test]
    fn registry_parses_packed_values() {
        let b = registry_block(&[("ZPL_MODE", pack(5, 8, 0)), ("ZPL_ATIME", pack(0, 16, 5))]);
        let reg = parse_sa_registry(&b);
        assert_eq!(
            reg.by_name("ZPL_MODE"),
            Some(SaAttrDesc {
                id: 5,
                size: 8,
                bswap: 0
            })
        );
        assert_eq!(reg.by_name("ZPL_ATIME").unwrap().size, 16);
        assert_eq!(reg.size_of(5), Some(8));
        assert_eq!(reg.size_of(99), None);
        assert_eq!(reg.len(), 2);
        assert!(!reg.is_empty());
        assert!(SaRegistry::default().is_empty());
    }

    #[test]
    fn layouts_default_is_empty() {
        let l = SaLayouts::default();
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
        assert!(l.attr_ids(0).is_none());
    }

    #[test]
    fn layouts_parse_skips_non_numeric_names() {
        // A micro-ZAP whose entries carry a non-numeric name ("REGISTRY") and a
        // numeric one ("2"): parse_sa_layouts keeps only the numeric layout and
        // `continue`s past the non-numeric name.
        let b = registry_block(&[("REGISTRY", 35), ("2", 0x0006_0005)]);
        let l = parse_sa_layouts(&b);
        // Only the numeric-named entry survives; its 8 LE value bytes regroup into
        // big-endian u16 pairs.
        assert!(l.attr_ids(35).is_none()); // "REGISTRY" skipped
        assert!(l.attr_ids(2).is_some());
        // An all-zero / unknown block yields no layouts.
        assert!(parse_sa_layouts(&vec![0u8; 512]).is_empty());
    }

    /// A registry naming the ZPL core attributes at their real ids/sizes.
    fn core_registry() -> SaRegistry {
        parse_sa_registry(&registry_block(&[
            ("ZPL_ATIME", pack(0, 16, 0)),
            ("ZPL_MTIME", pack(1, 16, 0)),
            ("ZPL_CTIME", pack(2, 16, 0)),
            ("ZPL_CRTIME", pack(3, 16, 0)),
            ("ZPL_GEN", pack(4, 8, 0)),
            ("ZPL_MODE", pack(5, 8, 0)),
            ("ZPL_SIZE", pack(6, 8, 0)),
            ("ZPL_PARENT", pack(7, 8, 0)),
            ("ZPL_LINKS", pack(8, 8, 0)),
            ("ZPL_FLAGS", pack(11, 8, 0)),
            ("ZPL_UID", pack(12, 8, 0)),
            ("ZPL_GID", pack(13, 8, 0)),
        ]))
    }

    /// A layouts table with layout 1 = [mode, size, mtime] and layout 7 unknown.
    fn tiny_layouts() -> SaLayouts {
        SaLayouts {
            by_num: vec![(1, vec![5, 6, 1])],
        }
    }

    /// Build an SA bonus: 8-byte header (layout `num`, hdrsz 8) then packed values.
    fn sa_bonus(num: u16, values: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 8 + values.len()];
        b[0..4].copy_from_slice(&SA_MAGIC.to_le_bytes());
        let info: u16 = (1u16 << 10) | num; // hdrsz field 1 -> 8 bytes; layout num
        b[4..6].copy_from_slice(&info.to_le_bytes());
        b[8..].copy_from_slice(values);
        b
    }

    #[test]
    fn decode_sa_bonus_walks_layout_and_registry() {
        let reg = core_registry();
        let layouts = tiny_layouts();
        // layout 1 = [MODE(8), SIZE(8), MTIME(16)]
        let mut vals = Vec::new();
        vals.extend_from_slice(&0o100_644u64.to_le_bytes());
        vals.extend_from_slice(&123u64.to_le_bytes());
        vals.extend_from_slice(&1_783_939_238u64.to_le_bytes());
        vals.extend_from_slice(&405u64.to_le_bytes());
        let bonus = sa_bonus(1, &vals);
        let a = decode_sa_bonus(&bonus, &reg, &layouts, Endian::Little).unwrap();
        assert_eq!(a.mode, 0o100_644);
        assert_eq!(a.size, 123);
        assert_eq!(a.mtime, (1_783_939_238, 405));
        assert!(a.unknown_attr_ids.is_empty());
    }

    #[test]
    fn decode_sa_bonus_wrong_magic_is_none() {
        let reg = core_registry();
        let layouts = tiny_layouts();
        let bonus = vec![0u8; 32];
        assert!(decode_sa_bonus(&bonus, &reg, &layouts, Endian::Little).is_none());
    }

    #[test]
    fn decode_sa_bonus_unknown_layout_is_none() {
        let reg = core_registry();
        let layouts = tiny_layouts();
        let bonus = sa_bonus(99, &[0u8; 8]);
        assert!(decode_sa_bonus(&bonus, &reg, &layouts, Endian::Little).is_none());
    }

    #[test]
    fn decode_sa_bonus_unknown_attr_id_surfaced_and_stops() {
        let reg = core_registry();
        // layout 2 = [MODE, 250 (unregistered)]
        let layouts = SaLayouts {
            by_num: vec![(2, vec![5, 250])],
        };
        let mut vals = Vec::new();
        vals.extend_from_slice(&0o644u64.to_le_bytes());
        vals.extend_from_slice(&0u64.to_le_bytes());
        let bonus = sa_bonus(2, &vals);
        let a = decode_sa_bonus(&bonus, &reg, &layouts, Endian::Little).unwrap();
        assert_eq!(a.mode, 0o644);
        assert_eq!(a.unknown_attr_ids, vec![250]);
    }

    #[test]
    fn decode_sa_bonus_variable_length_attr_stops() {
        // A layout whose second attr is registered with size 0 (variable): decode
        // stops after the fixed prefix rather than mis-skipping.
        let reg = parse_sa_registry(&registry_block(&[
            ("ZPL_MODE", pack(5, 8, 0)),
            ("ZPL_DACL_ACES", pack(19, 0, 4)),
        ]));
        let layouts = SaLayouts {
            by_num: vec![(3, vec![5, 19])],
        };
        let mut vals = Vec::new();
        vals.extend_from_slice(&0o755u64.to_le_bytes());
        vals.extend_from_slice(&[0xAB; 8]);
        let bonus = sa_bonus(3, &vals);
        let a = decode_sa_bonus(&bonus, &reg, &layouts, Endian::Little).unwrap();
        assert_eq!(a.mode, 0o755);
    }

    #[test]
    fn decode_sa_bonus_oversized_layout_never_over_reads() {
        let reg = core_registry();
        // layout 1 = [MODE(8), SIZE(8), MTIME(16)] = 32 bytes, but give only 8.
        let layouts = tiny_layouts();
        let bonus = sa_bonus(1, &0o600u64.to_le_bytes());
        let a = decode_sa_bonus(&bonus, &reg, &layouts, Endian::Little).unwrap();
        assert_eq!(a.mode, 0o600);
        assert_eq!(a.size, 0); // SIZE did not fit; left at default
    }

    #[test]
    fn znode_phys_decodes_and_rejects_short() {
        let mut b = vec![0u8; 264];
        b[72..80].copy_from_slice(&0o100_600u64.to_le_bytes()); // mode
        b[80..88].copy_from_slice(&4096u64.to_le_bytes()); // size
        b[96..104].copy_from_slice(&2u64.to_le_bytes()); // links
        let a = decode_znode_phys(&b, Endian::Little).unwrap();
        assert_eq!(a.mode, 0o100_600);
        assert_eq!(a.size, 4096);
        assert_eq!(a.links, 2);
        assert!(decode_znode_phys(&[0u8; 100], Endian::Little).is_none());
    }
}
