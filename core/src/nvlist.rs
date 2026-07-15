//! XDR-encoded nvlist (name/value pair list) parser — the ZFS pool config.
//!
//! Each vdev label carries a 112 KiB packed nvlist describing the pool: its
//! `version`, `name`, `pool_guid`, `txg`, and a nested `vdev_tree` giving
//! `ashift`/`asize` and the vdev topology. This is the pool bootstrap.
//!
//! # On-disk layout (verified against `zdb -l`)
//!
//! The packed buffer opens with a 4-byte header — `encoding` (`0x01` = XDR),
//! `endian` (host order of the writer), and two reserved bytes — followed by the
//! XDR nvlist body. Every integer in the body is **big-endian** (XDR), regardless
//! of the pool's native order. The body is:
//!
//! - `nvl_version` (`i32`), `nvl_nvflag` (`u32`), then a sequence of nvpairs.
//! - Each nvpair: `encoded_size` (`i32`), `decoded_size` (`i32`), name as an XDR
//!   string (`len` `i32` + bytes padded up to a 4-byte boundary), `data_type`
//!   (`i32`), `nelem` (`i32`), then the value(s).
//! - A terminating nvpair with `encoded_size == 0` ends the list.
//! - A nested nvlist value (`DATA_TYPE_NVLIST`) is `nvl_version` + `nvl_nvflag`
//!   followed by its own nvpairs (no repeated 4-byte packed header).

use crate::bytes::{be_u32, be_u64, u8_at};
use crate::error::ZfsError;

/// XDR encoding marker for a packed nvlist (`NV_ENCODE_XDR`).
const NV_ENCODE_XDR: u8 = 1;

/// `DATA_TYPE_UINT64`.
const DATA_TYPE_UINT64: i32 = 8;
/// `DATA_TYPE_STRING`.
const DATA_TYPE_STRING: i32 = 9;
/// `DATA_TYPE_NVLIST` (a nested nvlist).
const DATA_TYPE_NVLIST: i32 = 19;

/// Upper bound on an nvpair name length (bytes) — allocation-bomb guard.
const MAX_NAME_LEN: u64 = 4096;
/// Upper bound on a string value length (bytes) — allocation-bomb guard.
const MAX_STRING_LEN: u64 = 65536;
/// Upper bound on the number of nvpairs in one list — allocation-bomb guard.
const MAX_PAIRS: usize = 4096;
/// Upper bound on nested-nvlist recursion depth — allocation-bomb guard.
const MAX_DEPTH: usize = 16;

/// A decoded nvpair value (the subset P0 needs from the pool config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NvValue {
    /// `DATA_TYPE_UINT64`.
    U64(u64),
    /// `DATA_TYPE_STRING`.
    Str(String),
    /// `DATA_TYPE_NVLIST` (nested).
    NvList(NvList),
}

/// A decoded nvlist: an ordered set of `(name, value)` pairs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NvList {
    pairs: Vec<(String, NvValue)>,
}

impl NvList {
    /// Look up a name, returning the first matching value.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&NvValue> {
        self.pairs.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// Convenience: look up a `u64`-typed value by name.
    #[must_use]
    pub fn get_u64(&self, name: &str) -> Option<u64> {
        match self.get(name) {
            Some(NvValue::U64(v)) => Some(*v),
            _ => None,
        }
    }

    /// Convenience: look up a string-typed value by name.
    #[must_use]
    pub fn get_str(&self, name: &str) -> Option<&str> {
        match self.get(name) {
            Some(NvValue::Str(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Convenience: look up a nested-nvlist value by name.
    #[must_use]
    pub fn get_nvlist(&self, name: &str) -> Option<&NvList> {
        match self.get(name) {
            Some(NvValue::NvList(l)) => Some(l),
            _ => None,
        }
    }

    /// All `(name, value)` pairs in on-disk order.
    #[must_use]
    pub fn pairs(&self) -> &[(String, NvValue)] {
        &self.pairs
    }

    /// The nested `vdev_tree` decoded into its P0 fields, if present.
    #[must_use]
    pub fn vdev_tree(&self) -> Option<VdevTree> {
        self.get_nvlist("vdev_tree").map(VdevTree::from_nvlist)
    }
}

/// The P0 subset of the nested `vdev_tree` config.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VdevTree {
    /// vdev `type` (e.g. `"file"`, `"disk"`, `"raidz"`, `"mirror"`).
    pub vdev_type: String,
    /// `ashift` — log2 of the minimum allocation/sector size.
    pub ashift: u64,
    /// `asize` — allocatable size of the vdev in bytes.
    pub asize: u64,
    /// vdev `guid`.
    pub guid: u64,
}

impl VdevTree {
    /// Extract the P0 fields from an already-decoded `vdev_tree` nvlist.
    #[must_use]
    pub fn from_nvlist(nv: &NvList) -> Self {
        Self {
            vdev_type: nv.get_str("type").unwrap_or_default().to_owned(),
            ashift: nv.get_u64("ashift").unwrap_or(0),
            asize: nv.get_u64("asize").unwrap_or(0),
            guid: nv.get_u64("guid").unwrap_or(0),
        }
    }
}

/// Parse a packed nvlist config from `data` (the 112 KiB label nvlist region, or
/// any buffer that begins with the 4-byte packed header).
///
/// # Errors
///
/// - [`ZfsError::BadNvlistEncoding`] if the encoding byte is not XDR.
/// - [`ZfsError::NvlistBomb`] if a length/count field exceeds its sane cap.
/// - [`ZfsError::Truncated`] if the buffer ends mid-structure.
pub fn parse(data: &[u8]) -> Result<NvList, ZfsError> {
    let encoding = u8_at(data, 0);
    if encoding != NV_ENCODE_XDR {
        return Err(ZfsError::BadNvlistEncoding {
            encoding,
            offset: 0,
        });
    }
    if data.len() < 4 {
        return Err(ZfsError::Truncated {
            structure: "nvlist header",
            need: 4,
            have: data.len(),
        });
    }
    // The XDR body follows the 4-byte packed header (encoding, endian, 2 rsvd).
    let (list, _consumed) = parse_body(data, 4, 0)?;
    Ok(list)
}

/// Parse an nvlist body (version + nvflag + nvpairs) starting at `off`.
///
/// Returns the decoded list and the offset just past its terminator. `depth`
/// bounds nested recursion.
fn parse_body(data: &[u8], off: usize, depth: usize) -> Result<(NvList, usize), ZfsError> {
    if depth > MAX_DEPTH {
        return Err(ZfsError::NvlistBomb {
            field: "depth",
            value: depth as u64,
            cap: MAX_DEPTH as u64,
        });
    }
    // nvl_version (i32) + nvl_nvflag (u32).
    let mut cur = off.checked_add(8).ok_or(ZfsError::Truncated {
        structure: "nvlist body header",
        need: 8,
        have: data.len().saturating_sub(off),
    })?;
    let mut list = NvList::default();

    for _ in 0..MAX_PAIRS {
        let encoded_size = be_u32(data, cur) as i32;
        if encoded_size == 0 {
            // Terminator nvpair (encoded_size == 0, decoded_size == 0).
            cur = cur.saturating_add(8);
            return Ok((list, cur));
        }
        if encoded_size < 0 {
            return Err(ZfsError::NvlistBomb {
                field: "encoded_size",
                value: u64::from(encoded_size.unsigned_abs()),
                cap: u64::from(i32::MAX.unsigned_abs()),
            });
        }
        let pair_start = cur;
        // encoded_size (4) + decoded_size (4) then the name string.
        let name_off = cur.saturating_add(8);
        let (name, after_name) = read_xdr_string(data, name_off, "nvpair name", MAX_NAME_LEN)?;
        // data_type (i32) + nelem (i32).
        let data_type = be_u32(data, after_name) as i32;
        let value_off = after_name.saturating_add(8);

        let value = match data_type {
            DATA_TYPE_UINT64 => NvValue::U64(be_u64(data, value_off)),
            DATA_TYPE_STRING => {
                let (s, _) = read_xdr_string(data, value_off, "nvpair string", MAX_STRING_LEN)?;
                NvValue::Str(s)
            }
            DATA_TYPE_NVLIST => {
                let (nested, _) = parse_body(data, value_off, depth + 1)?;
                NvValue::NvList(nested)
            }
            // Types P0 does not consume (arrays, bool, nvlist arrays, …) are
            // skipped by encoded_size rather than failing — the config carries
            // fields we do not need, and skipping keeps the walk robust.
            _ => {
                cur = pair_start.saturating_add(encoded_size as usize);
                continue;
            }
        };
        list.pairs.push((name, value));
        cur = pair_start.saturating_add(encoded_size as usize);
        if cur >= data.len() {
            // Ran off the end without a terminator — surface what we decoded.
            return Ok((list, cur));
        }
    }
    Err(ZfsError::NvlistBomb {
        field: "pair_count",
        value: MAX_PAIRS as u64,
        cap: MAX_PAIRS as u64,
    })
}

/// Read an XDR string at `off`: a big-endian `i32` length followed by that many
/// bytes, padded up to a 4-byte boundary. Returns the string and the offset just
/// past the padded value.
fn read_xdr_string(
    data: &[u8],
    off: usize,
    field: &'static str,
    cap: u64,
) -> Result<(String, usize), ZfsError> {
    let len = be_u32(data, off) as i32;
    if len < 0 {
        return Err(ZfsError::NvlistBomb {
            field,
            value: u64::from(len.unsigned_abs()),
            cap,
        });
    }
    let len = u64::from(len.unsigned_abs());
    if len > cap {
        return Err(ZfsError::NvlistBomb {
            field,
            value: len,
            cap,
        });
    }
    let len = len as usize;
    let start = off.saturating_add(4);
    let end = start.checked_add(len).ok_or(ZfsError::Truncated {
        structure: "xdr string",
        need: len,
        have: data.len().saturating_sub(start),
    })?;
    let raw = data.get(start..end).ok_or(ZfsError::Truncated {
        structure: "xdr string",
        need: len,
        have: data.len().saturating_sub(start),
    })?;
    // XDR pads to a 4-byte boundary.
    let padded = (len + 3) & !3;
    let next = start.saturating_add(padded);
    Ok((String::from_utf8_lossy(raw).into_owned(), next))
}

#[cfg(test)]
mod unit {
    use super::{parse, NvList, NvValue, VdevTree};
    use crate::error::ZfsError;

    /// A minimal packed XDR nvlist: header + version/nvflag + one uint64 pair
    /// named `n` + terminator. Encodes big-endian throughout.
    fn one_u64(name: &str, val: u64) -> Vec<u8> {
        let mut b = vec![0x01, 0x01, 0x00, 0x00]; // XDR header
        b.extend_from_slice(&0i32.to_be_bytes()); // nvl_version
        b.extend_from_slice(&1u32.to_be_bytes()); // nvl_nvflag
                                                  // nvpair: encoded_size, decoded_size, name (xdr string), type, nelem, value
        let name_bytes = name.as_bytes();
        let padded = (name_bytes.len() + 3) & !3;
        let mut pair = Vec::new();
        pair.extend_from_slice(&(name_bytes.len() as i32).to_be_bytes());
        pair.extend_from_slice(name_bytes);
        pair.resize(4 + padded, 0);
        pair.extend_from_slice(&8i32.to_be_bytes()); // DATA_TYPE_UINT64
        pair.extend_from_slice(&1i32.to_be_bytes()); // nelem
        pair.extend_from_slice(&val.to_be_bytes());
        let encoded = 8 + pair.len();
        b.extend_from_slice(&(encoded as i32).to_be_bytes());
        b.extend_from_slice(&(encoded as i32).to_be_bytes());
        b.extend_from_slice(&pair);
        b.extend_from_slice(&0i32.to_be_bytes()); // terminator encoded_size
        b.extend_from_slice(&0i32.to_be_bytes()); // terminator decoded_size
        b
    }

    #[test]
    fn parses_a_single_u64_pair() {
        let buf = one_u64("answer", 42);
        let nv = parse(&buf).unwrap();
        assert_eq!(nv.get_u64("answer"), Some(42));
        assert_eq!(nv.pairs().len(), 1);
    }

    #[test]
    fn bad_encoding_is_rejected_with_the_byte() {
        let buf = [0x02, 0x01, 0x00, 0x00, 0, 0, 0, 0];
        assert_eq!(
            parse(&buf),
            Err(ZfsError::BadNvlistEncoding {
                encoding: 0x02,
                offset: 0
            })
        );
    }

    #[test]
    fn header_shorter_than_four_bytes_is_truncated() {
        let buf = [0x01, 0x01]; // right encoding byte, too short
        assert!(matches!(parse(&buf), Err(ZfsError::Truncated { .. })));
    }

    #[test]
    fn empty_buffer_reports_zero_encoding() {
        // u8_at yields 0 out of range, so an empty buffer reads encoding 0.
        assert!(matches!(
            parse(&[]),
            Err(ZfsError::BadNvlistEncoding { encoding: 0, .. })
        ));
    }

    #[test]
    fn oversized_name_length_is_capped() {
        let mut b = vec![0x01, 0x01, 0x00, 0x00];
        b.extend_from_slice(&0i32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&64i32.to_be_bytes()); // encoded_size
        b.extend_from_slice(&64i32.to_be_bytes()); // decoded_size
        b.extend_from_slice(&1_000_000i32.to_be_bytes()); // name len — bomb
        b.resize(256, 0);
        assert!(matches!(
            parse(&b),
            Err(ZfsError::NvlistBomb {
                field: "nvpair name",
                ..
            })
        ));
    }

    #[test]
    fn negative_name_length_is_rejected() {
        let mut b = vec![0x01, 0x01, 0x00, 0x00];
        b.extend_from_slice(&0i32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&64i32.to_be_bytes());
        b.extend_from_slice(&64i32.to_be_bytes());
        b.extend_from_slice(&(-1i32).to_be_bytes()); // negative len
        b.resize(256, 0);
        assert!(matches!(parse(&b), Err(ZfsError::NvlistBomb { .. })));
    }

    #[test]
    fn negative_encoded_size_is_rejected() {
        let mut b = vec![0x01, 0x01, 0x00, 0x00];
        b.extend_from_slice(&0i32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&(-1i32).to_be_bytes()); // negative encoded_size
        b.resize(64, 0);
        assert!(matches!(
            parse(&b),
            Err(ZfsError::NvlistBomb {
                field: "encoded_size",
                ..
            })
        ));
    }

    #[test]
    fn unknown_type_is_skipped_by_encoded_size() {
        // A pair of an unhandled type (e.g. DATA_TYPE_BOOLEAN=1) is skipped; a
        // following uint64 pair still decodes.
        let mut b = vec![0x01, 0x01, 0x00, 0x00];
        b.extend_from_slice(&0i32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        // unknown-type pair: name "x", type 1, nelem 0
        let mut p = Vec::new();
        p.extend_from_slice(&1i32.to_be_bytes()); // name len
        p.extend_from_slice(b"x\0\0\0"); // padded
        p.extend_from_slice(&1i32.to_be_bytes()); // DATA_TYPE_BOOLEAN
        p.extend_from_slice(&0i32.to_be_bytes()); // nelem
        let enc = 8 + p.len();
        b.extend_from_slice(&(enc as i32).to_be_bytes());
        b.extend_from_slice(&(enc as i32).to_be_bytes());
        b.extend_from_slice(&p);
        // then a normal uint64 pair
        let tail = one_u64("k", 7);
        b.extend_from_slice(&tail[12..]); // skip its header+version+nvflag
        let nv = parse(&b).unwrap();
        assert_eq!(nv.get_u64("k"), Some(7));
        assert!(nv.get("x").is_none());
    }

    #[test]
    fn typed_getters_return_none_on_mismatch() {
        let nv = parse(&one_u64("n", 3)).unwrap();
        assert!(nv.get_str("n").is_none()); // it is a u64, not a string
        assert!(nv.get_nvlist("n").is_none());
        assert!(nv.get_u64("absent").is_none());
        assert!(nv.get_str("absent").is_none());
        assert!(nv.get_nvlist("absent").is_none());
        assert!(nv.vdev_tree().is_none());
    }

    #[test]
    fn vdev_tree_defaults_when_fields_absent() {
        let vt = VdevTree::from_nvlist(&NvList::default());
        assert_eq!(vt, VdevTree::default());
        assert_eq!(vt.vdev_type, "");
    }

    #[test]
    fn nvvalue_equality() {
        assert_eq!(NvValue::U64(1), NvValue::U64(1));
        assert_ne!(NvValue::U64(1), NvValue::Str("1".into()));
    }

    /// Serialize one nvpair (name, big-endian type, value bytes) into `out`.
    fn pair(out: &mut Vec<u8>, name: &[u8], data_type: i32, value: &[u8]) {
        let padded = (name.len() + 3) & !3;
        let mut p = Vec::new();
        p.extend_from_slice(&(name.len() as i32).to_be_bytes());
        p.extend_from_slice(name);
        p.resize(4 + padded, 0);
        p.extend_from_slice(&data_type.to_be_bytes());
        p.extend_from_slice(&1i32.to_be_bytes()); // nelem
        p.extend_from_slice(value);
        let enc = 8 + p.len();
        out.extend_from_slice(&(enc as i32).to_be_bytes()); // encoded_size
        out.extend_from_slice(&(enc as i32).to_be_bytes()); // decoded_size
        out.extend_from_slice(&p);
    }

    #[test]
    fn excessive_nesting_depth_is_capped() {
        // Build a chain of nested NVLIST pairs deeper than MAX_DEPTH (16). Each
        // nested value is a body (version + nvflag + child + terminator).
        fn nested_value(remaining: usize) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&0i32.to_be_bytes()); // nvl_version
            body.extend_from_slice(&1u32.to_be_bytes()); // nvl_nvflag
            if remaining > 0 {
                let child = nested_value(remaining - 1);
                pair(&mut body, b"n", 19, &child); // DATA_TYPE_NVLIST
            }
            body.extend_from_slice(&0i32.to_be_bytes()); // terminator
            body.extend_from_slice(&0i32.to_be_bytes());
            body
        }
        let mut buf = vec![0x01, 0x01, 0x00, 0x00]; // XDR header
        buf.extend_from_slice(&nested_value(20)); // 20 > MAX_DEPTH
        assert!(matches!(
            parse(&buf),
            Err(ZfsError::NvlistBomb { field: "depth", .. })
        ));
    }

    #[test]
    fn pair_flush_with_the_buffer_at_the_end_returns_what_decoded() {
        // One valid uint64 pair, then the buffer ends exactly at the pair
        // boundary (no terminator) — the decoder returns the pair it recovered
        // rather than looping or reading past the end.
        let mut buf = vec![0x01, 0x01, 0x00, 0x00];
        buf.extend_from_slice(&0i32.to_be_bytes()); // nvl_version
        buf.extend_from_slice(&1u32.to_be_bytes()); // nvl_nvflag
        pair(&mut buf, b"only", 8, &99u64.to_be_bytes());
        // No terminator appended: `cur` lands at `data.len()` after the pair.
        let nv = parse(&buf).unwrap();
        assert_eq!(nv.get_u64("only"), Some(99));
    }

    #[test]
    fn too_many_pairs_is_capped() {
        // MAX_PAIRS+1 tiny uint64 pairs with no terminator: the loop runs
        // MAX_PAIRS times without hitting a terminator or the end, then the
        // pair-count bomb fires.
        let mut buf = vec![0x01, 0x01, 0x00, 0x00];
        buf.extend_from_slice(&0i32.to_be_bytes()); // nvl_version
        buf.extend_from_slice(&1u32.to_be_bytes()); // nvl_nvflag
        for _ in 0..=super::MAX_PAIRS {
            pair(&mut buf, b"k", 8, &0u64.to_be_bytes()); // DATA_TYPE_UINT64
        }
        // No terminator; buffer holds all pairs so `cur < data.len()` throughout.
        assert!(matches!(
            parse(&buf),
            Err(ZfsError::NvlistBomb {
                field: "pair_count",
                ..
            })
        ));
    }
}
