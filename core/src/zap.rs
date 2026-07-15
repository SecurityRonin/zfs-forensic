//! ZAP — the ZFS Attribute Processor, a persistent name → value(s) store.
//!
//! A ZAP object holds string-keyed entries. ZFS stores small ZAPs inline as a
//! **micro-ZAP** and large ones as a hashed **fat-ZAP**; a caller cannot tell
//! which from the object type (both are `DMU_OT_*` ZAP-ish types), so the format
//! is discovered from the first 8 bytes of the object's data — the
//! `*_block_type` / `zap_block_type` word.
//!
//! # micro-ZAP (`mzap_phys_t`, verified against `zap_impl.h` + `zdb`)
//!
//! One block, ≤ 128 KiB. Header then a packed array of fixed 64-byte entries:
//!
//! | offset | field            | size |
//! |--------|------------------|------|
//! | 0      | `mz_block_type`  | 8    | `ZBT_MICRO` = `(1<<63) \| 3` |
//! | 8      | `mz_salt`        | 8    |
//! | 16     | `mz_normflags`   | 8    |
//! | 24     | `mz_pad[5]`      | 40   |
//! | 64     | `mzap_ent_phys_t[]` | 64 each |
//!
//! Each `mzap_ent_phys_t`: `mze_value`(u64)\@0, `mze_cd`(u32)\@8, `mze_pad`(u16)\@12,
//! `mze_name[50]`\@14 (NUL-terminated). An all-zero slot (empty name) is skipped.
//!
//! # fat-ZAP (`zap_phys_t` + `zap_leaf_phys_t`, verified against `zdb`)
//!
//! Block 0 is the header (`zap_block_type` = `ZBT_HEADER` = `(1<<63) | 1`,
//! `zap_magic` = `0x2f52ab2ab`); the remaining blocks are hash leaves. This
//! reader does not need the pointer table to *enumerate* — it walks every leaf
//! block directly. The object's blocks are read via [`crate::read_dnode_data`]
//! and concatenated (all blocks share one `dblk` size, so leaf block *n* sits at
//! `n * block_size` in the concatenated buffer), which is what [`read_zap_object`]
//! returns; [`zap_list`]/[`zap_lookup`] then operate on that whole-object buffer.
//!
//! `zap_leaf_phys_t` (header 48 bytes): `l_block_type`\@0 (`ZBT_LEAF` = `1<<63`),
//! `l_magic`(u32)\@24 (`0x2ab1eaf`), `l_nentries`(u16)\@30; then `l_hash[nhash]`
//! (u16 each, `nhash = 1 << (block_shift − 5)`) at \@48; then the 24-byte chunk
//! array. Chunk type\@0: `ENTRY` = 252, `ARRAY` = 251, `FREE` = 253. An `ENTRY`
//! points at `ARRAY`-chunk chains for its name and value; **values are stored
//! big-endian** (network order), `le_int_size` bytes each.
//!
//! # Robustness (the Paranoid Gatekeeper standard)
//!
//! The block is untrusted. Entry/chunk counts are bounded by what the block can
//! physically hold; every chunk index is range-checked before use; a lying
//! `le_next` / name / value chunk pointer terminates the chain (a cap on the
//! number of chunks followed prevents an infinite loop on a cyclic pointer);
//! names and values are capped at the block size. Nothing panics or over-reads.

use crate::bytes::{le_u16, le_u32, le_u64, u8_at};
use crate::dnode::Dnode;
use crate::error::ZfsError;
use crate::read::read_dnode_data;

/// `ZBT_MICRO` — a micro-ZAP block's `mz_block_type`.
pub const ZBT_MICRO: u64 = (1 << 63) | 3;
/// `ZBT_HEADER` — a fat-ZAP header block's `zap_block_type`.
pub const ZBT_HEADER: u64 = (1 << 63) | 1;
/// `ZBT_LEAF` — a fat-ZAP leaf block's `l_block_type`.
pub const ZBT_LEAF: u64 = 1 << 63;

/// `ZAP_MAGIC` — the fat-ZAP header magic (`zap_phys_t.zap_magic`).
pub const ZAP_MAGIC: u64 = 0x0002_f52a_b2ab;
/// `ZAP_LEAF_MAGIC` — a fat-ZAP leaf magic (`zap_leaf_phys_t.l_magic`).
pub const ZAP_LEAF_MAGIC: u32 = 0x02ab_1eaf;

/// Size of one micro-ZAP entry (`mzap_ent_phys_t`).
const MZAP_ENT_SIZE: usize = 64;
/// Header size before the micro-ZAP entry array.
const MZAP_HDR_SIZE: usize = 64;
/// Maximum micro-ZAP name length (`MZAP_NAME_LEN`, includes the NUL).
const MZAP_NAME_LEN: usize = 50;

/// Size of one fat-ZAP leaf chunk (`ZAP_LEAF_CHUNKSIZE`).
const ZAP_LEAF_CHUNKSIZE: usize = 24;
/// `zap_leaf_phys_t` header size (before `l_hash[]`).
const ZAP_LEAF_HDR_SIZE: usize = 48;
/// Bytes of payload in one `ARRAY` chunk (`ZAP_LEAF_ARRAY_BYTES`).
const ZAP_LEAF_ARRAY_BYTES: usize = 21;

/// Fat-ZAP leaf chunk type: a name/value array chunk.
const ZAP_CHUNK_ARRAY: u8 = 251;
/// Fat-ZAP leaf chunk type: an entry.
const ZAP_CHUNK_ENTRY: u8 = 252;

/// Read a ZAP object's entire logical data by concatenating every L0 block of
/// `dnode` (blocks `0..=dn_maxblkid`), so a multi-block fat-ZAP is presented as
/// one contiguous buffer to [`zap_list`]/[`zap_lookup`].
///
/// # Errors
///
/// Propagates [`read_dnode_data`] errors for any block along the way.
pub fn read_zap_object(image: &[u8], dnode: &Dnode) -> Result<Vec<u8>, ZfsError> {
    let block_size = dnode.data_block_size();
    // A ZAP object always has a non-zero data block size; a zero would be a
    // corrupt dnode. Bound the block count so a lying dn_maxblkid cannot ask for
    // an unbounded allocation.
    if block_size == 0 {
        return Err(ZfsError::Truncated {
            structure: "zap object (zero block size)",
            need: 1,
            have: 0,
        });
    }
    // Cap total ZAP object size at 64 MiB (a ZAP that large is pathological);
    // this bounds the loop and the allocation against a lying dn_maxblkid.
    let max_blocks = (64 * 1024 * 1024) / block_size;
    let nblocks = (dnode.dn_maxblkid as usize)
        .saturating_add(1)
        .min(max_blocks);
    let mut out = Vec::with_capacity(nblocks.saturating_mul(block_size).min(64 * 1024 * 1024));
    for blkid in 0..nblocks {
        let block = read_dnode_data(image, dnode, blkid as u64)?;
        out.extend_from_slice(&block.data);
    }
    Ok(out)
}

/// List every `(name, value)` entry of a ZAP object, given its whole-object data
/// (one micro-ZAP block, or a concatenated fat-ZAP as [`read_zap_object`]
/// returns). Handles both micro- and fat-ZAP, detected from the block-type word.
///
/// The returned value is the **raw** 64-bit entry value; for a directory ZAP the
/// caller masks the low 48 bits for the object id (the top bits hold the dirent
/// type). Entries whose value is wider than 8 bytes (e.g. a 32-byte salt) are
/// returned with their first 8 bytes folded big-endian.
#[must_use]
pub fn zap_list(block: &[u8]) -> Vec<(String, u64)> {
    match le_u64(block, 0) {
        ZBT_MICRO => micro_list(block),
        ZBT_HEADER => fat_list(block),
        _ => Vec::new(),
    }
}

/// Look up `name` in a ZAP object's data, returning its raw value if present.
/// Handles both micro- and fat-ZAP (detected from the block-type word).
#[must_use]
pub fn zap_lookup(block: &[u8], name: &str) -> Option<u64> {
    zap_list(block)
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
}

/// List every `(name, value_bytes)` entry of a **fat-ZAP** object, preserving the
/// full byte payload of each value rather than folding it to a `u64`.
///
/// This is what wide-value ZAPs need — e.g. the SA `LAYOUTS` object, whose values
/// are arrays of `le_int_size`-byte integers (attr ids). The bytes are returned in
/// the on-disk (big-endian) order the ZAP stored them; the caller re-groups them
/// by the entry's integer size.
///
/// A micro-ZAP has only fixed 8-byte values, so this returns each value's 8 raw
/// little-endian bytes for a micro-ZAP block (rarely needed, but consistent).
#[must_use]
pub fn zap_list_arrays(block: &[u8]) -> Vec<(String, Vec<u8>)> {
    match le_u64(block, 0) {
        ZBT_MICRO => micro_list(block)
            .into_iter()
            .map(|(name, value)| (name, value.to_le_bytes().to_vec()))
            .collect(),
        ZBT_HEADER => fat_list_arrays(block),
        _ => Vec::new(),
    }
}

// ---- micro-ZAP -------------------------------------------------------------

fn micro_list(block: &[u8]) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    // Number of entries that physically fit the block.
    let capacity = block.len().saturating_sub(MZAP_HDR_SIZE) / MZAP_ENT_SIZE;
    for i in 0..capacity {
        let off = MZAP_HDR_SIZE + i * MZAP_ENT_SIZE;
        let value = le_u64(block, off);
        let name_off = off + 14;
        let Some(name_bytes) = block.get(name_off..name_off + MZAP_NAME_LEN) else {
            break; // cov:unreachable: capacity bounds off+64 <= block.len()
        };
        let end = name_bytes
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(MZAP_NAME_LEN);
        if end == 0 {
            continue; // empty slot
        }
        let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
        out.push((name, value));
    }
    out
}

// ---- fat-ZAP ---------------------------------------------------------------

fn fat_list(block: &[u8]) -> Vec<(String, u64)> {
    // The header block's block size is the leaf block size too (one dblk). Every
    // subsequent block-sized region is a leaf; walk them all.
    let block_size = fat_block_size(block);
    if block_size == 0 {
        return Vec::new(); // cov:unreachable: a real fat-ZAP block is >= 512 bytes
    }
    let mut out = Vec::new();
    let mut off = block_size; // block 0 is the header; leaves start at block 1
    while off + ZAP_LEAF_HDR_SIZE <= block.len() {
        let leaf = &block[off..(off + block_size).min(block.len())];
        if le_u64(leaf, 0) == ZBT_LEAF && le_u32(leaf, 24) == ZAP_LEAF_MAGIC {
            fat_leaf_entries(leaf, block_size, &mut out);
        }
        off += block_size;
    }
    out
}

/// Like [`fat_list`] but preserves each entry's full value byte payload (used for
/// wide-value objects such as the SA `LAYOUTS` ZAP).
fn fat_list_arrays(block: &[u8]) -> Vec<(String, Vec<u8>)> {
    let block_size = fat_block_size(block);
    if block_size == 0 {
        return Vec::new(); // cov:unreachable: a real fat-ZAP block is >= 512 bytes
    }
    let mut out = Vec::new();
    let mut off = block_size;
    while off + ZAP_LEAF_HDR_SIZE <= block.len() {
        let leaf = &block[off..(off + block_size).min(block.len())];
        if le_u64(leaf, 0) == ZBT_LEAF && le_u32(leaf, 24) == ZAP_LEAF_MAGIC {
            fat_leaf_entries_arrays(leaf, block_size, &mut out);
        }
        off += block_size;
    }
    out
}

fn fat_leaf_entries_arrays(leaf: &[u8], block_size: usize, out: &mut Vec<(String, Vec<u8>)>) {
    let block_shift = block_size.trailing_zeros() as usize;
    let nhash = 1usize << block_shift.saturating_sub(5);
    let chunk_area = ZAP_LEAF_HDR_SIZE + nhash * 2;
    if chunk_area >= leaf.len() {
        return; // cov:unreachable: nhash*2 < block_size for shift>=6
    }
    let nchunks = (leaf.len() - chunk_area) / ZAP_LEAF_CHUNKSIZE;
    for ci in 0..nchunks {
        let co = chunk_area + ci * ZAP_LEAF_CHUNKSIZE;
        if u8_at(leaf, co) != ZAP_CHUNK_ENTRY {
            continue;
        }
        let le_int_size = usize::from(u8_at(leaf, co + 1));
        let le_name_chunk = le_u16(leaf, co + 4);
        let le_name_numints = le_u16(leaf, co + 6) as usize;
        let le_value_chunk = le_u16(leaf, co + 8);
        let le_value_numints = le_u16(leaf, co + 10) as usize;

        let mut name = array_bytes(leaf, chunk_area, nchunks, le_name_chunk, le_name_numints);
        if name.last() == Some(&0) {
            name.pop();
        }
        let name = String::from_utf8_lossy(&name).into_owned();

        let want = le_int_size.saturating_mul(le_value_numints);
        let value_bytes = array_bytes(leaf, chunk_area, nchunks, le_value_chunk, want);
        if !name.is_empty() {
            out.push((name, value_bytes));
        }
    }
}

/// The fat-ZAP block size, inferred from the buffer by probing where the first
/// leaf begins. Block 0 is the header; block 1 (the first leaf) sits at
/// `block_size`, identifiable by its `ZBT_LEAF` block-type + `ZAP_LEAF_MAGIC`.
/// Try candidate power-of-two sizes small→large so the *smallest* size that lands
/// a valid leaf wins (the true block size — a larger multiple would skip leaves).
///
/// When no second block is present (a header-only buffer) or no leaf signature is
/// found, fall back to the buffer length (a single-block object has no leaves to
/// enumerate, so the fat walk simply finds nothing).
fn fat_block_size(block: &[u8]) -> usize {
    for shift in 9..=17 {
        let bs = 1usize << shift; // 512 .. 128 KiB
        if bs >= block.len() {
            break;
        }
        if le_u64(block, bs) == ZBT_LEAF && le_u32(block, bs + 24) == ZAP_LEAF_MAGIC {
            return bs;
        }
    }
    block.len()
}

fn fat_leaf_entries(leaf: &[u8], block_size: usize, out: &mut Vec<(String, u64)>) {
    // nhash = 1 << (block_shift - 5); chunk area starts after header + hash table.
    let block_shift = block_size.trailing_zeros() as usize;
    let nhash = 1usize << block_shift.saturating_sub(5);
    let chunk_area = ZAP_LEAF_HDR_SIZE + nhash * 2;
    if chunk_area >= leaf.len() {
        return; // cov:unreachable: nhash*2 < block_size for shift>=6
    }
    let nchunks = (leaf.len() - chunk_area) / ZAP_LEAF_CHUNKSIZE;
    for ci in 0..nchunks {
        let co = chunk_area + ci * ZAP_LEAF_CHUNKSIZE;
        if u8_at(leaf, co) != ZAP_CHUNK_ENTRY {
            continue;
        }
        let le_int_size = usize::from(u8_at(leaf, co + 1));
        let le_name_chunk = le_u16(leaf, co + 4);
        let le_name_numints = le_u16(leaf, co + 6) as usize;
        let le_value_chunk = le_u16(leaf, co + 8);
        let le_value_numints = le_u16(leaf, co + 10) as usize;

        let name_bytes = array_bytes(leaf, chunk_area, nchunks, le_name_chunk, le_name_numints);
        let mut name = name_bytes;
        if name.last() == Some(&0) {
            name.pop();
        }
        let name = String::from_utf8_lossy(&name).into_owned();

        // Value: le_int_size bytes per int, big-endian; fold the first 8 bytes.
        let want = le_int_size.saturating_mul(le_value_numints);
        let value_bytes = array_bytes(leaf, chunk_area, nchunks, le_value_chunk, want);
        let mut value = 0u64;
        for &b in value_bytes.iter().take(8) {
            value = (value << 8) | u64::from(b);
        }
        if !name.is_empty() {
            out.push((name, value));
        }
    }
}

/// Follow an `ARRAY`-chunk chain from `start`, collecting up to `want` payload
/// bytes. Bounds every chunk index and caps the chain length at `nchunks` so a
/// cyclic or lying `le_array_next` can never loop forever.
fn array_bytes(leaf: &[u8], chunk_area: usize, nchunks: usize, start: u16, want: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(want.min(4096));
    let mut nc = start;
    let mut hops = 0usize;
    while nc != u16::MAX && (nc as usize) < nchunks && hops < nchunks && out.len() < want {
        let co = chunk_area + (nc as usize) * ZAP_LEAF_CHUNKSIZE;
        if u8_at(leaf, co) != ZAP_CHUNK_ARRAY {
            break;
        }
        if let Some(payload) = leaf.get(co + 1..co + 1 + ZAP_LEAF_ARRAY_BYTES) {
            out.extend_from_slice(payload);
        } else {
            break; // cov:unreachable: chunk index < nchunks keeps co+24 in range
        }
        nc = le_u16(leaf, co + 1 + ZAP_LEAF_ARRAY_BYTES);
        hops += 1;
    }
    out.truncate(want);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::{
        zap_list, zap_lookup, MZAP_ENT_SIZE, MZAP_HDR_SIZE, ZBT_HEADER, ZBT_LEAF, ZBT_MICRO,
    };
    use crate::bytes::Endian;
    use crate::dnode::Dnode;

    fn micro_block(entries: &[(&str, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0..8].copy_from_slice(&ZBT_MICRO.to_le_bytes());
        for (i, (name, val)) in entries.iter().enumerate() {
            let off = MZAP_HDR_SIZE + i * MZAP_ENT_SIZE;
            b[off..off + 8].copy_from_slice(&val.to_le_bytes());
            let nb = name.as_bytes();
            b[off + 14..off + 14 + nb.len()].copy_from_slice(nb);
        }
        b
    }

    #[test]
    fn micro_list_and_lookup_roundtrip() {
        let b = micro_block(&[("ROOT", 34), ("VERSION", 5)]);
        let list = zap_list(&b);
        assert_eq!(list.len(), 2);
        assert_eq!(zap_lookup(&b, "ROOT"), Some(34));
        assert_eq!(zap_lookup(&b, "VERSION"), Some(5));
        assert_eq!(zap_lookup(&b, "MISSING"), None);
    }

    #[test]
    fn unknown_block_type_lists_nothing() {
        let b = vec![0u8; 512]; // block_type 0 -> neither micro nor fat
        assert!(zap_list(&b).is_empty());
        assert_eq!(zap_lookup(&b, "x"), None);
    }

    #[test]
    fn micro_zap_on_garbage_never_panics() {
        assert!(zap_list(&[]).is_empty());
        let mut b = vec![0u8; 100];
        b[0..8].copy_from_slice(&ZBT_MICRO.to_le_bytes());
        let _ = zap_list(&b); // capacity from a too-small block: no panic
    }

    #[test]
    fn fat_leaf_with_no_entries_is_empty() {
        // A 2-block fat-ZAP buffer: header + one leaf with a valid magic but zero
        // entry chunks -> empty list, no panic.
        let bs = 512usize;
        let mut b = vec![0u8; bs * 2];
        b[0..8].copy_from_slice(&ZBT_HEADER.to_le_bytes());
        b[bs..bs + 8].copy_from_slice(&ZBT_LEAF.to_le_bytes());
        b[bs + 24..bs + 28].copy_from_slice(&super::ZAP_LEAF_MAGIC.to_le_bytes());
        assert!(zap_list(&b).is_empty());
    }

    #[test]
    fn fat_header_only_buffer_lists_nothing() {
        // A single-block fat header (no leaf) exercises fat_block_size's
        // break-on-`bs >= len` and the block.len() fallback: no leaves to walk.
        let mut b = vec![0u8; 512];
        b[0..8].copy_from_slice(&ZBT_HEADER.to_le_bytes());
        assert!(zap_list(&b).is_empty());
    }

    #[test]
    fn fat_header_with_no_valid_leaf_signature_falls_back() {
        // Two 512-byte blocks but block 1 is NOT a valid leaf (no magic): the
        // block-size probe finds no leaf and falls back to the buffer length, so
        // enumeration finds nothing (and never over-reads).
        let mut b = vec![0u8; 1024];
        b[0..8].copy_from_slice(&ZBT_HEADER.to_le_bytes());
        // block 1 has ZBT_LEAF type but a WRONG magic -> not recognised.
        b[512..520].copy_from_slice(&ZBT_LEAF.to_le_bytes());
        assert!(zap_list(&b).is_empty());
    }

    #[test]
    fn fat_leaf_entry_with_non_array_name_chunk_is_skipped() {
        // A fat-ZAP with one leaf holding a single ENTRY whose name chunk points
        // at a non-ARRAY chunk: array_bytes breaks, the name is empty, and the
        // entry is dropped (no panic, no over-read).
        let bs = 512usize;
        let mut b = vec![0u8; bs * 2];
        b[0..8].copy_from_slice(&ZBT_HEADER.to_le_bytes());
        let leaf = bs;
        b[leaf..leaf + 8].copy_from_slice(&ZBT_LEAF.to_le_bytes());
        b[leaf + 24..leaf + 28].copy_from_slice(&super::ZAP_LEAF_MAGIC.to_le_bytes());
        // chunk area for a 512-byte leaf: nhash = 1<<(9-5)=16, so 48+32 = 80.
        let chunk_area = leaf + super::ZAP_LEAF_HDR_SIZE + 16 * 2;
        // chunk 0 = ENTRY, name_chunk=1, value_chunk=1 (both point at chunk 1).
        b[chunk_area] = super::ZAP_CHUNK_ENTRY;
        b[chunk_area + 1] = 8; // le_int_size
        b[chunk_area + 4..chunk_area + 6].copy_from_slice(&1u16.to_le_bytes()); // name_chunk
        b[chunk_area + 6..chunk_area + 8].copy_from_slice(&4u16.to_le_bytes()); // name_numints
        b[chunk_area + 8..chunk_area + 10].copy_from_slice(&1u16.to_le_bytes()); // value_chunk
        b[chunk_area + 10..chunk_area + 12].copy_from_slice(&1u16.to_le_bytes()); // value_numints
                                                                                  // chunk 1 is left as type 0 (NOT ZAP_CHUNK_ARRAY) -> array_bytes breaks.
        let list = zap_list(&b);
        assert!(list.is_empty(), "entry with empty name is dropped");
    }

    #[test]
    fn read_zap_object_rejects_zero_block_size() {
        let raw = [0u8; 512]; // datablkszsec = 0 -> data_block_size 0
        let dnode = Dnode::parse(&raw, Endian::Little).unwrap();
        let img = vec![0u8; 16];
        assert!(super::read_zap_object(&img, &dnode).is_err());
    }

    #[test]
    fn zap_list_arrays_micro_folds_value_to_8_le_bytes() {
        // On a micro-ZAP, zap_list_arrays returns each value's 8 raw LE bytes.
        let b = micro_block(&[("ROOT", 34)]);
        let arrays = super::zap_list_arrays(&b);
        assert_eq!(arrays.len(), 1);
        assert_eq!(arrays[0].0, "ROOT");
        assert_eq!(arrays[0].1, 34u64.to_le_bytes().to_vec());
        // An unknown block type yields nothing.
        assert!(super::zap_list_arrays(&[0u8; 512]).is_empty());
    }

    #[test]
    fn zap_list_arrays_fat_preserves_multi_int_value() {
        // A fat-ZAP leaf with one ENTRY: name = "3" (one ARRAY chunk), value = a
        // u16-array [5, 6] stored big-endian across one ARRAY chunk. zap_list_arrays
        // returns the full 4 value bytes (00 05 00 06), which the SA-layouts parser
        // regroups into u16 ids.
        let bs = 512usize;
        let mut b = vec![0u8; bs * 2];
        b[0..8].copy_from_slice(&ZBT_HEADER.to_le_bytes());
        let leaf = bs;
        b[leaf..leaf + 8].copy_from_slice(&ZBT_LEAF.to_le_bytes());
        b[leaf + 24..leaf + 28].copy_from_slice(&super::ZAP_LEAF_MAGIC.to_le_bytes());
        let chunk_area = leaf + super::ZAP_LEAF_HDR_SIZE + 16 * 2;
        // chunk 0 = ENTRY: name in chunk 1, value in chunk 2.
        b[chunk_area] = super::ZAP_CHUNK_ENTRY;
        b[chunk_area + 1] = 2; // le_int_size = 2 (u16 values)
        b[chunk_area + 4..chunk_area + 6].copy_from_slice(&1u16.to_le_bytes()); // name_chunk
        b[chunk_area + 6..chunk_area + 8].copy_from_slice(&1u16.to_le_bytes()); // name_numints
        b[chunk_area + 8..chunk_area + 10].copy_from_slice(&2u16.to_le_bytes()); // value_chunk
        b[chunk_area + 10..chunk_area + 12].copy_from_slice(&2u16.to_le_bytes()); // value_numints
        let c1 = chunk_area + super::ZAP_LEAF_CHUNKSIZE; // chunk 1 (name)
        b[c1] = super::ZAP_CHUNK_ARRAY;
        b[c1 + 1] = b'3'; // name payload "3"
        b[c1 + 1 + super::ZAP_LEAF_ARRAY_BYTES..c1 + 3 + super::ZAP_LEAF_ARRAY_BYTES]
            .copy_from_slice(&u16::MAX.to_le_bytes()); // next = end
        let c2 = chunk_area + 2 * super::ZAP_LEAF_CHUNKSIZE; // chunk 2 (value)
        b[c2] = super::ZAP_CHUNK_ARRAY;
        // value bytes: two u16 ids [5, 6] big-endian = 00 05 00 06.
        b[c2 + 1..c2 + 5].copy_from_slice(&[0, 5, 0, 6]);
        b[c2 + 1 + super::ZAP_LEAF_ARRAY_BYTES..c2 + 3 + super::ZAP_LEAF_ARRAY_BYTES]
            .copy_from_slice(&u16::MAX.to_le_bytes());

        let arrays = super::zap_list_arrays(&b);
        assert_eq!(arrays.len(), 1);
        assert_eq!(arrays[0].0, "3");
        assert_eq!(arrays[0].1, vec![0u8, 5, 0, 6]);
    }
}
