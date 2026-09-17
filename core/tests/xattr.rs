//! ZFS extended attributes — both storage modes.
//!
//! ZFS stores extended attributes two structurally different ways, chosen by the
//! dataset's `xattr` property, and a reader that handles only one silently
//! reports "no attributes" on half the pools it meets:
//!
//! | `xattr=` | where the attributes live |
//! |---|---|
//! | `sa` | a packed **nvlist** in the `ZPL_DXATTR` System Attribute |
//! | `dir` | a hidden **ZAP directory**, each attribute a separate file object |
//!
//! Both fixtures were minted in a `FreeBSD` 15.0 VM and the mode is confirmed by
//! the filesystem itself (`zfs get xattr` → `sa` / `dir`), not assumed from the
//! generator command.
//!
//! ## Why this needs new code rather than the existing SA walk
//!
//! `decode_sa_bonus` stops at the first variable-length attribute, and says so:
//!
//! > a variable-length attribute; its footprint lives in the header's
//! > `sa_lengths[]` array, which fixed-layout metadata (mode/size/times) never
//! > needs, so stop here rather than mis-skip.
//!
//! `ZPL_DXATTR` **is** that variable-length attribute, so the existing walk can
//! never reach it. Reaching it means reading `sa_lengths[]` — the array the
//! current code correctly declines to guess past.
//!
//! ## Ground truth
//!
//! `zdb -e -p . -dddd xpsa 2` on the `sa` fixture:
//!
//! ```text
//!      2    1   128K    512     4K     512    512  100.00  ZFS plain file
//!                                          292   bonus  System attributes
//!     SA xattrs: 108 bytes, 2 entries
//!         small = tiny-value
//!         comment = a second attribute
//! ```
//!
//! 108 bytes fits the 292-byte bonus, so this fixture exercises the **bonus**
//! path and NOT the spill-block path — stated because the dnode flags carry no
//! `SPILL_BLKPTR` here, and a decoder that only ever saw this image would have
//! its spill handling unexercised.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Read;

use zfs_core::{list_xattrs, zpl_objset, Endian, ObjsetPhys, VdevLabel};

/// `file.txt` is object 2 in both pools; `adir` is 128 (`sa`) / 384 (`dir`).
const FILE_OBJ: u64 = 2;

fn image(name: &str) -> Vec<u8> {
    let gz: &[u8] = match name {
        "sa" => include_bytes!("../../tests/data/zfs_sa.img.gz"),
        "dir" => include_bytes!("../../tests/data/zfs_dir.img.gz"),
        other => panic!("no fixture {other}"),
    };
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut out)
        .expect("fixture must decompress");
    out
}

fn zpl(img: &[u8]) -> ObjsetPhys {
    let label = VdevLabel::parse(&img[..zfs_core::LABEL_SIZE]).expect("vdev label");
    let bp = label.active_uberblock.rootbp_full();
    let block = zfs_core::read_block(img, &bp).expect("root block");
    let mos = ObjsetPhys::parse(&block.data, Endian::Little).expect("MOS");
    zpl_objset(img, &mos).expect("ZPL objset")
}

/// `xattr=sa`: the attributes are an nvlist inside `ZPL_DXATTR`.
#[test]
fn sa_mode_attributes_are_decoded_from_the_dxattr_nvlist() {
    let img = image("sa");
    let zpl = zpl(&img);
    let attrs = list_xattrs(&img, &zpl, FILE_OBJ);

    // Non-zero baseline: zdb reported "2 entries".
    assert_eq!(
        attrs.len(),
        2,
        "zdb: SA xattrs 108 bytes, 2 entries: {attrs:?}"
    );
    let get = |n: &str| -> Vec<u8> {
        attrs
            .iter()
            .find(|x| x.name == n)
            .unwrap_or_else(|| panic!("missing {n}; got {attrs:?}"))
            .value
            .clone()
    };
    assert_eq!(get("small"), b"tiny-value");
    assert_eq!(get("comment"), b"a second attribute");
}

/// `xattr=dir`: the attributes are files in a hidden directory.
///
/// Structurally unrelated to the `sa` path — a decoder that handled only the
/// nvlist would return an empty list here, which is indistinguishable from a
/// file that genuinely has none.
#[test]
fn dir_mode_attributes_are_decoded_from_the_hidden_directory() {
    let img = image("dir");
    let zpl = zpl(&img);
    let attrs = list_xattrs(&img, &zpl, FILE_OBJ);

    assert_eq!(
        attrs.len(),
        2,
        "lsextattr showed small and comment on this file too: {attrs:?}"
    );
    let get = |n: &str| -> Vec<u8> {
        attrs
            .iter()
            .find(|x| x.name == n)
            .unwrap_or_else(|| panic!("missing {n}; got {attrs:?}"))
            .value
            .clone()
    };
    assert_eq!(get("small"), b"tiny-value");
    assert_eq!(get("comment"), b"a second attribute");
}

/// Both modes must agree, because the same attributes were written to both.
///
/// This is the assertion that makes the two paths check each other: they share
/// no code, so agreement is evidence neither is quietly returning something
/// shaped right but wrong.
#[test]
fn both_storage_modes_yield_the_same_attributes() {
    let sa = image("sa");
    let dir = image("dir");
    let mut a: Vec<(String, Vec<u8>)> = list_xattrs(&sa, &zpl(&sa), FILE_OBJ)
        .into_iter()
        .map(|x| (x.name, x.value))
        .collect();
    let mut b: Vec<(String, Vec<u8>)> = list_xattrs(&dir, &zpl(&dir), FILE_OBJ)
        .into_iter()
        .map(|x| (x.name, x.value))
        .collect();
    a.sort();
    b.sort();
    assert!(!a.is_empty(), "the comparison must not be vacuous");
    assert_eq!(a, b, "the same attributes were written to both pools");
}

/// An object with no attributes yields an empty list, not an error.
#[test]
fn an_object_without_attributes_lists_nothing() {
    let img = image("sa");
    let zpl = zpl(&img);
    // The root directory was given no extended attributes.
    let root = zfs_core::zpl_master_root(&img, &zpl).expect("root object id");
    assert!(
        list_xattrs(&img, &zpl, root).is_empty(),
        "the ZPL root directory carries no extended attributes"
    );
}
