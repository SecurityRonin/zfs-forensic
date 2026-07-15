//! ZFS block checksums (fletcher2, fletcher4, sha256).
//!
//! Every ZFS block carries a 256-bit checksum in its block pointer. On read the
//! reader recomputes the checksum over the **on-disk (PSIZE, post-compression)**
//! bytes and compares. This is done **non-fatally** in a forensic reader: a
//! mismatch surfaces as `Some(false)` so the (possibly-corrupt) block is still
//! returned for examination — a checksum failure is evidence, not a reason to
//! refuse the read.
//!
//! # Algorithms (verified against `zdb`)
//!
//! - **fletcher4** (default) — accumulate `u32` words: `a+=w; b+=a; c+=b; d+=c`.
//!   Result = `[a, b, c, d]`. Byte order follows the block's stored byteorder.
//!   Confirmed byte-exact against `zdb`'s rootbp checksum on the minted pool.
//! - **fletcher2** — accumulate `u64` word pairs: `a0+=w0; a1+=w1; b0+=a0;
//!   b1+=a1`. Result = `[a0, a1, b0, b1]`.
//! - **sha256** — the raw 32-byte SHA-256 digest re-packed as four **big-endian**
//!   `u64` words (ZFS stores the digest as `zio_cksum_t`), via the audited
//!   `sha2` crate (never hand-rolled).
//!
//! All readers are bounds-checked and process only whole words; a trailing
//! partial word (an image never has one for a real block) is ignored.

use crate::bytes::{be_u32, be_u64, le_u32, le_u64, Endian};
use sha2::{Digest, Sha256};

/// ZFS checksum function (`zio_checksum` enum, on-disk `blk_prop` bits 40-47).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChecksumType {
    /// `ZIO_CHECKSUM_INHERIT` (0) — inherit from the dataset; not on-disk.
    Inherit,
    /// `ZIO_CHECKSUM_ON` (1) — the pool default (fletcher4); not on-disk.
    On,
    /// `ZIO_CHECKSUM_OFF` (2) — no checksum (embedded / gang cases).
    Off,
    /// `ZIO_CHECKSUM_LABEL` (3).
    Label,
    /// `ZIO_CHECKSUM_GANG_HEADER` (4).
    GangHeader,
    /// `ZIO_CHECKSUM_ZILOG` (5).
    Zilog,
    /// `ZIO_CHECKSUM_FLETCHER_2` (6).
    Fletcher2,
    /// `ZIO_CHECKSUM_FLETCHER_4` (7) — the default for metadata + data.
    Fletcher4,
    /// `ZIO_CHECKSUM_SHA256` (8).
    Sha256,
    /// Any other / newer function (skein, edonr, blake3, sha512, …) — carried as
    /// its raw enum value so an "unsupported checksum" report names the value.
    Other(u8),
}

impl ChecksumType {
    /// Map a raw on-disk checksum enum value to a [`ChecksumType`].
    #[must_use]
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => ChecksumType::Inherit,
            1 => ChecksumType::On,
            2 => ChecksumType::Off,
            3 => ChecksumType::Label,
            4 => ChecksumType::GangHeader,
            5 => ChecksumType::Zilog,
            6 => ChecksumType::Fletcher2,
            7 => ChecksumType::Fletcher4,
            8 => ChecksumType::Sha256,
            other => ChecksumType::Other(other),
        }
    }

    /// The raw on-disk `zio_checksum` enum value.
    #[must_use]
    pub fn raw(self) -> u8 {
        match self {
            ChecksumType::Inherit => 0,
            ChecksumType::On => 1,
            ChecksumType::Off => 2,
            ChecksumType::Label => 3,
            ChecksumType::GangHeader => 4,
            ChecksumType::Zilog => 5,
            ChecksumType::Fletcher2 => 6,
            ChecksumType::Fletcher4 => 7,
            ChecksumType::Sha256 => 8,
            ChecksumType::Other(v) => v,
        }
    }
}

/// fletcher4 over `data` in the block's byte order.
///
/// Reads `u32` words in `endian` order and accumulates the four running sums.
/// Verified byte-exact against `zdb` (the minted-pool rootbp checksum).
///
/// The `a`/`b`/`c`/`d` names mirror the OpenZFS `fletcher_4_scalar_native`
/// reference exactly, so the correspondence to the spec is auditable.
#[must_use]
#[allow(clippy::many_single_char_names)]
pub fn fletcher4(data: &[u8], endian: Endian) -> [u64; 4] {
    let (mut a, mut b, mut c, mut d) = (0u64, 0u64, 0u64, 0u64);
    let words = data.len() / 4;
    for i in 0..words {
        let off = i * 4;
        let w = u64::from(match endian {
            Endian::Little => le_u32(data, off),
            Endian::Big => be_u32(data, off),
        });
        a = a.wrapping_add(w);
        b = b.wrapping_add(a);
        c = c.wrapping_add(b);
        d = d.wrapping_add(c);
    }
    [a, b, c, d]
}

/// fletcher2 over `data` in the block's byte order.
///
/// Reads `u64` word pairs; a trailing partial pair (never present in a real
/// block, whose size is a power of two) is ignored.
#[must_use]
pub fn fletcher2(data: &[u8], endian: Endian) -> [u64; 4] {
    let (mut a0, mut a1, mut b0, mut b1) = (0u64, 0u64, 0u64, 0u64);
    let pairs = data.len() / 16;
    for i in 0..pairs {
        let off = i * 16;
        let (w0, w1) = match endian {
            Endian::Little => (le_u64(data, off), le_u64(data, off + 8)),
            Endian::Big => (be_u64(data, off), be_u64(data, off + 8)),
        };
        a0 = a0.wrapping_add(w0);
        a1 = a1.wrapping_add(w1);
        b0 = b0.wrapping_add(a0);
        b1 = b1.wrapping_add(a1);
    }
    [a0, a1, b0, b1]
}

/// sha256 over `data`, packed as ZFS stores it: four **big-endian** `u64` words.
#[must_use]
pub fn sha256(data: &[u8]) -> [u64; 4] {
    let digest = Sha256::digest(data);
    let mut out = [0u64; 4];
    for (i, word) in out.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&digest[i * 8..i * 8 + 8]);
        *word = u64::from_be_bytes(b);
    }
    out
}

/// Non-fatally verify `data` against an `expected` 256-bit checksum.
///
/// Returns:
/// - `Some(true)`  — the recomputed checksum matches.
/// - `Some(false)` — it does not match (the block is surfaced anyway; a mismatch
///   is a forensic finding, not a read failure).
/// - `None`        — the checksum function is `Off`/`Inherit`/`On` or an
///   unsupported newer function, so no verification was performed. The caller
///   distinguishes "checked and good" from "not checked".
#[must_use]
pub fn verify(kind: ChecksumType, endian: Endian, data: &[u8], expected: [u64; 4]) -> Option<bool> {
    let computed = match kind {
        ChecksumType::Fletcher4 => fletcher4(data, endian),
        ChecksumType::Fletcher2 => fletcher2(data, endian),
        ChecksumType::Sha256 => sha256(data),
        // Off/Inherit/On/label/gang/zilog and newer functions: not verified here.
        _ => return None,
    };
    Some(computed == expected)
}

#[cfg(test)]
mod unit {
    use super::{fletcher2, fletcher4, sha256, verify, ChecksumType};
    use crate::bytes::Endian;

    #[test]
    fn checksum_type_raw_round_trips_every_variant() {
        for v in [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 200] {
            assert_eq!(ChecksumType::from_raw(v).raw(), v);
        }
    }

    #[test]
    fn checksum_type_from_raw_covers_known_and_other() {
        assert_eq!(ChecksumType::from_raw(0), ChecksumType::Inherit);
        assert_eq!(ChecksumType::from_raw(1), ChecksumType::On);
        assert_eq!(ChecksumType::from_raw(2), ChecksumType::Off);
        assert_eq!(ChecksumType::from_raw(3), ChecksumType::Label);
        assert_eq!(ChecksumType::from_raw(4), ChecksumType::GangHeader);
        assert_eq!(ChecksumType::from_raw(5), ChecksumType::Zilog);
        assert_eq!(ChecksumType::from_raw(6), ChecksumType::Fletcher2);
        assert_eq!(ChecksumType::from_raw(7), ChecksumType::Fletcher4);
        assert_eq!(ChecksumType::from_raw(8), ChecksumType::Sha256);
        assert_eq!(ChecksumType::from_raw(12), ChecksumType::Other(12));
    }

    #[test]
    fn fletcher4_known_vector() {
        // 8 bytes = two u32 words [1, 2] (LE): a=1, then a+=2 -> a=3; b=1+3=4;
        // c=1+4=5; d=1+5=6.
        let data = [1u8, 0, 0, 0, 2, 0, 0, 0];
        assert_eq!(fletcher4(&data, Endian::Little), [3, 4, 5, 6]);
    }

    #[test]
    fn fletcher4_big_endian_reads_in_order() {
        let data = [0, 0, 0, 1, 0, 0, 0, 2];
        assert_eq!(fletcher4(&data, Endian::Big), [3, 4, 5, 6]);
    }

    #[test]
    fn fletcher2_known_vector() {
        // 16 bytes = one pair [w0=1, w1=2]: a0=1, a1=2, b0=1, b1=2.
        let mut data = [0u8; 16];
        data[0] = 1;
        data[8] = 2;
        assert_eq!(fletcher2(&data, Endian::Little), [1, 2, 1, 2]);
    }

    #[test]
    fn fletcher2_big_endian() {
        let mut data = [0u8; 16];
        data[7] = 1;
        data[15] = 2;
        assert_eq!(fletcher2(&data, Endian::Big), [1, 2, 1, 2]);
    }

    #[test]
    fn sha256_of_abc_matches_known_digest() {
        // Independent oracle: the published SHA-256("abc") digest.
        // ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
        let words = sha256(b"abc");
        assert_eq!(
            words,
            [
                0xba78_16bf_8f01_cfea,
                0x4141_40de_5dae_2223,
                0xb003_61a3_9617_7a9c,
                0xb410_ff61_f200_15ad,
            ]
        );
    }

    #[test]
    fn verify_returns_none_for_unverified_functions() {
        assert_eq!(
            verify(ChecksumType::Off, Endian::Little, b"x", [0; 4]),
            None
        );
        assert_eq!(
            verify(ChecksumType::Other(12), Endian::Little, b"x", [0; 4]),
            None
        );
        assert_eq!(verify(ChecksumType::On, Endian::Little, b"x", [0; 4]), None);
        assert_eq!(
            verify(ChecksumType::Inherit, Endian::Little, b"x", [0; 4]),
            None
        );
    }

    #[test]
    fn verify_true_false_paths() {
        let data = [1u8, 0, 0, 0, 2, 0, 0, 0];
        let good = fletcher4(&data, Endian::Little);
        assert_eq!(
            verify(ChecksumType::Fletcher4, Endian::Little, &data, good),
            Some(true)
        );
        assert_eq!(
            verify(ChecksumType::Fletcher4, Endian::Little, &data, [9, 9, 9, 9]),
            Some(false)
        );
        // fletcher2 and sha256 verify paths.
        let f2 = fletcher2(&data, Endian::Little);
        assert_eq!(
            verify(ChecksumType::Fletcher2, Endian::Little, &data, f2),
            Some(true)
        );
        let s = sha256(&data);
        assert_eq!(
            verify(ChecksumType::Sha256, Endian::Little, &data, s),
            Some(true)
        );
    }
}
