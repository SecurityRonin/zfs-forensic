//! Bounds-checked, endian-adaptive readers (the Paranoid Gatekeeper standard).
//!
//! ZFS is **endian-adaptive**: a pool is written in the host byte order of the
//! machine that created it, and the reader discovers that order from the
//! uberblock magic (`0x0000_0000_00ba_b10c` reads back native when same-endian,
//! byte-swapped when opposite). So this module exposes both little- and
//! big-endian bounds-checked readers, plus an [`Endian`] selector and the
//! [`Reader`] it drives, so the rest of the crate reads integers in whichever
//! order the on-disk data declared.
//!
//! Every reader yields `0` when the requested range lies outside the buffer, so
//! a malformed or truncated image can never panic a parser. Callers that must
//! distinguish "field absent" from "field is zero" bounds-check the buffer
//! length up front and surface [`crate::ZfsError::Truncated`].
//!
//! The XDR readers ([`xdr_i32`], [`xdr_u64`]) are *always* big-endian — the
//! packed nvlist config is XDR-encoded regardless of the pool's native order —
//! and are kept separate so the endian-adaptive path never accidentally decodes
//! a config field in the wrong order.

/// Byte order of the on-disk data, discovered from the uberblock magic.
///
/// [`Default`] is [`Endian::Little`], the common case (x86_64 / aarch64 pools),
/// so a zero-initialised [`crate::Blkptr`] has a sane byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Endian {
    /// Little-endian pool (the common case on x86_64 / aarch64 hosts).
    #[default]
    Little,
    /// Big-endian pool (created on a big-endian host, e.g. SPARC).
    Big,
}

// ---- little-endian ---------------------------------------------------------

/// Read a little-endian `u16` at `off`, or `0` if out of range.
#[must_use]
pub fn le_u16(data: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = data.get(off..off + 2) {
        b.copy_from_slice(s);
    }
    u16::from_le_bytes(b)
}

/// Read a little-endian `u32` at `off`, or `0` if out of range.
#[must_use]
pub fn le_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

/// Read a little-endian `u64` at `off`, or `0` if out of range.
#[must_use]
pub fn le_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off + 8) {
        b.copy_from_slice(s);
    }
    u64::from_le_bytes(b)
}

// ---- big-endian ------------------------------------------------------------

/// Read a big-endian `u16` at `off`, or `0` if out of range.
#[must_use]
pub fn be_u16(data: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = data.get(off..off + 2) {
        b.copy_from_slice(s);
    }
    u16::from_be_bytes(b)
}

/// Read a big-endian `u32` at `off`, or `0` if out of range.
#[must_use]
pub fn be_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_be_bytes(b)
}

/// Read a big-endian `u64` at `off`, or `0` if out of range.
#[must_use]
pub fn be_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off + 8) {
        b.copy_from_slice(s);
    }
    u64::from_be_bytes(b)
}

// ---- byte ------------------------------------------------------------------

/// Read a single byte at `off`, or `0` if out of range.
#[must_use]
pub fn u8_at(data: &[u8], off: usize) -> u8 {
    data.get(off).copied().unwrap_or(0)
}

// ---- XDR (always big-endian) -----------------------------------------------

/// Read an XDR (big-endian) signed `i32` at `off`, or `0` if out of range.
///
/// The packed nvlist config is XDR-encoded irrespective of the pool's native
/// byte order, so nvlist decoding always uses these two readers.
#[must_use]
pub fn xdr_i32(data: &[u8], off: usize) -> i32 {
    be_u32(data, off) as i32
}

/// Read an XDR (big-endian) unsigned `u64` at `off`, or `0` if out of range.
#[must_use]
pub fn xdr_u64(data: &[u8], off: usize) -> u64 {
    be_u64(data, off)
}

// ---- endian-adaptive reader ------------------------------------------------

/// A byte-order-parameterised reader over a slice.
///
/// Constructed once the pool's [`Endian`] is known (from the uberblock magic),
/// it reads every subsequent integer in that order. All accessors are
/// bounds-checked and yield `0` out of range, never panic.
#[derive(Debug, Clone, Copy)]
pub struct Reader {
    endian: Endian,
}

impl Reader {
    /// Build a reader for the given byte order.
    #[must_use]
    pub fn new(endian: Endian) -> Self {
        Self { endian }
    }

    /// The byte order this reader decodes in.
    #[must_use]
    pub fn endian(self) -> Endian {
        self.endian
    }

    /// Read a `u16` at `off` in this reader's byte order.
    #[must_use]
    pub fn u16(self, data: &[u8], off: usize) -> u16 {
        match self.endian {
            Endian::Little => le_u16(data, off),
            Endian::Big => be_u16(data, off),
        }
    }

    /// Read a `u32` at `off` in this reader's byte order.
    #[must_use]
    pub fn u32(self, data: &[u8], off: usize) -> u32 {
        match self.endian {
            Endian::Little => le_u32(data, off),
            Endian::Big => be_u32(data, off),
        }
    }

    /// Read a `u64` at `off` in this reader's byte order.
    #[must_use]
    pub fn u64(self, data: &[u8], off: usize) -> u64 {
        match self.endian {
            Endian::Little => le_u64(data, off),
            Endian::Big => be_u64(data, off),
        }
    }
}

#[cfg(test)]
mod unit {
    use super::{
        be_u16, be_u32, be_u64, le_u16, le_u32, le_u64, u8_at, xdr_i32, xdr_u64, Endian, Reader,
    };

    #[test]
    fn little_endian_readers_decode_in_range() {
        let d = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(le_u16(&d, 0), 0x0201);
        assert_eq!(le_u32(&d, 0), 0x0403_0201);
        assert_eq!(le_u64(&d, 0), 0x0807_0605_0403_0201);
    }

    #[test]
    fn big_endian_readers_decode_in_range() {
        let d = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(be_u16(&d, 0), 0x0102);
        assert_eq!(be_u32(&d, 0), 0x0102_0304);
        assert_eq!(be_u64(&d, 0), 0x0102_0304_0506_0708);
        assert_eq!(u8_at(&d, 3), 0x04);
    }

    #[test]
    fn xdr_readers_are_big_endian() {
        let d = [0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(xdr_i32(&d, 0), 42);
        assert_eq!(xdr_u64(&d, 0), 0x0000_002a_0000_0001);
    }

    #[test]
    fn readers_yield_zero_out_of_range() {
        assert_eq!(le_u16(&[0x12], 0), 0);
        assert_eq!(le_u32(&[0, 0, 0], 0), 0);
        assert_eq!(le_u64(&[0, 0, 0, 0, 0, 0, 0], 0), 0);
        assert_eq!(be_u16(&[0x12], 0), 0);
        assert_eq!(be_u32(&[0, 0, 0], 0), 0);
        assert_eq!(be_u64(&[0, 0, 0, 0, 0, 0, 0], 0), 0);
        assert_eq!(xdr_i32(&[0, 0], 0), 0);
        assert_eq!(xdr_u64(&[0, 0], 0), 0);
        assert_eq!(u8_at(&[], 0), 0);
        assert_eq!(u8_at(&[0xAA], 5), 0);
    }

    #[test]
    fn reader_reads_in_selected_byte_order() {
        let d = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let le = Reader::new(Endian::Little);
        assert_eq!(le.endian(), Endian::Little);
        assert_eq!(le.u16(&d, 0), 0x0201);
        assert_eq!(le.u32(&d, 0), 0x0403_0201);
        assert_eq!(le.u64(&d, 0), 0x0807_0605_0403_0201);
        let be = Reader::new(Endian::Big);
        assert_eq!(be.endian(), Endian::Big);
        assert_eq!(be.u16(&d, 0), 0x0102);
        assert_eq!(be.u32(&d, 0), 0x0102_0304);
        assert_eq!(be.u64(&d, 0), 0x0102_0304_0506_0708);
    }
}
