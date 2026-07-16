#![no_main]
//! The decompression and checksum paths are the prime attacker surface: a
//! compressed extent's declared `lsize` is an allocation-bomb vector, and the
//! checksum verifier runs over arbitrary block bytes. Neither may panic.
//!
//! Input layout: byte 0 selects the compression codec, bytes 1..3 the (bounded)
//! declared logical size, byte 3 the checksum function, and the remainder is the
//! compressed / to-be-checksummed payload.
use libfuzzer_sys::fuzz_target;
use zfs_core::{ChecksumType, CompressType, Endian};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let comp = CompressType::from_raw(data[0]);
    // Bounded lsize (up to 16 MiB) so the fuzzer explores real allocation sizes
    // and the codec's own cap logic, not just OOM.
    let lsize = ((usize::from(data[1]) << 8) | usize::from(data[2])) << 8;
    let payload = &data[4..];
    let _ = zfs_core::compress::decompress(comp, payload, lsize);

    // Checksum verify over the arbitrary payload, under either byte order.
    let kind = ChecksumType::from_raw(data[3]);
    for endian in [Endian::Little, Endian::Big] {
        let _ = zfs_core::checksum::verify(kind, endian, payload, [0; 4]);
    }
    let _ = zfs_core::checksum::fletcher4(payload, Endian::Little);
});
