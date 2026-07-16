#![no_main]
//! The 128-byte block pointer is attacker-controlled — `Blkptr::parse` and its
//! derived geometry (`lsize`/`psize`, DVA physical offsets, embedded/hole tests)
//! must never panic, under either detected byte order.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let endian = zfs_core::detect_blkptr_endian(data);
    let bp = zfs_core::Blkptr::parse(data, endian);
    // Exercise the derived-geometry accessors the reader drives off a blkptr.
    let _ = bp.lsize_bytes();
    let _ = bp.psize_bytes();
    let _ = bp.is_hole();
    for dva in &bp.dvas {
        let _ = dva.is_empty();
        let _ = dva.physical_byte_offset();
    }
});
