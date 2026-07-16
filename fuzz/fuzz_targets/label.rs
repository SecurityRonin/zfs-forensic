#![no_main]
//! The 256 KiB vdev label and its packed XDR nvlist config are fully
//! attacker-controlled — `VdevLabel::parse` and the standalone `nvlist_parse`
//! must never panic on any byte string (allocation-bomb length/count fields
//! included).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = zfs_core::VdevLabel::parse(data);
    // The nvlist decoder is also reachable standalone over an arbitrary buffer.
    let _ = zfs_core::nvlist_parse(data);
});
