#![no_main]
//! A single uberblock ring slot is attacker-controlled — endian detection from
//! the magic and `Uberblock::parse` must never panic on any byte string.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = zfs_core::uberblock_parse(data);
    if let Some(ub) = zfs_core::Uberblock::parse(data) {
        // The parsed uberblock's rootbp is expanded to a full Blkptr downstream.
        let _ = ub.rootbp_full();
    }
});
