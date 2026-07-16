#![no_main]
//! ZAP blocks (micro-ZAP and fat-ZAP leaf/header) are attacker-controlled —
//! `zap_list`, `zap_lookup`, and `zap_list_arrays` over an arbitrary block must
//! never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = zfs_core::zap_list(data);
    let _ = zfs_core::zap_lookup(data, "root_dataset");
    let _ = zfs_core::zap_list_arrays(data);
});
