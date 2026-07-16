#![no_main]
//! The DSL bonus accessors read `dsl_dir_phys_t` / `dsl_dataset_phys_t` fields
//! out of an attacker-controlled dnode bonus buffer — parsing an arbitrary dnode
//! and pulling its head-dataset / prev-snap / ds_bp must never panic.
use libfuzzer_sys::fuzz_target;
use zfs_core::Endian;

fuzz_target!(|data: &[u8]| {
    for endian in [Endian::Little, Endian::Big] {
        if let Some(dn) = zfs_core::Dnode::parse(data, endian) {
            let _ = zfs_core::dsl_dir_head_dataset(&dn);
            let _ = zfs_core::dsl_dataset_prev_snap(&dn);
            let _ = zfs_core::dsl_dataset_bp(&dn);
        }
    }
});
