#![no_main]
//! A `dnode_phys_t` and the `objset_phys_t` that embeds the meta-dnode are
//! attacker-controlled — `Dnode::parse` and `ObjsetPhys::parse` must never panic
//! under either byte order.
use libfuzzer_sys::fuzz_target;
use zfs_core::Endian;

fuzz_target!(|data: &[u8]| {
    for endian in [Endian::Little, Endian::Big] {
        let _ = zfs_core::Dnode::parse(data, endian);
        let _ = zfs_core::ObjsetPhys::parse(data, endian);
    }
});
