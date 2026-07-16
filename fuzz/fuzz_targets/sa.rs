#![no_main]
//! System-attribute (SA) parsing over attacker-controlled bytes: the registry
//! micro-ZAP, the layouts fat-ZAP, the SA bonus decode, and the legacy
//! `znode_phys_t` bonus decode must never panic. The registry/layouts parsed
//! from the same buffer feed the bonus decoder, exercising the full chain.
use libfuzzer_sys::fuzz_target;
use zfs_core::Endian;

fuzz_target!(|data: &[u8]| {
    let registry = zfs_core::parse_sa_registry(data);
    let layouts = zfs_core::parse_sa_layouts(data);
    for endian in [Endian::Little, Endian::Big] {
        let _ = zfs_core::decode_sa_bonus(data, &registry, &layouts, endian);
        let _ = zfs_core::decode_znode_phys(data, endian);
    }
});
