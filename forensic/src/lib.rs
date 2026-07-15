//! `zfs-forensic` — forensic anomaly auditor for ZFS, built on `zfs-core`.
//!
//! Scaffold. The auditor (uberblock-history/txg point-in-time recovery,
//! orphaned-dataset and integrity findings emitted as
//! [`forensicnomicon::report::Finding`]) is implemented in later phases over the
//! `zfs-core` reader. P0 established the vdev-label + endian-adaptive uberblock
//! foundation in `zfs-core`; this crate stays an empty shell until the reader
//! exposes the objsets/datasets the audit walks.

#![forbid(unsafe_code)]

/// Re-export of the reader this auditor is built on, so downstream consumers pull
/// one crate.
pub use zfs_core;
