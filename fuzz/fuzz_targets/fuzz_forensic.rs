#![no_main]
//! Full inspect/audit + carve pipeline over an arbitrary "image": the F-INTEGRITY
//! auditor (`audit_image` / `audit_findings`) and the F-CARVE CoW deleted-file
//! recovery (`recover_deleted`) must never panic on any byte string — this is the
//! end-to-end forensic front door driven by attacker-controlled disk bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Structural-integrity audit (typed anomalies + graded findings).
    let _ = zfs_forensic::audit_image(data);
    let _ = zfs_forensic::audit_findings(data, "fuzz");
    // CoW deleted-file recovery — walks the DSL snapshot chain.
    let _ = zfs_forensic::recover_deleted(data);
});
