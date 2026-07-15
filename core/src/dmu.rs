//! DMU object types (`dmu_object_type` enum) — the `type` field of a blkptr and
//! a dnode's `dn_type`.
//!
//! Verified against OpenZFS `dmu.h`. Only the variants P1 needs are named
//! explicitly (the object-directory / dnode / objset / dataset / ZPL types the
//! MOS and dataset walks touch); every other value round-trips through
//! [`DmuType::Other`] so an "unknown object type" report names the raw value.

/// A DMU object type. Use [`DmuType::raw`] for the on-disk numeric value (e.g.
/// `DmuType::Objset.raw() == 11`); the data-carrying [`DmuType::Other`] variant
/// means the enum is not a plain `#[repr(u8)]` cast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DmuType {
    /// `DMU_OT_NONE` (0).
    None,
    /// `DMU_OT_OBJECT_DIRECTORY` (1) — the MOS object directory (a ZAP).
    ObjectDirectory,
    /// `DMU_OT_OBJECT_ARRAY` (2).
    ObjectArray,
    /// `DMU_OT_PACKED_NVLIST` (3).
    PackedNvlist,
    /// `DMU_OT_BPOBJ` (5).
    Bpobj,
    /// `DMU_OT_SPACE_MAP` (8).
    SpaceMap,
    /// `DMU_OT_DNODE` (10) — a block whose data is an array of `dnode_phys_t`
    /// (the objset meta-dnode's object type).
    Dnode,
    /// `DMU_OT_OBJSET` (11) — an `objset_phys_t` (the rootbp's object type).
    Objset,
    /// `DMU_OT_DSL_DIR` (12).
    DslDir,
    /// `DMU_OT_DSL_DIR_CHILD_MAP` (13) — a ZAP of child dataset names.
    DslDirChildMap,
    /// `DMU_OT_DSL_DATASET` (16).
    DslDataset,
    /// `DMU_OT_PLAIN_FILE_CONTENTS` (19) — file data.
    PlainFileContents,
    /// `DMU_OT_DIRECTORY_CONTENTS` (20) — a ZPL directory (a ZAP).
    DirectoryContents,
    /// `DMU_OT_MASTER_NODE` (21) — the ZPL master node (object 1 of a dataset).
    MasterNode,
    /// Any other / newer type — carries the raw value.
    Other(u8),
}

impl DmuType {
    /// Map a raw on-disk object-type value to a [`DmuType`].
    #[must_use]
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => DmuType::None,
            1 => DmuType::ObjectDirectory,
            2 => DmuType::ObjectArray,
            3 => DmuType::PackedNvlist,
            5 => DmuType::Bpobj,
            8 => DmuType::SpaceMap,
            10 => DmuType::Dnode,
            11 => DmuType::Objset,
            12 => DmuType::DslDir,
            13 => DmuType::DslDirChildMap,
            16 => DmuType::DslDataset,
            19 => DmuType::PlainFileContents,
            20 => DmuType::DirectoryContents,
            21 => DmuType::MasterNode,
            other => DmuType::Other(other),
        }
    }

    /// The raw on-disk value.
    #[must_use]
    pub fn raw(self) -> u8 {
        match self {
            DmuType::None => 0,
            DmuType::ObjectDirectory => 1,
            DmuType::ObjectArray => 2,
            DmuType::PackedNvlist => 3,
            DmuType::Bpobj => 5,
            DmuType::SpaceMap => 8,
            DmuType::Dnode => 10,
            DmuType::Objset => 11,
            DmuType::DslDir => 12,
            DmuType::DslDirChildMap => 13,
            DmuType::DslDataset => 16,
            DmuType::PlainFileContents => 19,
            DmuType::DirectoryContents => 20,
            DmuType::MasterNode => 21,
            DmuType::Other(v) => v,
        }
    }
}

#[cfg(test)]
mod unit {
    use super::DmuType;

    #[test]
    fn from_raw_round_trips_known_and_other() {
        for v in [0u8, 1, 2, 3, 5, 8, 10, 11, 12, 13, 16, 19, 20, 21, 200] {
            assert_eq!(DmuType::from_raw(v).raw(), v);
        }
    }

    #[test]
    fn raw_matches_on_disk_values() {
        assert_eq!(DmuType::Objset.raw(), 11);
        assert_eq!(DmuType::Dnode.raw(), 10);
        assert_eq!(DmuType::ObjectDirectory.raw(), 1);
        assert_eq!(DmuType::PlainFileContents.raw(), 19);
    }
}
