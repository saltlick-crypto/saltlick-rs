// Copyright (c) 2019, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Supported Saltlick file format version.
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum Version {
    /// Format version 1.
    V1,

    /// Any other unrecognized version.
    Unknown(u8),
}

impl Version {
    /// Convert this version to a u8 representation.
    pub fn to_u8(self) -> u8 {
        match self {
            Version::V1 => 1,
            Version::Unknown(version) => version,
        }
    }

    /// Convert a u8 representation to a version.
    ///
    /// Note: the conversion is infalliable, but it is important to check that
    /// the version decoded is an understood one, as any unknown values map to
    /// the `Unknown` variant.
    pub fn from_u8(value: u8) -> Version {
        match value {
            1 => Version::V1,
            other => Version::Unknown(other),
        }
    }

    /// True if this is not a known version.
    pub fn is_unknown(self) -> bool {
        match self {
            Version::Unknown(_) => true,
            _ => false,
        }
    }
}
