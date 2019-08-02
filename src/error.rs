// Copyright (c) 2019, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::error::Error;
use std::fmt;
use std::io;

use pem::PemError;
use simple_asn1::{ASN1DecodeErr, ASN1EncodeErr};

/// Saltlick errors
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum SaltlickError {
    BadMagic,
    DecryptionFailure,
    Finalized,
    Incomplete,
    IncorrectKeyLength,
    InvalidKeyFormat,
    PublicKeyMismatch,
    SecretKeyNotFound,
    StreamStartFailure,
    UnsupportedKeyAlgorithm,
    UnsupportedVersion,
}

impl Error for SaltlickError {}

impl fmt::Display for SaltlickError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SaltlickError::*;
        match self {
            BadMagic => write!(f, "Magic value incorrect - is this a saltlick file?"),
            DecryptionFailure => write!(f, "Failed to decrypt - stream is corrupt."),
            Finalized => write!(f, "Stream is finalized, no more data may be written."),
            Incomplete => write!(
                f,
                "Stream ended before Final tag receive, file is incomplete!"
            ),
            IncorrectKeyLength => write!(f, "Key is the incorrect length."),
            InvalidKeyFormat => write!(f, "Key file is invalid, must be PEM encoded ASN.1"),
            PublicKeyMismatch => write!(f, "Provided public key does not match file public key."),
            SecretKeyNotFound => write!(f, "Unable to find secret key for file."),
            StreamStartFailure => write!(f, "Stream failed to start."),
            UnsupportedKeyAlgorithm => write!(f, "Key algorithm is unknown or unsupported."),
            UnsupportedVersion => write!(f, "Version is unknown or unsupported."),
        }
    }
}

impl From<PemError> for SaltlickError {
    fn from(_e: PemError) -> SaltlickError {
        SaltlickError::InvalidKeyFormat
    }
}

impl From<ASN1EncodeErr> for SaltlickError {
    fn from(_: ASN1EncodeErr) -> SaltlickError {
        SaltlickError::InvalidKeyFormat
    }
}

impl From<ASN1DecodeErr> for SaltlickError {
    fn from(_: ASN1DecodeErr) -> SaltlickError {
        SaltlickError::InvalidKeyFormat
    }
}

impl Into<io::Error> for SaltlickError {
    fn into(self) -> io::Error {
        io::Error::new(io::ErrorKind::Other, self)
    }
}
