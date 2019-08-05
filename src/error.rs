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

/// Errors when loading keys directly from a file.
///
/// Errors possible when keys are loaded directly from files. Note that this is
/// not part of the normal `SaltlickError` because `std::io::Error` does not
/// implement `Clone`, `Hash`, or `Eq`.
#[derive(Debug)]
pub enum SaltlickKeyIoError {
    IoError(io::Error),
    SaltlickError(SaltlickError),
}

impl Error for SaltlickKeyIoError {}

impl fmt::Display for SaltlickKeyIoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SaltlickKeyIoError::IoError(e) => write!(f, "key file I/O error: {}", e),
            SaltlickKeyIoError::SaltlickError(e) => write!(f, "key file parse error: {}", e),
        }
    }
}

impl From<io::Error> for SaltlickKeyIoError {
    fn from(e: io::Error) -> SaltlickKeyIoError {
        SaltlickKeyIoError::IoError(e)
    }
}

impl From<SaltlickError> for SaltlickKeyIoError {
    fn from(e: SaltlickError) -> SaltlickKeyIoError {
        SaltlickKeyIoError::SaltlickError(e)
    }
}
