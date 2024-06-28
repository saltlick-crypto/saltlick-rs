// Copyright (c) 2019, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use pem::PemError;
use simple_asn1::{ASN1DecodeErr, ASN1EncodeErr};
use std::io;
use thiserror::Error;

/// Saltlick errors.
#[derive(Clone, Debug, Error, Hash, Eq, PartialEq)]
pub enum SaltlickError {
    #[error("Magic value incorrect - is this a saltlick file?")]
    BadMagic,
    #[error("Failed to decrypt - stream is corrupt.")]
    DecryptionFailure,
    #[error("Failed to encrypt - buffer too small?")]
    EncryptionFailure,
    #[error("Stream is finalized, no more data may be written.")]
    Finalized,
    #[error("Stream ended before Final tag receive, file is incomplete!")]
    Incomplete,
    #[error("Key is the incorrect length.")]
    IncorrectKeyLength,
    #[error("Key file is invalid, must be PEM encoded ASN.1")]
    InvalidKeyFormat,
    #[error("Provided public key does not match file public key.")]
    PublicKeyMismatch,
    #[error("Unable to find secret key for file.")]
    SecretKeyNotFound,
    #[error("The state machine was called having previously returned an error.")]
    StateMachineErrored,
    #[error("Stream failed to start.")]
    StreamStartFailure,
    #[error("Key algorithm is unknown or unsupported.")]
    UnsupportedKeyAlgorithm,
    #[error("Version is unknown or unsupported.")]
    UnsupportedVersion,
}

impl From<PemError> for SaltlickError {
    fn from(_: PemError) -> SaltlickError {
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

impl From<SaltlickError> for io::Error {
    fn from(e: SaltlickError) -> io::Error {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

/// Errors when loading keys directly from a file.
///
/// Errors possible when keys are loaded directly from files. Note that this is
/// not part of the normal `SaltlickError` because `std::io::Error` does not
/// implement `Clone`, `Hash`, or `Eq`.
#[derive(Debug, Error)]
pub enum SaltlickKeyIoError {
    #[error("key file I/O error: {0}")]
    IoError(#[from] io::Error),
    #[error("key file parse error: {0}")]
    SaltlickError(#[from] SaltlickError),
}

#[cfg(test)]
mod tests {
    use super::SaltlickError;
    use pem::PemError;
    use simple_asn1::{ASN1DecodeErr, ASN1EncodeErr};

    #[test]
    fn from_conversions_test() {
        assert_eq!(
            SaltlickError::InvalidKeyFormat,
            SaltlickError::from(PemError::MissingData),
        );
        assert_eq!(
            SaltlickError::InvalidKeyFormat,
            SaltlickError::from(ASN1EncodeErr::ObjectIdentHasTooFewFields),
        );
        assert_eq!(
            SaltlickError::InvalidKeyFormat,
            SaltlickError::from(ASN1DecodeErr::EmptyBuffer),
        );
    }
}
