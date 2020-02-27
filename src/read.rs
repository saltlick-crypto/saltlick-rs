// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Wrapper types over [`Read`] objects.
//!
//! [`Read`]: https://doc.rust-lang.org/std/io/trait.Read.html

use crate::{
    bufread,
    crypter::{DEFAULT_BLOCK_SIZE, MIN_BLOCK_SIZE},
    key::{PublicKey, SecretKey},
};
use std::{
    cmp,
    io::{self, BufReader, Read},
};

/// Wraps an underlying reader with decryption using the saltlick format.
///
/// Wraps a reader that implements [`Read`] and returns a type that also
/// implements [`Read`]. Any data read from the returned type will be decrypted
/// with the provided secret key.  The public key is also checked to make sure
/// this encrypted data is for the public/secret key pair provided.
///
/// The underlying reader must reach the end of the stream in order to complete
/// decryption successfully, as the libsodium crypto relies on an end-of-stream
/// tag to provide guarantees of completeness.
///
/// [`Read`]: https://doc.rust-lang.org/std/io/trait.Read.html
#[derive(Debug)]
pub struct SaltlickDecrypter<R> {
    inner: bufread::SaltlickDecrypter<BufReader<R>>,
}

impl<R: Read> SaltlickDecrypter<R> {
    /// Create a new decryption layer over `reader` using `secret_key` and `public_key`.
    pub fn new(public_key: PublicKey, secret_key: SecretKey, reader: R) -> SaltlickDecrypter<R> {
        Self::with_capacity(DEFAULT_BLOCK_SIZE, public_key, secret_key, reader)
    }

    /// Create a new decryption layer over `reader`, using `lookup_fn` to match
    /// the stream's `public_key` to its `secret_key`.
    pub fn new_deferred<F>(reader: R, lookup_fn: F) -> SaltlickDecrypter<R>
    where
        F: FnOnce(&PublicKey) -> Option<SecretKey> + 'static,
    {
        Self::deferred_with_capacity(DEFAULT_BLOCK_SIZE, reader, lookup_fn)
    }

    /// Create a new decryption layer over `reader` using `secret_key` and
    /// `public_key` with the specified buffer capacity.
    pub fn with_capacity(
        capacity: usize,
        public_key: PublicKey,
        secret_key: SecretKey,
        reader: R,
    ) -> SaltlickDecrypter<R> {
        let capacity = cmp::max(capacity, MIN_BLOCK_SIZE);
        let bufreader = BufReader::with_capacity(capacity, reader);
        SaltlickDecrypter {
            inner: bufread::SaltlickDecrypter::new(public_key, secret_key, bufreader),
        }
    }

    /// Create a new decryption layer over `reader`, using `lookup_fn` to match
    /// the stream's `public_key` to its `secret_key` with the specified buffer
    /// capacity.
    pub fn deferred_with_capacity<F>(
        capacity: usize,
        reader: R,
        lookup_fn: F,
    ) -> SaltlickDecrypter<R>
    where
        F: FnOnce(&PublicKey) -> Option<SecretKey> + 'static,
    {
        let bufreader = BufReader::with_capacity(capacity, reader);
        SaltlickDecrypter {
            inner: bufread::SaltlickDecrypter::new_deferred(bufreader, lookup_fn),
        }
    }

    /// Stop reading/decrypting immediately and return the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner.into_inner().into_inner()
    }
}

impl<R: Read> Read for SaltlickDecrypter<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.inner.read(output)
    }
}

/// Wraps an underlying reader with encryption using the saltlick format.
///
/// Wraps a reader that implements [`Read`] and returns a type that also
/// implements [`Read`]. Any data read from the returned type will be encrypted
/// with the provided public key.
///
/// The underlying reader must reach the end of the stream in order to complete
/// encryption successfully, as the libsodium crypto relies on an end-of-stream
/// tag to provide guarantees of completeness.
///
/// [`Read`]: https://doc.rust-lang.org/std/io/trait.Read.html
#[derive(Debug)]
pub struct SaltlickEncrypter<R: Read> {
    inner: bufread::SaltlickEncrypter<BufReader<R>>,
}

impl<R: Read> SaltlickEncrypter<R> {
    /// Create a new encryption layer over `reader` using `public_key`.
    pub fn new(public_key: PublicKey, reader: R) -> SaltlickEncrypter<R> {
        Self::with_capacity(DEFAULT_BLOCK_SIZE, public_key, reader)
    }

    /// Create a new encryption layer over `reader` using `secret_key` and
    /// `public_key` with the specified buffer capacity.
    pub fn with_capacity(
        capacity: usize,
        public_key: PublicKey,
        reader: R,
    ) -> SaltlickEncrypter<R> {
        let bufreader = BufReader::with_capacity(capacity, reader);
        SaltlickEncrypter {
            inner: bufread::SaltlickEncrypter::new(public_key, bufreader),
        }
    }

    /// Set the block size for the underlying encrypter.
    pub fn set_block_size(&mut self, block_size: usize) {
        self.inner.set_block_size(block_size);
    }

    /// Stop reading/encrypting immediately and return the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner.into_inner().into_inner()
    }
}

impl<R: Read> Read for SaltlickEncrypter<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.inner.read(output)
    }
}

#[cfg(test)]
mod tests {
    use super::{SaltlickDecrypter, SaltlickEncrypter};
    use crate::key::gen_keypair;
    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::io::{Cursor, Read};

    fn random_bytes(seed: u64, size: usize) -> Box<[u8]> {
        let mut rng = XorShiftRng::seed_from_u64(seed);
        let mut bytes = vec![0u8; size];
        rng.fill_bytes(&mut bytes);
        bytes.into_boxed_slice()
    }

    #[test]
    fn round_trip_test() {
        for size in &[
            1,
            10 * 1024,
            32 * 1024,
            100 * 1024,
            200 * 1024,
            10 * 1024 * 1024,
        ] {
            let random_data = random_bytes(0, *size);
            let reader = Cursor::new(random_data.clone());
            let (public_key, secret_key) = gen_keypair();
            let mut encrypter = SaltlickEncrypter::new(public_key, reader);
            encrypter.set_block_size(1024);
            let mut decrypter = SaltlickDecrypter::new_deferred(encrypter, |_| Some(secret_key));
            let mut output = Vec::new();
            decrypter.read_to_end(&mut output).unwrap();
            assert_eq!(&random_data[..], &output[..]);
            let encrypter = decrypter.into_inner();
            let _ = encrypter.into_inner();
        }
    }

    #[test]
    fn corrupt_value_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let mut encrypter = SaltlickEncrypter::new(public_key.clone(), Cursor::new(random_data));
        let mut ciphertext = Vec::new();
        encrypter.read_to_end(&mut ciphertext).unwrap();

        // Inject a single bad byte near the end of the stream
        let index = ciphertext.len() - 5;
        ciphertext[index] = ciphertext[index].wrapping_add(1);

        let mut decrypter = SaltlickDecrypter::new(public_key, secret_key, Cursor::new(ciphertext));
        let mut output = Vec::new();
        assert!(decrypter.read_to_end(&mut output).is_err());
    }

    #[test]
    fn incomplete_stream_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let mut encrypter = SaltlickEncrypter::new(public_key.clone(), Cursor::new(random_data));
        let mut ciphertext = Vec::new();
        encrypter.read_to_end(&mut ciphertext).unwrap();

        // Remove a few bytes from the end
        ciphertext.resize(ciphertext.len() - 5, 0);

        let mut decrypter = SaltlickDecrypter::new(public_key, secret_key, Cursor::new(ciphertext));
        let mut output = Vec::new();
        assert!(decrypter.read_to_end(&mut output).is_err());
    }
}
