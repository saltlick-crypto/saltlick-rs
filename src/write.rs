// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Wrapper types over [`Write`] objects.
//!
//! [`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html

use crate::{
    commonio::{self, Buffer},
    crypter::{Decrypter, Encrypter, DEFAULT_BLOCK_SIZE, MIN_BLOCK_SIZE},
    key::{PublicKey, SecretKey},
};
use std::{
    cmp,
    io::{self, Write},
};

#[cfg(feature = "io-async")]
pub use crate::async_::write::*;

/// Wraps an underlying writer with decryption using the saltlick format.
///
/// Wraps a writer that implements [`Write`] and returns a type that also
/// implements [`Write`]. Any data written to the returned type will be
/// decrypted with the provided secret key and written to the underlying
/// writer.  The public key is also checked to make sure this encrypted data is
/// for the public/secret key pair provided.
///
/// Any data written after the encrypted stream is complete will be discarded.
///
/// # Note
///
/// If writing fails during the stream, the entire stream must be discarded and
/// started over, as the underlying crypto prevents restarting.
///
/// [`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
#[derive(Debug)]
pub struct SaltlickDecrypter<W: Write> {
    buffer: Buffer,
    decrypter: Decrypter,
    inner: Option<W>,
}

impl<W: Write> SaltlickDecrypter<W> {
    /// Create a new decryption layer over `writer` using `secret_key` and `public_key`.
    pub fn new(public_key: PublicKey, secret_key: SecretKey, writer: W) -> SaltlickDecrypter<W> {
        Self::with_capacity(DEFAULT_BLOCK_SIZE, public_key, secret_key, writer)
    }

    /// Create a new decryption layer over `writer`, using `lookup_fn` to match
    /// the stream's `public_key` to its `secret_key`.
    pub fn new_deferred<F>(writer: W, lookup_fn: F) -> SaltlickDecrypter<W>
    where
        F: FnOnce(&PublicKey) -> Option<SecretKey> + 'static,
    {
        Self::deferred_with_capacity(DEFAULT_BLOCK_SIZE, writer, lookup_fn)
    }

    /// Create a new decryption layer over `writer` using `secret_key` and
    /// `public_key` with the provided buffer `capacity`.
    pub fn with_capacity(
        capacity: usize,
        public_key: PublicKey,
        secret_key: SecretKey,
        writer: W,
    ) -> SaltlickDecrypter<W> {
        let capacity = cmp::max(capacity, MIN_BLOCK_SIZE);
        SaltlickDecrypter {
            buffer: Buffer::new(capacity),
            decrypter: Decrypter::new(public_key, secret_key),
            inner: Some(writer),
        }
    }

    /// Create a new decryption layer over `writer`, using `lookup_fn` to match
    /// the stream's `public_key` to its `secret_key` with the provided buffer
    /// capacity.
    pub fn deferred_with_capacity<F>(
        capacity: usize,
        writer: W,
        lookup_fn: F,
    ) -> SaltlickDecrypter<W>
    where
        F: FnOnce(&PublicKey) -> Option<SecretKey> + 'static,
    {
        let capacity = cmp::max(capacity, MIN_BLOCK_SIZE);
        SaltlickDecrypter {
            buffer: Buffer::new(capacity),
            decrypter: Decrypter::new_deferred(lookup_fn),
            inner: Some(writer),
        }
    }

    /// Write any remaining plaintext to the stream and verify the stream is
    /// finished.
    ///
    /// This will also be done automatically if the `SaltlickDecrypter` is
    /// dropped, but any errors will be silently discarded, which could mean
    /// the decrypted output is not properly finalized and therefore invalid.
    pub fn finalize(mut self) -> Result<W, io::Error> {
        let writer = self.inner.as_mut().expect("inner writer missing");
        commonio::write_finalized(writer, &mut self.decrypter, &mut self.buffer)?;
        let inner = self.inner.take().expect("inner writer missing");
        Ok(inner)
    }
}

impl<W: Write> Write for SaltlickDecrypter<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let writer = self.inner.as_mut().expect("inner writer missing");
        commonio::write(writer, &mut self.decrypter, &mut self.buffer, input)
    }

    fn flush(&mut self) -> io::Result<()> {
        let writer = self.inner.as_mut().expect("inner writer missing");
        self.buffer.flush(writer)?;
        writer.flush()
    }
}

impl<W: Write> Drop for SaltlickDecrypter<W> {
    fn drop(&mut self) {
        if self.inner.is_some() && !self.buffer.panicked() {
            let writer = self.inner.as_mut().unwrap();
            let _ = self.buffer.flush(writer);
            let _ = commonio::write_finalized(writer, &mut self.decrypter, &mut self.buffer);
        }
    }
}

/// Wraps an underlying writer with encryption using the saltlick format.
///
/// Wraps a writer that implements [`Write`] and returns a type that also
/// implements [`Write`].  Any data written to the returned type will be
/// encrypted with the provided public key and written to the underlying
/// writer.
///
/// # Note
///
/// If writing fails during the stream, the entire stream must be discarded and
/// started over, as the underlying crypto prevents restarting.
///
/// [`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
#[derive(Debug)]
pub struct SaltlickEncrypter<W: Write> {
    buffer: Buffer,
    encrypter: Encrypter,
    inner: Option<W>,
}

impl<W: Write> SaltlickEncrypter<W> {
    /// Create a new encryption layer over `writer` using `public_key`.
    pub fn new(public_key: PublicKey, writer: W) -> SaltlickEncrypter<W> {
        SaltlickEncrypter::with_capacity(DEFAULT_BLOCK_SIZE, public_key, writer)
    }

    /// Create a new encryption layer over `writer` using `public_key` with the
    /// provided buffer `capacity`.
    pub fn with_capacity(
        capacity: usize,
        public_key: PublicKey,
        writer: W,
    ) -> SaltlickEncrypter<W> {
        let capacity = cmp::max(capacity, MIN_BLOCK_SIZE);
        SaltlickEncrypter {
            buffer: Buffer::new(capacity),
            encrypter: Encrypter::new(public_key),
            inner: Some(writer),
        }
    }

    /// Set the block size for the underlying encrypter.
    pub fn set_block_size(&mut self, block_size: usize) {
        self.encrypter.set_block_size(block_size);
    }

    /// Write any remaining ciphertext to the stream and finalize.
    ///
    /// This will also be done automatically if the `SaltlickEncrypter` is
    /// dropped, but any errors will be silently discarded, which could mean
    /// the encrypted output is not properly finalized and therefore invalid.
    pub fn finalize(mut self) -> Result<W, io::Error> {
        let writer = self.inner.as_mut().expect("inner writer missing");
        commonio::write_finalized(writer, &mut self.encrypter, &mut self.buffer)?;
        let inner = self.inner.take().expect("inner writer missing");
        Ok(inner)
    }
}

impl<W: Write> Write for SaltlickEncrypter<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let writer = self.inner.as_mut().expect("inner writer missing");
        commonio::write(writer, &mut self.encrypter, &mut self.buffer, input)
    }

    fn flush(&mut self) -> io::Result<()> {
        let writer = self.inner.as_mut().expect("inner writer missing");
        self.buffer.flush(writer)?;
        writer.flush()
    }
}

impl<W: Write> Drop for SaltlickEncrypter<W> {
    fn drop(&mut self) {
        if self.inner.is_some() && !self.buffer.panicked() {
            let writer = self.inner.as_mut().unwrap();
            let _ = self.buffer.flush(writer);
            let _ = commonio::write_finalized(writer, &mut self.encrypter, &mut self.buffer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SaltlickDecrypter, SaltlickEncrypter};
    use crate::{key::gen_keypair, testutils::random_bytes};
    use std::{cmp, io::Write, iter};

    #[test]
    fn single_write_test() {
        for size in &[
            1,
            10 * 1024,
            32 * 1024,
            100 * 1024,
            200 * 1024,
            10 * 1024 * 1024,
        ] {
            let random_data = random_bytes(0, *size);
            let (public_key, secret_key) = gen_keypair();
            let decrypter = SaltlickDecrypter::new_deferred(Vec::new(), |_| Some(secret_key));
            let mut encrypter = SaltlickEncrypter::new(public_key, decrypter);
            encrypter.write_all(&random_data[..]).unwrap();
            let decrypter = encrypter.finalize().unwrap();
            let output = decrypter.finalize().unwrap();
            assert_eq!(&random_data[..], &output[..]);
        }
    }

    #[test]
    fn multiple_write_test() {
        for size in &[
            1,
            10 * 1024,
            32 * 1024,
            100 * 1024,
            200 * 1024,
            10 * 1024 * 1024,
        ] {
            let random_data = random_bytes(0, *size);
            let (public_key, secret_key) = gen_keypair();
            let decrypter = SaltlickDecrypter::new_deferred(Vec::new(), |_| Some(secret_key));
            let mut encrypter = SaltlickEncrypter::new(public_key, decrypter);
            encrypter.set_block_size(16 * 1024);

            // Take increasing chunks so we're varying chunk size.
            let mut written = 0;
            for take in iter::successors(Some(1usize), |n| Some(n + 7)) {
                let end = cmp::min(written + take, *size);
                encrypter.write_all(&random_data[written..end]).unwrap();
                encrypter.flush().unwrap();
                written += take;
                if written >= *size {
                    break;
                }
            }

            let decrypter = encrypter.finalize().unwrap();
            let output = decrypter.finalize().unwrap();
            assert_eq!(&random_data[..], &output[..]);
        }
    }

    #[test]
    fn drop_flush_test() {
        for size in &[
            1,
            10 * 1024,
            32 * 1024,
            100 * 1024,
            200 * 1024,
            10 * 1024 * 1024,
        ] {
            let random_data = random_bytes(0, *size);
            let (public_key, secret_key) = gen_keypair();
            let mut output = Vec::new();
            {
                let decrypter = SaltlickDecrypter::new(public_key.clone(), secret_key, &mut output);
                let mut encrypter = SaltlickEncrypter::new(public_key.clone(), decrypter);
                encrypter.write_all(&random_data[..]).unwrap();
                // Dropping encrypter/decrypter here should finalize content in `output`
            }
            assert_eq!(&random_data[..], &output[..]);
        }
    }

    #[test]
    fn corrupt_value_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let mut encrypter = SaltlickEncrypter::new(public_key.clone(), Vec::new());
        encrypter.write_all(&random_data[..]).unwrap();
        let mut ciphertext = encrypter.finalize().unwrap();

        // Inject a single bad byte near the end of the stream
        let index = ciphertext.len() - 5;
        ciphertext[index] = ciphertext[index].wrapping_add(1);

        let mut decrypter = SaltlickDecrypter::new(public_key, secret_key, Vec::new());
        assert!(decrypter.write_all(&ciphertext[..]).is_err());
    }

    #[test]
    fn incomplete_stream_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let mut encrypter = SaltlickEncrypter::new(public_key.clone(), Vec::new());
        encrypter.write_all(&random_data[..]).unwrap();
        let mut ciphertext = encrypter.finalize().unwrap();

        // Remove a few bytes from the end
        ciphertext.resize(ciphertext.len() - 5, 0);

        let mut decrypter = SaltlickDecrypter::new(public_key, secret_key, Vec::new());
        decrypter.write_all(&ciphertext[..]).unwrap();
        assert!(decrypter.finalize().is_err());
    }
}
