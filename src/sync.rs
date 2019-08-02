// Copyright (c) 2019, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp;
use std::io::{self, Read, Write};

use bytes::Buf;

use crate::crypter::{Decrypter, Encrypter, DEFAULT_BLOCK_SIZE};
use crate::error::SaltlickError;
use crate::key::{PublicKey, SecretKey};
use crate::multibuf::MultiBuf;

/// Wraps an underlying writer with encryption using the saltlick format.
///
/// Wraps a writer and returns a type that also implements `Write`. Any data
/// written to the returned type will be encrypted with the provided public key
/// and written to the underlying writer.
///
/// # Note
///
/// If writing fails during the stream, the entire stream must be discarded and
/// started over, as the underlying crypto prevents restarting.
#[derive(Debug)]
pub struct EncryptingWriter<W: Write> {
    encrypter: Encrypter,
    inner: Option<W>,
    panicked: bool,
}

impl<W: Write> EncryptingWriter<W> {
    /// Create a new encryption layer over `writer` using `public_key`.
    pub fn new(public_key: PublicKey, writer: W) -> EncryptingWriter<W> {
        EncryptingWriter {
            encrypter: Encrypter::new(public_key),
            inner: Some(writer),
            panicked: false,
        }
    }

    /// Set the block size for the underlying encrypter.
    pub fn block_size(&mut self, block_size: usize) {
        self.encrypter.set_block_size(block_size);
    }

    /// Write any remaining ciphertext to the stream and finalize.
    ///
    /// This will also be done automatically if the `EncryptingWriter` is
    /// dropped, but any errors will be silently discarded, which could mean
    /// the encrypted output is not properly finalized and therefore invalid.
    pub fn finalize(mut self) -> Result<W, io::Error> {
        self.write_data(&[] as &[u8], true)?;
        self.flush()?;
        let inner = self.inner.take().expect("inner writer missing");
        Ok(inner)
    }

    fn write_data(&mut self, buf: &[u8], finalize: bool) -> io::Result<usize> {
        let output = self
            .encrypter
            .push(buf, finalize)
            .map_err(|_| io::Error::from(io::ErrorKind::Other))?;
        self.panicked = true;
        let writer = self.inner.as_mut().expect("inner writer missing");
        for buffer in output.into_iter() {
            writer.write_all(&buffer)?;
        }
        self.panicked = false;

        Ok(buf.len())
    }
}

impl<W: Write> Write for EncryptingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_data(buf, false)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.as_mut().expect("").flush()
    }
}

impl<W: Write> Drop for EncryptingWriter<W> {
    fn drop(&mut self) {
        if self.inner.is_some() && !self.panicked {
            let _ = self.write_data(&[] as &[u8], true);
            let _ = self.flush();
        }
    }
}

/// Wraps an underlying reader with decryption using the saltlick format.
///
/// Wraps a reader and returns a type that also implements `Read`. Any data
/// read from the returned type will be decrypted with the provided secret key.
/// The public key is also checked to make sure this encrypted data is for the
/// public/secret key pair provided.
///
/// The underlying reader must reach the end of the stream in order to complete
/// decryption successfully, as the libsodium crypto relies on an end-of-stream
/// tag to provide guarantees of completeness.
#[derive(Debug)]
pub struct DecryptingReader<R: Read> {
    buffer: Vec<u8>,
    decrypter: Decrypter,
    finalized: bool,
    inner: R,
    plaintext: MultiBuf,
}

impl<R: Read> DecryptingReader<R> {
    /// Create a new decryption layer over `reader` using `secret_key` and `public_key`.
    pub fn new(public_key: PublicKey, secret_key: SecretKey, reader: R) -> DecryptingReader<R> {
        DecryptingReader {
            buffer: vec![0u8; DEFAULT_BLOCK_SIZE * 2],
            decrypter: Decrypter::new(public_key, secret_key),
            finalized: false,
            inner: reader,
            plaintext: MultiBuf::new(),
        }
    }

    /// Create a new decryption layer over `reader` using `secret_key` and `public_key`.
    pub fn new_deferred<F>(reader: R, lookup_fn: F) -> DecryptingReader<R>
    where
        F: FnOnce(&PublicKey) -> Option<SecretKey> + 'static,
    {
        DecryptingReader {
            buffer: vec![0u8; DEFAULT_BLOCK_SIZE * 2],
            decrypter: Decrypter::new_deferred(lookup_fn),
            finalized: false,
            inner: reader,
            plaintext: MultiBuf::new(),
        }
    }

    /// Stop reading/decrypting immediately and return the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for DecryptingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;

        // Read until we fill the buffer, finish the stream, or block to wait
        // for more ciphertext.
        while written < buf.len() {
            // Consume any existing plaintext buffer before going to underlying
            // reader for more ciphertext.
            if self.plaintext.has_remaining() {
                let n = cmp::min(self.plaintext.remaining(), buf.len() - written);
                self.plaintext
                    .copy_to_slice(&mut buf[written..(written + n)]);
                written += n;
            }

            // If the stream is finalized we don't want to hit the underlying
            // data source anymore.
            if self.finalized {
                return Ok(written);
            }

            // Read some more data from underlying stream.
            let n = self.inner.read(&mut self.buffer)?;

            // No more data, better have been finalized
            if n == 0 && !self.finalized {
                return Err(SaltlickError::Incomplete.into());
            }

            self.plaintext.extend(
                self.decrypter
                    .pull(&self.buffer[..n])
                    .map_err(Into::<io::Error>::into)?,
            );
            if self.decrypter.is_finalized() {
                self.finalized = true;
            }
        }

        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::key::gen_keypair;

    use super::{DecryptingReader, EncryptingWriter};

    fn random_bytes(seed: u64, size: usize) -> Box<[u8]> {
        let mut rng = XorShiftRng::seed_from_u64(seed);
        let mut bytes = vec![0u8; size];
        rng.fill_bytes(&mut bytes);
        bytes.into_boxed_slice()
    }

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
            let mut encrypter = EncryptingWriter::new(public_key.clone(), Vec::new());
            encrypter.block_size(16 * 1024);
            encrypter.write_all(&random_data[..]).unwrap();
            let inner = encrypter.finalize().unwrap();
            let mut decrypter =
                DecryptingReader::new(public_key.clone(), secret_key.clone(), Cursor::new(inner));
            let mut output = Vec::new();
            decrypter.read_to_end(&mut output).unwrap();
        }
    }

    #[test]
    fn corrupt_value_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let mut encrypter = EncryptingWriter::new(public_key.clone(), Vec::new());
        encrypter.write_all(&random_data[..]).unwrap();
        let mut ciphertext = encrypter.finalize().unwrap();

        // Inject a single bad byte near the end of the stream
        let index = ciphertext.len() - 5;
        ciphertext[index] = 0;

        let mut decrypter = DecryptingReader::new(
            public_key.clone(),
            secret_key.clone(),
            Cursor::new(ciphertext),
        );
        let mut output = Vec::new();
        assert!(decrypter.read_to_end(&mut output).is_err());
    }

    #[test]
    fn incomplete_stream_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let mut encrypter = EncryptingWriter::new(public_key.clone(), Vec::new());
        encrypter.write_all(&random_data[..]).unwrap();
        let mut ciphertext = encrypter.finalize().unwrap();

        // Remove a few bytes from the end
        ciphertext.resize(ciphertext.len() - 5, 0);

        let mut decrypter = DecryptingReader::new(
            public_key.clone(),
            secret_key.clone(),
            Cursor::new(ciphertext),
        );
        let mut output = Vec::new();
        assert!(decrypter.read_to_end(&mut output).is_err());
    }
}
