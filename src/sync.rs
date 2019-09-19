// Copyright (c) 2019, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{
    crypter::{Decrypter, Encrypter, DEFAULT_BLOCK_SIZE},
    error::SaltlickError,
    key::{PublicKey, SecretKey},
};
use std::{
    cmp,
    io::{self, BufRead, BufReader, Read, Write},
};

const MIN_BUF_SIZE: usize = 1024;
const DEFAULT_BUF_SIZE: usize = 32 * 1024;

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
    available: usize,
    ciphertext: Box<[u8]>,
    consumed: usize,
    encrypter: Encrypter,
    inner: Option<W>,
    panicked: bool,
}

impl<W: Write> EncryptingWriter<W> {
    /// Create a new encryption layer over `writer` using `public_key`.
    pub fn new(public_key: PublicKey, writer: W) -> EncryptingWriter<W> {
        EncryptingWriter::with_capacity(DEFAULT_BUF_SIZE, public_key, writer)
    }

    /// Create a new encryption layer over `writer` using `public_key` with the
    /// provided buffer `capacity`.
    pub fn with_capacity(capacity: usize, public_key: PublicKey, writer: W) -> EncryptingWriter<W> {
        let capacity = cmp::max(capacity, MIN_BUF_SIZE);
        EncryptingWriter {
            available: 0,
            ciphertext: vec![0u8; capacity].into_boxed_slice(),
            consumed: 0,
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
        while self.encrypter.is_not_finalized() {
            self.flush_buf()?;
            let (_, wr) = self.encrypter.update(&[], &mut self.ciphertext, true)?;
            self.available = wr;
            self.consumed = 0;
        }
        self.flush()?;
        let inner = self.inner.take().expect("inner writer missing");
        Ok(inner)
    }

    fn flush_buf(&mut self) -> io::Result<()> {
        while self.ciphertext_len() > 0 {
            self.panicked = true;
            let writer = self.inner.as_mut().expect("inner writer missing");
            let res = writer.write(&self.ciphertext[self.consumed..self.available]);
            self.panicked = false;
            match res {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write the buffered data",
                    ));
                }
                Ok(n) => self.consumed += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn ciphertext_len(&self) -> usize {
        self.available - self.consumed
    }
}

impl<W: Write> Write for EncryptingWriter<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        // All current ciphertext needs to be flushed before writing anything
        // new since we give `update` the whole buffer.
        self.flush_buf()?;

        // Returning a zero write is an error, so keep updating until we read
        // some input, block, or error.
        let mut last_rd = 0;
        while last_rd == 0 {
            let (rd, wr) = self.encrypter.update(input, &mut self.ciphertext, false)?;
            self.available = wr;
            self.consumed = 0;
            last_rd = rd;
            self.flush_buf()?;
        }
        Ok(last_rd)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buf()?;
        self.inner.as_mut().expect("inner writer missing").flush()
    }
}

impl<W: Write> Drop for EncryptingWriter<W> {
    fn drop(&mut self) {
        if self.inner.is_some() && !self.panicked {
            let (_, wr) = self
                .encrypter
                .update(&[] as &[u8], &mut self.ciphertext, true)
                .unwrap_or((0, 0));
            self.available = wr;
            self.consumed = 0;
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
    available: usize,
    bufread: BufReader<R>,
    consumed: usize,
    decrypter: Decrypter,
    plaintext: Box<[u8]>,
}

impl<R: Read> DecryptingReader<R> {
    /// Create a new decryption layer over `reader` using `secret_key` and `public_key`.
    pub fn new(public_key: PublicKey, secret_key: SecretKey, reader: R) -> DecryptingReader<R> {
        Self::with_capacity(
            DEFAULT_BLOCK_SIZE,
            DEFAULT_BLOCK_SIZE,
            public_key,
            secret_key,
            reader,
        )
    }

    /// Create a new decryption layer over `reader`, using `lookup_fn` to match
    /// the stream's `public_key` to its `secret_key`.
    pub fn new_deferred<F>(reader: R, lookup_fn: F) -> DecryptingReader<R>
    where
        F: FnOnce(&PublicKey) -> Option<SecretKey> + 'static,
    {
        Self::deferred_with_capacity(DEFAULT_BLOCK_SIZE, DEFAULT_BLOCK_SIZE, reader, lookup_fn)
    }

    /// Create a new decryption layer over `reader` using `secret_key` and `public_key`.
    pub fn with_capacity(
        read_capacity: usize,
        plaintext_capacity: usize,
        public_key: PublicKey,
        secret_key: SecretKey,
        reader: R,
    ) -> DecryptingReader<R> {
        let plaintext_capacity = cmp::max(plaintext_capacity, MIN_BUF_SIZE);
        let read_capacity = cmp::max(read_capacity, MIN_BUF_SIZE);
        DecryptingReader {
            available: 0,
            bufread: BufReader::with_capacity(read_capacity, reader),
            consumed: 0,
            decrypter: Decrypter::new(public_key, secret_key),
            plaintext: vec![0u8; plaintext_capacity].into_boxed_slice(),
        }
    }

    /// Create a new decryption layer over `reader`, using `lookup_fn` to match
    /// the stream's `public_key` to its `secret_key`.
    pub fn deferred_with_capacity<F>(
        read_capacity: usize,
        plaintext_capacity: usize,
        reader: R,
        lookup_fn: F,
    ) -> DecryptingReader<R>
    where
        F: FnOnce(&PublicKey) -> Option<SecretKey> + 'static,
    {
        let plaintext_capacity = cmp::max(plaintext_capacity, MIN_BUF_SIZE);
        let read_capacity = cmp::max(read_capacity, MIN_BUF_SIZE);
        DecryptingReader {
            available: 0,
            bufread: BufReader::with_capacity(read_capacity, reader),
            consumed: 0,
            decrypter: Decrypter::new_deferred(lookup_fn),
            plaintext: vec![0u8; plaintext_capacity].into_boxed_slice(),
        }
    }

    /// Stop reading/decrypting immediately and return the underlying reader.
    pub fn into_inner(self) -> R {
        self.bufread.into_inner()
    }

    fn plaintext_len(&self) -> usize {
        self.available - self.consumed
    }
}

impl<R: Read> Read for DecryptingReader<R> {
    fn read(&mut self, mut output: &mut [u8]) -> io::Result<usize> {
        let mut nwritten = 0;
        loop {
            if output.is_empty() {
                return Ok(nwritten);
            }

            if self.plaintext_len() > 0 {
                let take = cmp::min(self.plaintext_len(), output.len());
                let n = output.write(&self.plaintext[self.consumed..(self.consumed + take)])?;
                self.consumed += n;
                nwritten += n;
                continue;
            }

            // If the stream is finalized we don't want to hit the underlying
            // data source anymore.
            if self.decrypter.is_finalized() {
                return Ok(nwritten);
            }

            let input = self.bufread.fill_buf()?;

            // No more data, better have been finalized
            if input.is_empty() && self.decrypter.is_not_finalized() {
                return Err(SaltlickError::Incomplete.into());
            }

            let (rd, wr) = self.decrypter.update(input, &mut self.plaintext)?;
            self.available = wr;
            self.consumed = 0;
            self.bufread.consume(rd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DecryptingReader, EncryptingWriter};
    use crate::key::gen_keypair;
    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::{
        cmp,
        io::{Cursor, Read, Write},
        iter,
    };

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
            encrypter.write_all(&random_data[..]).unwrap();
            let ciphertext = Cursor::new(encrypter.finalize().unwrap());
            let mut decrypter =
                DecryptingReader::new(public_key.clone(), secret_key.clone(), ciphertext);
            let mut output = Vec::new();
            decrypter.read_to_end(&mut output).unwrap();
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
            let mut encrypter = EncryptingWriter::new(public_key.clone(), Vec::new());
            encrypter.block_size(16 * 1024);
            let mut written = 0;
            // Take increasing chunks so we're varying chunk size.
            for take in iter::successors(Some(1usize), |n| Some(n + 7)) {
                let end = cmp::min(written + take, *size);
                encrypter.write_all(&random_data[written..end]).unwrap();
                written += take;
                if written >= *size {
                    break;
                }
            }
            let ciphertext = Cursor::new(encrypter.finalize().unwrap());
            let mut decrypter =
                DecryptingReader::new(public_key.clone(), secret_key.clone(), ciphertext);
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
        ciphertext[index] = ciphertext[index].wrapping_add(1);

        let mut decrypter = DecryptingReader::new(public_key, secret_key, Cursor::new(ciphertext));
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

        let mut decrypter = DecryptingReader::new(public_key, secret_key, Cursor::new(ciphertext));
        let mut output = Vec::new();
        assert!(decrypter.read_to_end(&mut output).is_err());
    }
}
