// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{
    crypter::{Decrypter, DEFAULT_BLOCK_SIZE},
    error::SaltlickError,
    key::{PublicKey, SecretKey},
};
use std::{
    cmp,
    io::{self, BufRead, BufReader, Read, Write},
};

const MIN_BUF_SIZE: usize = 1024;

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
