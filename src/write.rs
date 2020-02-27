// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{crypter::Encrypter, key::PublicKey};
use std::{
    cmp,
    io::{self, Write},
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
pub struct SaltlickEncrypter<W: Write> {
    available: usize,
    ciphertext: Box<[u8]>,
    consumed: usize,
    encrypter: Encrypter,
    inner: Option<W>,
    panicked: bool,
}

impl<W: Write> SaltlickEncrypter<W> {
    /// Create a new encryption layer over `writer` using `public_key`.
    pub fn new(public_key: PublicKey, writer: W) -> SaltlickEncrypter<W> {
        SaltlickEncrypter::with_capacity(DEFAULT_BUF_SIZE, public_key, writer)
    }

    /// Create a new encryption layer over `writer` using `public_key` with the
    /// provided buffer `capacity`.
    pub fn with_capacity(
        capacity: usize,
        public_key: PublicKey,
        writer: W,
    ) -> SaltlickEncrypter<W> {
        let capacity = cmp::max(capacity, MIN_BUF_SIZE);
        SaltlickEncrypter {
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
    /// This will also be done automatically if the `SaltlickEncrypter` is
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

impl<W: Write> Write for SaltlickEncrypter<W> {
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

impl<W: Write> Drop for SaltlickEncrypter<W> {
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
