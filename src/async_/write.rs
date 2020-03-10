// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Wrapper types over [`AsyncWrite`] objects.
//!
//! [`AsyncWrite`]: https://docs.rs/tokio/0.2/tokio/io/trait.AsyncWrite.html

use super::commonio::{self, AsyncBuffer};
use crate::{
    crypter::{Decrypter, Encrypter, DEFAULT_BLOCK_SIZE, MIN_BLOCK_SIZE},
    key::{PublicKey, SecretKey},
};
use pin_project_lite::pin_project;
use std::{
    cmp, io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::AsyncWrite;

pin_project! {
    /// Wraps an underlying writer with decryption using the saltlick format.
    ///
    /// Wraps a writer that implements [`AsyncWrite`] and returns a type that
    /// also implements [`AsyncWrite`]. Any data written to the returned type
    /// will be decrypted with the provided secret key and written to the
    /// underlying writer.  The public key is also checked to make sure this
    /// encrypted data is for the public/secret key pair provided.
    ///
    /// Any data written after the encrypted stream is complete will be
    /// discarded.
    ///
    /// # Note
    ///
    /// If writing fails during the stream, the entire stream must be discarded
    /// and started over, as the underlying crypto prevents restarting.
    ///
    /// [`AsyncWrite`]: https://docs.rs/tokio/0.2/tokio/io/trait.AsyncWrite.html
    #[cfg_attr(docsrs, doc(cfg(feature = "io-async")))]
    #[derive(Debug)]
    pub struct AsyncSaltlickDecrypter<W> {
        buffer: AsyncBuffer,
        decrypter: Decrypter,
        #[pin]
        inner: W,
    }
}

impl<W: AsyncWrite> AsyncSaltlickDecrypter<W> {
    /// Create a new decryption layer over `writer` using `secret_key` and `public_key`.
    pub fn new(
        public_key: PublicKey,
        secret_key: SecretKey,
        writer: W,
    ) -> AsyncSaltlickDecrypter<W> {
        Self::with_capacity(DEFAULT_BLOCK_SIZE, public_key, secret_key, writer)
    }

    /// Create a new decryption layer over `writer`, using `lookup_fn` to match
    /// the stream's `public_key` to its `secret_key`.
    pub fn new_deferred<F>(writer: W, lookup_fn: F) -> AsyncSaltlickDecrypter<W>
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
    ) -> AsyncSaltlickDecrypter<W> {
        let capacity = cmp::max(capacity, MIN_BLOCK_SIZE);
        AsyncSaltlickDecrypter {
            buffer: AsyncBuffer::new(capacity),
            decrypter: Decrypter::new(public_key, secret_key),
            inner: writer,
        }
    }

    /// Create a new decryption layer over `writer`, using `lookup_fn` to match
    /// the stream's `public_key` to its `secret_key` with the provided buffer
    /// capacity.
    pub fn deferred_with_capacity<F>(
        capacity: usize,
        writer: W,
        lookup_fn: F,
    ) -> AsyncSaltlickDecrypter<W>
    where
        F: FnOnce(&PublicKey) -> Option<SecretKey> + 'static,
    {
        let capacity = cmp::max(capacity, MIN_BLOCK_SIZE);
        AsyncSaltlickDecrypter {
            buffer: AsyncBuffer::new(capacity),
            decrypter: Decrypter::new_deferred(lookup_fn),
            inner: writer,
        }
    }

    /// Stop writing/decrypting immediately and return the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite> AsyncWrite for AsyncSaltlickDecrypter<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, input: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.project();
        commonio::poll_write(this.inner, cx, this.decrypter, this.buffer, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.project();
        commonio::poll_flush(this.inner, cx, this.buffer)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.project();
        commonio::poll_shutdown(this.inner, cx, this.decrypter, this.buffer)
    }
}

pin_project! {
    /// Wraps an underlying writer with encryption using the saltlick format.
    ///
    /// Wraps a writer that implements [`AsyncWrite`] and returns a type that
    /// also implements [`AsyncWrite`].  Any data written to the returned type
    /// will be encrypted with the provided public key and written to the
    /// underlying writer.
    ///
    /// # Note
    ///
    /// If writing fails during the stream, the entire stream must be discarded
    /// and started over, as the underlying crypto prevents restarting.
    ///
    /// If polling manually, the `poll_shutdown` function must be called. If
    /// it is not called, the stream will not be finalized and decryption will
    /// fail with an [`Incomplete` error](../enum.SaltlickError.html).
    ///
    /// [`AsyncWrite`]: https://docs.rs/tokio/0.2/tokio/io/trait.AsyncWrite.html
    #[cfg_attr(docsrs, doc(cfg(feature = "io-async")))]
    #[derive(Debug)]
    pub struct AsyncSaltlickEncrypter<W> {
        buffer: AsyncBuffer,
        encrypter: Encrypter,
        #[pin]
        inner: W,
    }
}

impl<W: AsyncWrite> AsyncSaltlickEncrypter<W> {
    /// Create a new encryption layer over `writer` using `public_key`.
    pub fn new(public_key: PublicKey, writer: W) -> AsyncSaltlickEncrypter<W> {
        AsyncSaltlickEncrypter::with_capacity(DEFAULT_BLOCK_SIZE, public_key, writer)
    }

    /// Create a new encryption layer over `writer` using `public_key` with the
    /// provided buffer `capacity`.
    pub fn with_capacity(
        capacity: usize,
        public_key: PublicKey,
        writer: W,
    ) -> AsyncSaltlickEncrypter<W> {
        let capacity = cmp::max(capacity, MIN_BLOCK_SIZE);
        AsyncSaltlickEncrypter {
            buffer: AsyncBuffer::new(capacity),
            encrypter: Encrypter::new(public_key),
            inner: writer,
        }
    }

    /// Set the block size for the underlying encrypter.
    pub fn set_block_size(&mut self, block_size: usize) {
        self.encrypter.set_block_size(block_size);
    }

    /// Stop writing/encrypting immediately and return the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite> AsyncWrite for AsyncSaltlickEncrypter<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, input: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.project();
        commonio::poll_write(this.inner, cx, this.encrypter, this.buffer, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.project();
        commonio::poll_flush(this.inner, cx, this.buffer)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.project();
        commonio::poll_shutdown(this.inner, cx, this.encrypter, this.buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::{AsyncSaltlickDecrypter, AsyncSaltlickEncrypter};
    use crate::{key::gen_keypair, testutils::random_bytes};
    use std::{cmp, iter};
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn single_write_test() {
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
            let decrypter = AsyncSaltlickDecrypter::new_deferred(Vec::new(), |_| Some(secret_key));
            let mut encrypter = AsyncSaltlickEncrypter::new(public_key.clone(), decrypter);
            encrypter.write_all(&random_data[..]).await.unwrap();
            encrypter.flush().await.unwrap();
            encrypter.shutdown().await.unwrap();
            let output = encrypter.into_inner().into_inner();
            assert_eq!(&random_data[..], &output[..]);
        }
    }

    #[tokio::test]
    async fn multiple_write_test() {
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
            let decrypter = AsyncSaltlickDecrypter::new(public_key.clone(), secret_key, Vec::new());
            let mut encrypter = AsyncSaltlickEncrypter::new(public_key, decrypter);
            encrypter.set_block_size(16 * 1024);

            // Take increasing chunks so we're varying chunk size.
            let mut written = 0;
            for take in iter::successors(Some(1usize), |n| Some(n + 7)) {
                let end = cmp::min(written + take, *size);
                encrypter
                    .write_all(&random_data[written..end])
                    .await
                    .unwrap();
                written += take;
                if written >= *size {
                    break;
                }
            }

            encrypter.shutdown().await.unwrap();
            let output = encrypter.into_inner().into_inner();
            assert_eq!(&random_data[..], &output[..]);
        }
    }

    #[tokio::test]
    async fn corrupt_value_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let mut encrypter = AsyncSaltlickEncrypter::new(public_key.clone(), Vec::new());
        encrypter.write_all(&random_data[..]).await.unwrap();
        encrypter.shutdown().await.unwrap();
        let mut ciphertext = encrypter.into_inner();

        // Inject a single bad byte near the end of the stream
        let index = ciphertext.len() - 5;
        ciphertext[index] = ciphertext[index].wrapping_add(1);

        let mut decrypter = AsyncSaltlickDecrypter::new(public_key, secret_key, Vec::new());
        assert!(decrypter.write_all(&ciphertext[..]).await.is_err());
    }

    #[tokio::test]
    async fn incomplete_stream_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let mut encrypter = AsyncSaltlickEncrypter::new(public_key.clone(), Vec::new());
        encrypter.write_all(&random_data[..]).await.unwrap();
        encrypter.shutdown().await.unwrap();
        let mut ciphertext = encrypter.into_inner();

        // Remove a few bytes from the end
        ciphertext.resize(ciphertext.len() - 5, 0);

        let mut decrypter = AsyncSaltlickDecrypter::new(public_key, secret_key, Vec::new());
        decrypter.write_all(&ciphertext[..]).await.unwrap();
        assert!(decrypter.shutdown().await.is_err());
    }
}
