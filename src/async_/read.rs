// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Wrapper types over [`AsyncRead`] objects.
//!
//! [`AsyncRead`]: https://docs.rs/tokio/0.2/tokio/io/trait.AsyncRead.html

use super::bufread;
use crate::{
    crypter::DEFAULT_BLOCK_SIZE,
    key::{PublicKey, SecretKey},
};
use pin_project_lite::pin_project;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, BufReader};

pin_project! {
    /// Wraps an underlying reader with decryption using the saltlick format.
    ///
    /// Wraps a reader that implements [`AsyncRead`] and returns a type that
    /// also implements [`AsyncRead`]. Any data read from the returned type
    /// will be decrypted with the provided secret key.  The public key is also
    /// checked to make sure this encrypted data is for the public/secret key
    /// pair provided.
    ///
    /// The underlying reader must reach the end of the stream in order to
    /// complete decryption successfully, as the libsodium crypto relies on an
    /// end-of-stream tag to provide guarantees of completeness.
    ///
    /// [`AsyncRead`]: https://docs.rs/tokio/0.2/tokio/io/trait.AsyncRead.html
    #[cfg_attr(docsrs, doc(cfg(feature = "io-async")))]
    #[derive(Debug)]
    pub struct AsyncSaltlickDecrypter<R> {
        #[pin]
        inner: bufread::AsyncSaltlickDecrypter<BufReader<R>>,
    }
}

impl<R: AsyncRead> AsyncSaltlickDecrypter<R> {
    /// Create a new decryption layer over `reader` using `secret_key` and `public_key`.
    pub fn new(
        public_key: PublicKey,
        secret_key: SecretKey,
        reader: R,
    ) -> AsyncSaltlickDecrypter<R> {
        Self::with_capacity(DEFAULT_BLOCK_SIZE, public_key, secret_key, reader)
    }

    /// Create a new decryption layer over `reader`, using `lookup_fn` to match
    /// the stream's `public_key` to its `secret_key`.
    pub fn new_deferred<F>(reader: R, lookup_fn: F) -> AsyncSaltlickDecrypter<R>
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
    ) -> AsyncSaltlickDecrypter<R> {
        let bufreader = BufReader::with_capacity(capacity, reader);
        AsyncSaltlickDecrypter {
            inner: bufread::AsyncSaltlickDecrypter::new(public_key, secret_key, bufreader),
        }
    }

    /// Create a new decryption layer over `reader`, using `lookup_fn` to match
    /// the stream's `public_key` to its `secret_key` with the specified buffer
    /// capacity.
    pub fn deferred_with_capacity<F>(
        capacity: usize,
        reader: R,
        lookup_fn: F,
    ) -> AsyncSaltlickDecrypter<R>
    where
        F: FnOnce(&PublicKey) -> Option<SecretKey> + 'static,
    {
        let bufreader = BufReader::with_capacity(capacity, reader);
        AsyncSaltlickDecrypter {
            inner: bufread::AsyncSaltlickDecrypter::new_deferred(bufreader, lookup_fn),
        }
    }

    /// Stop reading/decrypting immediately and return the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner.into_inner().into_inner()
    }
}

impl<R: AsyncRead> AsyncRead for AsyncSaltlickDecrypter<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_read(cx, output)
    }
}

pin_project! {
    /// Wraps an underlying reader with encryption using the saltlick format.
    ///
    /// Wraps a reader that implements [`AsyncRead`] and returns a type that
    /// also implements [`AsyncRead`]. Any data read from the returned type
    /// will be encrypted with the provided public key.
    ///
    /// The underlying reader must reach the end of the stream in order to
    /// complete encryption successfully, as the libsodium crypto relies on an
    /// end-of-stream tag to provide guarantees of completeness.
    ///
    /// [`AsyncRead`]: https://docs.rs/tokio/0.2/tokio/io/trait.AsyncRead.html
    #[cfg_attr(docsrs, doc(cfg(feature = "io-async")))]
    #[derive(Debug)]
    pub struct AsyncSaltlickEncrypter<R> {
        #[pin]
        inner: bufread::AsyncSaltlickEncrypter<BufReader<R>>,
    }
}

impl<R: AsyncRead> AsyncSaltlickEncrypter<R> {
    /// Create a new encryption layer over `reader` using `public_key`.
    pub fn new(public_key: PublicKey, reader: R) -> AsyncSaltlickEncrypter<R> {
        Self::with_capacity(DEFAULT_BLOCK_SIZE, public_key, reader)
    }

    /// Create a new encryption layer over `reader` using `secret_key` and
    /// `public_key` with the specified buffer capacity.
    pub fn with_capacity(
        capacity: usize,
        public_key: PublicKey,
        reader: R,
    ) -> AsyncSaltlickEncrypter<R> {
        let bufreader = BufReader::with_capacity(capacity, reader);
        AsyncSaltlickEncrypter {
            inner: bufread::AsyncSaltlickEncrypter::new(public_key, bufreader),
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

impl<R: AsyncRead> AsyncRead for AsyncSaltlickEncrypter<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_read(cx, output)
    }
}

#[cfg(test)]
mod tests {
    use super::{AsyncSaltlickDecrypter, AsyncSaltlickEncrypter};
    use crate::key::gen_keypair;
    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, BufReader};

    fn random_bytes(seed: u64, size: usize) -> Box<[u8]> {
        let mut rng = XorShiftRng::seed_from_u64(seed);
        let mut bytes = vec![0u8; size];
        rng.fill_bytes(&mut bytes);
        bytes.into_boxed_slice()
    }

    #[tokio::test]
    async fn round_trip_test() {
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
            let mut encrypter = AsyncSaltlickEncrypter::new(public_key.clone(), reader);
            encrypter.set_block_size(1024);
            let mut decrypter =
                AsyncSaltlickDecrypter::new_deferred(BufReader::new(encrypter), |_| {
                    Some(secret_key)
                });
            let mut output = Vec::new();
            decrypter.read_to_end(&mut output).await.unwrap();
            assert_eq!(&random_data[..], &output[..]);
        }
    }

    #[tokio::test]
    async fn corrupt_value_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let mut encrypter =
            AsyncSaltlickEncrypter::new(public_key.clone(), Cursor::new(random_data));
        let mut ciphertext = Vec::new();
        encrypter.read_to_end(&mut ciphertext).await.unwrap();

        // Inject a single bad byte near the end of the stream
        let index = ciphertext.len() - 5;
        ciphertext[index] = ciphertext[index].wrapping_add(1);

        let mut decrypter =
            AsyncSaltlickDecrypter::new(public_key, secret_key, Cursor::new(ciphertext));
        let mut output = Vec::new();
        assert!(decrypter.read_to_end(&mut output).await.is_err());
    }

    #[tokio::test]
    async fn incomplete_stream_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let mut encrypter =
            AsyncSaltlickEncrypter::new(public_key.clone(), Cursor::new(random_data));
        let mut ciphertext = Vec::new();
        encrypter.read_to_end(&mut ciphertext).await.unwrap();

        // Remove a few bytes from the end
        ciphertext.resize(ciphertext.len() - 5, 0);

        let mut decrypter =
            AsyncSaltlickDecrypter::new(public_key, secret_key, Cursor::new(ciphertext));
        let mut output = Vec::new();
        assert!(decrypter.read_to_end(&mut output).await.is_err());
    }

    #[test]
    fn into_inner_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let encrypter =
            AsyncSaltlickEncrypter::new(public_key.clone(), Cursor::new(&random_data[..]));
        let decrypter = AsyncSaltlickDecrypter::new(public_key, secret_key, encrypter);
        let encrypter = decrypter.into_inner();
        let recovered_data = encrypter.into_inner().into_inner();
        assert_eq!(&random_data[..], recovered_data,);
    }
}
