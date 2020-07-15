// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Wrapper types over [`Stream`] objects.
//!
//! [`Stream`]: https://docs.rs/futures/0.3/futures/stream/trait.Stream.html

use crate::{
    crypter::{AsyncDecrypter, Encrypter},
    key::{PublicKey, SecretKey},
    SaltlickError,
};
use async_stream::try_stream;
use bytes::Bytes;
use futures::{
    ready,
    stream::{Fuse, Stream, StreamExt},
    Future,
};
use pin_project_lite::pin_project;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

pin_project! {
    pub struct SaltlickDecrypterStream {
        inner: Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>>>>,
    }
}

impl SaltlickDecrypterStream {
    /// Create a new decryption layer over `stream` using `secret_key` and `public_key`.
    pub fn new<S, E>(
        public_key: PublicKey,
        secret_key: SecretKey,
        stream: S,
    ) -> SaltlickDecrypterStream
    where
        E: Into<io::Error> + 'static,
        S: Stream<Item = Result<Bytes, E>> + 'static,
    {
        let decrypter = AsyncDecrypter::new(public_key, secret_key);
        let inner = Self::build_inner(stream, decrypter);
        SaltlickDecrypterStream {
            inner: Box::pin(inner),
        }
    }

    /// Create a new decryption layer over `stream`, using `lookup_fn` to match
    /// the stream's `public_key` to its `secret_key`.
    pub fn new_deferred<F, S, E>(stream: S, lookup_fn: F) -> SaltlickDecrypterStream
    where
        F: FnOnce(&PublicKey) -> Option<SecretKey> + 'static,
        E: Into<io::Error> + 'static,
        S: Stream<Item = Result<Bytes, E>> + 'static,
    {
        let decrypter = AsyncDecrypter::new_deferred(lookup_fn);
        let inner = Self::build_inner(stream, decrypter);
        SaltlickDecrypterStream {
            inner: Box::pin(inner),
        }
    }

    /// Create a new decryption layer over 'stream' using an async lookup function
    /// to perform the key match
    pub fn new_deferred_async<F, S, E>(
        stream: S,
        lookup_fn: impl FnOnce(PublicKey) -> F + 'static,
    ) -> SaltlickDecrypterStream
    where
        F: Future<Output = Option<SecretKey>> + Send + 'static,
        E: Into<io::Error> + 'static,
        S: Stream<Item = Result<Bytes, E>> + 'static,
    {
        let decrypter = AsyncDecrypter::new_deferred_async(lookup_fn);
        let inner = Self::build_inner(stream, decrypter);
        SaltlickDecrypterStream {
            inner: Box::pin(inner),
        }
    }

    fn build_inner<S, E>(
        stream: S,
        mut decrypter: AsyncDecrypter,
    ) -> impl Stream<Item = Result<Bytes, io::Error>>
    where
        E: Into<io::Error> + 'static,
        S: Stream<Item = Result<Bytes, E>> + 'static,
    {
        try_stream! {
            futures::pin_mut!(stream);
            while let Some(value) = stream.next().await {
                let value = value?;
                let res = decrypter.update_to_vec(&value[..]).await?;
                if res.is_empty() {
                    continue;
                }
                yield Bytes::from(res);
            }
            if !decrypter.is_finalized() {
                Err(io::Error::from(SaltlickError::Incomplete))?
            }
        }
    }
}

impl Stream for SaltlickDecrypterStream {
    type Item = io::Result<Bytes>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<io::Result<Bytes>>> {
        self.project().inner.as_mut().poll_next(cx)
    }
}

pin_project! {
    /// Wraps a stream of bytes and returns an encrypted stream of bytes.
    ///
    /// Wraps a stream of bytes and encrypts any received data with the
    /// provided public key.
    ///
    /// The underlying stream must reach its end (i.e. return `None`) in order
    /// to complete encryption successfully, as the libsodium crypto relies on
    /// an end-of-stream tag to provide guarantees of completeness.
    #[cfg_attr(docsrs, doc(cfg(feature = "io-async")))]
    #[derive(Debug)]
    pub struct SaltlickEncrypterStream<S> {
        encrypter: Encrypter,
        #[pin]
        inner: Fuse<S>,
    }
}

impl<S, E> SaltlickEncrypterStream<S>
where
    S: Stream<Item = Result<Bytes, E>> + 'static,
{
    /// Create a new encryption layer over `stream` using `public_key`.
    pub fn new(public_key: PublicKey, stream: S) -> SaltlickEncrypterStream<S> {
        SaltlickEncrypterStream {
            encrypter: Encrypter::new(public_key),
            inner: stream.fuse(),
        }
    }

    /// Set the block size for the underlying encrypter.
    pub fn set_block_size(&mut self, block_size: usize) {
        self.encrypter.set_block_size(block_size);
    }

    /// Stop reading/encrypting immediately and return the underlying reader.
    pub fn into_inner(self) -> S {
        self.inner.into_inner()
    }
}

impl<S, E> Stream for SaltlickEncrypterStream<S>
where
    E: Into<io::Error> + 'static,
    S: Stream<Item = Result<Bytes, E>> + 'static,
{
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<io::Result<Bytes>>> {
        let mut this = self.project();
        loop {
            let result = match ready!(this.inner.as_mut().poll_next(cx)) {
                Some(Ok(input)) => {
                    let encrypted = this.encrypter.update_to_vec(&input[..], false)?;
                    if !encrypted.is_empty() {
                        Some(Ok(Bytes::from(encrypted)))
                    } else {
                        continue;
                    }
                }
                Some(Err(e)) => Some(Err(e.into())),
                None if !this.encrypter.is_finalized() => {
                    let encrypted = this.encrypter.update_to_vec(&[], true)?;
                    Some(Ok(Bytes::from(encrypted)))
                }
                None => None,
            };
            return result.into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SaltlickDecrypterStream, SaltlickEncrypterStream};
    use crate::{
        key::{gen_keypair, PublicKey, SecretKey},
        testutils::random_bytes,
    };
    use bytes::{Bytes, BytesMut};
    use futures::Stream;
    use lazy_static::lazy_static;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::{cmp, io};
    use tokio::stream::{self, StreamExt};

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
            let (public_key, secret_key) = gen_keypair();
            let input_stream =
                stream::once(Ok::<_, io::Error>(Bytes::copy_from_slice(&random_data[..])));
            let mut encrypter = SaltlickEncrypterStream::new(public_key.clone(), input_stream);
            encrypter.set_block_size(16 * 1024);
            let decrypter = SaltlickDecrypterStream::new_deferred(encrypter, |_| Some(secret_key));

            let output: Bytes = decrypter
                .collect::<Result<Bytes, io::Error>>()
                .await
                .unwrap();
            assert_eq!(&random_data[..], &output[..]);
        }
    }

    lazy_static! {
        static ref ASYNC_KEYS: (PublicKey, SecretKey) = gen_keypair();
    }

    async fn key_lookup(_public_key: PublicKey) -> Option<SecretKey> {
        Some(ASYNC_KEYS.1.clone())
    }

    #[tokio::test]
    async fn async_key_lookup_test() {
        let random_data = random_bytes(2, 1024);
        let input_stream =
            stream::once(Ok::<_, io::Error>(Bytes::copy_from_slice(&random_data[..])));
        let encrypter = SaltlickEncrypterStream::new(ASYNC_KEYS.0.clone(), input_stream);
        let decrypter = SaltlickDecrypterStream::new_deferred_async(encrypter, key_lookup);

        let output: Bytes = decrypter
            .collect::<Result<Bytes, io::Error>>()
            .await
            .unwrap();
        assert_eq!(&random_data[..], &output[..]);
    }

    fn random_chunks(seed: u64, data: &[u8]) -> impl Stream<Item = io::Result<Bytes>> {
        let mut bytes = Bytes::copy_from_slice(data);
        let mut rng = XorShiftRng::seed_from_u64(seed);
        async_stream::stream! {
            loop {
                if bytes.is_empty() {
                    break;
                }
                let n = rng.gen_range(1, 1024);
                let take = cmp::min(bytes.len(), n);
                yield Ok(bytes.split_to(take));
            }
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

            // Take increasing chunks so we're varying chunk size.
            let input_stream = random_chunks(0, &random_data[..]);
            let encrypter = SaltlickEncrypterStream::new(public_key.clone(), input_stream);
            let decrypter = SaltlickDecrypterStream::new(public_key, secret_key, encrypter);

            let output: Bytes = decrypter
                .collect::<Result<Bytes, io::Error>>()
                .await
                .unwrap();
            assert_eq!(&random_data[..], &output[..]);
        }
    }

    #[tokio::test]
    async fn corrupt_value_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let input_stream =
            stream::once(Ok::<_, io::Error>(Bytes::copy_from_slice(&random_data[..])));
        let encrypter = SaltlickEncrypterStream::new(public_key.clone(), input_stream);
        let mut ciphertext = encrypter
            .collect::<Result<BytesMut, io::Error>>()
            .await
            .unwrap();

        // Inject a single bad byte near the end of the stream
        let index = ciphertext.len() - 5;
        ciphertext[index] = ciphertext[index].wrapping_add(1);

        let cipher_stream = stream::once(Ok::<_, io::Error>(ciphertext.freeze()));
        let decrypter = SaltlickDecrypterStream::new(public_key, secret_key, cipher_stream);
        decrypter
            .collect::<Result<Bytes, io::Error>>()
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn incomplete_stream_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let input_stream =
            stream::once(Ok::<_, io::Error>(Bytes::copy_from_slice(&random_data[..])));
        let encrypter = SaltlickEncrypterStream::new(public_key.clone(), input_stream);
        let mut ciphertext = encrypter
            .collect::<Result<BytesMut, io::Error>>()
            .await
            .unwrap();

        // Remove a few bytes from the end
        ciphertext.truncate(ciphertext.len() - 5);

        let cipher_stream = stream::once(Ok::<_, io::Error>(ciphertext.freeze()));
        let decrypter = SaltlickDecrypterStream::new(public_key, secret_key.clone(), cipher_stream);
        decrypter
            .collect::<Result<Bytes, io::Error>>()
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn underlying_stream_error_test() {
        let (public_key, secret_key) = gen_keypair();
        let input_stream = stream::once(Err::<Bytes, _>(io::Error::from(io::ErrorKind::Other)));
        let encrypter = SaltlickEncrypterStream::new(public_key.clone(), input_stream);
        let decrypter = SaltlickDecrypterStream::new(public_key, secret_key, encrypter);

        let error = decrypter
            .collect::<Result<Bytes, io::Error>>()
            .await
            .unwrap_err();
        assert_eq!(io::ErrorKind::Other, error.kind());
    }

    #[tokio::test]
    async fn into_inner_test() {
        // Making sure that passing a stream through the encrypter and not performing
        // any operations still returns the untouched input stream.
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, _secret_key) = gen_keypair();
        let input_stream =
            stream::once(Ok::<_, io::Error>(Bytes::copy_from_slice(&random_data[..])));
        let encrypter = SaltlickEncrypterStream::new(public_key.clone(), input_stream);
        let mut input_stream = encrypter.into_inner();
        assert_eq!(
            Bytes::copy_from_slice(&random_data[..]),
            input_stream.next().await.unwrap().unwrap()
        );
    }
}
