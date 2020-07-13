// Copyright (c) 2020, saltlick-rs maintainers
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{
    crypter::{advance_slice, advance_slice_mut, DecrypterInner, UpdateReturn},
    error::SaltlickError,
    key::{PublicKey, SecretKey},
};
use futures::{future::BoxFuture, Future};
use std::fmt;

type KeyLookupFn = Box<dyn FnOnce(&PublicKey) -> Option<SecretKey>>;
type AsyncKeyLookupFn = Box<dyn FnOnce(PublicKey) -> BoxFuture<'static, Option<SecretKey>>>;

#[derive(strum_macros::AsRefStr)]
enum KeyResolution {
    Available(PublicKey, SecretKey),
    Deferred(KeyLookupFn),
    DeferredAsync(AsyncKeyLookupFn),
}

impl fmt::Debug for KeyResolution {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

/// Wrapper type for the decrypter to support async key lookup functions.
#[derive(Debug)]
pub struct AsyncDecrypter {
    inner: DecrypterInner,
    key_resolution: Option<KeyResolution>,
}

impl AsyncDecrypter {
    /// Create a new decrypter using provided keys.
    pub fn new(public_key: PublicKey, secret_key: SecretKey) -> AsyncDecrypter {
        let key = KeyResolution::Available(public_key, secret_key);
        AsyncDecrypter {
            inner: DecrypterInner::default(),
            key_resolution: Some(key),
        }
    }

    /// Create a new decrypter that calls `lookup_fn` with the public key
    /// obtained from the stream to obtain a secret key.
    ///
    /// This function allows for delayed lookup of a secret key - for example,
    /// when there are multiple potential keys that could have been used to
    /// encrypt the file. The lookup function should return the secret key
    /// corresponding to the given public key, or `None` if no appropriate key
    /// is available. In this case, the Decrypter will return a
    /// `SaltlickError::SecretKeyNotFound` error from `update`.
    pub fn new_deferred<F>(lookup_fn: F) -> AsyncDecrypter
    where
        F: FnOnce(&PublicKey) -> Option<SecretKey> + 'static,
    {
        let key = KeyResolution::Deferred(Box::new(lookup_fn));
        AsyncDecrypter {
            inner: DecrypterInner::default(),
            key_resolution: Some(key),
        }
    }

    /// Create a new async key lookup decrypter. This functions exactly like the
    /// synchronous version of deferred key lookup but supports providing an async
    /// function.
    pub fn new_deferred_async<F>(lookup_fn: impl FnOnce(PublicKey) -> F + 'static) -> AsyncDecrypter
    where
        F: Future<Output = Option<SecretKey>> + Send + 'static,
    {
        let key = KeyResolution::DeferredAsync(Box::new(move |k| Box::pin(lookup_fn(k))));
        AsyncDecrypter {
            inner: DecrypterInner::default(),
            key_resolution: Some(key),
        }
    }

    /// Update decrypter with ciphertext input, receiving decrypted plaintext
    /// as output.
    ///
    /// Update decrypter with ciphertext `input`, receiving decrypted plaintext
    /// as `output`. Async returns a tuple of bytes read / bytes written.
    pub async fn update(
        &mut self,
        mut input: &[u8],
        mut output: &mut [u8],
    ) -> Result<(usize, usize), SaltlickError> {
        match self.inner.update(input, &mut output, None)? {
            UpdateReturn::Progress(nread, nwritten) => Ok((nread, nwritten)),
            UpdateReturn::NeedSecretKey(nread, nwritten, public_key) => {
                let secret = match self.key_resolution.take() {
                    Some(KeyResolution::Available(public, secret)) => {
                        if public == public_key {
                            Ok(secret)
                        } else {
                            Err(SaltlickError::PublicKeyMismatch)
                        }
                    }
                    Some(KeyResolution::Deferred(lookup_fn)) => {
                        lookup_fn(&public_key).ok_or(SaltlickError::SecretKeyNotFound)
                    }
                    Some(KeyResolution::DeferredAsync(lookup_fn)) => {
                        if let Some(secret) = lookup_fn(public_key).await {
                            Ok(secret)
                        } else {
                            Err(SaltlickError::SecretKeyNotFound)
                        }
                    }
                    None => Err(SaltlickError::SecretKeyNotFound),
                }?;
                advance_slice(&mut input, nread);
                advance_slice_mut(&mut output, nwritten);
                match self.inner.update(input, &mut output, Some(secret))? {
                    UpdateReturn::Progress(read, written) => Ok((nread + read, nwritten + written)),
                    UpdateReturn::NeedSecretKey(_, _, _) => unreachable!(),
                }
            }
        }
    }

    /// Convenience version of `update` that allocates and returns output data
    /// as a `Vec<u8>`.
    pub async fn update_to_vec(
        &mut self,
        input: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, SaltlickError> {
        let input = input.as_ref();
        let mut plaintext = vec![0u8; self.inner.estimate_output_size(input.len())];
        let (rd, wr) = self.update(input, &mut plaintext).await?;

        // The decrypter never buffers more than 1 complete block, and input
        // data will never decrypt larger than the ciphertext size. Since we
        // allocate space for 2 complete blocks plus the input size, we will
        // always consume the entire input. If we don't, an assumption has
        // broken down and the output is not valid.
        assert!(rd == input.len());

        plaintext.truncate(wr);
        Ok(plaintext)
    }

    /// Returns true if the crypter has been finalized.
    pub fn is_finalized(&self) -> bool {
        self.inner.is_finalized()
    }
}

#[cfg(test)]
mod tests {
    use super::AsyncDecrypter;
    use crate::{
        crypter::Encrypter,
        error::SaltlickError,
        key::{self, PublicKey, SecretKey},
        testutils::random_bytes,
    };
    use lazy_static::lazy_static;

    #[tokio::test]
    async fn simple_test() {
        let test_data = random_bytes(4, 25000);
        let (public, secret) = key::gen_keypair();

        let mut encrypter = Encrypter::new(public.clone());
        let ciphertext = encrypter.update_to_vec(&test_data[..], true).unwrap();

        let mut decrypter = AsyncDecrypter::new(public, secret);
        let plaintext = decrypter.update_to_vec(&ciphertext[..]).await.unwrap();
        assert!(decrypter.is_finalized());
        assert_eq!(test_data, plaintext.into_boxed_slice());
    }

    #[tokio::test]
    async fn wrong_publickey_test() {
        let test_data = random_bytes(4, 25000);
        let (public, secret) = key::gen_keypair();
        let (public_incorrect, _secret) = key::gen_keypair();

        let mut encrypter = Encrypter::new(public);
        let ciphertext = encrypter.update_to_vec(&test_data[..], true).unwrap();

        let mut decrypter = AsyncDecrypter::new(public_incorrect, secret);
        assert_eq!(
            SaltlickError::PublicKeyMismatch,
            decrypter.update_to_vec(&ciphertext[..]).await.unwrap_err()
        );
    }

    #[tokio::test]
    async fn deferred_key_load_test() {
        let test_data = random_bytes(4, 25000);
        let (public, secret) = key::gen_keypair();

        let mut encrypter = Encrypter::new(public);
        let ciphertext = encrypter.update_to_vec(&test_data[..], true).unwrap();

        let mut decrypter = AsyncDecrypter::new_deferred(|_public| Some(secret));
        let plaintext = decrypter.update_to_vec(&ciphertext[..]).await.unwrap();
        assert!(decrypter.is_finalized());
        assert_eq!(test_data, plaintext.into_boxed_slice());
    }

    #[tokio::test]
    async fn deferred_key_load_failure_test() {
        let test_data = random_bytes(4, 25000);
        let (public, _secret) = key::gen_keypair();

        let mut encrypter = Encrypter::new(public);
        let ciphertext = encrypter.update_to_vec(&test_data[..], true).unwrap();

        let mut decrypter = AsyncDecrypter::new_deferred(move |_public| None);
        assert_eq!(
            SaltlickError::SecretKeyNotFound,
            decrypter.update_to_vec(&ciphertext[..]).await.unwrap_err()
        );
    }

    lazy_static! {
        static ref ASYNC_KEYS: (PublicKey, SecretKey) = key::gen_keypair();
    }

    async fn key_lookup(_public_key: PublicKey) -> Option<SecretKey> {
        Some(ASYNC_KEYS.1.clone())
    }

    #[tokio::test]
    async fn deferred_async_key_load_test() {
        let test_data = random_bytes(4, 25000);

        let mut encrypter = Encrypter::new(ASYNC_KEYS.0.clone());
        let ciphertext = encrypter.update_to_vec(&test_data[..], true).unwrap();

        let mut decrypter = AsyncDecrypter::new_deferred_async(key_lookup);
        let plaintext = decrypter.update_to_vec(&ciphertext[..]).await.unwrap();
        assert!(decrypter.is_finalized());
        assert_eq!(test_data, plaintext.into_boxed_slice());
    }

    async fn key_lookup_failure(_public_key: PublicKey) -> Option<SecretKey> {
        None
    }

    #[tokio::test]
    async fn deferred_async_key_load_failure_test() {
        let test_data = random_bytes(4, 25000);

        let mut encrypter = Encrypter::new(ASYNC_KEYS.0.clone());
        let ciphertext = encrypter.update_to_vec(&test_data[..], true).unwrap();

        let mut decrypter = AsyncDecrypter::new_deferred_async(key_lookup_failure);
        assert_eq!(
            SaltlickError::SecretKeyNotFound,
            decrypter.update_to_vec(&ciphertext[..]).await.unwrap_err()
        );
    }
}
