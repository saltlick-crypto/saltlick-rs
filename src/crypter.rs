// Copyright (c) 2019, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Low-level API for saltlick stream operations.
//!
//! # Example
//!
//! ```
//! use saltlick::crypter::{Decrypter, Encrypter};
//!
//! let test_data = vec![vec![1, 2, 3], vec![4, 5, 6]];
//!
//! let (public, secret) = saltlick::gen_keypair();
//!
//! // Data is fed into the encrypter. Chunking into blocks is handled
//! // automatically.
//! let mut encrypter = Encrypter::new(public.clone());
//! let mut ciphertext = Vec::new();
//! for block in test_data.iter() {
//!     let encrypted_block = encrypter.update_to_vec(block, false).unwrap();
//!     ciphertext.extend(encrypted_block);
//! }
//!
//! // Once all data is written, the encrypter must be finalized. After
//! // this trying to add more data will result in an error. If the encryption
//! // stream is not finalized, decryption will fail as incomplete.
//! let final_block = encrypter.update_to_vec(&[] as &[u8], true).unwrap();
//! ciphertext.extend(final_block);
//!
//! // Decryption is the opposite of encrypting - feed chunks of ciphertext to
//! // the decrypter until `Decrypter::is_finalized` returns true (or just give
//! // the decrypter the full data set like we do here).
//! let mut decrypter = Decrypter::new(public, secret);
//! let plaintext = decrypter.update_to_vec(&ciphertext[..]).unwrap();
//! assert!(decrypter.is_finalized());
//! assert_eq!(
//!     test_data.into_iter().flatten().collect::<Vec<u8>>(),
//!     plaintext
//! );
//! ```

use self::read::ReadStatus;
use crate::{
    error::SaltlickError,
    key::{PublicKey, SecretKey},
    state::{self, StateMachine},
    version::Version,
};
use byteorder::{ByteOrder, NetworkEndian};
use bytes::{Buf, BytesMut};
use crypto_box::aead::OsRng;
use crypto_secretstream::{Header, Key, PullStream, Stream, Tag};
use std::{cmp, fmt, io::Write, mem};

#[cfg(feature = "io-async")]
pub use crate::async_::crypter::*;

/// Minimum block size allowed - values smaller than this will automatically be
/// coerced up to this value.
pub const MIN_BLOCK_SIZE: usize = 1024;

/// Maximum block size allowed - values larger than this will automatically be
/// coerced down to this value.
pub const MAX_BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// Default block size.
pub const DEFAULT_BLOCK_SIZE: usize = 512 * 1024;

const MAGIC: &[u8] = b"SALTLICK";
const MAGIC_LEN: usize = 8;
const MESSAGE_LEN_LEN: usize = Stream::ABYTES + mem::size_of::<u32>();

#[derive(strum_macros::AsRefStr)]
pub(crate) enum EncrypterState {
    Start,
    FlushOutput(PushStream),
    NextBlock(PushStream),
    GenBlock(PushStream, bool),
    Finalized,
    Errored,
}

impl fmt::Debug for EncrypterState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

// Each encrypted block is made up of an encrypted size field of fixed size,
// followed by an encrypted block with a decrypted length matching the value of
// the preceding size. This struct is a convenience for handling writing out
// both parts.
#[derive(Debug)]
struct EncryptedBlock {
    data: Vec<u8>,
    data_pos: usize,
    length: Vec<u8>,
    length_pos: usize,
}

impl EncryptedBlock {
    pub fn has_remaining(&self) -> bool {
        (self.data.len() - self.data_pos > 0) || (self.length.len() - self.length_pos > 0)
    }

    pub fn clear(&mut self) {
        self.data.clear();
        self.data_pos = 0;
        self.length.clear();
        self.length_pos = 0;
    }

    pub fn write(&mut self, mut buf: &mut [u8]) -> usize {
        let mut nwritten = 0;
        while self.has_remaining() && !buf.is_empty() {
            let size_len = self.length.len() - self.length_pos;
            if size_len > 0 {
                let end = self.length_pos + cmp::min(size_len, buf.len());
                let n = buf
                    .write(&self.length[self.length_pos..end])
                    .expect("write to slice is infallible");
                self.length_pos += n;
                nwritten += n;
                continue;
            }

            let end = self.data_pos + cmp::min(self.data.len() - self.data_pos, buf.len());
            let n = buf
                .write(&self.data[self.data_pos..end])
                .expect("write to slice is infallible");
            self.data_pos += n;
            nwritten += n;
        }

        nwritten
    }
}

/// Low-level interface to encrypting data in the saltlick format.
#[derive(Debug)]
pub struct Encrypter {
    block_size: usize,
    enc_block: EncryptedBlock,
    plaintext: BytesMut,
    public_key: PublicKey,
    state: Option<EncrypterState>,
}

impl Encrypter {
    /// Create a new encrypter using the provided public key.
    pub fn new(public_key: PublicKey) -> Encrypter {
        Encrypter {
            block_size: DEFAULT_BLOCK_SIZE,
            enc_block: EncryptedBlock {
                data: Vec::new(),
                data_pos: 0,
                length: Vec::new(),
                length_pos: 0,
            },
            plaintext: BytesMut::new(),
            public_key,
            state: Some(EncrypterState::Start),
        }
    }

    /// Set block size for encrypter.
    pub fn set_block_size(&mut self, block_size: usize) {
        let block_size = cmp::max(MIN_BLOCK_SIZE, cmp::min(block_size, MAX_BLOCK_SIZE));
        self.block_size = block_size;
    }

    /// Update encrypter with plaintext input, receiving encrypted ciphertext
    /// as output.
    ///
    /// Update encrypter with plaintext `input`, receiving encrypted ciphertext
    /// in `output`. Returns a tuple of bytes read / bytes written.
    pub fn update(
        &mut self,
        mut input: &[u8],
        mut output: &mut [u8],
        finalize: bool,
    ) -> Result<(usize, usize), SaltlickError> {
        use self::EncrypterState::*;
        let mut nread = 0;
        let mut nwritten = 0;
        state::turn(self, |next, self_| match next {
            Start => {
                let stream = self_.start()?;
                state::next(FlushOutput(stream))
            }
            FlushOutput(stream) => {
                if self_.enc_block.has_remaining() && output.is_empty() {
                    state::ret((nread, nwritten), FlushOutput(stream))
                } else if self_.enc_block.has_remaining() {
                    let n = self_.enc_block.write(output);
                    advance_slice_mut(&mut output, n);
                    nwritten += n;
                    state::next(FlushOutput(stream))
                } else {
                    self_.enc_block.clear();
                    state::next(NextBlock(stream))
                }
            }
            NextBlock(stream) => {
                if self_.plaintext.len() >= self_.block_size {
                    state::next(GenBlock(stream, false))
                } else if !input.is_empty() {
                    let take = cmp::min(input.len(), self_.block_size - self_.plaintext.len());
                    self_.plaintext.extend_from_slice(&input[..take]);
                    advance_slice(&mut input, take);
                    nread += take;
                    state::next(NextBlock(stream))
                } else if finalize && !stream.is_finalized() {
                    state::next(GenBlock(stream, true))
                } else if finalize {
                    state::ret((nread, nwritten), Finalized)
                } else {
                    state::ret((nread, nwritten), FlushOutput(stream))
                }
            }
            GenBlock(mut stream, finalize) => {
                self_.gen_block(&mut stream, finalize)?;
                state::next(FlushOutput(stream))
            }
            Finalized => state::ret((nread, nwritten), Finalized),
            Errored => state::err(SaltlickError::StateMachineErrored),
        })
    }

    /// Convenience version of `update` that allocates and returns output data
    /// as a `Vec<u8>`.
    pub fn update_to_vec(
        &mut self,
        input: impl AsRef<[u8]>,
        finalize: bool,
    ) -> Result<Vec<u8>, SaltlickError> {
        let mut nwritten = 0;
        let mut input = input.as_ref();
        let mut ciphertext = vec![0u8; self.estimate_output_size(input.len())];
        loop {
            let (rd, wr) = self.update(input, &mut ciphertext[nwritten..], finalize)?;
            advance_slice(&mut input, rd);
            nwritten += wr;
            if self.is_finalized() || (!finalize && input.is_empty()) {
                break;
            } else {
                // This case should be very rare and only occur when there are
                // changes to the block size mid-stream.
                ciphertext.resize(
                    ciphertext.len() + self.estimate_output_size(input.len()),
                    0u8,
                );
            }
        }
        ciphertext.truncate(nwritten);
        Ok(ciphertext)
    }

    /// Returns true if the crypter has been finalized.
    pub fn is_finalized(&self) -> bool {
        matches!(self.state, Some(EncrypterState::Finalized))
    }

    fn start(&mut self) -> Result<PushStream, SaltlickError> {
        let key = Key::generate(OsRng);
        let (header, stream) = PushStream::init(&key);
        self.enc_block.clear();
        self.enc_block.data = write::header_v1(&key, &header, &self.public_key)?;
        Ok(stream)
    }

    fn gen_block(&mut self, stream: &mut PushStream, finalize: bool) -> Result<(), SaltlickError> {
        let msg = self
            .plaintext
            .split_to(cmp::min(self.plaintext.len(), self.block_size));
        self.enc_block.length.resize(4, 0u8);
        NetworkEndian::write_u32(&mut self.enc_block.length, msg.len() as u32);
        stream
            .push(&mut self.enc_block.length, &[], Tag::Message)
            .map_err(|_| SaltlickError::Finalized)?;
        let tag = if finalize { Tag::Final } else { Tag::Message };
        std::io::copy(&mut &msg[..], &mut self.enc_block.data)
            .map_err(|_| SaltlickError::EncryptionFailure)?;
        stream
            .push(&mut self.enc_block.data, &[], tag)
            .map_err(|_| SaltlickError::Finalized)?;
        Ok(())
    }

    fn estimate_output_size(&self, input_len: usize) -> usize {
        let nblocks = input_len / self.block_size + 2;
        nblocks * (self.block_size + MESSAGE_LEN_LEN + Stream::ABYTES)
    }
}

impl StateMachine for Encrypter {
    type State = EncrypterState;
    type Return = (usize, usize);
    type Error = SaltlickError;

    fn take_state(&mut self) -> Self::State {
        if let Some(inner) = self.state.take() {
            inner
        } else {
            EncrypterState::Errored
        }
    }

    fn put_state(&mut self, state: Self::State) {
        self.state = Some(state);
    }
}

type KeyLookupFn = Box<dyn FnOnce(&PublicKey) -> Option<SecretKey>>;

#[derive(strum_macros::AsRefStr)]
enum KeyResolution {
    Available(PublicKey, SecretKey),
    Deferred(KeyLookupFn),
}

impl fmt::Debug for KeyResolution {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

/// Wrapper around crypto_secretstream::PushStream that observes Tag::Final
pub(crate) struct PushStream {
    inner: crypto_secretstream::PushStream,
    finalized: bool,
}

impl PushStream {
    pub fn init(key: &Key) -> (Header, Self) {
        let (header, inner) = crypto_secretstream::PushStream::init(OsRng, key);
        let finalized = false;

        (header, Self { inner, finalized })
    }

    pub fn push(
        &mut self,
        buffer: &mut impl crypto_secretstream::aead::Buffer,
        associated_data: &[u8],
        tag: Tag,
    ) -> crypto_secretstream::aead::Result<()> {
        if let Tag::Final = tag {
            self.finalized = true;
        }
        self.inner.push(buffer, associated_data, tag)
    }

    pub fn is_finalized(&self) -> bool {
        self.finalized
    }
}

#[derive(strum_macros::AsRefStr)]
pub(crate) enum DecrypterState {
    ReadPreheader,
    ReadPublicKey,
    SecretKeyLookup(PublicKey),
    ReadHeader(PublicKey, SecretKey),
    OpenStream(Key, Header),
    ReadLength(PullStream),
    ReadBlock(PullStream, usize),
    FlushOutput(PullStream, bool),
    Finalized,
    Errored,
}

impl fmt::Debug for DecrypterState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

/// Result of update call (read, written) or require secret key to make
/// progress.
pub(crate) enum UpdateReturn {
    Progress(usize, usize),
    NeedSecretKey(usize, usize, PublicKey),
}

/// Low-level interface to decrypting data in the saltlick format.
#[derive(Debug)]
pub struct Decrypter {
    inner: DecrypterInner,
    key_resolution: Option<KeyResolution>,
}

impl Decrypter {
    /// Create a new decrypter using the provided public and secret key.
    pub fn new(public_key: PublicKey, secret_key: SecretKey) -> Decrypter {
        let key = KeyResolution::Available(public_key, secret_key);
        Decrypter {
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
    pub fn new_deferred<F>(lookup_fn: F) -> Decrypter
    where
        F: FnOnce(&PublicKey) -> Option<SecretKey> + 'static,
    {
        let key = KeyResolution::Deferred(Box::new(lookup_fn));
        Decrypter {
            inner: DecrypterInner::default(),
            key_resolution: Some(key),
        }
    }

    /// Update decrypter with ciphertext input, receiving decrypted plaintext
    /// as output.
    ///
    /// Update decrypter with ciphertext `input`, receiving decrypted plaintext
    /// as `output`. Returns a tuple of bytes read / bytes written.
    pub fn update(
        &mut self,
        mut input: &[u8],
        mut output: &mut [u8],
    ) -> Result<(usize, usize), SaltlickError> {
        match self.inner.update(input, output, None)? {
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
                    None => Err(SaltlickError::SecretKeyNotFound),
                }?;
                advance_slice(&mut input, nread);
                advance_slice_mut(&mut output, nwritten);
                match self.inner.update(input, output, Some(secret))? {
                    UpdateReturn::Progress(read, written) => Ok((nread + read, nwritten + written)),
                    UpdateReturn::NeedSecretKey(_, _, _) => unreachable!(),
                }
            }
        }
    }

    /// Convenience version of `update` that allocates and returns output data
    /// as a `Vec<u8>`.
    pub fn update_to_vec(&mut self, input: impl AsRef<[u8]>) -> Result<Vec<u8>, SaltlickError> {
        let input = input.as_ref();
        let mut plaintext = vec![0u8; self.inner.estimate_output_size(input.len())];
        let (rd, wr) = self.update(input, &mut plaintext)?;

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

/// Inner decryption state machine.
///
/// The inner logic that performs stream decryption in a non-blocking fashion -
/// this type will always return as soon as all available data has been
/// processed. Wrapper types make use of this inner type to provide unique
/// key-lookup implementations.
#[derive(Debug)]
pub(crate) struct DecrypterInner {
    ciphertext: BytesMut,
    consumed: usize,
    last_block_size: Option<usize>,
    plaintext: Vec<u8>,
    state: Option<DecrypterState>,
}

impl DecrypterInner {
    pub fn update(
        &mut self,
        mut input: &[u8],
        mut output: &mut [u8],
        secret_key: Option<SecretKey>,
    ) -> Result<UpdateReturn, SaltlickError> {
        use self::DecrypterState::*;
        let mut nread = 0;
        let mut nwritten = 0;
        use UpdateReturn::{NeedSecretKey, Progress};
        state::turn(self, |next, self_| match next {
            ReadPreheader => match read::preheader(&self_.ciphertext)? {
                ReadStatus::Complete(version, n) => {
                    self_.ciphertext.advance(n);
                    if version != Version::V1 {
                        state::err(SaltlickError::UnsupportedVersion)
                    } else {
                        state::next(ReadPublicKey)
                    }
                }
                ReadStatus::Incomplete(_needed) if input.is_empty() => {
                    state::ret(Progress(nread, nwritten), ReadPreheader)
                }
                ReadStatus::Incomplete(needed) => {
                    let take = cmp::min(needed, input.len());
                    self_.ciphertext.extend_from_slice(&input[..take]);
                    advance_slice(&mut input, take);
                    nread += take;
                    state::next(ReadPreheader)
                }
            },
            ReadPublicKey => match read::header_v1_public_key(&self_.ciphertext)? {
                ReadStatus::Complete(file_public_key, n) => {
                    self_.ciphertext.advance(n);
                    state::ret(
                        NeedSecretKey(nread, nwritten, file_public_key.clone()),
                        SecretKeyLookup(file_public_key),
                    )
                }
                ReadStatus::Incomplete(_needed) if input.is_empty() => {
                    state::ret(Progress(nread, nwritten), ReadPublicKey)
                }
                ReadStatus::Incomplete(needed) => {
                    let take = cmp::min(needed, input.len());
                    self_.ciphertext.extend_from_slice(&input[..take]);
                    advance_slice(&mut input, take);
                    nread += take;
                    state::next(ReadPublicKey)
                }
            },
            SecretKeyLookup(file_public_key) => {
                if let Some(secret) = secret_key.clone() {
                    state::next(ReadHeader(file_public_key, secret))
                } else {
                    state::err(SaltlickError::SecretKeyNotFound)
                }
            }
            ReadHeader(public_key, secret_key) => {
                match read::header_v1_sealed_text(&self_.ciphertext, &public_key, &secret_key)? {
                    ReadStatus::Complete((key, header), n) => {
                        self_.ciphertext.advance(n);
                        state::next(OpenStream(key, header))
                    }
                    ReadStatus::Incomplete(_needed) if input.is_empty() => state::ret(
                        Progress(nread, nwritten),
                        ReadHeader(public_key, secret_key),
                    ),
                    ReadStatus::Incomplete(needed) => {
                        let take = cmp::min(needed, input.len());
                        self_.ciphertext.extend_from_slice(&input[..take]);
                        advance_slice(&mut input, take);
                        nread += take;
                        state::next(ReadHeader(public_key, secret_key))
                    }
                }
            }
            OpenStream(key, header) => state::next(ReadLength(PullStream::init(header, &key))),
            ReadLength(mut stream) => match read::length(&self_.ciphertext, &mut stream)? {
                ReadStatus::Complete(length, n) => {
                    self_.ciphertext.advance(n);
                    self_.last_block_size = Some(length);
                    state::next(ReadBlock(stream, length))
                }
                ReadStatus::Incomplete(_needed) if input.is_empty() => {
                    state::ret(Progress(nread, nwritten), ReadLength(stream))
                }
                ReadStatus::Incomplete(needed) => {
                    let take = cmp::min(needed, input.len());
                    self_.ciphertext.extend_from_slice(&input[..take]);
                    advance_slice(&mut input, take);
                    nread += take;
                    state::next(ReadLength(stream))
                }
            },
            ReadBlock(mut stream, length) => {
                match read::block(&self_.ciphertext, &mut self_.plaintext, &mut stream, length)? {
                    ReadStatus::Complete(finalized, n) => {
                        self_.ciphertext.advance(n);
                        self_.consumed = 0;
                        state::next(FlushOutput(stream, finalized))
                    }
                    ReadStatus::Incomplete(_needed) if input.is_empty() => {
                        state::ret(Progress(nread, nwritten), ReadBlock(stream, length))
                    }
                    ReadStatus::Incomplete(needed) => {
                        let take = cmp::min(needed, input.len());
                        self_.ciphertext.extend_from_slice(&input[..take]);
                        advance_slice(&mut input, take);
                        nread += take;
                        state::next(ReadBlock(stream, length))
                    }
                }
            }
            FlushOutput(stream, finalized) => {
                if self_.plaintext_len() == 0 {
                    if finalized {
                        state::next(Finalized)
                    } else {
                        state::next(ReadLength(stream))
                    }
                } else if output.is_empty() {
                    state::ret(Progress(nread, nwritten), FlushOutput(stream, finalized))
                } else {
                    let take = cmp::min(output.len(), self_.plaintext_len());
                    let n = output
                        .write(&self_.plaintext[self_.consumed..(self_.consumed + take)])
                        .expect("write to slice is infallible");
                    nwritten += n;
                    self_.consumed += n;
                    state::next(FlushOutput(stream, finalized))
                }
            }
            Finalized => state::ret(Progress(nread, nwritten), Finalized),
            Errored => state::err(SaltlickError::StateMachineErrored),
        })
    }

    pub fn is_finalized(&self) -> bool {
        matches!(self.state, Some(DecrypterState::Finalized))
    }

    pub fn estimate_output_size(&self, input_len: usize) -> usize {
        input_len + (2 * self.last_block_size.unwrap_or(DEFAULT_BLOCK_SIZE))
    }

    fn plaintext_len(&self) -> usize {
        self.plaintext.len() - self.consumed
    }
}

impl Default for DecrypterInner {
    fn default() -> DecrypterInner {
        DecrypterInner {
            ciphertext: BytesMut::new(),
            consumed: 0,
            last_block_size: None,
            plaintext: Vec::new(),
            state: Some(DecrypterState::ReadPreheader),
        }
    }
}

impl StateMachine for DecrypterInner {
    type State = DecrypterState;
    type Return = UpdateReturn;
    type Error = SaltlickError;

    fn take_state(&mut self) -> Self::State {
        if let Some(inner) = self.state.take() {
            inner
        } else {
            DecrypterState::Errored
        }
    }

    fn put_state(&mut self, state: Self::State) {
        self.state = Some(state);
    }
}

// Helper functions that mutate a reference to a slice, allowing us to
// effectively ignore input data that we've already read and output data that
// we've already written. This is safe because a slice is always a reference to
// some other data - all we're doing is updating the pointer so it points to a
// new subset of that same data.
pub(crate) fn advance_slice<T>(slice: &mut &[T], n: usize) {
    let (_a, b) = std::mem::take(slice).split_at(n);
    *slice = b;
}

pub(crate) fn advance_slice_mut<T>(slice: &mut &mut [T], n: usize) {
    let (_a, b) = std::mem::take(slice).split_at_mut(n);
    *slice = b;
}

mod read {
    use super::{
        PublicKey, PullStream, SaltlickError, SecretKey, Version, MAGIC, MAGIC_LEN, MESSAGE_LEN_LEN,
    };
    use byteorder::{ByteOrder, NetworkEndian};
    use crypto_box::{KEY_SIZE as PUBLICKEYBYTES, SEALBYTES};
    use crypto_secretstream::{Header, Key, Stream, Tag};
    use std::{convert::TryFrom, mem};

    const ABYTES: usize = Stream::ABYTES;
    const HEADERBYTES: usize = Header::BYTES;
    const KEYBYTES: usize = Key::BYTES;
    const PREHEADER_LEN: usize = MAGIC_LEN + mem::size_of::<u8>();
    const SEALEDTEXT_LEN: usize = KEYBYTES + HEADERBYTES + SEALBYTES;

    pub enum ReadStatus<T> {
        Incomplete(usize),
        Complete(T, usize),
    }

    pub fn preheader(input: &[u8]) -> Result<ReadStatus<Version>, SaltlickError> {
        if input.len() < PREHEADER_LEN {
            return Ok(ReadStatus::Incomplete(PREHEADER_LEN - input.len()));
        }
        if &input[..MAGIC.len()] != MAGIC {
            return Err(SaltlickError::BadMagic);
        }
        let version = Version::from_u8(input[MAGIC.len()]);

        Ok(ReadStatus::Complete(version, PREHEADER_LEN))
    }

    pub fn header_v1_public_key(input: &[u8]) -> Result<ReadStatus<PublicKey>, SaltlickError> {
        if input.len() < PUBLICKEYBYTES {
            return Ok(ReadStatus::Incomplete(PUBLICKEYBYTES - input.len()));
        }
        let public_key = PublicKey::from_raw_curve25519(&input[..PUBLICKEYBYTES])?;
        Ok(ReadStatus::Complete(public_key, PUBLICKEYBYTES))
    }

    pub fn header_v1_sealed_text(
        input: &[u8],
        _public_key: &PublicKey,
        secret_key: &SecretKey,
    ) -> Result<ReadStatus<(Key, Header)>, SaltlickError> {
        if input.len() < SEALEDTEXT_LEN {
            return Ok(ReadStatus::Incomplete(SEALEDTEXT_LEN - input.len()));
        }
        let sealed_text = &input[..SEALEDTEXT_LEN];
        let plaintext = secret_key
            .inner
            .unseal(sealed_text)
            .map_err(|_| SaltlickError::DecryptionFailure)?;
        let symmetric_key =
            Key::try_from(&plaintext[..KEYBYTES]).map_err(|_| SaltlickError::DecryptionFailure)?;
        let stream_header = Header::try_from(&plaintext[KEYBYTES..(KEYBYTES + HEADERBYTES)])
            .map_err(|_| SaltlickError::DecryptionFailure)?;
        Ok(ReadStatus::Complete(
            (symmetric_key, stream_header),
            SEALEDTEXT_LEN,
        ))
    }

    pub fn length(
        input: &[u8],
        stream: &mut PullStream,
    ) -> Result<ReadStatus<usize>, SaltlickError> {
        if input.len() < MESSAGE_LEN_LEN {
            return Ok(ReadStatus::Incomplete(MESSAGE_LEN_LEN - input.len()));
        }
        let mut plaintext = Vec::from(&input[..MESSAGE_LEN_LEN]);
        let tag = stream
            .pull(&mut plaintext, &[])
            .map_err(|_| SaltlickError::DecryptionFailure)?;
        if tag != Tag::Message {
            // A length block should never be the end of the stream
            return Err(SaltlickError::DecryptionFailure);
        }
        Ok(ReadStatus::Complete(
            NetworkEndian::read_u32(&plaintext) as usize,
            MESSAGE_LEN_LEN,
        ))
    }

    pub fn block(
        input: &[u8],
        output: &mut Vec<u8>,
        stream: &mut PullStream,
        message_length: usize,
    ) -> Result<ReadStatus<bool>, SaltlickError> {
        let block_len = message_length + ABYTES;
        if input.len() < block_len {
            return Ok(ReadStatus::Incomplete(block_len - input.len()));
        }
        output.clear();
        output.reserve(input.len());
        std::io::copy(&mut &input[..], output).map_err(|_| SaltlickError::DecryptionFailure)?;
        let tag = stream
            .pull(output, &[])
            .map_err(|_| SaltlickError::DecryptionFailure)?;
        match tag {
            Tag::Message if message_length == 0 => {
                // The only message allowed to be zero-length is the final
                // message.
                Err(SaltlickError::DecryptionFailure)
            }
            Tag::Message => Ok(ReadStatus::Complete(false, block_len)),
            Tag::Final => Ok(ReadStatus::Complete(true, block_len)),
            Tag::Push | Tag::Rekey => Err(SaltlickError::DecryptionFailure),
        }
    }
}

mod write {
    use crate::SaltlickError;

    use super::{PublicKey, Version, MAGIC};
    use crypto_secretstream::{aead::OsRng, Header, Key};

    pub fn preheader(version: Version) -> Vec<u8> {
        let mut header = Vec::from(MAGIC);
        header.push(version.to_u8());
        header
    }

    pub fn header_v1(
        symmetric_key: &Key,
        stream_header: &Header,
        public_key: &PublicKey,
    ) -> Result<Vec<u8>, SaltlickError> {
        let mut to_encrypt = Vec::new();
        to_encrypt.extend_from_slice(symmetric_key.as_ref());
        to_encrypt.extend_from_slice(stream_header.as_ref());

        let mut header = preheader(Version::V1);
        header.extend_from_slice(public_key.inner.as_bytes());
        let sealedbox = public_key
            .inner
            .seal(&mut OsRng, &to_encrypt)
            .map_err(|_| SaltlickError::EncryptionFailure)?;
        header.extend(sealedbox);
        Ok(header)
    }
}

#[cfg(test)]
mod testutils {
    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    pub fn random_bytes(seed: u64, size: usize) -> Vec<u8> {
        let mut rng = XorShiftRng::seed_from_u64(seed);
        let mut bytes = vec![0u8; size];
        rng.fill_bytes(&mut bytes);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::{testutils::random_bytes, Decrypter, Encrypter, KeyResolution};
    use crate::{error::SaltlickError, key};

    #[test]
    fn simple_test() {
        let test_data = vec![
            random_bytes(0, 567),
            random_bytes(1, 1337),
            random_bytes(2, 16742),
        ];
        let (public, secret) = key::gen_keypair();

        let mut encrypter = Encrypter::new(public.clone());
        let mut ciphertext = Vec::new();
        encrypter.set_block_size(1024);
        for block in test_data.iter() {
            ciphertext.extend(encrypter.update_to_vec(block, false).unwrap())
        }
        ciphertext.extend(encrypter.update_to_vec(&[] as &[u8], true).unwrap());

        let mut decrypter = Decrypter::new(public, secret);
        let plaintext = decrypter.update_to_vec(&ciphertext[..]).unwrap();
        assert!(decrypter.is_finalized());
        assert_eq!(
            test_data.into_iter().flatten().collect::<Vec<u8>>(),
            plaintext,
        );
    }

    #[test]
    fn one_byte_at_a_time_test() {
        let test_data = random_bytes(3, 25000);
        let (public, secret) = key::gen_keypair();

        let mut encrypter = Encrypter::new(public.clone());
        let mut ciphertext = Vec::new();
        encrypter.set_block_size(1024);
        for byte in test_data.iter().copied() {
            ciphertext.extend(encrypter.update_to_vec([byte], false).unwrap());
        }
        ciphertext.extend(encrypter.update_to_vec(&[] as &[u8], true).unwrap());

        let mut decrypter = Decrypter::new(public, secret);
        let mut plaintext = Vec::new();
        let mut buffer = vec![0u8; 512];
        for byte in ciphertext {
            let (rd, wr) = decrypter.update(&[byte], &mut buffer[..]).unwrap();
            plaintext.extend(&buffer[..wr]);
            assert_eq!(1, rd);
        }
        assert!(decrypter.is_finalized());
        assert_eq!(test_data, plaintext);
    }

    #[test]
    fn deferred_key_load_test() {
        let test_data = random_bytes(4, 25000);
        let (public, secret) = key::gen_keypair();
        let mut encrypter = Encrypter::new(public);
        let ciphertext = encrypter.update_to_vec(&test_data[..], true).unwrap();

        let mut decrypter = Decrypter::new_deferred(move |_public| Some(secret));
        let plaintext = decrypter.update_to_vec(&ciphertext[..]).unwrap();
        assert!(decrypter.is_finalized());
        assert_eq!(test_data, plaintext);
    }

    #[test]
    fn deferred_key_load_failure_test() {
        let test_data = random_bytes(5, 25000);
        let (public, _secret) = key::gen_keypair();

        let mut encrypter = Encrypter::new(public);
        let ciphertext = encrypter.update_to_vec(&test_data[..], true).unwrap();

        let mut decrypter = Decrypter::new_deferred(move |_public| None);
        assert_eq!(
            SaltlickError::SecretKeyNotFound,
            decrypter.update_to_vec(&ciphertext[..]).unwrap_err()
        );
    }

    #[test]
    fn wrong_public_key_test() {
        let test_data = random_bytes(6, 1024);
        let (public, _secret) = key::gen_keypair();
        let (other_public, other_secret) = key::gen_keypair();

        let mut encrypter = Encrypter::new(public);
        let ciphertext = encrypter.update_to_vec(&test_data[..], true).unwrap();

        let mut decrypter = Decrypter::new(other_public, other_secret);
        assert_eq!(
            SaltlickError::PublicKeyMismatch,
            decrypter.update_to_vec(&ciphertext[..]).unwrap_err(),
        );
    }

    #[test]
    fn bad_magic() {
        let test_data = random_bytes(7, 1024);
        let (public, secret) = key::gen_keypair();

        let mut encrypter = Encrypter::new(public.clone());
        let mut ciphertext = encrypter.update_to_vec(&test_data[..], true).unwrap();

        // Corrupt the magic
        ciphertext[0..8].copy_from_slice(&b"PEPRLICK"[..]);
        let mut decrypter = Decrypter::new(public, secret);
        assert_eq!(
            SaltlickError::BadMagic,
            decrypter.update_to_vec(&ciphertext[..]).unwrap_err(),
        );
    }

    #[test]
    fn unsupported_version() {
        let (public, secret) = key::gen_keypair();
        let unsupported_version = b"SALTLICK\0";
        let mut decrypter = Decrypter::new(public, secret);
        assert_eq!(
            SaltlickError::UnsupportedVersion,
            decrypter
                .update_to_vec(&unsupported_version[..])
                .unwrap_err()
        );
    }

    #[test]
    fn update_after_error_test() {
        let (public, secret) = key::gen_keypair();
        let unsupported_version = b"SALTLICK\0";
        let mut decrypter = Decrypter::new(public, secret);
        // Cause an error (unsupported version)
        decrypter
            .update_to_vec(&unsupported_version[..])
            .unwrap_err();
        // Trying to update again should return `StateMachineErrored`
        assert_eq!(
            SaltlickError::StateMachineErrored,
            decrypter.update_to_vec([]).unwrap_err(),
        );
    }

    #[test]
    fn update_after_finalized_test() {
        let (public, _secret) = key::gen_keypair();
        let mut encrypter = Encrypter::new(public);
        let _ = encrypter.update_to_vec(b"Hello there", true).unwrap();
        assert!(encrypter.is_finalized());
        let _ = encrypter.update_to_vec(b"Are you finished?", true).unwrap();
        assert!(encrypter.is_finalized());
    }

    #[test]
    fn update_to_vec_encrypter_resize_test() {
        let test_data = random_bytes(8, 512 * 1024);
        let (public, secret) = key::gen_keypair();

        let mut encrypter = Encrypter::new(public.clone());

        // set a large block size so the encrypter buffers input data
        encrypter.set_block_size(8 * 1024 * 1024);

        // write input data, it should all be buffered
        let ciphertext1 = encrypter.update_to_vec(&test_data[..], false).unwrap();

        // now make the block size really small, causing the buffer size
        // estimate to be wrong
        encrypter.set_block_size(1024);
        let ciphertext2 = encrypter.update_to_vec(&test_data[..], true).unwrap();

        // make sure that everything still decrypts properly
        let mut expected = Vec::from(&test_data[..]);
        expected.extend(&test_data[..]);
        let mut ciphertext = ciphertext1;
        ciphertext.extend(ciphertext2);

        let mut decrypter = Decrypter::new(public, secret);
        let plaintext = decrypter.update_to_vec(&ciphertext[..]).unwrap();
        assert!(decrypter.is_finalized());
        assert_eq!(expected, plaintext);
    }

    #[test]
    fn debug_impl_test() {
        let (public, secret) = key::gen_keypair();
        let decrypter = Decrypter::new(public.clone(), secret.clone());
        let encrypter = Encrypter::new(public.clone());
        let key_resolution = KeyResolution::Available(public, secret);

        let _ = format!("{:?}", decrypter);
        let _ = format!("{:?}", encrypter);
        let _ = format!("{:?}", key_resolution);
    }
}

#[cfg(test)]
#[cfg(feature = "proptest-tests")]
mod proptest_tests {
    use super::{testutils::random_bytes, Decrypter, Encrypter};
    use crate::key::{self, PublicKey, SecretKey};
    use proptest::prelude::*;
    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::{cmp, usize};

    const MAX_DATA: usize = 1024 * 1024;

    // Random bytes with "chunks" specifications for each step of the process.
    // The chunks are lists of `usize` variables with each element describing
    // the number of bytes to take. The chunk lists are put into a cycle so
    // they are effectively infinite, but return a different sized slice on
    // each iteration. This is to simulate a real-world situation where data
    // may be coming in at varying rates. The chunks described are:
    //
    //   * `encrypter_input_chunks` - input to encrypter from the plaintext data
    //   * `encrypter_output_chunks` - output buffer size from encrypter to encrypted data
    //   * `decrypter_input_chunks` - input to decrypter from the encrypted data
    //   * `decrypter_output_chunks` - output buffer size from decrypter
    #[derive(Debug)]
    struct TestData {
        data: Box<[u8]>,
        encrypter_input_chunks: Vec<usize>,
        encrypter_output_chunks: Vec<usize>,
        decrypter_input_chunks: Vec<usize>,
        decrypter_output_chunks: Vec<usize>,
    }

    fn round_trip(
        public_key: PublicKey,
        secret_key: SecretKey,
        td: TestData,
    ) -> (TestData, Vec<u8>) {
        let mut encrypter = Encrypter::new(public_key.clone());
        let mut decrypter = Decrypter::new(public_key, secret_key);
        let mut encrypted = Vec::with_capacity(td.data.len() * 2);
        let mut decrypted = Vec::with_capacity(td.data.len());
        let mut encrypter_nread = 0;
        let mut encrypter_nwritten = 0;
        let mut decrypter_nread = 0;

        let max_buffer = td
            .encrypter_output_chunks
            .iter()
            .chain(td.decrypter_output_chunks.iter())
            .max()
            .unwrap();
        let mut buffer = vec![0u8; *max_buffer];

        let chunk_iter = td
            .encrypter_input_chunks
            .iter()
            .copied()
            .cycle()
            .zip(td.encrypter_output_chunks.iter().copied().cycle())
            .zip(td.decrypter_input_chunks.iter().copied().cycle())
            .zip(td.decrypter_output_chunks.iter().copied().cycle())
            .map(|(((a, b), c), d)| (a, b, c, d));

        for (encrypt_in, encrypt_out, decrypt_in, decrypt_out) in chunk_iter {
            if encrypter.is_finalized() && decrypter.is_finalized() {
                break;
            }

            if !encrypter.is_finalized() {
                let take = cmp::min(td.data[encrypter_nread..].len(), encrypt_in);
                let finish = encrypter_nread >= td.data.len();
                let (rd, wr) = encrypter
                    .update(
                        &td.data[encrypter_nread..(encrypter_nread + take)],
                        &mut buffer[..encrypt_out],
                        finish,
                    )
                    .unwrap();
                encrypter_nread += rd;
                encrypter_nwritten += wr;
                encrypted.extend(&buffer[..wr]);
            }

            let take = cmp::min(
                encrypted[decrypter_nread..encrypter_nwritten].len(),
                decrypt_in,
            );
            let (rd, wr) = decrypter
                .update(
                    &encrypted[decrypter_nread..(decrypter_nread + take)],
                    &mut buffer[..decrypt_out],
                )
                .unwrap();
            decrypter_nread += rd;
            decrypted.extend(&buffer[..wr]);
        }

        (td, decrypted)
    }

    // Creates arbitrary chunk descriptions with values between min_value and
    // max_value, inclusive.
    fn arb_chunks(
        min_value: usize,
        max_value: usize,
        max_count: usize,
    ) -> impl Strategy<Value = Vec<usize>> {
        proptest::collection::vec(min_value..=max_value, 1..=max_count)
    }

    // Create arbitrary test data - both in terms of random input bytes as well
    // as random chunk sizes to read/write.
    prop_compose! {
        fn arb_test_data(max_count: usize)
            (data_len in 1..MAX_DATA)
            (
                data_len in Just(data_len),
                seed in any::<u64>().no_shrink(),
                encrypter_input_chunks in arb_chunks(1, data_len * 2, max_count),
                encrypter_output_chunks in arb_chunks(1, data_len * 2, max_count),
                decrypter_input_chunks in arb_chunks(1, data_len * 2, max_count),
                decrypter_output_chunks in arb_chunks(1, data_len * 2, max_count),
            )
            -> TestData
        {
            let data = random_bytes(seed, data_len).into_boxed_slice();
            TestData {
                data,
                encrypter_input_chunks,
                encrypter_output_chunks,
                decrypter_input_chunks,
                decrypter_output_chunks,
            }
        }
    }

    #[test]
    fn round_trip_proptest() {
        let (public, secret) = key::gen_keypair();
        proptest!(move |(test_data in arb_test_data(50))| {
            let (test_data, result) = round_trip(
                public.clone(),
                secret.clone(),
                test_data,
            );
            prop_assert_eq!(&test_data.data[..], &result[..]);
        });
    }

    proptest! {
        #[test]
        fn encrypter_fuzz_test(
            seed in any::<u64>().no_shrink(),
            chunks in proptest::collection::vec(1usize..=1024, 1..=1024),
        ) {
            let (public, _) = key::gen_keypair();
            let mut rng = XorShiftRng::seed_from_u64(seed);
            let mut data = vec![0u8; 1024];
            let mut encrypter = Encrypter::new(public);
            for chunk in chunks {
                rng.fill_bytes(&mut data);
                let _ = encrypter.update_to_vec(&data[..chunk], false).unwrap();
            }
        }

        #[test]
        fn decrypter_fuzz_test(
            seed in any::<u64>().no_shrink(),
            chunks in proptest::collection::vec(1usize..=1024, 1..=1024),
        ) {
            let (public, secret) = key::gen_keypair();
            let mut rng = XorShiftRng::seed_from_u64(seed);
            let mut data = vec![0u8; 1024];
            let mut decrypter = Decrypter::new(public, secret);
            for chunk in chunks {
                rng.fill_bytes(&mut data);
                // Just making sure that we don't panic/crash, not actually
                // checking the output is valid. We can't just blanket
                // `unwrap_err` though because the decrypter may buffer some
                // bytes and return success early on.
                let _ = decrypter.update_to_vec(&data[..chunk]);
            }
        }
    }
}
