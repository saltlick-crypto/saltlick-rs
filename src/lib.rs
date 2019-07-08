// Copyright (c) 2019, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A library for encrypting and decrypting file streams using libsodium.
//!
//! This library provides a Rust implementation of the saltlick binary file
//! format, which is itself a format for encrypting and decrypting files using
//! strong elliptic curve cryptography. See the [saltlick spec] for details
//! about the motivation and implementation of the file format itself.
//!
//! Both low-level and high-level APIs are provided. The low-level API requires
//! manually pushing chunks of data into an encrypter and receiving ciphertext,
//! or pulling plaintext from a decrypter that is fed chunks of ciphertext. The
//! current high-level API implements Rust's [`Read`] and [`Write`] traits to
//! provide a simple to use way to read and write files.
//!
//! [saltlick spec]: https://github.com/saltlick-crypto/saltlick-spec
//! [`Read`]: https://doc.rust-lang.org/std/io/trait.Read.html
//! [`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
//!
//! # Usage
//!
//! First, add this to your Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! saltlick = "0.1"
//! ```
//!
//! Next:
//!
//! ```
//! use std::error::Error;
//! use std::fs::File;
//! use std::io::{self, Cursor, Read, Write};
//!
//! use saltlick::{DecryptingReader, EncryptingWriter, SaltlickError};
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     // Generate a new public/secret keypair
//!     let (public, secret) = saltlick::gen_keypair();
//!
//!     // Writing data to a stream
//!     let writer = Vec::new();
//!     let mut stream = EncryptingWriter::new(public.clone(), writer);
//!     stream.write_all(b"I have a secret for you")?;
//!     let ciphertext = stream.finalize()?;
//!
//!     // Reading data back from stream
//!     let reader = Cursor::new(ciphertext);
//!     let mut stream = DecryptingReader::new(public.clone(), secret.clone(), reader);
//!     let mut output = String::new();
//!     stream.read_to_string(&mut output)?;
//!     assert_eq!("I have a secret for you", output);
//!
//!     // Save public and private keys as PEM format
//!     let public_pem = public.to_pem();
//!     let secret_pem = secret.to_pem();
//!
//!     Ok(())
//! }
//! ```
//!
//! # Generating Keys
//!
//! In addition to generating keys programmatically, it is possible to generate
//! compliant key files with OpenSSL 1.1.0 or newer:
//!
//! ```sh
//! openssl genpkey -algorithm x25519 > secret.pem
//! openssl pkey -in secret.key -pubout > public.pem
//! ```

pub mod crypter;

mod error;
mod key;
mod multibuf;
mod sync;
mod version;

pub use self::error::SaltlickError;
pub use self::key::{gen_keypair, PublicKey, SecretKey, PUBLICKEYBYTES, SECRETKEYBYTES};
pub use self::sync::{DecryptingReader, EncryptingWriter};
pub use self::version::Version;
