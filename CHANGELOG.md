# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [master] - Unreleased

- Add support for async key lookups by way of a `AsyncDecrypter` type which
  wraps the decryption state machine into a `DecrypterInner` type (with
  synchronous key lookup being done by the now-wrapper type `Decrypter`).
- Replace `Decrypter` with `AsyncDecrypter` type in `AsyncDecrypterStream` to
  support using async key lookup functions when using the decrypter stream.

## [0.3.0] - 2020-03-20
### Added
- Add `Encrypter` and `Decrypter` methods `update_to_vec`, which automatically
  allocates and fills a `Vec<u8>` for output.
- Add `with_capacity` to `SaltlickEncrypter` types and
  `with_capacity`/`deferred_with_capacity` to `SaltlickDecrypter` types to
  allow control of inner buffer sizes.
- Wrappers now exist for all permutations of encrypt/decrypt and `Read`,
  `Write`, and `BufRead`.
- Add async implementations for `AsyncRead`, `AsyncWrite`, `AsyncBufRead` and
  `Stream` data sources.

### Changed
- `Encrypter` and `Decrypter` now reuses buffers for communicating with
  libsodium through sodiumoxide, avoiding many extra allocations and removing
  the need for the `MultiBuf` helper.
- The methods `Encrypter::pull` and `Decrypter::push` are now called
  `Encrypter::update` and `Decrypter::update` and have changed function
  signatures.
- `EncryptingWriter` and `DecryptingReader` have been moved into the `write`
  and `read` modules respectively. They have been renamed `SaltlickEncrypter`
  and `SaltlickDecrypter`.

### Removed
- `MultiBuf` has been completely removed in favor of slices for input and
  output to `Encrypter`/`Decrypter` `update` functions.
- `is_not_finalized` functions have been removed from `Encrypter`/`Decrypter` -
  use `!is_finalized()` instead.

## [0.2.0] - 2020-01-16
### Added
- Add deferred key-loading function to `Decrypter`, allowing the type to be
  constructed with a closure that later provides a secret key based on the
  public key present in a stream.
- Extend deferred key-loading to `DecryptingReader`.
- Add helper functions to `PublicKey` and `SecretKey` that read/write keys
  directly to/from PEM-encoded files.

### Changed
- Change MSRV from 1.34 to 1.39 to address MSRV change in sodiumoxide (>=1.36)
  and bytes (>=1.39).

## [0.1.0] - 2019-07-22
### Added
- Initial library development

[master]: https://github.com/saltlick-crypto/saltlick-rs/compare/0.3.0...master
[0.3.0]: https://github.com/saltlick-crypto/saltlick-rs/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/saltlick-crypto/saltlick-rs/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/saltlick-crypto/saltlick-rs/tree/0.1.0
