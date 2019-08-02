# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [master] - Unreleased
### Added
- Add deferred key-loading function to `Decrypter`, allowing the type to be
  constructed with a closure that later provides a secret key based on the
  public key present in a stream.

### Changed
- Change MSRV from 1.34 to 1.33

## [0.1.0] - July 22, 2019
### Added
- Initial library development

[master]: https://github.com/saltlick-crypto/saltlick-rs/compare/0.1.0...master
[0.1.0]: https://github.com/saltlick-crypto/saltlick-rs/tree/0.1.0
