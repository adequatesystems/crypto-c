# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.2] - 2020-04-15
Addresses the naive padding within hashing structs.
Moved global static vars inside associated function scopes.
Updated to `build-c-1.1.3`.

## Added
- build-c-1.1.3 CUDA compilation (revert) changes

## Changed
- Moved static "global" variables inside associated function scopes
  - due to issues with compilation units that include multiple source files

## Removed
- Alignment padding within hashing contexts
  - Such padding cannot be guarenteed by the C standard

## [1.1.1] - 2022-04-13
Update to build-c-1.1.2 for CUDA build fixes and docs config adjustments.

## [1.1.0] - 2022-04-06
CUDA source code separation.

### Added
- Separate CUDA source code files for all Cryptographic Hashing functions
- Test files for all CUDA variant Cryptographic Hashing functions

### Changed
- Upated build-c to v1.1.1

## [1.0.0] - 2022-01-26
Initial repository release.

### Added
- Cryptographic hasing functions:
  - blake2b
  - crc16
  - crc32
  - md2
  - md5
  - sha1
  - sha256
  - sha3/keccak

[Unreleased]: https://github.com/adequatesystems/crypto-c/compare/v1.1.2...HEAD
[1.1.2]: https://github.com/adequatesystems/crypto-c/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/adequatesystems/crypto-c/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/adequatesystems/crypto-c/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/adequatesystems/crypto-c/releases/tag/v1.0.0
