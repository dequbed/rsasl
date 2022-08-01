# Revision history for `rsasl`

<!-- next-header -->
## [Unreleased] — ReleaseDate

### Added

- Added utilities to generate channel binding data for rustls

## [v2.0.0-alpha1] — 2022-07-30

First 'alpha' release of rsasl 2.0.0, with most of the API stabilized enough that testing if rsasl
is usable by third-party crates in other situations than BFFH is possible.

Examples of using rsasl in other crates:
- [lettre](https://github.com/dequbed/lettre/tree/rsasl-auth)

## [v2.0.0-preview1] — 2021-12-03

First preview release for the pure-Rust version. This is a full rewrite of rsasl, changing just
about every part of the code. Most of the code was transpiled using
[c2rust](https://github.com/immunant/c2rust) and then ported piece by piece to more sensible and
modern Rust.

**Big thanks to all [c2rust contributors](https://github.com/immunant/c2rust/graphs/contributors)
making this release possible.**

## [v1.4.1] — 2021-10-20

* Fixes potential bad pointer conversion on non-x86 targets

## [v1.4.0] — 2021-10-09

* Usability improvements with better type aliases

## 1.3.0 — 2021-10-02

* Improved error messages

## 1.2.0 — 2021-10-02

* `SaslError` marked `Eq` and `Ord`
* Fixes a null-pointer panic when passing invalid SaslErrors

## 1.0.0 — 2021-04-06

* Initial stabilized release

<!-- next-url -->
[Unreleased]: https://github.com/dequbed/rsasl/compare/v2.0.0-alpha1...HEAD
[v2.0.0-alpha1]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview1...v2.0.0-alpha1
[v2.0.0-preview1]: https://github.com/dequbed/rsasl/compare/v1.4.1...v2.0.0-preview1
[v1.4.1]: https://github.com/dequbed/rsasl/compare/v1.4.0...v1.4.1
