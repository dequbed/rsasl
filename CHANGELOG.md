# Revision history for `rsasl`

All notable changes are documented or linked to in this file. The format of the changelog is based on 
['Keep a Changelog'](https://keepachangelog.com/en/1.0.0/). In short, this changelog is sorted the most recent
release at the top, and the first section —  Unreleased — documents features that are in the `development` 
branch but have not yet landed in the `main` branch from which releases are generated.

`rsasl` adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html); with 
the notable exception of custom mechanism support and excluding 
bug-fixes there will not be any backwards-incompatible changes within a major version release.

The MSRV (minimum supported Rust version) of the project is documented in the [`Cargo.toml`](Cargo.toml) and in the 
[README](README.md). Changes to the MSRV are considered a **non-breaking change** and thus can happen in a *MINOR* 
release. They will however *never* happen in a patch release.

<!-- next-header -->
## [Unreleased] — ReleaseDate

### Added
- New integration tests that should make it easier to test rsasl against other implementations

### Changed
- `Session::step64` did not return the actual bytes written but the bytes encoded into base64. As the exact length 
  isn't know step64 now returns a `bool` instead of an `Option<usize>` to indicate if a message should be sent.

## [v2.0.0-preview11] — 2022-08-25
### Fixed
- Fixed a bug where the XOAUTH2 mechanisms were registered as `PLAIN` instead, making all `PLAIN` authentication fail.

## [v2.0.0-preview10] — 2022-08-24

### Fixed
- `ANONYMOUS` client now correctly allows no token to be provided
- `ANONYMOUS` server will now correctly allow no token to be provided by a client
- `EXTERNAL` client now correctly requests an optional `AuthzId` instead of a required `AuthId`
- `EXTERNAL` server now correctly provides `Authzid` instead of `Authid`
- `PLAIN` client correctly rejects empty authid or password. Empty authzid is still treated as no authzid provided.
- `PLAIN` server now allows non-UTF8 passwords, and does not apply saslprep to the authzid anymore. If authid or 
  password are empty after saslprep an error is returned.
- `SCRAM` server now calls validate correctly

## [v2.0.0-preview9] — 2022-08-08

### Changed
- `Mechname::new` is now more appropiately named `Mechname::parse`
- `SASLConfig::with_credentials` only enabled `LOGIN` if no authzid is provided
- Session is now `Send` + `Sync`

### Fixed
- XOAUTH2 now compiles with the msrv 1.56.0 
- clippy passes the code with default lints now

## [v2.0.0-preview8] — 2022-08-05

rsasl is now licensed under Apache-2.0 and MIT dual license.

### Added

- Properties can now contain data with other lifetimes than `'static`
- XOAUTH2 mechanism, both server and client-side.
- Testing utilities for the server side of an authentication exchange

### Changed

- `Request::satisfy_with` is now limited to `SizedProperty`.
- The `-PLUS` variants of SCRAM aren't automatically registered by the static registry anymore. Instead they should 
  be manually registered if they are to be used.

### Fixed

- Fixed 'actionable' callbacks not correctly indicating they were handled


## [v2.0.0-preview7] — 2022-07-30

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
[Unreleased]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview11...development
[v2.0.0-preview11]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview10...v2.0.0-preview11
[v2.0.0-preview10]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview9...v2.0.0-preview10
[v2.0.0-preview9]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview8...v2.0.0-preview9
[v2.0.0-preview8]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview7...v2.0.0-preview8
[v2.0.0-preview7]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview1...v2.0.0-preview7
[v2.0.0-preview1]: https://github.com/dequbed/rsasl/compare/v1.4.1...v2.0.0-preview1
[v1.4.1]: https://github.com/dequbed/rsasl/compare/v1.4.0...v1.4.1
