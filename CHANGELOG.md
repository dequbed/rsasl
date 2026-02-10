# Revision history for `rsasl`

All notable changes are documented or linked to in this file. The format of the changelog is based on 
['Keep a Changelog'](https://keepachangelog.com/en/1.0.0/). In short, this changelog is sorted the most recent
release at the top, and the first section documents features that are in the `development` 
branch but have not yet landed in the `main` branch from which releases are generated.

`rsasl` adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html); with 
the notable exception of custom mechanism support and excluding 
bug-fixes there will not be any backwards-incompatible changes within a major version release.

The MSRV (minimum supported Rust version) of the project is documented in the [`Cargo.toml`](Cargo.toml) and in the 
[README](README.md). Changes to the MSRV are considered a **non-breaking change** and thus can happen in a *MINOR* 
release. They will however *never* happen in a patch release.

<!-- next-header -->
# [Upcoming Changes] — Not Yet ;)

[Changes rendered on GitHub][Upcoming/diff]

# [v2.2.1] — 2026-02-10

[Changes rendered on GitHub][v2.2.1/diff]

## Changed
- fixed compilation failing on current rustc nightly due to dyn pointer cast changes (see [rust-lang/rust#141402](https://github.com/rust-lang/rust/issues/141402))


# [v2.2.0] — 2024-10-15

[Changes rendered on GitHub][v2.2.0/diff]

## Fixed
- #58 — Constructing OAuthBearerError is not (directly) possible
- #57 — Export types for unstable_custom_mechanism feature


# [v2.1.0] — 2024-08-21

[Changes rendered on GitHub][v2.1.0/diff]

## Added
- `SCRAM-SHA-512` and `SCRAM-SHA-512-PLUS` mechanisms were added by WenyXu

## Fixed
- #26 — SCRAM-SHA512 and SCRAM-SHA512-PLUS support

  The two mechanisms have been added by WenyXu, as mentioned above


# [v2.0.2] — 2024-08-10

[Changes rendered on GitHub][v2.0.2/diff]

## Added
- Mathieu-Lala added a lot of build engineering, improving the CI and adding dependabot alerts. 

## Changed
- Mathieu-Lala also moved the I/O-dependant code from `acid_io` to `core2`.
  This change is not user-visible as it only applies to `no_std` systems which
  are not supported yet.

## Fixed
- #41 — Library not compiling on rust v1.82.0
  Changes in the typechecker made rsasl not compile on Rust versions past
  v1.81. Thanks to Mathieu-Lala this was fixed for rsasl v2.0.2

# [v2.0.1] — 2023-09-12

[Changes rendered on GitHub][v2.0.1/diff]

## Fixed
- #29 — `GSSAPI` fails to build on macOS
  
  This issue seems to be caused by the same problem as [estokes/libgssapi#2](https://github.com/estokes/libgssapi/issues/2).
  Building libgssapi without default features solves this build issue.

# [v2.0.0] — 2023-02-04

[Changes rendered on GitHub][v2.0.0/diff]

## Added
- `GSSAPI` mechanism implementation
- Security layer functionality in `Session`
- Mechanisms preference can be selected by implementations of `Callback` using `Callback::prefer`.

## Changed
- Recursive callbacks calls are now prevented by making property methods on `MechanismData` take `&mut self`. 
  See ADR-0003 ([crate::docs::adr] on docs.rs, [GitHub link](https://github.com/dequbed/rsasl/tree/development/docs/decisions) otherwise) for further details about why this change was done.

## Fixed
- #9 — `GSSAPI` Mechanism support
- #18 — Decide if recursive callback calls are acceptable
  
  Closed by the above change explicitly making them impossible

# [v2.0.0-rc.4] — 2022-11-22

[Changes rendered on GitHub][v2.0.0-rc.4/diff]

## Added
- `SASLClient::start_suggested` can now be called with any `impl IntoIterator<Item=&&Mechname>`.  As 
  `&[&Mechname]` does implement this trait no changes are required for users of this method.
- A new method `SASLClient::start_suggested_iter` is added that takes `impl IntoIterator<Item=&Mechname>`, i.e. an
  iterator with a layer of indirection removed compared to the non-`_iter` variant. This variant is
  more efficient if direct references to `&Mechname` can be constructed. It also may be easier to
  use with a zero-copy parsing approach than the non-`_iter` variant.

## Changed
- MSRV was raised to rustc 1.61.0 due to that release stabilizing generic parameters in `const fn`.

# [v2.0.0-rc.3] — 2022-10-12

[Changes rendered on GitHub][v2.0.0-rc.3/diff]

## Changed
- Thanks to Mathieu Lala work rsasl is much closer to a stable release! PR#19 fixes most clippy lints and marks 
  externally visible structs and enums `#[non_exhaustive]` so we don't program ourselves into a corner.

## Fixed
- #14 — Ensure types that are visible by external crates can be extended without breaking semver.

  This fix makes using rsasl safer for downstream crates as version updates have a smaller change of breakage and 
  uphold more semver guarantees.

# [v2.0.0-rc.2] — 2022-09-28

[Changes rendered on GitHub][v2.0.0-rc.2/diff]

## Added
- All dependencies on `std::io::Write` have been moved to `acid_io::Write` from the [`acid_io` crate](https://github.com/dataphract/acid_io).
  This will make moving towards a `#[no_std]`-enabled version of rsasl easier, as the move of `std::io` into `core` 
  is still somewhat far off. All types implementing `std::io::Write` also automatically implement `acid_io::Write`, 
  so no changes to downstream code should be necessary.
- An `OAUTHBEARER` mechanism implementation

## Changed
- Finished the changes started in `-preview12` and `-rc.1`; instead of `Session::step` and `Session::step64` 
  returning a tuple they now only return a `State` which contains a two-valued enum for "was a message produced". 
  This means the previous (potentially wrong!) "message size" is now not returned anymore. Clients that must know 
  the exact length of output written (e.g. because the surrounding protocol includes length values, or they need to 
  special-case zero-length messages) should use a length-tracking writer.

  To move to the new version, instead of e.g. the following:
  ```rust
  let (state, written) = session.step(input, &mut output)?;
  ```
  code must now use
  ```rust
  let state = session.step(input, &mut output)?;
  let written = state.has_sent_message();
  ```
  for the same effect.

## Fixed
- The client-side XOAUTH2 implementation now correctly indicates a final (empty) message to be sent when an error 
  was returned by the server.
- #10 — OAUTHBEARER Mechanism support

# [v2.0.0-rc.1] — 2022-08-30

[Changes rendered on GitHub][v2.0.0-rc.1/diff]

`v2.0.0-rc.1` is a re-release of the `v2.0.0-preview12` version due to me messing up the pre-release version 
numbering of the `preview` releases. `preview12` is ordered alphanumerically as mixed ASCII and thus considered smaller 
than `preview9`. To enforce numeric sorting the number must be separated using a dot, so e.g. `preview.12`. However 
`preview.12` is considered smaller than *all* `previewXX` releases because it is shorter. Thus rsasl now uses `rc` 
as 'r' is sorted after 'p' and thus 'rc.X' > 'previewYZ'. Sorry for the confusion.

# [v2.0.0-preview12] — 2022-08-30

[Changes rendered on GitHub][v2.0.0-preview12/diff]

## Added
- New integration tests that should make it easier to test rsasl against other implementations

## Changed
- `Session::step64` did not return the actual bytes written but the bytes encoded into base64. As the exact length 
  isn't know step64 now returns a `bool` instead of an `Option<usize>` to indicate if a message should be sent.


# [v2.0.0-preview11] — 2022-08-25

[Changes rendered on GitHub][v2.0.0-preview11/diff]

## Fixed
- Fixed a bug where the XOAUTH2 mechanisms were registered as `PLAIN` instead, making all `PLAIN` authentication fail.

# [v2.0.0-preview10] — 2022-08-24

[Changes rendered on GitHub][v2.0.0-preview10/diff]

## Fixed
- `ANONYMOUS` client now correctly allows no token to be provided
- `ANONYMOUS` server will now correctly allow no token to be provided by a client
- `EXTERNAL` client now correctly requests an optional `AuthzId` instead of a required `AuthId`
- `EXTERNAL` server now correctly provides `Authzid` instead of `Authid`
- `PLAIN` client correctly rejects empty authid or password. Empty authzid is still treated as no authzid provided.
- `PLAIN` server now allows non-UTF8 passwords, and does not apply saslprep to the authzid anymore. If authid or 
  password are empty after saslprep an error is returned.
- `SCRAM` server now calls validate correctly

# [v2.0.0-preview9] — 2022-08-08

[Changes rendered on GitHub][v2.0.0-preview9/diff]

## Changed
- `Mechname::new` is now more appropiately named `Mechname::parse`
- `SASLConfig::with_credentials` only enabled `LOGIN` if no authzid is provided
- Session is now `Send` + `Sync`

## Fixed
- XOAUTH2 now compiles with the msrv 1.56.0 
- clippy passes the code with default lints now

# [v2.0.0-preview8] — 2022-08-05

[Changes rendered on GitHub][v2.0.0-preview8/diff]

rsasl is now licensed under Apache-2.0 and MIT dual license.

## Added

- Properties can now contain data with other lifetimes than `'static`
- XOAUTH2 mechanism, both server and client-side.
- Testing utilities for the server side of an authentication exchange

## Changed

- `Request::satisfy_with` is now limited to `SizedProperty`.
- The `-PLUS` variants of SCRAM aren't automatically registered by the static registry anymore. Instead they should 
  be manually registered if they are to be used.

## Fixed

- Fixed 'actionable' callbacks not correctly indicating they were handled


# [v2.0.0-preview7] — 2022-07-30

[Changes rendered on GitHub][v2.0.0-preview7/diff]

First 'alpha' release of rsasl 2.0.0, with most of the API stabilized enough that testing if rsasl
is usable by third-party crates in other situations than BFFH is possible.

Examples of using rsasl in other crates:
- [lettre](https://github.com/dequbed/lettre/tree/rsasl-auth)

# [v2.0.0-preview1] — 2021-12-03

[Changes rendered on GitHub][v2.0.0-preview1/diff]

First preview release for the pure-Rust version. This is a full rewrite of rsasl, changing just
about every part of the code. Most of the code was transpiled using
[c2rust](https://github.com/immunant/c2rust) and then ported piece by piece to more sensible and
modern Rust.

**Big thanks to all [c2rust contributors](https://github.com/immunant/c2rust/graphs/contributors)
making this release possible.**

# [v1.4.1] — 2021-10-20

[Changes rendered on GitHub][v1.4.1/diff]

* Fixes potential bad pointer conversion on non-x86 targets

# [v1.4.0] — 2021-10-09

* Usability improvements with better type aliases

# 1.3.0 — 2021-10-02

* Improved error messages

# 1.2.0 — 2021-10-02

* `SaslError` marked `Eq` and `Ord`
* Fixes a null-pointer panic when passing invalid SaslErrors

# 1.0.0 — 2021-04-06

* Initial stabilized release

[Upcoming Changes]: https://github.com/dequbed/rsasl/tree/development
<!-- next-url -->
[Upcoming/diff]: https://github.com/dequbed/rsasl/compare/v2.2.1...development
[v2.2.1]: https://github.com/dequbed/rsasl/releases/tag/v2.2.1
[v2.2.1/diff]: https://github.com/dequbed/rsasl/compare/v2.2.0...v2.2.1
[v2.2.0]: https://github.com/dequbed/rsasl/releases/tag/v2.2.0
[v2.2.0/diff]: https://github.com/dequbed/rsasl/compare/v2.1.0...v2.2.0
[v2.1.0]: https://github.com/dequbed/rsasl/releases/tag/v2.1.0
[v2.1.0/diff]: https://github.com/dequbed/rsasl/compare/v2.0.2...v2.1.0
[v2.0.2]: https://github.com/dequbed/rsasl/releases/tag/v2.0.2
[v2.0.2/diff]: https://github.com/dequbed/rsasl/compare/v2.0.1...v2.0.2
[v2.0.1]: https://github.com/dequbed/rsasl/releases/tag/v2.0.1
[v2.0.1/diff]: https://github.com/dequbed/rsasl/compare/v2.0.0...v2.0.1
[v2.0.0]: https://github.com/dequbed/rsasl/releases/tag/v2.0.0
[v2.0.0/diff]: https://github.com/dequbed/rsasl/compare/v2.0.0-rc.4...v2.0.0
[v2.0.0-rc.4]: https://github.com/dequbed/rsasl/releases/tag/v2.0.0-rc.4
[v2.0.0-rc.4/diff]: https://github.com/dequbed/rsasl/compare/v2.0.0-rc.3...v2.0.0-rc.4
[v2.0.0-rc.3]: https://github.com/dequbed/rsasl/releases/tag/v2.0.0-rc.3
[v2.0.0-rc.3/diff]: https://github.com/dequbed/rsasl/compare/v2.0.0-rc.2...v2.0.0-rc.3
[v2.0.0-rc.2]: https://github.com/dequbed/rsasl/releases/tag/v2.0.0-rc.2
[v2.0.0-rc.2/diff]: https://github.com/dequbed/rsasl/compare/v2.0.0-rc.1...v2.0.0-rc.2
[v2.0.0-rc.1]: https://github.com/dequbed/rsasl/releases/tag/v2.0.0-rc.1
[v2.0.0-rc.1/diff]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview12...v2.0.0-rc.1
[v2.0.0-preview12]: https://github.com/dequbed/rsasl/releases/tag/v2.0.0-preview12
[v2.0.0-preview12/diff]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview11...v2.0.0-preview12
[v2.0.0-preview11]: https://github.com/dequbed/rsasl/releases/tag/v2.0.0-preview11
[v2.0.0-preview11/diff]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview10...v2.0.0-preview11
[v2.0.0-preview10]: https://github.com/dequbed/rsasl/releases/tag/v2.0.0-preview10
[v2.0.0-preview10/diff]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview9...v2.0.0-preview10
[v2.0.0-preview9]: https://github.com/dequbed/rsasl/releases/tag/v2.0.0-preview9
[v2.0.0-preview9/diff]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview8...v2.0.0-preview9
[v2.0.0-preview8]: https://github.com/dequbed/rsasl/releases/tag/v2.0.0-preview8
[v2.0.0-preview8/diff]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview7...v2.0.0-preview8
[v2.0.0-preview7]: https://github.com/dequbed/rsasl/releases/tag/v2.0.0-preview7
[v2.0.0-preview7/diff]: https://github.com/dequbed/rsasl/compare/v2.0.0-preview1...v2.0.0-preview7
[v2.0.0-preview1]: https://github.com/dequbed/rsasl/releases/tag/v2.0.0-preview1
[v2.0.0-preview1/diff]: https://github.com/dequbed/rsasl/compare/v1.4.1...v2.0.0-preview1
[v1.4.1]: https://github.com/dequbed/rsasl/releases/tag/v1.4.1
[v1.4.1/diff]: https://github.com/dequbed/rsasl/compare/v1.4.0...v1.4.1
[v1.4.0]: https://github.com/dequbed/rsasl/releases/tag/v1.4.0
