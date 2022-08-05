# The Rust SASL framework

[![Latest Version]][crates.io]
[![docs]][docs.rs]
![maintenance]
![license]
![msrv]

rsasl is an framework for [RFC 4422](https://tools.ietf.org/html/rfc4422); the Simple Authentication and Security 
Layer — aka SASL.

It is designed to enable implementing SASL support in protocol handling crates while abstracting away the details, 
allowing downstream users to select available mechanisms and add support for additional mechanisms without any 
changes required in the protocol handling crate.

rsasl provide a number of mechanisms by itself: 

- EXTERNAL
- ANONYMOUS
- PLAIN
- LOGIN
- SCRAM-SHA-1 and SCRAM-SHA-1-PLUS
- SCRAM-SHA-256 and SCRAM-SHA-256-PLUS
- XOAUTH2 (Client side only)

Support for the following mechanisms was available in rsasl 1 but is not implemented in rsasl 2:

- OPENID20
- SAML20
- GSSAPI
- GS2-KRB5
- KERBEROS_V5
- NTLM
- SECURID
- CRAM-MD5
- DIGEST-MD5

Additional mechanisms can be implemented by other crates. (**NOTE: In the current `v2.0.0` this feature is unstable**)

### Conditional compilation of mechanism

rsasl allows users to select the available mechanisms at compile time using cargo features.
For an overview refer to the module documentation of `rsasl::mechanisms`.


### MSRV — Minimum Supported Rust Version

The current msrv rsasl is Rust `1.56.0`, however do note that certain features (e.g. `registry_static`) have
dependencies with much more recent msrv.

# Versions

Major version 1 of this crate uses [gsasl-sys](https://crates.io/crates/gsasl-sys) which are binding
to [GNU gsasl](https://www.gnu.org/software/gsasl). This makes the use of `unsafe` code and FFI necessary.
You can find the latest 1.X.Y version in the [branch `1.X.X`](https://github.com/dequbed/rsasl/tree/1.X.X)

Version `2.0.0-preview` is a pure-Rust rewrite using sources transpiled using [c2rust](https://github.com/immunant/c2rust).
Keep in mind that despite being Rust this code is as least as unsafe as the original C code. Most of this unsafe 
code will be removed before the first non-preview `2.0.0` release.

# License

Version 2 and later of this library are dual licensed under both [Apache-2.0](LICENSE.APACHE-2.0) and 
[MIT](LICENSE.MIT), at your option.

# Examples

You can find a few examples on [GitHub](examples/).

[Latest Version]: https://img.shields.io/crates/v/rsasl.svg
[crates.io]: https://crates.io/crates/rsasl
[docs]: https://docs.rs/rsasl/badge.svg
[docs.rs]: https://docs.rs/rsasl/
[maintenance]: https://img.shields.io/badge/maintenance-actively%20developed-green.svg
[license]: https://img.shields.io/crates/l/rsasl
[msrv]: https://img.shields.io/badge/rust%20msrv-1.56.0-blueviolet