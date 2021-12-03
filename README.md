# SASL in Rust

[![Latest Version]][crates.io] [![docs]][docs.rs] ![maintenance]

rsasl is an implementation of the Simple Authentication and Security Layer — SASL.

rsasl can provide a large number of mechanisms:
- EXTERNAL
- ANONYMOUS
- PLAIN
- LOGIN
- CRAM-MD5
- DIGEST-MD5
- SCRAM-SHA-1
- SCRAM-SHA-256
- NTLM
- SECURID
- GSSAPI
- GS2-KRB5
- SAML20
- OPENID20
- KERBEROS_V5

# Versions

Major version 1 of this crate uses [gsasl-sys](https://crates.io/crates/gsasl-sys) which are binding
to [GNU gsasl](https://www.gnu.org/software/gsasl). This makes the use of `unsafe` code and FFI necessary.
You can find the latest 1.X.Y version in the [branch `1.X.X`](https://github.com/dequbed/rsasl/tree/1.X.X)

Version `2.0.0-preview` is a pure-Rust rewrite using sources transpiled using [c2rust](https://github.com/immunant/c2rust).
Keep in mind that despite being Rust this code is as least as unsafe as the original C code. Most of this unsafe 
code will be removed before the first non-preview `2.0.0` release.

# Examples

You can find a few examples on [GitHub](examples/).

[Latest Version]: https://img.shields.io/crates/v/rsasl.svg
[crates.io]: https://crates.io/crates/rsasl
[docs]: https://docs.rs/rsasl/badge.svg
[docs.rs]: https://docs.rs/rsasl/
[maintenance]: https://img.shields.io/badge/maintenance-actively%20developed-green.svg