# The Rust SASL framework

[![Latest Version]][crates.io]
[![docs]][docs.rs]
![maintenance]
![license]

rsasl is an framework for [RFC 4422](https://tools.ietf.org/html/rfc4422); the Simple Authentication and Security 
Layer — aka SASL.

rsasl provide a large number of mechanisms by itself: (Crossed off ones are ported to pure Rust already, striked through
ones aren't yet implemented in the 2.0 version / main branch)

- [x] EXTERNAL
- [x] ANONYMOUS
- [x] PLAIN
- [ ] LOGIN
- [ ] CRAM-MD5
- [ ] DIGEST-MD5
- [x] SCRAM-SHA-1
- [x] SCRAM-SHA-256
- [ ] ~~NTLM~~
- [ ] SECURID
- [ ] ~~GSSAPI~~
- [ ] ~~GS2-KRB5~~
- [ ] SAML20
- [ ] OPENID20
- [ ] ~~KERBEROS_V5~~

Additional mechanisms can be implemented by other crates.

### Conditional compilation of mechanism

rsasl allows users to select the available mechanisms at compile time using cargo features.
For an overview refer to the module documentation of `rsasl::mechanisms`.

# Versions

Major version 1 of this crate uses [gsasl-sys](https://crates.io/crates/gsasl-sys) which are binding
to [GNU gsasl](https://www.gnu.org/software/gsasl). This makes the use of `unsafe` code and FFI necessary.
You can find the latest 1.X.Y version in the [branch `1.X.X`](https://github.com/dequbed/rsasl/tree/1.X.X)

Version `2.0.0-preview` is a pure-Rust rewrite using sources transpiled using [c2rust](https://github.com/immunant/c2rust).
Keep in mind that despite being Rust this code is as least as unsafe as the original C code. Most of this unsafe 
code will be removed before the first non-preview `2.0.0` release.

# License

Version 2 of this library is a transpilation of gsasl and thus under the very same [license of LGPL 2.1 or later](LICENSE).

# Examples

You can find a few examples on [GitHub](examples/).

[Latest Version]: https://img.shields.io/crates/v/rsasl.svg
[crates.io]: https://crates.io/crates/rsasl
[docs]: https://docs.rs/rsasl/badge.svg
[docs.rs]: https://docs.rs/rsasl/
[maintenance]: https://img.shields.io/badge/maintenance-actively%20developed-green.svg
[license]: https://img.shields.io/github/license/dequbed/rsasl
