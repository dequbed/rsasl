# SASL in Rust

[![Latest Version]][crates.io] [![docs]][docs.rs]

rsasl is an implementation of the Simple Authentication and Security Layer — SASL.

Currently it uses [gsasl-sys](https://crates.io/crates/gsasl-sys) which are bindings to [GNU gsasl](https://www.gnu.org/software/gsasl), that however may change in the future.

Since it links to gsasl rsasl can provide a large number of mechanisms:
- EXTERNAL
- ANONYMOUS
- PLAIN
- LOGIN
- CRAM-MD5
- DIGEST-MD5
- SCRAM-SHA-1
- NTLM
- SECURID
- GSSAPI
- GS2-KRB5
- SAML20
- OPENID20
- KERBEROS_V5


# Alternatives

Please see [sasl-rs](https://gitlab.com/xmpp-rs/sasl-rs) for a pure Rust SASL
implementation. It provides less Mechanisms but does not need `unsafe` like
rsasl does due to it's FFI-bindings and does not rely on an old (albeit
well written) C library.



[Latest Version]: https://img.shields.io/crates/v/rsasl.svg
[crates.io]: https://crates.io/crates/rsasl
[docs]: https://docs.rs/rsasl/badge.svg
[docs.rs]: https://docs.rs/rsasl/
