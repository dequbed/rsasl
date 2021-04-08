# SASL in Rust

[![Latest Version]][crates.io] [![docs]][docs.rs] ![maintenance]

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
- SCRAM-SHA-256
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

# Examples

You can find a few examples on [GitHub](examples/).

# Stability & Development

rsasl is currently in stable maintenance mode. While there are no plans to
extend this crate with additional features or mechanism, issues and especially
security-related bugs will be responded to and fixed quickly.

If you have need for additional features in this crate do open an issue on
GitHub but be aware that we may not have time to implement it.

[Latest Version]: https://img.shields.io/crates/v/rsasl.svg
[crates.io]: https://crates.io/crates/rsasl
[docs]: https://docs.rs/rsasl/badge.svg
[docs.rs]: https://docs.rs/rsasl/
[maintenance]: https://img.shields.io/badge/maintenance-passively--developed-green.svg
