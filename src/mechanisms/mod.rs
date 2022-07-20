//! # SASL Mechanism support
//!
//! rsasl implements most of the [IANA registered mechanisms](http://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml)
//! in `COMMON` use.
//! The implementations of these mechanisms can be found in this module
//!
//! # Mechanism selection and conditional compilation
//!
//! rsasl allows the final end-user to decide which mechanisms are required to be implemented.
//! To this end each mechanism in the rsasl crate can be disabled using feature flags.
//!
//! By default **all** implemented mechanisms are compiled into the crate.
//!
//! However if you know certain mechanisms will never be used you can select the mechanisms by
//! depending on `rsasl` with `default-features` set to `false`:
//! ```toml
//! rsasl = { version = "2.0.0", default-features = false, features = ["plain", "gssapi", "scram-sha-2"] }
//! ```
//! With the example dependencies line above only code for the mechanisms `PLAIN`, `GSSAPI`,
//! `SCRAM-SHA256` and `SCRAM-SHA256-PLUS` would be compiled into the crate and available at run
//! time.
//!
//! Protocol implementations should always depend on rsasl with `default-features` set to `false`
//! making use of [feature unification](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification)
//! to not compile in mechanisms that aren't needed.

#[cfg(feature = "anonymous")]
pub mod anonymous {
    //! `ANONYMOUS` *mechanism. Requires feature `anonymous`*
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(feature = "cram-md5")]
pub mod cram_md5 {
    //! `CRAM_MD5` *mechanism. Requires feature `cram-md5`*
    pub mod challenge;
    pub mod client;
    pub mod digest;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(feature = "digest-md5")]
pub mod digest_md5 {
    //! `DIGEST_MD5` *mechanism. Requires feature `digest-md5`*
    pub mod client;
    pub mod digesthmac;
    pub mod free;
    pub mod getsubopt;
    pub mod mechinfo;
    pub mod nonascii;
    pub mod parser;
    pub mod printer;
    pub mod qop;
    pub mod server;
    pub mod session;
    pub mod validate;
}

#[cfg(feature = "external")]
pub mod external {
    //! `EXTERNAL` *mechanism. Requires feature `external`*
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(feature = "login")]
pub mod login {
    //! `LOGIN` *mechanism. Requires feature `login`*
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(feature = "openid20")]
pub mod openid20 {
    //! `OPENID20` *mechanism. Requires feature `openid20`*
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(feature = "plain")]
pub mod plain {
    //! `PLAIN` *mechanism. Requires feature `plain`*
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(feature = "saml20")]
pub mod saml20 {
    //! `SAML20` *mechanism. Requires feature `saml20`*
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(any(feature = "scram-sha-1", feature = "scram-sha-2"))]
pub mod scram {
    //! `SCRAM-*` *mechanisms. Requires feature `scram-sha-1` (for* `-SHA1` *) and/or
    //! `scram-sha-2` (for* `-SHA256` *)*
    pub mod client;
    pub mod mechinfo;
    pub mod parser;
    pub mod properties;
    pub mod server;
    pub mod tools;
}

#[cfg(feature = "securid")]
pub mod securid {
    //! `SECURID` *mechanism. Requires feature `securid`*
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}
