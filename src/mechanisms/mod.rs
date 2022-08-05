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

#[cfg(doc)]
// import all props here so we can use them in the doc-comments below
use crate::property::*;

#[cfg(feature = "anonymous")]
pub mod anonymous {
    //! `ANONYMOUS` *mechanism. Requires feature `anonymous`*
    mod client;
    mod mechinfo;
    mod server;
    pub use mechinfo::*;
}

#[cfg(feature = "external")]
pub mod external {
    //! `EXTERNAL` *mechanism. Requires feature `external`*
    mod client;
    mod mechinfo;
    mod server;
    pub use mechinfo::*;
}

#[cfg(feature = "login")]
pub mod login {
    //! `LOGIN` *mechanism. Requires feature `login`*
    //!
    //! The `LOGIN` mechanism sends authentication data in the plain without any form of hashing
    //! or encryption being applied. It should thus only be used over an encrypted channel such
    //! as TLS.
    mod client;
    mod mechinfo;
    mod server;
    pub use mechinfo::*;
}

#[cfg(feature = "plain")]
pub mod plain {
    //! `PLAIN` *mechanism. Requires feature `plain`*
    //!
    //! The `PLAIN` mechanism sends authentication data in the plain without any form of hashing
    //! or encryption being applied. It should thus only be used over an encrypted channel such
    //! as TLS.
    //!
    //! # Client
    //! Plain will query three properties at the beginning of an authentication exchange:
    //! [`AuthzId`], [`AuthId`] and [`Password`]. The supplied Provider will not satisfy any
    //! queries.
    //!
    //! `AuthzId` and `AuthId` may not contain a NULL-byte.
    //!
    //! `Password` must be valid UTF-8 and must not contain NULL according to
    //! [RFC 4616](https://www.rfc-editor.org/rfc/rfc4616.html), but rsasl will not validate a
    //! password and instead send it as-is.
    //!
    //!
    //! # Server
    //! Plain will not query any properties.
    //!
    //! The provider passed to `validate` will allow access to [`AuthzId`], [`AuthId`] and [`Password`].
    //!
    //! `Authzid`, `AuthId` and `Password` are valid UTF-8, contain no NULL bytes and have
    //! `saslprep` applied.
    mod client;
    mod mechinfo;
    mod server;
    pub use mechinfo::*;
}

#[cfg(any(feature = "scram-sha-1", feature = "scram-sha-2"))]
pub mod scram {
    //! `SCRAM-*` *mechanisms. Requires feature `scram-sha-1` (for* `-SHA1` *) and/or
    //! `scram-sha-2` (for* `-SHA256` *)*
    //!
    //! The SCRAM mechanisms cryptographically verify that the other party has knowledge of the
    //! password without sending the password in the clear.
    //!
    //! Additionally *integrity* validation of the authentication exchange is provided even when
    //! used over unencrypted transport.
    //! Thus SCRAM may be used over unencrypted channels but will in that case leak the `AuthId`
    //! and `AuthzId` used.
    //!
    //! # Client
    //!
    //! Scram will at first query [`AuthzId`], [`AuthId`] and [`Password`].
    //!
    //! If channel bindings are used (i.e. the mechanism ends in `-PLUS`) [`OverrideCBType`] is
    //! queried to allow setting the channel binding name to a different value than the default.
    //!
    //! Afterwards [`ChannelBindings`] is queried, with the name of channel bindings to be
    //! supplied available from the provider as [`ChannelBindingName`].
    //!
    //!
    mod client;
    mod mechinfo;
    mod parser;
    pub mod properties;
    mod server;
    mod tools;
    pub use mechinfo::*;
}

#[cfg(feature = "xoauth2")]
pub mod xoauth2 {
    //!
    //!
    //! # Server
    ///
    /// Since XOAUTH2 can return almost arbitrary error responses a callback must be used to be able
    /// to set the error message to be returned.
    ///
    /// A 'satisfiable' callback for the property [`XOAuth2Validate`](properties::XOAuth2Validate)
    /// will be issued on the server side, with a provider provider giving access to [`AuthId`]
    /// and [`OAuthBearerToken`].
    mod client;
    mod mechinfo;
    pub mod properties;
    mod server;
    pub use mechinfo::*;
}
