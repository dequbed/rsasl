#![allow(non_upper_case_globals, non_camel_case_types)]
//! `rsasl` is the Rust SASL framework designed to make supporting SASL in protocols and doing SASL
//! authentication in application code simple and safe.
//!
//! # SASL primer
//!
//! *you can safely skip this section if you know your way around SASL and just want to know
//! [how to use this library](#where-to-start).*
//!
//! [SASL (RFC 4422)](https://tools.ietf.org/html/rfc4422) was designed to separate
//! authentication from the remaining protocol implementation, both server- and client-side. The
//! goal was to make authentication pluggable and more modular, so that a new protocol doesn't
//! have to re-invent authentication from scratch and could instead rely on existing
//! implementations of just the authentication part.
//!
//! SASL implements this by abstracting all authentication into so called 'mechanisms' that
//! authenticate in a number of 'steps', with each step consisting of some amount of data being
//! sent from the client to the server and from the server to the client.
//! This data is explicitly opaque to the outer protocol (e.g. SMTP, IMAP, …). The protocol only
//! needs to define a way to transport this data to the respective other end. The way this is done
//! differs between protocols, but the format of the authentication data is always the same for any
//! given mechanism, so any mechanism can work with any protocol out of the box.
//!
//! One of the best known mechanism for example, `PLAIN`, always transports the username and
//! password separated by singular NULL bytes. Yet the very same plain authentication using the
//! username "username" and password "secret" looks very different in different protocols:
//!
//! IMAP:
//! ```text
//! S: * OK IMAP4rev1 Service Ready
//! C: D0 CAPABILITY
//! S: * CAPABILITY IMAP4 IMAP4rev1 AUTH=GSSAPI AUTH=PLAIN
//! S: D0 OK CAPABILITY completed.
//! C: D1 AUTHENTICATE PLAIN
//! S: +
//! C: AHVzZXJuYW1lAHNlY3JldAo=
//! S: D1 OK AUTHENTICATE completed
//! ```
//!
//! SMTP:
//! ```test
//! S: 220 smtp.example.com Simple Mail Transfer Service Ready
//! C: EHLO client.example.org
//! S: 250-smtp.server.com Hello client.example.org
//! S: 250-SIZE 1000000
//! S: 250 AUTH GSSAPI PLAIN
//! C: AUTH PLAIN
//! S: 334
//! C: AHVzZXJuYW1lAHNlY3JldAo=
//! S: 235 2.7.0 Authentication successful
//! ```
//!
//! XMPP:
//! ```text
//! S: <stream:features>
//! S:     <mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
//! S:         <mechanism>GSSAPI</mechanism>
//! S:         <mechanism>PLAIN</mechanism>
//! S:     </mechanisms>
//! S: </stream:features>
//! C: <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>
//! C:     AHVzZXJuYW1lAHNlY3JldAo=
//! C: </auth>
//! ```
//!
//! But the inner authentication **data** (here base64 encoded as `AHVzZXJuYW1lAHNlY3JldAo=`)
//! is always the same.
//!
//! This modularity becomes an even bigger advantage when combined with cryptographically strong
//! authentication (like SCRAM) or single-sign-on technologies (like OpenID Connect or Kerberos).
//! Instead of every protocol and their implementations having to juggle cryptographic proofs or
//! figure out the latest SSO mechanism by themselves they can share their implementations.
//!
//! Of course a client or server application for those protocols still has to worry about
//! authentication and authorization on some level. Which is why rsasl is designed to make
//! authentication pluggable and enable middleware-style protocol crates that are entirely
//! authentication-agnostic, deferring the details entirely to their downstream users.
//!
//! # Where to start using this crate
//! - [I'm implementing some network protocol and I need to add SASL authentication to it!](#protocol-implementations)
//! - [I'm an user of such a protocol crate and I need to configure my credentials!](#application-code)
//! - [I'm both/either/none of those but I have to implement a custom SASL mechanism!](#custom-mechanisms)
//!
//!
//! # Protocol Implementations
//!
//! Authentication in rsasl is done using [`Session`], by calling [`Session::step`] or
//! [`Session::step64`] until [`State::Finished`](session::State::Finished) is returned.
//!
//! These Sessions are constructed using the [`SASL`] struct.
//! This struct is configured by the user with the list of enabled mechanisms and their preference,
//! and with a callback used by mechanisms to retrieve required data (e.g. username/password for
//! PLAIN) without involvement of the protocol crate.
//!
//! The `SASL` struct is instantiated by the user and provided to the protocol crate which can then
//! call either [`SASL::client_start_suggested()`] or [`SASL::server_start_suggested()`] to start
//! an authentication with the best mechanism available on both sides.
//!
//! Both of these methods return a [`SessionBuilder`] which needs to be finalized into a [`Session`]
//! to be used for the entire authentication exchange.
//!
//! To minimize dependencies protocol implementations should always depend on rsasl as follows:
//! ```toml
//! [dependencies]
//! rsasl = { version = "2", default-features = false, features = ["provider"]}
//! ```
//! or, if they need base64 support:
//! ```Cargo.toml
//! [dependencies]
//! rsasl = { version = "2", default-features = false, features = ["provider_base64"]}
//! ```
//!
//! This makes use of [feature unification](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification)
//! to make rsasl a (near-)zero dependency crate. All decisions about compiled-in mechanism support
//! and other features are put into the hand of the final user.
//!
//! Specifically when depended on this way rsasl does not compile code for *any mechanism* or
//! most of the selection internals, minimizing the compile-time and code size impact.
//! Re-enabling required mechanisms and selection system is deferred to the user of
//! the protocol implementation who will have their own dependency on rsasl if they want to make
//! use of SASL authentication.
//!
//! To this end a protocol crate **should not** re-export anything from the rsasl crate! Doing so
//! may lead to a situation where users can't use any mechanisms since they only depend on
//! rsasl via a transient dependency that has no mechanism features enabled.
//!
// TODO: How to handle EXTERNAL?
// TODO:
//     Bonus minus points: sasl.wrap(data) and sasl.unwrap(data) for security layers. Prefer to
//     not and instead do TLS. Needs better explanation I fear.
//!
//! # Application Code
//!
//! Applications needs to construct a [`SASL`] struct to be passed to the protocol crate to perform
//! authentication exchanges.
//!
//! This [`SASL`] struct must be configured with a [`SessionCallback`] that can request required
//! [`Property`]s during the authentication exchange.
//!
//! Applications can enable and disable mechanism support at compile time using features, with the
//! default being to add all IANA-registered mechanisms in `COMMON` use.
//! See the module documentation for [`mechanisms`] for details.
//!
// TODO:
//     - Static vs Dynamic Registry
//     - Enable/Disable mechanisms at runtime
//     - Explicit dependency because feature unification
//!
//! # Custom Mechanisms
//!
//! *NOTE:* **The system to add custom mechanisms is in flux and does not observe the same stability
//! guarantees as the rest of the crate. Breaking changes in this system may happen even for
//! minor changes of the crate version.**
//!
//! Custom mechanism implementations are possible but not stable as of rsasl `2.0.0`. To
//! implement a custom mechanism implementation the feature `unstable_custom_mechanism` must be
//! enabled.
//!
//! A custom mechanism must implement the trait [`Authentication`] and define a
//! [`Mechanism`](registry::Mechanism) struct describing the implemented mechanism. Documentation
//! about how to add a custom mechanism is found in the [`registry module documentation`](registry).
//!

pub mod error;
pub mod callback;
pub mod sasl;
pub mod session;
pub mod property;
pub mod validate;
pub mod mechanisms;
pub mod mechname;

mod gsasl;
mod init;

#[cfg(not(any(doc, feature = "unstable_custom_mechanism")))]
mod registry;
#[cfg(not(any(doc, feature = "unstable_custom_mechanism")))]
mod mechanism;

#[cfg(any(doc, feature = "unstable_custom_mechanism"))]
pub mod registry;
#[cfg(any(doc, feature = "unstable_custom_mechanism"))]
pub mod mechanism;

mod channel_bindings;
mod context;
mod typed;

mod vectored_io;

pub mod prelude {
    //! prelude exporting the most commonly used types
    pub use crate::sasl::SASL;
    pub use crate::session::Session;
    pub use crate::mechname::Mechname;
    pub use crate::property::Property;
    pub use crate::error::{
        SASLError,
        SessionError
    };
}

struct Shared;

pub mod docs {
    //! Modules purely for documentation

    pub mod readme {
        //! Render of the repositories' README.md:
        #![doc = include_str!("../README.md")]
    }

    pub mod adr {
        //! Architecture design record explaining design decisions

        pub mod adr0001_property_and_validation_newtype {
            #![doc = include_str!("../docs/decisions/0001-property-and-validation-newtype.md")]
        }
    }
}
