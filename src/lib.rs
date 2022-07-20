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
//! The starting point of rsasl for protocol implementations is the
//! sided [`SASLConfig`](prelude::SASLConfig) struct, usually as
//! [`ClientConfig`](prelude::ClientConfig) or [`ServerConfig`](prelude::ServerConfig).
//! These structs are created by the downstream user of the protocol crate and contain all
//! required configuration and data in an opaque and easily storable way.
//! The `SASLConfig` type is designed to be long-lived and to be valid for multiple contexts and
//! authentication exchanges.
//!
//! To start an authentication a [`SASLClient`](prelude::SASLClient) or
//! [`SASLServer`](prelude::SASLServer) is constructed from this config, allowing a
//! protocol crate to provide additional, context-specific, data.
//!
//! The produced `SASLClient` / `SASLServer` are thus themselves context-specific and usually not
//! readily reusable, for example channel bindings are specific to a single TLS session requiring a
//! new `SASLClient` or `SASLServer` to be constructed for every connection.
//!
//! To finally start an authentication exchange a [`Session`](session::Session) is
//! constructed by selecting the best shared authentication Mechanism, and the methods
//! [`Session::step`](session::Session::step) or [`Session::step64`](session::Session::step64) are
//! called until [`State::Finished`](session::State::Finished) is returned:
//!
//! ```rust
//! # use std::io;
//! # use std::sync::Arc;
//! use rsasl::prelude::*;
//!
//! # fn get_initial_auth_data(_: &Mechname) -> Vec<u8> { unimplemented!() }
//! # fn tell_other_side_which(_: &Mechname) {}
//! # fn get_more_auth_data() -> Option<Vec<u8>> { unimplemented!() }
//! // the `config` is provided by the user of this crate. The `writer` is a stand-in for sending
//! // data to other side of the authentication exchange.
//! fn sasl_authenticate(config: Arc<ClientConfig>, writer: &mut impl io::Write) {
//!     let sasl = SASLClient::new(config);
//!     // These would normally be provided via the protocol in question
//!     let offered_mechs = [Mechname::new(b"PLAIN").unwrap(), Mechname::new(b"GSSAPI").unwrap()];
//!
//!     // select the best offered mechanism that the user enabled in the `config`
//!     let mut session = sasl.start_suggested(offered_mechs.iter()).expect("no shared mechanisms");
//!
//!     // Access to the name of the selected mechanism
//!     let selected_mechanism = session.get_mechname();
//!
//!     let mut data: Option<Vec<u8>> = None;
//!     // Which side needs to send the first bit of data depends on the mechanism
//!     if !session.are_we_first() {
//!         // Tell the other side which mechanism we selected and receive initial auth data
//!         data = Some(get_initial_auth_data(selected_mechanism));
//!     } else {
//!         // If we *are* going first we still need to inform the other party of the selected
//!         // mechanism. Many protocols allow sending the selected mechanism with the initial
//!         // batch of data, but we're not doing that here for simplicities sake.
//!         tell_other_side_which(selected_mechanism);
//!     }
//!
//!     // stepping the authentication exchange to completion
//!     while {
//!         // each call to step writes the generated auth data into the provided writer.
//!         // Normally this data would then have to be sent to the other party, but this goes
//!         // beyond the scope of this example
//!         let (state, _) = session.step(data.as_deref(), writer).expect("step errored!");
//!         // returns `true` if step needs to be called again with another batch of data
//!         state.is_running()
//!     } {
//!         // While we aren't finished, receive more data from the other party
//!         data = get_more_auth_data()
//!     }
//!     // Wohoo, we're done!
//!     // rsasl can in most cases not tell if the authentication was successful, this would have
//!     // to be checked in a protocol-specific way.
//! }
//! ```
//!
//! After an authentication exchange has finished [`Session::validation`](session::Session::validation)
//! may be used in server contexts to extract a `Validation` type from the authentication exchange.
//! Further details about `Validation` can be found in the [`validate`] module documentation.
//!
//! To minimize dependencies protocol implementations should always depend on rsasl with the
//! least amount of features enabled:
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
//! To allow protocol implementations to use SASL authentication Applications needs to construct a
//! [`ClientConfig`](prelude::ClientConfig) or [`ServerConfig`](prelude::ServerConfig) to be used
//! by the protocol implementation.
//!
//! This config selects the mechanisms that will be available, the priority of mechanisms, and
//! provides required authentication data.
//!
//! This authentication data is accessed using [`Property`](property::Property)s and can be either
//! provided preemptively or on demand via a [`SessionCallback`](callback::SessionCallback). The
//! use of a callback is the more
//! flexible
//! as [`SessionCallback::callback`](callback::SessionCallback::callback) has access to
//! context-specific data from the ongoing
//! authentication exchange, and as some mechanisms will always require the use of a user callback.
//!
//! Additionally callbacks can implement the
//! [`SessionCallback::validate`](callback::SessionCallback::validate) method to return data
//! from the authentication to the protocol implementation, e.g. to return the user that was just
//! authenticated. Details for this use-case are found in the [`validate`] module documentation.
//!
//! Additionally to selecting mechanisms at runtime, available mechanisms can also be limited at
//! compile time using feature flags, with the default being to enable all IANA-registered
//! mechanisms in `COMMON` use that are implemented. See the module documentation for
//! [`mechanisms`] for further details.
//!
//! To ensure that authentication can proceed all required `Property`s must be provided. The
//! documentation for each mechanism will list the required `Property` and any additional
//! limitations that may be put their values. Currently no discovery of queryable properties is
//! done, so it is the responsibility of the downstream user to limit mechanisms to those they
//! are providing all properties for.
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
//! A custom mechanism must implement the trait [`Authentication`](mechanism::Authentication) and
//! define a [`Mechanism`](registry::Mechanism) struct describing the implemented mechanism.
//! Documentation about how to add a custom mechanism is found in the [`registry module documentation`](registry).

mod builder;
pub mod callback;
pub mod config;
mod error;
pub mod mechanisms;
pub mod mechname;
pub mod property;
mod session;
pub mod validate;

mod sasl;

mod gsasl;
mod init;

#[cfg(not(any(doc, feature = "unstable_custom_mechanism")))]
mod mechanism;
#[cfg(not(any(doc, feature = "unstable_custom_mechanism")))]
mod registry;

#[cfg(any(doc, feature = "unstable_custom_mechanism"))]
pub mod mechanism;
#[cfg(any(doc, feature = "unstable_custom_mechanism"))]
pub mod registry;

mod channel_bindings;
mod context;
mod typed;

mod vectored_io;

pub mod prelude {
    //! prelude exporting the most commonly used types
    pub use crate::config::{ClientConfig, SASLConfig, ServerConfig};
    pub use crate::error::{SASLError, SessionError};
    pub use crate::mechname::Mechname;
    pub use crate::property::Property;
    pub use crate::sasl::{SASLClient, SASLServer};
    pub use crate::session::{
        ClientSession, ServerSession, Session, SessionData, State, StepResult,
    };
    pub use crate::validate::Validation;
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
